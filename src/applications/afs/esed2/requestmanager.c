/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/** 
 * @file applications/afs/esed2/requestmanager.c
 * @brief The RequestManager keeps track of and re-issues queries
 * @author Christian Grothoff
 */ 

#include "gnunet_afs_esed2.h"
#include "platform.h"

#define DEBUG_REQUESTMANAGER NO

/**
 * Highest TTL allowed? (equivalent of 25-50 HOPS distance!)
 */
#define MAX_TTL (100 * TTL_DECREMENT)

/**
 * After how many retries do we print a warning?
 */
#define MAX_TRIES 50

/**
 * Print the contents of the request manager. For debugging.
 */
void printRequestManager(RequestManager * this) {
  int i;
  HexName hex;

  MUTEX_LOCK(&this->lock);
  LOG(LOG_DEBUG,
      "RM TTL %u duplicates %d\n",
      this->initialTTL, 
      this->duplicationEstimate);
  for (i=0;i<this->requestListIndex;i++) {
    IFLOG(LOG_DEBUG,
	  hash2hex(&((AFS_CS_QUERY_GENERIC*)(this->requestList[i]->message))->queries[0], 
		   &hex));
    LOG(LOG_DEBUG,
	"%4i: %s for node %d (%d tries)\n",
	i, 
	&hex, 
	this->requestList[i]->receiverNode,
	this->requestList[i]->tries);
  }  
  MUTEX_UNLOCK(&this->lock);
}

/**
 * Test that the given entry does not occur
 * in the continuations list (and if it does,
 * NULL it out).
 */
static void freeInContinuations(RequestManager * this,
				RequestEntry * entry) {
  RequestContinuations * cur;

  cur = this->start;
  while (cur != NULL) {
    if (cur->entry == entry)
      cur->entry = NULL;
    cur = cur->next;
  }
}

/**
 * We have determined success or failure for
 * sending the query.  Now update the state of
 * the RM adequately.  this->start contains the
 * continuation that holds the state required
 * to do this update.
 */
static void runContinuation(RequestManager * this,
			    int ok) { 
  RequestContinuations * cur;

  cur = this->start;
  if (cur->entry != NULL) {
    if (ok != OK) {
      /* we did not send this entry, revert! */
      LOG(LOG_DEBUG,
	  "sending canceled (would block)\n");
      cur->entry->message->ttl 
	= htonl(cur->prevttl);
      cur->entry->message->priority 
	= htonl(cur->prevpri);
      cur->entry->lasttime 
	= cur->prevlt;
      cur->entry->tries--;
    } else {
      if (cur->entry->tries > 1) {
	TIME_T nowTT;
	
	TIME(&nowTT);
	if ( (nowTT - this->initialTTL) > this->lastDET) {
	  /* only consider congestion control every
	     "average" TTL seconds, otherwise the system
	     reacts to events that are far too old! */
	  /* we performed retransmission, treat as congestion (RFC 2001) */
#if DEBUG_REQUESTMANAGER
	  LOG(LOG_DEBUG,
	      "received duplicate data, changing CW (%d to %d) and SST (%d->%d)\n",
	      this->congestionWindow,
	      (this->congestionWindow / 2) + 1,
	      this->ssthresh,
	      this->congestionWindow / 2);
#endif
	  this->ssthresh 
	    = this->congestionWindow / 2;
	  if (this->ssthresh < 2)
	    this->ssthresh = 2;
	  this->congestionWindow 
	  = this->ssthresh + 1;
	  this->lastDET = nowTT;
      }
	cur->nc->stats.totalRetries++;
	cur->nc->stats.currentRetries++;      
      }
    }
  }
  this->start = cur->next;
  FREE(cur);
}

/**
 * Send the request from the requestList[requestIndex] out onto
 * the network.
 *
 * @param this the RequestManager
 * @param requestIndex the index of the Request to issue
 */
static void issueRequest(RequestManager * this,
			 int requestIndex) {
  RequestContinuations * con;
  RequestContinuations * pos;
  RequestEntry * entry; 
  NodeContext * nc;
  cron_t now;
  HexName hex;
  CS_HEADER * msg;
  GNUNET_TCP_SOCKET * sock;
  int ok;

  cronTime(&now);
  con = MALLOC(sizeof(RequestContinuations));
  con->next = NULL;
  con->entry
    = entry
    = this->requestList[requestIndex];

  if ((entry->lasttime +
       ntohl(entry->message->ttl)) > now - TTL_DECREMENT) 
    BREAK(); 
  if (entry->lasttime == 0) {
    entry->message->ttl = htonl(0); /* to avoid assert failure */
    con->ttl = this->initialTTL;
    con->prevttl = con->ttl;
  } else {
    con->ttl = ntohl(entry->message->ttl);
    con->prevttl = con->ttl;
    if (con->ttl > MAX_TTL) {
      con->ttl = MAX_TTL + randomi(2*TTL_DECREMENT);
      entry->message->ttl = htonl(MAX_TTL); /* to avoid assert failure */
    } else if (con->ttl > this->initialTTL) {
      /* switch to slow back-off */
      unsigned int rd;
      if (this->initialTTL == 0)
	rd = con->ttl;
      else
	rd = con->ttl / this->initialTTL;
      if (rd == 0)
	rd = 1; /* how? */
      rd = TTL_DECREMENT / rd;
      if (rd == 0)
	rd = 1;
      con->ttl += randomi(50 * cronMILLIS + rd); 
      /* rd == TTL_DECREMENT / (con->ttl / this->initialTTL) + saveguards 
	 50ms: minimum increment */
    } else {
      con->ttl += randomi(con->ttl + 2 * TTL_DECREMENT); /* exponential backoff with random factor */
    }
  }
  con->prevlt = entry->lasttime;
  entry->lasttime = now + 2 * TTL_DECREMENT;
  if (randomi(1+entry->tries) > 1) {
    /* do linear (in tries) extra back-off (in addition to ttl)
       to avoid repeatedly tie-ing with other peers; this is somewhat
       equivalent to what ethernet is doing, only that 'tries' is our
       (rough) indicator for collisions.  For ethernet back-off, see:
       http://www.industrialethernetuniversity.com/courses/101_4.htm
    */
    entry->lasttime += randomi(TTL_DECREMENT * (1+entry->tries));
  }
  if (NO == checkAnonymityPolicy(AFS_CS_PROTO_QUERY,
				 ntohs(entry->message->header.size)+sizeof(PeerIdentity))) {
#if DEBUG_REQUESTMANAGER
    LOG(LOG_DEBUG,
	"Not sending query '%s' due to anonymity policy!\n",
	&hex);
#endif
    FREE(con);
    return; 
  }
  if (con->ttl < ntohl(entry->message->ttl)) 
    BREAK();
  con->prevpri 
    = ntohl(entry->message->priority);
  if (con->prevpri > 0x0FFFFFF)
    con->prevpri 
      = randomi(0xFFFFFF); /* bound! */
  entry->tries++;
  if (entry->successful_replies > 0) {
    /* do NOT change priority / ttl for n iterations
       where n is the number of successful replies! */
    con->ttl 
      = ntohl(entry->message->ttl);     
    entry->successful_replies /= 2; /* better than --? better than = 0? */
  } else {
    unsigned int tpriority;
    unsigned int mpriority;
    int count;

    if (con->ttl > (con->prevpri+8)* TTL_DECREMENT) 
      con->ttl = (con->prevpri+8) * TTL_DECREMENT;
    entry->message->ttl 
      = htonl(con->ttl);
    tpriority = con->prevpri + randomi(entry->tries);
    mpriority = getMaxPriority();
    /* adjust mpriority according to the number of queries */

    count = ( ntohs(entry->message->header.size) - 
	      sizeof(AFS_CS_QUERY) ) / sizeof(HashCode160);
    if (count >= 2)
      count--; /* discount super-query */
    mpriority *= count;
    
    if (tpriority > mpriority) {
      /* mpriority is (2 * (current average priority + 2)) and
	 is used as the maximum priority that we use; if the
	 calculated tpriority is above it, we reduce tpriority
	 to random value between the average (mpriority/2) but
	 bounded by mpriority */
      tpriority = mpriority / 2 + (randomi(1+mpriority/2));
    }
    entry->message->priority 
      = htonl(tpriority);
  }
#if DEBUG_REQUESTMANAGER
  {
    int i;
    int count;

    count = ( ntohs(entry->message->header.size) - 
	      sizeof(AFS_CS_QUERY) ) / sizeof(HashCode160);
    for (i=0;i<count;i++) {
      IFLOG(LOG_DEBUG,
	    hash2hex(&((AFS_CS_QUERY_GENERIC*)entry->message)->queries[i],
		     &hex));
      if (con->prevlt == 0) {
	LOG(LOG_DEBUG,
	    "%d sending %dst time (last: NEVER; ttl %d) %s; ttl %d, priority %u (%d)\n",
	    i,
	    entry->tries,
	    con->prevttl,
	    &hex,
	    con->ttl,
	    ntohl(entry->message->priority),
	    this->initialTTL);
      } else {
	LOG(LOG_DEBUG,
	    "%d sending %d-th time (last: %lld ms ago; ttl %d) %s; ttl %d, priority %u (%d)\n",
	    i,
	    entry->tries,
	    (now - con->prevlt),
	    con->prevttl,
	    &hex,
	    con->ttl,
	    ntohl(entry->message->priority),
	    this->initialTTL);
      }
    }
  }
#endif
  con->nc
    = nc
    = (NodeContext *)entry->data;
  nc->stats.requestsPending 
    = this->requestListIndex;
  nc->stats.requestsSent 
    = this->requestListIndex;
  nc->stats.currentTTL 
    = con->ttl;
  nc->stats.duplicationEstimate 
    = this->duplicationEstimate;
  nc->pmodel(&nc->stats, nc->data);    


  if (0 == (entry->tries % (MAX_TRIES * 50))) {
    IFLOG(LOG_WARNING,
	  hash2hex(&((AFS_CS_QUERY_GENERIC*)(entry->message))->queries[0],
		   &hex));
    LOG(LOG_WARNING,
	_("Content '%s' seems to be not available on the network.\n"),
	&hex);
    entry->receiverNode->vtbl->print(entry->receiverNode, 0);
  }
  msg = MALLOC(ntohs(entry->message->header.size));
  memcpy(msg,
	 entry->message,
	 ntohs(entry->message->header.size));
  sock = this->sock;

  ok = SYSERR;
  if (sock != NULL) { 
    /* add con to the end of the (very short) 
       linked list */
    pos = this->start;
    if (pos == NULL) {
      this->start = con;
    } else {
      while (pos->next != NULL)
	pos = pos->next;
      pos->next = con;
    }
    
    /* destroyRM may set this->sock to NULL at ANY point! */
    ok = writeToSocketNonBlocking(sock, 
				  msg);
    if (ok == SYSERR) {
      LOG(LOG_WARNING,
	  _("Could not send request to gnunetd.\n"));
      runContinuation(this,
		      SYSERR);
    } else {
      /* receiverThread will call 
	 runContinuation */
    }
  } else {
    FREE(con);
  }
  FREE(msg);
}

/**
 * Cron job that re-issues requests. Should compute how long to sleep
 * (min ttl until next job is ready) and re-schedule itself
 * accordingly!
 */
static void requestJob(RequestManager * this) {
  cron_t minSleep;
  cron_t now;
  cron_t delta;
  int i;  
  int pending;
  int * perm;

#if DEBUG_REQUESTMANAGER
  LOG(LOG_CRON,
      "requestJob %p running\n",
      this);
#endif
  MUTEX_LOCK(&this->lock);
  if (this->requestListIndex == 0) {
    MUTEX_UNLOCK(&this->lock);
    return;
  }
  cronTime(&now);
  pending = 0;

  for (i=0;i<this->requestListIndex;i++) {
    if (this->requestList[i]->lasttime +
	ntohl(this->requestList[i]->message->ttl) >= now) 
      pending++;
  }

  minSleep = 5 * cronSECONDS; /* max-sleep! */
  perm = permute(this->requestListIndex);
  for (i=0;i<this->requestListIndex;i++) {
    int j = perm[i];
    if ( (this->requestList[j]->lasttime +
	  ntohl(this->requestList[j]->message->ttl)) <= now - TTL_DECREMENT) {
      int pOCWCubed;
      int pendingOverCWin = pending - this->congestionWindow;
      if (pendingOverCWin <= 0)
	pendingOverCWin = -1; /* avoid 0! */
      pOCWCubed = pendingOverCWin *
	pendingOverCWin *
	pendingOverCWin;
     
      if ( (pOCWCubed <= 0) ||
	   (pOCWCubed * this->requestListIndex <= 0) /* see #642 */ ||
	   /* avoid no-start: override congestionWindow occasionally... */
	   (0 == randomi(this->requestListIndex * 
			 pOCWCubed)) ) {
	delta = ntohl(this->requestList[j]->message->ttl) + 10 * cronMILLIS;    
	issueRequest(this, j);
	pending++;
      } else {	
#if DEBUG_REQUESTMANAGER
	static int lpri = 0;
	lpri++;
	/* do not print ALL the time, just once per iteration */
	if ( (lpri % (this->requestListIndex+1)) == 0) 
	  LOG(LOG_DEBUG,
	      " congestion control: %d pending, %d window; %u initial TTL\n",
	      pending,
	      this->congestionWindow,
	      this->initialTTL);
#endif
	delta = 0;
      }
    } else {
      delta = (this->requestList[j]->lasttime + TTL_DECREMENT +
	       ntohl(this->requestList[j]->message->ttl)) - now;
#if DEBUG_REQUESTMANAGER
      LOG(LOG_DEBUG,
	  "request %d:%x (TTL: %u) is still pending for %us\n",
	  i,
	  ((AFS_CS_QUERY_GENERIC*) this->requestList[j]->message)->queries[0].a,
	  ntohl(this->requestList[j]->message->ttl),
	  (unsigned int) (delta / cronSECONDS));
#endif
    }
      
    if ( delta < minSleep )
      minSleep = delta;
  }
  FREE(perm);
  if (minSleep < cronMILLIS * 100)
    minSleep = cronMILLIS * 100; /* maximum resolution: 100ms */
  if (this->requestListIndex > 0) {
#if DEBUG_REQUESTMANAGER
    LOG(LOG_CRON,
	"scheduling next run for in %dms\n",
	minSleep);
#endif
    addCronJob((CronJob)&requestJob, 
	       minSleep, 
	       0, 
	       this);
  }
#if DEBUG_REQUESTMANAGER
  else
    LOG(LOG_DEBUG,
	"no more jobs pending, cron not renewed!\n");
#endif
  MUTEX_UNLOCK(&this->lock);
}

/**
 * This method receives data corresponding to the indicated filename
 * (hashcode). Finds the Listener that scheduled this request and drop
 * it from the list of pending requests.<p>
 * 
 * @param this the request manager struct from createRequestManager
 * @param msg the message received from gnunetd
 */ 
static void requestManagerReceive(RequestManager * this,
				  AFS_CS_RESULT_CHK * msg) {
  int pos;
  int i;
  int j;
  HashCode160 query;
  RequestEntry * entry;

  /* check type of reply msg, fill in query */
  hash(&msg->result,
       sizeof(CONTENT_Block),
       &query);  
  pos = -1;  
  /* find which query matches the reply, call the callback
     and recycle the slot */
  for (i=0;i<this->requestListIndex;i++) {
    AFS_CS_QUERY * acq;

    acq = this->requestList[i]->message;
    j = (ntohs(acq->header.size)-sizeof(AFS_CS_QUERY))/sizeof(HashCode160);    
    while ( j > 0 ) {
      j--;
      if (equalsHashCode160(&query, 
			    &((AFS_CS_QUERY_GENERIC*)acq)->queries[j])) 
	pos = i;
    }
  }
  if (pos == -1) {
    TIME_T nowTT;

    TIME(&nowTT);
    this->duplicationEstimate++;
    if ( (nowTT - this->initialTTL) > this->lastDET) {
      /* only consider congestion control every
	 "average" TTL seconds, otherwise the system
	 reacts to events that are far too old! */

      /* duplicate reply, treat as congestion (RFC 2001) */
#if DEBUG_REQUESTMANAGER
      LOG(LOG_DEBUG,
	  "received duplicate data, changing CW (%d to %d) and SST (%d->%d)\n",
	  this->congestionWindow,
	  (this->congestionWindow / 2) + 1,
	  this->ssthresh,
	  this->congestionWindow / 2);
#endif
      this->ssthresh = this->congestionWindow / 2;
      if (this->ssthresh < 2)
	this->ssthresh = 2;
      this->congestionWindow 
	= this->ssthresh + 1;
      this->lastDET = nowTT;
    } 
#if DEBUG_REQUESTMANAGER
    {
      HexName hex;
      IFLOG(LOG_INFO,
	    hash2hex(&query,
		     &hex));
      LOG(LOG_INFO, 
	  "RequestManager: received useless data matching query %s (%d, %us)!\n",
	  &hex,
	  this->duplicationEstimate,
	  this->initialTTL / cronSECONDS);   
    }
#endif
    return;
  }
#if DEBUG_REQUESTMANAGER
  {
    HexName hex;

    IFLOG(LOG_DEBUG,
	  hash2hex(&((AFS_CS_QUERY_GENERIC*)this->requestList[pos]->message)->queries[0], 
		   &hex));
    LOG(LOG_DEBUG,
	"RequestManager: received reply for request %d (%s)\n",
	pos,
	&hex);
  }
#endif
  entry = this->requestList[pos];
  
  if ( (entry->lasttime < cronTime(NULL)) &&
       (entry->lasttime != 0) ) {
    unsigned int weight = 15;
    unsigned int ettl = ntohl(entry->message->ttl);
    if (ettl > TTL_DECREMENT) 
      ettl -= TTL_DECREMENT;
    else
      ettl = 0;
    if ( (ettl > 4 * this->initialTTL) &&
	 ( (cronTime(NULL) - entry->lasttime) < this->initialTTL) ) {
      weight = 127; /* eTTL is MUCH bigger than what we currently expect AND the time
		    between the last query and the reply was in the range of the
		    expected TTL => don't take ettl too much into account! */   
    }     
    this->initialTTL = ((this->initialTTL) * weight + ettl) / (weight+1);

    /* RFC 2001: increase cwnd; note that we can't really discriminate between
       slow-start and cong. control mode since our RSS is too small... */
    if (this->congestionWindow < this->ssthresh)
      this->congestionWindow += 2; /* slow start */
    else
      this->congestionWindow += 1; /* slower start :-) */
  }
  /* and finally use the entry to notify the node
     that we got a reply! */
#if DEBUG_REQUESTMANAGER
  LOG(LOG_DEBUG,
      "request manager receives data for %p\n",
      entry->receiverNode);
#endif

  if (SYSERR == entry->receiver(entry->receiverNode,
				&query,
				msg,
				this,
				entry->data)) {
    int i;
    
    /* ABORT download, receiver method has
       already notified the controller via
       the pmodel callback, we need to stop
       requesting... */
#if DEBUG_REQUESTMANAGER
    LOG(LOG_DEBUG,
	" entry->receiver aborted download!\n");
#endif
    for (i=0;i<this->requestListIndex;i++) {
      freeInContinuations(this,
			  this->requestList[i]);
      FREENONNULL(this->requestList[i]);
    }
    this->requestListIndex = 0;
  }
}

/**
 * We are approaching the end of the download.  Cut
 * all TTLs in half.
 */
void requestManagerEndgame(RequestManager * this) {
  int i;

  MUTEX_LOCK(&this->lock);
  for (i=0;i<this->requestListIndex;i++) {
    RequestEntry * entry = this->requestList[i];
    int ttl = ntohl(entry->message->ttl);
    entry->message->ttl = htonl(ttl / 2);
  }
  MUTEX_UNLOCK(&this->lock);
}

/**
 * Listen on socket and receive messages. Call requestManagerReceive
 * on every reply. Never returns, if the RM dies, it will cancel us.
 */
static void * receiveThread(RequestManager * this) {
  CS_HEADER * buffer;
  GNUNET_TCP_SOCKET * sock;

  while (this->sock != NULL) {
    MUTEX_LOCK(&this->lock);
    sock = this->sock;
    MUTEX_UNLOCK(&this->lock);
    if (sock == NULL)
      break;
    buffer = NULL;
    if (SYSERR == readFromSocket(sock,
				 &buffer) ) {
      if (this->sock == NULL)
	break;
      LOG(LOG_WARNING,
	  "'%s' at %s:%d could not "
	  "read data from gnunetd, is the server running?\n",
	  __FUNCTION__, __FILE__, __LINE__);
      sleep(15);
      continue;
    }
    if ( (ntohs(buffer->type) == CS_PROTO_RETURN_VALUE) &&
	 (ntohs(buffer->size) == sizeof(CS_RETURN_VALUE) ) ) {
      int value;

      value = ntohl(((CS_RETURN_VALUE*)buffer)->return_value);
      MUTEX_LOCK(&this->lock);
      if (this->start == NULL) {
	BREAK();
      } else {
	runContinuation(this,
			value);
      }
      MUTEX_UNLOCK(&this->lock);    
    } else if ( (ntohs(buffer->type) == AFS_CS_PROTO_RESULT_CHK) &&
	 (ntohs(buffer->size) == sizeof(AFS_CS_RESULT_CHK) ) ) {
      MUTEX_LOCK(&this->lock);
      requestManagerReceive(this, 
			    (AFS_CS_RESULT_CHK*) buffer);
      MUTEX_UNLOCK(&this->lock);    
    } else {
      /* This should no longer happen, but better check than sorry... */
      LOG(LOG_ERROR,
	  _("Received unexpected message (%d) from gnunetd. "
	    "(this is a bug, though we can probably recover gracefully).\n"),
	  ntohs(buffer->type));
      MUTEX_LOCK(&this->lock);
      releaseClientSocket(this->sock);
      this->sock = getClientSocket();
      MUTEX_UNLOCK(&this->lock);
    }
    FREE(buffer);
  }
  return NULL;
}

/**
 * Create a request manager. Will create the request manager
 * datastructures and also connect to gnunetd. Creates thread that
 * listens to gnunetd replies and another thread that periodically
 * re-issues the queries. Use destroyRequestManager to abort and/or to
 * free resources after the download is complete. The callback method
 * in nc will be invoked to notify the caller of the download progress
 * such that it is possible to tell when we are done.
 *
 * @return NULL on error
 */
RequestManager * createRequestManager() {
  RequestManager * rm;

  rm = MALLOC(sizeof(RequestManager));
  rm->start
    = NULL;
  rm->lastDET 
    = 0;
  MUTEX_CREATE_RECURSIVE(&rm->lock);
  rm->requestListIndex 
    = 0;
  rm->requestListSize  
    = 0;
  rm->requestList      
    = NULL;
  GROW(rm->requestList,
       rm->requestListSize,
       256);
  rm->initialTTL
    = 5 * cronSECONDS;
  /* RFC 2001 suggests to use 1 segment size initially;
     Given 1500 octets per message in GNUnet, we would
     have 2-3 queries of maximum size (552); but since
     we are multi-casting to many peers at the same
     time AND since queries can be much smaller,
     we do WHAT??? */
  rm->congestionWindow
    = 1; /* RSS is 1 */
  rm->ssthresh
    = 65535;
  rm->duplicationEstimate
    = 0;
  rm->sock
    = getClientSocket();
  if (rm->sock == NULL) {
    LOG(LOG_WARNING,
	_("Could not create socket to connect to gnunetd.\n"));
    GROW(rm->requestList,
	 rm->requestListSize,
	 0);
    FREE(rm);
    return NULL;
  }
  memset(&rm->receiveThread_, 
	 0, 
	 sizeof(PTHREAD_T));
  if (0 != PTHREAD_CREATE(&rm->receiveThread_,
			  (PThreadMain)&receiveThread,
			  rm, 
			  256*1024)) {
    DIE_STRERROR("pthread_create");
    /* ok, we don't get here... */
    destroyRequestManager(rm);
    return NULL;
  }
  return rm;
}

/**
 * Destroy the resources associated with a request manager.
 * Invoke this method to abort the download or to clean up
 * after the download is complete.
 *
 * @param this the request manager struct from createRequestManager
 */
void destroyRequestManager(RequestManager * this) {
  GNUNET_TCP_SOCKET * sock;
  int i;
  void * unused;
  RequestContinuations * cur;

  suspendCron();
  MUTEX_LOCK(&this->lock);
  sock = this->sock;
  this->sock = NULL;
  delCronJob((CronJob)&requestJob, 
	     0, 
	     this);
  MUTEX_UNLOCK(&this->lock);
  if (sock != NULL)
    closeSocketTemporarily(sock); /* unblock RM thread */
  PTHREAD_JOIN(&this->receiveThread_, &unused);
  if (sock != NULL)
    releaseClientSocket(sock);
  MUTEX_LOCK(&this->lock);
  for (i=0;i<this->requestListIndex;i++) {
    freeInContinuations(this,
			this->requestList[i]);
    FREENONNULL(this->requestList[i]);
  }  
  this->requestListIndex = 0;
  while (this->start != NULL) {
    cur = this->start->next;
    FREE(this->start);
    this->start = cur;
  }
  GROW(this->requestList,
       this->requestListSize,
       0);
  MUTEX_UNLOCK(&this->lock);
  if (this->top != NULL)
    this->top->vtbl->done(this->top, this);
  MUTEX_DESTROY(&this->lock);
  FREE(this);
  resumeCron();
}

/**
 * Queue a request for execution.
 * 
 * @param this the request manager struct from createRequestManager
 * @param node the node to call once a reply is received
 * @param callback the method to invoke
 * @param data the data argument to the Listener
 * @param message the query to send to gnunetd, freed by callee!
 */
void requestManagerRequest(RequestManager * this,
			   Block * node,
			   Listener callback,
			   void * data,
			   AFS_CS_QUERY * message) {
  RequestEntry * entry;

#if DEBUG_REQUESTMANAGER
  LOG(LOG_DEBUG,
      "requestManagerRequest for %p with callback %p\n",
      node,
      callback);
#endif
  entry = MALLOC(sizeof(RequestEntry));
  entry->message 
    = message;
  entry->successful_replies 
    = 0;
  entry->lasttime 
    = 0; /* never sent */
  entry->receiver 
    = callback;
  entry->receiverNode
    = node;
  entry->data 
    = data;
  entry->tries 
    = 0; /* not tried so far */

  MUTEX_LOCK(&this->lock);   
  /* can we add to current list & issue instantly? */
  if (this->requestListSize == this->requestListIndex) 
    GROW(this->requestList,
	 this->requestListSize,
	 this->requestListSize*2);
  this->requestList[this->requestListIndex++] = entry;
#if DEBUG_REQUESTMANAGER
  LOG(LOG_CRON,
      "scheduling next run for now!\n");
#endif
  advanceCronJob((CronJob)&requestJob,
		 0, 
		 this);
  MUTEX_UNLOCK(&this->lock);
  return;
}

/**
 * Assert that there are no pending requests for this node.
 */
void requestManagerAssertDead(RequestManager * this,
			      Block * node) {
  int i;

  if (this == NULL)
    return; /* do not check */
  MUTEX_LOCK(&this->lock);
  for (i=0;i<this->requestListIndex;i++)
    GNUNET_ASSERT(this->requestList[i]->receiverNode != node);
  MUTEX_UNLOCK(&this->lock);
}

/**
 * Update a request.  This method is used to selectively change a
 * query or drop it entirely.
 *
 * @param this the request manager struct from createRequestManager
 * @param node the block for which the request is updated
 * @param msg the new query message for that node, NULL for 
 *        none (then the request is dropped)
 */
void requestManagerUpdate(RequestManager * this,
			  Block * node,
			  AFS_CS_QUERY * msg) {
  int i;

#if DEBUG_REQUESTMANAGER
  LOG(LOG_DEBUG,
      "updating request for %p to %p\n",
      node, 
      msg);
#endif
  MUTEX_LOCK(&this->lock);
  for (i=0;i<this->requestListIndex;i++) {
    if (this->requestList[i]->receiverNode == node) {
      if (msg != NULL) { /* update */
	msg->priority 
	  = this->requestList[i]->message->priority; /* keep priority */
	msg->ttl
	  = this->requestList[i]->message->ttl; /* keep ttl */
	this->requestList[i]->successful_replies++;
	FREE(this->requestList[i]->message);
	this->requestList[i]->message = msg;	
	/* also wait a bit longer before re-issueing the
	   request, after all, we got at least one of the
	   replies! */
	this->requestList[i]->lasttime 
	  = cronTime(NULL) + 2*TTL_DECREMENT; /* add 2*TTL grace time if we got a reply
						 to a multi-query; this dramatically
						 reduces the amount of "useless"
						 (duplicate) replies we get! */
      } else { /* delete */
        /* update stats */
        if (this->requestList[i]->tries > 1)
          ((NodeContext *)(this->requestList[i]->data))->stats.currentRetries 
	    -= (this->requestList[i]->tries - 1);
	FREE(this->requestList[i]->message);
	freeInContinuations(this,
			    this->requestList[i]);
	FREE(this->requestList[i]);
	this->requestList[i] 
	  = this->requestList[--this->requestListIndex];
	this->requestList[this->requestListIndex] 
	  = NULL;	
      }
      MUTEX_UNLOCK(&this->lock);
      return; /* found! */
    }
  }
  MUTEX_UNLOCK(&this->lock);  
}

/* end of requestmanager.c */
