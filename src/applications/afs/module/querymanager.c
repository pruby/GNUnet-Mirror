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
 * @file applications/afs/module/querymanager.c
 * @brief forwarding of queries
 * @author Christian Grothoff
 *
 * The query manager is responsible for queueing queries.  Queued
 * queries are used to fill buffers (instead of using noise). The QM
 * is also responsible for selecting the initial set of nodes that
 * will receive the query. For a good choice, it keeps track of which
 * nodes were recently hot in answering queries. Some randomness is
 * preserved to ensure that we potentially find a better path.<p>
 *
 * Routing is an incredibly hard problem, so please consider
 * consulting with other gnunet-developers before making any
 * significant changes here, even if you have CVS write access.
 */

#include "querymanager.h"

#define DEBUG_QUERYMANAGER NO

/**
 * Set to 'YES' to play with 0.6.2b (and earlier) behavior.
 */
#define TRADITONAL_SELECTION NO

/* default size of the bitmap: 16 byte = 128 bit */
#define BITMAP_SIZE 16

/* of how many outbound queries do we simultaneously
   keep track? */
#define QUERY_RECORD_COUNT 512

/**
 * How much is a query worth 'in general' (even
 * if there is no trust relationship between
 * the peers!).  Multiplied by the number of queries
 * in the request.  20 is for '20 bytes / hash',
 * so this is kind of the base unit.
 */
#define BASE_QUERY_PRIORITY 20

/**
 * In this struct, we store information about a 
 * query that is being send from the local node to
 * optimize the sending strategy. 
 */
typedef struct {

  /**
   * How often did we send this query so far?
   */
  unsigned int sendCount;  
  
  /**
   * The message that we are sending.
   */
  AFS_p2p_QUERY * msg;

  /**
   * Bit-map marking the hostIndices (computeIndex)
   * of nodes that have received this query already.
   * Note that the bit-map has a maximum size, if
   * the index is out-of-bounds, it is hashed into
   * the smaller size of the bitmap. There may thus be
   * nodes with identical indices, in that case, only one of
   * the nodes will receive the query.
   */
  unsigned char bitmap[BITMAP_SIZE];

  /**
   * When do we stop forwarding (!) this query?
   */
  cron_t expires;

  /**
   * How many nodes were connected when we
   * initated sending this query?
   */
  unsigned int activeConnections;

  /**
   * What is the total distance of the query to
   * the connected nodes?
   */
  unsigned long long totalDistance;

  /**
   * To how many peers has / will this query be transmitted?
   */
  unsigned int transmissionCount;
  
  /**
   * To which peer will we never send this message?
   */
  PeerIdentity noTarget;

  /**
   * Sender identity, for a local client.
   */
  ClientHandle localClient;

  /**
   * How important would it be to send the message
   * to all peers in this bucket?
   */
  int * rankings;

} QueryRecord;

/**
 * Array of the queries we are currently sending out.
 */
static QueryRecord queries[QUERY_RECORD_COUNT];

/**
 * Mutex for all query manager structures.
 */
static Mutex * queryManagerLock;

/**
 * How many queries are in the given query (header given).
 */
#define NUMBER_OF_QUERIES(qhdr) (((ntohs(qhdr.size)-sizeof(AFS_p2p_QUERY))/sizeof(HashCode160)))

/**
 * Linked list of peer ids with number of replies received.
 */
typedef struct RL_ {
  PeerIdentity responder;
  unsigned int responseCount;
  struct RL_ * next;
} ResponseList;

/**
 * Structure for tracking from which peer we got valueable replies for
 * which clients / other peers.
 */
typedef struct RTD_ {
  /**
   * For which client does this entry track replies?
   * Only valid if localQueryOrigin == NULL!
   */
  PeerIdentity queryOrigin;

  /**
   * For which client does this entry track replies?
   */
  ClientHandle localQueryOrigin;

  /**
   * Time at which we received the last reply
   * for this client.  Used to discard old entries
   * eventually.
   */
  TIME_T lastReplyReceived;

  /**
   * Linked list of peers that responded, with
   * number of responses.
   */
  ResponseList * responseList;

  /**
   * Linked list.
   */
  struct RTD_ * next;
} ReplyTrackData;

/**
 * Linked list tracking reply statistics.  Synchronize access using
 * the queryManagerLock!
 */
static ReplyTrackData * rtdList = NULL;

/**
 * Cron job that ages the RTD data and that frees
 * memory for entries that reach 0.
 */
static void ageRTD(void * unused) {
  ReplyTrackData * pos;
  ReplyTrackData * prev;
  ResponseList * rpos;
  ResponseList * rprev;
  MUTEX_LOCK(queryManagerLock);
  prev = NULL;
  pos = rtdList;
  while (pos != NULL) {
    /* after 10 minutes, always discard everything */
    if (pos->lastReplyReceived < TIME(NULL) - 600) {
      while (pos->responseList != NULL) {
	rpos = pos->responseList;
	pos->responseList = rpos->next;
	FREE(rpos);
      }
    }
    /* otherwise, age reply counts */
    rprev = NULL;
    rpos = pos->responseList;
    while (rpos != NULL) {
      rpos->responseCount = rpos->responseCount / 2;
      if (rpos->responseCount == 0) {	
	if (rprev == NULL)
	  pos->responseList = rpos->next;
	else
	  rprev->next = rpos->next;
	FREE(rpos);
	if (rprev == NULL)
	  rpos = pos->responseList;
	else
	  rpos = rprev->next;
	continue;
      }
    }
    /* if we have no counts for a peer anymore, 
       free pos entry */
    if (pos->responseList == NULL) {
      if (prev == NULL)
	rtdList = pos->next;
      else
	prev->next = pos->next;
      FREE(pos);
      if (prev == NULL)
	pos = rtdList;
      else
	pos = prev->next;
      continue;     
    }
    prev = pos;
    pos = pos->next;
  }
  MUTEX_UNLOCK(queryManagerLock);
}

/**
 * We received a reply from 'responder' to a query received from
 * 'origin' (or 'localOrigin').  Update reply track data!
 *
 * @param origin only valid if localOrigin == NULL
 * @param localOrigin origin if query was initiated by local client
 * @param responder peer that send the reply
 */
void updateResponseData(const PeerIdentity * origin,
			ClientHandle localOrigin,
			const PeerIdentity * responder) {
  ReplyTrackData * pos;
  ReplyTrackData * prev;
  ResponseList * rpos;
  ResponseList * rprev;

  if (responder == NULL)
    return; /* we don't track local responses */
  MUTEX_LOCK(queryManagerLock);
  pos = rtdList;
  prev = NULL;
  while (pos != NULL) {
    if ( (pos->localQueryOrigin == localOrigin) &&
	 ( (localOrigin != NULL) ||
	   (0 == memcmp(origin,
			&pos->queryOrigin,
			sizeof(PeerIdentity))) ) )
      break; /* found */
    prev = pos;
    pos = pos->next;
  }
  if (pos == NULL) {
    pos = MALLOC(sizeof(ReplyTrackData));
    pos->next = NULL;
    pos->localQueryOrigin = localOrigin;
    if (localOrigin == NULL)
      pos->queryOrigin = *origin;
    pos->responseList = NULL;
    if (prev == NULL)
      rtdList = pos;
    else
      prev->next = pos;
  }
  TIME(&pos->lastReplyReceived);
  rpos = pos->responseList;
  rprev = NULL;
  while (rpos != NULL) {
    if (0 == memcmp(responder,
		    &rpos->responder,
		    sizeof(PeerIdentity))) {
      rpos->responseCount++;
      MUTEX_UNLOCK(queryManagerLock);
      return;
    }
    rprev = rpos;
    rpos = rpos->next;
  }
  rpos = MALLOC(sizeof(ResponseList));
  rpos->responseCount = 1;
  rpos->responder = *responder;
  rpos->next = NULL;
  if (rprev == NULL)
    pos->responseList = rpos;
  else
    rprev->next = rpos;
  MUTEX_UNLOCK(queryManagerLock);
}


/**
 * Map the id to an index into the bitmap array.
 */
static int getIndex(const PeerIdentity * id) {
  unsigned int index;

  index = coreAPI->computeIndex(id);
  if (index >= 8*BITMAP_SIZE)
    index = index & (8*BITMAP_SIZE-1);
  return index;
}

static void setBit(QueryRecord * qr,
		   int bit) {
  unsigned char theBit = (1 << (bit & 7));
  qr->bitmap[bit>>3] |= theBit;
}

static int getBit(QueryRecord * qr,
		  int bit) {
  unsigned char theBit = (1 << (bit & 7));
  return (qr->bitmap[bit>>3] & theBit) > 0;
}

/**
 * Callback method for filling buffers. This method is invoked by the
 * core if a message is about to be send and there is space left for a
 * 3QUERY.  We then search the pending queries and fill one (or more)
 * in if possible.
 *
 * Note that the same query is not transmitted twice to a peer and that
 * queries are not queued more frequently than 2 TTL_DECREMENT.
 *
 * @param receiver the receiver of the message
 * @param position is the reference to the
 *        first unused position in the buffer where GNUnet is building
 *        the message
 * @param padding is the number of bytes left in that buffer.
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
static int fillInQuery(const PeerIdentity * receiver,
		       void * position,
		       int padding) {
  static unsigned int pos = 0;
  unsigned int start;
  unsigned int delta;
  cron_t now;

  cronTime(&now);
  MUTEX_LOCK(queryManagerLock);
  start = pos;
  delta = 0;
  while (padding - delta > sizeof(AFS_p2p_QUERY)+sizeof(HashCode160)) {
    if ( (queries[pos].expires > now) &&
	 (getBit(&queries[pos],
		 getIndex(receiver)) == 0) &&
	 (padding - delta >=
	  ntohs(queries[pos].msg->header.size) ) ) {
#if DEBUG_QUERYMANAGER
      EncName qenc;
      EncName henc;

      IFLOG(LOG_DEBUG,
	    hash2enc(&receiver->hashPubKey,
		     &henc);
	    hash2enc(&queries[pos].msg->queries[0],
		     &qenc));
      LOG(LOG_DEBUG,
	  "adding %d queries (%s) to outbound buffer of %s\n",
	  NUMBER_OF_QUERIES(queries[pos].msg->header),
	  &qenc,
	  &henc);
#endif
      setBit(&queries[pos],
	     getIndex(receiver));
      memcpy(&((char*)position)[delta],
	     queries[pos].msg,
	     ntohs(queries[pos].msg->header.size));
      queries[pos].sendCount++;
      delta += ntohs(queries[pos].msg->header.size);
    }
    pos++;
    if (pos >= QUERY_RECORD_COUNT)
      pos = 0;
    if (pos == start)
      break;
  }
  MUTEX_UNLOCK(queryManagerLock);
  return delta;
}

/**
 * Initialize the query management.
 */
int initQueryManager() {
  int i;

  for (i=0;i<QUERY_RECORD_COUNT;i++) {
    queries[i].expires = 0; /* all expired */
    queries[i].msg = NULL;
  }
  queryManagerLock = coreAPI->getConnectionModuleLock();
  coreAPI->registerSendCallback(sizeof(AFS_p2p_QUERY)+sizeof(HashCode160),
				&fillInQuery);
  addCronJob(&ageRTD,
	     2 * cronMINUTES,
	     2 * cronMINUTES,
	     NULL);
  return OK;
}

void doneQueryManager() {
  int i;
  ResponseList * rpos;
  ReplyTrackData * pos;

  delCronJob(&ageRTD,
	     2 * cronMINUTES,
	     NULL);
  while (rtdList != NULL) {
    pos = rtdList;
    rtdList = rtdList->next;
    while (pos->responseList != NULL) {
      rpos = pos->responseList;
      pos->responseList = rpos->next;
      FREE(rpos);
    }
    FREE(pos);
  }
  for (i=0;i<QUERY_RECORD_COUNT;i++) 
    FREENONNULL(queries[i].msg);
  coreAPI->unregisterSendCallback(sizeof(AFS_p2p_QUERY)+sizeof(HashCode160),
				  &fillInQuery);
}

#if TRADITIONAL_SELECTION

/**
 * A "PerNodeCallback" method that selects the most
 * active nodes for forwarding (with some randomness).
 *
 * Also computes the sum of the distances of the
 * other node IDs as a side-effect.
 */
static void selectActiveNodes(PeerIdentity * id,
			      QueryRecord * qr) {
#if DEBUG_QUERYMANAGER
  EncName enc;
#endif
  static unsigned int average = 0;
  static double weight = 4.0;
  unsigned int trf;
  
  /* how many peers should be selected on average? */
#define SELECT_GOAL 2.0
  
  if (id == NULL) {
     /* special call for weight adjustment */
     weight = weight / sqrt((qr->transmissionCount+1.0) / (SELECT_GOAL+1.0));
     return;
  } 
  trf = coreAPI->queryBPMfromPeer(id);
  average  = (average * 15 + trf) / 16; /* approximate average over time...*/ 
#if DEBUG_QUERYMANAGER
  IFLOG(LOG_EVERYTHING,
	hash2enc(&id->hashPubKey,
		 &enc));
  LOG(LOG_EVERYTHING,
      "Selecting active node '%s' as rand(%u) > rand(%u)*%f\n",
      &enc, 
      trf+1,
      average+1,
      weight);
#endif
  /* Forward the query to peers that have on average lots of bandwidth
     assigned to them (and are thus recently very productive...) */
  if (randomi(trf+1) >
      randomi(average+1)*weight) {
    setBit(qr, getIndex(id));
    qr->transmissionCount++;
#if DEBUG_QUERYMANAGER
    LOG(LOG_EVERYTHING,
	"Node '%s' selected for forwarding due to recent activity.\n",
	&enc);
#endif
  } else
    qr->totalDistance += distanceHashCode160(&qr->msg->queries[0],
					     &id->hashPubKey);
}


/**
 * A "PerNodeCallback" method that selects some
 * random nodes (biased according to proximity).
 */
static void selectRandomNodes(PeerIdentity * id,
			      QueryRecord * qr) {
  unsigned int avgDist;
  unsigned int peerDist;
#if DEBUG_QUERYMANAGER
  EncName enc;
#endif
  static double weight = 4.0;

#define FINAL_GOAL 3.0
  if (id == NULL) {
    weight = weight / sqrt( (qr->transmissionCount+1.0) / (FINAL_GOAL+1.0) );
    return;
  }
  
  if ( (qr->totalDistance == 0) ||
       (qr->activeConnections == 0) ) {
    return; /* activeConnections should never be 0,
	       if totalDistance is 0, this is caused
	       by us selectAcitveNodes selecting
	       all nodes already */
  }
  if (getBit(qr, getIndex(id)))
    return;
  avgDist = qr->totalDistance / qr->activeConnections;
  peerDist = distanceHashCode160(&qr->msg->queries[0],
		                 &id->hashPubKey);
#if DEBUG_EVERYTHING
  IFLOG(LOG_EVERYTHING,
	hash2enc(&id->hashPubKey,
		 &enc));
  LOG(LOG_EVERYTHING,
      "Selecting at random active node '%s' using rand(%d)*%f*%u < rand(%d)\n",
      &enc,
      peerDist+1,
      qr->transmissionCount,
      weight,
      avgDist+1);
#endif

  /* Select 2 random nodes for forwarding. Give preference  
     to nodes that are close.  Division by 4 to ensure
     that we are in the range of a signed int. */
  if (randomi(1+peerDist) * qr->transmissionCount * weight
      < randomi(1+avgDist) ) {
#if DEBUG_QUERYMANAGER
    LOG(LOG_EVERYTHING,
	"Node '%s' selected for forwarding from random set.\n",
	&enc);
#endif
    setBit(qr, getIndex(id));
    qr->transmissionCount++;
  }
}

#else


static void newSelectCode(PeerIdentity * id,
			  QueryRecord * qr) {
  ReplyTrackData * pos;
  ResponseList * rp;
  int ranking = 0;
  int distance;

  pos = rtdList;
  while (pos != NULL) {
    if ( ( (qr->localClient == NULL) && 
	   (equalsHashCode160(&pos->queryOrigin.hashPubKey,
			      &qr->noTarget.hashPubKey)) ) ||
	 (qr->localClient == pos->localQueryOrigin) ) 
      break;
    pos = pos->next;
  }
  if (pos != NULL) {
    rp = pos->responseList;
    while (rp != NULL) {
      if (equalsHashCode160(&rp->responder.hashPubKey,
			    &id->hashPubKey))
	break;
      rp = rp->next;
    }
    if (rp != NULL) {
      if (rp->responseCount < 0xFFFF)
	ranking = 0x7FFF * rp->responseCount;
      else
	ranking = 0x7FFFFFF;
    }
  }    
  distance 
    = distanceHashCode160(&((AFS_p2p_QUERY_GENERIC*)(qr->msg))->queries[0],
			  &id->hashPubKey);
  if (distance <= 0)
    distance = 1;
  ranking += 0xFFFF / (1 + randomi(distance));
  ranking += randomi(0xFF); /* small random chance for everyone */
  qr->rankings[getIndex(id)] 
    = ranking;
}

#endif



/**
 * A "PerNodeCallback" method that forwards
 * the query to the selected nodes.
 */
static void sendToSelected(PeerIdentity * id,
			   QueryRecord * qr) {
  if (equalsHashCode160(&id->hashPubKey,
			&qr->noTarget.hashPubKey))
    return;
  if (getBit(qr, getIndex(id)) == 1) {
#if DEBUG_QUERYMANAGER
    EncName enc;
    EncName enc2;

    IFLOG(LOG_EVERYTHING,
	  hash2enc(&id->hashPubKey,
		   &enc);
	  hash2enc(&qr->msg->queries[0],
		   &enc2));
    LOG(LOG_EVERYTHING,
	"Queueing query '%s' in buffer of selected node '%s'.\n",
	&enc2,
	&enc);
#endif
    coreAPI->sendToNode(id,
			&qr->msg->header,
			BASE_QUERY_PRIORITY * 
			(ntohl(qr->msg->priority)*2+
			 NUMBER_OF_QUERIES(qr->msg->header)),
			TTL_DECREMENT);
  }
}

/**
 * Take a query and forward it to the appropriate
 * number of nodes (depending on load, queue, etc).
 */
void forwardQuery(AFS_p2p_QUERY * msg,		  
		  const PeerIdentity * excludePeer,
		  const ClientHandle client) {
  cron_t now;
  QueryRecord * qr;
  QueryRecord dummy;
#if DEBUG_QUERYMANAGER
  EncName enc;
#endif
  cron_t oldestTime;
  cron_t expirationTime;
  int oldestIndex;
  int i;
  int noclear = NO;
  
#if DEBUG_QUERYMANAGER
  IFLOG(LOG_DEBUG,
	hash2enc(&msg->queries[0],
		 &enc));
  LOG(LOG_DEBUG,
      "Forwarding query for '%s' with ttl %d.\n",
      &enc,
      ntohl(msg->ttl));
#endif
  cronTime(&now);
  MUTEX_LOCK(queryManagerLock);
  
  oldestIndex = -1;
  expirationTime = now + ntohl(msg->ttl);
  oldestTime = expirationTime;
  for (i=0;i<QUERY_RECORD_COUNT;i++) {
    if (queries[i].expires < oldestTime) {
      oldestTime = queries[i].expires;      
      oldestIndex = i;      
    }
    if (queries[i].msg == NULL)
      continue;
    if ( (queries[i].msg->header.size == msg->header.size) &&
	 (0 == memcmp(&((AFS_p2p_QUERY_GENERIC*)(queries[i].msg))->queries[0],
		      &((AFS_p2p_QUERY_GENERIC*)msg)->queries[0],
		      ntohs(msg->header.size)-sizeof(AFS_p2p_QUERY))) ) {
      /* We have exactly this query pending already.
	 Replace existing query! */
      oldestIndex = i;     
      if ( (queries[i].expires > now - 4 * TTL_DECREMENT) && /* not long expired */
	   (randomi(4) != 0) ) {
	/* do not clear the bitmap describing which peers we have
	   forwarded the query to already; but do this only with high
	   probability since we may want to try again if the query is
	   retransmitted lots (this can happen if this is the only
	   query; we may forward it to all connected peers and get no
	   reply.  If the initiator keeps retrying, we want to
	   eventually forward it again. 

	   Note that the initial probability here (0.6.0/0.6.1) was
	   very low (1:64), which is far too low considering that the
	   clients do an exponential back-off.  The rule is a pure
	   optimization, and as such the probability that we
	   eventually forward must be significant.  25% seems to work
	   better... (extra-note: in small testbeds, the problem
	   is bigger than in a larger network where the case that
	   a query stays in the QM indefinitely might be much more
           rare; so don't just trust a micro-scale benchmark when
           trying to figure out an 'optimal' threshold). */
	noclear = YES; 
#if DEBUG_QUERYMANAGER
	LOG(LOG_DEBUG,
	    "QM noclear rule applied!\n");
#endif
      }
      break; /* this is it, do not scan for other 
		'oldest' entries */
    }
  }
  if (oldestIndex == -1) {				    
#if DEBUG_QUERYMANAGER
    LOG(LOG_DEBUG,
	"Leeping track of %d queries already, will not manage this one.\n",
	QUERY_RECORD_COUNT);    
#endif
    qr = &dummy;  
  } else {
    qr = &queries[oldestIndex];
    FREENONNULL(qr->msg);
    qr->msg = NULL;
  } 
  qr->expires = expirationTime;
  qr->transmissionCount = 0;
  qr->msg = MALLOC(ntohs(msg->header.size));
  memcpy(qr->msg,
	 msg,
	 ntohs(msg->header.size));
  if (noclear == NO) {
    memset(&qr->bitmap[0],
	   0,
	   BITMAP_SIZE);
    if (excludePeer != NULL)
      qr->noTarget = *excludePeer;
    else
      qr->noTarget = *coreAPI->myIdentity;
    qr->localClient = client;
    qr->totalDistance = 0;
#if TRADITIONAL_SELECTION
    qr->activeConnections
      = coreAPI->forAllConnectedNodes
      ((PerNodeCallback)&selectActiveNodes,
       qr);
    if (qr->activeConnections > 0) {
      selectActiveNodes(NULL, qr); /* give SAN chance to adjust weight at the
				      end of the iteration! */    
      for (i=BITMAP_SIZE*4/qr->activeConnections;i>=0;i--)
	setBit(qr, randomi(BITMAP_SIZE)*8); /* select 4 random nodes */
      coreAPI->forAllConnectedNodes
	((PerNodeCallback)&selectRandomNodes,
	 qr);    
    }
#else
    qr->rankings = MALLOC(sizeof(int)*8*BITMAP_SIZE);
    qr->activeConnections
      = coreAPI->forAllConnectedNodes
      ((PerNodeCallback)&newSelectCode,
       qr);    
    /* actual selection, proportional to rankings
       assigned by newSelectCode ... */
    {
      int j;
      unsigned long long rankingSum = 0;
      for (i=0;i<8*BITMAP_SIZE;i++)
	rankingSum += qr->rankings[i];
      if ( (rankingSum != 0) && /* doppelt haelt besser */
	   (qr->activeConnections > 0) ) {
	/* select 4 peers for forwarding */
	for (i=0;i<4;i++) {
	  unsigned long long sel;
	  unsigned long long pos;
	  sel = randomi64(rankingSum);
	  pos = 0;	
	  for (j=0;j<8*BITMAP_SIZE;j++) {
	    pos += qr->rankings[j];
	    if (pos > sel) {
	      setBit(qr, j);
	      break;
	    }
	  }  
	}
      } else {
	/* no bias available, go random! */
	if (qr->activeConnections > 0) {
	  for (i=4*BITMAP_SIZE*8/qr->activeConnections-1;i>=0;i--)
	    setBit(qr, randomi(BITMAP_SIZE)*8); /* select 4 random nodes */
	}	
      }
    }
    FREE(qr->rankings);
    qr->rankings = NULL;
#endif    
    /* now forward to a couple of selected nodes */
    coreAPI->forAllConnectedNodes
      ((PerNodeCallback)&sendToSelected,
       qr);
    if (qr == &dummy)
      FREE(dummy.msg);
  }
  MUTEX_UNLOCK(queryManagerLock);
}

/**
 * Stop transmitting a certain query (we don't route it anymore or
 * we have learned the answer).
 */
void dequeueQuery(const HashCode160 * query) {
  int i;
  int j;
  QueryRecord * qr;

  MUTEX_LOCK(queryManagerLock);
  for (i=0;i<QUERY_RECORD_COUNT;i++) {
    qr = &queries[i];
    if( qr->msg != NULL ) {
      for (j=NUMBER_OF_QUERIES(qr->msg->header)-1;j>=0;j--) {
        if (equalsHashCode160(query,
 	  	  	      &((AFS_p2p_QUERY_GENERIC*)(qr->msg))->queries[j])) {
  	  qr->expires = 0; /* expire NOW! */
 	  break;
        }
      }
    }
  }  
  MUTEX_UNLOCK(queryManagerLock);
}

/* end of querymanager.c */
