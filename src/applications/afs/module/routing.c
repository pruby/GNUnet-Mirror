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
 * @file applications/afs/module/routing.c
 * @brief routing of AFS queries and replies
 * @author Christian Grothoff
 *
 * The routing code is responsible for deciding which replies
 * need to be forwarded to which peers. While the querymanager
 * decides where to forward queries, it needs to negotiate with
 * the routing code which queries can be forwarded since we may
 * not be able to keep track of all queries.
 */

#include "routing.h"
#include "manager.h"
#include "bloomfilter.h"
#include "routing.h"
#include "querymanager.h"

#define DEBUG_ROUTING NO

#define DEBUG_WRITE_INDTABLE NO

/**
 * How much is a response worth 'in general'.
 * Since replies are roughly 1k and should be
 * much (factor of 4) preferred over queries
 * (which have a base priority of 20, which
 * yields a base unit of roughly 1 per byte).
 * Thus if we set this value to 4092 we'd rather
 * send a reply instead of a query unless
 * the queries have (on average) a priority that
 * is more than double the reply priority
 * (note that querymanager multiplies the
 *  query priority with 2 to compute the scheduling
 *  priority).
 */
#define BASE_REPLY_PRIORITY 4092

/** 
 * Size of the indirection table specified in gnunet.conf
 */
static unsigned int indirectionTableSize;

/* ****************** config ************** */

/**
 * minimum indirection table size, defaults to 8192 entries, reduce if 
 * you have very little memory, enlarge if you start to overflow often 
 * and have memory available.<p>
 *  
 * If the average query lives for say 1 minute (10 hops), and you have
 * a 56k connection (= 420 kb/minute, or approximately 8000
 * queries/minute) the maximum reasonable routing table size would
 * thus be 8192 entries.  Every entry takes about 68 bytes.<p>
 *  
 * The larger the value is that you pick here, the greater your
 * anonymity can become.  It also can improve your download speed.<p>
 *
 * Memory consumption: 
 * <ul>
 * <li>8192 => 560k indirection table => approx. 6 MB gnunetd</li>
 * <li>65536 => 4456k indirection table => approx. 10 MB gnuentd</li>
 * </ul>
 * <p>
 * THE VALUE YOU PICK MUST BE A POWER OF 2, for example:
 * 128, 256, 512, 1024, 2048, 4092, 8192, 16384, 32768, 65536
 */
#define MIN_INDIRECTION_TABLE_SIZE (8192)
/* #define MIN_INDIRECTION_TABLE_SIZE 8 */

/**
 * Under certain cirumstances, two peers can interlock in their
 * routing such that both have a slot that is blocked exactly until 
 * the other peer will make that slot available.  This is the
 * probability that one will give in.  And yes, it's a hack.  It
 * may not be needed anymore once we add collision-resistance to
 * the routing hash table. 
 */
#define TIE_BREAKER_CHANCE 4

/**
 * Indirection table entry. Lists what we're looking for,
 * where to forward it, and how long to keep looking for it.
 */
typedef struct {
  /**
   * what are we waiting for? 
   */
  HashCode160 hash;  

  /**
   * Are we limited to a specific namespace?
   * Non-NULL if yes.
   */
  HashCode160 * namespace;

  /**
   * when can we forget about this entry? 
   */
  cron_t ttl;

  /**
   * How much is this query worth to us, that is, how much would
   * this node be willing to "pay" for an answer that matches the
   * hash stored in this ITE? (This is NOT the inbound priority,
   * it is the trust-adjusted inbound priority <B>divided</B> by the
   * number of queries (for a multi-query)).
   */
  unsigned int priority;

  /**
   * which replies have we already seen? 
   */
  unsigned int seenIndex; 

  /**
   * hashcodes of the encrypted (!) replies that we have forwarded so far
   */
  HashCode160 * seen; 

  /**
   * How many hosts are waiting for an answer to this query (length of
   * destination array)
   */
  unsigned int hostsWaiting; 

  /**
   * who are these hosts? 
   */
  PeerIdentity * destination; 

  /**
   * How many tcpsocks are in use?
   */
  unsigned int tcpsocksSize;

  /**
   * local TCP clients to send the reply to, NULL if none 
   */
  ClientHandle * tcpsocks; 

  /**
   * Do we currently have a response in the delay
   * loop (delays are introduced to make traffic
   * analysis harder and thus enable anonymity)?
   * This marker is set to avoid looking up content
   * again before the first content exits the delay
   * loop.  Since this *not* looking up content again
   * is not externally visible, it is ok to do this
   * optimization to reduce disk accesses (see Mantis
   * bug #407).
   */
  int successful_local_lookup_in_delay_loop;

  /**
   * Avoiding concurrent lookups for the same ITE: semaphore grants
   * access to peers to perform a lookup that matches this ITE entry.
   */
   Mutex lookup_exclusion;

} IndirectionTableEntry;

/**
 * The routing table. This table has entries for all
 * queries that we have recently send out. It helps 
 * GNUnet to route the replies back to the respective
 * sender.
 */
static IndirectionTableEntry * ROUTING_indTable_;

#if VERBOSE_STATS
/**
 * Stats handle for how much content replies we have
 * send back to clients.
 */
static int stat_cs_reply_content_out;
#endif

/**
 * Stats handles about incoming blocks
 */
static int stat_content_in_ok;
static int stat_content_in_dupe;
static int stat_content_in_orphan;
static int stat_routingFull;
static int stat_routingReplaced;
static int stat_routingPresent;
static int stat_p2p_query_out;
#if VERBOSE_STATS
static int stat_concurrent_route_replacement;
static int stat_delaytime_route_replacement;
#endif

static int random_qsel;

#if DEBUG_WRITE_INDTABLE
/**
 * This function will write numeric entries of the indirectiontable 
 * to a textfile. With idtablesize of (8192*8), it will generate
 * >1200 kb per run. The output will not be an accurate snapshot
 * of the idtable at any moment as the locking is done on per-entry
 * basis. Naturally this function might also twist the routing
 * itself a little by locking the entries. The hope is that analyzing 
 * this data in eg octave or matlab might help understand the 
 * routing behaviour better. Or not.
 */
static void writeIDtable(void) 
{
  int i;
  FILE * fp;
  IndirectionTableEntry * ite;
  static int round = 0;
  cron_t now;
  
  cronTime(&now);

  fp = FOPEN("/tmp/gn_idstats.txt", "a");

  for(i=0;i<indirectionTableSize;i++) {
    ite = &ROUTING_indTable_[i];
    MUTEX_LOCK(&ite->lookup_exclusion);

    fprintf(fp, "%d %d %d %d %d %d %d %d\n",
            round,
	    i,
    	    (ite->namespace ? 1 : 0),
	    (ite->ttl == 0 ? 0 : (int) (((long long) ite->ttl - (long long)now)/cronSECONDS)),
	    ite->priority,
	    ite->seenIndex,
	    ite->hostsWaiting,
	    ite->tcpsocksSize);
	    
    MUTEX_UNLOCK(&ite->lookup_exclusion);
  }
 
  fclose(fp);
  round++;
}
#endif

/**
 * Compute the hashtable index of a host id.
 */
static unsigned int computeRoutingIndex(const HashCode160 * query) {
  unsigned int res = ( (((unsigned int*)query)[random_qsel]) & 
		       ((unsigned int)(indirectionTableSize - 1)) );
  if (res >= indirectionTableSize)
    errexit(" indirectionTableSize not power of 2? (%d)\n",
	    indirectionTableSize);
  return res;
}

/**
 * ITE modes for addToSlot.
 */
#define ITE_REPLACE 0
#define ITE_GROW 1

/**
 * Call useContent "later" and then free the pmsg.
 */
static void useSBLOCKContentLater(AFS_p2p_SBLOCK_RESULT * pmsg) {
  useContent(NULL,
	     &pmsg->result.identifier,
	     &pmsg->header);
  FREE(pmsg);
}

/**
 * Call useContent "later" and then free the
 * pmsg.
 */
static void useCHKContentLater(AFS_p2p_CHK_RESULT * pmsg) {
  HashCode160 hc;
  IndirectionTableEntry * ite;

  hash(&pmsg->result,
       sizeof(CONTENT_Block),
       &hc);
  ite = &ROUTING_indTable_[computeRoutingIndex(&hc)];
  MUTEX_LOCK(&ite->lookup_exclusion);
  if (equalsHashCode160(&hc,
			&ite->hash) ) 
    ite->successful_local_lookup_in_delay_loop = NO;
#if VERBOSE_STATS
  else
    statChange(stat_delaytime_route_replacement, 1);
#endif
  MUTEX_UNLOCK(&ite->lookup_exclusion);
  useContent(NULL,
	     &hc,
	     &pmsg->header);
  FREE(pmsg);
}

/**
 * Call useContent "later" and then free the
 * pmsg.
 */
static void use3HashContentLater(AFS_p2p_3HASH_RESULT * pmsg) {
  HashCode160 hc;

  hash(&pmsg->hash,
       sizeof(HashCode160),
       &hc);
  useContent(NULL,
	     &hc,
	     &pmsg->header);
  FREE(pmsg);
}

/**
 * Queue a CHK reply with cron to simulate
 * another peer returning the response with
 * some latency (and then route as usual).
 * 
 * @param sender the next hop
 * @param result the content that was found
 */
static void queueCHKReply(PeerIdentity * sender,
			  CONTENT_Block * result) {
  AFS_p2p_CHK_RESULT * pmsg;
  HashCode160 hc;
  IndirectionTableEntry * ite;

  hash(result,
       sizeof(CONTENT_Block),
       &hc);
  
  ite = &ROUTING_indTable_[computeRoutingIndex(&hc)];
  if (! equalsHashCode160(&ite->hash,
			  &hc) ) {
#if DEBUG_ROUTING
    EncName enc;

    IFLOG(LOG_EVERYTHING,
	  hash2enc(&hc, &enc));
    LOG(LOG_EVERYTHING,
	"concurrent route replacement: %s\n",
	&enc);
#endif    
#if VERBOSE_STATS
    statChange(stat_concurrent_route_replacement, 1);
#endif
    return;
  }
  if (YES == ite->successful_local_lookup_in_delay_loop) {
#if DEBUG_ROUTING
    EncName enc;    
    IFLOG(LOG_WARNING,
	  hash2enc(&hc, &enc));
    LOG(LOG_WARNING,
	_("Unexpected concurrent CHK lookup of '%s'.\n"),
	&enc);
#endif    
    return; /* wow, really bad concurrent DB lookup and processing for
	       the same query.  Well, at least we should not also
	       queue the delayed reply twice... */
  }
  ite->successful_local_lookup_in_delay_loop = YES;
  pmsg = MALLOC(sizeof(AFS_p2p_CHK_RESULT));
  pmsg->header.size 
    = htons(sizeof(AFS_p2p_CHK_RESULT));
  pmsg->header.type 
    = htons(AFS_p2p_PROTO_CHK_RESULT);
  pmsg->result = *result;

  /* delay reply, delay longer if we are busy (makes it harder
     to predict / analyze, too). */
  addCronJob((CronJob)&useCHKContentLater,
	     randomi(TTL_DECREMENT), 
	     0,
	     pmsg);
}

/**
 * Queue an SBLOCK reply with cron to simulate
 * another peer returning the response with
 * some latency (and then route as usual).
 * 
 * @param sender the next hop
 * @param result the content that was found
 */
static void queueSBLOCKReply(PeerIdentity * sender,
			     SBlock * result) {
  AFS_p2p_SBLOCK_RESULT * pmsg;

  pmsg = MALLOC(sizeof(AFS_p2p_SBLOCK_RESULT));
  pmsg->header.size 
    = htons(sizeof(AFS_p2p_SBLOCK_RESULT));
  pmsg->header.type 
    = htons(AFS_p2p_PROTO_SBLOCK_RESULT);
  memcpy(&pmsg->result,
	 result,
	 sizeof(CONTENT_Block));
  /* delay reply, delay longer if we are busy (makes it harder
     to predict / analyze, too). */
  addCronJob((CronJob)&useSBLOCKContentLater, 
	     randomi(TTL_DECREMENT), 
	     0,
	     pmsg);
}

/**
 * Queue a 3Hash reply with cron to simulate
 * another peer returning the response with
 * some latency (and then route as usual).
 * 
 * @param sender the next hop
 * @param hc the double (!) hash
 * @param result the content that was found
 */
static void queue3HashReply(PeerIdentity * sender,
			    HashCode160 * hc,
			    CONTENT_Block * result) {
  AFS_p2p_3HASH_RESULT * pmsg;

  pmsg = MALLOC(sizeof(AFS_p2p_3HASH_RESULT));
  pmsg->header.size 
    = htons(sizeof(AFS_p2p_3HASH_RESULT));
  pmsg->header.type
    = htons(AFS_p2p_PROTO_3HASH_RESULT);
  memcpy(&pmsg->result,
	 result,
	 sizeof(CONTENT_Block));
  pmsg->hash = *hc;
  /* delay reply, delay longer if we are busy (makes it harder
     to predict / analyze, too). */
  addCronJob((CronJob)&use3HashContentLater,
	     randomi(TTL_DECREMENT), 
	     0,
	     pmsg);
}

/**
 * Hand a CHK reply to the client.
 * @param sock the client socket
 * @param result the response
 */
static void tellClientCHKReply(ClientHandle sock,
			       CONTENT_Block * result) {
  AFS_CS_RESULT_CHK * reply;
  HashCode160 hc;
#if DEBUG_ROUTING
  EncName enc;
#endif

  hash(result,
       sizeof(CONTENT_Block),
       &hc);
#if DEBUG_ROUTING
  hash2enc(&hc,
	   &enc);
  LOG(LOG_DEBUG,
      "Sending client response to CHK query '%s'.\n",
      &enc);
#endif
  reply = MALLOC(sizeof(AFS_CS_RESULT_CHK));
  reply->header.type
    = htons(AFS_CS_PROTO_RESULT_CHK);
  reply->header.size 
    = htons(sizeof(AFS_CS_RESULT_CHK));
  reply->result = *result;
#if VERBOSE_STATS
  statChange(stat_cs_reply_content_out, 1);
#endif
  coreAPI->sendToClient(sock,
		&reply->header);
  FREE(reply);
}


/**
 * Hand an SBLOCK reply to the client.
 * @param sock the client socket
 * @param result the response
 */
static void tellClientSBLOCKReply(ClientHandle sock,
				  SBlock * result) {
  AFS_CS_RESULT_SBLOCK * reply;
  
  reply = MALLOC(sizeof(AFS_CS_RESULT_SBLOCK));
  reply->header.type
    = htons(AFS_CS_PROTO_RESULT_SBLOCK);
  reply->header.size 
    = htons(sizeof(AFS_CS_RESULT_SBLOCK));
  memcpy(&reply->result,
	 result,
	 sizeof(CONTENT_Block));
#if VERBOSE_STATS
  statChange(stat_cs_reply_content_out, 1);
#endif
  coreAPI->sendToClient(sock,
		&reply->header);
  FREE(reply);
}

/**
 * Hand a 3Hash reply to the client.
 * @param sock the client socket
 * @param hc the double hash
 * @param result the response
 */
static void tellClient3HashReply(ClientHandle sock,
				 HashCode160 * hc,
				 CONTENT_Block * result) {
  AFS_CS_RESULT_3HASH * reply;
  
  reply = MALLOC(sizeof(AFS_CS_RESULT_3HASH));
  reply->header.type
    = htons(AFS_CS_PROTO_RESULT_3HASH);
  reply->header.size 
    = htons(sizeof(AFS_CS_RESULT_3HASH));
  memcpy(&reply->result,
	 result,
	 sizeof(RootNode));
  reply->hash = *hc;
#if VERBOSE_STATS
  statChange(stat_cs_reply_content_out, 1);
#endif
  coreAPI->sendToClient(sock,
			&reply->header);
  FREE(reply);
}

/**
 * Add an entry to the routing table. The lock on the ite
 * must be held and is being released.
 *
 * @param mode replace or extend an existing entry?
 * @param ite slot in the routing table that is manipulated
 * @param query the query to look for
 * @param namespace the namespace to look in (NULL for global namespace)
 * @param ttl how long to keep the new entry, relative ttl
 * @param priority how important is the new entry
 * @param sender for which node is the entry (NULL for local client)
 * @param sock for which local client is the entry (NULL for peer)
 * @return OK if sock or sender was added, SYSERR if both are NULL or existed already
 *            in the queue
 */
static int addToSlot(int mode,
		     IndirectionTableEntry * ite,
		     HashCode160 * query,
		     HashCode160 * namespace,
		     int ttl,
		     unsigned int priority,
		     PeerIdentity * sender,
		     ClientHandle sock) {
  unsigned int i;
  cron_t now;
  int ret = SYSERR;

  /* namespace handling: always override with 
     the new value (query collisions are 
     supposed to be 'impossible', so this should
     always be correct.  Either we replace the
     existing slot with something new, or it
     should not make a difference since the old 
     and the new namespace will be the same. */
  if (ite->namespace != NULL) {
    if (namespace == NULL) {
      FREE(ite->namespace);
      ite->namespace = NULL;
    } else {
      *ite->namespace = *namespace;
    }
  } else {
    if (namespace != NULL) {
      ite->namespace = MALLOC(sizeof(HashCode160));
      *ite->namespace = *namespace;
    }
  }
  cronTime(&now);
  if (mode == ITE_REPLACE) {
    GROW(ite->seen,
	 ite->seenIndex,
	 0);
    if (equalsHashCode160(query,
			  &ite->hash)) {
      statChange(stat_routingPresent, 1); 
      ite->ttl = now + ttl;
      ite->priority = priority;
    } else {
      if ( (ite->tcpsocksSize > 0) &&
	   (sender == NULL) &&
	   (ite->seenIndex == 0) ) {
#if DEBUG_ROUTING
	EncName enc;
	hash2enc(query,
		 &enc);
	LOG(LOG_DEBUG,
	    "Replacing local query '%s' without results with foreign query!\n",
	    &enc);
#endif
      }

      ite->successful_local_lookup_in_delay_loop = NO;
      /* different request, flush pending queues */
      statChange(stat_routingReplaced, 1);
      dequeueQuery(&ite->hash);
      ite->hash = *query;
      GROW(ite->destination,
	   ite->hostsWaiting,
	   0);
      GROW(ite->tcpsocks,
	   ite->tcpsocksSize,
	   0);
      ite->ttl = now + ttl;
      ite->priority = priority;      
    }
  } else { /* GROW mode */
    GNUNET_ASSERT(equalsHashCode160(query,
				    &ite->hash));
    if (sender != NULL) 
      for (i=0;i<ite->hostsWaiting;i++)
	if (equalsHashCode160(&sender->hashPubKey,
			      &ite->destination[i].hashPubKey)) {
	  sender = NULL;
	  break;
	}    
    statChange(stat_routingPresent, 1);
    if (sock != NULL) 
      for (i=0;i<ite->tcpsocksSize;i++)
	if (sock == ite->tcpsocks[i]) {
	  sock = NULL;
	  break;
	}
    if ( (sock == NULL) && 
	 (sender == NULL) ) {
      return ret; /* already there! */  
    }
    /* extend lifetime */
    if (ite->ttl < now + ttl)
      ite->ttl = now + ttl; 
    ite->priority += priority;
  }
  if (sock != NULL) { 
    for (i=0;i<ite->tcpsocksSize;i++)
      if (ite->tcpsocks[i] == sock) 
	sock = NULL;
    if (sock != NULL) {
      GROW(ite->tcpsocks,
	   ite->tcpsocksSize,
	   ite->tcpsocksSize+1);
      ite->tcpsocks[ite->tcpsocksSize-1] = sock;
      GROW(ite->seen,
	   ite->seenIndex,
	   0); /* new listener, flush "seen" list */
      ret = OK;
    }
  }
  if (sender != NULL) {
    for (i=0;i<ite->hostsWaiting;i++)
      if (equalsHashCode160(&ite->destination[i].hashPubKey,
			    &sender->hashPubKey)) {
	sender = NULL;
	break;
      }
  }
  if (sender != NULL) {
    GROW(ite->destination,
	 ite->hostsWaiting,
	 ite->hostsWaiting+1);
    ite->destination[ite->hostsWaiting-1] = *sender;
    ret = OK;
    /* again: new listener, flush seen list */
    GROW(ite->seen,
	 ite->seenIndex,
	 0);
  }
  return ret;
}

/**
 * Find out, if this query is already pending. If the ttl of
 * the new query is higher than the ttl of an existing query,
 * NO is returned since we should re-send the query.<p>
 *
 * If YES is returned, the slot is also marked as used by
 * the query and the sender (HostId or socket) is added.<p>
 *
 * This method contains a heuristic that attempts to do its best to
 * route queries without getting too many cycles, send a query and
 * then drop it from the routing table without sending a response,
 * etc.  Before touching this code, definitely consult Christian
 * (grothoff@cs.purdue.edu) who has put more bugs in these five lines
 * of code than anyone on this planet would think is possible.
 *
 *
 * @param query the hash to look for
 * @param namespace the namespace to look in, NULL for the global namespace
 * @param ttl how long would the new query last 
 * @param priority the priority of the query
 * @param sender which peer transmitted the query? (NULL for this peer)
 * @param sock which client transmitted the query? (NULL for other peer)
 * @param isRouted set to OK if we can route this query, SYSERR if we can not
 * @param doForward is set to OK if we should forward the query, SYSERR if not
 * @return a case ID for debugging
 */
static int needsForwarding(HashCode160 * query,
			   HashCode160 * namespace,
			   int ttl,
			   unsigned int priority,
			   PeerIdentity * sender,
			   ClientHandle sock,
			   int * isRouted,
			   int * doForward) {
  IndirectionTableEntry * ite;
  cron_t now;

  cronTime(&now);
  ite = &ROUTING_indTable_[computeRoutingIndex(query)];
  /* released either in here or by addToSlot! */

  if ( ( ite->ttl < now - TTL_DECREMENT * 10) &&
       ( ttl > - TTL_DECREMENT * 5) ) {
    addToSlot(ITE_REPLACE, ite, query, namespace, ttl, priority, sender, sock);
    *isRouted = YES;
    *doForward = YES;
    return 21; 
  }
  if ( ( ttl < 0) &&
       (equalsHashCode160(query,
			  &ite->hash) ) ) {
    /* if ttl is "expired" and we have
       the exact query pending, route 
       replies but do NOT forward _again_! */
#if DEBUG_ROUTING
    LOG(LOG_INFO,
	"GROW: ttl < 0 and existing query is equal (%d, %d)\n",
	ttl, 
	(int) (ite->ttl - now));
#endif
    addToSlot(ITE_GROW, ite, query, namespace, ttl, priority, sender, sock);
    *isRouted = NO; /* don't go again, we are not even going to reset the seen
		       list, so why bother looking locally again, if we would find
		       something, the seen list would block sending the reply anyway
		       since we're not resetting that (ttl too small!)! */
    *doForward = NO;
    return 0; 
  }
 
  if ( (ite->ttl + (TTL_DECREMENT * coreAPI->estimateNetworkSize()) < 
	(cron_t)(now + ttl)) &&
       (ite->ttl < now) ) { 
    /* expired AND is significantly (!) 
       longer expired than new query */
#if DEBUG_ROUTING
    LOG(LOG_INFO,
	"REPLACE and reset SEEN: existing query "
	"expired and older than new query (%d, %d)\n",
	ttl, 
	(int) (ite->ttl - now));
#endif
    /* previous entry relatively expired, start using the slot --
       and kill the old seen list!*/
    GROW(ite->seen,
	 ite->seenIndex,
	 0);
    if ( equalsHashCode160(query,
			   &ite->hash) &&
	 (YES == ite-> successful_local_lookup_in_delay_loop) ) {
      *isRouted = NO;
      *doForward = NO;    
      addToSlot(ITE_GROW, ite, query, namespace, ttl, priority, sender, sock);
      return 1;
    } else {
      *isRouted = YES;
      *doForward = YES;    
      addToSlot(ITE_REPLACE, ite, query, namespace, ttl, priority, sender, sock);
      return 2;
    }
  }
  if (equalsHashCode160(query,
			&ite->hash) ) {
    if (ite->seenIndex == 0) {
      /* can not tell if CHK/3HASH/NSQUERY */
      if (ite->ttl + TTL_DECREMENT < (cron_t)(now + ttl)) { /* ttl of new is SIGNIFICANTLY
							       longer? */
	/* query again */
#if DEBUG_ROUTING
	LOG(LOG_INFO,
	    "REPLACE (seen was empty): existing query and TTL higher (%d, %d)\n",
	    (int) (ite->ttl - now),
	    ttl);
#endif
	addToSlot(ITE_REPLACE, ite, query, namespace, ttl, priority, sender, sock);
	if (YES == ite->successful_local_lookup_in_delay_loop) {
	  *isRouted = NO; /* don't go again, we are already processing a local lookup! */
	  *doForward = NO;
	  return 3;
	} else {
	  *isRouted = YES;
	  *doForward = YES;
	  return 4;
	}
      } else {
	/* new TTL is lower than the old one, thus
	   just wait for the reply that may come back */
#if DEBUG_ROUTING
	LOG(LOG_INFO,
	    "GROW - equal existing query exists without replies (%d, %d)\n",
	    (int) (ite->ttl - now),
	    ttl);	    
#endif
	if (OK == addToSlot(ITE_GROW, ite, query, namespace, ttl, priority, sender, sock)) {
	  if (YES == ite->successful_local_lookup_in_delay_loop) {
	    *isRouted = NO; /* don't go again, we are already processing a local lookup! */
	    *doForward = NO;
	    return 5;
	  } else {
	    *isRouted = YES;
	    *doForward = NO;
	    return 6;
	  }
	} else {
	  *isRouted = NO; /* same query with _higher_ TTL has already been
			     processed FOR THE SAME recipient! Do NOT do
			     the lookup *again*. */
	  *doForward = NO;
	  return 7;
	}
      }      
    }
    /* ok, seen reply before, can judge type of query! */

    /* pending == new! */
    if ( equalsHashCode160(&ite->hash,
			   &ite->seen[0]) &&
	 (ite->namespace == NULL) ) { /* CHK */
      if (ite->ttl < (cron_t)(now + ttl)) { /* ttl of new is longer? */
	/* go again */
	GROW(ite->seen,
	     ite->seenIndex,
	     0);
#if DEBUG_ROUTING
	LOG(LOG_INFO,
	    "REPLACE and reset SEEN: existing query equal "
	    "but we've seen the response already (%d, %d)\n",
	    (int) (ite->ttl - now),
	    ttl);
#endif
	addToSlot(ITE_REPLACE, ite, query, namespace, ttl, priority, sender, sock);
	if (YES == ite->successful_local_lookup_in_delay_loop) {
	  *isRouted = NO; /* don't go again, we are already processing a local lookup! */
	  *doForward = NO;
	  return 8;
	} else {
	  *isRouted = YES; 
	  /* only forward if new TTL is significantly higher */
	  if (ite->ttl + TTL_DECREMENT < (cron_t)(now + ttl)) 
	    *doForward = YES;
	  else
	    *doForward = NO;
	  return 9;
	}
      } else {
	/* new TTL is lower than the old one, thus
	   just wait for the reply that may come back */
#if DEBUG_ROUTING
	LOG(LOG_INFO,
	    "GROW - equal existing query exists without replies (%d, %d)\n",
	    (int) (ite->ttl - now),
	    ttl);	    
#endif
	if (OK == addToSlot(ITE_GROW, ite, query, namespace, ttl, priority, sender, sock)) {
	  if (YES == ite->successful_local_lookup_in_delay_loop) {
	    *isRouted = NO;
	    *doForward = NO;
	    return 10;
	  } else {
	    *isRouted = YES; 
	    *doForward = NO;
	    return 11;
	  }
	} else {
	  *isRouted = NO; 
	  *doForward = NO;
	  return 12;
	}
      }
    } else { /* 3HASH or SQUERY, multiple results possible! */
      /* It's a pending 3HASH or SQUERY that can have multiple 
	 replies.  Do not re-send, just forward the
	 answers that we get from now on to this additional
	 receiver */
      int isttlHigher;
#if DEBUG_ROUTING
      LOG(LOG_INFO,
	  "GROW - equal existing query exists without replies (%d, %d)\n",
	  (int) (ite->ttl - now), 
	  ttl);	    
#endif
      if (ite->ttl < (cron_t) now+ttl)
	isttlHigher = NO;
      else
	isttlHigher = YES;
      if (OK == addToSlot(ITE_GROW, ite, query, namespace, ttl, priority, sender, sock)) {
	*isRouted = YES;
	*doForward = NO;
	return 13;
      } else {
	*isRouted = isttlHigher; /* receiver is the same as the one that already got the
				    answer, do not bother to do this again, IF
				    the TTL is not higher! */
	*doForward = NO;
	return 14;
      }
    }
  } 
  /* a different query that is expired a bit longer is using
     the slot; but if it is a CHK query that has received
     a response already, we can eagerly throw it out 
     anyway, since the request has been satisfied 
     completely */
  if ( (ite->ttl + TTL_DECREMENT < (cron_t)(now + ttl) ) &&
       (ite->ttl < now) && 
       (ite->seenIndex == 1) &&
       (ite->namespace == NULL) &&
       (equalsHashCode160(&ite->hash,
			  &ite->seen[0])) ) {
    /* is CHK and we have seen the answer, get rid of it early */
#if DEBUG_ROUTING
    EncName old;
    IFLOG(LOG_INFO,
	  hash2enc(&ite->hash,
		   &old));
    LOG(LOG_INFO,
	"CHK '%s' with reply already seen, replacing eagerly (%d, %d).\n",
	&old,
	(int) (ite->ttl - now),
	ttl);	    
#endif
    addToSlot(ITE_REPLACE, ite, query, namespace, ttl, priority, sender, sock);
    *isRouted = YES;
    *doForward = YES;
    return 15;
  }   
  /* Another still valid query is using the slot.  Now we need a _really_
     good reason to discard it... */
  if (ttl < 0) {
    *isRouted = NO;
    *doForward = NO;
    return 16; /* if new ttl is "expired", don't bother with priorities */
  }

  /* Finally try to find a _strong_ reason looking at priority/ttl
     relationships to replace the existing query. A low ttl with high
     priority should be preferred, so we do a cross-multiplication
     (!). Also, we want a _strong_ reason, so we add a "magic" factor
     of 10 for the additional work that the replacement would make
     (the network needs a certain amount of resilience to changes in
     the routing table, otherwise it might happen that query A
     replaces query B which replaces query A which could happen so
     quickly that no response to either query ever makes it through...
  */
  if ( (long long)((ite->ttl - now) * priority) > 
       (long long) 10 * (ttl * ite->priority) ) {
#if DEBUG_ROUTING
    LOG(LOG_INFO,
	"priority of new query is much higher, overriding (%d, %d).\n",
	(int) (ite->ttl - now), 
	ttl);	    
#endif
    addToSlot(ITE_REPLACE, ite, query, namespace, ttl, priority, sender, sock);
    *isRouted = YES;
    *doForward = YES;
    return 17;
  } 
  if (randomi(TIE_BREAKER_CHANCE) == 0) {
#if DEBUG_ROUTING
    LOG(LOG_INFO,
	"TIE-BREAKER.  Overriding (%d, %d).\n",
	(int) (ite->ttl - now), 
	ttl);	    
#endif
    addToSlot(ITE_REPLACE, ite, query, namespace, ttl, priority, sender, sock);
    *isRouted = YES;
    *doForward = YES;
    return 20;
  } 
  /* sadly, the slot is busy with something else; we can 
     not even add ourselves to the reply set */
  statChange(stat_routingFull, 1);
  *isRouted = NO;
  *doForward = NO;
#if DEBUG_ROUTING
  {
    EncName enc;
    hash2enc(&ite->hash, 
	     &enc);
    LOG(LOG_INFO,
	"Existing %s query '%s' (%d) is more important (EP: %d, ET: %d; NP: %d, NT: %d)\n",
	(ite->tcpsocksSize == 0) ? "remote" : "local", 
	&enc,
	computeRoutingIndex(&ite->hash),
	ite->priority,
	ite->ttl - now,
	priority,
	ttl);
  }
#endif

  return 18;
}

/**
 * Send a reply to a host.  Distinguishes between local and remote
 * delivery, converts the reply into the appropriate format and sends
 * it out.
 *
 * @param ite the matching slot in the indirection table
 * @param msg the message to route
 */
static void sendReply(IndirectionTableEntry * ite,
		      const p2p_HEADER * msg) {
  unsigned int j;
  unsigned int maxDelay;
  cron_t now;
   
  cronTime(&now);
  if (now < ite->ttl)
    maxDelay = ite->ttl - now;
  else
    maxDelay = TTL_DECREMENT; /* for expired queries */
  /* send to peers */  
  for (j=0;j<ite->hostsWaiting;j++)
    coreAPI->sendToNode(&ite->destination[j],
			msg, 
			BASE_REPLY_PRIORITY *
			(ite->priority+1), 
			/* weigh priority */
			maxDelay);    
  for (j=0;j<ite->tcpsocksSize;j++) {
    switch (ntohs(msg->type)) {
    case AFS_p2p_PROTO_3HASH_RESULT:
      tellClient3HashReply(ite->tcpsocks[j],
			   &((AFS_p2p_3HASH_RESULT*)msg)->hash,
			   (CONTENT_Block*)&((AFS_p2p_3HASH_RESULT*)msg)->result);
      break;
    case AFS_p2p_PROTO_CHK_RESULT:
      tellClientCHKReply(ite->tcpsocks[j],
			 &((AFS_p2p_CHK_RESULT*)msg)->result);
      break;
    case AFS_p2p_PROTO_SBLOCK_RESULT:
      tellClientSBLOCKReply(ite->tcpsocks[j],
			    &((AFS_p2p_SBLOCK_RESULT*)msg)->result);
      break;
    default:
      LOG(LOG_WARNING,
	  _("Search result has unexpected type %d at %s:%d.\n"),
	  ntohs(msg->type),
	  __FILE__, __LINE__);
      break;
    }    
  }
}
 
/**
 * TCP connection is shut down, cancel all replies to that client.
 */
static void cancelTCP_routing(ClientHandle sock) {
  unsigned int i;
  unsigned int j;
  IndirectionTableEntry * ite;

  for (i=0;i<indirectionTableSize;i++) {
    ite = &ROUTING_indTable_[i];  
    MUTEX_LOCK(&ite->lookup_exclusion);
    for (j=0;j<ite->tcpsocksSize;j++)
      if (ite->tcpsocks[j] == sock) {
	ite->tcpsocks[j] 
	  = ite->tcpsocks[--ite->tcpsocksSize];
	/* we don't shrink, not worth it */
      }
    MUTEX_UNLOCK(&ite->lookup_exclusion);  
  }
}

/**
 * Execute a single query. Tests if the query can be routed. If yes, 
 * the query is added to the routing table and the content is looked 
 * for locally. If the content is available locally, a deferred 
 * response is simulated with a cron job and the local content is 
 * marked as valueable. The method returns OK if the query should 
 * subsequently be routed to other peers.
 *
 * @param sender next hop in routing of the reply
 * @param sock client socket if we are ultimate receiver
 * @param prio the effective priority of the query
 * @param ttl the relative ttl of the query
 * @param query the query itself
 * @param superHash YES if the super-hash test has indicated that we#
 *        have a reply locally available
 * @return OK if the query should be routed further, SYSERR if not.
 */
static int execSingleQuery(PeerIdentity * sender,
			   ClientHandle sock,
			   unsigned int prio,
			   int ttl,
			   HashCode160 * query,
			   int superHash) {
  ContentIndex ce;
  CONTENT_Block * result;
  int len;  
  int isRouted;
  int doForward;
  IndirectionTableEntry * ite;
  int nfCase;

  ite = &ROUTING_indTable_[computeRoutingIndex(query)];
  MUTEX_LOCK(&ite->lookup_exclusion); 
  nfCase = needsForwarding(query,
			   NULL,
			   ttl,
			   prio,
			   sender,
			   sock,
			   &isRouted,
			   &doForward); 
#if DEBUG_ROUTING
  {
    EncName enc;
    hash2enc(query,
	     &enc);
    LOG(LOG_DEBUG,
	"needsForwarding decided for %s query %s (%d, ttl %d, pri %d): case %d (%s, %s)\n",
	(sock == NULL) ? "remote" : "LOCAL",
	&enc,
	computeRoutingIndex(query),
	ttl,
	prio,
	nfCase,
	doForward ? "FWD" : "",
	isRouted ? "ROUTE" : "");
  }
#endif
  if ( (sender != NULL) && 
       (isRouted != YES) ) {
    MUTEX_UNLOCK(&ite->lookup_exclusion);
    return SYSERR; /* if we can't route, 
		      forwarding never makes
		      any sense */
  }

  if ( (NO == superHash) &&
       (NO == testBloomfilter(singleBloomFilter,
			      query)) ) {
    MUTEX_UNLOCK(&ite->lookup_exclusion);
    return doForward; /* content not available locally,
			 just route */
  }
  result = NULL;
  len = retrieveContent(query,
			&ce,
			(void**)&result,
			prio,
			sender == NULL);
  if (len == -1) {
    MUTEX_UNLOCK(&ite->lookup_exclusion);
    return doForward; /* bloomfilter was wrong, content not there */
  } else {
    HashCode160 hc;

    if (len == sizeof(CONTENT_Block)) {
      hash(result,
	   len,
	   &hc);
      if (ite->seenIndex > 0) {
	if (equalsHashCode160(&hc,
			      &ite->seen[0])) {
	  LOG(LOG_WARNING,
	      _("Lookup produced result already seen. Case: %d\n"),
	      nfCase);
	}
      }
    }
  }

  if (sender != NULL) {
    if (ntohs(ce.type) == LOOKUP_TYPE_3HASH) {
      if (NO == checkAnonymityPolicy(AFS_CS_PROTO_RESULT_3HASH,
				     sizeof(AFS_p2p_3HASH_RESULT))) {
	FREENONNULL(result);
	MUTEX_UNLOCK(&ite->lookup_exclusion);
	return doForward; /* policy says: no direct response, but
			     routing is ok! */
      }
    } else {
      if (NO == checkAnonymityPolicy(AFS_CS_PROTO_RESULT_CHK,
				     sizeof(AFS_p2p_CHK_RESULT))) {
	FREENONNULL(result);
	MUTEX_UNLOCK(&ite->lookup_exclusion);
	return doForward; /* policy says: no direct response, but 
			     routing is ok */
      }
    }
  }
  switch (ntohs(ce.type)) {
  case LOOKUP_TYPE_CHK:
  case LOOKUP_TYPE_CHKS:
    if (len != sizeof(CONTENT_Block)) {
      BREAK();
      break;
    }
    if (sock != NULL) {
      tellClientCHKReply(sock,
			 result);
      doForward = SYSERR; /* purely local handling! */
    }
    if (sender != NULL) 
      queueCHKReply(sender,
		    result);
    doForward = SYSERR; /* we have the one and only answer */
    break;
  case LOOKUP_TYPE_3HASH: {
    unsigned int i;
    int rcount;

    rcount = len / sizeof(CONTENT_Block);
    if (rcount * sizeof(CONTENT_Block) != (unsigned int) len) {
      BREAK();
      break;
    }
    if (sock != NULL)
      for (i=0;i<(unsigned int)rcount;i++)
	tellClient3HashReply(sock,
			     &ce.hash,
			     &result[i]);
    if (sender != NULL) 
      for (i=0;i<(unsigned int)rcount;i++)
        queue3HashReply(sender,
		        &ce.hash,
		        &result[i]);    
    break;
  }
  default:
    LOG(LOG_DEBUG,
	_("Lookup produced unexpected type %d!\n"),
	ntohs(ce.type));
    break;
  }
  MUTEX_UNLOCK(&ite->lookup_exclusion);    
  FREENONNULL(result);
  return doForward;
}


/**
 * Execute a namespace query. Tests if the query can be routed. If yes, 
 * the query is added to the routing table and the content is looked 
 * for locally. If the content is available locally, a deferred 
 * response is simulated with a cron job and the local content is 
 * marked as valueable. The method returns OK if the query should 
 * subsequently be routed to other peers.
 *
 * @param sender next hop in routing of the reply
 * @param sock client socket if we are ultimate receiver
 * @param prio the effective priority of the query
 * @param ttl the relative ttl of the query
 * @param query the query itself
 * @param namespace for which namespace
 * @return OK if the query should be routed further, SYSERR if not.
 */
static int execNSQuery(PeerIdentity * sender,
		       ClientHandle sock,
		       unsigned int prio,
		       int ttl,
		       HashCode160 * query,
		       HashCode160 * namespace) {
  ContentIndex ce;
  SBlock * result;
  int len;  
  HashCode160 hc;
#if DEBUG_ROUTING
  EncName enc1;
  EncName enc2;
#endif
  int isRouted;
  int doForwarding;
  int k;
  IndirectionTableEntry * ite;
  
#if DEBUG_ROUTING
  IFLOG(LOG_DEBUG,
	hash2enc(query,
		 &enc1));
  IFLOG(LOG_DEBUG,
	hash2enc(namespace,
		 &enc2));
  LOG(LOG_DEBUG,
      "received NS query for %s/%s\n",
      &enc2,
      &enc1);
#endif
  ite = &ROUTING_indTable_[computeRoutingIndex(query)];  
  MUTEX_LOCK(&ite->lookup_exclusion); 
  needsForwarding(query,
		  namespace,
		  ttl,
		  prio,
		  sender,
		  sock,
		  &isRouted,
		  &doForwarding);
  MUTEX_UNLOCK(&ite->lookup_exclusion); 
  if (SYSERR == isRouted)
    return SYSERR;
  if (NO == testBloomfilter(singleBloomFilter,
			    query)) {
#if DEBUG_ROUTING
    LOG(LOG_DEBUG,
	"Bloomfilter test says content is not available locally.\n");
#endif
    return doForwarding; /* content not available locally,
			    just route */
  }

  result = NULL;
  len = retrieveContent(query,
			&ce,
			(void**)&result,
			prio,
			sender == NULL);
  if (len == -1) {
#if DEBUG_ROUTING
    LOG(LOG_DEBUG,
	"Bloomfilter test was wrong, DB lookup did not succeed.\n");
#endif
    return doForwarding; /* bloomfilter was wrong, content not there */
  }
  if (ntohs(ce.type) != LOOKUP_TYPE_SBLOCK) {
    FREE(result);
    return doForwarding;
  }
  if (sender != NULL)
    if (NO == checkAnonymityPolicy(AFS_CS_PROTO_RESULT_SBLOCK,
				   sizeof(AFS_p2p_SBLOCK_RESULT))) {
#if DEBUG_ROUTING
      LOG(LOG_DEBUG,
	  "Anonymity policy denies sending a reply at this time.\n");
#endif
      FREE(result);
      return doForwarding; /* policy says: no direct response, but 
			      routing is ok */  
    }
  if (0 != (len % sizeof(CONTENT_Block))) {
    BREAK();
    FREE(result);
    return doForwarding;
  }
  
  for (k=(len/sizeof(CONTENT_Block))-1;k>=0;k--) {
    hash(&result[k].subspace,
	 sizeof(PublicKey),
	 &hc);
    if (! equalsHashCode160(namespace,
			    &hc)) {
      LOG(LOG_WARNING,
	  _("Namespace mismatch at %s:%d (should be rare but can theoretically happen).\n"),
	  __FILE__, __LINE__);
      FREE(result);
      return doForwarding;
    }
    if (sender != NULL)
      queueSBLOCKReply(sender,
		       &result[k]);
    if (sock != NULL) {
      tellClientSBLOCKReply(sock,
			    &result[k]);
      doForwarding = SYSERR;
    }
  }
  FREENONNULL(result);
  return doForwarding;
}

 
/* ****************** public methods ****************** */

/**
 * Initialize routing module (initializes indirection table)
 */
void initRouting() {
  unsigned int i;

  random_qsel = randomi(sizeof(HashCode160)/sizeof(int));
#if VERBOSE_STATS
  stat_cs_reply_content_out 
    = statHandle(_("# kb downloaded by clients"));
  stat_delaytime_route_replacement
    = statHandle(_("# routing-table entry replaced during delaytime"));
  stat_concurrent_route_replacement
    = statHandle(_("# routing-table entry replaced during lookup"));
#endif
  stat_content_in_ok
    = statHandle(_("# kb ok content in"));
  stat_content_in_dupe
    = statHandle(_("# kb dupe content in"));
  stat_content_in_orphan
    = statHandle(_("# kb orphan or pushed content in"));
  stat_routingFull
    = statHandle(_("# routing table full"));
  stat_routingReplaced
    = statHandle(_("# routing table entry replaced"));
  stat_routingPresent
    = statHandle(_("# routing table entry already in place"));
  stat_p2p_query_out
    = statHandle(_("# p2p queries sent"));
  indirectionTableSize =
    getConfigurationInt("AFS",
    			"INDIRECTIONTABLESIZE");
  if (indirectionTableSize < MIN_INDIRECTION_TABLE_SIZE)
    indirectionTableSize = MIN_INDIRECTION_TABLE_SIZE;
  i = 1;
  while (i < indirectionTableSize)
    i*=2;
  indirectionTableSize = i; /* make sure it's a power of 2 */
#if DEBUG_ROUTING
  LOG(LOG_DEBUG,
      "Set indirectiontablesize to %d\n",
      indirectionTableSize);
#endif
  ROUTING_indTable_ 
    = MALLOC(sizeof(IndirectionTableEntry)*
	     indirectionTableSize);
  for (i=0;i<indirectionTableSize;i++) {
    ROUTING_indTable_[i].namespace = NULL;
    ROUTING_indTable_[i].ttl = 0; /* expired / free */  
    ROUTING_indTable_[i].seenIndex = 0;
    ROUTING_indTable_[i].seen = NULL;
    ROUTING_indTable_[i].hostsWaiting = 0; /* expired / free */  
    ROUTING_indTable_[i].destination = NULL;
    ROUTING_indTable_[i].tcpsocksSize = 0;
    ROUTING_indTable_[i].tcpsocks = NULL;
    ROUTING_indTable_[i].successful_local_lookup_in_delay_loop = NO;
    MUTEX_CREATE(&ROUTING_indTable_[i].lookup_exclusion);
  }
  coreAPI->registerClientExitHandler(&cancelTCP_routing);
#if DEBUG_WRITE_INDTABLE
  addCronJob((CronJob)writeIDtable,
  	     0,
	     60*cronSECONDS,
	     NULL);
#endif
}

/**
 * Shutdown the routing module.
 */
void doneRouting() {
  unsigned int i;

  for (i=0;i<indirectionTableSize;i++) {
    MUTEX_DESTROY(&ROUTING_indTable_[i].lookup_exclusion);
    FREENONNULL(ROUTING_indTable_[i].namespace);
    ROUTING_indTable_[i].namespace = NULL;
    GROW(ROUTING_indTable_[i].seen, 
	 ROUTING_indTable_[i].seenIndex, 
	 0);
    GROW(ROUTING_indTable_[i].destination, 
	 ROUTING_indTable_[i].hostsWaiting,
	 0);
    GROW(ROUTING_indTable_[i].tcpsocks,
	 ROUTING_indTable_[i].tcpsocksSize,
	 0);	 
  }
  coreAPI->unregisterClientExitHandler(&cancelTCP_routing);
  FREE(ROUTING_indTable_);

#if DEBUG_WRITE_INDTABLE
  delCronJob((CronJob)writeIDtable,
	     60*cronSECONDS,
	     NULL);
#endif
}

/**
 * Print the routing table.
 */
void printRoutingTable() {
  unsigned int i;
  IndirectionTableEntry * ite;
  EncName h1;
  cron_t now;

  cronTime(&now);
  LOG(LOG_MESSAGE,
      "Routing TABLE:\n");
  for (i=0;i<indirectionTableSize;i++) {
    ite = &ROUTING_indTable_[i];  
    MUTEX_LOCK(&ite->lookup_exclusion); 
    IFLOG(LOG_MESSAGE,
	  hash2enc(&ite->hash, 
		   &h1));
    /* if (ite->ttl >= now)*/
    LOG(LOG_DEBUG,
	"%u: hash %s ttl %ds "
	"hostsWaiting %d prio %d seenIndex: %d\n", 
	i,
	&h1, 
	(int) (((long long) ite->ttl - (long long)now)/cronSECONDS),
	ite->hostsWaiting,
	ite->priority,
	ite->seenIndex);
    MUTEX_UNLOCK(&ite->lookup_exclusion); 
  }    
}

/**
 * Execute the query. <p>
 *
 * Execute means to test if we can route the query (or, in the case
 * of a multi-query, any of the sub-queries). If yes, we lookup the
 * content locally and potentially route it deferred. Regardless if
 * the content was found or not, the queries that we can route are
 * forwarded to other peers (by the querymanager code).<p>
 *
 * The decision if we can route is made by "needsForwarding". Note that
 * queries that we are already routing do not "need forwarding". If
 * we do route the query, execQuery decides if we are going to do source
 * rewriting or not.<p>
 *
 * If we route a query, execSingleQuery will use the bloom filters and
 * the databases to locate the content and queue a cron job that will
 * pass the response to "useContent" as if it came from another peer.
 * Note that if the query originated from a local client, the response
 * is instant (no cron job scheduled).
 * 
 * @param qp the polciy (priority) for the query
 * @param msg the query message (with host identity for the reply)
 * @param sock the TCP socket to send the answer to if it is
 *        a query from the local host, otherwise NULL.
 * @return OK if the query was routed (at least in part), SYSERR if it was dropped
 */
int execQuery(QUERY_POLICY qp, 
	      AFS_p2p_QUERY * msg,
	      ClientHandle sock) {  
  PeerIdentity * sender;
#if DEBUG_ROUTING
  EncName queryEnc;
#endif
  PeerIdentity senderCpy;
  unsigned int prio;
  int count;
  int routeCount;

  count = (ntohs(msg->header.size)-sizeof(AFS_p2p_QUERY)) / sizeof(HashCode160);
  prio = ntohl(msg->priority) / count; /* per-query priority */

  /* source rewriting (or not...) */
  if (sock == NULL) {
    if (equalsHashCode160(&msg->returnTo.hashPubKey,
			  &coreAPI->myIdentity->hashPubKey))
      return SYSERR; /* A to B, B sends back to A without (!) source rewriting,
			in this case, A must just drop */
    senderCpy = msg->returnTo;
    sender = &senderCpy;
  } else {
    sender = NULL;
    senderCpy = *(coreAPI->myIdentity);
  }
  if ((qp & QUERY_INDIRECT) > 0) {
    msg->returnTo = *(coreAPI->myIdentity);
  } else {
    msg->priority = ntohl(0);  
  }

#if DEBUG_ROUTING
  IFLOG(LOG_INFO,
	hash2enc(&((AFS_p2p_QUERY_GENERIC*)msg)->queries[0],
		 &queryEnc));
  LOG(LOG_INFO,
      "received %d-query %s with ttl %d and priority %u\n",
      count,
      &queryEnc,
      ntohl(msg->ttl),
      ntohl(msg->priority));
#endif
  if (ntohs(msg->header.type) == AFS_p2p_PROTO_NSQUERY) {
    if (OK == execNSQuery(sender,
			  sock,
			  prio,
			  ntohl(msg->ttl),
			  &((AFS_p2p_NSQUERY*)msg)->identifier,
			  &((AFS_p2p_NSQUERY*)msg)->namespace))
      routeCount = 2; /* NAMESPACE + IDENTIFIER! */
    else
      routeCount = 0;  
  } else {
    if (count > 1) { /* MUTLI-QUERY, take apart for individual
			routing, but reassemble for forwarding */
      int i;
      int superBF;
      
      superBF = testBloomfilter(superBloomFilter,
				&((AFS_p2p_QUERY_GENERIC*)msg)->queries[0]);
      routeCount = 1;
      for (i=1;i<count;i++) {
	if (OK == execSingleQuery(sender,
				  sock,
				  prio,
				  ntohl(msg->ttl),
				  &((AFS_p2p_QUERY_GENERIC*)msg)->queries[i],
				  superBF)) {
	  /* route this query! */
	  ((AFS_p2p_QUERY_GENERIC*)msg)->queries[routeCount] 
                 = ((AFS_p2p_QUERY_GENERIC*)msg)->queries[i];
	  routeCount++;
	}
      }
      if (routeCount == 1)
	routeCount = 0; /* nothing to forward */
    } else { /* single query or 3hash search */
      if (OK == execSingleQuery(sender,
				sock,
				prio,
				ntohl(msg->ttl),
				&((AFS_p2p_QUERY_GENERIC*)msg)->queries[0],
				NO))
	routeCount = 1;
      else
	routeCount = 0;
    }
  }

  if (routeCount >= 1) {
#if DEBUG_ROUTING
    EncName enc;
#endif
    statChange(stat_p2p_query_out, routeCount);
    msg->header.size = htons(sizeof(AFS_p2p_QUERY) + 
			     routeCount * sizeof(HashCode160));
    forwardQuery(msg, 
		 (sock == NULL) ? sender : NULL,
		 sock);
#if DEBUG_ROUTING
    hash2enc(&((AFS_p2p_QUERY_GENERIC*)msg)->queries[0],
	     &enc);
    LOG(LOG_DEBUG,
	"slots free in routing table for %s query '%s'; forwarded %d out of %d queries\n",
	(sock == NULL) ? "remote" : "local",
	&enc,
	routeCount, 
	count);
#endif
    return OK;
  } else {
    
#if DEBUG_ROUTING
    EncName enc;

    hash2enc(&((AFS_p2p_QUERY_GENERIC*)msg)->queries[0],
	     &enc);
    LOG(LOG_DEBUG,
	"0 slots free in routing table for %s query '%s' with %d hash codes, none forwarded.\n",
	(sock == NULL) ? "remote" : "local",
	&enc,
	count);
#endif
    return SYSERR;
  }
}

/**
 * Content has arrived. We must decide if we want to a) forward it to
 * our clients b) indirect it to other nodes. The routing module
 * should know what to do.  This method checks the routing table if
 * we have a matching route and if yes queues the reply. It also makes
 * sure that we do not send the same reply back on the same route more
 * than once.
 *
 * @param hostId who sent the content? NULL for locally found content.
 * @param queryHash either the triple hash or the CHK of the content
 * @param msg the p2p reply to send 
 * @return how good this content was (effective priority of the original request)
 */
int useContent(const PeerIdentity * hostId,
	       const HashCode160 * queryHash,
	       const p2p_HEADER * msg) {
  unsigned int i;
  CONTENT_Block * content;
  HashCode160 contentHC;
  IndirectionTableEntry * ite;
  int prio = -1;
  cron_t now;
  EncName enc;
  EncName peer;
  
  /*LOG(LOG_DEBUG,
      " useContent - prints routing table\n");
      printRoutingTable();*/
  IFLOG(LOG_DEBUG,
	hash2enc(queryHash, &enc));
  if (hostId != NULL)
    hash2enc(&hostId->hashPubKey, &peer);
#if DEBUG_ROUTING
  LOG(LOG_DEBUG, 
      "received content %s from peer %s\n",
      &enc,
      (hostId == NULL) ? "self" : (char*)&peer);
#endif

  cronTime(&now);
  ite = &ROUTING_indTable_[computeRoutingIndex(queryHash)];
  MUTEX_LOCK(&ite->lookup_exclusion);

  if (!equalsHashCode160(&ite->hash,
			 queryHash) ) {	
    statChange(stat_content_in_orphan, 1);
    MUTEX_UNLOCK(&ite->lookup_exclusion);
#if DEBUG_ROUTING
    hash2enc(queryHash,
	     &enc);
    LOG(LOG_DEBUG, 
	"no matching query pending for content %s (not indirected)\n",
	&enc);
#endif
    return 0; /* no indirection pending: was useless */
  }
  

  switch (ntohs(msg->type)) {
  case AFS_p2p_PROTO_3HASH_RESULT:
    content = (CONTENT_Block*) &((AFS_p2p_3HASH_RESULT*)msg)->result;
    if (ite->namespace != NULL) {
      MUTEX_UNLOCK(&ite->lookup_exclusion);
      return 0;
    }
    break;
  case AFS_p2p_PROTO_CHK_RESULT:
    dequeueQuery(&ite->hash);
    content = &((AFS_p2p_CHK_RESULT*)msg)->result;
    if (ite->namespace != NULL) {
      MUTEX_UNLOCK(&ite->lookup_exclusion);
      return 0;
    }
    /* remove the sender from the waiting list
       (if the sender was waiting for a response) */
    if (hostId != NULL)
      for (i=0;i<ite->hostsWaiting;i++) {
	if (equalsHashCode160(&hostId->hashPubKey,
			      &ite->destination[i].hashPubKey)) {
	  ite->destination[i] = ite->destination[ite->hostsWaiting-1];
	  GROW(ite->destination,
	       ite->hostsWaiting,
	       ite->hostsWaiting - 1);
	}			  
      }

    break;
  case AFS_p2p_PROTO_SBLOCK_RESULT:
    content = (CONTENT_Block*) &((AFS_p2p_SBLOCK_RESULT*)msg)->result;
    if (ite->namespace == NULL) {
      MUTEX_UNLOCK(&ite->lookup_exclusion);
      return 0;
    } else {
      HashCode160 hc;
      hash(&((AFS_p2p_SBLOCK_RESULT*)msg)->result.subspace,
	   sizeof(PublicKey),
	   &hc);
      if (! equalsHashCode160(ite->namespace,
			      &hc) ) {
	MUTEX_UNLOCK(&ite->lookup_exclusion);
	return 0;
      }
    }
    break;
  default:
    LOG(LOG_WARNING,
	_("Result has unexpected type %d at %s:%d.\n"),
	ntohs(msg->type),
	__FILE__, __LINE__);
    MUTEX_UNLOCK(&ite->lookup_exclusion);
    return 0;
  }
  hash(content,
       sizeof(CONTENT_Block),
       &contentHC);

  for (i=0;i<ite->seenIndex;i++) {
    if (equalsHashCode160(&contentHC,
			  &ite->seen[i])) {
      statChange(stat_content_in_dupe, 1);
#if DEBUG_ROUTING
      LOG(LOG_DEBUG, 
	  "Content is not new (slot: %d).\n",
	  computeRoutingIndex(queryHash)); 
#endif
      MUTEX_UNLOCK(&ite->lookup_exclusion);
      return 0; /* seen before, useless */
    }
  }
  /* new reply, adjust credits! */
  if (hostId != NULL) /* if we are the sender, hostId will be NULL */
    coreAPI->changeTrust(hostId, ite->priority);
  prio = ite->priority;
  ite->priority = 0; /* no priority for further replies,
			because we don't get paid for those... */
#if DEBUG_ROUTING
  IFLOG(LOG_DEBUG,
	hash2enc(&ite->hash,
		 &enc));
  LOG(LOG_DEBUG, 
      "Indirecting new content matching query '%s'.\n",
      &enc);
#endif

  for (i=0;i<ite->tcpsocksSize;i++)
    updateResponseData(NULL,
		       ite->tcpsocks[i],
		       hostId);
  for (i=0;i<ite->hostsWaiting;i++)
    updateResponseData(&ite->destination[i],
		       NULL,
		       hostId);
  sendReply(ite,
	    msg); 
  GROW(ite->seen,
       ite->seenIndex,
       ite->seenIndex+1);
  ite->seen[ite->seenIndex-1] = contentHC;
  statChange(stat_content_in_ok, 1);
  MUTEX_UNLOCK(&ite->lookup_exclusion);
  return prio;
}


/**
 * Handle query for current average routing priority.
 */
int csHandleRequestAvgPriority(ClientHandle sock,
			       const p2p_HEADER * msg) {
  int i;
  IndirectionTableEntry * ite;
  unsigned int j = 0;
  unsigned long long priSum = 0;
  for (i=0;i<MIN_INDIRECTION_TABLE_SIZE;i++) {
    ite = &ROUTING_indTable_[i];
    MUTEX_LOCK(&ite->lookup_exclusion);
    if ( (ite->ttl != 0) &&
	 (ite->hostsWaiting > 0) &&
	 (ite->tcpsocksSize == 0) ) {
      /* only count entries that do NOT correspond to
	 local requests in any way... */
      priSum += ite->priority;
      j++;
    }
    MUTEX_UNLOCK(&ite->lookup_exclusion);
  }
  if (j > 0)
    priSum = priSum / j;

  return coreAPI->sendTCPResultToClient(sock, 
					(int) priSum); 
}



/* end of routing.c */
