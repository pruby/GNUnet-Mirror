 /*
      This file is part of GNUnet
      (C) 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file module/dht.c
 * @brief definition of the entry points to the module; implements
 *   the client-server application using the DHT service; the DHT
 *   service is based on RPC and the DHT itself is roughly based
 *   on kademlia.
 * @author Marko Räihä, Christian Grothoff
 *
 *
 * WARNING (to self): What follows is 3.500+ lines of incomplete,
 * crazy, recursive, asynchronous, multithreaded routing code with
 * plenty of function pointers, too little documentation and not
 * enough testing.  Pray to the C gods before venturing any further.
 *
 *
 * Todo:
 * 1) document (lots!)
 *
 * Desirable features:
 * 1) security: how to pick priorities?  Access rights?
 * 2) performance: add optional hello messages
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_rpc_service.h"
#include "gnunet_dht_service.h"
#include "datastore_dht_master.h"

/* ********************* CONSTANTS ******************* */

/**
 * Enable/disable DHT debugging output.
 */
#define DEBUG_DHT YES

#if DEBUG_DHT
#define ENTER() LOG(LOG_EVERYTHING, "Entering method %s at %s:%d.\n", __FUNCTION__, __FILE__, __LINE__)
#else
#define ENTER() do {} while (0)
#endif

/**
 * Number of replications / parallel requests.
 */
#define ALPHA 7

/**
 * Frequency of the DHT maintain job (trade-off between
 * more smooth traffic from the maintain job and useless
 * CPU consumption for the job going over the table doing
 * nothing).
 */
#define DHT_MAINTAIN_FREQUENCY (15 * cronSECONDS)

/**
 * How often do we do maintenance 'find' operations on
 * each table to maintain the routing table (finding
 * peers close to ourselves)?
 */
#define DHT_MAINTAIN_FIND_FREQUENCY (2 * cronMINUTES)

/**
 * How often should we notify the master-table about our
 * bucket status?
 */
#define DHT_MAINTAIN_BUCKET_FREQUENCY (5 * cronMINUTES)

/**
 * How often should we ping a peer?  Only applies once we
 * are nearing the DHT_INACTIVITY_DEATH time.
 */
#define DHT_PING_FREQUENCY (64 * DHT_MAINTAIN_FREQUENCY)

/**
 * After what time do peers always expire for good?
 */
#define DHT_INACTIVITY_DEATH (4 * DHT_PING_FREQUENCY)

/**
 * For how long after the last message do we consider a peer
 * "hyperactive" and refuse to remove it from the table?
 */
#define DHT_HYPERACTIVE_TIME (60 * cronSECONDS)

/**
 * What is the trade-off factor between the number of tables that a
 * peer participates in and the additional time we give it before
 * removing it? (We may also want to take table-diversity into account
 * here, but for now just the number of tables will do).  Effectively,
 * a peer with k tables more stays DHT_TABLE_FACTOR seconds longer in
 * our connection list.
 */
#define DHT_TABLE_FACTOR (10 * cronSECONDS)

/**
 * What is the CURRENT target size for buckets?
 */
#define BUCKET_TARGET_SIZE (4 + ALPHA * tablesCount)


/* ********************* STRUCTS ************************** */
/* ******************and Function-Types******************** */

/**
 * Per-peer information.
 */
typedef struct {
  /**
   * What was the last time we received a message from this peer?
   */
  cron_t lastActivity;
  /**
   * What was the last time we received a table status message
   * from this peer?
   */
  cron_t lastTableRefresh;
  /**
   * What was the last time we send a PING to this peer?
   */
  cron_t lastTimePingSend;
  /**
   * In which tables do we know that peer to participate in?
   */
  DHT_TableId * tables;
  /**
   * How large is the tables array?
   */
  unsigned int tableCount;
  /**
   * What is the identity of the peer?
   */
  PeerIdentity id;
} PeerInfo;

/**
 * Peers are grouped into buckets.
 */
typedef struct {
  /**
   * Peers in this bucket fall into the distance-range
   * (2^bstart to 2^bend].
   */
  unsigned int bstart;

  /**
   * Peers in this bucket fall into the distance-range
   * (2^bstart to 2^bend].
   */
  unsigned int bend;

  /**
   * Peers in this bucket.  NULL is used if no peer is known.
   */
  struct Vector * peers; /* contains PeerInfo instances */
} PeerBucket;

/**
 * Local information about a DHT table that this peer is participating
 * in.
 */
typedef struct {
  DHT_TableId id;
  Blockstore * store;
  /**
   * What was the last time we advertised this nodes participation in
   * this table to the master table?
   */
  cron_t lastMasterAdvertisement;

  /**
   * What was the last time we ran a find-node operation on
   * this table to find neighbouring peers?
   */
  cron_t lastFindOperation;
} LocalTableData;


/**
 * Context for callbacks used by FindNodes.
 */
typedef struct {
  /**
   * Towards which key are we routing?
   */
  HashCode512 key;

  /**
   * In what table are we searching?
   */
  DHT_TableId table;

  /**
   * Signal used to return from findNodes when timeout has
   * expired.
   */
  Semaphore * signal;

  /**
   * Number of entries in matches.
   */
  unsigned int k;

  /**
   * Best k matches found so far.  Of size ALPHA.
   */
  HashCode512 * matches;

  /**
   * Number of RPCs transmitted so far (if it reaches
   * rpcRepliesExpected we can possibly abort before
   * the timeout!).
   */
  unsigned int rpcRepliesReceived;

  /**
   * Size of the RPC array.
   */
  unsigned int rpcRepliesExpected;

  /**
   * Handle for the async dht_get operation (NULL if
   * such an operation was not performed).
   */
  struct DHT_GET_RECORD * async_handle;

  /**
   * ASYNC RPC handles.
   */
  struct RPC_Record ** rpc;

  /**
   * When do we need to be done (absolute time).
   */
  cron_t timeout;

  /**
   * Lock for accessing this struct.
   */
  Mutex lock;
} FindNodesContext;

/**
 * Callback for findNodes that is invoked whenever a node is found.
 *
 * @param identity the identity of the node that was found
 * @return OK to continue searching, SYSERR to abort early
 */
typedef int (*NodeFoundCallback)(const PeerIdentity * identity,
				 void * closure);

/**
 * Context for callbacks used by FindNodes.
 */
typedef struct {
  /**
   * Towards which key are we routing?
   */
  HashCode512 key;

  /**
   * In what table are we searching?
   */
  DHT_TableId table;

  /**
   * Number of entries to wait for
   */
  unsigned int k;

  /**
   * Number of entries found so far.
   */
  unsigned int found;

  /**
   * Number of RPCs transmitted so far (if it reaches
   * rpcRepliesExpected we can possibly abort before
   * the timeout!).
   */
  unsigned int rpcRepliesReceived;

  /**
   * Size of the RPC array.
   */
  unsigned int rpcRepliesExpected;

  /**
   * Handle for the async dht_get operation (NULL if
   * such an operation was not performed).
   */
  struct DHT_GET_RECORD * async_handle;

  /**
   * ASYNC RPC handles.
   */
  struct RPC_Record ** rpc;

  /**
   * When do we need to be done (absolute time).
   */
  cron_t timeout;

  /**
   * Lock for accessing this struct.
   */
  Mutex lock;

  /**
   * Callback to call on the k nodes.
   */
  NodeFoundCallback callback;

  /**
   * Extra argument to the callback.
   */
  void * closure;
} FindKNodesContext;

/**
 * Context for async DHT_GET operation.
 */
typedef struct DHT_GET_RECORD {
  /**
   * What is the (absolute) time of the timeout?
   */
  cron_t timeout;

  /**
   * In which table are we searching?
   */
  DHT_TableId table;

  unsigned int type;

  unsigned int keyCount;

  /**
   * What are the keys?
   */
  HashCode512 * keys;

  DataProcessor resultCallback;

  void * resultClosure;

  unsigned int resultsFound;

  /**
   * Context of findKNodes (async); NULL if the table was local.
   */
  FindKNodesContext * kfnc;

  DHT_OP_Complete callback;

  void * closure;

  /**
   * Size of the RPC array.
   */
  unsigned int rpcRepliesExpected;

  /**
   * ASYNC RPC handles.
   */
  struct RPC_Record ** rpc;

  /**
   * Lock for concurrent access to the record.
   */
  Mutex lock;

} DHT_GET_RECORD;

/**
 * Context for async DHT_PUT operation.
 */
typedef struct DHT_PUT_RECORD {
  /**
   * What is the (absolute) time of the timeout?
   */
  cron_t timeout;

  /**
   * In which table are we searching?
   */
  DHT_TableId table;

  /**
   * What is the key?
   */
  HashCode512 key;

  DataContainer * value;

  /**
   * Context of findKNodes (async); NULL if the table was local.
   */
  FindKNodesContext * kfnc;

  /**
   * Callback to call upon completion.
   */
  DHT_OP_Complete callback;

  /**
   * Extra argument to callback.
   */
  void * closure;

  unsigned int confirmed_stores;

  /**
   * Size of the RPC array.
   */
  unsigned int rpcRepliesExpected;

  /**
   * ASYNC RPC handles.
   */
  struct RPC_Record ** rpc;

  /**
   * Lock for concurrent access to the record.
   */
  Mutex lock;

} DHT_PUT_RECORD;


/**
 * Context for async DHT_REMOVE operation.
 */
typedef struct DHT_REMOVE_RECORD {
  /**
   * What is the (absolute) time of the timeout?
   */
  cron_t timeout;

  /**
   * In which table are we searching?
   */
  DHT_TableId table;

  /**
   * What is the key?
   */
  HashCode512 key;

  /**
   * Which value should be removed?
   */
  DataContainer * value;

  unsigned int confirmed_stores;

  /**
   * Context of findKNodes (async); NULL if the table was local.
   */
  FindKNodesContext * kfnc;

  /**
   * Callback to call upon completion.
   */
  DHT_OP_Complete callback;

  /**
   * Extra argument to callback.
   */
  void * closure;

  /**
   * Size of the RPC array.
   */
  unsigned int rpcRepliesExpected;

  /**
   * ASYNC RPC handles.
   */
  struct RPC_Record ** rpc;

  /**
   * Lock for concurrent access to the record.
   */
  Mutex lock;

} DHT_REMOVE_RECORD;


typedef struct {

  /**
   * Number of results currently received (size of the
   * results-array).
   */
  unsigned int count;
  /**
   * The results received so far.
   */
  DataContainer ** results;
  /**
   * RPC callback to call with the final result set.
   */
  Async_RPC_Complete_Callback callback;
  /**
   * Argument to the RPC_Complete callback.
   */
  struct CallInstance * rpc_context;
  /**
   * Argument to stop the async DHT-get operation.
   */
  DHT_GET_RECORD * get_record;
  /**
   * Did we send the final reply for this RPC? (if YES,
   * the dht-cron job or dht-shutdown will free the resources
   * of this struct).
   */
  int done;
  /**
   * Lock for accessing this struct.
   */
  Mutex lock;
} RPC_DHT_FindValue_Context;

typedef struct {
  /**
   * RPC callback to call with the final result set.
   */
  Async_RPC_Complete_Callback callback;
  /**
   * Argument to the RPC_Complete callback.
   */
  struct CallInstance * rpc_context;
  /**
   * Argument to stop the async DHT-get operation.
   */
  DHT_PUT_RECORD * put_record;
  /**
   * Did we send the final reply for this RPC? (if YES,
   * the dht-cron job or dht-shutdown will free the resources
   * of this struct).
   */
  int done;
  /**
   * Lock for accessing this struct.
   */
  Mutex lock;
} RPC_DHT_store_Context;

typedef struct {
  /**
   * RPC callback to call with the final result set.
   */
  Async_RPC_Complete_Callback callback;
  /**
   * Argument to the RPC_Complete callback.
   */
  struct CallInstance * rpc_context;
  /**
   * Argument to stop the async DHT-get operation.
   */
  DHT_REMOVE_RECORD * remove_record;
  /**
   * Did we send the final reply for this RPC? (if YES,
   * the dht-cron job or dht-shutdown will free the resources
   * of this struct).
   */
  int done;
  /**
   * Lock for accessing this struct.
   */
  Mutex lock;
} RPC_DHT_remove_Context;

/**
 * Cron-job that must be run before DHT can shutdown.
 */
typedef struct {
  CronJob job;
  void * arg;
} DHT_CronJobAbortEntry;


/* ***************** prototypes ******************** */

/**
 * Send an RPC 'ping' request to that node requesting DHT table
 * information.  Note that this is done asynchronously.
 * This is just the prototype, the function is below.
 */
static void request_DHT_ping(const PeerIdentity * identity,
			     FindNodesContext * fnc);

static FindKNodesContext * findKNodes_start(const DHT_TableId * table,
					    const HashCode512 * key,
					    cron_t timeout,
					    unsigned int k,
					    NodeFoundCallback callback,
					    void * closure);

static int findKNodes_stop(FindKNodesContext * fnc);


/* ******************* GLOBALS ********************* */

/**
 * Global core API.
 */
static CoreAPIForApplication * coreAPI = NULL;

/**
 * RPC API
 */
static RPC_ServiceAPI * rpcAPI = NULL;

/**
 * The buckets (Kademlia style routing table).
 */
static PeerBucket * buckets;

/**
 * Total number of active buckets.
 */
static unsigned int bucketCount;

/**
 * The ID of the master table.
 */
static HashCode512 masterTableId;

/**
 * List of the tables that this peer participates in.
 */
static LocalTableData * tables;

/**
 * Number of entries in the tables array.
 */
static unsigned int tablesCount;

/**
 * Mutex to synchronize access to tables.
 */
static Mutex * lock;

/**
 * Handle for the masterTable datastore that is used by this node
 * to store information about which peers participate in which
 * tables (the masterTable is another DHT, this store is just the
 * part of the masterTable that is stored at this peer).
 */
static Blockstore * masterTableDatastore;

/**
 * Table of cron-jobs (and arguments) that MUST be run
 * before the DHT module can shutdown.  All of these
 * jobs are guaranteed to be triggered during the shutdown.
 */
static DHT_CronJobAbortEntry * abortTable;

static unsigned int abortTableSize;

/* *********************** CODE! ********************* */

#if DEBUG_DHT
static void printRoutingTable() {
  unsigned int i;

  MUTEX_LOCK(lock);
  LOG(LOG_DEBUG,
      "DHT ROUTING TABLE:\n");
  for (i=0;i<bucketCount;i++) {
    if (buckets[i].peers != NULL) {
      PeerInfo * pos = NULL;

      pos = vectorGetFirst(buckets[i].peers);
      while (pos != NULL) {
	EncName enc;
	EncName tabs[3];
	int j;

	memset(tabs, 0, sizeof(EncName)*3);
	hash2enc(&pos->id.hashPubKey,
		 &enc);
	for (j=0;j<pos->tableCount;j++)
	  hash2enc(&pos->tables[j],
		   &tabs[j]);
	
	LOG(LOG_DEBUG,
	    "[%4d: %3d-%3d]: %s with %u tables (%s, %s, %s)\n",
	    i,
	    buckets[i].bstart, buckets[i].bend,
	    &enc,
	    pos->tableCount,
	    &tabs[0],
	    &tabs[1],
	    &tabs[2]);
	pos = vectorGetNext(buckets[i].peers);
      }
    }
  }
  LOG(LOG_DEBUG,
      "DHT ROUTING TABLE END\n");
  MUTEX_UNLOCK(lock);
}
#endif

/**
 * we need to prevent unloading of the
 * DHT module while this cron-job is pending (or
 * rather keep track of it globally to do a proper
 * shutdown on-the-spot if needed!
 */
static void addAbortJob(CronJob job,
			void * arg) {
  ENTER();
  MUTEX_LOCK(lock);
  GROW(abortTable,
       abortTableSize,
       abortTableSize+1);
  abortTable[abortTableSize-1].job = job;
  abortTable[abortTableSize-1].arg = arg;
  MUTEX_UNLOCK(lock);
}

/**
 * Remove a job from the abort table.
 */
static void delAbortJob(CronJob job,
			void * arg) {
  int i;

  ENTER();
  MUTEX_LOCK(lock);
  for (i=0;i<abortTableSize;i++) {
    if ( (abortTable[i].job == job) &&
	 (abortTable[i].arg == arg) ) {
      abortTable[i] = abortTable[abortTableSize-1];
      GROW(abortTable,
	   abortTableSize,
	   abortTableSize-1);
      break;
    }
  }
  MUTEX_UNLOCK(lock);
}

/**
 * Get the LocalTableData for the given table ID.
 * @return NULL if this peer does not participate in that table.
 */
static LocalTableData * getLocalTableData(const DHT_TableId * id) {
  int i;
  for (i=tablesCount-1;i>=0;i--)
    if (equalsHashCode512(id,
			  &tables[i].id))
      return &tables[i];
  return NULL;
}

/**
 * If this peer supports the given table and the
 * other peer is not closer than this peer to the
 * given key, returns YES.
 */
static int isNotCloserThanMe(const DHT_TableId * table,
			     const PeerIdentity * peer,
			     const HashCode512 * key) {
  if (NULL == getLocalTableData(table))
    return NO;
  if (-1 == hashCodeCompareDistance(&peer->hashPubKey,
				    &coreAPI->myIdentity->hashPubKey,
				    key))
    return NO;
  else
    return YES;
}

/**
 * Find the bucket into which the given peer belongs.
 */
static PeerBucket * findBucket(const PeerIdentity * peer) {
  unsigned int index;
  int i;
  int diff;
#if DEBUG_DHT
  EncName enc1;
  EncName enc2;
#endif

  index = sizeof(HashCode512)*8;
  for (i = sizeof(HashCode512)*8 - 1; i >= 0; --i) {
    diff = getHashCodeBit(&peer->hashPubKey, i) - getHashCodeBit(&coreAPI->myIdentity->hashPubKey, i);
    if (diff != 0) {
      index = i;
      break;
    }
  }
#if DEBUG_DHT
  hash2enc(&peer->hashPubKey,
	   &enc1);
  hash2enc(&coreAPI->myIdentity->hashPubKey,
	   &enc2);
  LOG(LOG_DEBUG,
      "Bit-distance from `%s' to this peer `%s' is %u bit.\n",
      &enc1,
      &enc2,
      index);
#endif
  i = bucketCount-1;
  while ( (buckets[i].bstart >= index) &&
	  (i > 0) ) {
    i--;
  }
  if ( (buckets[i].bstart <  index) &&
       (buckets[i].bend   >= index) ) {
    return &buckets[i];
  } else {
#if DEBUG_DHT
    LOG(LOG_WARNING,
	"Index %d not in range for bucket %d which is [%d,%d[\n",
	index,
	i,
	buckets[i].bstart,
	buckets[i].bend);
#endif
    return NULL; /* should only happen for localhost! */
  }
}

/**
 * Update the set kbest which is supposed to accumulate the k closest
 * peers to the given key.  The size of the kbset set is given by
 * limit.
 *
 * @param newValue the new candidate for inclusion in the set
 * @param *k the current number of entries in the set
 */
static void k_best_insert(unsigned int limit,
			  unsigned int * k,
			  const HashCode512 * key,
			  HashCode512 * kbest,
			  const HashCode512 * newValue) {
  int replace;
  int m;

  if ((*k) < limit) {
    memcpy(&kbest[*k],
	   newValue,
	   sizeof(HashCode512));
    (*k)++;
  } else {
    replace = -1;
    for (m=limit-1;m>=0;m--)
      if ( (1 == hashCodeCompareDistance(&kbest[m],
					 newValue,
					 key)) &&
	   ( (replace == -1) ||
	     (1 == hashCodeCompareDistance(&kbest[m],
					   &kbest[replace],
					   key)) ) )
	replace = m;
    if (replace != -1) {
      memcpy(&kbest[replace],
	     newValue,
	     sizeof(HashCode512));
    }
  }
}

/**
 * Find the PeerInfo for the given peer.
 *
 * @return NULL if the peer is not in the RT.
 */
static PeerInfo * findPeerInfo(const PeerIdentity * peer) {
  PeerBucket * bucket;
  PeerInfo * pos;

  bucket = findBucket(peer);
  if (bucket == NULL)
    return NULL;
  pos = vectorGetFirst(bucket->peers);
  while (pos != NULL) {
    if (equalsHashCode512(&peer->hashPubKey,
			  &pos->id.hashPubKey))
      return pos;
    pos = vectorGetNext(bucket->peers);
  }
  return NULL;
}

/**
 * We receive a message from 'responder' which may contain optional
 *
 * fields about the responder.  Process those fields (if present).
 * @param results::tables list of tables the responder participates in (optional)
 * @param results::hellos list of hellos for responder (optional)
 */
static void processOptionalFields(const PeerIdentity * responder,
				  RPC_Param * results) {
  unsigned int dataLength;
  char * data;
  unsigned int tableCount;
  DHT_TableId * tables;
  EncName enc;
  cron_t now;
  PeerBucket * bucket;
  PeerInfo * pos;

  if (OK == RPC_paramValueByName(results,
				 "tables",
				 &dataLength,
				 (void**)&data)) {
    tableCount = dataLength / sizeof(DHT_TableId);
    if (tableCount * sizeof(DHT_TableId) != dataLength) {
      IFLOG(LOG_WARNING,
	    hash2enc(&responder->hashPubKey,
		     &enc));
      LOG(LOG_WARNING,
	  _("Malformed optional field `%s' received from peer `%s'.\n"),
	  "tables",
	  &enc);
      return;
    }
    tables = (DHT_TableId*) data;
    cronTime(&now);

#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"updating routing table after learning about peer `%s' who provides %d tables.\n",	
	&enc,
	tableCount);
#endif

    /* update buckets */
    MUTEX_LOCK(lock);
    pos = findPeerInfo(responder);
    bucket = findBucket(responder);
    if (bucket == NULL) {
      IFLOG(LOG_WARNING,
	    hash2enc(&responder->hashPubKey,
		     &enc));
      LOG(LOG_WARNING,
	  _("Could not find peer `%s' in routing table!\n"),
	  &enc);
    }
    GNUNET_ASSERT(bucket != NULL);
    if (pos == NULL) {
      PeerInfo * oldest = NULL;

      pos = vectorGetFirst(bucket->peers);
      while (pos != NULL) {
	if (pos->lastActivity + DHT_INACTIVITY_DEATH < now) {
	  if (oldest == NULL)
	    oldest = pos;
	  else
	    if (pos->lastActivity < oldest->lastActivity)
	      oldest = pos;
	}
	if (pos->lastTableRefresh +
	    (pos->tableCount - tableCount) * DHT_TABLE_FACTOR + DHT_HYPERACTIVE_TIME < now) {
	  if (oldest == NULL)
	    oldest = pos;
	  else if (pos->lastTableRefresh +
		   (pos->tableCount - tableCount) * DHT_TABLE_FACTOR <
		   oldest->lastTableRefresh +
		   (oldest->tableCount - tableCount) * DHT_TABLE_FACTOR)
	    oldest = pos;
	}
	pos = vectorGetNext(bucket->peers);
      }
      pos = oldest;
    }
    if ( (vectorSize(bucket->peers) < BUCKET_TARGET_SIZE) &&
	 (pos == NULL) ) {
      /* create new entry */
      pos = MALLOC(sizeof(PeerInfo));
      pos->tables = NULL;
      pos->tableCount = 0;
      pos->lastTimePingSend = cronTime(NULL);
      vectorInsertLast(bucket->peers, pos);
    }
    if (pos == NULL) {
#if DEBUG_DHT
      IFLOG(LOG_DEBUG,
	    hash2enc(&responder->hashPubKey,
		     &enc));
      LOG(LOG_DEBUG,
	  "routing table full, not adding peer `%s'.\n",	
	  &enc);
#endif
    } else {
#if DEBUG_DHT
      IFLOG(LOG_DEBUG,
	    hash2enc(&responder->hashPubKey,
		     &enc));
      LOG(LOG_DEBUG,
	  "adding peer `%s' to routing table.\n",	
	  &enc);
#endif

      pos->lastActivity = now;
      pos->lastTableRefresh = now;
      pos->id = *responder;
      GROW(pos->tables,
	   pos->tableCount,
	   tableCount);
      memcpy(pos->tables,
	     tables,
	     sizeof(DHT_TableId) * tableCount);
    }
    MUTEX_UNLOCK(lock);
  }

  /* HERE: process other optional fields (hellos) */

}

/**
 * We are sending out a message and have the chance to communicate
 * optional fields.  Add those if we feel like it.
 *
 * @param args the argument list to which optional fields can be added
 */
static void addOptionalFields(RPC_Param * args) {
  DHT_TableId * tabs;
  int i;
  unsigned int tc;
  size_t s;

  MUTEX_LOCK(lock);
  tc = tablesCount;
  tabs = MALLOC(sizeof(DHT_TableId) * tc);
  for (i=0;i<tc;i++)
    tabs[i] = tables[i].id;
  MUTEX_UNLOCK(lock);
  s = RPC_paramSize(args) + sizeof(DHT_TableId) * tc;
  /* always add if resulting size is less than 1k;
     never generate messages > 32k;
     if greater than 1k, only add with exponentially
     decreasing probability */
  if ( (s < 1024) ||
       ( (s*s < randomi(32768)*randomi(32768)) &&
	 (s*s < randomi(32768)*randomi(32768)) ) ) {
    RPC_paramAdd(args,
		 "tables",
		 sizeof(DHT_TableId) * tc,
		 tabs);
  }
  FREE(tabs);

  /* FIXME: here: add other optional fields (hellos) */
}

/**
 * The given peer has responded to our find RPC callback.  Update the
 * last response time in the peer list and add the peers from results
 * to the FNC.  Trigger further create_find_nodes_rpc requests.
 *
 * @param responder the ID of the responding peer
 * @param results::peers serialized HostIdentities
 * @param results::tables list of tables the responder participates in (optional)
 * @param fnc the context (used to continue iterative search)
 */
static void create_find_nodes_rpc_complete_callback(const PeerIdentity * responder,
						    RPC_Param * results,
						    FindNodesContext * fnc) {
  PeerInfo * info;
  char * value;
  unsigned int dataLength;
  unsigned int pos;
  EncName enc;

  ENTER();
  processOptionalFields(responder, results);
  /* update peer list */
  MUTEX_LOCK(lock);
  info = findPeerInfo(responder);
  if (info != NULL)
    info->lastActivity = cronTime(NULL);
  MUTEX_UNLOCK(lock);

  if (OK != RPC_paramValueByName(results,
				 "peer",
				 &dataLength,
				 (void**) &value)) {
    IFLOG(LOG_WARNING,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_WARNING,
	_("Received malformed response to `%s' from peer `%s'.\n"),
	"DHT_findNode",
	&enc);
    return;
  }

  /* parse value, try to DHT-ping  the new peers
     (to add it to the table; if that succeeds
     the peer will automatically trigger the ping_reply_handler
     which will in turn trigger create_find_nodes_rpc) */
  if ( (dataLength % sizeof(PeerIdentity)) != 0) {
    IFLOG(LOG_WARNING,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_WARNING,
	_("Received malformed response to `%s' from peer `%s'.\n"),
	"DHT_findNode",
	&enc);
    return;
  }
  for (pos=0;pos<dataLength;pos+=sizeof(PeerIdentity)) {
    PeerIdentity * msg;

    msg = (PeerIdentity*) &value[pos];
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(&responder->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"processing PeerID received from peer `%s' in response to `%s' RPC.\n",
	&enc,
	"DHT_findNode");
    IFLOG(LOG_DEBUG,
	  hash2enc(&msg->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"sending RPC `%s' to learn more about peer `%s'.\n",
	"DHT_ping",
	&enc);
#endif
    if (hostIdentityEquals(msg,
			   coreAPI->myIdentity))
      continue; /* ignore self-references! */
    request_DHT_ping(msg,
		     fnc);
  }
}

/**
 * Send a find_nodes RPC to the given peer.  Replies are
 * to be inserted into the FNC k-best table.
 */
static void create_find_nodes_rpc(const PeerIdentity * peer,
				  FindNodesContext * fnc) {
  RPC_Param * param;
  cron_t now;
  cron_t rel;
  LocalTableData * table;
#if DEBUG_DHT
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&peer->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "sending RPC `%s' to peer `%s'.\n",
      "DHT_find_nodes",
      &enc);
#endif
  ENTER();
  cronTime(&now);
  param = RPC_paramNew();
  MUTEX_LOCK(&fnc->lock);
  if (equalsHashCode512(&fnc->key,
			&coreAPI->myIdentity->hashPubKey)) {
    table = getLocalTableData(&fnc->table);
    if (table != NULL)
      table->lastFindOperation = now;
  }
  RPC_paramAdd(param,
	       "table",
	       sizeof(DHT_TableId),
	       &fnc->table);
	
  RPC_paramAdd(param,
	       "key",
	       sizeof(HashCode512),
	       &fnc->key);
  GROW(fnc->rpc,
       fnc->rpcRepliesExpected,
       fnc->rpcRepliesExpected+1);
  if (fnc->timeout > now)
    rel = fnc->timeout - now;
  else
    rel = 0;
  addOptionalFields(param);
  fnc->rpc[fnc->rpcRepliesExpected-1]
    = rpcAPI->RPC_start(peer,
			"DHT_findNode",
			param,
			0,
			rel,
			(RPC_Complete) &create_find_nodes_rpc_complete_callback,
			fnc);
  MUTEX_UNLOCK(&fnc->lock);
  RPC_paramFree(param);
}

/**
 * We received a reply from a peer that we ping'ed.  Update
 * the FNC's kbest list and the buckets accordingly.
 */
static void ping_reply_handler(const PeerIdentity * responder,
			       RPC_Param * results,
			       FindNodesContext * fnc) {
  int i;
  EncName enc;
  PeerInfo * pos;

  ENTER();
  GNUNET_ASSERT(! hostIdentityEquals(responder,
				     coreAPI->myIdentity));
  /* this processes the 'tables' field! */
  processOptionalFields(responder,
			results);
  if (fnc == NULL)
    return;
  /* update k-best list */
  MUTEX_LOCK(&fnc->lock);
  pos = findPeerInfo(responder);
  /* does the peer support the table in question? */
  if (! equalsHashCode512(&fnc->table,
			  &masterTableId)) {
    for (i=pos->tableCount-1;i>=0;i--)
      if (equalsHashCode512(&fnc->table,
			    &pos->tables[i]))
	break;
    if (i == -1) {
      MUTEX_UNLOCK(&fnc->lock);
      return; /* peer does not support table in question */
    }
  }

#if DEBUG_DHT
  IFLOG(LOG_DEBUG,
	hash2enc(&responder->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "peer `%s' supports table in question, considering the peer for list of %d-best matches.\n",	
      &enc,
      ALPHA);
#endif
  k_best_insert(ALPHA,
		&fnc->k,
		&fnc->key,
		fnc->matches,
		&responder->hashPubKey);

  /* trigger transitive request searching for more nodes! */
  create_find_nodes_rpc(responder,
			fnc);
  MUTEX_UNLOCK(&fnc->lock);
}

/**
 * Send an RPC 'ping' request to that node requesting DHT table
 * information.  Note that this is done asynchronously.
 */
static void request_DHT_ping(const PeerIdentity * identity,
			     FindNodesContext * fnc) {
  RPC_Param * request_param;
  PeerInfo * pos;
  cron_t now;
  cron_t rel;
#if DEBUG_DHT
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&identity->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "sending RPC `%s' to peer `%s'.\n",
      "DHT_ping",
      &enc);
#endif
  ENTER();
  if (hostIdentityEquals(identity,
			 coreAPI->myIdentity)) {
    BREAK();
    return; /* refuse to self-ping!... */
  }
  MUTEX_LOCK(lock);
  /* test if this peer is already in buckets */
  pos = findPeerInfo(identity);
  cronTime(&now);
  if (pos != NULL)
    pos->lastTimePingSend = now;
  MUTEX_UNLOCK(lock);

  /* peer not in RPC buckets; try PINGing via RPC */
  MUTEX_LOCK(&fnc->lock);
  GROW(fnc->rpc,
       fnc->rpcRepliesExpected,
       fnc->rpcRepliesExpected+1);
  request_param = vectorNew(4);
  if (fnc->timeout > now)
    rel = fnc->timeout - now;
  else
    rel = 0;
  addOptionalFields(request_param);
  fnc->rpc[fnc->rpcRepliesExpected-1]
    = rpcAPI->RPC_start(identity,
			"DHT_ping",
			request_param,
			0,
			rel,
			(RPC_Complete) &ping_reply_handler,
			fnc);
  vectorFree(request_param);
  MUTEX_UNLOCK(&fnc->lock);
}

/**
 * Find k nodes in the local buckets that are closest to the
 * given key for the given table.  Return instantly, do NOT
 * attempt to query remote peers.
 *
 * @param hosts array with space for k hosts.
 * @return number of hosts found
 */
static unsigned int findLocalNodes(const DHT_TableId * table,
				   const HashCode512 * key,
				   PeerIdentity * hosts,
				   unsigned int k) {
  int i;
  int j;
  PeerBucket * bucket;
  PeerInfo * pos;
  unsigned int ret;
#if DEBUG_DHT
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(table,
		 &enc));
  LOG(LOG_DEBUG,
      "searching local table for peers supporting table `%s'.\n",
      &enc);
#endif
  ENTER();
  ret = 0;
  /* find peers in local peer-list that participate in
     the given table */
  for (i=bucketCount-1;i>=0;i--) {
    bucket = &buckets[i];
    pos = vectorGetFirst(bucket->peers);
    while (pos != NULL) {
      for (j=pos->tableCount-1;j>=0;j--) {
	if (equalsHashCode512(&pos->tables[j],
			      table)) {
#if DEBUG_DHT
	  EncName enc;
	
	  IFLOG(LOG_DEBUG,
		hash2enc(&pos->id.hashPubKey,
			 &enc));
	  LOG(LOG_DEBUG,
	      "local table search showed peer `%s' is supporting the table.\n",
	      &enc);
#endif
	  k_best_insert(k,
			&ret,
			key,
			(HashCode512*) hosts,
			&pos->id.hashPubKey);
	}
      }
      pos = vectorGetNext(bucket->peers);
    }
  } /* end for all buckets */
  return ret;
}
					
/**
 * We got a reply from the DHT-get operation.  Update the
 * record datastructures accordingly (and call the record's
 * callback).
 *
 * @param results::data created in rpc_DHT_findValue_abort
 */
static void dht_findvalue_rpc_reply_callback(const PeerIdentity * responder,
					     RPC_Param * results,
					     DHT_GET_RECORD * record) {
  DataContainer * value;
  unsigned int i;
  unsigned int max;
  PeerInfo * pos;
  EncName enc;

  ENTER();
  processOptionalFields(responder, results);
  MUTEX_LOCK(lock);
  pos = findPeerInfo(responder);
  pos->lastActivity = cronTime(NULL);
  MUTEX_UNLOCK(lock);

  max = RPC_paramCount(results);
#if DEBUG_DHT
  IFLOG(LOG_DEBUG,
	hash2enc(&responder->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "peer `%s' responded to RPC `%s' with %u results.\n",
      &enc,
      "DHT_findvalue",
      max);
#endif
  for (i=0;i<max;i++) {
    value = RPC_paramDataContainerByPosition(results,
					     i);
    if (value == NULL) {
      hash2enc(&responder->hashPubKey,
	       &enc);
      LOG(LOG_WARNING,
	  _("Invalid response to `%s' from peer `%s'.\n"),
	  "DHT_findValue",
	  &enc);
      return;
    }
    MUTEX_LOCK(&record->lock);
    if (record->callback != NULL)
      record->resultCallback(record->keys,
			     value,
			     record->resultClosure);
    MUTEX_UNLOCK(&record->lock);
    FREE(value);
  }
}

/**
 * Send an (async) DHT get to the given peer.  Replies are to be
 * processed by the callback in record.  The RPC async handle is to be
 * stored in the records rpc list.  Locking is not required.
 */
static void send_dht_get_rpc(const PeerIdentity * peer,
			     DHT_GET_RECORD * record) {
  RPC_Param * param;
  unsigned long long timeout;
  unsigned int type;
  cron_t delta;
  cron_t now;
#if DEBUG_DHT
  EncName enc;

  ENTER();
  IFLOG(LOG_DEBUG,
	hash2enc(&peer->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "sending RPC `%s' to peer `%s'.\n",
      "DHT_findvalue",
      &enc);
#endif
  if (isNotCloserThanMe(&record->table,
			peer,		
			record->keys))
    return; /* refuse! */
  cronTime(&now);
  if (record->timeout > now)
    delta = (record->timeout - now) / 2;
  else
    delta = 0;
  timeout = htonll(delta);
  type = htonl(record->type);
  param = RPC_paramNew();
  RPC_paramAdd(param,
	       "table",
	       sizeof(DHT_TableId),
	       &record->table);
  RPC_paramAdd(param,
	       "keys",
	       sizeof(HashCode512) * record->keyCount,
	       record->keys);
  RPC_paramAdd(param,
	       "timeout",
	       sizeof(unsigned long long),
	       &timeout);
  RPC_paramAdd(param,
	       "type",
	       sizeof(unsigned int),
	       &type);
  GROW(record->rpc,
       record->rpcRepliesExpected,
       record->rpcRepliesExpected+1);
  addOptionalFields(param);
  record->rpc[record->rpcRepliesExpected-1]
    = rpcAPI->RPC_start(peer,
		        "DHT_findValue",
			param,
			0,
			delta,
			(RPC_Complete) &dht_findvalue_rpc_reply_callback,
			record);
  RPC_paramFree(param);
}

/**
 * Callback called for local results found in
 * dht_get_async_start.  Calls the DHT_OP_Complete
 * callback with the results found locally.
 * A DataProcessor.
 */
static int getLocalResultCallback(const HashCode512 * key,
				  const DataContainer * val,
				  DHT_GET_RECORD * rec) {
  int ret;
  if ( (equalsHashCode512(&rec->table,
			  &masterTableId)) &&
       ((ntohl(val->size) - sizeof(DataContainer)) % sizeof(PeerIdentity) != 0) )
    BREAK(); /* assertion failed: entry in master table malformed! */
  ret = OK;
  if (rec->resultCallback != NULL)
    ret = rec->resultCallback(key,
			      val,
			      rec->resultClosure);
  rec->resultsFound++;
  return ret;
}

/**
 * Perform an asynchronous GET operation on the DHT identified by
 * 'table' using 'key' as the key.  The peer does not have to be part
 * of the table (if so, we will attempt to locate a peer that is!)
 *
 * @param table table to use for the lookup
 * @param key the key to look up
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param callback function to call on each result
 * @param closure extra argument to callback
 * @return handle to stop the async get
 */
static struct DHT_GET_RECORD *
dht_get_async_start(const DHT_TableId * table,
		    unsigned int type,
		    unsigned int keyCount,
		    const HashCode512 * keys,
		    cron_t timeout,
		    DataProcessor resultCallback,
		    void * cls,
		    DHT_OP_Complete callback,
		    void * closure) {
  int i;
  LocalTableData * ltd;
  DHT_GET_RECORD * ret;
  unsigned int count;
#if DEBUG_DHT
  EncName enc;
  EncName enc2;
  int res;

  ENTER();
  IFLOG(LOG_DEBUG,
	hash2enc(&keys[0],
		 &enc));
  IFLOG(LOG_DEBUG,
	hash2enc(table,
		 &enc2));
  LOG(LOG_DEBUG,
      "performing `%s' operation on key `%s' and table `%s'.\n",
      "DHT_GET",
      &enc,
      &enc2);
#endif

  if (timeout > 1 * cronHOURS) {
    LOG(LOG_WARNING,
	_("`%s' called with timeout above 1 hour (bug?)\n"),
	__FUNCTION__);
    timeout = 1 * cronHOURS;
  }

  ret = MALLOC(sizeof(DHT_GET_RECORD));
  ret->timeout = cronTime(NULL) + timeout;
  ret->type = type;
  ret->keyCount = keyCount;
  ret->keys = MALLOC(keyCount * sizeof(HashCode512));
  memcpy(ret->keys,
	 keys,
	 keyCount * sizeof(HashCode512));
  ret->table = *table;
  ret->resultCallback = resultCallback;
  ret->resultClosure = cls;
  ret->resultsFound = 0;
  ret->callback = callback;
  ret->closure = closure;
  MUTEX_CREATE_RECURSIVE(&ret->lock);
  ret->rpc = NULL;
  ret->rpcRepliesExpected = 0;
  ret->kfnc = NULL;
  MUTEX_LOCK(lock);


  ltd = getLocalTableData(table);
  if (ltd != NULL) {
    PeerIdentity * hosts;
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(table,
		   &enc));
    LOG(LOG_DEBUG,
	"I participate in the table `%s' for the `%s' operation.\n",
	&enc,
	"DHT_GET");
#endif
    /* We do participate in the table, it is fair to assume
       that we know the relevant peers in my neighbour set */
    hosts = MALLOC(sizeof(PeerIdentity) * ALPHA);
    count = findLocalNodes(table,
			   &keys[0],
			   hosts,
			   ALPHA);
    /* try adding this peer to hosts */
    k_best_insert(ALPHA,
		  &count,
		  &keys[0],
		  (HashCode512*) hosts,
		  &coreAPI->myIdentity->hashPubKey);
    if (count == 0) {
      BREAK();
      /* Assertion failed: I participate in a table but findLocalNodes returned 0! */
      MUTEX_UNLOCK(lock);
      FREE(ret->keys);
      FREE(ret);
      return NULL;
    }
    /* if this peer is in 'hosts', try local datastore lookup */
    for (i=0;i<count;i++)
      if (hostIdentityEquals(coreAPI->myIdentity,
			     &hosts[i])) {
	res = ltd->store->get(ltd->store->closure,
			      type,
			      0, /* FIXME: priority */
			      keyCount,
			      keys,
			      (DataProcessor)&getLocalResultCallback,
			      ret);
#if DEBUG_DHT
	IFLOG(LOG_DEBUG,
	      hash2enc(&keys[0],
		       &enc));
	LOG(LOG_DEBUG,
	    "local datastore lookup for key `%s' resulted in %d results.\n",
	    &enc,
	    res);
#endif
	break;
      }

    if (ALPHA > ret->resultsFound) {
      /* if less than ALPHA replies were found, send
	 dht_get_RPC to the other peers */
      for (i=0;i<count;i++) {
	if (! hostIdentityEquals(coreAPI->myIdentity,
				 &hosts[i])) {
#if DEBUG_DHT
	  IFLOG(LOG_DEBUG,
		hash2enc(&hosts[i].hashPubKey,
			 &enc));
	  LOG(LOG_DEBUG,
	      "sending RPC `%s' to peer `%s' that also participates in the table.\n",
	      "DHT_GET",
	      &enc);
#endif
	  send_dht_get_rpc(&hosts[i],
			   ret);
	}
      }
    }
  } else {
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(table,
		   &enc));
    LOG(LOG_DEBUG,
	"I do not participate in the table `%s', finding %d other nodes that do.\n",
	&enc,
	ALPHA);
#endif
    /* We do not particpate in the table; hence we need to use
       findKNodes to find an initial set of peers in that
       table; findKNodes tries to find k nodes and instantly
       allows us to query each node found.  For each peer found,
       we then perform send_dht_get_rpc.
    */
    ret->kfnc
      = findKNodes_start(table,
			 &keys[0],
			 timeout,
			 ALPHA,
			 (NodeFoundCallback) &send_dht_get_rpc,
			 ret);
  }
  MUTEX_UNLOCK(lock);
  return ret;
}

/**
 * Stop async DHT-get.  Frees associated resources.
 */
static int dht_get_async_stop(struct DHT_GET_RECORD * record) {
  int i;
  int resultsFound;

  ENTER();
  if (record == NULL)
    return SYSERR;
  /* abort findKNodes (if running) - it may cause
     the addition of additional RPCs otherwise! */
  if (record->kfnc != NULL)
    findKNodes_stop(record->kfnc);

  for (i=0;i<record->rpcRepliesExpected;i++)
    rpcAPI->RPC_stop(record->rpc[i]);
  MUTEX_DESTROY(&record->lock);
  resultsFound = record->resultsFound;
  FREE(record);
#if DEBUG_DHT
  LOG(LOG_DEBUG,
      "`%s' operation completed with %d results.\n",
      "DHT_GET",
      resultsFound);
#endif

  if (resultsFound > 0)
    return resultsFound;
  else
    return SYSERR; /* timeout */
}

/**
 * We found a peer in the MasterTable that supports the table that
 * we're trying to find peers for.  Update FNC accordingly and
 * start transitive search for peers from that new peer.
 *
 * @param value should contain a set of HeloMessages corresponding
 *  to the identities of peers that support the table that we're
 *  looking for; pass those Helos to the core *and* try to ping them.
 */
static int
findnodes_dht_master_get_callback(const HashCode512 * key,
				  const DataContainer * cont,
				  FindNodesContext * fnc) {
  unsigned int dataLength;
  const PeerIdentity * id;
  int i;

  ENTER();
  dataLength = ntohl(cont->size) - sizeof(DataContainer);

  if ( (dataLength % sizeof(PeerIdentity)) != 0) {
    LOG(LOG_DEBUG,
	"Response size was %d, expected multile of %d\n",
	dataLength,
	sizeof(PeerIdentity));
    LOG(LOG_WARNING,
	_("Invalid response to `%s'.\n"),
	"DHT_findValue");
    return SYSERR;
  }
  id = (const PeerIdentity*) &cont[1];
  for (i=dataLength/sizeof(PeerIdentity)-1;i>=0;i--) {
    if (!hostIdentityEquals(&id[i],
			    coreAPI->myIdentity))
      request_DHT_ping(&id[i],
		       fnc);
  }
  return OK;
}


/**
 * In the induced sub-structure for the given 'table', find the ALPHA
 * nodes closest to the given key.  The code first tries to find ALPHA
 * nodes in the routing table that participate in the given table.  If
 * nodes are found, the k<=ALPHA nodes closest to the key are queried
 * (using the find node RPC) to find nodes closer to the key.
 *
 * If no (zero!) participating nodes are found, the a set of introduction
 * nodes for this table is obtained from the master table (using RPC
 * get).  For the master table we try to discover peers participating
 * in the DHT using broadcasts to all connected peers (relying on
 * GNUnet core peer discovery).
 *
 * If we learn about new nodes in this step, add them to the RT table;
 * if we run out of space in the RT, send pings to oldest entry; if
 * oldest entry did not respond to PING, replace it!
 *
 * This function is used periodially for each table that we have joined
 * to ensure that we're connected to our neighbours.
 *
 * @param table the table which the peers must participate in
 * @param key the target key to use for routing
 * @param timeout how long to tell the RPCs that we will wait
 *  (note that the caller is supposed to call findNodes_stop
 *   to finally collect the collected nodes)
 * @return context for findNodes_stop
 */
static FindNodesContext * findNodes_start(const DHT_TableId * table,
					  const HashCode512 * key,
					  cron_t timeout) {
  FindNodesContext * fnc;
  int i;
#if DEBUG_DHT
  EncName enc;

  ENTER();
  IFLOG(LOG_DEBUG,
	hash2enc(table,
		 &enc));
  LOG(LOG_DEBUG,
      "function `%s' called to look for nodes participating in table `%s'.\n",
      __FUNCTION__,
      &enc);
#endif
  fnc = MALLOC(sizeof(FindNodesContext));
  fnc->key = *key;
  fnc->table = *table;
  fnc->k = 0;
  fnc->matches = MALLOC(sizeof(HashCode512) * ALPHA);
  fnc->signal = SEMAPHORE_NEW(0);
  fnc->timeout = cronTime(NULL) + timeout;
  fnc->rpcRepliesExpected = 0;
  fnc->rpcRepliesReceived = 0;
  fnc->async_handle = NULL;
  MUTEX_CREATE_RECURSIVE(&fnc->lock);

  /* find peers in local peer-list that participate in
     the given table */
  fnc->k = findLocalNodes(table,
			  key,
			  (PeerIdentity*) fnc->matches,
			  ALPHA);
#if DEBUG_DHT
  LOG(LOG_DEBUG,
      "found %d participating nodes in local routing table.\n",
      fnc->k);
#endif
  for (i=0;i<fnc->k;i++) {
    /* we found k nodes participating in the table; ask these
       k nodes to search further (in this table, with this key,
       with this timeout).  Improve k-best node until timeout
       expires */
    create_find_nodes_rpc((PeerIdentity*) &fnc->matches[i],
			  fnc);     		
  }

  /* also search for more peers for this table? */
  fnc->async_handle = NULL;
  if (fnc->k < ALPHA) {
    if (equalsHashCode512(table,
			  &masterTableId)) {
#if DEBUG_DHT
      LOG(LOG_DEBUG,
	  "broadcasting RPC ping to find other peers for master table.\n");
#endif
     /* No or too few other DHT peers known, search
	 for more by sending a PING to all connected peers
	 that are not in the table already */
      coreAPI->forAllConnectedNodes((PerNodeCallback)&request_DHT_ping,
				    fnc);
    } else {
#if DEBUG_DHT
      IFLOG(LOG_DEBUG,
	    hash2enc(table,
		     &enc));
      LOG(LOG_DEBUG,
	  "performing RPC `%s' to find other peers participating in table `%s'.\n",
	  "DHT_findValue",
	  &enc);
#endif
      /* try finding peers responsible for this table using
	 the master table */
      fnc->async_handle
	= dht_get_async_start(&masterTableId,
			      0, /* type */
			      1, /* 1 key */
			      table, /* key */
			      timeout,
			      (DataProcessor) &findnodes_dht_master_get_callback,
			      fnc,
			      NULL,
			      NULL);
    }
  }
  return fnc;
}

/**
 * This stops the asynchronous findNodes process.  The search is aborted
 * and the k-best results are passed to the callback.
 *
 * @param fnc context returned from findNodes_start
 * @param callback function to call for each peer found
 * @param closure extra argument to the callback
 * @return number of peers found, SYSERR on error
 */
static int findNodes_stop(FindNodesContext * fnc,
			  NodeFoundCallback callback,
			  void * closure) {
  int i;

  ENTER();
  /* stop async DHT get */
  if (fnc->async_handle != NULL) {
    dht_get_async_stop(fnc->async_handle);
    fnc->async_handle = NULL;
  }

  /* stop all async RPCs */
  for (i=fnc->rpcRepliesExpected-1;i>=0;i--)
    rpcAPI->RPC_stop(fnc->rpc[i]);
  SEMAPHORE_FREE(fnc->signal);
  MUTEX_DESTROY(&fnc->lock);

  /* Finally perform callbacks on collected k-best nodes. */
  if (callback != NULL)
    for (i=fnc->k-1;i>=0;i--)
      callback((PeerIdentity*)&fnc->matches[i], closure);
  FREE(fnc->matches);
  i = fnc->k;
  FREE(fnc);
  return i;
}

/**
 * We found a peer in the MasterTable that supports the table that
 * we're trying to find peers for.  Notify the caller about this peer.
 *
 * @param value should contain a set of HeloMessages corresponding
 *  to the identities of peers that support the table that we're
 *  looking for; pass those Helos to the core *and* to the callback
 *  as peers supporting the table.
 */
static void find_k_nodes_dht_master_get_callback(const HashCode512 * key,
						 const DataContainer * cont,
						 FindKNodesContext * fnc) {
  unsigned int pos;
  unsigned int dataLength;
  const PeerIdentity * value;
#if DEBUG_DHT
  EncName enc;
#endif

  ENTER();
  dataLength = ntohl(cont->size) - sizeof(DataContainer);
  value = (const PeerIdentity*) &cont[1];

  /* parse value, try to DHT-ping the new peers
     (to add it to the table; if that succeeds
     the peer will automatically trigger the ping_reply_handler
     which will in turn trigger create_find_nodes_rpc) */
  if ( (dataLength % sizeof(PeerIdentity)) != 0) {
    LOG(LOG_WARNING,
	_("Malformed response to `%s' on master table.\n"),
	"DHT_findValue");
    return;
  }
  for (pos = 0;pos<dataLength/sizeof(PeerIdentity);pos++) {
    const PeerIdentity * msg;

    msg = &value[pos];
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(&msg->hashPubKey,
		   &enc));
    LOG(LOG_DEBUG,
	"master table returned peer `%s' in `%s' operation.\n",
	&enc,
	"DHT_findValue");
#endif
    MUTEX_LOCK(&fnc->lock);
    if (fnc->k > 0) {
      if (fnc->callback != NULL)
	fnc->callback(msg,
		      fnc->closure);
      fnc->k--;
      fnc->found++;
    }
    MUTEX_UNLOCK(&fnc->lock);
  }
}

/**
 * In the induced sub-structure for the given 'table', find k nodes
 * close to the given key that participate in that table.  Any node in
 * the table will do, but preference is given to nodes that are close.
 * Still, the first k nodes that were found are returned (just the
 * search goes towards the key).  This function is used for lookups
 * in tables in which this peer does not participate in.
 *
 * If no (zero!) participating nodes are found locally, the a set of
 * introduction nodes for this table is obtained from the master table
 * (using RPC get).  For the master table we try to discover peers
 * participating in the DHT using broadcasts to all connected peers
 * (relying on GNUnet core peer discovery).
 *
 * If we learn about new nodes in this step, add them to the RT table;
 * if we run out of space in the RT, send pings to oldest entry; if
 * oldest entry did not respond to PING, replace it!
 *
 * @param table the table which the peers must participate in,
 *        for this function, this should NEVER be the master-table.
 * @param key the target key to use for routing
 * @param timeout how long to tell the RPCs that we will wait
 *  (note that the caller is supposed to call findNodes_stop
 *   to finally collect the collected nodes)
 * @param k number of nodes to find
 * @param callback function to call for each peer found
 * @param closure extra argument to the callback
 * @return context for findKNodes_stop
 */
static FindKNodesContext * findKNodes_start(const DHT_TableId * table,
					    const HashCode512 * key,
					    cron_t timeout,
					    unsigned int k,
					    NodeFoundCallback callback,
					    void * closure) {
  FindKNodesContext * fnc;
  int i;
  int found;
  PeerIdentity * matches;
#if DEBUG_DHT
  EncName enc;

  ENTER();
  hash2enc(table,
	   &enc);
  LOG(LOG_DEBUG,
      "`%s' called to find %d nodes that participate in table `%s'.\n",
      __FUNCTION__,
      k,
      &enc);
#endif
  fnc = MALLOC(sizeof(FindKNodesContext));
  fnc->key = *key;
  fnc->table = *table;
  fnc->k = k;
  fnc->callback = callback;
  fnc->closure = closure;
  fnc->timeout = cronTime(NULL) + timeout;
  fnc->rpcRepliesExpected = 0;
  fnc->rpcRepliesReceived = 0;
  fnc->found = 0;
  MUTEX_CREATE_RECURSIVE(&fnc->lock);
  matches = MALLOC(sizeof(PeerIdentity) * fnc->k);

  /* find peers in local peer-list that participate in
     the given table */
  found = findLocalNodes(table,
			 key,
			 matches,
			 k);
  if (callback != NULL)
    for (i=0;i<found;i++)
      callback(&matches[i],
	       closure);
  if (found == k) {
#if DEBUG_DHT
    LOG(LOG_DEBUG,
	"`%s' found %d nodes in local table, no remote requests needed.\n",
	__FUNCTION__,
	k);
#endif
    FREE(matches);
    return fnc; /* no need for anything else, we've found
		   all we care about! */
  }
  fnc->k -= found;
  fnc->found = found;
  FREE(matches);

  /* also do 'get' to find for more peers for this table */
  fnc->async_handle = NULL;
  if (equalsHashCode512(table,
			  &masterTableId)) {
    BREAK();
    /* findKNodes_start called for masterTable.  That should not happen! */
  } else {
 #if DEBUG_DHT
    LOG(LOG_DEBUG,
	"`%s' sends request to find %d in master table.\n",
	__FUNCTION__,
	k);
#endif
    /* try finding peers responsible for this table using
       the master table */
    fnc->async_handle
      = dht_get_async_start(&masterTableId,
			    0, /* type */
			    1, /* key count */
			    table, /* keys */
			    timeout,
			    (DataProcessor)&find_k_nodes_dht_master_get_callback,
			    fnc,
			    NULL,
			    NULL);
  }
  return fnc;
}

/**
 * This stops the asynchronous find-k-Nodes process.
 * The search is aborted.
 *
 * @param fnc context returned from findNodes_start
 * @return number of peers found, SYSERR on error
 */
static int findKNodes_stop(FindKNodesContext * fnc) {
  int i;
  /* stop async DHT get */
  ENTER();
  if (fnc->async_handle != NULL) {
    dht_get_async_stop(fnc->async_handle);
    fnc->async_handle = NULL;
  }

  /* stop all async RPCs */
  for (i=fnc->rpcRepliesExpected-1;i>=0;i--)
    rpcAPI->RPC_stop(fnc->rpc[i]);
  MUTEX_DESTROY(&fnc->lock);

  i = fnc->found;
  FREE(fnc);
  return i;
}

/**
 * We got a reply from the DHT_store operation.  Update the
 * record datastructures accordingly (and call the record's
 * callback).
 *
 * @param results::peer created in rpc_DHT_store_abort
 */
static void dht_put_rpc_reply_callback(const PeerIdentity * responder,
				       RPC_Param * results,
				       DHT_PUT_RECORD * record) {
  PeerIdentity * peer;
  unsigned int dataLength;
  PeerInfo * pos;
  unsigned int i;
  unsigned int max;

  ENTER();
  processOptionalFields(responder, results);
  MUTEX_LOCK(&record->lock);
  pos = findPeerInfo(responder);
  pos->lastActivity = cronTime(NULL);

  max = RPC_paramCount(results);
  for (i=0;i<max;i++) {
    if (0 != strcmp("peer",
		    RPC_paramName(results, i)))
      continue; /* ignore */
    if ( (OK != RPC_paramValueByPosition(results,
					 i,
					 &dataLength,
					 (void**)&peer)) ||
	 (dataLength != sizeof(PeerIdentity)) ) {
      EncName enc;

      MUTEX_UNLOCK(&record->lock);
      hash2enc(&responder->hashPubKey,
	       &enc);
      LOG(LOG_WARNING,
	  _("Invalid response to `%s' from `%s'\n"),
	  "DHT_put",
	  &enc);
      return;
    }
  }
  MUTEX_UNLOCK(&record->lock);
}

/**
 * Send an (async) DHT put to the given peer.  Replies are to be
 * processed by the callback in record.  The RPC async handle is to be
 * stored in the records rpc list.  Locking is not required.
 */
static void send_dht_put_rpc(const PeerIdentity * peer,
			     DHT_PUT_RECORD * record) {
  RPC_Param * param;
  unsigned long long timeout;
  cron_t delta;
  cron_t now;
#if DEBUG_DHT
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&peer->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "sending RPC `%s' to peer `%s'.\n",
      "DHT_store",
      &enc);
#endif
  ENTER();
  if (isNotCloserThanMe(&record->table,
			peer,		
			&record->key))
    return;
  cronTime(&now);
  if (record->timeout > now)
    delta = (record->timeout - now) / 2;
  else
    delta = 0;
  timeout = htonll(delta);
  param = RPC_paramNew();
  RPC_paramAdd(param,
	       "table",
	       sizeof(DHT_TableId),
	       &record->table);
  RPC_paramAdd(param,
	       "key",
	       sizeof(HashCode512),
	       &record->key);
  RPC_paramAdd(param,
	       "timeout",
	       sizeof(unsigned long long),
	       &timeout);
  RPC_paramAddDataContainer(param,
			    "value",
			    record->value);
  GROW(record->rpc,
       record->rpcRepliesExpected,
       record->rpcRepliesExpected+1);
  addOptionalFields(param);
  record->rpc[record->rpcRepliesExpected-1]
    = rpcAPI->RPC_start(peer,
		        "DHT_store",
			param,
			0,
			delta,
			(RPC_Complete) &dht_put_rpc_reply_callback,
			record);
  RPC_paramFree(param);
}


/**
 * Perform an asynchronous PUT operation on the DHT identified by
 * 'table' storing a binding of 'key' to 'value'.  The peer does not
 * have to be part of the table (if so, we will attempt to locate a
 * peer that is!)
 *
 * @param table table to use for the lookup
 * @param key the key to look up
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param callback function to call on successful completion
 * @param closure extra argument to callback
 * @return handle to stop the async put
 */
static struct DHT_PUT_RECORD *
dht_put_async_start(const DHT_TableId * table,
		    const HashCode512 * key,
		    cron_t timeout,
		    const DataContainer * value,
		    DHT_OP_Complete callback,
		    void * closure) {
  int i;
  LocalTableData * ltd;
  DHT_PUT_RECORD * ret;
  unsigned int count;
#if DEBUG_DHT
  EncName enc;
  EncName enc2;

  if (value == NULL) {
    BREAK();
    return NULL;
  }

  ENTER();
  IFLOG(LOG_DEBUG,
	hash2enc(key,
		 &enc));
  IFLOG(LOG_DEBUG,
	hash2enc(table,
		 &enc2));
  LOG(LOG_DEBUG,
      "performing `%s' operation on key `%s' and table `%s'.\n",
      "DHT_PUT",
      &enc,
      &enc2);
#endif
  if (timeout > 1 * cronHOURS) {
    LOG(LOG_WARNING,
	_("`%s' called with timeout above 1 hour (bug?)\n"),
	__FUNCTION__);
    timeout = 1 * cronHOURS;
  }
  ret = MALLOC(sizeof(DHT_PUT_RECORD));
  ret->timeout = cronTime(NULL) + timeout;
  ret->key = *key;
  ret->table = *table;
  ret->callback = callback;
  ret->closure = closure;
  ret->value = MALLOC(ntohl(value->size));
  memcpy(ret->value,
	 value,
	 ntohl(value->size));
  MUTEX_CREATE_RECURSIVE(&ret->lock);
  ret->rpc = NULL;
  ret->rpcRepliesExpected = 0;
  ret->kfnc = NULL;
  MUTEX_LOCK(lock);


  ltd = getLocalTableData(table);
  if (ltd != NULL) {
    PeerIdentity * hosts;
#if DEBUG_DHT
    IFLOG(LOG_DEBUG,
	  hash2enc(table,
		   &enc));
    LOG(LOG_DEBUG,
	"I participate in the table `%s' for the `%s' operation.\n",
	&enc,
	"DHT_PUT");
#endif
    /* We do participate in the table, it is fair to assume
       that we know the relevant peers in my neighbour set */
    hosts = MALLOC(sizeof(PeerIdentity) * ALPHA);
    count = findLocalNodes(table,
			   key,
			   hosts,
			   ALPHA);
    /* try adding this peer to hosts */
    k_best_insert(ALPHA,
		  &count,
		  key,
		  (HashCode512*) hosts,
		  &coreAPI->myIdentity->hashPubKey);
    if (count == 0) {
      BREAK();
      /* Assertion failed: I participate in a table but findLocalNodes returned 0! */
      MUTEX_UNLOCK(lock);
      return NULL;
    }
    /* if this peer is in 'hosts', try local datastore lookup */
    for (i=0;i<count;i++) {
      if (hostIdentityEquals(coreAPI->myIdentity,
			     &hosts[i])) {
	if (OK == ltd->store->put(ltd->store->closure,
				  key,
				  value,
				  0 /* FIXME: priority */))
	  ret->confirmed_stores++;
	break;
      }
    }

    /* send dht_put_RPC to the other peers */
    for (i=0;i<count;i++)
      if (! hostIdentityEquals(coreAPI->myIdentity,
			       &hosts[i]))
	send_dht_put_rpc(&hosts[i],
			 ret);
  } else {
    /* We do not particpate in the table; hence we need to use
       findKNodes to find an initial set of peers in that
       table; findKNodes tries to find k nodes and instantly
       allows us to query each node found.  For each peer found,
       we then perform send_dht_put_rpc.
    */
    ret->kfnc
      = findKNodes_start(table,
			 key,
			 timeout,
			 ALPHA,
			 (NodeFoundCallback) &send_dht_put_rpc,
			 ret);
  }
  /* FIXME: ensure we call OP_Complete callback
     after timeout! */
  MUTEX_UNLOCK(lock);
  return ret;
}

/**
 * Stop async DHT-put.  Frees associated resources.
 */
static int dht_put_async_stop(struct DHT_PUT_RECORD * record) {
  int i;

  ENTER();
  if (record == NULL)
    return SYSERR;

  /* abort findKNodes (if running) - it may cause
     the addition of additional RPCs otherwise! */
  if (record->kfnc != NULL)
    findKNodes_stop(record->kfnc);

  for (i=0;i<record->rpcRepliesExpected;i++)
    rpcAPI->RPC_stop(record->rpc[i]);
  MUTEX_DESTROY(&record->lock);
  i = record->confirmed_stores;
  FREE(record->value);
  FREE(record);
  if (i > 0)
    return OK;
  else
    return SYSERR;
}

/**
 * We got a reply from the DHT_remove operation.  Update the
 * record datastructures accordingly (and call the record's
 * callback).
 *
 * @param results::peer created in rpc_DHT_store_abort
 */
static void dht_remove_rpc_reply_callback(const PeerIdentity * responder,
					  RPC_Param * results,
					  DHT_REMOVE_RECORD * record) {
  PeerIdentity * peer;
  unsigned int dataLength;
  PeerInfo * pos;
  unsigned int i;
  unsigned int max;

  ENTER();
  processOptionalFields(responder, results);
  MUTEX_LOCK(&record->lock);
  pos = findPeerInfo(responder);
  pos->lastActivity = cronTime(NULL);
  max = RPC_paramCount(results);
  for (i=0;i<max;i++) {
    if (0 != strcmp("peer",
		    RPC_paramName(results, i)))
      continue; /* ignore */
    if ( (OK != RPC_paramValueByPosition(results,
					 i,
					 &dataLength,
					 (void**)&peer)) ||
	 (dataLength != sizeof(PeerIdentity)) ) {
      EncName enc;

      MUTEX_UNLOCK(&record->lock);
      hash2enc(&responder->hashPubKey,
	       &enc);
      LOG(LOG_WARNING,
	  _("Invalid response to `%s' from `%s'\n"),
	  "DHT_remove",
	  &enc);
      return;
    }
    record->confirmed_stores++;
  }
  MUTEX_UNLOCK(&record->lock);
}

/**
 * Send an (async) DHT remove to the given peer.  Replies are to be
 * processed by the callback in record.  The RPC async handle is to be
 * stored in the records rpc list.  Locking is not required.
 */
static void send_dht_remove_rpc(const PeerIdentity * peer,
				DHT_REMOVE_RECORD * record) {
  RPC_Param * param;
  unsigned long long timeout;
  cron_t delta;
  cron_t now;
#if DEBUG_DHT
  EncName enc;

  ENTER();
  IFLOG(LOG_DEBUG,
	hash2enc(&peer->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "sending RPC `%s' to peer `%s'.\n",
      "DHT_remove",
      &enc);
#endif
  if (isNotCloserThanMe(&record->table,
			peer,		
			&record->key))
    return; /* refuse! */
  cronTime(&now);
  if (record->timeout > now)
    delta = (record->timeout - now) / 2;
  else
    delta = 0;
  timeout = htonll(delta);
  param = RPC_paramNew();
  RPC_paramAdd(param,
	       "table",
	       sizeof(DHT_TableId),
	       &record->table);
  RPC_paramAdd(param,
	       "key",
	       sizeof(HashCode512),
	       &record->key);
  RPC_paramAdd(param,
	       "timeout",
	       sizeof(unsigned long long),
	       &timeout);
  if (record->value != NULL)
    RPC_paramAddDataContainer(param,
			      "value",
			      record->value);
  GROW(record->rpc,
       record->rpcRepliesExpected,
       record->rpcRepliesExpected+1);
  addOptionalFields(param);
  record->rpc[record->rpcRepliesExpected-1]
    = rpcAPI->RPC_start(peer,
		        "DHT_remove",
			param,
			0,
			delta,
			(RPC_Complete) &dht_remove_rpc_reply_callback,
			record);
  RPC_paramFree(param);
}

/**
 * Perform an asynchronous REMOVE operation on the DHT identified by
 * 'table' removing the binding of 'key' to 'value'.  The peer does not
 * have to be part of the table (if so, we will attempt to locate a
 * peer that is!)
 *
 * @param table table to use for the lookup
 * @param key the key to look up
 * @param timeout how long to wait until this operation should
 *        automatically time-out (relative time)
 * @param callback function to call on successful completion
 * @param closure extra argument to callback
 * @return handle to stop the async remove
 */
static struct DHT_REMOVE_RECORD *
dht_remove_async_start(const DHT_TableId * table,
		       const HashCode512 * key,
		       cron_t timeout,
		       const DataContainer * value,
		       DHT_OP_Complete callback,
		       void * closure) {
  int i;
  LocalTableData * ltd;
  DHT_REMOVE_RECORD * ret;
  unsigned int count;

  if (timeout > 1 * cronHOURS) {
    LOG(LOG_WARNING,
	_("`%s' called with timeout above 1 hour (bug?)\n"),
	__FUNCTION__);
    timeout = 1 * cronHOURS;
  }
  ENTER();
  ret = MALLOC(sizeof(DHT_REMOVE_RECORD));
  ret->timeout = cronTime(NULL) + timeout;
  ret->key = *key;
  ret->table = *table;
  ret->callback = callback;
  ret->closure = closure;
  if (value == NULL) {
    ret->value = NULL;
  } else {
    ret->value = MALLOC(ntohl(value->size));
    memcpy(ret->value,
	   value,
	   ntohl(value->size));
  }
  MUTEX_CREATE_RECURSIVE(&ret->lock);
  ret->rpc = NULL;
  ret->rpcRepliesExpected = 0;
  ret->confirmed_stores = 0;
  ret->kfnc = NULL;
  MUTEX_LOCK(lock);


  ltd = getLocalTableData(table);
  if (ltd != NULL) {
    PeerIdentity * hosts;
    /* We do participate in the table, it is fair to assume
       that we know the relevant peers in my neighbour set */
    hosts = MALLOC(sizeof(PeerIdentity) * ALPHA);
    count = findLocalNodes(table,
			   key,
			   hosts,
			   ALPHA);
    /* try adding this peer to hosts */
    k_best_insert(ALPHA,
		  &count,
		  key,
		  (HashCode512*) hosts,
		  &coreAPI->myIdentity->hashPubKey);
    if (count == 0) {
      BREAK();
      /* Assertion failed: I participate in a table but findLocalNodes returned 0! */
      MUTEX_UNLOCK(lock);
      return NULL;
    }
    /* if this peer is in 'hosts', try local datastore lookup */
    for (i=0;i<count;i++) {
      if (hostIdentityEquals(coreAPI->myIdentity,
			     &hosts[i])) {
	if (OK == ltd->store->del(ltd->store->closure,
				  key,
				  value))
	  ret->confirmed_stores++;
	break;
      }
    }

    /* send dht_remove_RPC to the other peers */
    for (i=0;i<count;i++)
      if (! hostIdentityEquals(coreAPI->myIdentity,
			       &hosts[i]))
	send_dht_remove_rpc(&hosts[i],
			    ret);
  } else {
    /* We do not particpate in the table; hence we need to use
       findKNodes to find an initial set of peers in that
       table; findKNodes tries to find k nodes and instantly
       allows us to query each node found.  For each peer found,
       we then perform send_dht_remove_rpc.
    */
    ret->kfnc
      = findKNodes_start(table,
			 key,
			 timeout,
			 ALPHA,
			 (NodeFoundCallback) &send_dht_remove_rpc,
			 ret);
  }
  MUTEX_UNLOCK(lock);
  return ret;
}

/**
 * Stop async DHT-remove.  Frees associated resources.
 */
static int dht_remove_async_stop(struct DHT_REMOVE_RECORD * record) {
  int i;

  ENTER();
  if (record == NULL)
    return SYSERR;

  /* abort findKNodes (if running) - it may cause
     the addition of additional RPCs otherwise! */
  if (record->kfnc != NULL)
    findKNodes_stop(record->kfnc);

  for (i=0;i<record->rpcRepliesExpected;i++)
    rpcAPI->RPC_stop(record->rpc[i]);
  MUTEX_DESTROY(&record->lock);
  i = record->confirmed_stores;
  FREE(record->value);
  FREE(record);
  if (i > 0)
    return OK;
  else
    return SYSERR;
}

/**
 * Join a table (start storing data for the table).  Join
 * fails if the node is already joint with the particular
 * table.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @param timeout NOT USED.  Remove?
 * @return SYSERR on error, OK on success
 */
static int dht_join(Blockstore * datastore,
		    const DHT_TableId * table) {
  int i;

  ENTER();
  MUTEX_LOCK(lock);
  for (i=0;i<tablesCount;i++) {
    if (equalsDHT_TableId(&tables[i].id, table)) {
      MUTEX_UNLOCK(lock);
      return SYSERR;
    }
  }
  GROW(tables,
       tablesCount,
       tablesCount+1);
  tables[tablesCount-1].id = *table;
  tables[tablesCount-1].store = datastore;
  MUTEX_UNLOCK(lock);
  return OK;
}

/**
 * Leave a table (stop storing data for the table).  Leave
 * fails if the node is not joint with the table.  Blocks
 * for at most timeout ms to migrate content elsewhere.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @return SYSERR on error, OK on success
 */
static int dht_leave(const DHT_TableId * table) {
  int i;
  int idx;
  LocalTableData old;
  DHT_REMOVE_RECORD * remRec;

  ENTER();
  MUTEX_LOCK(lock);
  idx = -1;
  for (i=0;i<tablesCount;i++) {
    if (equalsDHT_TableId(&tables[i].id, table)) {
      idx = i;
      break;
    }
  }
  if (idx == -1) {
    MUTEX_UNLOCK(lock);
    return SYSERR;
  }
  old = tables[i];
  tables[i] = tables[tablesCount-1];
  GROW(tables,
       tablesCount,
       tablesCount-1);
  MUTEX_UNLOCK(lock);
  if (! equalsHashCode512(&masterTableId,
			  table)) {
    /* issue dht_remove to remove this peer
       from the master table for this table;
       not needed/possible if we quit the DHT
       altogether... */
    DataContainer * value;

    value = MALLOC(sizeof(PeerIdentity) + sizeof(DataContainer));
    value->size = htonl(sizeof(PeerIdentity) + sizeof(DataContainer));
    memcpy(&value[1],
	   coreAPI->myIdentity,
	   sizeof(PeerIdentity));
    remRec = dht_remove_async_start(&masterTableId,
				    table,
				    0,
				    value,
				    NULL,
				    NULL);
    dht_remove_async_stop(remRec);
  }
  return OK;
}

/**
 * We received a PING from another DHT.  The appropriate response
 * is to send a list of the tables that this peer participates in.
 *
 * @param arguments do we need any?
 * @param results::tables the tables we participate in (DHT_TableIds)
 * @param helos::hellos for this peer (optional)
 */
static void rpc_DHT_ping(const PeerIdentity * sender,
			 RPC_Param * arguments,
			 RPC_Param * results) {
#if DEBUG_DHT
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&sender->hashPubKey,
		 &enc));
  LOG(LOG_DEBUG,
      "Received RPC `%s' from peer `%s'.\n",
      "DHT_ping",
      &enc);
#endif
  ENTER();
  processOptionalFields(sender, arguments);
  /* processes 'tables' */
  addOptionalFields(results);
  /* adds 'tables' (with very high probability since there's nothing else,
     except if we participate in over 50 tables, which would be bad...) */
}

/**
 * Find nodes that we know of that participate in the given
 * table and that are close to the given key.
 *
 * @param arguments::key the key to route towards
 * @param arguments::table the id of the table
 * @param results::peers list of peers found to participate in the given table with ID close to key;
 *    peers consists of HostIdentities one after the other. See
 *    create_find_nodes_rpc_complete_callback for the parser of the reply.
 * @param results::tables list of tables that this peer participates in (optional)
 */
static void rpc_DHT_findNode(const PeerIdentity * sender,
			     RPC_Param * arguments,
			     RPC_Param * results) {
  HashCode512 * key;
  DHT_TableId * table;
  unsigned int dataLength;
  unsigned int count;
  unsigned int k;
  PeerIdentity * peers;

  ENTER();
  processOptionalFields(sender, arguments);
  key = NULL;
  table = NULL;
  if ( (OK != RPC_paramValueByName(arguments,
				   "key",
				   &dataLength,
				   (void**) &key)) ||
       (dataLength != sizeof(HashCode512)) ||
       (OK != RPC_paramValueByName(arguments,
				   "table",
				   &dataLength,
				   (void**) &table)) ||
       (dataLength != sizeof(DHT_TableId)) ) {
    LOG(LOG_WARNING,
	_("Received invalid RPC `%s'.\n"),
	"DHT_findNode");
    return;
  }
  k = ALPHA; /* optionally obtain k from arguments??? */
  peers = MALLOC(sizeof(PeerIdentity) * k);
  count = findLocalNodes(table,
			 key,
			 peers,
			 k);
  RPC_paramAdd(results,
	       "peer",
	       count * sizeof(PeerIdentity),
	       peers);
  FREE(peers);
  addOptionalFields(results);
}

/**
 * Cron-job to abort an rpc_DHT_findValue operation on timeout.
 * Takes the existing set of results and constructs a reply for
 * the RPC callback.  If there are no replies, responds with
 * timeout.<p>
 *
 * The result is parsed in dht_findvalue_rpc_reply_callback.
 */
static void rpc_DHT_findValue_abort(RPC_DHT_FindValue_Context * fw) {
  RPC_Param * results;

  ENTER();
  delAbortJob((CronJob) &rpc_DHT_findValue_abort,
	      fw);
  MUTEX_LOCK(&fw->lock);
  if (fw->done == YES) {
    MUTEX_UNLOCK(&fw->lock);
    return;
  }
  dht_get_async_stop(fw->get_record);
  fw->get_record = NULL;

  /* build RPC reply, call RPC callback */
  if (fw->callback != NULL) {
    results = RPC_paramNew();
    addOptionalFields(results);
    fw->callback(results,
		 OK,
		 fw->rpc_context);
    RPC_paramFree(results);
  }
  fw->done = YES;
  MUTEX_UNLOCK(&fw->lock);
}

/**
 * Job that adds a given reply to the list of replies for this
 * find-value operation.  If the maximum number of results has
 * been accumulated this will also stop the cron-job and trigger
 * sending the cummulative reply via RPC.
 */
static int rpc_dht_findValue_callback(const HashCode512 * key,
				      const DataContainer * value,
				      RPC_DHT_FindValue_Context * fw) {
  ENTER();
  MUTEX_LOCK(&fw->lock);
  GROW(fw->results,
       fw->count,
       fw->count+1);
  fw->results[fw->count-1] = MALLOC(ntohl(value->size));
  memcpy(fw->results[fw->count-1],
	 value,
	 ntohl(value->size));
  MUTEX_UNLOCK(&fw->lock);
  return OK;
}

static void rpc_dht_findValue_complete(RPC_DHT_FindValue_Context * ctx) {
  /* FIXME! */

}

/**
 * Asynchronous RPC function called for 'findValue' RPC.
 *
 * @param arguments::keys the keys to search for
 * @param arguments::table the table to search in
 * @param arguments::timeout how long to wait at most
 * @param arguments::type type of the request (block type)
 * @param callback function to call with results when done
 * @param context additional argument to callback
 * @param results::data the result of the get operation
 * @param results::tables optional argument describing the tables
 *   that this peer participates in
 */
static void rpc_DHT_findValue(const PeerIdentity * sender,
			      RPC_Param * arguments,
			      Async_RPC_Complete_Callback callback,
			      struct CallInstance * rpc_context) {
  HashCode512 * keys;
  DHT_TableId * table;
  unsigned long long * timeout;
  unsigned int * type;
  unsigned int keysLength;
  unsigned int dataLength;
  RPC_DHT_FindValue_Context * fw_context;

  ENTER();
  processOptionalFields(sender, arguments);
  /* parse arguments */
  if ( (OK != RPC_paramValueByName(arguments,
				   "keys",
				   &keysLength,
				   (void**) &keys)) ||
       (0 != (keysLength % sizeof(HashCode512))) ||
       (OK != RPC_paramValueByName(arguments,
				   "table",
				   &dataLength,
				   (void**) &table)) ||
       (dataLength != sizeof(DHT_TableId)) ||
       (OK != RPC_paramValueByName(arguments,
				   "timeout",
				   &dataLength,
				   (void**) &timeout)) ||
       (dataLength != sizeof(unsigned long long)) ||
       (OK != RPC_paramValueByName(arguments,
				   "type",
				   &dataLength,
				   (void**) &type)) ||
       (dataLength != sizeof(unsigned int)) ) {
    LOG(LOG_WARNING,
	_("Received invalid RPC `%s'.\n"),
	"DHT_findValue");
    return;
  }

  fw_context
    = MALLOC(sizeof(RPC_DHT_FindValue_Context));
  MUTEX_CREATE_RECURSIVE(&fw_context->lock);
  fw_context->count
    = 0;
  fw_context->done
    = NO;
  fw_context->results
    = NULL;
  fw_context->callback
    = callback;
  fw_context->rpc_context
    = rpc_context;
  fw_context->get_record
    = dht_get_async_start(table,
			  ntohl(*type),
			  keysLength / sizeof(HashCode512),
			  keys,
			  ntohll(*timeout),
			  (DataProcessor) &rpc_dht_findValue_callback,
			  fw_context,
			  (DHT_OP_Complete) &rpc_dht_findValue_complete,
			  fw_context);
  /* FIXME: manage abort properly, also fix
     rpc_dht_findValue_complete! */
  addAbortJob((CronJob)&rpc_DHT_findValue_abort,
	      fw_context);
  addCronJob((CronJob)&rpc_DHT_findValue_abort,
	     ntohll(*timeout),
	     0,
	     fw_context);
}

/**
 * Cron-job to abort an rpc_DHT_store operation on timeout.
 * Takes the existing set of results and constructs a reply for
 * the RPC callback.  If there are no replies, responds with
 * timeout.<p>
 *
 * The result is parsed in dht_put_rpc_reply_callback.
 */
static void rpc_DHT_store_abort(RPC_DHT_store_Context * fw) {
  RPC_Param * results;

  ENTER();
  delAbortJob((CronJob) &rpc_DHT_store_abort,
	      fw);
  MUTEX_LOCK(&fw->lock);
  if (fw->done == YES) {
    MUTEX_UNLOCK(&fw->lock);
    return;
  }
  dht_put_async_stop(fw->put_record);
  fw->put_record = NULL;

  /* build RPC reply, call RPC callback */
  if (fw->callback != NULL) {
    results = RPC_paramNew();
    addOptionalFields(results);
    fw->callback(results,
		 OK,
		 fw->rpc_context);
    RPC_paramFree(results);
  }
  fw->done = YES;
  MUTEX_UNLOCK(&fw->lock);
}

/**
 * Job that adds a given reply to the list of replies for this
 * store operation.  If the maximum number of peers has stored
 * the value, this will also stop the cron-job and trigger
 * sending the cummulative reply via RPC.
 */
static void rpc_dht_store_callback(RPC_DHT_store_Context * fw) {
  /* FIXME: shutdown coordination! */
}

static void rpc_DHT_store(const PeerIdentity * sender,
			  RPC_Param * arguments,
			  Async_RPC_Complete_Callback callback,
			  struct CallInstance * rpc_context) {
  HashCode512 * key;
  DHT_TableId * table;
  unsigned int dataLength;
  DataContainer * value;
  unsigned long long * timeout;
  RPC_DHT_store_Context * fw_context;
  LocalTableData * ltd;

  ENTER();
  processOptionalFields(sender, arguments);
  /* parse arguments */
  if ( (OK != RPC_paramValueByName(arguments,
				   "key",
				   &dataLength,
				   (void**) &key)) ||
       (dataLength != sizeof(HashCode512)) ||
       (OK != RPC_paramValueByName(arguments,
				   "table",
				   &dataLength,
				   (void**) &table)) ||
       (dataLength != sizeof(DHT_TableId)) ||
       (OK != RPC_paramValueByName(arguments,
				   "timeout",
				   &dataLength,
				   (void**) &timeout)) ||
       (dataLength != sizeof(unsigned long long)) ||
       ((NULL == (value = RPC_paramDataContainerByName(arguments,
						       "value")))) ) {
    LOG(LOG_WARNING,
	_("Received invalid RPC `%s'.\n"),
	"DHT_store");
    return;
  }

  fw_context
    = MALLOC(sizeof(RPC_DHT_store_Context));
  MUTEX_CREATE_RECURSIVE(&fw_context->lock);
  MUTEX_LOCK(lock);
  ltd = getLocalTableData(table);
  if (ltd == NULL) {
    LOG(LOG_WARNING,
	_("RPC for `%s' received for table that we do not participate in!\n"),
	"DHT_store");
  }
  MUTEX_UNLOCK(lock);
  fw_context->done
    = NO;
  fw_context->callback
    = callback;
  fw_context->rpc_context
    = rpc_context;
  fw_context->put_record
    = dht_put_async_start(table,
			  key,
			  ntohll(*timeout),
			  value,
			  (DHT_OP_Complete) &rpc_dht_store_callback,
			  fw_context);
  /* FIXME: fix shutdown
     (also fix rpc_dht_store_callback) */
  addAbortJob((CronJob)&rpc_DHT_store_abort,
	      fw_context);
  addCronJob((CronJob)&rpc_DHT_store_abort,
	     ntohll(*timeout),
	     0,
	     fw_context);
  FREE(value);
}

/**
 * Cron-job to abort an rpc_DHT_remove operation on timeout.
 * Takes the existing set of results and constructs a reply for
 * the RPC callback.  If there are no replies, responds with
 * timeout.<p>
 *
 * The result is parsed in dht_remove_rpc_reply_callback.
 */
static void rpc_DHT_remove_abort(RPC_DHT_remove_Context * fw) {
  RPC_Param * results;

  ENTER();
  delAbortJob((CronJob) &rpc_DHT_remove_abort,
	      fw);
  MUTEX_LOCK(&fw->lock);
  if (fw->done == YES) {
    MUTEX_UNLOCK(&fw->lock);
    return;
  }
  dht_remove_async_stop(fw->remove_record);
  fw->remove_record = NULL;

  /* build RPC reply, call RPC callback */
  results = RPC_paramNew();
  addOptionalFields(results);
  if (fw->callback != NULL)
    fw->callback(results,
		 OK,
		 fw->rpc_context);
  RPC_paramFree(results);
  fw->done = YES;
  MUTEX_UNLOCK(&fw->lock);
}

/**
 * Job that adds a given reply to the list of peers that have removed
 * this find-value operation.  If the number of peers reaches the
 * number of replicas this will also stop the cron-job and trigger
 * sending the cummulative reply via RPC.
 */
static void rpc_dht_remove_callback(RPC_DHT_remove_Context * fw) {
  /* FIXME: shutdown sequence! */
}

/**
 * ASYNC RPC call for removing entries from the DHT.
 *
 * @param arguments::key the key to remove
 * @param arguments::table the table to remove data from
 * @param arguments::timeout how long to wait at most
 * @param arguments::value optional argument specifying which
 *    value to remove from the given table under the given key
 * @param callback RPC service function to call once we are done
 * @param rpc_context extra argument to callback
 */
static void rpc_DHT_remove(const PeerIdentity * sender,
			   RPC_Param * arguments,
			   Async_RPC_Complete_Callback callback,
			   struct CallInstance * rpc_context) {
  HashCode512 * key;
  DHT_TableId * table;
  unsigned int dataLength;
  DataContainer * value;
  unsigned long long * timeout;
  RPC_DHT_remove_Context * fw_context;
  LocalTableData * ltd;

  ENTER();
  processOptionalFields(sender, arguments);
  /* parse arguments */
  if ( (OK != RPC_paramValueByName(arguments,
				   "key",
				   &dataLength,
				   (void**) &key)) ||
       (dataLength != sizeof(HashCode512)) ||
       (OK != RPC_paramValueByName(arguments,
				   "table",
				   &dataLength,
				   (void**) &table)) ||
       (dataLength != sizeof(DHT_TableId)) ||
       (OK != RPC_paramValueByName(arguments,
				   "timeout",
				   &dataLength,
				   (void**) &timeout)) ||
       (dataLength != sizeof(unsigned long long)) ) {
    LOG(LOG_WARNING,
	_("Received invalid RPC `%s'.\n"),
	"DHT_remove");
    return;
  }

  value = RPC_paramDataContainerByName(arguments,
				       "value");
  fw_context
    = MALLOC(sizeof(RPC_DHT_remove_Context));
  MUTEX_CREATE_RECURSIVE(&fw_context->lock);
  MUTEX_LOCK(lock);
  ltd = getLocalTableData(table);
  if (ltd == NULL) {
    LOG(LOG_DEBUG,
	_("RPC for `%s' received for table that we do not participate in!\n"),
	"DHT_removed");
  }
  MUTEX_UNLOCK(lock);
  fw_context->done
    = NO;
  fw_context->callback
    = callback;
  fw_context->rpc_context
    = rpc_context;
  fw_context->remove_record
    = dht_remove_async_start(table,
			     key,
			     ntohll(*timeout),
			     value,
			     (DHT_OP_Complete) &rpc_dht_remove_callback,
			     fw_context);
  /* FIXME: shutdown sequence! */
  addAbortJob((CronJob)&rpc_DHT_remove_abort,
	      fw_context);
  addCronJob((CronJob)&rpc_DHT_remove_abort,
	     ntohll(*timeout),
	     0,
	     fw_context);
  FREE(value);
}

/**
 * Cron-job to maintain DHT invariants.  The responsibility of
 * this job is to maintain the routing table (by finding peers
 * if necessary).
 *
 * During shutdown the cron-job is called at a particular point
 * to free the associated resources.  The point is chosen such
 * that the cron-job will not allocate new resources (since all
 * tables and all buckets are empty at that point).
 */
static void dhtMaintainJob(void * shutdownFlag) {
  static struct RPC_Record ** pingRecords = NULL;
  static cron_t * pingTimes = NULL;
  static unsigned int pingRecordsSize = 0;
  static unsigned int pingTimesSize = 0;
  static struct DHT_PUT_RECORD ** putRecords = 0;
  static cron_t * putTimes = 0;
  static unsigned int putRecordsSize = 0;
  static unsigned int putTimesSize = 0;
  static FindNodesContext ** findRecords = NULL;
  static cron_t * findTimes = NULL;
  static unsigned int findRecordsSize = 0;
  static unsigned int findTimesSize = 0;
  int i;
  RPC_Param * request_param;
  PeerBucket * bucket;
  PeerInfo * pos;
  cron_t now;
  DataContainer * value;

  ENTER();
  MUTEX_LOCK(lock);
#if DEBUG_DHT
  printRoutingTable();
  /* first, free resources from ASYNC calls started last time */
  LOG(LOG_CRON,
      "`%s' stops async requests from last cron round.\n",
      __FUNCTION__);
#endif
  cronTime(&now);
  for (i=putRecordsSize-1;i>=0;i--) {
    if ( (shutdownFlag != NULL) ||
	 (putTimes[i] + DHT_MAINTAIN_BUCKET_FREQUENCY < now)) {
      dht_put_async_stop(putRecords[i]);
      putRecords[i] = putRecords[putRecordsSize-1];
      putTimes[i] = putTimes[putRecordsSize-1];
      GROW(putRecords,
	   putRecordsSize,
	   putRecordsSize-1);
      GROW(putRecords,
	   putTimesSize,
	   putTimesSize-1);
    }
  }
  for (i=findRecordsSize-1;i>=0;i--) {
    if ( (shutdownFlag != NULL) ||
	 (findTimes[i] + DHT_MAINTAIN_FIND_FREQUENCY < cronTime(NULL))) {
      findNodes_stop(findRecords[i],
		     NULL,
		     NULL);
      findTimes[i] = findTimes[findRecordsSize-1];
      findRecords[i] = findRecords[findRecordsSize-1];
      GROW(findRecords,
	   findRecordsSize,
	   findRecordsSize-1);
      GROW(findTimes,
	   findTimesSize,
	   findTimesSize-1);
    }
  }
  for (i=0;i<pingRecordsSize;i++) {
    if ( (shutdownFlag != NULL) ||
	 (pingTimes[i] + DHT_PING_FREQUENCY < cronTime(NULL))) {
      rpcAPI->RPC_stop(pingRecords[i]);
      pingRecords[i] = pingRecords[pingRecordsSize-1];
      pingTimes[i] = pingTimes[pingRecordsSize-1];
      GROW(pingRecords,
	   pingRecordsSize,
	   pingRecordsSize-1);
      GROW(pingTimes,
	   pingTimesSize,
	   pingTimesSize-1);
    }
  }
  if (shutdownFlag != NULL) {
    MUTEX_UNLOCK(lock);
    return;
  }

  /* now trigger next round of ASYNC calls */

  /* for all of our tables, do a PUT on the master table */
  request_param = vectorNew(4);
  value = MALLOC(sizeof(PeerIdentity) + sizeof(DataContainer));
  value->size = htonl(sizeof(PeerIdentity) + sizeof(DataContainer));
  memcpy(&value[1],
	 coreAPI->myIdentity,
	 sizeof(PeerIdentity));
#if DEBUG_DHT
  LOG(LOG_CRON,
      "`%s' issues DHT_PUTs to advertise tables this peer participates in.\n",
      __FUNCTION__);
#endif

  for (i=0;i<tablesCount;i++) {
    if (tables[i].lastMasterAdvertisement + DHT_MAINTAIN_BUCKET_FREQUENCY < now) {
      tables[i].lastMasterAdvertisement = now;
      if (equalsHashCode512(&tables[i].id,
			    &masterTableId))
	continue;
      GROW(putRecords,
	   putRecordsSize,
	   putRecordsSize+1);
      GROW(putTimes,
	   putTimesSize,
	   putTimesSize+1);
      putRecords[putRecordsSize-1]
	= dht_put_async_start(&masterTableId,
			      &tables[i].id,
			      DHT_MAINTAIN_BUCKET_FREQUENCY,
			      value,
			      NULL,
			      NULL);
      putTimes[putTimesSize-1] = now;
    }
  }
  vectorFree(request_param);
  FREE(value);

  /*
    for each table that we have joined gather OUR neighbours
  */
#if DEBUG_DHT
  LOG(LOG_CRON,
      "`%s' issues findNodes for each table that we participate in.\n",
      __FUNCTION__);
#endif
  for (i=0;i<tablesCount;i++) {
    if (tables[i].lastFindOperation + DHT_MAINTAIN_FIND_FREQUENCY < now) {
      tables[i].lastFindOperation = now;
      GROW(findRecords,
	   findRecordsSize,
	   findRecordsSize+1);
      GROW(findTimes,
	   findTimesSize,
	   findTimesSize+1);
      findRecords[findRecordsSize-1]
	= findNodes_start(&tables[i].id,
			  &coreAPI->myIdentity->hashPubKey,
			  DHT_MAINTAIN_FIND_FREQUENCY);
      findTimes[findTimesSize-1] = now;
    }
  }
  /*
     for all peers in RT:
     a) if lastTableRefresh is very old, send ping
     b) if lastActivity is very very old, drop
  */
#if DEBUG_DHT
  LOG(LOG_CRON,
      "`%s' issues put to advertise tables that we participate in.\n",
      __FUNCTION__);
#endif
  request_param = vectorNew(4);
  for (i=bucketCount-1;i>=0;i--) {
    bucket = &buckets[i];
    pos = vectorGetFirst(bucket->peers);
    while (pos != NULL) {
      if (now - pos->lastTableRefresh > DHT_INACTIVITY_DEATH) {
	/* remove from table: dead peer */
	vectorRemoveObject(bucket->peers,
			   pos);
	GROW(pos->tables,
	     pos->tableCount,
	     0);
	FREE(pos);
	pos = vectorGetFirst(bucket->peers);
	continue;
      }
      if ( (now - pos->lastTableRefresh > DHT_INACTIVITY_DEATH / 2) &&
	   (now - pos->lastTimePingSend > DHT_PING_FREQUENCY) ) {
#if DEBUG_DHT
	EncName enc;
	
	ENTER();
	IFLOG(LOG_DEBUG,
	      hash2enc(&pos->id.hashPubKey,
		       &enc));
	LOG(LOG_DEBUG,
	    "sending RPC `%s' to peer `%s'.\n",
	    "DHT_ping",
	    &enc);
#endif
	pos->lastTimePingSend = now;
	GROW(pingRecords,
	     pingRecordsSize,
	     pingRecordsSize+1);
	GROW(pingTimes,
	     pingTimesSize,
	     pingTimesSize+1);
	pingRecords[pingRecordsSize-1]
	  = rpcAPI->RPC_start(&pos->id,
			      "DHT_ping",
			      request_param,
			      0,
			      DHT_PING_FREQUENCY,
			      (RPC_Complete) &ping_reply_handler,
			      NULL);
	pingTimes[pingTimesSize-1]
	  = now;
      }
      pos = vectorGetNext(bucket->peers);
    }
  } /* end for all buckets */
  vectorFree(request_param);

  /*
     OPTIMIZE-ME:
     for all content in all tables:
     check if this peer should still be responsible for
     it, if not, migrate!
  */
  MUTEX_UNLOCK(lock);
}

/**
 * Provide the DHT service.  The DHT service depends on the RPC
 * service.
 *
 * @param capi the core API
 * @return NULL on errors, DHT_API otherwise
 */
DHT_ServiceAPI * provide_module_dht(CoreAPIForApplication * capi) {
  static DHT_ServiceAPI api;
  unsigned int i;

  ENTER();
  coreAPI = capi;
  rpcAPI = capi->requestService("rpc");
  if (rpcAPI == NULL)
    return NULL;
  i = getConfigurationInt("DHT",
			  "BUCKETCOUNT");
  if ( (i == 0) || (i > 512) )
    i = 512;
  GROW(buckets,
       bucketCount,
       i);
  for (i=0;i<bucketCount;i++) {
    buckets[i].bstart = 512 * i / bucketCount;
    buckets[i].bend = 512 * (i+1) / bucketCount;
    buckets[i].peers = vectorNew(4);
  }

  rpcAPI->RPC_register("DHT_ping",
		       &rpc_DHT_ping);
  rpcAPI->RPC_register("DHT_findNode",
		       &rpc_DHT_findNode);
  rpcAPI->RPC_register_async("DHT_findValue",
			     &rpc_DHT_findValue);
  rpcAPI->RPC_register_async("DHT_store",
			     &rpc_DHT_store);
  rpcAPI->RPC_register_async("DHT_remove",
			     &rpc_DHT_remove);
  lock = coreAPI->getConnectionModuleLock();
  api.join = &dht_join;
  api.leave = &dht_leave;
  api.get_start = &dht_get_async_start;
  api.get_stop = &dht_get_async_stop;
  api.put_start = &dht_put_async_start;
  api.put_stop = &dht_put_async_stop;
  api.remove_start = &dht_remove_async_start;
  api.remove_stop = &dht_remove_async_stop;

  memset(&masterTableId, 0, sizeof(HashCode512));
  /* join the master table */
  i = getConfigurationInt("DHT",
			  "MASTER-TABLE-SIZE");
  if (i == 0)
    i = 65536; /* 64k memory should suffice */
  masterTableDatastore
    = create_datastore_dht_master(i);
  dht_join(masterTableDatastore,
	   &masterTableId);
  addCronJob(&dhtMaintainJob,
	     0,
	     DHT_MAINTAIN_FREQUENCY,
	     NULL);
  return &api;
}

/**
 * Shutdown DHT service.
 */
int release_module_dht() {
  unsigned int i;
  PeerInfo * bucket;

  ENTER();
  rpcAPI->RPC_unregister("DHT_ping",
			 &rpc_DHT_ping);
  rpcAPI->RPC_unregister("DHT_findNode",
			 &rpc_DHT_findNode);
  rpcAPI->RPC_unregister_async("DHT_findValue",
			       &rpc_DHT_findValue);
  rpcAPI->RPC_unregister_async("DHT_store",
			       &rpc_DHT_store);
  rpcAPI->RPC_unregister_async("DHT_remove",
			       &rpc_DHT_remove);
  delCronJob(&dhtMaintainJob,
	     DHT_MAINTAIN_FREQUENCY,
	     NULL);
  /* stop existing / pending DHT operations */
  while (abortTableSize > 0) {
    delCronJob(abortTable[0].job,
	       0,
	       abortTable[0].arg);
    abortTable[0].job(abortTable[0].arg);
  }
  /* leave the master table */
  dht_leave(&masterTableId);
  for (i=0;i<bucketCount;i++) {
    bucket = (PeerInfo*) vectorGetFirst(buckets[i].peers);
    while (bucket != NULL) {
      GROW(bucket->tables,
	   bucket->tableCount,
	   0);
      bucket = (PeerInfo*) vectorGetNext(buckets[i].peers);
    }
    vectorFree(buckets[i].peers);
  }
  GROW(buckets,
       bucketCount,
       0);

  dhtMaintainJob((void*)1); /* free's cron's internal resources! */
  destroy_datastore_dht_master(masterTableDatastore);
  coreAPI->releaseService(rpcAPI);
  lock = NULL;
  rpcAPI = NULL;
  coreAPI = NULL;
  return OK;
}


/* end of dht.c */
