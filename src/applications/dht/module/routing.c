/*
      This file is part of GNUnet
      (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file module/routing.c
 * @brief state for active DHT routing operations
 * @author Christian Grothoff
 *
 * RC:
 * - add support for GET retry (or delayed initial GET ops)
 * - fix problem with possible GET/PUT routing loops!
 *   (not convinced that current design even probabilistically
 *    prevents loops; also check for routing loops by
 *    checking pending queries)
 *
 * LATER:
 * - prioritization
 * - delay selection
 */

#include "platform.h"
#include "routing.h"
#include "table.h"
#include "dstore.h"
#include "gnunet_protocols.h"
#include "gnunet_stats_service.h"

#define DEBUG_ROUTING NO

/**
 * @brief record used for sending response back
 */
typedef struct {

  /**
   * Source of the request.  Replies should be forwarded to
   * this peer.
   */
  PeerIdentity source;

  /**
   * If local peer is NOT interested in results, this callback
   * will be NULL.
   */
  ResultHandler receiver;

  void * receiver_closure;

} DHT_Source_Route;

/**
 * @brief message send for DHT lookup
 */
typedef struct {

  MESSAGE_HEADER header;

  /**
   * Type of the requested content
   */
  unsigned int type;

  /**
   * Priority of requested content
   */
  unsigned int prio;

  /**
   * Reserved (for now, always zero)
   */
  unsigned int reserved;

  /**
   * Search key.
   */
  HashCode512 key;

} DHT_GET_MESSAGE;

/**
 * @brief message send for DHT put
 *
 * Message is followed by the data.
 */
typedef struct {

  MESSAGE_HEADER header;

  /**
   * Type of the content
   */
  unsigned int type;

  /**
   * When to discard the content (relative time)
   */
  cron_t timeout;

  /**
   * Key for the content.
   */
  HashCode512 key;

} DHT_PUT_MESSAGE;

/**
 * @brief message send for DHT put
 *
 * Message is followed by the data.
 */
typedef struct {

  MESSAGE_HEADER header;

  /**
   * Type of the content
   */
  unsigned int type;

  /**
   * Key for the content.
   */
  HashCode512 key;

} DHT_RESULT_MESSAGE;

/**
 * Entry in the DHT routing table.
 */
typedef struct {

  /**
   * Information about where to send the results back to.
   */
  DHT_Source_Route source;

  /**
   * GET message of this record.
   */
  DHT_GET_MESSAGE * get;

  /**
   * Hashcodes of the results that we have send back
   * so far.
   */
  HashCode512 * results;

  /**
   * Number of entries in results.
   */
  unsigned int result_count;

} DHTQueryRecord;

static unsigned int rt_size;

static unsigned int rt_pos;

/**
 * rt_size records of active queries
 */
static DHTQueryRecord ** records;

/**
 * Statistics service.
 */
static Stats_ServiceAPI * stats;

static struct MUTEX * lock;

static CoreAPIForApplication * coreAPI;

static unsigned int stat_replies_routed;

static unsigned int stat_results_received;

static unsigned int stat_requests_routed;

static unsigned int stat_get_requests_received;

static unsigned int stat_put_requests_received;

/**
 * Given a result, lookup in the routing table
 * where to send it next.
 */
static void routeResult(const HashCode512 * key,
			unsigned int type,
			unsigned int size,
			const char * data,
			void * cls) {
  DHTQueryRecord * q;
  int i;
  int j;
  int found;
  HashCode512 hc;
  DHT_RESULT_MESSAGE * result;
  unsigned int routed;
  unsigned int tracked;

  if (cls != NULL) {
    result = cls;
  } else {
    result = MALLOC(sizeof(DHT_RESULT_MESSAGE) + size);
    result->header.size = htons(sizeof(DHT_RESULT_MESSAGE) + size);
    result->header.type = htons(P2P_PROTO_DHT_RESULT);
    result->type = htonl(type);
    result->key = *key;
    memcpy(&result[1],
	   data,
	   size);
  }
  hash(data,
       size,
       &hc);
  routed = 0;
  tracked = 0;
  MUTEX_LOCK(lock);
  for (i=0;i<rt_size;i++) {
    q = records[i];
    if (q == NULL)
      continue;
    tracked++;
    if ( (ntohl(q->get->type) != type) ||
	 (0 != memcmp(key,
		      &q->get->key,
		      sizeof(HashCode512))) )
      continue;
    found = NO;
    for (j=0;j<q->result_count;j++)
      if (0 == memcmp(&hc,
		      &q->results[j],
		      sizeof(HashCode512))) {
	found = YES;
	break;
      }
    if (found == YES)
      continue;
    GROW(q->results,
	 q->result_count,
	 q->result_count + 1);
    routed++;
    q->results[q->result_count-1] = hc;
    if (0 != memcmp(&q->source.source,
		    coreAPI->myIdentity,
		    sizeof(PeerIdentity))) {
#if DEBUG_ROUTING
      GE_LOG(coreAPI->ectx,
	     GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	     "Routing result to other peer\n");
#endif
      coreAPI->unicast(&q->source.source,
		       &result->header,
		       0, /* FIXME: priority */
		       5 * cronSECONDS); /* FIXME */
      if (stats != NULL)
	stats->change(stat_replies_routed, 1);
    } else if (q->source.receiver != NULL) {
#if DEBUG_ROUTING
      GE_LOG(coreAPI->ectx,
	     GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	     "Routing result to local client\n");
#endif
      q->source.receiver(key,
			 type,
			 size,
			 data,
			 q->source.receiver_closure);
      if (stats != NULL)
	stats->change(stat_replies_routed, 1);
    }
  }
  MUTEX_UNLOCK(lock); 
#if DEBUG_ROUTING
  GE_LOG(coreAPI->ectx,
	 GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	 "Routed result to %u out of %u pending requests\n",
	 routed,
	 tracked);
#endif
  if (cls == NULL)
    FREE(result);
}

static void addRoute(const PeerIdentity * sender,
		     ResultHandler handler,
		     void * cls,
		     const DHT_GET_MESSAGE * get) {
  DHTQueryRecord * q;

  MUTEX_LOCK(lock);
  if (records[rt_pos] != NULL) {
    FREE(records[rt_pos]->get);
    GROW(records[rt_pos]->results,
	 records[rt_pos]->result_count,
	 0);
  } else {
    records[rt_pos] = MALLOC(sizeof(DHTQueryRecord));
  }
  q = records[rt_pos];
  memset(q,
	 0,
	 sizeof(DHTQueryRecord));
  q->get = MALLOC(ntohs(get->header.size));
  memcpy(q->get,
	 get,
	 ntohs(get->header.size));
  if (sender != NULL)
    q->source.source = *sender;
  else
    q->source.source = *coreAPI->myIdentity;
  q->source.receiver = handler;
  q->source.receiver_closure = cls;
#if DEBUG_ROUTING
  GE_LOG(coreAPI->ectx,
	 GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	 "Tracking request in slot %u\n",
	 rt_pos);
#endif 
  rt_pos = (rt_pos + 1) % rt_size;
  MUTEX_UNLOCK(lock);
  if (stats != NULL)
    stats->change(stat_requests_routed, 1);
}

/**
 * Larger factors will result in more aggressive routing of GET
 * operations (each peer will either forward to GET_TRIES peers that
 * are closer to the key).
 */
#define GET_TRIES 4

/**
 * Handle GET message.
 */
static int handleGet(const PeerIdentity * sender,
		     const MESSAGE_HEADER * msg) {
  PeerIdentity next[GET_TRIES];
  const DHT_GET_MESSAGE * get;
  int total;
  int i;
#if DEBUG_ROUTING
  EncName enc;
#endif

  if (ntohs(msg->size) != sizeof(DHT_GET_MESSAGE)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  get = (const DHT_GET_MESSAGE*) msg;
#if DEBUG_ROUTING
  hash2enc(&get->key, &enc);
  GE_LOG(coreAPI->ectx,
	 GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	 "Received DHT GET for key `%s'.\n",
	 &enc);
#endif
  if (stats != NULL)
    stats->change(stat_get_requests_received, 1);
  if (sender != NULL)
    addRoute(sender,
	     NULL,
	     NULL,
	     get);  
  total = dht_store_get(&get->key,
			ntohl(get->type),
			&routeResult,
			NULL);
  if ( (total > GET_TRIES) &&
       (sender != NULL) ) {
#if DEBUG_ROUTING
    GE_LOG(coreAPI->ectx,
	   GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	   "Found %d results locally, will not route GET any further\n",
	   total);
#endif
    return OK;
  }
  for (i=0;i<GET_TRIES;i++) {
    if (OK != select_dht_peer(&next[i],
			      &get->key,
			      &next[0],
			      i))
      break;
    if (-1 == hashCodeCompareDistance(&next[i].hashPubKey,
				      &coreAPI->myIdentity->hashPubKey,
				      &get->key)) {
      coreAPI->unicast(&next[i],
		       msg,
		       0, /* FIXME: priority */
		       5 * cronSECONDS); /* FIXME */
    }
  }
  return OK;
}

/**
 * Larger factors will result in more replication and
 * more aggressive routing of PUT operations (each
 * peer will either forward to PUT_TRIES peers that
 * are closer to the key, or replicate the content).
 */
#define PUT_TRIES 2

/**
 * Handle PUT message.
 */
static int handlePut(const PeerIdentity * sender,
		     const MESSAGE_HEADER * msg) {
  PeerIdentity next[PUT_TRIES];
  const DHT_PUT_MESSAGE * put;
  cron_t now;
  int store;
  int i;
#if DEBUG_ROUTING
  EncName enc;
#endif

  if (ntohs(msg->size) < sizeof(DHT_PUT_MESSAGE)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  if (stats != NULL)
    stats->change(stat_put_requests_received, 1);
  put = (const DHT_PUT_MESSAGE*) msg;
#if DEBUG_ROUTING
  hash2enc(&put->key, &enc);
  GE_LOG(coreAPI->ectx,
	 GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	 "Received DHT PUT for key `%s'.\n",
	 &enc);
#endif
  store = 0;
  for (i=0;i<PUT_TRIES;i++) {
    if (OK != select_dht_peer(&next[i],
			      &put->key,
			      &next[0],
			      i)) {
      store = 1;
      break;
    }
    if (1 == hashCodeCompareDistance(&next[i].hashPubKey,
				     &coreAPI->myIdentity->hashPubKey,
				     &put->key))
      store = 1; /* we're closer than the selected target */
    else
      coreAPI->unicast(&next[i],
		       msg,
		       0, /* FIXME: priority */
		       5 * cronSECONDS); /* FIXME */
  }
  if (store != 0) {
    now = get_time();
#if DEBUG_ROUTING
    GE_LOG(coreAPI->ectx,
	   GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	   "Decided to cache data `%.*s' locally until %llu (for %llu ms)\n",
	   ntohs(put->header.size) - sizeof(DHT_PUT_MESSAGE),
	   &put[1],
	   ntohll(put->timeout) + now,
	   ntohll(put->timeout));
#endif
    dht_store_put(ntohl(put->type),
		  &put->key,
		  ntohll(put->timeout) + now,
		  ntohs(put->header.size) - sizeof(DHT_PUT_MESSAGE),
		  (const char*) &put[1]);
  } else {
#if DEBUG_ROUTING
  GE_LOG(coreAPI->ectx,
	 GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	 "Decided NOT to cache data `%.*s' locally\n",
	 ntohs(put->header.size) - sizeof(DHT_PUT_MESSAGE),
	 &put[1]);
#endif
  }      
  return OK;
}

/**
 * Handle RESULT message.
 */
static int handleResult(const PeerIdentity * sender,
			const MESSAGE_HEADER * msg) {
  const DHT_RESULT_MESSAGE * result;
#if DEBUG_ROUTING
  EncName enc;
#endif

  if (ntohs(msg->size) < sizeof(DHT_RESULT_MESSAGE)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  if (stats != NULL)
    stats->change(stat_results_received, 1);
  result = (const DHT_RESULT_MESSAGE*) msg;
#if DEBUG_ROUTING
  hash2enc(&result->key, &enc);
  GE_LOG(coreAPI->ectx,
	 GE_DEBUG | GE_REQUEST | GE_DEVELOPER,
	 "Received DHT RESULT for key `%s'.\n",
	 &enc);
#endif
  routeResult(&result->key,
	      ntohl(result->type),
	      ntohs(result->header.size) - sizeof(DHT_RESULT_MESSAGE),
	      (const char*) &result[1],
	      (void*) msg);
  return OK;
}

/**
 * Start a DHT get operation.
 */
void dht_get_start(const HashCode512 * key,
		   unsigned int type,
		   ResultHandler handler,
		   void * cls) {
  DHT_GET_MESSAGE get;

  get.header.size = htons(sizeof(DHT_GET_MESSAGE));
  get.header.type = htons(P2P_PROTO_DHT_GET);
  get.type = htonl(type);
  get.prio = htonl(0); /* FIXME */
  get.reserved = htonl(0);
  get.key = *key;
  addRoute(NULL,
	   handler,
	   cls,
	   &get);	      
  handleGet(NULL,
	    &get.header);
}

/**
 * Stop a DHT get operation (prevents calls to
 * the given iterator).
 */
void dht_get_stop(const HashCode512 * key,
		  unsigned int type,
		  ResultHandler handler,
		  void * cls) {
  int i;

  MUTEX_LOCK(lock);
  for (i=0;i<rt_size;i++) {
    if (records[i] == NULL)
      continue;
    if ( (records[i]->source.receiver == handler) &&
	 (records[i]->source.receiver_closure == cls) &&
	 (0 == memcmp(key,
		      &records[i]->get->key,
		      sizeof(HashCode512))) ) {
      FREE(records[i]->get);
      FREE(records[i]);
      records[i] = NULL;
      break;
    }
  }
  MUTEX_UNLOCK(lock);
}

/**
 * Perform a DHT put operation.  Note that PUT operations always
 * expire after a period of time and the client is responsible for
 * doing periodic refreshs.  The given expiration time is ONLY used to
 * ensure that the datum is certainly deleted by that time (it maybe
 * deleted earlier).
 *
 * @param expirationTime absolute expiration time
 */
void dht_put(const HashCode512 * key,
	     unsigned int type,
	     unsigned int size,
	     cron_t expirationTime,
	     const char * data) {
  DHT_PUT_MESSAGE * put;

  put = MALLOC(sizeof(DHT_PUT_MESSAGE) + size);
  put->header.size = htons(sizeof(DHT_PUT_MESSAGE) + size);
  put->header.type = htons(P2P_PROTO_DHT_PUT);
  put->key = *key;
  put->type = htonl(type);
  put->timeout = htonll(expirationTime - get_time()); /* convert to relative time */
  memcpy(&put[1],
	 data,
	 size);
  handlePut(NULL,
	    &put->header);
  FREE(put);
}

/**
 * Initialize routing DHT component.
 *
 * @param capi the core API
 * @return OK on success
 */
int init_dht_routing(CoreAPIForApplication * capi) {
  unsigned long long rts;
  
  coreAPI = capi;
  rts = 65536;
  GC_get_configuration_value_number(coreAPI->cfg,
				    "DHT",
				    "TABLESIZE",
				    128,
				    1024 * 1024,
				    1024,
				    &rts);
  GROW(records,
       rt_size,
       rts);
  lock = MUTEX_CREATE(NO);
  stats = capi->requestService("stats");
  if (stats != NULL) {
    stat_replies_routed = stats->create(gettext_noop("# dht replies routed"));
    stat_requests_routed = stats->create(gettext_noop("# dht requests routed"));
    stat_get_requests_received = stats->create(gettext_noop("# dht get requests received"));
    stat_put_requests_received = stats->create(gettext_noop("# dht put requests received"));
    stat_results_received = stats->create(gettext_noop("# dht results received"));
  }
  GE_LOG(coreAPI->ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 _("`%s' registering p2p handlers: %d %d %d\n"),
	 "dht",
	 P2P_PROTO_DHT_GET,
	 P2P_PROTO_DHT_PUT,
	 P2P_PROTO_DHT_RESULT);
  coreAPI->registerHandler(P2P_PROTO_DHT_GET,
			   &handleGet);
  coreAPI->registerHandler(P2P_PROTO_DHT_PUT,
			   &handlePut);
  coreAPI->registerHandler(P2P_PROTO_DHT_RESULT,
			   &handleResult);
  return OK;
}

/**
 * Shutdown routing DHT component.
 *
 * @return OK on success
 */
int done_dht_routing() {
  unsigned int i;

  coreAPI->unregisterHandler(P2P_PROTO_DHT_GET,
			     &handleGet);
  coreAPI->unregisterHandler(P2P_PROTO_DHT_PUT,
			     &handlePut);
  coreAPI->unregisterHandler(P2P_PROTO_DHT_RESULT,
			     &handleResult);
  if (stats != NULL) {
    coreAPI->releaseService(stats);
    stats = NULL;
  }
  MUTEX_DESTROY(lock);
  for (i=0;i<rt_size;i++) {
    if (records[i] != NULL) {
      FREE(records[i]->get);
      FREE(records[i]);
    }
  }
  GROW(records,
       rt_size,
       0);
  return OK;
}

/* end of routing.c */
