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
 * TODO:
 * - tracking of get/put opertations
 * - retry
 * - reply handling
 * - prioritization
 * - stats
 */

#include "platform.h"
#include "routing.h"
#include "table.h"
#include "dstore.h"
#include "gnunet_protocols.h"
#include "gnunet_stats_service.h"

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

  DHT_Source_Route source;

  DHT_GET_MESSAGE * get;

} DHTQueryRecord;

static unsigned int rt_size;

static unsigned int rt_pos;

static DHTQueryRecord ** records;

/**
 * Statistics service.
 */
static Stats_ServiceAPI * stats;

static struct MUTEX * lock;

static CoreAPIForApplication * coreAPI;

static unsigned int stat_replies_routed;

static unsigned int stat_requests_routed;

/**
 * Given a result, lookup in the routing table
 * where to send it next.
 */
static void routeResult(const HashCode512 * key,
			unsigned int type,
			unsigned int size,
			const char * data,
			void * cls) {
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

  if (ntohs(msg->size) != sizeof(DHT_GET_MESSAGE)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  get = (const DHT_GET_MESSAGE*) msg;
  total = dht_store_get(&get->key,
			ntohl(get->type),
			&routeResult,
			NULL);
  if (total > 0)
    return OK;
  for (i=0;i<GET_TRIES;i++) {
    if (OK != select_dht_peer(&next[i],
			      &get->key,
			      &next[0],
			      i)) 
      break;
    if (-1 == hashCodeCompareDistance(&next[i].hashPubKey,
				      &coreAPI->myIdentity->hashPubKey,
				      &get->key))
      coreAPI->unicast(&next[i],
		       msg,
		       0, /* FIXME: priority */
		       5 * cronSECONDS); /* FIXME */
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
  int store;
  int i;

  if (ntohs(msg->size) < sizeof(DHT_PUT_MESSAGE)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  put = (const DHT_PUT_MESSAGE*) msg;
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
  if (store != 0)
    dht_store_put(ntohl(put->type),
		  &put->key,
		  ntohll(put->timeout) + get_time(),
		  ntohs(put->header.size) - sizeof(DHT_PUT_MESSAGE),
		  (const char*) &put[1]);
  return OK;
}

/**
 * Handle RESULT message.
 */
static int handleResult(const PeerIdentity * sender,
			const MESSAGE_HEADER * msg) {
  const DHT_RESULT_MESSAGE * result;

  if (ntohs(msg->size) < sizeof(DHT_RESULT_MESSAGE)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  result = (const DHT_RESULT_MESSAGE*) msg;
  routeResult(&result->key,
	      ntohl(result->type),
	      ntohs(result->header.size) - sizeof(DHT_RESULT_MESSAGE),
	      (const char*) &result[1],
	      NULL);
  return OK;
}

/**
 * Initialize routing DHT component.
 *
 * @param capi the core API
 * @return OK on success
 */
int init_dht_routing(CoreAPIForApplication * capi) {
  coreAPI = capi;
  GROW(records,
       rt_size,
       512);
  lock = MUTEX_CREATE(NO);
  stats = capi->requestService("stats");
  if (stats != NULL) {
    stat_replies_routed = stats->create(gettext_noop("# dht replies routed"));
    stat_requests_routed = stats->create(gettext_noop("# dht requests routed"));
  }
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
