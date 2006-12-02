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
 * @file module/table.c
 * @brief maintains routing table
 * @author Christian Grothoff
 *
 * New DHT infrastructure plan:
 * - no RPC, pure async messaging
 * - stateful routing; needed for retry and reply routing
 * - no per-table storage; instead global,
 *   SQL database-based storage for entire peer
 * - no delete operation, just get/put + expiration
 * - modules:
 *   + table.c: DHT-peer table, peer discovery cron jobs;
 *     code tries to fill table "as much as possible" over time;
 *     reliabily metrics (to be added later)
 *   + discovery.c: support code to supply peers with neighbour
 *     information to improve routing tables (HELLO lookup)
 *   + routing.c: tracking of get/put operations, retry, reply handling
 *     code tries best-match routing among entries in table
 *   + dstore (plugin): SQL-based datastore: key, value, expiration
 *     (bounded FIFO-datastore, when full, kill oldest entry first)
 *     [?: better replacement policy to guard against attacks?]
 *
 * TODO:
 * - peer-in-proximity selection
 * - public internal table API
 * - HELLO request when learning
 * - tracking of live connections, expiration of stale entries
 * - tracking of peer latency and drop rates
 * - extension of protocols.h header with new DHT ID
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_dht_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_identity_service.h"

/**
 * How often should the cron job for maintaining the DHT
 * run?
 */
#define MAINTAIN_FREQUENCY 1500 * cronMILLIS

/**
 * What is the chance (1 in XXX) that we send DISCOVERY messages
 * to another peer?
 */
#define MAINTAIN_CHANCE 100

/**
 * What is the maximum number of known DHT-enabled peers 
 * advertised for each DISCOVERY message?
 */
#define MAINTAIN_ADV_CAP 8

/**
 * Target number of peers per bucket
 */
#define MAINTAIN_BUCKET_SIZE 2

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
   * What is the average latency for replies received?
   */
  cron_t expected_latency;

  /**
   * What is the average response rate?
   */
  double drop_rate;

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
   * Peers in this bucket.  NULL is used if no peer is known.
   */
  PeerInfo ** peers;

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

  unsigned int peers_size;

} PeerBucket;


 * Global core API.
 */
static CoreAPIForApplication * coreAPI;

/**
 * The buckets (Kademlia style routing table).
 */
static PeerBucket * buckets;

/**
 * Total number of active buckets.
 */
static unsigned int bucketCount;

/**
 * Total number of peers in routing table.
 */
static unsigned int total_peers;

/**
 * Mutex to synchronize access to tables.
 */
static struct MUTEX * lock;

/**
 * Identity service.
 */
static Identity_ServiceAPI * identity;

/**
 * Statistics service.
 */
static Stats_ServiceAPI * stats;


static int stat_dht_total_peers;

static int stat_dht_discoveries;

static int stat_dht_route_looks;

typedef struct {
  
  MESSAGE_HEADER header;

  unsigned int space_available;

} P2P_DHT_Discovery;

static PeerBucket * findBucketFor(const PeerIdentity * peer) {
  /* FIXME! */
  return NULL;
}

/**
 * Find the PeerInfo for the given peer. Returns NULL if peer is not
 * in our DHT routing table.
 */
static PeerInfo * findPeerEntry(const PeerIdentity * peer) {
  PeerBucket * bucket;

  bucket = findBucketFor(peer);
  return NULL;
}

/**
 * Select a peer from the routing table that would be a good routing
 * destination for sending a message for "target".  The resulting peer
 * must not be in the set of blocked peers.<p>
 *
 * Note that we should not ALWAYS select the closest peer to the
 * target, peers further away from the target should be chosen with
 * exponentially declining probability (this function is also used for
 * populating the target's routing table).
 *
 * @return OK on success, SYSERR on error
 */
static int selectPeer(PeerIdentity * set,
		      const HashCode512 * target,
		      const PeerIdentity * blocked,
		      unsigned int blocked_size) {
  MUTEX_LOCK(lock);
  /* fixme: select peers */
  MUTEX_UNLOCK(lock);
  if (stats != NULL)
    stats->update(stat_dht_route_looks, 1);
  return SYSERR;
}

static void broadcast_dht_discovery(const PeerIdentity * other,
				    void * cls) {
  P2P_DHT_Discovery * disco = cls;
  unsigned int pc;
  unsigned int i;
  PeerIdentity * pos;

  if (weak_randomi(MAINTAIN_CHANCE) != 0)
    return;
  if (disco != NULL) {
    coreAPI->unicast(other,
		     &disco->header,
		     EXTREME_PRIORITY/4,
		     MAINTAIN_FREQUENCY * MAINTAIN_CHANCE / 2);
    return;
  }
  pc = total_peers;
  if (pc > MAINTAIN_ADV_CAP) 
    pc = MAINTAIN_ADV_CAP;
  if (pc == 0)
    pc = 1;
  disco = MALLOC(pc * sizeof(PeerIdentity) + sizeof(P2P_DHT_Discovery));
  disco->header.type = htons(P2P_PROTO_DHT_DISCOVERY);
  disco->space_available = -1; /* FIXME */
  pos = (PeerIdentity*) &disco[1];
  i = 0;
  if (total_peers == 0) {
    /* put in our own identity (otherwise we get into a
       storm of empty discovery messages) */
    pos[0] = *coreAPI->myIdentity;
    i = 1;
  }
  while (i < pc) {
    if (OK != selectPeer(&pos[i],
			 &other->hashPubKey,
			 pos,
			 i)) 
      pc--;
    else
      i++;
  }
  disco->header.size = htons(pc * sizeof(PeerIdentity) + sizeof(P2P_DHT_Discovery));
  coreAPI->unicast(other,
		   &disco->header,
		   0,
		   MAINTAIN_FREQUENCY * MAINTAIN_CHANCE / 2);
  FREE(disco);
}

/**
 * Cron job to maintain DHT routing table.
 */
static void maintain_dht_job(void * unused) {
  P2P_DHT_Discovery disc;

  if (total_peers == 0) {
    disc.header.size = htons(sizeof(P2P_DHT_Discovery));
    disc.header.type = htons(P2P_PROTO_DHT_DISCOVERY);
    disc.space_available = -1; /* FIXME */
    coreAPI->forAllConnectedNodes(&broadcast_dht_discovery,
				  &disc);
  } else {
    coreAPI->forAllConnectedNodes(&broadcast_dht_discovery,
				  NULL);
  }
}

/**
 * Handle discovery message.
 */
static int handleDiscovery(const PeerIdentity * sender,
			   const MESSAGE_HEADER * msg) {
  unsigned int pc;
  unsigned int i;
  PeerBucket * bucket;
  const PeerIdentity * peers;
  const P2P_DHT_Discovery * disco;

  pc = (ntohs(msg->size) - sizeof(P2P_DHT_Discovery)) / sizeof(PeerIdentity);
  if (pc > MAINTAIN_ADV_CAP * 8) {
    GE_BREAK(coreAPI->ectx, 0);
    return SYSERR; /* far too big */
  }
  if (ntohs(msg->size) != sizeof(P2P_DHT_Discovery) + pc * sizeof(PeerIdentity)) {
    GE_BREAK(coreAPI->ectx, 0);
    return SYSERR; /* malformed */
  }
  disco = (const P2P_DHT_Discovery) msg;
  if (stats != NULL)
    stats->update(stat_dht_discoveries, 1);
  if (pc == 0) {
    /* if peer has 0 connections, be sure to send discovery back */
    broadcast_dht_discovery(sender,
			    NULL);
    return OK;
  }
  MUTEX_LOCK(lock);
  peers = (const PeerIdentity*) &disco[1];
  for (i=0;i<pc;i++) {
    bucket = findBucketFor(&peers[i]);
    if (bucket->peers_size >= MAINTAIN_BUCKET_SIZE) 
      continue; /* do not care */
    /* FIXME: learn about connection opportunities */
    /* if identity not known, ask sender for HELLO of other peer */
    /* if identity known, connect (sending DISCOVERY) */
    /* if connected (in core), add to bucket */
    
  }
  MUTEX_UNLOCK(lock);
  return OK;
}

/**
 * Initialize table DHT component.
 *
 * @param capi the core API
 * @return OK on success
 */
int init_dht_table(CoreAPIForApplication * capi) {
  unsigned long long i;
  unsigned long long j;

  coreAPI = capi;
  ectx = capi->ectx;
  /* FIXME: this should depend on core's target
     connection count, not on the end-user! */
  if (-1 == GC_get_configuration_value_number(capi->cfg,
					      "DHT",
					      "BUCKETCOUNT",
					      1,
					      512,
					      512,
					      &i))
    return SYSERR;
  GROW(buckets,
       bucketCount,
       i);
  for (i=0;i<bucketCount;i++) {
    buckets[i].bstart = 512 * i / bucketCount;
    buckets[i].bend = 512 * (i+1) / bucketCount;
  }
  lock = MUTEX_CREATE(NO);
  stats = capi->requestService("stats");
  if (stats != NULL) {
    stat_dht_total_peers = stats->create(gettext_noop("# dht connections"));
    stat_dht_discoveries = stats->create(gettext_noop("# dht discovery messages received"));
    stat_dht_route_looks = stats->create(gettext_noop("# dht route host lookups performed"));
  }
  identity = coreAPI->requestService("identity");
  GE_ASSERT(ectx, identity != NULL);
  
  capi->registerHandler(P2P_PROTO_DHT_DISCOVERY,
			&handleDiscovery);
  cron_add_job(coreAPI->cron_manager,
	       &maintain_dht_job,
	       MAINTAIN_FREQUENCY,
	       MAINTAIN_FREQUENCY);
  return OK;
}

/**
 * Shutdown table DHT component.
 *
 * @param capi the core API
 * @return OK on success
 */
int done_dht_table() {
  unsigned int i;

  capi->unregisterHandler(P2P_PROTO_DHT_DISCOVERY,
			  &handleDiscovery);
  cron_del_job(coreAPI->cron_manager,
	       &maintain_dht_job,
	       MAINTAIN_FREQUENCY);
  if (stats != NULL) {
    coreAPI->releaseService(stats);
    stats = NULL;
  }
  coreAPI->releaseService(identity);
  identity = NULL;
  for (i=0;i<bucketCount;i++) {
    GROW(buckets[i]->peers,
	 buckets[i]->peers_size,
	 0);
  }
  GROW(buckets,
       bucketCount,
       0);
  MUTEX_DESTROY(lock);
  return OK;
}

/* end of table.c */
