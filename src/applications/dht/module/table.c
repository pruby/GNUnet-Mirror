/*
      This file is part of GNUnet
      (C) 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @brief maintains table of DHT connections of this peer
 * @author Christian Grothoff
 *
 * New DHT infrastructure plan:
 * - no RPC, pure async messaging
 * - stateful routing; needed for retry and reply routing
 * - no per-table storage; instead global,
 *   SQL database-based storage for entire peer
 * - no delete operation, just get/put + expiration
 * - no "put" confirmation, try a get to confirm important put!
 * - modules:
 *   + table.c: DHT-peer table, peer discovery cron jobs;
 *     code tries to fill table "as much as possible" over time;
 *     TODO: expose and improve reliabily metrics (to be added later)???
 *     TODO: better randomized neighbor selection in DHT_select_peer???
 *     TODO: add callback for discovery-message padding (use core callback
 *           for extra-available bandwidth)
 *     TODO: add LAN tunnels for increased connectivity choices
 *   + routing.c: tracking of get/put operations, retry, reply handling
 *     code tries best-match routing among entries in table
 *   + service.c: provide DHT services to rest of GNUnet process
 *     (i.e. register datastore with shared data, get/put operations)
 *   + cs.c: services to out-of-process DHT clients (via dht-lib)
 */

#include "platform.h"
#include "table.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_dht_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_pingpong_service.h"


/**
 * How often should the cron job for maintaining the DHT
 * run?
 */
#define MAINTAIN_FREQUENCY 1500 * GNUNET_CRON_MILLISECONDS

/**
 * What is the chance (1 in XXX) that we send DISCOVERY messages
 * to another peer?
 */
#define MAINTAIN_CHANCE (10 + 100 * total_peers)

/**
 * How long can a peer be inactive before we tiem it out?
 */
#define MAINTAIN_PEER_TIMEOUT MAINTAIN_FREQUENCY * MAINTAIN_CHANCE * 4

/**
 * What is the maximum number of known DHT-enabled peers
 * advertised for each DISCOVERY message?
 */
#define MAINTAIN_ADV_CAP 8

/**
 * Target number of peers per bucket
 */
#define MAINTAIN_BUCKET_SIZE 4


/**
 * Per-peer information.
 */
typedef struct
{

  /**
   * What was the last time we received a message from this peer?
   */
  GNUNET_CronTime lastActivity;

  /**
   * What was the last time we send a PING to this peer?
   */
  GNUNET_CronTime lastTimePingSend;

  /**
   * What is the average latency for replies received?
   */
  GNUNET_CronTime expected_latency;

  /**
   * Number of responses received
   */
  unsigned long long response_count;

  /**
   * Number of requests sent
   */
  unsigned long long request_count;

  /**
   * What is the identity of the peer?
   */
  GNUNET_PeerIdentity id;

} PeerInfo;

/**
 * Peers are grouped into buckets.
 */
typedef struct
{

  /**
   * Peers in this bucket.  NULL is used if no peer is known.
   */
  PeerInfo **peers;

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

/**
 * Global core API.
 */
static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * The buckets (Kademlia style routing table).
 */
static PeerBucket *buckets;

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
static struct GNUNET_Mutex *lock;

/**
 * Identity service.
 */
static GNUNET_Identity_ServiceAPI *identity;

/**
 * Statistics service.
 */
static GNUNET_Stats_ServiceAPI *stats;

/**
 * Pingpong service.
 */
static GNUNET_Pingpong_ServiceAPI *pingpong;

static int stat_dht_total_peers;

static int stat_dht_discoveries;

static int stat_dht_route_looks;

static int stat_dht_advertisements;

/**
 * The struct is followed by zero or more
 * PeerIdentities that the sender knows to
 * be participating in the DHT.
 */
typedef struct
{

  GNUNET_MessageHeader header;

  unsigned int space_available;

} P2P_DHT_Discovery;

/**
 * Request for a HELLO for another peer that is participating in the
 * DHT.  Receiver is expected to send back a HELLO for the peer that
 * is being requested.
 */
typedef struct
{

  GNUNET_MessageHeader header;

  unsigned int reserved;

  GNUNET_PeerIdentity peer;

} P2P_DHT_ASK_HELLO;

/**
 * Compute a (rough) estimate of the networks diameter.
 *
 * @return estimated network diameter
 */
unsigned int
GNUNET_DHT_estimate_network_diameter ()
{
  unsigned int i;
  for (i = bucketCount - 1; i > 0; i--)
    {
      if (buckets[i].peers_size > 0)
        break;
    }
  return i + 1;
}

/**
 * Get the index of the lowest bit of the two GNUNET_hash codes that
 * differs.
 */
static unsigned int
get_bit_distance (const GNUNET_HashCode * h1, const GNUNET_HashCode * h2)
{
  unsigned int i;
  int diff;

  for (i = 0; i < sizeof (GNUNET_HashCode) * 8; i++)
    {
      diff = GNUNET_hash_get_bit (h1, i) - GNUNET_hash_get_bit (h2, i);
      if (diff != 0)
        return i;
    }
  return sizeof (GNUNET_HashCode) * 8;
}

/**
 * @return NULL if peer is the current host
 */
static PeerBucket *
findBucketFor (const GNUNET_PeerIdentity * peer)
{
  unsigned int index;
  int i;

  if (0 == memcmp (peer, coreAPI->my_identity, sizeof (GNUNET_PeerIdentity)))
    return NULL;                /* myself! */
  index = get_bit_distance (&peer->hashPubKey,
                            &coreAPI->my_identity->hashPubKey);
  i = bucketCount - 1;
  while ((buckets[i].bstart >= index) && (i > 0))
    i--;
  if ((buckets[i].bstart <= index) && (buckets[i].bend >= index))
    return &buckets[i];
  GNUNET_GE_BREAK (NULL, 0);
  return NULL;
}

/**
 * Find the PeerInfo for the given peer. Returns NULL if peer is not
 * in our DHT routing table.
 */
static PeerInfo *
findPeerEntryInBucket (PeerBucket * bucket, const GNUNET_PeerIdentity * peer)
{
  unsigned int i;

  if (bucket == NULL)
    return NULL;
  for (i = 0; i < bucket->peers_size; i++)
    if (0 ==
        memcmp (peer, &bucket->peers[i]->id, sizeof (GNUNET_PeerIdentity)))
      return bucket->peers[i];
  return NULL;
}

/**
 * Find the PeerInfo for the given peer. Returns NULL if peer is not
 * in our DHT routing table.
 */
static PeerInfo *
findPeerEntry (const GNUNET_PeerIdentity * peer)
{
  return findPeerEntryInBucket (findBucketFor (peer), peer);
}

/**
 * Return a number that is the larger the closer the
 * "have" GNUNET_hash code is to the "target".  The basic
 * idea is that if "have" would be in the n-th lowest
 * bucket of "target", the returned value should be
 * 2^n.  However, the largest number we can return
 * is 2^31, so this number may have to be scaled.
 *
 * @return inverse distance metric, non-zero.
 */
static unsigned int
inverse_distance (const GNUNET_HashCode * target,
                  const GNUNET_HashCode * have)
{
  unsigned int bucket;
  double d;

  bucket = get_bit_distance (target, have);
  d = bucket * 32;
  d = exp2 (d / (sizeof (GNUNET_HashCode) * 8));
  if (d > ((unsigned int) -1))
    return -1;
  return (unsigned int) d;
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
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DHT_select_peer (GNUNET_PeerIdentity * set,
                        const GNUNET_HashCode * target,
                        const GNUNET_PeerIdentity * blocked,
                        unsigned int blocked_size)
{
  unsigned long long total_distance;
  unsigned long long selected;
  unsigned int distance;
  unsigned int bc;
  unsigned int ec;
  unsigned int i;
  int match;
  const PeerBucket *bucket;
  const PeerInfo *pi;

  GNUNET_mutex_lock (lock);
  if (stats != NULL)
    stats->change (stat_dht_route_looks, 1);
  total_distance = 0;
  for (bc = 0; bc < bucketCount; bc++)
    {
      bucket = &buckets[bc];
      for (ec = 0; ec < bucket->peers_size; ec++)
        {
          pi = bucket->peers[ec];
          match = GNUNET_NO;
          for (i = 0; i < blocked_size; i++)
            {
              if (0 ==
                  memcmp (&pi->id, &blocked[i], sizeof (GNUNET_PeerIdentity)))
                {
                  match = GNUNET_YES;
                  break;
                }
            }
          if (match == GNUNET_YES)
            continue;
          total_distance += inverse_distance (target, &pi->id.hashPubKey);
        }
    }
  if (total_distance == 0)
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  selected = GNUNET_random_u64 (GNUNET_RANDOM_QUALITY_WEAK, total_distance);
  for (bc = 0; bc < bucketCount; bc++)
    {
      bucket = &buckets[bc];
      for (ec = 0; ec < bucket->peers_size; ec++)
        {
          pi = bucket->peers[ec];
          match = GNUNET_NO;
          for (i = 0; i < blocked_size; i++)
            {
              if (0 ==
                  memcmp (&pi->id, &blocked[i], sizeof (GNUNET_PeerIdentity)))
                {
                  match = GNUNET_YES;
                  break;
                }
            }
          if (match == GNUNET_YES)
            continue;
          distance = inverse_distance (target, &pi->id.hashPubKey);
          if (distance > selected)
            {
              *set = pi->id;
              GNUNET_mutex_unlock (lock);
              return GNUNET_OK;
            }
          selected -= distance;
        }
    }
  GNUNET_GE_BREAK (NULL, 0);
  GNUNET_mutex_unlock (lock);
  return GNUNET_SYSERR;
}

/**
 * Send a discovery message to the other peer.
 *
 * @param cls NULL or pre-build discovery message
 */
static void
broadcast_dht_discovery (const GNUNET_PeerIdentity * other, void *cls)
{
  P2P_DHT_Discovery *disco = cls;
  unsigned int pc;
  unsigned int i;
  GNUNET_PeerIdentity *pos;

  if (stats != NULL)
    stats->change (stat_dht_advertisements, 1);
  if (disco != NULL)
    {
      coreAPI->ciphertext_send (other,
                                &disco->header,
                                GNUNET_EXTREME_PRIORITY / 4,
                                MAINTAIN_FREQUENCY * MAINTAIN_CHANCE / 2);
      return;
    }
  pc = total_peers;
  if (pc > MAINTAIN_ADV_CAP)
    pc = MAINTAIN_ADV_CAP;
  if (pc == 0)
    pc = 1;
  disco =
    GNUNET_malloc (pc * sizeof (GNUNET_PeerIdentity) +
                   sizeof (P2P_DHT_Discovery));
  disco->header.type = htons (GNUNET_P2P_PROTO_DHT_DISCOVERY);
  disco->space_available = -1;  /* FIXME */
  pos = (GNUNET_PeerIdentity *) & disco[1];
  i = 0;
  if (total_peers == 0)
    {
      /* put in our own identity (otherwise we get into a
         storm of empty discovery messages) */
      pos[0] = *coreAPI->my_identity;
      i = 1;
    }
  while (i < pc)
    {
      if (GNUNET_OK !=
          GNUNET_DHT_select_peer (&pos[i], &other->hashPubKey, pos, i))
        pc--;
      else
        i++;
    }
  disco->header.size =
    htons (pc * sizeof (GNUNET_PeerIdentity) + sizeof (P2P_DHT_Discovery));
  coreAPI->ciphertext_send (other, &disco->header, 0,
                            MAINTAIN_FREQUENCY * MAINTAIN_CHANCE / 2);
  GNUNET_free (disco);
}

static void
broadcast_dht_discovery_prob (const GNUNET_PeerIdentity * other, void *cls)
{
  if (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, MAINTAIN_CHANCE) != 0)
    return;
  broadcast_dht_discovery (other, cls);
}

/**
 * Cron job to maintain DHT routing table.
 */
static void
maintain_dht_job (void *unused)
{
  P2P_DHT_Discovery disc;

  if (total_peers == 0)
    {
      disc.header.size = htons (sizeof (P2P_DHT_Discovery));
      disc.header.type = htons (GNUNET_P2P_PROTO_DHT_DISCOVERY);
      disc.space_available = -1;        /* FIXME */
      coreAPI->p2p_connections_iterate (&broadcast_dht_discovery_prob, &disc);
    }
  else
    {
      coreAPI->p2p_connections_iterate (&broadcast_dht_discovery_prob, NULL);
    }
}

/**
 * We have received a pong from a peer and know it is still
 * there.
 */
static void
pongNotify (void *cls)
{
  GNUNET_PeerIdentity *peer = cls;
  PeerInfo *pi;

  pi = findPeerEntry (peer);
  if (pi != NULL)
    {
      pi->lastActivity = GNUNET_get_time ();
      pi->expected_latency = pi->lastActivity - pi->lastTimePingSend;
      pi->response_count++;
    }
  GNUNET_free (peer);
}

/**
 * Send a ping to the given peer to check if it is still
 * running.
 */
static void
pingPeer (PeerInfo * pi)
{
  GNUNET_PeerIdentity *p;

  p = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
  *p = pi->id;
  if (GNUNET_OK == pingpong->ping (p, &pongNotify, p, GNUNET_NO, rand ()))
    {
      pi->lastTimePingSend = GNUNET_get_time ();
      pi->request_count++;
    }
}

/**
 * Check if pi is still up and running.  May also try
 * to confirm that the peer is still live.
 *
 * @return GNUNET_YES if the peer should be removed from the DHT table
 */
static int
checkExpired (PeerInfo * pi)
{
  GNUNET_CronTime now;

  now = GNUNET_get_time ();
  if (pi->lastActivity >= now)
    return GNUNET_NO;
  if (now - pi->lastActivity > MAINTAIN_PEER_TIMEOUT)
    return GNUNET_YES;
  if (now - pi->lastActivity > MAINTAIN_PEER_TIMEOUT / 2)
    pingPeer (pi);
  return GNUNET_NO;
}

/**
 * Check for expired peers in the given bucket.
 */
static void
checkExpiration (PeerBucket * bucket)
{
  unsigned int i;
  PeerInfo *peer;

  for (i = 0; i < bucket->peers_size; i++)
    {
      peer = bucket->peers[i];
      if (checkExpired (peer) == GNUNET_YES)
        {
          total_peers--;
          if (stats != NULL)
            stats->change (stat_dht_total_peers, -1);
          GNUNET_free (peer);
          bucket->peers[i] = bucket->peers[bucket->peers_size - 1];
          GNUNET_array_grow (bucket->peers, bucket->peers_size,
                             bucket->peers_size - 1);
          i--;
        }
    }
}

/**
 * Consider adding the given peer to the DHT.
 */
static void
considerPeer (const GNUNET_PeerIdentity * sender,
              const GNUNET_PeerIdentity * peer)
{
  PeerInfo *pi;
  PeerBucket *bucket;
  P2P_DHT_ASK_HELLO ask;
  GNUNET_MessageHello *hello;

  bucket = findBucketFor (peer);
  if (bucket == NULL)
    return;                     /* peers[i] == self */
  if (bucket->peers_size >= MAINTAIN_BUCKET_SIZE)
    checkExpiration (bucket);
  if (bucket->peers_size >= MAINTAIN_BUCKET_SIZE)
    return;                     /* do not care */
  if (NULL != findPeerEntryInBucket (bucket, peer))
    return;                     /* already have this peer in buckets */
  /* do we know how to contact this peer? */
  hello =
    identity->identity2Hello (peer, GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY,
                              GNUNET_NO);
  if (hello == NULL)
    {
      /* if identity not known, ask sender for HELLO of other peer */
      ask.header.size = htons (sizeof (P2P_DHT_ASK_HELLO));
      ask.header.type = htons (sizeof (GNUNET_P2P_PROTO_DHT_ASK_HELLO));
      ask.reserved = 0;
      ask.peer = *peer;
      coreAPI->ciphertext_send (sender, &ask.header, 0, /* FIXME: priority */
                                5 * GNUNET_CRON_SECONDS);
      return;
    }
  GNUNET_free (hello);
  /* check if connected, if not, send discovery */
  if (GNUNET_OK != coreAPI->p2p_connection_status_check (peer, NULL, NULL))
    {
      /* not yet connected; connect sending DISCOVERY */
      broadcast_dht_discovery (peer, NULL);
      return;
    }
  /* we are connected (in core), add to bucket */
  pi = GNUNET_malloc (sizeof (PeerInfo));
  memset (pi, 0, sizeof (PeerInfo));
  pi->id = *peer;
  pingPeer (pi);
  GNUNET_array_grow (bucket->peers, bucket->peers_size,
                     bucket->peers_size + 1);
  bucket->peers[bucket->peers_size - 1] = pi;
  total_peers++;
  if (stats != NULL)
    stats->change (stat_dht_total_peers, 1);
}

/**
 * Handle discovery message.
 */
static int
handleDiscovery (const GNUNET_PeerIdentity * sender,
                 const GNUNET_MessageHeader * msg)
{
  unsigned int pc;
  unsigned int i;
  const P2P_DHT_Discovery *disco;
  const GNUNET_PeerIdentity *peers;

  pc =
    (ntohs (msg->size) -
     sizeof (P2P_DHT_Discovery)) / sizeof (GNUNET_PeerIdentity);
  if (pc > MAINTAIN_ADV_CAP * 8)
    {
      GNUNET_GE_BREAK_OP (coreAPI->ectx, 0);
      return GNUNET_SYSERR;     /* far too big */
    }
  if (ntohs (msg->size) !=
      sizeof (P2P_DHT_Discovery) + pc * sizeof (GNUNET_PeerIdentity))
    {
      GNUNET_GE_BREAK_OP (coreAPI->ectx, 0);
      return GNUNET_SYSERR;     /* malformed */
    }
  disco = (const P2P_DHT_Discovery *) msg;
  if (stats != NULL)
    stats->change (stat_dht_discoveries, 1);
  if (pc == 0)
    {
      /* if peer has 0 connections, be sure to send discovery back */
      broadcast_dht_discovery (sender, NULL);
    }
  GNUNET_mutex_lock (lock);
  considerPeer (sender, sender);
  peers = (const GNUNET_PeerIdentity *) &disco[1];
  for (i = 0; i < pc; i++)
    considerPeer (sender, &peers[i]);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Handle ask hello message.
 */
static int
handleAskHello (const GNUNET_PeerIdentity * sender,
                const GNUNET_MessageHeader * msg)
{
  const P2P_DHT_ASK_HELLO *ask;
  GNUNET_MessageHello *hello;

  if (ntohs (msg->size) != sizeof (P2P_DHT_ASK_HELLO))
    {
      GNUNET_GE_BREAK_OP (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  ask = (const P2P_DHT_ASK_HELLO *) msg;
  if (NULL == findBucketFor (&ask->peer))
    return GNUNET_OK;
  hello =
    identity->identity2Hello (&ask->peer,
                              GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY,
                              GNUNET_NO);
  if (hello == NULL)
    return GNUNET_OK;
  coreAPI->ciphertext_send (sender, &hello->header, 0,
                            5 * GNUNET_CRON_SECONDS);
  GNUNET_free (hello);
  return GNUNET_OK;
}

static void
peer_disconnect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
  PeerBucket *bucket;
  PeerInfo *info;

  GNUNET_mutex_lock (lock);
  bucket = findBucketFor (peer);
  if (bucket != NULL)
    {
      info = findPeerEntryInBucket (bucket, peer);
      if (info != NULL)
        {
          info->lastActivity = 0;
          checkExpiration (bucket);
        }
    }
  GNUNET_mutex_unlock (lock);
}

/**
 * Initialize table DHT component.
 *
 * @param capi the core API
 * @return GNUNET_OK on success
 */
int
GNUNET_DHT_table_init (GNUNET_CoreAPIForPlugins * capi)
{
  unsigned long long i;

  coreAPI = capi;
  /* use less than 50% of peer's ideal number of
     connections for DHT table size */
  i = coreAPI->core_slots_count () / MAINTAIN_BUCKET_SIZE / 2;
  if (i < 4)
    i = 4;
  GNUNET_array_grow (buckets, bucketCount, i);
  for (i = 0; i < bucketCount; i++)
    {
      buckets[i].bstart = 512 * i / bucketCount;
      buckets[i].bend = 512 * (i + 1) / bucketCount;
    }
  lock = capi->global_lock_get ();
  stats = capi->service_request ("stats");
  if (stats != NULL)
    {
      stat_dht_total_peers =
        stats->create (gettext_noop ("# dht connections"));
      stat_dht_discoveries =
        stats->create (gettext_noop ("# dht discovery messages received"));
      stat_dht_route_looks =
        stats->create (gettext_noop ("# dht route host lookups performed"));
      stat_dht_advertisements =
        stats->create (gettext_noop ("# dht discovery messages sent"));
    }
  identity = coreAPI->service_request ("identity");
  GNUNET_GE_ASSERT (coreAPI->ectx, identity != NULL);
  pingpong = coreAPI->service_request ("pingpong");
  GNUNET_GE_ASSERT (coreAPI->ectx, pingpong != NULL);
  capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_DHT_DISCOVERY,
                                         &handleDiscovery);
  capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_DHT_ASK_HELLO,
                                         &handleAskHello);
  capi->peer_disconnect_notification_register (&peer_disconnect_handler,
                                               NULL);
  GNUNET_cron_add_job (coreAPI->cron, &maintain_dht_job, MAINTAIN_FREQUENCY,
                       MAINTAIN_FREQUENCY, NULL);
  return GNUNET_OK;
}

/**
 * Shutdown table DHT component.
 *
 * @return GNUNET_OK on success
 */
int
GNUNET_DHT_table_done ()
{
  unsigned int i;
  unsigned int j;

  coreAPI->peer_disconnect_notification_unregister (&peer_disconnect_handler,
                                                    NULL);
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_DHT_DISCOVERY,
                                              &handleDiscovery);
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_DHT_ASK_HELLO,
                                              &handleAskHello);
  GNUNET_cron_del_job (coreAPI->cron, &maintain_dht_job, MAINTAIN_FREQUENCY,
                       NULL);
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }
  coreAPI->service_release (identity);
  identity = NULL;
  coreAPI->service_release (pingpong);
  pingpong = NULL;
  for (i = 0; i < bucketCount; i++)
    {
      for (j = 0; j < buckets[i].peers_size; j++)
        GNUNET_free (buckets[i].peers[j]);
      GNUNET_array_grow (buckets[i].peers, buckets[i].peers_size, 0);
    }
  GNUNET_array_grow (buckets, bucketCount, 0);
  lock = NULL;
  return GNUNET_OK;
}

/* end of table.c */
