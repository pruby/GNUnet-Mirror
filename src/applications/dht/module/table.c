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
 *     TODO: expose and improve reliabily metrics (to be added later)
 *   + dstore.c + plugin: SQL-based datastore: key, value, expiration
 *     (bounded FIFO-datastore, when full, kill oldest entry first)
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
#define MAINTAIN_FREQUENCY 1500 * cronMILLIS

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
  cron_t lastActivity;

  /**
   * What was the last time we send a PING to this peer?
   */
  cron_t lastTimePingSend;

  /**
   * What is the average latency for replies received?
   */
  cron_t expected_latency;

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
  PeerIdentity id;

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
static CoreAPIForApplication *coreAPI;

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
static struct MUTEX *lock;

/**
 * Identity service.
 */
static Identity_ServiceAPI *identity;

/**
 * Statistics service.
 */
static Stats_ServiceAPI *stats;

/**
 * Pingpong service.
 */
static Pingpong_ServiceAPI *pingpong;

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

  MESSAGE_HEADER header;

  unsigned int space_available;

} P2P_DHT_Discovery;

/**
 * Request for a HELLO for another peer that is participating in the
 * DHT.  Receiver is expected to send back a HELLO for the peer that
 * is being requested.
 */
typedef struct
{

  MESSAGE_HEADER header;

  unsigned int reserved;

  PeerIdentity peer;

} P2P_DHT_ASK_HELLO;

/**
 * Get the index of the lowest bit of the two hash codes that
 * differs.
 */
static unsigned int
get_bit_distance (const HashCode512 * h1, const HashCode512 * h2)
{
  unsigned int i;
  int diff;

  for (i = 0; i < sizeof (HashCode512) * 8; i++)
    {
      diff = getHashCodeBit (h1, i) - getHashCodeBit (h2, i);
      if (diff != 0)
        return i;
    }
  return sizeof (HashCode512) * 8;
}

/**
 * @return NULL if peer is the current host
 */
static PeerBucket *
findBucketFor (const PeerIdentity * peer)
{
  unsigned int index;
  int i;

  index = get_bit_distance (&peer->hashPubKey,
                            &coreAPI->myIdentity->hashPubKey);
  i = bucketCount - 1;
  while ((buckets[i].bstart >= index) && (i > 0))
    i--;
  if ((buckets[i].bstart < index) && (buckets[i].bend >= index))
    return &buckets[i];
  return NULL;
}

/**
 * Find the PeerInfo for the given peer. Returns NULL if peer is not
 * in our DHT routing table.
 */
static PeerInfo *
findPeerEntryInBucket (PeerBucket * bucket, const PeerIdentity * peer)
{
  unsigned int i;

  if (bucket == NULL)
    return NULL;
  for (i = 0; i < bucket->peers_size; i++)
    if (0 == memcmp (peer, &bucket->peers[i]->id, sizeof (PeerIdentity)))
      return bucket->peers[i];
  return NULL;
}

/**
 * Find the PeerInfo for the given peer. Returns NULL if peer is not
 * in our DHT routing table.
 */
static PeerInfo *
findPeerEntry (const PeerIdentity * peer)
{
  return findPeerEntryInBucket (findBucketFor (peer), peer);
}

/**
 * Return a number that is the larger the closer the
 * "have" hash code is to the "target".  The basic
 * idea is that if "have" would be in the n-th lowest
 * bucket of "target", the returned value should be
 * 2^n.  However, the largest number we can return
 * is 2^31, so this number may have to be scaled.
 *
 * @return inverse distance metric, non-zero.
 */
static unsigned int
inverse_distance (const HashCode512 * target, const HashCode512 * have)
{
  unsigned int bucket;
  double d;

  bucket = get_bit_distance (target, have);
  d = bucket * 32;
  d = exp2 (d / (sizeof (HashCode512) * 8));
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
 * @return OK on success, SYSERR on error
 */
int
select_dht_peer (PeerIdentity * set,
                 const HashCode512 * target,
                 const PeerIdentity * blocked, unsigned int blocked_size)
{
  unsigned long long total_distance;
  unsigned long long selected;
  unsigned int distance;
  unsigned int bc;
  unsigned int ec;
  unsigned int i;
  int match;
  PeerBucket *bucket;
  PeerInfo *pi;

  MUTEX_LOCK (lock);
  if (stats != NULL)
    stats->change (stat_dht_route_looks, 1);
  total_distance = 0;
  for (bc = 0; bc < bucketCount; bc++)
    {
      bucket = &buckets[bc];
      for (ec = 0; ec < bucket->peers_size; ec++)
        {
          pi = bucket->peers[ec];
          match = NO;
          for (i = 0; i < blocked_size; i++)
            {
              if (0 == memcmp (&pi->id, &blocked[i], sizeof (PeerIdentity)))
                {
                  match = YES;
                  break;
                }
            }
          if (match == YES)
            continue;
          total_distance += inverse_distance (target, &pi->id.hashPubKey);
        }
    }
  if (total_distance == 0)
    {
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  selected = weak_randomi64 (total_distance);
  for (bc = 0; bc < bucketCount; bc++)
    {
      bucket = &buckets[bc];
      for (ec = 0; ec < bucket->peers_size; ec++)
        {
          pi = bucket->peers[ec];
          match = NO;
          for (i = 0; i < blocked_size; i++)
            {
              if (0 == memcmp (&pi->id, &blocked[i], sizeof (PeerIdentity)))
                {
                  match = YES;
                  break;
                }
            }
          if (match == YES)
            continue;
          distance = inverse_distance (target, &pi->id.hashPubKey);
          if (distance > selected)
            {
              *set = pi->id;
              MUTEX_UNLOCK (lock);
              return OK;
            }
          selected -= distance;
        }
    }
  GE_BREAK (NULL, 0);
  MUTEX_UNLOCK (lock);
  return SYSERR;
}

/**
 * Send a discovery message to the other peer.
 *
 * @param cls NULL or pre-build discovery message
 */
static void
broadcast_dht_discovery (const PeerIdentity * other, void *cls)
{
  P2P_DHT_Discovery *disco = cls;
  unsigned int pc;
  unsigned int i;
  PeerIdentity *pos;

  if (stats != NULL)
    stats->change (stat_dht_advertisements, 1);
  if (disco != NULL)
    {
      coreAPI->unicast (other,
                        &disco->header,
                        EXTREME_PRIORITY / 4,
                        MAINTAIN_FREQUENCY * MAINTAIN_CHANCE / 2);
      return;
    }
  pc = total_peers;
  if (pc > MAINTAIN_ADV_CAP)
    pc = MAINTAIN_ADV_CAP;
  if (pc == 0)
    pc = 1;
  disco = MALLOC (pc * sizeof (PeerIdentity) + sizeof (P2P_DHT_Discovery));
  disco->header.type = htons (P2P_PROTO_DHT_DISCOVERY);
  disco->space_available = -1;  /* FIXME */
  pos = (PeerIdentity *) & disco[1];
  i = 0;
  if (total_peers == 0)
    {
      /* put in our own identity (otherwise we get into a
         storm of empty discovery messages) */
      pos[0] = *coreAPI->myIdentity;
      i = 1;
    }
  while (i < pc)
    {
      if (OK != select_dht_peer (&pos[i], &other->hashPubKey, pos, i))
        pc--;
      else
        i++;
    }
  disco->header.size =
    htons (pc * sizeof (PeerIdentity) + sizeof (P2P_DHT_Discovery));
  coreAPI->unicast (other, &disco->header, 0,
                    MAINTAIN_FREQUENCY * MAINTAIN_CHANCE / 2);
  FREE (disco);
}

static void
broadcast_dht_discovery_prob (const PeerIdentity * other, void *cls)
{
  if (weak_randomi (MAINTAIN_CHANCE) != 0)
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
      disc.header.type = htons (P2P_PROTO_DHT_DISCOVERY);
      disc.space_available = -1;        /* FIXME */
      coreAPI->forAllConnectedNodes (&broadcast_dht_discovery_prob, &disc);
    }
  else
    {
      coreAPI->forAllConnectedNodes (&broadcast_dht_discovery_prob, NULL);
    }
}

/**
 * We have received a pong from a peer and know it is still
 * there.
 */
static void
pongNotify (void *cls)
{
  PeerIdentity *peer = cls;
  PeerInfo *pi;

  pi = findPeerEntry (peer);
  if (pi != NULL)
    {
      pi->lastActivity = get_time ();
      pi->expected_latency = pi->lastActivity - pi->lastTimePingSend;
      pi->response_count++;
    }
  FREE (peer);
}

/**
 * Send a ping to the given peer to check if it is still
 * running.
 */
static void
pingPeer (PeerInfo * pi)
{
  PeerIdentity *p;

  p = MALLOC (sizeof (PeerIdentity));
  *p = pi->id;
  if (OK == pingpong->ping (p, &pongNotify, p, NO, rand ()))
    {
      pi->lastTimePingSend = get_time ();
      pi->request_count++;
    }
}

/**
 * Check if pi is still up and running.  May also try
 * to confirm that the peer is still live.
 *
 * @return YES if the peer should be removed from the DHT table
 */
static int
checkExpired (PeerInfo * pi)
{
  cron_t now;

  now = get_time ();
  if (pi->lastActivity >= now)
    return NO;
  if (now - pi->lastActivity > MAINTAIN_PEER_TIMEOUT)
    return YES;
  if (now - pi->lastActivity > MAINTAIN_PEER_TIMEOUT / 2)
    pingPeer (pi);
  return NO;
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
      if (checkExpired (peer) == YES)
        {
          total_peers--;
          if (stats != NULL)
            stats->change (stat_dht_total_peers, -1);
          FREE (peer);
          bucket->peers[i] = bucket->peers[bucket->peers_size - 1];
          GROW (bucket->peers, bucket->peers_size, bucket->peers_size - 1);
        }
    }
}

/**
 * Consider adding the given peer to the DHT.
 */
static void
considerPeer (const PeerIdentity * sender, const PeerIdentity * peer)
{
  PeerInfo *pi;
  PeerBucket *bucket;
  P2P_DHT_ASK_HELLO ask;
  P2P_hello_MESSAGE *hello;

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
  hello = identity->identity2Hello (peer, ANY_PROTOCOL_NUMBER, NO);
  if (hello == NULL)
    {
      /* if identity not known, ask sender for HELLO of other peer */
      ask.header.size = htons (sizeof (P2P_DHT_ASK_HELLO));
      ask.header.type = htons (sizeof (P2P_PROTO_DHT_ASK_HELLO));
      ask.reserved = 0;
      ask.peer = *peer;
      coreAPI->unicast (sender, &ask.header, 0, /* FIXME: priority */
                        5 * cronSECONDS);
      return;
    }
  FREE (hello);
  /* check if connected, if not, send discovery */
  if (OK != coreAPI->queryPeerStatus (peer, NULL, NULL))
    {
      /* not yet connected; connect sending DISCOVERY */
      broadcast_dht_discovery (peer, NULL);
      return;
    }
  /* we are connected (in core), add to bucket */
  pi = MALLOC (sizeof (PeerInfo));
  memset (pi, 0, sizeof (PeerInfo));
  pi->id = *peer;
  pingPeer (pi);
  GROW (bucket->peers, bucket->peers_size, bucket->peers_size + 1);
  bucket->peers[bucket->peers_size - 1] = pi;
  total_peers++;
  if (stats != NULL)
    stats->change (stat_dht_total_peers, 1);
}

/**
 * Handle discovery message.
 */
static int
handleDiscovery (const PeerIdentity * sender, const MESSAGE_HEADER * msg)
{
  unsigned int pc;
  unsigned int i;
  const P2P_DHT_Discovery *disco;
  const PeerIdentity *peers;

  pc =
    (ntohs (msg->size) - sizeof (P2P_DHT_Discovery)) / sizeof (PeerIdentity);
  if (pc > MAINTAIN_ADV_CAP * 8)
    {
      GE_BREAK (coreAPI->ectx, 0);
      return SYSERR;            /* far too big */
    }
  if (ntohs (msg->size) !=
      sizeof (P2P_DHT_Discovery) + pc * sizeof (PeerIdentity))
    {
      GE_BREAK (coreAPI->ectx, 0);
      return SYSERR;            /* malformed */
    }
  disco = (const P2P_DHT_Discovery *) msg;
  if (stats != NULL)
    stats->change (stat_dht_discoveries, 1);
  if (pc == 0)
    {
      /* if peer has 0 connections, be sure to send discovery back */
      broadcast_dht_discovery (sender, NULL);
    }
  MUTEX_LOCK (lock);
  considerPeer (sender, sender);
  peers = (const PeerIdentity *) &disco[1];
  for (i = 0; i < pc; i++)
    considerPeer (sender, &peers[i]);
  MUTEX_UNLOCK (lock);
  return OK;
}

/**
 * Handle ask hello message.
 */
static int
handleAskHello (const PeerIdentity * sender, const MESSAGE_HEADER * msg)
{
  const P2P_DHT_ASK_HELLO *ask;
  P2P_hello_MESSAGE *hello;

  if (ntohs (msg->size) != sizeof (P2P_DHT_ASK_HELLO))
    return SYSERR;
  ask = (const P2P_DHT_ASK_HELLO *) msg;
  if (NULL == findBucketFor (&ask->peer))
    return OK;
  hello = identity->identity2Hello (&ask->peer, ANY_PROTOCOL_NUMBER, NO);
  if (hello == NULL)
    return OK;
  coreAPI->unicast (sender, &hello->header, 0, 5 * cronSECONDS);
  FREE (hello);
  return OK;
}

/**
 * Initialize table DHT component.
 *
 * @param capi the core API
 * @return OK on success
 */
int
init_dht_table (CoreAPIForApplication * capi)
{
  unsigned long long i;

  coreAPI = capi;
  /* use less than 50% of peer's ideal number of
     connections for DHT table size */
  i = coreAPI->getSlotCount () / MAINTAIN_BUCKET_SIZE / 2;
  if (i < 4)
    i = 4;
  GROW (buckets, bucketCount, i);
  for (i = 0; i < bucketCount; i++)
    {
      buckets[i].bstart = 512 * i / bucketCount;
      buckets[i].bend = 512 * (i + 1) / bucketCount;
    }
  lock = capi->getConnectionModuleLock ();
  stats = capi->requestService ("stats");
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
  identity = coreAPI->requestService ("identity");
  GE_ASSERT (coreAPI->ectx, identity != NULL);
  pingpong = coreAPI->requestService ("pingpong");
  GE_ASSERT (coreAPI->ectx, pingpong != NULL);
  capi->registerHandler (P2P_PROTO_DHT_DISCOVERY, &handleDiscovery);
  capi->registerHandler (P2P_PROTO_DHT_ASK_HELLO, &handleAskHello);
  cron_add_job (coreAPI->cron,
                &maintain_dht_job,
                MAINTAIN_FREQUENCY, MAINTAIN_FREQUENCY, NULL);
  return OK;
}

/**
 * Shutdown table DHT component.
 *
 * @return OK on success
 */
int
done_dht_table ()
{
  unsigned int i;
  unsigned int j;

  coreAPI->unregisterHandler (P2P_PROTO_DHT_DISCOVERY, &handleDiscovery);
  coreAPI->unregisterHandler (P2P_PROTO_DHT_ASK_HELLO, &handleAskHello);
  cron_del_job (coreAPI->cron, &maintain_dht_job, MAINTAIN_FREQUENCY, NULL);
  if (stats != NULL)
    {
      coreAPI->releaseService (stats);
      stats = NULL;
    }
  coreAPI->releaseService (identity);
  identity = NULL;
  coreAPI->releaseService (pingpong);
  pingpong = NULL;
  for (i = 0; i < bucketCount; i++)
    {
      for (j = 0; j < buckets[i].peers_size; j++)
        FREE (buckets[i].peers[j]);
      GROW (buckets[i].peers, buckets[i].peers_size, 0);
    }
  GROW (buckets, bucketCount, 0);
  lock = NULL;
  return OK;
}

/* end of table.c */
