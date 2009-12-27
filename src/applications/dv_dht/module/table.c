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
 * @brief maintains table of DV_DHT connections of this peer
 * @author Christian Grothoff
 *
 * New DV_DHT infrastructure plan:
 * - no RPC, pure async messaging
 * - stateful routing; needed for retry and reply routing
 * - no per-table storage; instead global,
 *   SQL database-based storage for entire peer
 * - no delete operation, just get/put + expiration
 * - no "put" confirmation, try a get to confirm important put!
 * - modules:
 *   + table.c: DV_DHT-peer table, peer discovery cron jobs;
 *     code tries to fill table "as much as possible" over time;
 *     TODO: expose and improve reliability metrics (to be added later)???
 *     TODO: better randomized neighbor selection in DV_DHT_select_peer???
 *     TODO: add callback for discovery-message padding (use core callback
 *           for extra-available bandwidth)
 *     TODO: add LAN tunnels for increased connectivity choices
 *   + routing.c: tracking of get/put operations, retry, reply handling
 *     code tries best-match routing among entries in table
 *   + service.c: provide DV_DHT services to rest of GNUnet process
 *     (i.e. register datastore with shared data, get/put operations)
 *   + cs.c: services to out-of-process DV_DHT clients (via dv_dht-lib)
 */

#include "platform.h"
#include <math.h>
#include "table.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_dv_dht_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_pingpong_service.h"
#include "gnunet_dv_service.h"


#define DEBUG_TABLE GNUNET_NO

/**
 * How often should the cron job for maintaining the DV_DHT
 * run?
 */
#define MAINTAIN_FREQUENCY 10000 * GNUNET_CRON_MILLISECONDS

/**
 * How long can a peer be inactive before we time it out?
 */
#define MAINTAIN_PEER_TIMEOUT MAINTAIN_FREQUENCY * 4

/**
 * What is the maximum number of known DV_DHT-enabled peers
 * advertised for each DISCOVERY message?
 */
#define MAINTAIN_ADV_CAP 8

/**
 * Target number of peers per bucket
 */
#define MAINTAIN_BUCKET_SIZE 8  /* Previously 4, trying different values... */


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

static GNUNET_DV_ServiceAPI *dvapi;

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
 * be participating in the DV_DHT.
 */
typedef struct
{

  GNUNET_MessageHeader header;

  unsigned int space_available;

} P2P_DV_DHT_Discovery;

/**
 * Request for a HELLO for another peer that is participating in the
 * DV_DHT.  Receiver is expected to send back a HELLO for the peer that
 * is being requested.
 */
typedef struct
{

  GNUNET_MessageHeader header;

  unsigned int reserved;

  GNUNET_PeerIdentity peer;

} P2P_DV_DHT_ASK_HELLO;

#if DEBUG_TABLE
static FILE *debug_file;
static char *debug_file_name;
static unsigned int indentation;
static void
print_entry (char *function)
{
  int i;

  for (i = 0; i < indentation; i++)
    {
      fprintf (debug_file, "  ");
    }

  fprintf (debug_file, _("Entering `%s'\n"), function);
  indentation++;
}

static void
print_exit (char *function)
{
  int i;
  if (indentation >= 1)
    indentation--;
  for (i = 0; i < indentation; i++)
    {
      fprintf (debug_file, "  ");
    }
  fprintf (debug_file, _("Exiting `%s'\n"), function);
}
#endif

/**
 * Compute a (rough) estimate of the networks diameter.
 *
 * @return estimated network diameter
 */
unsigned int
GNUNET_DV_DHT_estimate_network_diameter ()
{
  unsigned int i;

  for (i = bucketCount - 1; i > 0; i--)
    if (buckets[i].peers_size > 0)
      break;
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

  for (i = 0; i < sizeof (GNUNET_HashCode) * 8; i++)
    if (GNUNET_hash_get_bit (h1, i) != GNUNET_hash_get_bit (h2, i))
      return i;
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
  while ((buckets[i].bstart > index) && (i > 0))
    i--;
  if ((buckets[i].bstart <= index) && (buckets[i].bend >= index))
    return &buckets[i];
  GNUNET_GE_BREAK (NULL, 0);
  return NULL;
}

/**
 * Find the PeerInfo for the given peer. Returns NULL if peer is not
 * in our DV_DHT routing table.
 */
static PeerInfo *
findPeerEntryInBucket (PeerBucket * bucket, const GNUNET_PeerIdentity * peer)
{
  unsigned int i;

  if (bucket == NULL)
    return NULL;
  for (i = 0; i < bucket->peers_size; i++)
    if (0 == memcmp (peer,
                     &bucket->peers[i]->id, sizeof (GNUNET_PeerIdentity)))
      return bucket->peers[i];
  return NULL;
}

/**
 * Find the PeerInfo for the given peer. Returns NULL if peer is not
 * in our DV_DHT routing table.
 */
static PeerInfo *
findPeerEntry (const GNUNET_PeerIdentity * peer)
{
  return findPeerEntryInBucket (findBucketFor (peer), peer);
}



/**
 * Compute the distance between have and target as a 32-bit value.
 * Differences in the lower bits must count stronger than differences
 * in the higher bits.
 *
 * @return 0 if have==target, otherwise a number
 *           that is larger as the distance between
 *           the two hash codes inceases
 */
static unsigned int
distance (const GNUNET_HashCode * target, const GNUNET_HashCode * have)
{
  unsigned int bucket;
  unsigned int msb;
  unsigned int lsb;
  unsigned int i;

  /* We have to represent the distance between two 2^9 (=512)-bit
     numbers as a 2^5 (=32)-bit number with "0" being used for the
     two numbers being identical; furthermore, we need to
     guarantee that a difference in the number of matching
     bits is always represented in the result.

     We use 2^32/2^9 numerical values to distinguish between
     hash codes that have the same LSB bit distance and
     use the highest 2^9 bits of the result to signify the
     number of (miss)matching LSB bits; if we have 0 matching
     and hence 512 missmatching LSB bits we return -1 (since
     512 itself cannot be represented with 9 bits) */

  /* first, calculate the most significant 9 bits of our
     result, aka the number of LSBs */
  bucket = get_bit_distance (target, have);
  /* bucket is now a value between 0 and 512 */
  if (bucket == 512)
    return 0;                   /* perfect match */
  if (bucket == 0)
    return (unsigned int) -1;   /* LSB differs; use max (if we did the bit-shifting
                                   below, we'd end up with max+1 (overflow)) */

  /* calculate the most significant bits of the final result */
  msb = (512 - bucket) << (32 - 9);
  /* calculate the 32-9 least significant bits of the final result by
     looking at the differences in the 32-9 bits following the
     mismatching bit at 'bucket' */
  lsb = 0;
  for (i = bucket + 1;
       (i < sizeof (GNUNET_HashCode) * 8) && (i < bucket + 1 + 32 - 9); i++)
    {
      if (GNUNET_hash_get_bit (target, i) != GNUNET_hash_get_bit (have, i))
        lsb |= (1 << (bucket + 32 - 9 - i));    /* first bit set will be 10,
                                                   last bit set will be 31 -- if
                                                   i does not reach 512 first... */
    }
  return msb | lsb;
}

/**
 * Return a number that is the larger the closer the
 * "have" GNUNET_hash code is to the "target".
 *
 * @return inverse distance metric, non-zero.
 */
static unsigned int
inverse_distance (const GNUNET_HashCode * target,
                  const GNUNET_HashCode * have)
{
  return ((unsigned int) -1) - distance (target, have);
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
GNUNET_DV_DHT_select_peer (GNUNET_PeerIdentity * set,
                           const GNUNET_HashCode * target,
                           const GNUNET_PeerIdentity * blocked,
                           unsigned int blocked_size,
                           struct GNUNET_BloomFilter *bloom)
{
  unsigned long long selected;
  unsigned int distance;
  unsigned int bc;
  unsigned int ec;
  unsigned int i;
  int match;
  const PeerBucket *bucket;
  const PeerInfo *pi;
#if USE_KADEMLIA
  const PeerInfo *chosen;
  unsigned long long largest_distance;
#else
  unsigned long long total_distance;
#endif

#if USE_KADEMLIA
  largest_distance = 0;
  GNUNET_mutex_lock (lock);
  for (bc = 0; bc < bucketCount; bc++)
    {
      bucket = &buckets[bc];
      for (ec = 0; ec < bucket->peers_size; ec++)
        {
          pi = bucket->peers[ec];
          match = GNUNET_NO;
          match = GNUNET_bloomfilter_test (bloom, &pi->id.hashPubKey);
          if (match == GNUNET_YES)
            {
              continue;
            }
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

          if (inverse_distance (target, &pi->id.hashPubKey) >
              largest_distance)
            {
              chosen = bucket->peers[ec];
              largest_distance =
                inverse_distance (target, &pi->id.hashPubKey);
            }
        }
    }

  GNUNET_mutex_unlock (lock);
  if ((largest_distance > 0) && (chosen != NULL))
    {
      *set = chosen->id;
      return GNUNET_OK;
    }
  else
    {
      return GNUNET_SYSERR;
    }
#else
  /* GNUnet-style */
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
          match = GNUNET_bloomfilter_test (bloom, &pi->id.hashPubKey);
          if (match == GNUNET_YES)
            {
              /* circular route */
              continue;
            }
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
          match = GNUNET_bloomfilter_test (bloom, &pi->id.hashPubKey);
          if (match == GNUNET_YES)
            {
              /* circular route */
              continue;
            }
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
#endif
}


/*
 * Find the actual, closest peer in our buckets to target
 *
 * @return GNUNET_SYSERR if there are no peers known, GNUNET_OK if
 *         we found a peer
 */
static int
find_closest_peer (GNUNET_PeerIdentity * set, const GNUNET_HashCode * target)
{
  unsigned int largest_inv_distance;
  unsigned int inv_dist;
  unsigned int bc;
  unsigned int ec;
  const PeerBucket *bucket;
  const PeerInfo *pi;
  const PeerInfo *chosen;

  chosen = NULL;
  largest_inv_distance = 0;
  GNUNET_mutex_lock (lock);
  for (bc = 0; bc < bucketCount; bc++)
    {
      bucket = &buckets[bc];
      for (ec = 0; ec < bucket->peers_size; ec++)
        {
          pi = bucket->peers[ec];
          inv_dist = inverse_distance (target, &pi->id.hashPubKey);
          if (inv_dist > largest_inv_distance)
            {
              chosen = bucket->peers[ec];
              largest_inv_distance = inv_dist;
            }
        }
    }
  GNUNET_mutex_unlock (lock);
  if (chosen != NULL)
    {
      *set = chosen->id;
      return GNUNET_OK;
    }
  return GNUNET_SYSERR;
}

#if DEBUG_TABLE
static void
printKeyBits (const GNUNET_HashCode * key)
{
  unsigned int i;
  char loc[sizeof (GNUNET_HashCode) * 8 + 1];

  loc[sizeof (loc) - 1] = '\0';
  for (i = 0; i < sizeof (GNUNET_HashCode) * 8; i++)
    {
      if (GNUNET_hash_get_bit (key, i) == 0)
        loc[i] = '0';
      else
        loc[i] = '1';
    }
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s\n", &loc);
}

static void
printPeerBits (GNUNET_PeerIdentity * peer)
{
  printKeyBits (&peer->hashPubKey);
}

#endif

/*
 * Check whether my identity is closer than any known peers.
 *
 * Return GNUNET_YES if node location is closest, GNUNET_NO
 * otherwise.
 */
int
GNUNET_DV_DHT_am_closest_peer (const GNUNET_HashCode * target)
{

  GNUNET_PeerIdentity closest;

  memset (&closest, 0, sizeof (GNUNET_PeerIdentity));
  if (GNUNET_OK != find_closest_peer (&closest, target))
    {
      /* no other peers known; hence we must be the closest! */
      return GNUNET_YES;
    }
#if DEBUG_TABLE
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "closest peer\n");
  printPeerBits (&closest);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "me\n");
  printPeerBits (coreAPI->my_identity);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "key\n");
  printKeyBits (target);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "closest peer inverse distance is %u, mine is %u\n",
                 inverse_distance (target, &closest.hashPubKey),
                 inverse_distance (target,
                                   &coreAPI->my_identity->hashPubKey));
#endif
  if (distance (target, &coreAPI->my_identity->hashPubKey) <=
      distance (target, &closest.hashPubKey))
    return GNUNET_YES;
  return GNUNET_NO;
}

/**
 * We have received a pong from a peer and know it is still there.
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
  pi->lastTimePingSend = GNUNET_get_time ();
  pi->request_count++;
  pingpong->ping (p, &pongNotify, p, GNUNET_NO, rand ());
}

/**
 * Check if pi is still up and running.  May also try
 * to confirm that the peer is still live.
 *
 * @return GNUNET_YES if the peer should be removed from the DV_DHT table
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
 * Consider adding the given peer to the DV_DHT.
 */
void
GNUNET_DV_DHT_considerPeer (const GNUNET_PeerIdentity * peer)
{
  PeerInfo *pi;
  PeerBucket *bucket;

  bucket = findBucketFor (peer);
  if (bucket == NULL)
    {
      return;                   /* peers[i] == self */
    }
  if (bucket->peers_size >= MAINTAIN_BUCKET_SIZE)
    {
      checkExpiration (bucket);
    }
  if (bucket->peers_size >= MAINTAIN_BUCKET_SIZE)
    {
      return;                   /* do not care */
    }
  if (NULL != findPeerEntryInBucket (bucket, peer))
    {
      return;                   /* already have this peer in buckets */
    }

  /* do we know how to contact this peer? */
  /* This may not work with the dv implementation... */

  /* check if connected, if not, send discovery */
  /* coreAPI->p2p_connection_status_check (peer, NULL, NULL); */
  if (GNUNET_OK != dvapi->p2p_connection_status_check (peer, NULL, NULL))
    {
#if DISCOVERY
      /* not yet connected; connect sending DISCOVERY */
      /*broadcast_dht_discovery (peer, NULL); */
#endif
      return;
    }
  /* we are connected (in dv), add to bucket */
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

static void
broadcast_dht_discovery_prob (const GNUNET_PeerIdentity * other, void *cls)
{
#if DEBUG_TABLE
  print_entry ("broadcast_dht_discovery_prob");
#endif
  GNUNET_mutex_lock (lock);
  GNUNET_DV_DHT_considerPeer (other);
  GNUNET_mutex_unlock (lock);
#if DEBUG_TABLE
  print_exit ("broadcast_dht_discovery_prob");
#endif
}


/**
 * Cron job to maintain DV_DHT routing table.
 */
static void
maintain_dht_job (void *unused)
{
#if DEBUG_TABLE
  print_entry ("maintain_dht_job");
#endif
  dvapi->dv_connections_iterate (&broadcast_dht_discovery_prob, NULL);

#if DEBUG_TABLE
  print_exit ("maintain_dht_job");
#endif
}

/**
 * Handle ask hello message.
 */
static int
handleAskHello (const GNUNET_PeerIdentity * sender,
                const GNUNET_MessageHeader * msg)
{
  const P2P_DV_DHT_ASK_HELLO *ask;
  GNUNET_MessageHello *hello;

  if (ntohs (msg->size) != sizeof (P2P_DV_DHT_ASK_HELLO))
    {
      GNUNET_GE_BREAK_OP (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  ask = (const P2P_DV_DHT_ASK_HELLO *) msg;
  if (NULL == findBucketFor (&ask->peer))
    return GNUNET_OK;
  hello =
    identity->identity2Hello (&ask->peer,
                              GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY,
                              GNUNET_NO);
  if (hello == NULL)
    return GNUNET_OK;
  dvapi->dv_send (sender, &hello->header, 0, GNUNET_CRON_SECONDS);
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

#if DEBUG_TABLE
void
print_buckets ()
{
  unsigned int i;
  unsigned int j;
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "My bit location:\n");
  printPeerBits (coreAPI->my_identity);
  for (i = 0; i < bucketCount; i++)
    {
      if (buckets[i].peers_size > 0)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
                         | GNUNET_GE_BULK, "Printing peers in bucket %d", i);
          for (j = 0; j < buckets[i].peers_size; j++)
            {
              printPeerBits (&buckets[i].peers[j]->id);
            }
        }
    }
}
#endif


/**
 * Initialize table DV_DHT component.
 *
 * @param capi the core API
 * @return GNUNET_OK on success
 */
int
GNUNET_DV_DHT_table_init (GNUNET_CoreAPIForPlugins * capi)
{
  unsigned long long i;

  coreAPI = capi;
#if DEBUG_TABLE
  char *gnunet_path;
  GNUNET_GC_get_configuration_value_string (coreAPI->cfg, "PATHS",
                                            "GNUNETD_HOME", "/tmp",
                                            &gnunet_path);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "gnunet_path %s\n", gnunet_path);
  debug_file_name =
    GNUNET_malloc (strlen (gnunet_path) + strlen ("table.log") + 2);
  sprintf (debug_file_name, "%s/%s", gnunet_path, "table.log");
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "table log file is %s\n", debug_file_name);
  debug_file = fopen (debug_file_name, "w");
  if (debug_file == NULL)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "unable to create/open file `%s', errno is %s\n",
                     debug_file_name, strerror (errno));
      return GNUNET_SYSERR;
    }
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "My bit location:\n");
  printPeerBits (coreAPI->my_identity);
#endif
  /* use less than 50% of peer's ideal number of
     connections for DV_DHT table size */
  i = coreAPI->core_slots_count () / MAINTAIN_BUCKET_SIZE / 2;
  i = sizeof (GNUNET_HashCode) * 8;
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_INFO | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "core_slots_count returns %d, using %d buckets for DHT\n",
                 coreAPI->core_slots_count (), i);

  GNUNET_array_grow (buckets, bucketCount, i);
  for (i = 0; i < bucketCount; i++)
    {
      buckets[i].bstart = 512 * i / bucketCount;
      buckets[i].bend = 512 * (i + 1) / bucketCount;
    }
  lock = capi->global_lock_get ();
  stats = capi->service_request ("stats");
  dvapi = capi->service_request ("dv");
  GNUNET_GE_ASSERT (coreAPI->ectx, dvapi != NULL);
  if (stats != NULL)
    {
      stat_dht_total_peers =
        stats->create (gettext_noop ("# dv_dht connections"));
      stat_dht_discoveries =
        stats->create (gettext_noop ("# dv_dht discovery messages received"));
      stat_dht_route_looks =
        stats->
        create (gettext_noop ("# dv_dht route host lookups performed"));
      stat_dht_advertisements =
        stats->create (gettext_noop ("# dv_dht discovery messages sent"));
    }
  identity = coreAPI->service_request ("identity");
  GNUNET_GE_ASSERT (coreAPI->ectx, identity != NULL);
  pingpong = coreAPI->service_request ("pingpong");
  GNUNET_GE_ASSERT (coreAPI->ectx, pingpong != NULL);
#if DISCOVERY
  capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_DHT_DISCOVERY,
                                         &handleDiscovery);
#endif
  capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_DHT_ASK_HELLO,
                                         &handleAskHello);
  capi->peer_disconnect_notification_register (&peer_disconnect_handler,
                                               NULL);
  GNUNET_cron_add_job (coreAPI->cron, &maintain_dht_job, MAINTAIN_FREQUENCY,
                       MAINTAIN_FREQUENCY, NULL);

  return GNUNET_OK;
}

/**
 * Shutdown table DV_DHT component.
 *
 * @return GNUNET_OK on success
 */
int
GNUNET_DV_DHT_table_done ()
{
  unsigned int i;
  unsigned int j;

  coreAPI->peer_disconnect_notification_unregister (&peer_disconnect_handler,
                                                    NULL);
#if DISCOVERY
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_DHT_DISCOVERY,
                                              &handleDiscovery);
#endif
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_DHT_ASK_HELLO,
                                              &handleAskHello);
  GNUNET_cron_del_job (coreAPI->cron, &maintain_dht_job, MAINTAIN_FREQUENCY,
                       NULL);
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }
  if (dvapi != NULL)
    {
      coreAPI->service_release (dvapi);
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
