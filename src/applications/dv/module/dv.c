/*
  This file is part of GNUnet.
  (C) 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file applications/dv/module/dv.c
 * @author Nathan Evans
 * @author Christian Grothoff
 * @brief Core of distance vector routing algorithm.  Loads the service,
 * initializes necessary routing tables, and schedules updates, etc.
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_dv_service.h"
#include "gnunet_stats_service.h"
#include "dv.h"

/**
 * Should DV support hiding a fraction of our directly connected
 * peers?  This is good for better anonymity (network harder to
 * analyze for attackers), but likely not so good for testing DV...
 */
#define SUPPORT_HIDING GNUNET_YES

#define DEBUG_DV GNUNET_NO

/**
 * Enable checks that in theory should not fail but we know to 
 * fail but are harmless (and warning would confuse users).
 */ 
#define STRICT GNUNET_NO

/**
 * How often do we check about sending out more peer information (if
 * we are connected to no peers previously).
 */
#define GNUNET_DV_DEFAULT_SEND_INTERVAL (500 * GNUNET_CRON_MILLISECONDS)

/**
 * How long do we wait at most between sending out information?
 */
#define GNUNET_DV_MAX_SEND_INTERVAL (5000 * GNUNET_CRON_MILLISECONDS)

/**
 * How long can we have not heard from a peer and
 * still have it in our tables?
 */
#define GNUNET_DV_PEER_EXPIRATION_TIME (3000 * GNUNET_CRON_SECONDS)

/**
 * Priority for gossip.
 */
#define GNUNET_DV_DHT_GOSSIP_PRIORITY (GNUNET_EXTREME_PRIORITY / 10)

/**
 * How often should we check if expiration time has elapsed for
 * some peer?
 */
#define GNUNET_DV_MAINTAIN_FREQUENCY (5 * GNUNET_CRON_SECONDS)

/**
 * How long to allow a message to be delayed?
 */
#define DV_DELAY (5000 * GNUNET_CRON_MILLISECONDS)

/**
 * Priority to use for DV data messages.
 */
#define DV_PRIORITY 0

/**
 * Statistics service.
 */
static GNUNET_Stats_ServiceAPI *stats;
static int stat_dv_total_peers;
static int stat_dv_sent_messages;
static int stat_dv_actual_sent_messages;
static int stat_dv_received_messages;
static int stat_dv_forwarded_messages;
static int stat_dv_failed_forwards;
static int stat_dv_sent_gossips;
static int stat_dv_received_gossips;
static int stat_dv_unknown_peer;


/**
 * Struct where neighbor information is stored.
 */
struct DistantNeighbor *referees;

/**
 * Struct where actual neighbor information is stored,
 * referenced by min_heap and max_heap.  Freeing dealt
 * with when items removed from hashmap.
 */
struct DirectNeighbor
{
  /**
   * Identity of neighbor.
   */
  GNUNET_PeerIdentity identity;

  /**
   * Head of DLL of nodes that this direct neighbor referred to us.
   */
  struct DistantNeighbor *referee_head;

  /**
   * Tail of DLL of nodes that this direct neighbor referred to us.
   */
  struct DistantNeighbor *referee_tail;

  /**
   * Is this one of the direct neighbors that we are "hiding"
   * from DV?
   */
  int hidden;
};


/**
 * Struct where actual neighbor information is stored,
 * referenced by min_heap and max_heap.  Freeing dealt
 * with when items removed from hashmap.
 */
struct DistantNeighbor
{
  /**
   * We keep distant neighbor's of the same referrer in a DLL.
   */
  struct DistantNeighbor *next;

  /**
   * We keep distant neighbor's of the same referrer in a DLL.
   */
  struct DistantNeighbor *prev;

  /**
   * Node in min heap
   */
  struct GNUNET_CONTAINER_HeapNode *min_loc;

  /**
   * Node in max heap
   */
  struct GNUNET_CONTAINER_HeapNode *max_loc;

  /**
   * Identity of referrer (next hop towards 'neighbor').
   */
  struct DirectNeighbor *referrer;

  /**
   * Identity of neighbor.
   */
  GNUNET_PeerIdentity identity;

  /**
   * Last time we received routing information from this peer
   */
  GNUNET_CronTime last_activity;

  /**
   * Cost to neighbor, used for actual distance vector computations
   */
  unsigned int cost;

  /**
   * Random identifier *we* use for this peer, to be used as shortcut
   * instead of sending full peer id for each message
   */
  unsigned int our_id;

  /**
   * Random identifier the *referrer* uses for this peer.
   */
  unsigned int referrer_id;

  /**
   * Is this one of the direct neighbors that we are "hiding"
   * from DV?
   */
  int hidden;
};


/**
 * Global construct
 */
struct GNUNET_DV_Context
{
  struct GNUNET_Mutex *dvMutex;

  /**
   * Map of PeerIdentifiers to 'struct GNUNET_dv_neighbor*'s for all
   * directly connected peers.
   */
  struct GNUNET_MultiHashMap *direct_neighbors;

  /**
   * Map of PeerIdentifiers to 'struct GNUNET_dv_neighbor*'s for
   * peers connected via DV (extended neighborhood).  Does ALSO
   * include any peers that are in 'direct_neighbors'; for those
   * peers, the cost will be zero and the referrer all zeros.
   */
  struct GNUNET_MultiHashMap *extended_neighbors;

  /**
   * We use the min heap (min refers to cost) to prefer
   * gossipping about peers with small costs.
   */
  struct GNUNET_CONTAINER_Heap *neighbor_min_heap;

  /**
   * We use the max heap (max refers to cost) for general
   * iterations over all peers and to remove the most costly
   * connection if we have too many.
   */
  struct GNUNET_CONTAINER_Heap *neighbor_max_heap;

  unsigned long long fisheye_depth;

  unsigned long long max_table_size;

  unsigned int send_interval;

  unsigned int neighbor_id_loc;

  int closing;
};

static char shortID[5];

static struct GNUNET_DV_Context ctx;

static struct GNUNET_ThreadHandle *sendingThread;

static GNUNET_CoreAPIForPlugins *coreAPI;


/**
 * Update the statistics about dv routing
 */
static void
update_stats ()
{
  if (stats == NULL)
    return;
  stats->set (stat_dv_total_peers,
              GNUNET_multi_hash_map_size (ctx.extended_neighbors));
}


/**
 * Free a DistantNeighbor node, including removing it
 * from the referer's list.
 */
static void
distant_neighbor_free (struct DistantNeighbor *referee)
{
  struct DirectNeighbor *referrer;

  referrer = referee->referrer;
  if (referrer != NULL)
    {
      GNUNET_DLL_remove (referrer->referee_head,
                         referrer->referee_tail, referee);
    }
  GNUNET_CONTAINER_heap_remove_node (ctx.neighbor_max_heap, referee->max_loc);
  GNUNET_CONTAINER_heap_remove_node (ctx.neighbor_min_heap, referee->min_loc);
  GNUNET_multi_hash_map_remove_all (ctx.extended_neighbors,
                                    &referee->identity.hashPubKey);
  GNUNET_free (referee);
}


/**
 * A callback for deleting expired nodes from heaps...
 *
 * @param cls unused
 * @param node peer we may delete
 * @param element 'DistantNeighbor' struct of that peer
 * @param cost known communication cost
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
delete_expired_callback (void *cls,
                         struct GNUNET_CONTAINER_HeapNode *node,
                         void *element, GNUNET_CONTAINER_HeapCostType cost)
{
  struct DistantNeighbor *neighbor = element;
  GNUNET_CronTime now;

  if (cost == 0)
    return GNUNET_YES;          /* never delete direct neighbors */
  now = GNUNET_get_time ();
  if (now - neighbor->last_activity > GNUNET_DV_PEER_EXPIRATION_TIME)
    {
      distant_neighbor_free (neighbor);
      /* Stop iteration since we changed 'neighbor_max_heap', which
         breaks invariants of the iterator code (besides,
         expiring one entry per run should be enough)! */
      return GNUNET_NO;
    }
  return GNUNET_YES;
}


/**
 * Cron job to maintain dv routing table.
 */
static void
maintain_dv_job (void *unused)
{
  GNUNET_mutex_lock (ctx.dvMutex);
  GNUNET_CONTAINER_heap_iterate (ctx.neighbor_max_heap,
                                 &delete_expired_callback, NULL);
  GNUNET_mutex_unlock (ctx.dvMutex);
}


/**
 * Checks whether the given peer is known to us.
 *
 * @return GNUNET_YES if known, GNUNET_NO if not
 */
static int
GNUNET_DV_have_peer (const GNUNET_PeerIdentity * peer)
{
  int ret;

  GNUNET_mutex_lock (ctx.dvMutex);
  ret = GNUNET_multi_hash_map_contains (ctx.extended_neighbors,
                                        &peer->hashPubKey);
  GNUNET_mutex_unlock (ctx.dvMutex);
  return ret;
}


struct IteratePeersWrapper
{
  GNUNET_NodeIteratorCallback method;
  void *arg;
  int cnt;
};


/**
 * A callback for iterating over all known nodes.
 */
static int
connection_iterate_callback (void *cls,
                             struct GNUNET_CONTAINER_HeapNode *node,
                             void *element,
                             GNUNET_CONTAINER_HeapCostType cost)
{
  struct IteratePeersWrapper *wrap = cls;
  struct DistantNeighbor *neighbor = element;

  wrap->method (&neighbor->identity, wrap->arg);
  wrap->cnt++;
  return GNUNET_OK;
}


/**
 * Calls a given method for each dv connected host.
 *
 * @param method method to call for each connected peer
 * @param arg second argument to method
 * @return number of connected nodes
 */
static int
GNUNET_DV_connection_iterate_peers (GNUNET_NodeIteratorCallback method,
                                    void *arg)
{
  struct IteratePeersWrapper wrap;

  wrap.method = method;
  wrap.arg = arg;
  wrap.cnt = 0;
  GNUNET_mutex_lock (ctx.dvMutex);
  GNUNET_CONTAINER_heap_iterate (ctx.neighbor_max_heap,
                                 &connection_iterate_callback, &wrap);
  GNUNET_mutex_unlock (ctx.dvMutex);
  return wrap.cnt;
}


/**
 * Low level sending of a DV message
 */
static int
send_message (const GNUNET_PeerIdentity * recipient,
              const GNUNET_PeerIdentity * sender,
              const GNUNET_MessageHeader * message,
              unsigned int importance, unsigned int maxdelay)
{
  p2p_dv_MESSAGE_Data *toSend;
  unsigned int msg_size;
  unsigned int cost;
  unsigned int recipient_id;
  unsigned int sender_id;
  struct DistantNeighbor *target;
  struct DistantNeighbor *source;

  msg_size = ntohs (message->size) + sizeof (p2p_dv_MESSAGE_Data);
  if (msg_size > GNUNET_MAX_BUFFER_SIZE - 8)
    return GNUNET_SYSERR;

  GNUNET_mutex_lock (ctx.dvMutex);
  target = GNUNET_multi_hash_map_get (ctx.extended_neighbors,
                                      &recipient->hashPubKey);
  if (target == NULL)
    {
      /* target unknown to us, drop! */
      GNUNET_mutex_unlock (ctx.dvMutex);
      return GNUNET_SYSERR;
    }
  recipient_id = target->referrer_id;

  source = GNUNET_multi_hash_map_get (ctx.extended_neighbors,
                                      &sender->hashPubKey);
  if (source == NULL)
    {
      if (0 != (memcmp (coreAPI->my_identity,
                        sender, sizeof (GNUNET_PeerIdentity))))
        {
          /* sender unknown to us, drop! */
          GNUNET_mutex_unlock (ctx.dvMutex);
          return GNUNET_SYSERR;
        }
      sender_id = 0;            /* 0 == us */
    }
  else
    {
      /* find out the number that we use when we gossip about
         the sender */
      sender_id = source->our_id;
    }

  cost = target->cost;
  toSend = GNUNET_malloc (msg_size);
  toSend->header.size = htons (msg_size);
  toSend->header.type = htons (GNUNET_P2P_PROTO_DV_DATA_MESSAGE);
  toSend->sender = htonl (sender_id);
  toSend->recipient = htonl (recipient_id);
  memcpy (&toSend[1], message, ntohs (message->size));
  coreAPI->ciphertext_send (&target->referrer->identity,
                            &toSend->header, importance, maxdelay);
  if (stats != NULL)
    stats->change (stat_dv_actual_sent_messages, 1);
  GNUNET_free (toSend);
  GNUNET_mutex_unlock (ctx.dvMutex);
  return (int) cost;
}


struct FindDestinationContext
{
  unsigned int tid;
  struct DistantNeighbor *dest;
};


/**
 * We've been given a target ID based on the random numbers that
 * we assigned to our DV-neighborhood.  Find the entry for the
 * respective neighbor.
 */
static int
find_destination (void *cls,
                  struct GNUNET_CONTAINER_HeapNode *node,
                  void *element, GNUNET_CONTAINER_HeapCostType cost)
{
  struct FindDestinationContext *fdc = cls;
  struct DistantNeighbor *dn = element;

  if (fdc->tid != dn->our_id)
    return GNUNET_YES;
  fdc->dest = dn;
  return GNUNET_NO;
}


/**
 * Handle a DATA message receipt, if recipient matches our identity
 * message is for this peer, otherwise check if we know of the
 * intended recipient and send onwards
 */
static int
p2pHandleDVDataMessage (const GNUNET_PeerIdentity * sender,
                        const GNUNET_MessageHeader * message)
{
  const p2p_dv_MESSAGE_Data *incoming = (const p2p_dv_MESSAGE_Data *) message;
  const GNUNET_MessageHeader *packed_message
    = (const GNUNET_MessageHeader *) &incoming[1];
  struct DirectNeighbor *dn;
  struct DistantNeighbor *pos;
  unsigned int sid;             /* Sender id */
  unsigned int tid;             /* Target id */
  GNUNET_PeerIdentity original_sender;
  GNUNET_PeerIdentity destination;
  struct FindDestinationContext fdc;
  int ret;

  if ((ntohs (incoming->header.size) <
       sizeof (p2p_dv_MESSAGE_Data) + sizeof (GNUNET_MessageHeader))
      || (ntohs (incoming->header.size) !=
          (sizeof (p2p_dv_MESSAGE_Data) + ntohs (packed_message->size))))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_dv_received_messages, 1);

  GNUNET_mutex_lock (ctx.dvMutex);
  dn = GNUNET_multi_hash_map_get (ctx.direct_neighbors,
                                  &sender->hashPubKey);
  if (dn == NULL)
    {
#if STRICT
      GNUNET_GE_BREAK (NULL, 0);
#endif
      GNUNET_mutex_unlock (ctx.dvMutex);
      return GNUNET_OK;
    }
  sid = ntohl (incoming->sender);
  pos = dn->referee_head;
  while ((NULL != pos) && (pos->referrer_id != sid))
    pos = pos->next;
  if (pos == NULL)
    {
      /* unknown sender */
      GNUNET_mutex_unlock (ctx.dvMutex);
      if (stats != NULL)
        stats->change (stat_dv_unknown_peer, 1);
      return GNUNET_OK;
    }
  original_sender = pos->identity;
  tid = ntohl (incoming->recipient);
  if (tid == 0)
    {
      /* 0 == us */
      GNUNET_mutex_unlock (ctx.dvMutex);
      GNUNET_GE_BREAK (NULL, ntohs (packed_message->type) != GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);
      GNUNET_GE_BREAK (NULL, ntohs (packed_message->type) != GNUNET_P2P_PROTO_DV_DATA_MESSAGE);
      if ( (ntohs (packed_message->type) != GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE) &&
	   (ntohs (packed_message->type) != GNUNET_P2P_PROTO_DV_DATA_MESSAGE) )
	coreAPI->loopback_send (&original_sender,
				(const char *) packed_message,
				ntohs (packed_message->size), GNUNET_YES, NULL);
      return GNUNET_OK;
    }

  /* FIXME: this is the *only* per-request operation we have in DV
     that is O(n) in relation to the number of connected peers; a
     hash-table lookup could easily solve this (minor performance
     issue) */
  fdc.tid = tid;
  fdc.dest = NULL;
  GNUNET_CONTAINER_heap_iterate (ctx.neighbor_max_heap,
                                 &find_destination, &fdc);
  if (fdc.dest == NULL)
    {
      if (stats != NULL)
        stats->change (stat_dv_failed_forwards, 1);
      GNUNET_mutex_unlock (ctx.dvMutex);
      return GNUNET_OK;
    }
  destination = fdc.dest->identity;
  GNUNET_mutex_unlock (ctx.dvMutex);
  if (0 == memcmp (&destination, sender, sizeof (GNUNET_PeerIdentity)))
    {
      /* FIXME: create stat: routing loop-discard! */
      return GNUNET_OK;
    }
  ret = send_message (&destination,
                      &original_sender,
                      packed_message, DV_PRIORITY, DV_DELAY);
  if (stats != NULL)
    {
      if (ret != GNUNET_SYSERR)
        stats->change (stat_dv_forwarded_messages, 1);
      else
        stats->change (stat_dv_failed_forwards, 1);
    }
  return GNUNET_OK;
}


/**
 * Build and send a fresh message from this peer to a peer in the
 * fisheye neighborhood.  Returns GNUNET_OK provided all goes well,
 * GNUNET_NO if recipient is not in the neighborhood, and
 * GNUNET_SYSERR if some other problem happens
 *
 * @param recipient for which peer is this message intended
 * @param message message being sent
 * @return cost of sent message, GNUNET_SYSERR on error
 */
int
GNUNET_DV_send_message (const GNUNET_PeerIdentity * recipient,
                        const GNUNET_MessageHeader * message,
                        unsigned int importance, unsigned int maxdelay)
{
  if (stats != NULL)
    stats->change (stat_dv_sent_messages, 1);
  return send_message (recipient, coreAPI->my_identity, message, importance,
                       maxdelay);
}


/**
 * For core, Query how much bandwidth is availabe FROM the given
 * node to this node in bpm (at the moment).  For DV, currently
 * only returns GNUNET_OK if node is known in DV tables.  Should
 * be obsoleted by DV/transports/Core integration.  Necessary
 * now because DHT uses this call to check if peer is known
 * before adding to DHT routing tables.
 *
 * @param bpm set to the bandwidth
 * @param last_seen set to last time peer was confirmed up
 * @return GNUNET_OK on success, GNUNET_SYSERR if if we are NOT connected
 */
int
GNUNET_DV_connection_get_bandwidth_assigned_to_peer (const
                                                     GNUNET_PeerIdentity *
                                                     node,
                                                     unsigned int *bpm,
                                                     GNUNET_CronTime *
                                                     last_seen)
{
  struct DistantNeighbor *dn;
  unsigned int ret;

  ret = GNUNET_SYSERR;
  GNUNET_mutex_lock (ctx.dvMutex);
  dn = GNUNET_multi_hash_map_get (ctx.extended_neighbors, &node->hashPubKey);
  if (dn != NULL)
    {
      ret = GNUNET_OK;
      if (bpm != NULL)
        {
          coreAPI->p2p_connection_status_check (&dn->referrer->identity,
                                                bpm, last_seen);
        }
      if ((dn->cost > 0) && (last_seen != NULL))
        *last_seen = dn->last_activity;
    }
  GNUNET_mutex_unlock (ctx.dvMutex);
  return ret;
}


/**
 * Handles when a peer is either added due to being newly connected
 * or having been gossiped about, also called when a cost for a neighbor
 * needs to be updated.
 *
 * @param peer identity of the peer whose info is being added/updated
 * @param peer_id id to use when sending to 'peer'
 * @param referrer if this is a gossiped peer, who did we hear it from?
 * @param cost the cost of communicating with this peer via 'referrer'
 */
static void
addUpdateNeighbor (const GNUNET_PeerIdentity * peer,
                   unsigned int referrer_peer_id,
                   struct DirectNeighbor *referrer, unsigned int cost)
{
  struct DistantNeighbor *neighbor;
  struct DistantNeighbor *max;
  GNUNET_CronTime now;
  unsigned int our_id;

  now = GNUNET_get_time ();
  our_id = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, RAND_MAX - 1) + 1;
  GNUNET_mutex_lock (ctx.dvMutex);
  neighbor = GNUNET_multi_hash_map_get (ctx.extended_neighbors,
                                        &peer->hashPubKey);
  if (neighbor == NULL)
    {
      /* new neighbor! */
      if (cost > ctx.fisheye_depth)
        {
          /* too costly */
          GNUNET_mutex_unlock (ctx.dvMutex);
          return;
        }
      if (ctx.max_table_size <=
          GNUNET_multi_hash_map_size (ctx.extended_neighbors))
        {
          /* remove most expensive entry */
          max = GNUNET_CONTAINER_heap_peek (ctx.neighbor_max_heap);
          if (cost > max->cost)
            {
              /* new entry most expensive, don't create */
              GNUNET_mutex_unlock (ctx.dvMutex);
              return;
            }
          if (max->cost > 0)
            {
              /* only free if this is not a direct connection;
                 we could theoretically have more direct
                 connections than DV entries allowed total! */
              distant_neighbor_free (max);
            }
        }

      neighbor = GNUNET_malloc (sizeof (struct DistantNeighbor));
      GNUNET_DLL_insert (referrer->referee_head,
                         referrer->referee_tail, neighbor);
      neighbor->max_loc = GNUNET_CONTAINER_heap_insert (ctx.neighbor_max_heap,
                                                        neighbor, cost);
      neighbor->min_loc = GNUNET_CONTAINER_heap_insert (ctx.neighbor_min_heap,
                                                        neighbor, cost);
      neighbor->referrer = referrer;
      memcpy (&neighbor->identity, peer, sizeof (GNUNET_PeerIdentity));
      neighbor->last_activity = now;
      neighbor->cost = cost;
      neighbor->referrer_id = referrer_peer_id;
      neighbor->our_id = our_id;
      neighbor->hidden =
        (cost == 0) ? (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 4) ==
                       0) : GNUNET_NO;
      GNUNET_multi_hash_map_put (ctx.extended_neighbors, &peer->hashPubKey,
                                 neighbor,
                                 GNUNET_MultiHashMapOption_UNIQUE_ONLY);
      if (stats != NULL)
        stats->change (stat_dv_total_peers, 1);
      GNUNET_mutex_unlock (ctx.dvMutex);
      return;
    }

  /* update existing entry! */
  if (neighbor->referrer == referrer)
    {
      /* same referrer, cost change! */
      GNUNET_CONTAINER_heap_update_cost (ctx.neighbor_max_heap,
                                         neighbor->max_loc, cost);
      GNUNET_CONTAINER_heap_update_cost (ctx.neighbor_min_heap,
                                         neighbor->min_loc, cost);
      neighbor->last_activity = now;
      neighbor->cost = cost;
      GNUNET_mutex_unlock (ctx.dvMutex);
      return;
    }

  if (neighbor->cost <= cost)
    {
      /* more costly than existing alternative */
      GNUNET_mutex_unlock (ctx.dvMutex);
      return;
    }

  /* better path! */
  GNUNET_DLL_remove (neighbor->referrer->referee_head,
                     neighbor->referrer->referee_tail, neighbor);
  neighbor->referrer = referrer;
  GNUNET_DLL_insert (referrer->referee_head,
                     referrer->referee_tail, neighbor);
  GNUNET_CONTAINER_heap_update_cost (ctx.neighbor_max_heap,
                                     neighbor->max_loc, cost);
  GNUNET_CONTAINER_heap_update_cost (ctx.neighbor_min_heap,
                                     neighbor->min_loc, cost);
  neighbor->referrer_id = referrer_peer_id;
  neighbor->last_activity = now;
  neighbor->cost = cost;
  GNUNET_mutex_unlock (ctx.dvMutex);
}


/**
 * Handles a gossip message from another peer.  Basically
 * just check the message size, cast to the correct type
 * and call addUpdateNeighbor to do the real work.
 */
static int
p2pHandleDVNeighborMessage (const GNUNET_PeerIdentity * sender,
                            const GNUNET_MessageHeader * message)
{
  const p2p_dv_MESSAGE_NeighborInfo *nmsg;
  struct DirectNeighbor *neighbor;

  if (ntohs (message->size) < sizeof (p2p_dv_MESSAGE_NeighborInfo))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;     /* invalid message */
    }
  nmsg = (const p2p_dv_MESSAGE_NeighborInfo *) message;
  if (stats != NULL)
    stats->change (stat_dv_received_gossips, 1);
  neighbor = GNUNET_multi_hash_map_get (ctx.direct_neighbors,
                                        &sender->hashPubKey);
#if STRICT
  GNUNET_GE_BREAK (NULL, neighbor != NULL);
#endif
  if (neighbor == NULL)
    return GNUNET_OK;
  addUpdateNeighbor (&nmsg->neighbor,
                     ntohl (nmsg->neighbor_id),
                     neighbor, ntohl (nmsg->cost) + 1);

  return GNUNET_OK;
}


/**
 * Handles a peer connect notification, indicating a peer should
 * be added to the direct neighbor table.
 *
 * @param peer identity of the connected peer
 * @param unused unused closure arg
 */
static void
peer_connect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
  struct DirectNeighbor *neighbor;

  GNUNET_mutex_lock (ctx.dvMutex);
  neighbor = GNUNET_malloc (sizeof (struct DirectNeighbor));
  memcpy (&neighbor->identity, peer, sizeof (GNUNET_PeerIdentity));
  GNUNET_multi_hash_map_put (ctx.direct_neighbors,
                             &peer->hashPubKey,
                             neighbor, GNUNET_MultiHashMapOption_UNIQUE_ONLY);
  GNUNET_mutex_unlock (ctx.dvMutex);
  addUpdateNeighbor (peer, 0, neighbor, 0);
}


/**
 * Handles the receipt of a peer disconnect notification, removing
 * the direct neighbor from the direct list and any referenced
 * neighbors as well.
 *
 * @param peer the peer that has disconnected from us
 */
static void
peer_disconnect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
  struct DirectNeighbor *neighbor;
  struct DistantNeighbor *referee;

  GNUNET_mutex_lock (ctx.dvMutex);
  neighbor =
    GNUNET_multi_hash_map_get (ctx.direct_neighbors, &peer->hashPubKey);
  if (neighbor == NULL)
    {
      GNUNET_mutex_unlock (ctx.dvMutex);
      return;
    }
  while (NULL != (referee = neighbor->referee_head))
    distant_neighbor_free (referee);
  GNUNET_GE_ASSERT (NULL, neighbor->referee_tail == NULL);
  GNUNET_multi_hash_map_remove (ctx.direct_neighbors,
                                &peer->hashPubKey, neighbor);
  GNUNET_free (neighbor);
  GNUNET_mutex_unlock (ctx.dvMutex);
  update_stats ();
}



/**
 * Method which changes how often peer sends neighbor information to
 * other peers.  Basically, if we know how many peers we have and want
 * to gossip all of them to all of our direct neighbors we will need
 * to send them such that they will all reach their destinations
 * within the timeout frequency.  We assume all peers share our
 * timeout frequency so it's a simple calculation.  May need
 * revisiting if we want to specify a maximum or minimum value for
 * this interval.
 */
static void
updateSendInterval ()
{
  unsigned int direct_neighbors;
  unsigned int total_neighbors;
  unsigned int total_messages;

  direct_neighbors = GNUNET_multi_hash_map_size (ctx.direct_neighbors);
  total_neighbors = GNUNET_multi_hash_map_size (ctx.extended_neighbors);
  if (direct_neighbors == 0)
    {
      ctx.send_interval = GNUNET_DV_DEFAULT_SEND_INTERVAL;
      return;
    }
  total_messages = direct_neighbors * total_neighbors;
  ctx.send_interval =
    (unsigned int) ((GNUNET_DV_PEER_EXPIRATION_TIME / total_messages) / 2);
  if (ctx.send_interval > GNUNET_DV_MAX_SEND_INTERVAL)
    ctx.send_interval = GNUNET_DV_MAX_SEND_INTERVAL;
}


/**
 * Thread which chooses a peer to gossip about and a peer to gossip
 * to, then constructs the message and sends it out.  Will run until
 * done_module_dv is called.
 */
static void *
neighbor_send_thread (void *rcls)
{
#if DEBUG_DV
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s: Entering neighbor_send_thread...\n",
                 &shortID);
  GNUNET_EncName encPeerAbout;
  GNUNET_EncName encPeerTo;
#endif
  struct DistantNeighbor *about;
  struct DirectNeighbor *to;
  unsigned int count;
  p2p_dv_MESSAGE_NeighborInfo message;

  message.header.size = htons (sizeof (p2p_dv_MESSAGE_NeighborInfo));
  message.header.type = htons (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);
  count = 0;
  while (!ctx.closing)
    {
      GNUNET_thread_sleep (ctx.send_interval);
      if (ctx.closing)
        break;
      if (0 == (count++ % 20))
        updateSendInterval ();

      GNUNET_mutex_lock (ctx.dvMutex);
      about = GNUNET_CONTAINER_heap_walk_get_next (ctx.neighbor_min_heap);
      to = GNUNET_multi_hash_map_get_random (ctx.direct_neighbors);

      if ((about != NULL) && (to != about->referrer /* split horizon */ ) &&
#if SUPPORT_HIDING
          (about->hidden == GNUNET_NO) &&
#endif
          (to != NULL) &&
          (0 != memcmp (&about->identity,
                        &to->identity, sizeof (GNUNET_PeerIdentity))))
        {
#if DEBUG_DV
          GNUNET_hash_to_enc (&about->neighbor->hashPubKey, &encPeerAbout);
          GNUNET_hash_to_enc (&to->neighbor->hashPubKey, &encPeerTo);
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
                         | GNUNET_GE_BULK,
                         "%s: Sending info about peer %s to directly connected peer %s\n",
                         &shortID,
                         (char *) &encPeerAbout, (char *) &encPeerTo);
#endif
          message.cost = htonl (about->cost);
          message.neighbor_id = htonl (about->our_id);
          memcpy (&message.neighbor,
                  &about->identity, sizeof (GNUNET_PeerIdentity));
          coreAPI->ciphertext_send (&to->identity, &message.header,
                                    GNUNET_DV_DHT_GOSSIP_PRIORITY,
                                    ctx.send_interval);
          if (stats != NULL)
            stats->change (stat_dv_sent_gossips, 1);
        }
      GNUNET_mutex_unlock (ctx.dvMutex);
    }
  return NULL;
}

/**
 * Initializes and provides the fisheye DV service
 *
 * @param capi the core API
 * @return NULL on errors, DV_API otherwise
 */
GNUNET_DV_ServiceAPI *
provide_module_dv (GNUNET_CoreAPIForPlugins * capi)
{
  unsigned long long max_hosts;
  GNUNET_EncName encMe;
  static GNUNET_DV_ServiceAPI api;

  api.dv_send = &GNUNET_DV_send_message;
  api.dv_connections_iterate = &GNUNET_DV_connection_iterate_peers;
  api.p2p_connection_status_check =
    &GNUNET_DV_connection_get_bandwidth_assigned_to_peer;
  api.have_peer = &GNUNET_DV_have_peer;

  stats = capi->service_request ("stats");
  if (stats != NULL)
    {
      stat_dv_total_peers = stats->create (gettext_noop ("# dv connections"));
      stat_dv_sent_messages =
        stats->create (gettext_noop ("# dv messages sent"));
      stat_dv_actual_sent_messages =
        stats->create (gettext_noop ("# dv actual messages sent"));
      stat_dv_received_messages =
        stats->create (gettext_noop ("# dv messages received"));
      stat_dv_forwarded_messages =
        stats->create (gettext_noop ("# dv messages forwarded"));
      stat_dv_failed_forwards =
        stats->create (gettext_noop ("# dv forwards failed"));
      stat_dv_received_gossips =
        stats->create (gettext_noop ("# dv gossips received"));
      stat_dv_sent_gossips =
        stats->create (gettext_noop ("# dv gossips sent"));
      stat_dv_unknown_peer =
        stats->create (gettext_noop ("# dv messages of unknown peers"));
    }
  memset (&ctx, 0, sizeof (ctx));
  ctx.neighbor_min_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  ctx.neighbor_max_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);
  ctx.send_interval = GNUNET_DV_DEFAULT_SEND_INTERVAL;
  ctx.dvMutex = capi->global_lock_get ();

  coreAPI = capi;
  GNUNET_hash_to_enc (&coreAPI->my_identity->hashPubKey, &encMe);
  strncpy ((char *) &shortID, (char *) &encMe, 4);
  shortID[4] = '\0';
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_INFO | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 _("%s: `%s' registering P2P handlers %d %d\n"),
                 "dv", &shortID,
                 GNUNET_P2P_PROTO_DV_DATA_MESSAGE,
                 GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);


  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DV",
                                            "FISHEYEDEPTH",
                                            0, -1, 3, &ctx.fisheye_depth);

  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DV",
                                            "TABLESIZE",
                                            0, -1, 100, &ctx.max_table_size);
  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "gnunetd", "connection-max-hosts",
                                            1, -1, 50, &max_hosts);

  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "dv",
                                                                   _
                                                                   ("enables distance vector routing")));

  ctx.direct_neighbors = GNUNET_multi_hash_map_create (max_hosts);
  ctx.extended_neighbors =
    GNUNET_multi_hash_map_create (ctx.max_table_size * 3);
  coreAPI->peer_disconnect_notification_register
    (&peer_disconnect_handler, NULL);
  coreAPI->peer_connect_notification_register (&peer_connect_handler, NULL);
  coreAPI->p2p_ciphertext_handler_register
    (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE, &p2pHandleDVNeighborMessage);
  coreAPI->p2p_ciphertext_handler_register
    (GNUNET_P2P_PROTO_DV_DATA_MESSAGE, &p2pHandleDVDataMessage);
  sendingThread =
    GNUNET_thread_create (&neighbor_send_thread, &coreAPI, 1024 * 1);
  GNUNET_cron_add_job (coreAPI->cron, &maintain_dv_job,
                       GNUNET_DV_MAINTAIN_FREQUENCY,
                       GNUNET_DV_MAINTAIN_FREQUENCY, NULL);
  return &api;
}


/**
 * Deletes a distant neighbor from the max and min heaps and from the
 * extended neighbor hash map.
 */
static int
distant_neighbor_free_iterator (const GNUNET_HashCode * key,
                                void *value, void *cls)
{

  struct DistantNeighbor *neighbor = value;
  distant_neighbor_free (neighbor);
  return GNUNET_YES;
}


/**
 * Deletes a direct neighbor from the min heap and from the
 * direct neighbor hash map.
 */
static int
direct_neighbor_free_iterator (const GNUNET_HashCode * key,
                               void *value, void *cls)
{
  struct DirectNeighbor *neighbor = value;

  GNUNET_GE_ASSERT (NULL, neighbor->referee_head == NULL);
  GNUNET_GE_ASSERT (NULL, neighbor->referee_tail == NULL);
  GNUNET_multi_hash_map_remove (ctx.direct_neighbors, key, value);
  GNUNET_free (neighbor);
  return GNUNET_NO;
}


/**
 * Shuts down and cleans up the DV module
 */
void
release_module_dv ()
{
  void *unused;

  ctx.closing = 1;
  GNUNET_thread_stop_sleep (sendingThread);
  GNUNET_thread_join (sendingThread, &unused);

  coreAPI->p2p_ciphertext_handler_unregister
    (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE, &p2pHandleDVNeighborMessage);
  coreAPI->p2p_ciphertext_handler_unregister
    (GNUNET_P2P_PROTO_DV_DATA_MESSAGE, &p2pHandleDVDataMessage);
  coreAPI->peer_disconnect_notification_unregister (&peer_disconnect_handler,
                                                    NULL);
  coreAPI->peer_connect_notification_unregister (&peer_connect_handler, NULL);
  update_stats ();
  GNUNET_cron_del_job (coreAPI->cron, &maintain_dv_job,
                       GNUNET_DV_MAINTAIN_FREQUENCY, NULL);
  GNUNET_multi_hash_map_iterate (ctx.extended_neighbors,
                                 &distant_neighbor_free_iterator, NULL);
  while (0 !=
         GNUNET_multi_hash_map_iterate (ctx.direct_neighbors,
                                        &direct_neighbor_free_iterator,
                                        NULL));
  GNUNET_multi_hash_map_destroy (ctx.extended_neighbors);
  GNUNET_multi_hash_map_destroy (ctx.direct_neighbors);
  GNUNET_CONTAINER_heap_destroy (ctx.neighbor_max_heap);
  GNUNET_CONTAINER_heap_destroy (ctx.neighbor_min_heap);
  coreAPI->service_release (stats);
  stats = NULL;
  coreAPI = NULL;
}

/* end of dv.c */
