/*
 This file is part of GNUnet.
 (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @author Nathan Evans
 * @file applications/dv/module/dv.c
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

#define DEBUG_DV_MAINTAIN GNUNET_NO
#define DEBUG_DV GNUNET_NO
#define DEBUG_DV_FORWARD GNUNET_NO
#define DEBUG_PEERS GNUNET_NO
/* How long to allow a message to be delayed */
#define DV_DELAY (5000 * GNUNET_CRON_MILLISECONDS)
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

/*
 * Struct to map neighbor_id to GNUNET_PeerIdentity
 */

struct NeighborID
{
  unsigned int neighbor_id;
  GNUNET_PeerIdentity identity;
};

/*
 * Global construct
 */
struct GNUNET_DV_Context
{
  struct GNUNET_Mutex *dvMutex;
  struct GNUNET_MultiHashMap *direct_neighbors;

  struct GNUNET_MultiHashMap *extended_neighbors;
  struct GNUNET_CONTAINER_Heap *neighbor_min_heap;
  struct GNUNET_CONTAINER_Heap *neighbor_max_heap;
  struct NeighborID *neighbor_id_array;
  unsigned long long fisheye_depth;
  unsigned long long max_table_size;
  unsigned int send_interval;
  unsigned int neighbor_id_loc;
  unsigned short closing;
};

struct callbackWrapper
{
  GNUNET_NodeIteratorCallback method;
  void *arg;
};

static char shortID[5];
static struct GNUNET_DV_Context *ctx;
static struct GNUNET_ThreadHandle *sendingThread;
static GNUNET_CoreAPIForPlugins *coreAPI;

#if DEBUG_PEERS
static int
printPeer (const GNUNET_HashCode * key, void *value, void *cls)
{
  GNUNET_EncName enc;
  GNUNET_hash_to_enc (key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "\tPeer: %s", (char *) &enc);
}
#endif

/*
 * Update the statistics about dv routing
 */
static void
update_stats ()
{
  if (stats == NULL)
    return;
  stats->set (stat_dv_total_peers, 
	      GNUNET_multi_hash_map_size (ctx->extended_neighbors));	      
#if DEBUG_PEERS
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s: Known Peers\n", &shortID);
  GNUNET_multi_hash_map_iterate (ctx->extended_neighbors, &printPeer, NULL);

#endif
}

/*
 * Deletes a neighbor from the max and min heaps and
 * from the extended neighbor hash map.  Does not delete
 * from the directly connected neighbor list, because
 * we like to keep those around.
 */
static int
delete_neighbor (struct GNUNET_dv_neighbor *neighbor)
{
  GNUNET_CONTAINER_heap_remove_node (ctx->neighbor_max_heap, neighbor);
  GNUNET_CONTAINER_heap_remove_node (ctx->neighbor_min_heap, neighbor);
  GNUNET_multi_hash_map_remove_all (ctx->extended_neighbors,
                                    &neighbor->neighbor->hashPubKey);
  GNUNET_free (neighbor->neighbor);
  GNUNET_free_non_null (neighbor->referrer);
  GNUNET_free (neighbor);
  update_stats ();
  return GNUNET_OK;
}

/*
 * A callback for iterating over all known nodes.
 */
static int
connection_iterate_callback (void *element, GNUNET_CostType cost,
                             struct GNUNET_CONTAINER_Heap *root, void *cls)
{
  struct GNUNET_dv_neighbor *neighbor = element;
  struct callbackWrapper *wrap = cls;
  wrap->method (neighbor->neighbor, wrap->arg);
  return GNUNET_OK;
}


/*
 * A callback for deleting expired nodes from heaps...
 *
 * neighbor - the peer we may delete
 * root - the root of the heap
 * cls - unused
 */
static int
delete_expired_callback (void *element, GNUNET_CostType cost,
                         struct GNUNET_CONTAINER_Heap *root, void *cls)
{
  struct GNUNET_dv_neighbor *neighbor = element;
  GNUNET_CronTime now;

  now = GNUNET_get_time ();
  /*
   * Why do we check if it is a direct neighbor? delete_neighbor
   * only deletes from the extended list anyways...
   */
  if ((GNUNET_NO ==
       GNUNET_multi_hash_map_contains (ctx->direct_neighbors,
                                       &neighbor->neighbor->hashPubKey))
      && (now - neighbor->last_activity > GNUNET_DV_PEER_EXPIRATION_TIME))
    {
#if DEBUG_DV_MAINTAIN
      GNUNET_EncName encToDel;
      GNUNET_hash_to_enc (&neighbor->neighbor->hashPubKey, &encToDel);
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "%s: Entering delete_expired_callback, now is %llu, last_activity is %llu\nDifference is %llu, Max is %llu\nNode to remove is %s\n",
                     &shortID, now, neighbor->last_activity,
                     now - neighbor->last_activity,
                     GNUNET_DV_PEER_EXPIRATION_TIME, (char *) &encToDel);
#endif
      delete_neighbor (neighbor);
    }
  return GNUNET_OK;
}

/**
 * Cron job to maintain dv routing table.
 */
static void
maintain_dv_job (void *unused)
{
  GNUNET_mutex_lock (ctx->dvMutex);
  GNUNET_CONTAINER_heap_iterate (ctx->neighbor_max_heap,
                                 &delete_expired_callback, NULL);
  GNUNET_mutex_unlock (ctx->dvMutex);
}

/**
 * Checks whether the given peer is known to us.
 *
 * @return GNUNET_YES if known, GNUNET_NO if not
 */
int
GNUNET_DV_have_peer (const GNUNET_PeerIdentity * peer)
{
  int ret;

  GNUNET_mutex_lock (ctx->dvMutex);
  ret = GNUNET_multi_hash_map_contains (ctx->extended_neighbors,
					&peer->hashPubKey);
  GNUNET_mutex_unlock (ctx->dvMutex);
  return ret;
}

/**
 * Calls a given method for each dv connected host.
 *
 * @param method method to call for each connected peer
 * @param arg second argument to method
 * @return number of connected nodes
 */
int
GNUNET_DV_connection_iterate_peers (GNUNET_NodeIteratorCallback method,
                                    void *arg)
{
  struct callbackWrapper wrap;
  int ret;

  wrap.method = method;
  wrap.arg = arg;
  GNUNET_mutex_lock (ctx->dvMutex);
  ret =
    GNUNET_CONTAINER_heap_iterate (ctx->neighbor_max_heap,
                                   &connection_iterate_callback, &wrap);
  GNUNET_mutex_unlock (ctx->dvMutex);
  return ret;
}


static unsigned int
get_peer_id (const GNUNET_PeerIdentity *peer)
{
  struct GNUNET_dv_neighbor *neighbor;
#if DEBUG_DV_FORWARD
  GNUNET_EncName enc;
  GNUNET_EncName encMe;
#endif

  if (GNUNET_YES ==
      GNUNET_multi_hash_map_contains (ctx->direct_neighbors,
                                      &peer->hashPubKey))    
    return 0;    
  if (GNUNET_YES ==
      GNUNET_multi_hash_map_contains (ctx->extended_neighbors,
				      &peer->hashPubKey))
    {
      neighbor =
        GNUNET_multi_hash_map_get (ctx->extended_neighbors,
                                   &peer->hashPubKey);
      return neighbor->neighbor_id;
    }
#if DEBUG_DV_FORWARD
  GNUNET_hash_to_enc (&coreAPI->my_identity->hashPubKey, &encMe);
  GNUNET_hash_to_enc (&peer->hashPubKey, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
		 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
		 GNUNET_GE_BULK,
		 "%s: I AM:\n%s\nAsked to send message to unknown peer:\n%s\n\n",
		 &shortID, (char *) &encMe, (char *) &enc);
#endif
  if (stats != NULL)
    stats->change (stat_dv_unknown_peer, 1);
  return GNUNET_SYSERR;
}


/*
 * Low level sending of a DV message
 */
static int
send_message (const GNUNET_PeerIdentity * recipient,
              const GNUNET_PeerIdentity * original_sender,
              const GNUNET_MessageHeader * message,
              unsigned int importance, unsigned int maxdelay)
{
  p2p_dv_MESSAGE_Data *toSend;
  unsigned int msg_size;
  unsigned int cost;
  unsigned int recipient_id;
  unsigned int original_sender_id;
  struct GNUNET_dv_neighbor *neighbor;
#if DEBUG_DV_FORWARD
  GNUNET_EncName encVia;
  GNUNET_EncName encRecipient;
  GNUNET_EncName encMe;
  GNUNET_EncName encSender;

  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s: Entered send_message!\n", &shortID);
#endif
  msg_size = ntohs (message->size) + sizeof (p2p_dv_MESSAGE_Data);
  if (msg_size > GNUNET_MAX_BUFFER_SIZE - 8)
    return GNUNET_SYSERR;
  GNUNET_mutex_lock (ctx->dvMutex);

  recipient_id = get_peer_id (recipient);
  original_sender_id = get_peer_id (original_sender);
  if ( (GNUNET_SYSERR == recipient_id) ||
       (GNUNET_SYSERR == original_sender_id) )
    {
      GNUNET_mutex_unlock (ctx->dvMutex);
      return GNUNET_SYSERR;
    }

  neighbor =
    GNUNET_multi_hash_map_get (ctx->extended_neighbors,
			       &recipient->hashPubKey);
  GNUNET_GE_ASSERT (NULL, neighbor != NULL);
  cost = neighbor->cost;
  toSend = GNUNET_malloc (msg_size);
  toSend->header.size = htons (msg_size);
  toSend->header.type = htons (GNUNET_P2P_PROTO_DV_DATA_MESSAGE);
  toSend->sender = htonl (original_sender_id);
  toSend->recipient = htonl (recipient_id);
  memcpy (&toSend[1], message, ntohs (message->size));
#if DEBUG_DV_FORWARD
  GNUNET_hash_to_enc (&original_sender->hashPubKey, &encMe);
  GNUNET_hash_to_enc (&recipient->hashPubKey, &encRecipient);
  GNUNET_GE_LOG (coreAPI->ectx,
		 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
		 GNUNET_GE_BULK, "%s: Cost to intended peer is %d\n",
		 &shortID, neighbor->cost);
  if (neighbor->referrer != NULL)
    {
      GNUNET_hash_to_enc (&neighbor->referrer->hashPubKey, &encVia);
      GNUNET_GE_LOG (coreAPI->ectx,
		     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
		     | GNUNET_GE_BULK,
		     "%s: Original Sender:\n%s\nMessage intended for:\n%s\nSending via:\n%s\n\n",
		     &shortID, (char *) &encMe, (char *) &encRecipient,
		     (char *) &encVia);
    }
  else
    {
      GNUNET_GE_LOG (coreAPI->ectx,
		     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
		     | GNUNET_GE_BULK,
		     "%s: Original Sender:\n%s\nMessage intended for:\n%s\nSending Direct.\n",
		     &shortID, (char *) &encMe, (char *) &encRecipient);
    }
#endif
  coreAPI->ciphertext_send ((neighbor->referrer != NULL) 
			    ? neighbor->referrer 
			    : neighbor->neighbor,
			    &toSend->header,
			    importance, 
			    maxdelay);
  if (stats != NULL)
    stats->change (stat_dv_actual_sent_messages, 1);
  GNUNET_free (toSend);
  GNUNET_mutex_unlock (ctx->dvMutex);
  return (int) cost;
}


/*
 * Forward a received message that was not intended
 * for us.
 *
 * @param message message being forwarded
 */
static int
forward_message (const p2p_dv_MESSAGE_Data * message,
                 const GNUNET_PeerIdentity * sender)
{
#if DEBUG_DV_FORWARD
  GNUNET_EncName encMe;
  GNUNET_EncName encRecipient;
  GNUNET_EncName encOrigin;
#endif
  GNUNET_PeerIdentity recipient;
  int ret;
  int i;
  const GNUNET_MessageHeader *packed_message =
    (const GNUNET_MessageHeader *) & message[1];

  if ((ntohs (message->header.size) < sizeof (p2p_dv_MESSAGE_Data))
      || (ntohs (message->header.size) !=
          (sizeof (p2p_dv_MESSAGE_Data) + ntohs (packed_message->size))))
    {
#if DEBUG_DV_FORWARD
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "%s: Got bad message size.  Expected at least %d, got %d, packed message size %d\n",
                     &shortID, sizeof (p2p_dv_MESSAGE_Data),
                     ntohs (message->header.size),
                     ntohs (packed_message->size));
#endif
      return GNUNET_SYSERR;
    }

  GNUNET_mutex_lock (ctx->dvMutex);
  ret = GNUNET_SYSERR;
  for (i = 0; i < ctx->max_table_size * 2; i++)
    {
      if (ntohl (message->recipient) == ctx->neighbor_id_array[i].neighbor_id)
        {
          memcpy (&recipient, &ctx->neighbor_id_array[i].identity,
                  sizeof (GNUNET_PeerIdentity));
	  ret = GNUNET_OK;
          break;
        }
    }
  GNUNET_mutex_unlock (ctx->dvMutex);
  if (ret == GNUNET_SYSERR)
    return GNUNET_SYSERR;

#if DEBUG_DV_FORWARD
  GNUNET_hash_to_enc (&coreAPI->my_identity->hashPubKey, &encMe);
  GNUNET_hash_to_enc (&recipient->hashPubKey, &encRecipient);
  GNUNET_hash_to_enc (&sender->hashPubKey, &encOrigin);

  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "%s: Received message for:\n%s\nI am:\n%s\nOriginal Sender:\n%s\n",
                 &shortID, (char *) &encRecipient, (char *) &encMe,
                 (char *) &encOrigin);
#endif
  return send_message (&recipient, 
		       sender,
		       packed_message, DV_PRIORITY, DV_DELAY);
}

/*
 * Handle a DATA message receipt, if recipient matches our identity
 * message is for this peer, otherwise check if we know of the
 * intended recipient and send onwards
 */
static int
p2pHandleDVDataMessage (const GNUNET_PeerIdentity * sender,
                        const GNUNET_MessageHeader * message)
{
#if DEBUG_DV_FORWARD
  GNUNET_EncName encMe;
  GNUNET_EncName encSender;
  GNUNET_EncName encOrigin;
  unsigned int message_length;
#endif
  const p2p_dv_MESSAGE_Data *incoming
    = (const p2p_dv_MESSAGE_Data *) message;
  const GNUNET_MessageHeader *packed_message 
    = (const GNUNET_MessageHeader *) & incoming[1];
  GNUNET_PeerIdentity original_sender;
  int ret;
  int i;

#if DEBUG_DV_FORWARD
  GNUNET_hash_to_enc (&sender->hashPubKey, &encSender);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "%s: Received data message:\nImmediate sender:\n%s\nOriginal Sender ID:\n%d\nDestination ID:%d\n",
                 &shortID, (char *) &encSender, ntohl (incoming->sender),
                 ntohl (incoming->recipient));

#endif
  ret = GNUNET_OK;

#if DEBUG_DV
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "%s: Received data message:\nOriginal Sender ID:\n%d\nDestination ID:%d, type: %d\n",
                 &shortID, ntohl (incoming->sender),
                 ntohl (incoming->recipient), ntohs (packed_message->type));
#endif

  if ((ntohs (incoming->header.size) < sizeof (p2p_dv_MESSAGE_Data))
      || (ntohs (incoming->header.size) !=
          (sizeof (p2p_dv_MESSAGE_Data) + ntohs (packed_message->size))))
    {
#if DEBUG_DV_FORWARD
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "%s: Got bad message size.  Expected at least %d, got %d, packed message size %d\n",
                     &shortID, sizeof (p2p_dv_MESSAGE_Data),
                     ntohs (incoming->header.size),
                     ntohs (packed_message->size));
#endif
      return GNUNET_SYSERR;
    }

#if DEBUG_DV 
  message_length =
    ntohs (incoming->header.size) - sizeof (p2p_dv_MESSAGE_Data);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "%s: Guessing packed message size %d, actual packed message size %d\n",
                 &shortID, message_length, ntohs (packed_message->size));
#endif
  if (stats != NULL)
    stats->change (stat_dv_received_messages, 1);

  GNUNET_mutex_lock (ctx->dvMutex);
  if (ntohl (incoming->sender) == 0)
    {
      memcpy (&original_sender, sender, sizeof (GNUNET_PeerIdentity));
    }
  else
    {
      ret = GNUNET_SYSERR;
      for (i = 0; i < ctx->max_table_size * 2; i++)
        {
          if (ntohl (incoming->sender) ==
              ctx->neighbor_id_array[i].neighbor_id)
            {
              memcpy (&original_sender, &ctx->neighbor_id_array[i].identity,
                      sizeof (GNUNET_PeerIdentity));
	      ret = GNUNET_OK;
              break;
            }
        }
      if (ret == GNUNET_SYSERR)
	{
	  GNUNET_mutex_unlock (ctx->dvMutex);
#if DEBUG_DV_FORWARD
	  GNUNET_hash_to_enc (&coreAPI->my_identity->hashPubKey, &encMe);
	  GNUNET_hash_to_enc (&sender->hashPubKey, &encSender);	 
	  GNUNET_GE_LOG (coreAPI->ectx,
			 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
			 GNUNET_GE_BULK,
			 "%s: Received message:\nI am:\n%s\nImmediate sender:\n%s\nOriginal Sender UNKNOWN\n",
			 &shortID, (char *) &encMe, (char *) &encSender);
	  
#endif	  
	  if (stats != NULL)
	    stats->change (stat_dv_unknown_peer, 1);
	  return GNUNET_SYSERR;
	}
    }
  GNUNET_mutex_unlock (ctx->dvMutex);

  if (ntohl (incoming->recipient) == 0)
    {
      coreAPI->loopback_send (&original_sender, 
			      (const char *) packed_message,
			      ntohs (packed_message->size), GNUNET_YES,
			      NULL);
#if DEBUG_DV_FORWARD
      GNUNET_hash_to_enc (&coreAPI->my_identity->hashPubKey, &encMe);
      GNUNET_hash_to_enc (&sender->hashPubKey, &encSender);
      GNUNET_hash_to_enc (&original_sender.hashPubKey, &encOrigin);     
      GNUNET_GE_LOG (coreAPI->ectx,
		     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
		     | GNUNET_GE_BULK,
		     "%s: Received message for me:\nI am:\n%s\nImmediate sender:\n%s\nOriginal Sender:\n%s\n",
		     &shortID, (char *) &encMe, (char *) &encSender,
		     (char *) &encOrigin);      
#endif
    }
  else
    {
      ret = forward_message (incoming, &original_sender);
      if (stats != NULL)
	{
	  if (ret != GNUNET_SYSERR)
	    stats->change (stat_dv_forwarded_messages, 1);
	  else
	    stats->change (stat_dv_failed_forwards, 1);
	}        
    }
  return ret;
}

/*
 * Build and send a fresh message from this peer to a
 * peer in the fisheye neighborhood.  Returns GNUNET_OK
 * provided all goes well, GNUNET_NO if recipient is not
 * in the neighborhood, and GNUNET_SYSERR if some other
 * problem happens
 *
 * @recipient for which peer is this message intended
 * @message message being sent
 * return cost of sent message, GNUNET_SYSERR on error
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
  unsigned int ret;
  ret = GNUNET_SYSERR;
  GNUNET_mutex_lock (ctx->dvMutex);
  if (GNUNET_YES == GNUNET_multi_hash_map_contains (ctx->extended_neighbors,
                                                    &node->hashPubKey))
    {
      ret = GNUNET_OK;
      if (bpm != NULL)
	*bpm = 0; /* FIXME */
      if (last_seen != NULL)
	*last_seen = 0; /* FIXME */
    }
  GNUNET_mutex_unlock (ctx->dvMutex);
  return ret;
}

/*
 * Adds a peer to the temporary mapping between neighbor_id's and
 * GNUNET_PeerIdentity's
 */
static int
addToNeighborMap (unsigned int neighbor_id,
                  const GNUNET_PeerIdentity * identity)
{

  if (ctx->neighbor_id_loc == ctx->max_table_size * 2)
    {
      ctx->neighbor_id_loc = 0;
    }

  ctx->neighbor_id_array[ctx->neighbor_id_loc].neighbor_id = neighbor_id;
  memcpy (&ctx->neighbor_id_array[ctx->neighbor_id_loc].identity, identity,
          sizeof (GNUNET_PeerIdentity));
  ctx->neighbor_id_loc++;
  return GNUNET_OK;
}


/*
 * Handles when a peer is either added due to being newly connected
 * or having been gossiped about, also called when a cost for a neighbor
 * needs to be updated.
 *
 * @param neighbor identity of the peer whose info is being added/updated
 * @param referrer if this is a gossiped peer, who did we hear it from?
 * @param cost the cost to this peer (the actual important part!)
 *
 */
static int
addUpdateNeighbor (const GNUNET_PeerIdentity * peer, unsigned int neighbor_id,
                   const GNUNET_PeerIdentity * referrer, unsigned int cost)
{
  struct GNUNET_dv_neighbor *neighbor;
  GNUNET_CronTime now;
#if DEBUG_DV
  GNUNET_EncName encPeer;
  GNUNET_EncName encReferrer;
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s: Entering addUpdateNeighbor\n",
                 &shortID);

  GNUNET_hash_to_enc (&peer->hashPubKey, &encPeer);
  if (referrer == NULL)
    GNUNET_GE_LOG (coreAPI->ectx,
                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_BULK, "%s: Adding/Updating Node %s\n",
                   &shortID, (char *) &encPeer);
  else
    {
      GNUNET_hash_to_enc (&referrer->hashPubKey, &encReferrer);
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "%s: Adding/Updating Node %s, Learned about from %s\n",
                     &shortID, (char *) &encPeer, (char *) &encReferrer);
    }
#endif
  now = GNUNET_get_time ();
  GNUNET_mutex_lock (ctx->dvMutex);
  if (cost > ctx->fisheye_depth)
    {
      /* too expensive */
#if DEBUG_DV_MAINTAIN
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK, "Node cost %d too high, not adding this peer!\n",
                     cost);
#endif
      if ((GNUNET_YES ==
           GNUNET_multi_hash_map_contains (ctx->extended_neighbors,
                                           &peer->hashPubKey))
          && (GNUNET_NO ==
              GNUNET_multi_hash_map_contains (ctx->direct_neighbors,
                                              &peer->hashPubKey)))
        {
          neighbor =
            GNUNET_multi_hash_map_get (ctx->extended_neighbors,
                                       &peer->hashPubKey);
          if (((neighbor->referrer == NULL) && (referrer == NULL)) ||
              (((neighbor->referrer != NULL) && (referrer != NULL))
               &&
               (memcmp
                (neighbor->referrer, referrer,
                 sizeof (GNUNET_PeerIdentity)) == 0)))
            {
              delete_neighbor (neighbor);
            }
        }
      GNUNET_mutex_unlock (ctx->dvMutex);
      return GNUNET_NO;      
    }
  if (GNUNET_NO ==
      GNUNET_multi_hash_map_contains (ctx->extended_neighbors,
				      &peer->hashPubKey))
    {
      /* new neighbor */
      if (ctx->max_table_size <=
          GNUNET_multi_hash_map_size (ctx->extended_neighbors))
	{
	  /* don't care, have plenty */
	  /* FIXME: might want to consider cost here! */
	  GNUNET_mutex_unlock (ctx->dvMutex);
	  return GNUNET_OK;      	  
	}        
      neighbor = GNUNET_malloc (sizeof (struct GNUNET_dv_neighbor));
      neighbor->cost = cost;
      neighbor->last_activity = now;
      neighbor->neighbor = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
      neighbor->neighbor_id = neighbor_id;
      memcpy (neighbor->neighbor, peer, sizeof (GNUNET_PeerIdentity));
      addToNeighborMap (neighbor_id, peer);
      
      if (referrer == NULL)
	neighbor->referrer = NULL;
      else
	{
	  neighbor->referrer =
	    GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
	  memcpy (neighbor->referrer, referrer,
		  sizeof (GNUNET_PeerIdentity));
	}
      
      GNUNET_multi_hash_map_put (ctx->extended_neighbors,
				 &peer->hashPubKey, neighbor,
				 GNUNET_MultiHashMapOption_REPLACE);
      
      GNUNET_CONTAINER_heap_insert (ctx->neighbor_max_heap, neighbor,
				    cost);
      GNUNET_CONTAINER_heap_insert (ctx->neighbor_min_heap, neighbor,
				    cost);
      if (stats != NULL)
	stats->change (stat_dv_total_peers, 1);    
      GNUNET_mutex_unlock (ctx->dvMutex);
      return GNUNET_OK;      
    }
  neighbor =
    GNUNET_multi_hash_map_get (ctx->extended_neighbors,
			       &peer->hashPubKey);
  
  if ((((neighbor->referrer == NULL) && (referrer == NULL)) ||
       (((neighbor->referrer != NULL) && (referrer != NULL))
	&&
	(memcmp
	 (neighbor->referrer, referrer,
	  sizeof (GNUNET_PeerIdentity)) == 0))))
    {
      /* same path as the one we already have */
      neighbor->last_activity = now;
      if (neighbor->cost != cost)
	{
	  /* update cost */
	  neighbor->cost = cost; 
	  GNUNET_CONTAINER_heap_update_cost (ctx->neighbor_max_heap, neighbor,
					     cost);
	  GNUNET_CONTAINER_heap_update_cost (ctx->neighbor_min_heap, neighbor,
					     cost);
	}
      GNUNET_mutex_unlock (ctx->dvMutex);
      return GNUNET_OK;
    }
  if (neighbor->cost <= cost)
    {
      /* alternative, costlier path found, ignore */
      GNUNET_mutex_unlock (ctx->dvMutex);
      return GNUNET_OK;
    }
  /* alternative, cheaper path found, replace */
  delete_neighbor (neighbor);
  neighbor = GNUNET_malloc (sizeof (struct GNUNET_dv_neighbor));
  neighbor->cost = cost;
  neighbor->last_activity = now;
  neighbor->neighbor = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
  neighbor->neighbor_id = neighbor_id;
  memcpy (neighbor->neighbor, peer, sizeof (GNUNET_PeerIdentity));
  addToNeighborMap (neighbor_id, peer);
      
  if (referrer == NULL)
    neighbor->referrer = NULL;
  else
    {
      neighbor->referrer =
	GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
      memcpy (neighbor->referrer, referrer,
	      sizeof (GNUNET_PeerIdentity));
    }
  
  GNUNET_multi_hash_map_put (ctx->extended_neighbors,
			     &peer->hashPubKey, neighbor,
			     GNUNET_MultiHashMapOption_REPLACE);
  
  GNUNET_CONTAINER_heap_insert (ctx->neighbor_max_heap, neighbor,
				cost);
  GNUNET_CONTAINER_heap_insert (ctx->neighbor_min_heap, neighbor,
				cost);
#if DEBUG_DV
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s: Exiting addUpdateNeighbor\n", &shortID);
#endif
  GNUNET_mutex_unlock (ctx->dvMutex);
  return GNUNET_OK;
}


/*
 * Handles a gossip message from another peer.  Basically
 * just check the message size, cast to the correct type
 * and call addUpdateNeighbor to do the real work.
 */
static int
p2pHandleDVNeighborMessage (const GNUNET_PeerIdentity * sender,
                            const GNUNET_MessageHeader * message)
{
  int ret = GNUNET_OK;
  const p2p_dv_MESSAGE_NeighborInfo *nmsg;
#if DEBUG_DV
  GNUNET_EncName from;
  GNUNET_EncName about;
#endif

  if (ntohs (message->size) < sizeof (p2p_dv_MESSAGE_NeighborInfo))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;     /* invalid message */
    }
  nmsg = (const p2p_dv_MESSAGE_NeighborInfo *) message;

  ret =
    addUpdateNeighbor (&nmsg->neighbor, ntohl (nmsg->neighbor_id), sender,
                       ntohl (nmsg->cost) + 1);
  if (stats != NULL)
    stats->change (stat_dv_received_gossips, 1);

#if DEBUG_DV_MAINTAIN
  if (GNUNET_OK != ret)
    GNUNET_GE_LOG (coreAPI->ectx,
                   GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                   _("%s: Problem adding/updating neighbor in `%s'\n"),
                   &shortID, "dv");
#endif

#if DEBUG_DV
  GNUNET_hash_to_enc (&sender->hashPubKey, &from);
  GNUNET_hash_to_enc (&nmsg->neighbor.hashPubKey, &about);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "%s: Received info about peer %s from directly connected peer %s\n",
                 &shortID, (char *) &about, (char *) &from);
#endif
  return ret;
}

/*
 * Handles a peer connect notification, indicating a peer should
 * be added to the direct neighbor table.
 *
 * @param peer - ident of the connected peer
 * @param unused - unused closure arg
 */
static void
peer_connect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
#if DEBUG_DV
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s: Entering peer_connect_handler:\n",
                 &shortID);

#endif
  struct GNUNET_dv_neighbor *neighbor;
  unsigned int cost = GNUNET_DV_LEAST_COST;

  GNUNET_mutex_lock (ctx->dvMutex);
  if (GNUNET_YES !=
      GNUNET_multi_hash_map_contains (ctx->direct_neighbors,
                                      &peer->hashPubKey))
    {
      neighbor = GNUNET_malloc (sizeof (struct GNUNET_dv_neighbor));
      neighbor->cost = cost;
      neighbor->last_activity = GNUNET_get_time ();
      neighbor->neighbor = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
      neighbor->neighbor_id =
        GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, RAND_MAX - 1) + 1;
      memcpy (neighbor->neighbor, peer, sizeof (GNUNET_PeerIdentity));
      GNUNET_multi_hash_map_put (ctx->direct_neighbors, &peer->hashPubKey,
                                 neighbor, GNUNET_MultiHashMapOption_REPLACE);
    }
  else
    {
      neighbor =
        GNUNET_multi_hash_map_get (ctx->direct_neighbors, &peer->hashPubKey);

      if (neighbor->cost != cost)
        {
          neighbor->last_activity = GNUNET_get_time ();
          neighbor->cost = cost;
        }

    }
  GNUNET_mutex_unlock (ctx->dvMutex);
  addUpdateNeighbor (peer, neighbor->neighbor_id, NULL, cost);
}


/*
 * A callback for deleting matching nodes from heaps...
 *
 * @param element a neighbor - the peer we may delete
 * @param root the root of the heap
 * @param cls the peer identity to compare neighbor's identity to
 */
static int
delete_callback (void *element, GNUNET_CostType cost,
                 struct GNUNET_CONTAINER_Heap *root, void *cls)
{
  struct GNUNET_dv_neighbor *neighbor = element;
  GNUNET_PeerIdentity *toMatch = cls;
#if DEBUG_DV
  GNUNET_EncName encNeighbor;
  GNUNET_EncName encReferrer;
  GNUNET_EncName encToMatch;

  GNUNET_hash_to_enc (&neighbor->neighbor->hashPubKey, &encNeighbor);
  GNUNET_hash_to_enc (&toMatch->hashPubKey, &encToMatch);
  if (neighbor->referrer != NULL)
    {
      GNUNET_hash_to_enc (&neighbor->referrer->hashPubKey, &encReferrer);
      fprintf (stderr, "Checking for node\n%s to match\n%s or\n%s\n",
               (char *) &encToMatch, (char *) &encNeighbor,
               (char *) &encReferrer);
    }
  fprintf (stderr, "Checking for node %s to match %s\n", (char *) &encToMatch,
           (char *) &encNeighbor);
#endif

  if (((memcmp (neighbor->neighbor, toMatch, sizeof (GNUNET_PeerIdentity)) ==
        0) && (neighbor->referrer == NULL)) || ((neighbor->referrer != NULL)
                                                &&
                                                (memcmp
                                                 (neighbor->referrer, toMatch,
                                                  sizeof
                                                  (GNUNET_PeerIdentity)) ==
                                                 0)))
    {
      /* FIXME: we might want to have some way to notify the rest of
	 our DV-neigborhood about this disconnect as well... */
      delete_neighbor (neighbor);
      /* we must not continue iterating at this point since
	 'delete_neighbor' modified the tree and hence internal
	 invariants of the iterator were likely broken!
	 Besides, each neighbor should only appear once anyway... */
      return GNUNET_NO;
    }
  return GNUNET_YES;
}

/*
 * Handles the receipt of a peer disconnect notification, removing
 * the direct neighbor from the direct list and any referenced
 * neighbors as well.
 *
 * @param peer - the peer that has disconnected from us
 */
static void
peer_disconnect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
  struct GNUNET_dv_neighbor *neighbor;

#if DEBUG_DV
  GNUNET_EncName myself;
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s: Entering peer_disconnect_handler\n",
                 &shortID);
  GNUNET_hash_to_enc (&peer->hashPubKey, &myself);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s: disconnected peer: %s\n", &shortID,
                 (char *) &myself);
#endif

  GNUNET_mutex_lock (ctx->dvMutex);

  if (GNUNET_YES ==
      GNUNET_multi_hash_map_contains (ctx->direct_neighbors,
                                      &peer->hashPubKey))
    {
      neighbor =
        GNUNET_multi_hash_map_get (ctx->direct_neighbors, &peer->hashPubKey);
      if (neighbor != NULL)
        {
	  GNUNET_multi_hash_map_remove_all (ctx->direct_neighbors,
					    &peer->hashPubKey);
	  GNUNET_CONTAINER_heap_iterate (ctx->neighbor_max_heap,
                                         &delete_callback, (void*) peer);
          /* Note that we do not use delete_neighbor here because
	     we are deleting from the direct neighbor list! */
          GNUNET_free (neighbor->neighbor);
	  GNUNET_free_non_null (neighbor->referrer);
          GNUNET_free (neighbor);
        }
    }
  GNUNET_mutex_unlock (ctx->dvMutex);
#if DEBUG_DV
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s: Exiting peer_disconnect_handler\n",
                 &shortID);
#endif
  return;
}

/*
 * Chooses a neighbor at random to gossip peer information
 * to
 */
static struct GNUNET_dv_neighbor *
chooseToNeighbor ()
{
  if (GNUNET_multi_hash_map_size (ctx->direct_neighbors) == 0)
    return NULL;

  return (struct GNUNET_dv_neighbor *)
    GNUNET_multi_hash_map_get_random (ctx->direct_neighbors);
}

/*
 * Chooses a neighbor to send information about
 * by walking through the neighbor heap
 */
static struct GNUNET_dv_neighbor *
chooseAboutNeighbor ()
{
  unsigned int heap_size;
  heap_size = GNUNET_CONTAINER_heap_get_size (ctx->neighbor_min_heap);
  if (heap_size == 0)
    return NULL;

#if DEBUG_DV
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "%s: Min heap size %d\n",
                 &shortID, heap_size);
#endif

  return GNUNET_CONTAINER_heap_walk_get_next (ctx->neighbor_min_heap);

}

/*
 * Method which changes how often peer sends neighbor information
 * to other peers.  Basically, if we know how many peers we have
 * and want to gossip all of them to all of our direct neighbors
 * we will need to send them such that they will all reach their
 * destinations within the timeout frequency.  We assume all
 * peers share our timeout frequency so it's a simple calculation.
 * May need revisiting if we want to specify a maximum or minimum
 * value for this interval.
 */
static void 
updateSendInterval ()
{
  unsigned int direct_neighbors;
  unsigned int total_neighbors;
  unsigned int total_messages;
#if DEBUG_DV
  unsigned int old_interval;
#endif
  direct_neighbors = GNUNET_multi_hash_map_size (ctx->direct_neighbors);
  total_neighbors = GNUNET_multi_hash_map_size (ctx->extended_neighbors);

  if (direct_neighbors == 0)
    return;

  total_messages = direct_neighbors * total_neighbors;
#if DEBUG_DV
  old_interval = ctx->send_interval;
#endif

  ctx->send_interval =
    (unsigned int) ((GNUNET_DV_PEER_EXPIRATION_TIME / total_messages) / 2);
  if (ctx->send_interval > GNUNET_DV_MAX_SEND_INTERVAL)
    ctx->send_interval = GNUNET_DV_MAX_SEND_INTERVAL;

#if DEBUG_DV
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
                 | GNUNET_GE_BULK,
                 "%s: Updated send_interval. Was %llu, now is %llu\n",
                 &shortID, old_interval, ctx->send_interval);
#endif
}

/*
 * Thread which chooses a peer to gossip about and
 * a peer to gossip to, then constructs the message
 * and sends it out.  Will run until done_module_dv
 * is called.
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
  struct GNUNET_dv_neighbor *about;
  struct GNUNET_dv_neighbor *to;
  unsigned int count;
  p2p_dv_MESSAGE_NeighborInfo message;

  message.header.size = htons (sizeof (p2p_dv_MESSAGE_NeighborInfo));
  message.header.type = htons (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);
  count = 0;
  while (!ctx->closing)
    {
      if (0 == (++count % 20))
        updateSendInterval ();

      GNUNET_mutex_lock (ctx->dvMutex);
      about = chooseAboutNeighbor ();
      to = chooseToNeighbor ();

      if ((about != NULL) && (to != NULL)
          && (memcmp (about->neighbor, to->neighbor, sizeof (GNUNET_HashCode))
              != 0))
        {
#if DEBUG_DV
          GNUNET_hash_to_enc (&about->neighbor->hashPubKey, &encPeerAbout);
          GNUNET_hash_to_enc (&to->neighbor->hashPubKey, &encPeerTo);
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
                         | GNUNET_GE_BULK,
                         "%s: Sending info about peer %s to directly connected peer %s\n",
                         &shortID, (char *) &encPeerAbout,
                         (char *) &encPeerTo);
#endif
          message.cost = htonl (about->cost);
          message.neighbor_id = htonl (about->neighbor_id);
          memcpy (&message.neighbor, about->neighbor,
                  sizeof (GNUNET_PeerIdentity));
          coreAPI->ciphertext_send (to->neighbor, &message.header,
                                    GNUNET_DV_DHT_GOSSIP_PRIORITY,
                                    ctx->send_interval);
          if (stats != NULL)
            stats->change (stat_dv_sent_gossips, 1);
        }
      GNUNET_mutex_unlock (ctx->dvMutex);
      GNUNET_thread_sleep (ctx->send_interval);
    }
  return NULL;
}

/*
 * Initializes and provides the fisheye DV service
 *
 * @param capi the core API
 * @return NULL on errors, DV_API otherwise
 */
GNUNET_DV_ServiceAPI *
provide_module_dv (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;
  unsigned long long max_hosts;
  GNUNET_EncName encMe;
  static GNUNET_DV_ServiceAPI api;
  int i;

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
        stats->create (gettext_noop ("# dv messages to/from unknown peers"));
    }

  ctx = GNUNET_malloc (sizeof (struct GNUNET_DV_Context));
  ctx->neighbor_min_heap = GNUNET_CONTAINER_heap_create (GNUNET_MIN_HEAP);
  ctx->neighbor_max_heap = GNUNET_CONTAINER_heap_create (GNUNET_MAX_HEAP);
  ctx->send_interval = GNUNET_DV_DEFAULT_SEND_INTERVAL;
  ctx->dvMutex = capi->global_lock_get ();

  coreAPI = capi;
  GNUNET_hash_to_enc (&coreAPI->my_identity->hashPubKey, &encMe);
  strncpy ((char *) &shortID, (char *) &encMe, 4);
  shortID[4] = '\0';
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 _("%s: `%s' registering P2P handlers %d %d\n"),
                 "dv", &shortID,
		 GNUNET_P2P_PROTO_DV_DATA_MESSAGE,
		 GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);


  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DV",
                                            "FISHEYEDEPTH",
                                            0, -1, 3, &ctx->fisheye_depth);

  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DV",
                                            "TABLESIZE",
                                            0, -1, 100, &ctx->max_table_size);

  ctx->neighbor_id_array =
    GNUNET_malloc (sizeof (struct NeighborID) * ctx->max_table_size * 2);
  for (i = 0; i < ctx->max_table_size * 2; i++)
    {
      ctx->neighbor_id_array[i].neighbor_id = 0;
      memset (&ctx->neighbor_id_array[i].identity, 0,
              sizeof (GNUNET_PeerIdentity));
    }
  ctx->neighbor_id_loc = 0;

  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "gnunetd", "connection-max-hosts",
                                            1, -1, 50, &max_hosts);

  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "dv",
                                                                   _
                                                                   ("enables distance vector type routing (wip)")));


  ctx->direct_neighbors = GNUNET_multi_hash_map_create (max_hosts);
  if (ctx->direct_neighbors == NULL)
    {
      ok = GNUNET_SYSERR;
    }

  ctx->extended_neighbors =
    GNUNET_multi_hash_map_create (ctx->max_table_size * 3);
  if (ctx->extended_neighbors == NULL)
    {
      ok = GNUNET_SYSERR;
    }

  if (GNUNET_SYSERR ==
      coreAPI->peer_disconnect_notification_register
      (&peer_disconnect_handler, NULL))
    ok = GNUNET_SYSERR;

  if (GNUNET_SYSERR ==
      coreAPI->peer_connect_notification_register (&peer_connect_handler,
                                                   NULL))
    ok = GNUNET_SYSERR;

  if (GNUNET_SYSERR ==
      coreAPI->p2p_ciphertext_handler_register
      (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE, &p2pHandleDVNeighborMessage))
    ok = GNUNET_SYSERR;

  if (GNUNET_SYSERR ==
      coreAPI->p2p_ciphertext_handler_register
      (GNUNET_P2P_PROTO_DV_DATA_MESSAGE, &p2pHandleDVDataMessage))
    ok = GNUNET_SYSERR;

  /* FIXME: do something with 'ok' */
  sendingThread =
    GNUNET_thread_create (&neighbor_send_thread, &coreAPI, 1024 * 1);

  GNUNET_cron_add_job (coreAPI->cron, &maintain_dv_job,
                       GNUNET_DV_MAINTAIN_FREQUENCY,
                       GNUNET_DV_MAINTAIN_FREQUENCY, NULL);

  return &api;
}

/*
 * Shuts down and cleans up the DV module
 */
void
release_module_dv ()
{
  void *unused;

  ctx->closing = 1;
  GNUNET_thread_stop_sleep (sendingThread);
  GNUNET_thread_join (sendingThread, &unused);

  coreAPI->p2p_ciphertext_handler_unregister
    (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE, &p2pHandleDVNeighborMessage);

  coreAPI->peer_disconnect_notification_unregister (&peer_disconnect_handler,
                                                    NULL);
  coreAPI->peer_disconnect_notification_unregister (&peer_connect_handler,
                                                    NULL);
  GNUNET_cron_del_job (coreAPI->cron, &maintain_dv_job,
                       GNUNET_DV_MAINTAIN_FREQUENCY, NULL);
  GNUNET_multi_hash_map_destroy (ctx->direct_neighbors);
  GNUNET_multi_hash_map_destroy (ctx->extended_neighbors);
  GNUNET_CONTAINER_heap_destroy (ctx->neighbor_max_heap);
  GNUNET_CONTAINER_heap_destroy (ctx->neighbor_min_heap);
  GNUNET_free (ctx->neighbor_id_array);
  coreAPI->service_release (stats);
  stats = NULL;
  coreAPI = NULL;
}

/* end of dv.c */
