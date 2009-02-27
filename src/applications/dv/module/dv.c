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
#include "gnunet_dv_lib.h"
#include "dv.h"
#include "heap.h"

#define DEBUG_DV GNUNET_NO
#define DEBUG_DV_FORWARD GNUNET_NO
/* How long to allow a message to be delayed */
#define DV_DELAY (100 * GNUNET_CRON_MILLISECONDS)

/*
 * Global construct
 */
struct GNUNET_DV_Context
{
  unsigned long long fisheye_depth;
  unsigned long long max_table_size;
  unsigned int send_interval;

  unsigned short closing;

  struct GNUNET_Mutex *dvMutex;
  struct GNUNET_MultiHashMap *direct_neighbors;

  struct GNUNET_MultiHashMap *extended_neighbors;
  struct GNUNET_dv_heap neighbor_min_heap;
  struct GNUNET_dv_heap neighbor_max_heap;


};

static struct GNUNET_DV_Context *ctx;
static struct GNUNET_ThreadHandle *sendingThread;
static GNUNET_CoreAPIForPlugins *coreAPI;

// CG: unless defined in a header and used by
//     other C source files (or used with dlsym),'
//     make sure all of your functions are declared "static"
static int
printTableEntry (const GNUNET_HashCode * key, void *value, void *cls)
{
  struct GNUNET_dv_neighbor *neighbor = (struct GNUNET_dv_neighbor *) value;
  char *type = (char *) cls;
  GNUNET_EncName encPeer;
  GNUNET_EncName encReferrer;

  GNUNET_hash_to_enc (&neighbor->neighbor->hashPubKey, &encPeer);
  if (neighbor->referrer == NULL)
    GNUNET_GE_LOG (coreAPI->ectx,
                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_BULK, "%s\tNeighbor: %s\nCost: %d\n", type,
                   (char *) &encPeer, neighbor->cost);
  else
    {
      GNUNET_hash_to_enc (&neighbor->referrer->hashPubKey, &encReferrer);
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "%s\tNeighbor: %s\nCost: %d Referred by: %s\n", type,
                     (char *) &encPeer, neighbor->cost,
                     (char *) &encReferrer);
    }
  return GNUNET_OK;
}

static void
print_tables ()
{
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Printing directly connected neighbors:\n");
  GNUNET_multi_hash_map_iterate (ctx->direct_neighbors, &printTableEntry,
                                 "DIRECT");

  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Printing extended neighbors:\n");
  GNUNET_multi_hash_map_iterate (ctx->extended_neighbors, &printTableEntry,
                                 "EXTENDED");
  return;
}

/*
 * Forward a received message that was not intended
 * for us.
 *
 * @recipient for which peer is this message intended
 * @message message being forwarded
 */
static int
forward_message (p2p_dv_MESSAGE_Data *message)
{
  p2p_dv_MESSAGE_Data *toSend;
  GNUNET_MessageHeader *packed_message = (GNUNET_MessageHeader *)&message[1];
  int ret = GNUNET_OK;
  unsigned int msg_size;
  struct GNUNET_dv_neighbor *neighbor;

  if (ntohs(message->header.size) != (sizeof(p2p_dv_MESSAGE_Data) + ntohs(packed_message->size)))
  {
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES ==
      GNUNET_multi_hash_map_contains (ctx->extended_neighbors,
                                      &message->recipient.hashPubKey))
    {
#if DEBUG_DV_FORWARD
  GNUNET_GE_LOG (coreAPI->ectx,
                GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                GNUNET_GE_BULK,
                "Sending a forwarded message!\n");
#endif
      neighbor =
        GNUNET_multi_hash_map_get (ctx->extended_neighbors,
                                   &message->recipient.hashPubKey);
      msg_size = ntohs(message->header.size);
      if (msg_size > GNUNET_MAX_BUFFER_SIZE - 8)
        return GNUNET_SYSERR;
      toSend = GNUNET_malloc (msg_size);
      toSend->header.size = htons (msg_size);
      toSend->header.type = htons (GNUNET_P2P_PROTO_DV_DATA_MESSAGE);
      memcpy (&toSend->sender, &message->sender, sizeof(GNUNET_PeerIdentity));
      memcpy (&toSend->recipient, &message->recipient, sizeof (GNUNET_PeerIdentity));
      memcpy (&toSend[1], packed_message, packed_message->size);
      coreAPI->ciphertext_send (neighbor->neighbor, &toSend->header, 0,
                                DV_DELAY);
      GNUNET_free (toSend);
      return ret;
    }
  else
    {
#if DEBUG_DV_FORWARD
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Attempted to send a message to an unknown peer!\n");
#endif
      return GNUNET_NO;
    }

}

/*
 * Handle a message receipt, if recipient matches ident message is
 * for this peer, otherwise check if we know of the intended
 * recipient and send onwards
 */
static int
p2pHandleDVDataMessage (const GNUNET_PeerIdentity * sender,
                        const GNUNET_MessageHeader * message)
{
#if DEBUG_DV_FORWARD
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Entering p2pHandleDVDataMessage, Received message!\n");
#endif
  p2p_dv_MESSAGE_Data *incoming;
  incoming = (p2p_dv_MESSAGE_Data *) message;
  GNUNET_MessageHeader *packed_message = (GNUNET_MessageHeader *)&incoming[1];
  char *message_content;
  unsigned int message_length;
  int ret;
#if DEBUG_DV_FORWARD
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Got message original size: %d, packed message size %d (original should be packed size + %d)\n", ntohs(incoming->header.size), ntohs(packed_message->size), sizeof (p2p_dv_MESSAGE_Data));
#endif
  ret = GNUNET_OK;
  if ((ntohs (incoming->header.size) < sizeof (p2p_dv_MESSAGE_Data)) || (ntohs(incoming->header.size) != (sizeof(p2p_dv_MESSAGE_Data) + ntohs(packed_message->size))))
  {
#if DEBUG_DV_FORWARD
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Got bad message size.  Expected at least %d, got %d, packed message size %d\n", sizeof (p2p_dv_MESSAGE_Data), ntohs(incoming->header.size), ntohs(packed_message->size));
#endif
    return GNUNET_SYSERR;
  }

  message_length =
    ntohs (incoming->header.size) - sizeof (p2p_dv_MESSAGE_Data);
  message_content = GNUNET_malloc (message_length);
  memcpy (message_content, &incoming[1], message_length);
#if DEBUG_DV
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Guessing packed message size %d, actual packed message size %d\n", message_length, ntohs(packed_message->size));
#endif
  if (memcmp
      (coreAPI->my_identity, &incoming->recipient,
       sizeof (GNUNET_PeerIdentity)) == 0)
    {
      /*FIXME: Deliver message up to ???  Handle arbitrary messages? */
#if DEBUG_DV_FORWARD
  GNUNET_EncName encMe;
  GNUNET_EncName encRecipient;
  GNUNET_hash_to_enc (coreAPI->my_identity, &encMe);
  GNUNET_hash_to_enc (&incoming->recipient, &encRecipient);

  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Received message for: %s, I am %s\n", (char *)&encRecipient, (char*)&encMe);

  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "Received message intended for this node!\n",
                  message_content);
#endif
      coreAPI->loopback_send(&incoming->sender, (char *)packed_message, ntohs(packed_message->size), GNUNET_YES, NULL);
    }
  else
    {
      fprintf(stderr, "\n\n\nOTHER NODES MESSAGE\n\n\n");
#if DEBUG_DV_FORWARD
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Received message for some other node!\n",
                     message_content);
#endif
      ret = forward_message (incoming);
    }
  GNUNET_free (message_content);
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
 */
int
GNUNET_DV_send_message (const GNUNET_PeerIdentity * recipient, const GNUNET_MessageHeader *message)
{
  p2p_dv_MESSAGE_Data *toSend;
  int ret = GNUNET_OK;
  unsigned int msg_size;
  struct GNUNET_dv_neighbor *neighbor;
#if DEBUG_DV_FORWARD
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Entered GNUNET_DV_send_message!\n");
#endif
  if (GNUNET_YES ==
      GNUNET_multi_hash_map_contains (ctx->extended_neighbors,
                                      &recipient->hashPubKey))
    {
#if DEBUG_DV_FORWARD
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Found peer, attempting to send message!\n");
#endif
      neighbor =
        GNUNET_multi_hash_map_get (ctx->extended_neighbors,
                                   &recipient->hashPubKey);
      msg_size = ntohs(message->size) + sizeof (p2p_dv_MESSAGE_Data);
      if (msg_size > GNUNET_MAX_BUFFER_SIZE - 8)
        return GNUNET_SYSERR;
      toSend = GNUNET_malloc (msg_size);
      toSend->header.size = htons (msg_size);
      toSend->header.type = htons (GNUNET_P2P_PROTO_DV_DATA_MESSAGE);
      memcpy (&toSend->sender, coreAPI->my_identity , sizeof(GNUNET_PeerIdentity));
      memcpy (&toSend->recipient, recipient, sizeof (GNUNET_PeerIdentity));
      memcpy (&toSend[1], message, ntohs(message->size));
      coreAPI->ciphertext_send (neighbor->neighbor, &toSend->header, 0,
                                0);
      GNUNET_free (toSend);
      return ret;
    }
  else
    {
#if DEBUG_DV_FORWARD
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Attempted to send a message to an unknown peer!\n");
#endif
      return GNUNET_NO;
    }

}

/*
 * Handles when a peer is either added due to being newly connected
 * or having been gossiped about, also called when a cost for a neighbor
 * needs to be updated.
 *
 * @param neighbor - identity of the peer whose info is being added/updated
 * @param referrer - if this is a gossiped peer, who did we hear it from?
 * @param cost - the cost to this peer (the actual important part!)
 *
 */
static int
addUpdateNeighbor (const GNUNET_PeerIdentity * peer,
                   const GNUNET_PeerIdentity * referrer, unsigned int cost)
{
  int ret;
  struct GNUNET_dv_neighbor *neighbor;
#if DEBUG_DV
  GNUNET_EncName encPeer;
  GNUNET_EncName encReferrer;
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Entering addUpdateNeighbor\n");

  GNUNET_hash_to_enc (&peer->hashPubKey, &encPeer);
  if (referrer == NULL)
    GNUNET_GE_LOG (coreAPI->ectx,
                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                   GNUNET_GE_BULK, "Adding/Updating Node %s\n",
                   (char *) &encPeer);
  else
    {
      GNUNET_hash_to_enc (&referrer->hashPubKey, &encReferrer);
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Adding/Updating Node %s, Learned about from %s\n",
                     (char *) &encPeer, (char *) &encReferrer);
    }
#endif
  ret = GNUNET_OK;

  GNUNET_mutex_lock (ctx->dvMutex);

  if (GNUNET_NO ==
      GNUNET_multi_hash_map_contains (ctx->extended_neighbors,
                                      &peer->hashPubKey))
    {
      neighbor = GNUNET_malloc (sizeof (struct GNUNET_dv_neighbor));
      neighbor->cost = cost;
      neighbor->neighbor = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
      memcpy (neighbor->neighbor, peer, sizeof (GNUNET_PeerIdentity));

      if (referrer == NULL)
        neighbor->referrer = NULL;
      else
        {
          neighbor->referrer = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
          memcpy (neighbor->referrer, referrer, sizeof (GNUNET_PeerIdentity));
        }

      GNUNET_multi_hash_map_put (ctx->extended_neighbors, &peer->hashPubKey,
                                 neighbor, GNUNET_MultiHashMapOption_REPLACE);

      GNUNET_DV_Heap_insert (&ctx->neighbor_max_heap, neighbor);
      GNUNET_DV_Heap_insert (&ctx->neighbor_min_heap, neighbor);

    }
  else
    {
      neighbor =
        GNUNET_multi_hash_map_get (ctx->extended_neighbors,
                                   &peer->hashPubKey);

      if ((neighbor->cost != cost) &&
          (((neighbor->referrer == NULL) && (referrer == NULL)) ||
           (((neighbor->referrer != NULL) && (referrer != NULL))
            &&
            (memcmp
             (neighbor->referrer, referrer,
              sizeof (GNUNET_PeerIdentity)) == 0))))
        {
          neighbor->cost = cost;
          GNUNET_DV_Heap_updatedCost (&ctx->neighbor_max_heap, neighbor);
          GNUNET_DV_Heap_updatedCost (&ctx->neighbor_min_heap, neighbor);
        }
      else if (neighbor->cost > cost)
        {
          GNUNET_DV_Heap_removeNode (&ctx->neighbor_max_heap, neighbor);
          GNUNET_DV_Heap_removeNode (&ctx->neighbor_min_heap, neighbor);

          GNUNET_free (neighbor->neighbor);
          if (neighbor->referrer != NULL)
            GNUNET_free (neighbor->referrer);
          GNUNET_free (neighbor);
          GNUNET_multi_hash_map_remove_all (ctx->extended_neighbors,
                                            &peer->hashPubKey);

          neighbor = GNUNET_malloc (sizeof (struct GNUNET_dv_neighbor));
          neighbor->cost = cost;
          neighbor->neighbor = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
          memcpy (neighbor->neighbor, peer, sizeof (GNUNET_PeerIdentity));

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

          GNUNET_DV_Heap_insert (&ctx->neighbor_max_heap, neighbor);
          GNUNET_DV_Heap_insert (&ctx->neighbor_min_heap, neighbor);
        }
    }


#if DEBUG_DV
  print_tables ();
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Exiting addUpdateNeighbor\n");
#endif

  GNUNET_mutex_unlock (ctx->dvMutex);
  return ret;
}

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

  ret = addUpdateNeighbor (&nmsg->neighbor, sender, ntohl (nmsg->cost) + 1);

  if (GNUNET_OK != ret)
    GNUNET_GE_LOG (coreAPI->ectx,
                   GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                   _("Problem adding/updating neighbor in `%s'\n"), "dv");

#if DEBUG_DV
  GNUNET_hash_to_enc (&sender->hashPubKey, &from);
  GNUNET_hash_to_enc (&nmsg->neighbor.hashPubKey, &about);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "Received info about peer %s from directly connected peer %s\n",
                 (char *) &about, (char *) &from);
#endif
  return ret;
}

/*
 * Handles a peer connect notification, eliminates any need for polling.
 * @param peer - ident of the connected peer
 * @param unused - unused closure arg
 */
static void
peer_connect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
#if DEBUG_DV
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Entering peer_connect_handler:\n");
  GNUNET_mutex_lock (ctx->dvMutex);
  print_tables ();
  GNUNET_mutex_unlock (ctx->dvMutex);

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
      neighbor->neighbor = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
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
          neighbor->cost = cost;
          /*GNUNET_multi_hash_map_put (ctx->direct_neighbors, &peer->hashPubKey,
             neighbor,
             GNUNET_MultiHashMapOption_REPLACE); */
        }

    }
  GNUNET_mutex_unlock (ctx->dvMutex);
  addUpdateNeighbor (peer, NULL, cost);

#if DEBUG_DV
  GNUNET_mutex_lock (ctx->dvMutex);
  print_tables ();
  GNUNET_mutex_unlock (ctx->dvMutex);
#endif
  return;

}

/*
 * A callback for deleting nodes from heaps...
 */
static int
delete_callback (struct GNUNET_dv_neighbor *neighbor,
                 struct GNUNET_dv_heap *root, void *cls)
{
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
      GNUNET_DV_Heap_removeNode (&ctx->neighbor_max_heap, neighbor);
      GNUNET_DV_Heap_removeNode (&ctx->neighbor_min_heap, neighbor);
      GNUNET_multi_hash_map_remove_all (ctx->extended_neighbors,
                                        &neighbor->neighbor->hashPubKey);

      GNUNET_free (neighbor->neighbor);
      if (neighbor->referrer != NULL)
        GNUNET_free (neighbor->referrer);
      GNUNET_free (neighbor);
    }
  return GNUNET_OK;
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
                 GNUNET_GE_BULK, "Entering peer_disconnect_handler\n");
  GNUNET_hash_to_enc (&peer->hashPubKey, &myself);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "disconnected peer: %s\n", (char *) &myself);
  GNUNET_mutex_lock (ctx->dvMutex);
  print_tables ();
  GNUNET_mutex_unlock (ctx->dvMutex);
#endif

  GNUNET_mutex_lock (ctx->dvMutex);

  if (GNUNET_YES ==
      GNUNET_multi_hash_map_contains (ctx->direct_neighbors,
                                      &peer->hashPubKey))
    {
      neighbor =
        GNUNET_multi_hash_map_get (ctx->direct_neighbors, &peer->hashPubKey);

      GNUNET_multi_hash_map_remove_all (ctx->direct_neighbors,
                                        &peer->hashPubKey);
      if (neighbor != NULL)
        {
          GNUNET_DV_Heap_Iterator (&ctx->neighbor_max_heap,
                                   ctx->neighbor_max_heap.root,
                                   &delete_callback, (void *) peer);

          GNUNET_free (neighbor->neighbor);
          if (neighbor->referrer != NULL)
            GNUNET_free (neighbor->referrer);

          GNUNET_free (neighbor);

        }
    }

  GNUNET_mutex_unlock (ctx->dvMutex);
#if DEBUG_DV
  GNUNET_mutex_lock (ctx->dvMutex);
  print_tables ();
  GNUNET_mutex_unlock (ctx->dvMutex);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Exiting peer_disconnect_handler\n");
#endif
  return;
}

static struct GNUNET_dv_neighbor *
chooseToNeighbor ()
{
  if (GNUNET_multi_hash_map_size (ctx->direct_neighbors) == 0)
    return NULL;

  return (struct GNUNET_dv_neighbor *)
    GNUNET_multi_hash_map_get_random (ctx->direct_neighbors);
}

static struct GNUNET_dv_neighbor *
chooseAboutNeighbor ()
{
  if (ctx->neighbor_min_heap.size == 0)
    return NULL;

#if DEBUG_DV
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Min heap size %d\nMax heap size %d\n",
                 ctx->neighbor_min_heap.size, ctx->neighbor_max_heap.size);
#endif

  return GNUNET_DV_Heap_Walk_getNext (&ctx->neighbor_min_heap);

}

static void *
neighbor_send_thread (void *rcls)
{
#if DEBUG_DV
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Entering neighbor_send_thread...\n");
  GNUNET_EncName encPeerAbout;
  GNUNET_EncName encPeerTo;
#endif
  struct GNUNET_dv_neighbor *about = NULL;
  struct GNUNET_dv_neighbor *to = NULL;

  p2p_dv_MESSAGE_NeighborInfo *message =
    GNUNET_malloc (sizeof (p2p_dv_MESSAGE_NeighborInfo));

  message->header.size = htons (sizeof (p2p_dv_MESSAGE_NeighborInfo));
  message->header.type = htons (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);

  while (!ctx->closing)
    {
      //updateSendInterval();
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
                         "Sending info about peer %s to directly connected peer %s\n",
                         (char *) &encPeerAbout, (char *) &encPeerTo);
#endif
          message->cost = htonl (about->cost);
          memcpy (&message->neighbor, about->neighbor,
                  sizeof (GNUNET_PeerIdentity));
          coreAPI->ciphertext_send (to->neighbor, &message->header, 0,
                                    ctx->send_interval *
                                    GNUNET_CRON_MILLISECONDS);
        }
      GNUNET_thread_sleep (ctx->send_interval * GNUNET_CRON_MILLISECONDS);
    }

  GNUNET_free (message);
  return NULL;
}

int
initialize_module_dv (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;
  unsigned long long max_hosts;

  ctx = GNUNET_malloc (sizeof (struct GNUNET_DV_Context));

  ctx->neighbor_min_heap.type = GNUNET_DV_MIN_HEAP;
  ctx->neighbor_max_heap.type = GNUNET_DV_MAX_HEAP;
  ctx->neighbor_min_heap.max_size = GNUNET_DV_MAX_TABLE_SIZE;
  ctx->neighbor_max_heap.max_size = GNUNET_DV_MAX_TABLE_SIZE;
  ctx->neighbor_max_heap.traversal_pos = NULL;
  ctx->neighbor_min_heap.traversal_pos = NULL;
  ctx->send_interval = GNUNET_DV_DEFAULT_SEND_INTERVAL;
  ctx->dvMutex = GNUNET_mutex_create (GNUNET_NO);
  coreAPI = capi;
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 _("`%s' registering P2P handler %d\n"),
                 "dv", GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);


  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DV",
                                            "FISHEYEDEPTH",
                                            0, -1, 3, &ctx->fisheye_depth);

  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DV",
                                            "TABLESIZE",
                                            0, -1, 100, &ctx->max_table_size);

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


  sendingThread =
    GNUNET_thread_create (&neighbor_send_thread, &coreAPI, 1024 * 1);

  return ok;
}

void
done_module_dv ()
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

  GNUNET_mutex_destroy (ctx->dvMutex);
  coreAPI = NULL;
}

/* end of dv.c */
