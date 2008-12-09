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
#include "dv.h"

#define DEBUG_DV
/**
 * TODO: Add code for initialization/maintenance of directly
 * connected and all known, code for sending and receiving neighbor lists
 * (more likely sending and receiving incrementally) and . ? . ? .
 */

// CG: if you must have globals, you MUST make them
//     all "static", we do not want to have
//     a global symbol "closing"!
unsigned long long fisheye_depth;
unsigned long long max_table_size;
unsigned int send_interval = 1000;

// CG: all static/global variables are initially
//     set to zero, so = 0 is superfluous.
unsigned int curr_neighbor_table_size = 0;
unsigned int curr_connected_neighbor_table_size = 0;
unsigned short closing = 0;

static struct GNUNET_ThreadHandle *connectionThread;

// CG: document each struct 
struct GNUNET_dv_neighbor
{
  /**
   * Generic list structure for neighbor lists
   */
  struct GNUNET_dv_neighbor *next;
  struct GNUNET_dv_neighbor *prev;

  /**
   * Identity of neighbor
   */
  GNUNET_PeerIdentity *neighbor;

  /**
   * Identity of referrer (where we got the information)
   */
  GNUNET_PeerIdentity *referrer;

  /**
   * Cost to neighbor, used for actual distance vector computations
   */
  unsigned int cost;
};

struct GNUNET_dv_neighbor *neighbors;
struct GNUNET_dv_neighbor *connected_neighbors;

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_Mutex *dvMutex;

static void
printTables ()
{
  struct GNUNET_dv_neighbor *pos;
  unsigned int count;
  GNUNET_EncName encPeer;

  pos = connected_neighbors;
  count = 0;
  fprintf (stderr, "Directly connected neighbors:\n");
  while (pos != NULL)
    {
      GNUNET_hash_to_enc (&pos->neighbor->hashPubKey, &encPeer);
      fprintf (stderr, "\t%d : %s\n", count, (char *) &encPeer);
      pos = pos->next;
      count++;
    }

  fprintf (stderr, "Known neighbors:\n");
  pos = neighbors;
  count = 0;
  while (pos != NULL)
    {
      GNUNET_hash_to_enc (&pos->neighbor->hashPubKey, &encPeer);
      fprintf (stderr, "\t%d : %s\n", count, (char *) &encPeer);
      pos = pos->next;
      count++;
    }

}
static int
p2pHandleDVNeighborMessage (const GNUNET_PeerIdentity * sender,
                            const GNUNET_MessageHeader * message)
{
  int ret = GNUNET_OK;
  const p2p_dv_MESSAGE_NeighborInfo *nmsg;

  if (ntohs (message->size) < sizeof (p2p_dv_MESSAGE_NeighborInfo))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;     /* invalid message */
    }
  nmsg = (const p2p_dv_MESSAGE_NeighborInfo *) message;
  /*
   * Need to fix nmsg->cost comparison to make sense!
   */
  /*if ((nmsg->cost + 1 <= fisheye_depth) && (findNeighbor(&nmsg->neighbor,sender) == NULL)) */

  ret = addUpdateNeighbor (&nmsg->neighbor, sender, ntohl (nmsg->cost));

  if (GNUNET_OK != ret)
    GNUNET_GE_LOG (coreAPI->ectx,
                   GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                   _("Problem adding/updating neighbor in `%s'\n"), "dv");

  return ret;
}

/*
 * Handles the receipt of a peer disconnect notification.
 *
 */
static void
peer_disconnect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
  GNUNET_EncName myself;
  struct GNUNET_dv_neighbor *pos = neighbors;
  struct GNUNET_dv_neighbor *temp = NULL;

#ifdef DEBUG_DV
  fprintf (stderr, "Entering peer_disconnect_handler\n");
  GNUNET_hash_to_enc (&peer->hashPubKey, &myself);
  fprintf (stderr, "disconnected peer: %s\n", (char *) &myself);
  printTables ();
#endif
  GNUNET_mutex_lock (dvMutex);

  while (pos != NULL)
    {
      if (memcmp (peer, pos->referrer, sizeof (GNUNET_PeerIdentity)) == 0)
        {
          if (pos->prev != NULL)
            pos->prev->next = pos->next;
          else
            neighbors = pos->next;

          if (pos->next != NULL)
            pos->next->prev = pos->prev;

          temp = pos->next;
          GNUNET_free (pos->neighbor);
          if (pos->referrer != NULL)
            GNUNET_free (pos->referrer);
          GNUNET_free (pos);
          pos = temp;
          curr_neighbor_table_size--;
        }
      else
        pos = pos->next;
    }

  pos = connected_neighbors;
  while (pos != NULL)
    {
      if (memcmp (peer, pos->neighbor, sizeof (GNUNET_PeerIdentity)) == 0)
        {
          if (pos->prev != NULL)
            pos->prev->next = pos->next;
          else
            connected_neighbors = pos->next;

          if (pos->next != NULL)
            pos->next->prev = pos->prev;

          temp = pos->next;
          GNUNET_free (pos->neighbor);
          if (pos->referrer != NULL)
            GNUNET_free (pos->referrer);
          GNUNET_free (pos);
          pos = temp;
          curr_connected_neighbor_table_size--;
        }
      else
        pos = pos->next;
    }

  GNUNET_mutex_unlock (dvMutex);
#ifdef DEBUG_DV
  printTables ();
  fprintf (stderr, "Exiting peer_disconnect_handler\n");
#endif
  return;
}

/*
 * Finds a neighbor in the distance vector table.  Logically there is only one
 * routing table, but for optimization purposes they are separated into those
 * that are directly connected, and those that are known by reference.
 *
 * @param neighbor peer to look up
 * @param connected which list to look in
 */
struct GNUNET_dv_neighbor *
findNeighbor (const GNUNET_PeerIdentity * neighbor, short connected)
{
#ifdef DEBUG_DV
  fprintf (stderr, "Entering findNeighbor\n");
#endif
  struct GNUNET_dv_neighbor *pos;
  if (connected)
    pos = connected_neighbors;
  else
    pos = neighbors;

  while (pos != NULL)
    {
      if (memcmp (neighbor, pos->neighbor, sizeof (GNUNET_PeerIdentity)) == 0)
        {
#ifdef DEBUG_DV
          fprintf (stderr, "FOUND Neighbor!!!\n");
#endif
          return pos;

        }
      pos = pos->next;
    }
#ifdef DEBUG_DV
  fprintf (stderr, "Exiting findNeighbor\n");
#endif
  return pos;
}

static int
addUpdateNeighbor (const GNUNET_PeerIdentity * neighbor,
                   const GNUNET_PeerIdentity * referrer, unsigned int cost)
{
#ifdef DEBUG_DV
  fprintf (stderr, "Entering addUpdateNeighbor\n");
  if (referrer == NULL)
    fprintf (stderr, "Referrer is NULL\n");
#endif
  int ret = GNUNET_OK;

  GNUNET_mutex_lock (dvMutex);
  GNUNET_EncName encPeer;
  struct GNUNET_dv_neighbor *dv_neighbor;

#ifdef DEBUG_DV
  GNUNET_hash_to_enc (&neighbor->hashPubKey, &encPeer);
  fprintf (stderr, "Adding Node %s\n", (char *) &encPeer);
#endif

  if (referrer == NULL)
    dv_neighbor = findNeighbor (neighbor, 1);
  else
    dv_neighbor = findNeighbor (neighbor, 0);

  if (dv_neighbor != NULL)
    {
      if (dv_neighbor->cost != cost)
        {
          dv_neighbor->cost = cost;
        }
      if ((referrer != NULL) && (dv_neighbor->referrer != NULL)
          &&
          (memcmp
           (dv_neighbor->referrer, referrer,
            sizeof (GNUNET_PeerIdentity)) != 0))
        {
          GNUNET_free (dv_neighbor->referrer);
          dv_neighbor->referrer =
            GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
          memcpy (dv_neighbor->referrer, referrer,
                  sizeof (GNUNET_PeerIdentity));
        }
      else if ((referrer != NULL) && (dv_neighbor->referrer == NULL))
        {
          dv_neighbor->referrer =
            GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
          memcpy (dv_neighbor->referrer, referrer,
                  sizeof (GNUNET_PeerIdentity));
        }
    }
  else
    {

      dv_neighbor = GNUNET_malloc (sizeof (struct GNUNET_dv_neighbor));
      dv_neighbor->neighbor = malloc (sizeof (GNUNET_PeerIdentity));
      memcpy (dv_neighbor->neighbor, neighbor, sizeof (GNUNET_PeerIdentity));
      dv_neighbor->cost = cost;

      if (referrer != NULL)
        {
          dv_neighbor->referrer = malloc (sizeof (GNUNET_PeerIdentity));
          memcpy (dv_neighbor->referrer, referrer,
                  sizeof (GNUNET_PeerIdentity));
          dv_neighbor->prev = NULL;
          if (neighbors != NULL)
            neighbors->prev = dv_neighbor;
          dv_neighbor->next = neighbors;
          neighbors = dv_neighbor;
          curr_neighbor_table_size++;
        }
      else
        {
          dv_neighbor->referrer = NULL;

          dv_neighbor->prev = NULL;
          if (connected_neighbors != NULL)
            connected_neighbors->prev = dv_neighbor;
          dv_neighbor->next = connected_neighbors;
          connected_neighbors = dv_neighbor;
          curr_connected_neighbor_table_size++;
        }
    }

#ifdef DEBUG_DV
  printTables ();
  fprintf (stderr, "Exiting addUpdateNeighbor\n");
#endif

  GNUNET_mutex_unlock (dvMutex);
  return ret;
}


static void
initialAddNeighbor (const GNUNET_PeerIdentity * neighbor, void *cls)
{
  addUpdateNeighbor (neighbor, NULL, GNUNET_DV_LEAST_COST);
  return;
}

static void *
connection_poll_thread (void *rcls)
{
  while (!closing)
    {
#ifdef DEBUG_DV
      fprintf (stderr, "Polling connections...\n");
#endif
      coreAPI->p2p_connections_iterate (&initialAddNeighbor, NULL);
      GNUNET_thread_sleep (15 * GNUNET_CRON_SECONDS);
    }

  return NULL;
}

static void *
neighbor_send_thread (void *rcls)
{
#ifdef DEBUG_DV
  fprintf (stderr, "Entering neighbor_send_thread...\n");
  GNUNET_EncName encPeerAbout;
  GNUNET_EncName encPeerTo;
#endif
  struct GNUNET_dv_neighbor *about = NULL;
  struct GNUNET_dv_neighbor *to = NULL;

  p2p_dv_MESSAGE_NeighborInfo *message =
    GNUNET_malloc (sizeof (p2p_dv_MESSAGE_NeighborInfo));

  message->header.size = htons (sizeof (p2p_dv_MESSAGE_NeighborInfo));
  message->header.type = htons (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);
  message->reserved = htonl (0);

  while (!closing)
    {
      //updateSendInterval();
      about = chooseAboutNeighbor ();
      to = chooseToNeighbor ();

      if ((about != NULL) && (to != NULL)
          && (memcmp (about->neighbor, to->neighbor, sizeof (GNUNET_HashCode))
              != 0))
        {
#ifdef DEBUG_DV
          GNUNET_hash_to_enc (&about->neighbor->hashPubKey, &encPeerAbout);
          GNUNET_hash_to_enc (&to->neighbor->hashPubKey, &encPeerTo);
          fprintf (stderr,
                   "Sending info about peer %s to directly connected peer %s\n",
                   (char *) &encPeerAbout, (char *) &encPeerTo);
#endif
          message->cost = htonl (about->cost);
          memcpy (&message->neighbor, about->neighbor,
                  sizeof (GNUNET_PeerIdentity));
          coreAPI->ciphertext_send (to->neighbor, &message->header, 0,
                                    send_interval * GNUNET_CRON_MILLISECONDS);
        }

      GNUNET_thread_sleep (send_interval * GNUNET_CRON_MILLISECONDS);
    }

  GNUNET_free (message);
#ifdef DEBUG_DV
  fprintf (stderr, "Exiting neighbor_send_thread...\n");
#endif
  return NULL;
}

// CG: unless defined in a header and used by 
//     other C source files (or used with dlsym),'
//     make sure all of your functions are declared "static"
struct GNUNET_dv_neighbor *
chooseToNeighbor ()
{
  if (!(curr_connected_neighbor_table_size > 0))
    return NULL;
  unsigned int rand =
    GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                       curr_connected_neighbor_table_size);
  int i;
  struct GNUNET_dv_neighbor *pos = connected_neighbors;
#ifdef DEBUG_DV
  fprintf (stderr, "# Connected: %d Rand: %d\n",
           curr_connected_neighbor_table_size, rand);
#endif
  i = 0;
  while ((pos != NULL) && (i < rand))
    {
      pos = pos->next;
      i++;
    }

  return pos;
}

struct GNUNET_dv_neighbor *
chooseAboutNeighbor ()
{
  if (!(curr_connected_neighbor_table_size + curr_neighbor_table_size > 0))
    return NULL;
  int rand =
    GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                       curr_connected_neighbor_table_size +
                       curr_neighbor_table_size);
  int i;
  struct GNUNET_dv_neighbor *pos;
#ifdef DEBUG_DV
  fprintf (stderr, "Table size %d Rand %d\n",
           curr_connected_neighbor_table_size + curr_neighbor_table_size,
           rand);
#endif
  if (rand < curr_connected_neighbor_table_size)
    pos = connected_neighbors;
  else
    {
      pos = neighbors;
      rand = rand - curr_connected_neighbor_table_size;
    }

  i = 0;
  while ((pos != NULL) && (i < rand))
    {
      pos = pos->next;
      i++;
    }

  return pos;
}

int
initialize_module_dv (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;
  dvMutex = GNUNET_mutex_create (GNUNET_NO);
  coreAPI = capi;
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering P2P handler %d\n"),
                 "dv", GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);

  neighbors = NULL;
  connected_neighbors = NULL;

  if (GNUNET_SYSERR ==
      coreAPI->
      peer_disconnect_notification_register (&peer_disconnect_handler, NULL))
    ok = GNUNET_SYSERR;


  if (GNUNET_SYSERR ==
      coreAPI->
      p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE,
                                       &p2pHandleDVNeighborMessage))
    ok = GNUNET_SYSERR;

  connectionThread =
    GNUNET_thread_create (&connection_poll_thread, NULL, 1024 * 16);
  GNUNET_thread_create (&neighbor_send_thread, &coreAPI, 1024 * 1);


  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DV",
                                            "FISHEYEDEPTH",
                                            0, -1, 3, &fisheye_depth);

  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DV",
                                            "TABLESIZE",
                                            0, -1, 100, &max_table_size);

  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "dv",
                                                                   _
                                                                   ("enables distance vector type routing (wip)")));

  return ok;
}

void
done_module_dv ()
{
  closing = 1;
  coreAPI->
    p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE,
                                       &p2pHandleDVNeighborMessage);

  coreAPI->peer_disconnect_notification_unregister (&peer_disconnect_handler,
                                                    NULL);


  GNUNET_mutex_destroy (dvMutex);
  coreAPI = NULL;
}

/* end of dv.c */
