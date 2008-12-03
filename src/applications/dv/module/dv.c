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

/**
 * TODO: add structures for directly connected, all known nodes, and neighbor
 * all known nodes.  Add code for initialization/maintenance of directly
 * connected and all known, code for sending and receiving neighbor lists
 * (more likely sending and receiving incrementally), code for initialization
 * and death of the module, and....
 */

unsigned long long fisheye_depth;
unsigned long long max_table_size;
unsigned short curr_table_size;
unsigned short closing = 0;

struct GNUNET_dv_neighbor
{
  /**
   * Generic list structure for neighbor lists
   */
  struct GNUNET_dv_neighbor *next;

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

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_Mutex *dvMutex;

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

  ret = addUpdateNeighbor (&nmsg->neighbor, sender, nmsg->cost);

  if (GNUNET_OK != ret)
    GNUNET_GE_LOG (coreAPI->ectx,
                   GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                   _("Problem adding/updating neighbor in `%s'\n"), "dv");

  return ret;
}

static void
peer_disconnect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
  struct GNUNET_dv_neighbor *pos = neighbors;
  struct GNUNET_dv_neighbor *prev = NULL;
  int not_found = 1;
  GNUNET_mutex_lock (dvMutex);
  while ((pos->next != NULL) && (not_found))
    {
      prev = pos;
      if (memcmp (&peer, &pos->next->neighbor, sizeof (GNUNET_PeerIdentity))
          == 0)
        not_found = 0;
      pos = pos->next;
    }
  if ((prev == NULL)
      && (memcmp (&peer, &pos->next->neighbor, sizeof (GNUNET_PeerIdentity))
          == 0))
    {
      if (neighbors->referrer != NULL)
        GNUNET_free (neighbors->referrer);
      GNUNET_free (neighbors);
      neighbors = NULL;
      curr_table_size = 0;
    }
  else if (prev != NULL)
    {
      prev->next = pos->next;
      GNUNET_free (pos->neighbor);
      if (pos->referrer != NULL)
        GNUNET_free (pos->referrer);
      GNUNET_free (pos);
    }
  GNUNET_mutex_unlock (dvMutex);
  return;
}

struct GNUNET_dv_neighbor *
findNeighbor (const GNUNET_PeerIdentity * neighbor,
              const GNUNET_PeerIdentity * referrer)
{
  struct GNUNET_dv_neighbor *pos = neighbors;

  while (pos != NULL)
    {
      if (memcmp (&neighbor, &pos->neighbor, sizeof (GNUNET_PeerIdentity)) ==
          0)
        {
          if ((referrer == NULL) && (&pos->referrer == NULL))
            return pos;
          else if ((referrer != NULL) && (&pos->referrer != NULL)
                   &&
                   (memcmp
                    (&referrer, &pos->referrer,
                     sizeof (GNUNET_PeerIdentity)) == 0))
            return pos;
        }
      pos = pos->next;
    }
  return pos;
}

static int
addUpdateNeighbor (const GNUNET_PeerIdentity * neighbor,
                   const GNUNET_PeerIdentity * referrer, unsigned int cost)
{
  int ret = GNUNET_OK;

  GNUNET_mutex_lock (dvMutex);
  struct GNUNET_dv_neighbor *dv_neighbor = findNeighbor (neighbor, referrer);

  if (dv_neighbor != NULL)
    {
      if (dv_neighbor->cost != cost)
        {
          dv_neighbor->cost = cost;
        }
    }
  else
    {
      dv_neighbor = GNUNET_malloc (sizeof (struct GNUNET_dv_neighbor));
      dv_neighbor->cost = cost;
      dv_neighbor->neighbor = malloc (sizeof (GNUNET_PeerIdentity));
      memcpy (&dv_neighbor->neighbor, &neighbor,
              sizeof (GNUNET_PeerIdentity));

      if (referrer != NULL)
        {
          dv_neighbor->referrer = malloc (sizeof (GNUNET_PeerIdentity));
          memcpy (&dv_neighbor->referrer, &referrer,
                  sizeof (GNUNET_PeerIdentity));
        }
      else
        {
          dv_neighbor->referrer = NULL;
        }

      dv_neighbor->next = neighbors;
      neighbors = dv_neighbor;
      curr_table_size++;
    }
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
connection_poll_dv_calc_thread (void *rcls)
{
  static GNUNET_CoreAPIForPlugins *capi = rcls;

  while (!closing)
    {
      capi->p2p_connections_iterate (&initialAddNeighbor, (void *) NULL);
      GNUNET_thread_sleep (30 * GNUNET_CRON_SECONDS);
    }

}

int
initialize_module_dv (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;

  coreAPI = capi;
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering handler %d\n"),
                 "dv", GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);

  if (GNUNET_SYSERR ==
      capi->peer_disconnect_notification_register (&peer_disconnect_handler,
                                                   NULL))
    ok = GNUNET_SYSERR;

  if (GNUNET_SYSERR ==
      capi->
      p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE,
                                       &p2pHandleDVNeighborMessage))
    ok = GNUNET_SYSERR;

  GNUNET_thread_create (&connection_poll_thread, &coreAPI, 1024 * 4);

  /*
     if (GNUNET_SYSERR == capi->p2p_connections_iterate(&initialAddNeighbor,
     (void *)NULL))
     ok = GNUNET_SYSERR;
   */

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
  dvMutex = GNUNET_mutex_create (GNUNET_NO);
  return ok;
}

void
done_module_dv ()
{
  closing = 1;
  coreAPI->
    p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE,
                                       &p2pHandleDVNeighborMessage);

  GNUNET_mutex_destroy (dvMutex);
  coreAPI = NULL;
}

/* end of dv.c */
