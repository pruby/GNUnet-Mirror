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

struct GNUNET_dv_connected_neighbor
{
  /**
   * Generic list structure for neighbor lists
   */
  struct GNUNET_dv_connected_neighbor *next;

  /**
   * Neighbor list of neighbor
   */
  struct GNUNET_dv_extended_neighbor *neighbors;

  /**
   * Identity of neighbor
   */
  GNUNET_PeerIdentity *neighbor;

  /**
   * Distance (hops) to neighbor, should never be in list if larger than
   * fisheye_distance.
   */
  unsigned int distance;

  /**
   * Sequence number of value, used to decide if data is new (could compare
   * values either/as well)
   */
  unsigned int sequence_number;

  /**
   * Cost to neighbor, used for actual distance vector computations
   */
  unsigned int cost;
};

struct GNUNET_dv_extended_neighbor
{
  /**
   * Generic list structure for neighbor lists
   */
  struct GNUNET_dv_extended_neighbor *next;

  /**
   * Identity of neighbor
   */
  GNUNET_PeerIdentity *neighbor;

  /**
   * Identity of referrer (where we got the information)
   */
  GNUNET_PeerIdentity *referrer;

  /**
   * Distance (hops) to neighbor, should never be in list if larger than
   * fisheye_distance.
   */
  unsigned int distance;

  /**
   * Sequence number of value, used to decide if data is new (could compare
   * values either/as well)
   */
  unsigned int sequence_number;

  /**
   * Cost to neighbor, used for actual distance vector computations
   */
  unsigned int cost;
};


struct GNUNET_dv_connected_neighbor *connected_neighbors;

struct GNUNET_dv_extended_neighbor *extended_neighbors;

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
  if ((nmsg->distance + 1 <= fisheye_depth) && (findConnectedNeighbor(&nmsg->neighbor) == NULL))
    ret = addUpdateExtendedNeighbor(sender,&nmsg->neighbor, nmsg->cost, nmsg->distance, nmsg->sequence_number);
  if (GNUNET_OK != ret)
    GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     _("Problem adding neighbor in `%s'\n"),
                     "dv");

  return ret;
}

static void
peer_disconnect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
  struct GNUNET_dv_connected_neighbor *pos = connected_neighbors;
  struct GNUNET_dv_connected_neighbor *prev = NULL;
  int not_found = 1;

  while ((pos->next != NULL) && (not_found))
  {
    prev = pos;
    if (memcmp(&peer, &pos->next->neighbor, sizeof(GNUNET_PeerIdentity)) == 0)
      not_found = 0;
    pos = pos->next;
  }
  if ((prev == NULL) && (memcmp(&peer, &pos->next->neighbor, sizeof(GNUNET_PeerIdentity)) == 0))
  {
    GNUNET_free(connected_neighbors->neighbor);
    if (connected_neighbors->neighbors != NULL)
    {
      //Free all neighbors list, not sure what that requires yet!
    }
    GNUNET_free(connected_neighbors);
    connected_neighbors = NULL;
  }
  else if (prev != NULL)
  {
    prev->next = pos->next;
    GNUNET_free(pos->neighbor);
    if (pos->neighbors != NULL)
    {
      //Free all neighbors list, not sure what that requires yet!
    }
    GNUNET_free(pos);
  }

  return;
}

struct GNUNET_dv_connected_neighbor
*findConnectedNeighbor(const GNUNET_PeerIdentity *neighbor)
{
  struct GNUNET_dv_connected_neighbor *pos = connected_neighbors;

  while (pos != NULL)
  {
    if (memcmp(&neighbor, &pos->neighbor, sizeof(GNUNET_PeerIdentity)) == 0)
      return pos;
    pos = pos->next;
  }
  return pos;
}

static int
addUpdateConnectedNeighbor(const GNUNET_PeerIdentity *neighbor, unsigned int cost, unsigned int distance, unsigned int sequence_number)
{
  int ret = GNUNET_OK;
  struct GNUNET_dv_connected_neighbor *dv_neighbor = findConnectedNeighbor(neighbor);

  if (dv_neighbor != NULL)
  {
    if ((dv_neighbor->sequence_number < sequence_number) || (sequence_number == 0))
    {
      GNUNET_mutex_lock(dvMutex);
      dv_neighbor->cost = cost;
      dv_neighbor->distance = distance;
      dv_neighbor->sequence_number = sequence_number;
      GNUNET_mutex_unlock(dvMutex);
    }
  }
  else
  {
    dv_neighbor = GNUNET_malloc(sizeof(struct GNUNET_dv_connected_neighbor));

    dv_neighbor->cost = cost;
    dv_neighbor->distance = distance;
    dv_neighbor->sequence_number = sequence_number;
    dv_neighbor->neighbor = malloc(sizeof(GNUNET_PeerIdentity));
    memcpy(&dv_neighbor->neighbor, &neighbor, sizeof(GNUNET_PeerIdentity));

    GNUNET_mutex_lock(dvMutex);
    dv_neighbor->next = connected_neighbors;
    connected_neighbors = dv_neighbor;
    GNUNET_mutex_unlock(dvMutex);
  }

  return ret;
}

static int
addUpdateExtendedNeighbor(const GNUNET_PeerIdentity *neighbor, const GNUNET_PeerIdentity *referent, unsigned int cost, unsigned int distance, unsigned int sequence_number)
{
  int ret = GNUNET_OK;
  struct GNUNET_dv_extended_neighbor *dv_neighbor = findExtendedNeighbor(neighbor);

  if (dv_neighbor != NULL)
  {
    if ((dv_neighbor->sequence_number < sequence_number) || (sequence_number == 0))
    {
      GNUNET_mutex_lock(dvMutex);
      dv_neighbor->cost = cost;
      dv_neighbor->distance = distance;
      dv_neighbor->sequence_number = sequence_number;
      GNUNET_mutex_unlock(dvMutex);
    }
  }
  else
  {
    dv_neighbor = GNUNET_malloc(sizeof(struct GNUNET_dv_extended_neighbor));

    dv_neighbor->cost = cost;
    dv_neighbor->distance = distance;
    dv_neighbor->sequence_number = sequence_number;
    dv_neighbor->neighbor = malloc(sizeof(GNUNET_PeerIdentity));
    memcpy(&dv_neighbor->neighbor, &neighbor, sizeof(GNUNET_PeerIdentity));

    GNUNET_mutex_lock(dvMutex);
    dv_neighbor->next = connected_neighbors;
    connected_neighbors = dv_neighbor;
    GNUNET_mutex_unlock(dvMutex);
  }

  return ret;
}


static void
initialAddConnectedNeighbor(const GNUNET_PeerIdentity *neighbor, void *cls)
{
  addUpdateConnectedNeighbor(neighbor, GNUNET_DV_LEAST_COST, GNUNET_DV_MAX_DISTANCE, GNUNET_DV_INITIAL_SEQUENCE_NUMBER);
  return;
}

int
initialize_module_dv (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;

  coreAPI = capi;
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering handler %d\n"),
                 "dv",GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);

  if (GNUNET_SYSERR ==
      capi->peer_disconnect_notification_register (&peer_disconnect_handler,
                                                 NULL))
    ok = GNUNET_SYSERR;

  if (GNUNET_SYSERR ==
      capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE,
                                 &p2pHandleDVNeighborMessage))
    ok = GNUNET_SYSERR;

  if (GNUNET_SYSERR == capi->p2p_connections_iterate(&initialAddConnectedNeighbor,
      (void *)NULL))
    ok = GNUNET_SYSERR;

  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                              "DV",
                                              "FISHEYEDEPTH",
                                              0, -1, 3, &fisheye_depth);

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

  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE,
                                  &p2pHandleDVNeighborMessage);

  GNUNET_mutex_destroy (dvMutex);
  coreAPI = NULL;
}

/* end of dv.c */
