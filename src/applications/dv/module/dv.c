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
unsigned int send_interval;
unsigned short curr_table_size;
unsigned short closing = 0;

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

/*
 * Handles the receipt of a peer disconnect notification.
 *
 */
static void
peer_disconnect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
  struct GNUNET_dv_neighbor *pos = neighbors;
  struct GNUNET_dv_neighbor *temp = NULL;

  GNUNET_mutex_lock (dvMutex);

  while (pos != NULL)
  {
  	if ((memcmp (&peer, &pos->neighbor, sizeof (GNUNET_PeerIdentity))
	          == 0) || (memcmp (&peer, &pos->referrer, sizeof (GNUNET_PeerIdentity))
	          == 0))
	  {
	  	if (pos->prev != NULL)
	  	{
	  		pos->prev->next = pos->next;
	  	}
	  	else
	  	{
	  		neighbors = pos->next;
	  	}

	  	if (pos->next != NULL)
	  	{
	  		pos->next->prev = pos->prev;
	  	}

	  	temp = pos->next;
	  	GNUNET_free(pos->neighbor);
	  	if (pos->referrer != NULL)
	  		GNUNET_free(pos->referrer);
	  	GNUNET_free(pos);
	  	pos = temp;
	  }
	  else
	   	pos = pos->next;
  }

	GNUNET_mutex_unlock (dvMutex);
  return;
}

struct GNUNET_dv_neighbor *
findNeighbor (const GNUNET_PeerIdentity * neighbor)
{
  struct GNUNET_dv_neighbor *pos = neighbors;

  while (pos != NULL)
    {
      if (memcmp (&neighbor, &pos->neighbor, sizeof (GNUNET_PeerIdentity)) ==
          0)
        {
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
  struct GNUNET_dv_neighbor *dv_neighbor = findNeighbor (neighbor);

  if (dv_neighbor != NULL)
    {
      if (dv_neighbor->cost != cost)
        {
          dv_neighbor->cost = cost;
        }
      if ((referrer != NULL) && (dv_neighbor->referrer != NULL) && (memcmp(dv_neighbor->referrer,referrer,sizeof(GNUNET_PeerIdentity)) != 0))
      {
      	GNUNET_free(dv_neighbor->referrer);
      	dv_neighbor->referrer = GNUNET_malloc(sizeof(GNUNET_PeerIdentity));
      	memcpy(&dv_neighbor->referrer,&referrer,sizeof(GNUNET_PeerIdentity));
      }
      else if ((referrer != NULL)&&(dv_neighbor->referrer == NULL))
      {
      	dv_neighbor->referrer = GNUNET_malloc(sizeof(GNUNET_PeerIdentity));
      	memcpy(&dv_neighbor->referrer,&referrer,sizeof(GNUNET_PeerIdentity));
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

			dv_neighbor->prev = NULL;
			neighbors->prev = dv_neighbor;
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
connection_poll_thread (void *rcls)
{
  GNUNET_CoreAPIForPlugins *capi = rcls;

  while (!closing)
    {
      capi->p2p_connections_iterate (&initialAddNeighbor, (void *) NULL);
      GNUNET_thread_sleep (30 * GNUNET_CRON_SECONDS);
    }

	return NULL;
}

static void *
neighbor_send_thread (void *rcls)
{

	struct GNUNET_dv_neighbor *about = NULL;
	struct GNUNET_dv_neighbor *to = NULL;
	p2p_dv_MESSAGE_NeighborInfo *message = GNUNET_malloc(sizeof(p2p_dv_MESSAGE_NeighborInfo));

	message->header.size = htons (sizeof(p2p_dv_MESSAGE_NeighborInfo));
	message->header.type = htons (GNUNET_P2P_PROTO_DV_NEIGHBOR_MESSAGE);
	message->reserved = htonl(0);

  while (!closing)
	{
		//updateSendInterval();
		about = chooseAboutNeighbor();
		to = chooseToNeighbor();

		if (message->neighbor != NULL)
		{
			GNUNET_free(message->neighbor);
		}
		message->neighbor = GNUNET_malloc(sizeof(GNUNET_PeerIdentity));
		message->cost = htonl(about->cost);
		memcpy(&message->neighbor,&about->neighbor,sizeof(GNUNET_PeerIdentity));
		coreAPI->ciphertext_send(to->neighbor,&message,0,send_interval * GNUNET_CRON_MILLISECONDS);

		GNUNET_thread_sleep (send_interval * GNUNET_CRON_MILLISECONDS);
	}

  if (message->neighbor != NULL)
	{
		GNUNET_free(message->neighbor);
	}

  GNUNET_free(message);

	return NULL;
}

struct GNUNET_dv_neighbor *
chooseToNeighbor()
{

}

struct GNUNET_dv_neighbor *
chooseAboutNeighbor()
{

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
