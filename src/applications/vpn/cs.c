/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/vpn/cs.c
 * @author Michael John Wensley
 * @brief tunnel RFC 4193 in GNUnet
 *
 * TODO:
 * - split up into individual handlers
 * - export only initialization and shutdown
 *   methods taking coreAPI
 * - eliminate useless locking
 */

#include "vpn.h"
#include "cs.h"
#include "helper.h"

/** The console client is used to admin/debug vpn */
int
csHandle (struct GNUNET_ClientHandle *c, const GNUNET_MessageHeader * message)
{
  GNUNET_MessageHeader *rgp = NULL;
  int i;
  GNUNET_PeerIdentity id;
  int parameter = ntohs (message->size) - sizeof (GNUNET_MessageHeader);
  char *ccmd = (char *) (message + 1);
  char *parm;

  /* issued command from client */
  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_MSG)
    {
      if (ntohs (message->size) == 0)
        return GNUNET_OK;
    }
  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_TUNNELS)
    {
      GNUNET_mutex_lock (lock);
      id2ip (c, coreAPI->myIdentity);
      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, "::/48 This Node\n");
      for (i = 0; i < entries1; i++)
        {
          id2ip (c, &(store1 + i)->peer);
          cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                   "::/48 gnu%d active=%s routeentry=%d\n", (store1 + i)->id,
                   (store1 + i)->active ? _("Yes") : _("No"),
                   (store1 + i)->route_entry);
        }
      cprintf (c, GNUNET_CS_PROTO_VPN_TUNNELS, "%d Tunnels\n", entries1);
      GNUNET_mutex_unlock (lock);
    }
  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_ROUTES)
    {
      GNUNET_mutex_lock (lock);
      for (i = 0; i < route_entries; i++)
        {
          identity->getPeerIdentity (&(route_store + i)->owner, &id);
          id2ip (c, &id);
          if ((route_store + i)->hops == 0)
            {
              cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                       "::/48 hops 0 (This Node)\n");
            }
          else
            {
              cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                       "::/48 hops %d tunnel gnu%d\n",
                       (route_store + i)->hops,
                       (store1 + ((route_store + i)->tunnel))->id);
            }
        }
      cprintf (c, GNUNET_CS_PROTO_VPN_ROUTES, "%d Routes\n", route_entries);
      GNUNET_mutex_unlock (lock);
    }
  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_REALISED)
    {
      GNUNET_mutex_lock (lock);
      for (i = 0; i < realised_entries; i++)
        {
          identity->getPeerIdentity (&(realised_store + i)->owner, &id);
          id2ip (c, &id);
          if ((realised_store + i)->hops == 0)
            {
              cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                       "::/48 hops 0 (This Node)\n");
            }
          else
            {
              cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                       "::/48 hops %d tunnel gnu%d\n",
                       (realised_store + i)->hops,
                       (store1 + ((realised_store + i)->tunnel))->id);
            }
        }
      cprintf (c, GNUNET_CS_PROTO_VPN_REALISED, "%d Realised\n",
               realised_entries);
      GNUNET_mutex_unlock (lock);
    }
  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_RESET)
    {
      GNUNET_mutex_lock (lock);
      init_router ();
      for (i = 0; i < entries1; i++)
        {
          (store1 + i)->route_entry = 0;
          /* lets send it to everyone - expect response only from VPN enabled nodes tho :-) */
/*  		if ((store1+i)->active == GNUNET_YES) { */
          rgp = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + sizeof (int));
          if (rgp == NULL)
            {
              break;
            }
          rgp->type = htons (GNUNET_P2P_PROTO_AIP_GETROUTE);
          rgp->size = htons (sizeof (GNUNET_MessageHeader) + sizeof (int));
          *((int *) (rgp + 1)) = htonl ((store1 + i)->route_entry);
          cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                   "Request level %d from peer %d ",
                   (store1 + i)->route_entry, i);
          id2ip (c, &((store1 + i)->peer));
          cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, "\n");
          coreAPI->unicast (&((store1 + i)->peer), rgp,
                            GNUNET_EXTREME_PRIORITY, 60);
          GNUNET_free (rgp);
/*  		}	*/
        }
      GNUNET_mutex_unlock (lock);
      cprintf (c, GNUNET_CS_PROTO_VPN_RESET,
               "Rebuilding routing tables done\n");
    }
  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_TRUST)
    {
      GNUNET_mutex_lock (lock);
      for (i = 0; i < entries1; i++)
        {
          if ((store1 + i)->active == GNUNET_YES)
            {
              cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, "Uprating peer ");
              id2ip (c, &(store1 + i)->peer);
              cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, " with credit %d\n",
                       identity->changeHostTrust (&(store1 + i)->peer, 1000));
            }
        }
      cprintf (c, GNUNET_CS_PROTO_VPN_TRUST,
               "Gave credit to active nodes of %d nodes...\n", entries1);
      GNUNET_mutex_unlock (lock);
    }
  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_ADD)
    {
      if (parameter > 0)
        {
          if ((parm = GNUNET_malloc (parameter + 1)) != NULL)
            {
              strncpy (parm, ccmd, parameter);
              *(parm + parameter) = 0;
              cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, "Connect ");
              if (GNUNET_OK == GNUNET_enc_to_hash (parm, &(id.hashPubKey)))
                {
                  id2ip (c, &id);

                  /* this does not seem to work, strangeness with threads and capabilities?
                   * GNUNET_mutex_lock(lock);
                   * checkensure_peer(&id, NULL);
                   * GNUNET_mutex_unlock(lock);
                   */

                  /* get it off the local blacklist */
                  identity->whitelistHost (&id);

                  switch (session->tryConnect (&id))
                    {
                    case GNUNET_YES:
                      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                               " already connected.\n");
                      break;
                    case GNUNET_NO:
                      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                               " schedule connection.\n");
                      break;
                    case GNUNET_SYSERR:
                      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                               " core refused.\n");
                      break;
                    default:
                      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                               " misc error.\n");
                      break;
                    }

                  /* req route level 0
                     rgp = GNUNET_malloc(sizeof(GNUNET_MessageHeader) + sizeof(int));
                     if (rgp != NULL) {
                     rgp->type = htons(GNUNET_P2P_PROTO_AIP_GETROUTE);
                     rgp->size = htons(sizeof(GNUNET_MessageHeader) + sizeof(int));
                     *((int*)(rgp+1)) = 0;
                     coreAPI->unicast(&id,rgp,GNUNET_EXTREME_PRIORITY,4);
                     cprintf(c, " Sent");
                     GNUNET_free(rgp);
                     } */

                  cprintf (c, GNUNET_CS_PROTO_VPN_ADD, "\n");
                }
              else
                {
                  cprintf (c, GNUNET_CS_PROTO_VPN_ADD,
                           "Could not decode PeerId %s from parameter.\n",
                           parm);

                }
              GNUNET_free (parm);
            }
          else
            {
              cprintf (c, GNUNET_CS_PROTO_VPN_ADD,
                       "Could not allocate for key.\n");
            }
        }
      else
        {
          cprintf (c, GNUNET_CS_PROTO_VPN_ADD, "Require key for parameter\n");
        }
    }
  return GNUNET_OK;
}
