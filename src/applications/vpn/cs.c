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
 * @author Christian Grothoff (code clean up)
 * @brief methods for interaction with gnunet-vpn tool
 *
 * TODO:
 * - define structs for some of the messages
 *   => eliminate mallocs!
 */

#include "vpn.h"
#include "cs.h"
#include "helper.h"

/**
 * send given string to client
 */
static void
cprintf (struct GNUNET_ClientHandle *c, unsigned short t, const char *format,
         ...)
{
  va_list args;
  int size;
  GNUNET_MessageHeader *b;

  size = GNUNET_MAX_BUFFER_SIZE - sizeof (GNUNET_MessageHeader) - 8;
  b = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + size);
  va_start (args, format);
  size = VSNPRINTF ((char *) &b[1], size, format, args);
  va_end (args);
  if (size > 0)
    {
      b->type = htons (t);
      b->size = htons (sizeof (GNUNET_MessageHeader) + size);
      coreAPI->cs_send_message (c, b, GNUNET_YES);
    }
  GNUNET_free (b);
}

/**
 * Convert a PeerIdentify into a "random" RFC4193 prefix.
 * We make the first 40 bits of the GNUNET_hash into the prefix!
 */
static void
id2ip (struct GNUNET_ClientHandle *cx, const GNUNET_PeerIdentity * them)
{
  cprintf (cx,
           GNUNET_CS_PROTO_VPN_REPLY,
           "fd%02x:%02x%02x:%02x%02x",
           (them->hashPubKey.bits[0] >> 8) & 0xff,
           (them->hashPubKey.bits[0] >> 0) & 0xff,
           (them->hashPubKey.bits[1] >> 8) & 0xff,
           (them->hashPubKey.bits[1] >> 0) & 0xff,
           (them->hashPubKey.bits[2] >> 8) & 0xff);
}


/** The console client is used to admin/debug vpn */
static int
cs_handle_vpn_tunnels (struct GNUNET_ClientHandle *c,
                       const GNUNET_MessageHeader * message)
{
  int i;

  GNUNET_mutex_lock (lock);
  id2ip (c, coreAPI->my_identity);
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
  return GNUNET_OK;
}

static int
cs_handle_vpn_routes (struct GNUNET_ClientHandle *c,
                      const GNUNET_MessageHeader * message)
{
  int i;
  GNUNET_PeerIdentity id;

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
  return GNUNET_OK;
}

static int
cs_handle_vpn_realised (struct GNUNET_ClientHandle *c,
                        const GNUNET_MessageHeader * message)
{
  int i;
  GNUNET_PeerIdentity id;

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
  return GNUNET_OK;
}

static int
cs_handle_vpn_reset (struct GNUNET_ClientHandle *c,
                     const GNUNET_MessageHeader * message)
{
  int i;
  GNUNET_MessageHeader *rgp;

  GNUNET_mutex_lock (lock);
  init_router ();
  for (i = 0; i < entries1; i++)
    {
      (store1 + i)->route_entry = 0;
      /* lets send it to everyone - expect response only from VPN enabled nodes tho :-) */
      /* if ((store1+i)->active != GNUNET_YES) continue; */
      rgp = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + sizeof (int));
      rgp->type = htons (GNUNET_P2P_PROTO_AIP_GETROUTE);
      rgp->size = htons (sizeof (GNUNET_MessageHeader) + sizeof (int));
      *((int *) (rgp + 1)) = htonl ((store1 + i)->route_entry);
      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
               "Request level %d from peer %d ",
               (store1 + i)->route_entry, i);
      id2ip (c, &((store1 + i)->peer));
      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, "\n");
      coreAPI->ciphertext_send (&((store1 + i)->peer), rgp,
                                GNUNET_EXTREME_PRIORITY, 60);
      GNUNET_free (rgp);
    }
  GNUNET_mutex_unlock (lock);
  cprintf (c, GNUNET_CS_PROTO_VPN_RESET, "Rebuilding routing tables done\n");
  return GNUNET_OK;
}

static int
cs_handle_vpn_trust (struct GNUNET_ClientHandle *c,
                     const GNUNET_MessageHeader * message)
{
  int i;

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
  return GNUNET_OK;
}

static int
cs_handle_vpn_add (struct GNUNET_ClientHandle *c,
                   const GNUNET_MessageHeader * message)
{
  unsigned int parameter =
    ntohs (message->size) - sizeof (GNUNET_MessageHeader);
  const char *ccmd = (const char *) &message[1];
  GNUNET_MessageHeader *rgp;
  GNUNET_PeerIdentity id;
  char *parm;

  if (parameter == 0)
    return GNUNET_SYSERR;
  parm = GNUNET_malloc (parameter + 1);
  strncpy (parm, ccmd, parameter);
  *(parm + parameter) = 0;
  if (GNUNET_OK != GNUNET_enc_to_hash (parm, &(id.hashPubKey)))
    {
      GNUNET_free (parm);
      return GNUNET_SYSERR;
    }
  GNUNET_free (parm);
  if (0)
    {
      /* this does not seem to work, strangeness with threads and capabilities? */
      GNUNET_mutex_lock (lock);
      checkensure_peer (&id, NULL);
      GNUNET_mutex_unlock (lock);
    }
  /* get it off the local blacklist */
  identity->whitelistHost (&id);
  cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, "Connect ");
  id2ip (c, &id);
  switch (session->tryConnect (&id))
    {
    case GNUNET_YES:
      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, " already connected.\n");
      break;
    case GNUNET_NO:
      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, " schedule connection.\n");
      break;
    case GNUNET_SYSERR:
      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, " core refused.\n");
      break;
    default:
      GNUNET_GE_BREAK (NULL, 0);
      break;
    }
  if (0)
    {
      /* req route level 0 */
      rgp = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + sizeof (int));
      rgp->type = htons (GNUNET_P2P_PROTO_AIP_GETROUTE);
      rgp->size = htons (sizeof (GNUNET_MessageHeader) + sizeof (int));
      *((int *) &rgp[1]) = 0;
      coreAPI->ciphertext_send (&id, rgp, GNUNET_EXTREME_PRIORITY,
                                4 * GNUNET_CRON_MILLISECONDS);
      cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, " Sent");
      GNUNET_free (rgp);
    }
  cprintf (c, GNUNET_CS_PROTO_VPN_ADD, "\n");
  return GNUNET_OK;
}


int
GNUNET_VPN_cs_handler_init (GNUNET_CoreAPIForPlugins * capi)
{
  if (GNUNET_SYSERR ==
      capi->cs_handler_register (GNUNET_CS_PROTO_VPN_TUNNELS,
                                 &cs_handle_vpn_tunnels))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->cs_handler_register (GNUNET_CS_PROTO_VPN_ROUTES,
                                 &cs_handle_vpn_routes))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->cs_handler_register (GNUNET_CS_PROTO_VPN_REALISED,
                                 &cs_handle_vpn_realised))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->cs_handler_register (GNUNET_CS_PROTO_VPN_RESET,
                                 &cs_handle_vpn_reset))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->cs_handler_register (GNUNET_CS_PROTO_VPN_TRUST,
                                 &cs_handle_vpn_trust))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->cs_handler_register (GNUNET_CS_PROTO_VPN_ADD, &cs_handle_vpn_add))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

int
GNUNET_VPN_cs_handler_done ()
{
  coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_VPN_TUNNELS,
                                  &cs_handle_vpn_tunnels);
  coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_VPN_ROUTES,
                                  &cs_handle_vpn_routes);
  coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_VPN_REALISED,
                                  &cs_handle_vpn_realised);
  coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_VPN_RESET,
                                  &cs_handle_vpn_reset);
  coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_VPN_TRUST,
                                  &cs_handle_vpn_trust);
  coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_VPN_ADD,
                                  &cs_handle_vpn_add);
  return GNUNET_OK;
}

/* end of cs.c */
