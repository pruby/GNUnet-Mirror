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
 * @file applications/vpn/p2p.c
 * @author Michael John Wensley
 * @brief handling of P2P messages for VPN
 *
 * TODO:
 * - do not use HANG UP as a shutdown notification; we have a better API now!
 * - define and use structs for messages
 */
#include "vpn.h"
#include "p2p.h"
#include "helper.h"

/**
 * Pass IP packet to tap. Which tap depends on what the GNUNET_PeerIdentity is.
 * If we've not seen the peer before, create a new TAP and tell our thread about it?
 * else scan the array of TAPS and copy the message into it.
 *
 * Mainly this routine exchanges the GNUNET_MessageHeader on incoming ipv6 packets
 * for a TUN/TAP header for writing it to TUNTAP.
 */
static int
p2p_handle_vpn_aip_ip (const GNUNET_PeerIdentity * sender,
                       const GNUNET_MessageHeader * gp)
{
  int i = 0, fd;
  char loginfo[100];

  char frame[IP_FRAME + sizeof (struct tun_pi)];
  const struct ip6_hdr *fp = (struct ip6_hdr *) (gp + 1);
  struct ip6_hdr *new_fp =
    (struct ip6_hdr *) (((char *) &frame) + sizeof (struct tun_pi));
  struct tun_pi *tp = (struct tun_pi *) (&frame);

  tp->flags = 0;

  /* better check src/dst IP for anonymity preservation requirements here...
   * I.e. in fd::/8 and check next header as well.
   *
   * Also permit multicast [ RFC 3306 ] ff3x:0030:fdnn:nnnn:nnnn::/96
   * where x = diameter. n are the random bits from the allocater's IP
   * (and must match the sender's )
   * 30 = usual bit length of a sender's node/network-prefix,
   * we allow longer, and that must match sender if specified.
   */
  switch (((struct iphdr *) fp)->version)
    {
    case 6:
      tp->proto = htons (ETH_P_IPV6);
      if (ntohs (fp->ip6_src.s6_addr16[0]) < 0xFD00)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                         GNUNET_GE_REQUEST,
                         _("VPN IP src not anonymous. drop..\n"));
          return GNUNET_OK;
        }
      if (ntohs (fp->ip6_dst.s6_addr16[0]) < 0xFD00)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                         GNUNET_GE_REQUEST,
                         _("VPN IP not anonymous, drop.\n"));
          return GNUNET_OK;
        }
      break;
    case 4:
      tp->proto = htons (ETH_P_IP);
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                     GNUNET_GE_REQUEST,
                     _("VPN Received, not anonymous, drop.\n"));
      return GNUNET_OK;
    default:
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("VPN Received unknown IP version %d...\n"),
                     ((struct iphdr *) fp)->version);
      return GNUNET_OK;
    }

  ipinfo (loginfo, fp);

  /* do packet memcpy outside of mutex for speed */
  memcpy (new_fp, fp, ntohs (gp->size) - sizeof (GNUNET_MessageHeader));

  GNUNET_mutex_lock (lock);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                 _("<- GNUnet(%d) : %s\n"),
                 ntohs (gp->size) - sizeof (GNUNET_MessageHeader), loginfo);
  for (i = 0; i < entries1; i++)
    {
      if (isEqual (sender, &((store1 + i)->peer)))
        {
          fd = ((store1 + i)->fd);

          (store1 + i)->active = GNUNET_YES;

          /* We are only allowed one call to write() per packet.
           * We need to write packet and packetinfo together in one go.
           */
          write (fd, tp,
                 ntohs (gp->size) + sizeof (struct tun_pi) -
                 sizeof (GNUNET_MessageHeader));
          coreAPI->preferTrafficFrom (&((store1 + i)->peer), 1000);
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
    }
  /* do not normally get here... but checkensure so any future packets could be routed... */
  checkensure_peer (sender, NULL);
  GNUNET_mutex_unlock (lock);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                 GNUNET_GE_REQUEST,
                 _
                 ("Could not write the tunnelled IP to the OS... Did to setup a tunnel?\n"));
  return GNUNET_OK;
}

static int
p2p_handle_pong (const GNUNET_PeerIdentity * sender,
                 const GNUNET_MessageHeader * gp)
{
  GNUNET_mutex_lock (lock);
  checkensure_peer (sender, NULL);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/* FIXME: use connection shutdown handler
   instead -- we may not always get a hangup! */
static int
p2p_handle_hang_up (const GNUNET_PeerIdentity * sender,
                    const GNUNET_MessageHeader * gp)
{
  int i;

  GNUNET_mutex_lock (lock);
  for (i = 0; i < entries1; i++)
    {
      if ((((store1 + i)->fd) > 0) && isEqual (sender, &((store1 + i)->peer)))
        {
          (store1 + i)->active = GNUNET_NO;
        }
    }
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

static int
p2p_handle_vpn_aip_getroute (const GNUNET_PeerIdentity * sender,
                             const GNUNET_MessageHeader * gp)
{
  int i;
  GNUNET_MessageHeader *rgp;
  const struct ip6_hdr *fp = (struct ip6_hdr *) (gp + 1);

  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                 _("Receive route request\n"));
  if (ntohs (gp->size) == (sizeof (GNUNET_MessageHeader) + sizeof (int)))
    {
      i = ntohl (*((int *) fp));
      GNUNET_mutex_lock (lock);
      if (i < realised_entries)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_BULK |
                         GNUNET_GE_ADMIN,
                         _("Prepare route announcement level %d\n"), i);
          rgp =
            GNUNET_malloc (sizeof (GNUNET_MessageHeader) +
                           sizeof (transit_route));
          rgp->size =
            htons (sizeof (GNUNET_MessageHeader) + sizeof (transit_route));
          rgp->type = htons (GNUNET_P2P_PROTO_AIP_ROUTE);
          ((transit_route *) (rgp + 1))->owner = (realised_store + i)->owner;
          ((transit_route *) (rgp + 1))->hops =
            htonl ((realised_store + i)->hops);
          GNUNET_mutex_unlock (lock);
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_BULK |
                         GNUNET_GE_ADMIN,
                         _
                         ("Send route announcement %d with route announce\n"),
                         i);
          /* it must be delivered if possible, but it can wait longer than IP */
          coreAPI->unicast (sender, rgp, GNUNET_EXTREME_PRIORITY, 15);
          GNUNET_free (rgp);
          return GNUNET_OK;
        }
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                     _("Send outside table info %d\n"), i);
      rgp = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + sizeof (int));
      rgp->size = htons (sizeof (GNUNET_MessageHeader) + sizeof (int));
      rgp->type = htons (GNUNET_P2P_PROTO_AIP_ROUTES);
      *((int *) (rgp + 1)) = htonl (realised_entries);
      GNUNET_mutex_unlock (lock);
      coreAPI->unicast (sender, rgp, GNUNET_EXTREME_PRIORITY, 15);
      GNUNET_free (rgp);
      return GNUNET_OK;
    }
  return GNUNET_OK;
}

static int
p2p_handle_vpn_aip_route (const GNUNET_PeerIdentity * sender,
                          const GNUNET_MessageHeader * gp)
{
  int i;
  GNUNET_MessageHeader *rgp;

  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                 _("Receive route announce.\n"));
  /** peer sent us a route, insert it into routing table, then req next entry */
  if (ntohs (gp->size) ==
      (sizeof (GNUNET_MessageHeader) + sizeof (transit_route)))
    {
      GNUNET_mutex_lock (lock);
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                     _("Going to try insert route into local table.\n"));
      for (i = 0; i < entries1; i++)
        {
          if (isEqual (sender, &((store1 + i)->peer)))
            {
              (store1 + i)->active = GNUNET_YES;
              GNUNET_GE_LOG (coreAPI->ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_BULK |
                             GNUNET_GE_ADMIN,
                             _("Inserting with hops %d\n"),
                             ntohl (((transit_route *) (gp + 1))->hops));
              add_route (&(((transit_route *) (gp + 1))->owner),
                         1 + ntohl (((transit_route *) (gp + 1))->hops), i);
              if ((store1 + i)->route_entry < GNUNET_VIEW_LIMIT)
                {
                  (store1 + i)->route_entry++;
                  rgp =
                    GNUNET_malloc (sizeof (GNUNET_MessageHeader) +
                                   sizeof (int));
                  rgp->type = htons (GNUNET_P2P_PROTO_AIP_GETROUTE);
                  rgp->size =
                    htons (sizeof (GNUNET_MessageHeader) + sizeof (int));
                  *((int *) (rgp + 1)) = htonl ((store1 + i)->route_entry);
                  GNUNET_GE_LOG (coreAPI->ectx,
                                 GNUNET_GE_DEBUG | GNUNET_GE_BULK |
                                 GNUNET_GE_ADMIN,
                                 _("Request level %d from peer %d\n"),
                                 (store1 + i)->route_entry, i);
                  coreAPI->unicast (&((store1 + i)->peer), rgp,
                                    GNUNET_EXTREME_PRIORITY, 60);
                  GNUNET_free (rgp);
                }
              break;
            }
        }
      GNUNET_mutex_unlock (lock);
    }
  return GNUNET_OK;
}

static int
p2p_handle_vpn_aip_routes (const GNUNET_PeerIdentity * sender,
                           const GNUNET_MessageHeader * gp)
{
  const struct ip6_hdr *fp = (struct ip6_hdr *) (gp + 1);

  if (ntohs (gp->size) == (sizeof (GNUNET_MessageHeader) + sizeof (int)))
    {
      /* if this is the last route message, we do route realisation
       * that is, insert the routes into the operating system.
       */
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                     _("Receive table limit on peer reached %d\n"),
                     ntohl (*((int *) fp)));
      /*                GNUNET_mutex_lock(lock);
         for (i = 0; i < entries1; i++) {
         if (isEqual(sender, &((store1+i)->peer))) {
         GNUNET_GE_LOG (coreAPI->ectx,
         GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
         _("Storing table limit %d for peer %d\n"), ntohl( *((int*)fp)), i );
         (store1+i)->route_limit = ntohl( *((int*)fp));
         break;
         }
         }
         GNUNET_mutex_unlock(lock);
       */ }
  return GNUNET_OK;
}


int
GNUNET_VPN_p2p_handler_init (GNUNET_CoreAPIForPlugins * capi)
{
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_AIP_IP, &p2p_handle_vpn_aip_ip))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_AIP_GETROUTE,
                             &p2p_handle_vpn_aip_getroute))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_AIP_ROUTE,
                             &p2p_handle_vpn_aip_route))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_AIP_ROUTES,
                             &p2p_handle_vpn_aip_routes))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_PONG, &p2p_handle_pong))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_HANG_UP, &p2p_handle_hang_up))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

int
GNUNET_VPN_p2p_handler_done ()
{
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_AIP_IP,
                              &p2p_handle_vpn_aip_ip);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_AIP_GETROUTE,
                              &p2p_handle_vpn_aip_getroute);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_AIP_ROUTE,
                              &p2p_handle_vpn_aip_route);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_AIP_ROUTES,
                              &p2p_handle_vpn_aip_routes);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_PONG, &p2p_handle_pong);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_HANG_UP, &p2p_handle_hang_up);
  return GNUNET_OK;
}


/* end of p2p.c */
