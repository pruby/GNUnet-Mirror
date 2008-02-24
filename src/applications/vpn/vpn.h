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
 * @file applications/vpn/vpn.h
 * @author Michael John Wensley
 * @brief tunnel RFC 4193 in GNUnet
 *
 *
 * http://gnunet.wensley.org.uk/
 *
 * Yes this will thoroughly break most of the coding guidelines :-/ at least the first release.
 *
 * We use IPv6 addresses because they provide a larger space, and are
 * not as likely to be in use by other applications such as NAT.
 *
 * We also follow the guidance in RFC4193 and use only the 40 bits
 * specified for the randomly generated publickey. This allows nodes
 * to connect subnets to the network.
 *
 * It also allows interoperation with other users of this space such
 * as anonymous internets. We use GNUnet to benefit from its key
 * infrastructure, though other users may well rip fdxx:: bits
 * directly from public keys, using the private key to GNUNET_RSA_sign
 * route announcements.
 *
 * CHANGELOG:
 * 20060110 Change ifconfig/route to ioctl's
 * 20060111 P2P packet includes length of the header.
 * 20060802 Logging for multiple clients
 */
#ifndef VPN_H
#define VPN_H

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "gnunet_session_service.h"


/* i'm going to put platform dependent code here for now */
#include <linux/if_tun.h>
#include <linux/if_ether.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

/* require struct in6_rtmsg */
#include <net/route.h>

/* This is derived from ifconfig source code... in6_ifreq needed from <linux/ipv6.h> */
#include <asm/types.h>
#ifndef _LINUX_IN6_H
struct in6_ifreq
{
  struct in6_addr ifr6_addr;
  __u32 ifr6_prefixlen;
  unsigned int ifr6_ifindex;
};
#endif

/* the idea is that you can use the first subnet number as a persistent identifier for your
 * website, services etc, so numbering of virtual circuits to other nodes begins at 2.
 * If you want to use more subnets locally, you can of course increase this number.
 */
#define VC_START 2

#define MAXSIG_BUF 128

/* Here we define the maximum size of any headers that go in front of IP packets
 * it's the maximum of the GNUnet header and any platform headers, such as TUN/TAP's
 * packet information header on Linux.
 */
#define maxi(a,b) ((a)>(b)?(a):(b))
#define mini(a,b) ((a)<(b)?(a):(b))
#define HEADER_FRAME maxi(sizeof(GNUNET_MessageHeader), sizeof(struct tun_pi))

/* we can't actually send messages this long... maybe 2 bytes shorter tho
 * planned includes a way to send yet longer messages
 */
#define IP_FRAME 65536


/* id = number portion of interface name. I.e. 0 = gnu0, 1= gnu1 ...
 * hd = filedescriptor of this tunnel
 * active = tunnel is in use, i.e. peer is online
 * route_entry = index in the remote node's routing table we have requested
 * ifindex = linux internal number to identify an interface
 */
typedef struct
{
/*  char name[IFNAMSIZ]; */
  int id;
  int fd;
  int active;
  int route_entry;
  int ifindex;
  GNUNET_PeerIdentity peer;
} tunnel_info;

/**
 * Routing goes like this. Gather routes from all peers and put them in prototype store.
 * Only store lowest hop count if get multiple of the same public key from the same peer.
 *
 * When this process is complete, sort (so that 0 hop comes first and put in complete list.
 * complete list used to upload routing table to os.
 *
 * as the routes table can grow very large (need an entry for every reachable node in gnunet!) we can set a limit
 * below (GNUNET_VIEW_LIMIT)
 */

/* This is an entry in the routing table */
typedef struct
{
  /** owner's public key */
  GNUNET_RSA_PublicKey owner;
  /** hops to owner 1 = have a tunnel to owner, 0 = I am the owner.*/
  int hops;
  /** which tunnel entry in tunnels array */
  int tunnel;
} route_info;

/**
 * here we define a constant to limit the growth of your routing tables, and hence memory consumption
 * of course, increasing this helps the network by providing more routes to nodes further away in the mesh,
 * so long as it does not slow down your node significantly. :-)
 * 100 * 30 peers * 1000 (typical size of public key) = 3 meg of ram.
 * 100 * 30 = upto 3000 accessible peers. (reverse exponential will affect this though)
 */
#define GNUNET_VIEW_LIMIT 100

/* same thing as route but without the tunnel info,
 * which is implicit with the sender GNUNET_PeerIdentity anyway.
 *
 * also the fields here are network byte order.
 */
typedef struct
{
  GNUNET_RSA_PublicKey owner;
  int hops;
} transit_route;

extern struct GNUNET_Mutex *lock;

extern GNUNET_CoreAPIForPlugins *coreAPI;

extern GNUNET_Identity_ServiceAPI *identity;

extern GNUNET_Session_ServiceAPI *session;

extern tunnel_info *store1;

extern int entries1;

extern route_info *route_store;

extern int route_entries;

extern route_info *realised_store;

extern int realised_entries;

void init_router (void);

void checkensure_peer (const GNUNET_PeerIdentity * them, void *callerinfo);

void add_route (GNUNET_RSA_PublicKey * them, int hops, int tunnel);

#endif
