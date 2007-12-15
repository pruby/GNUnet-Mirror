/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/vpn/vpn.c
 * @author Michael John Wensley
 * @brief tunnel RFC 4193 in GNUnet
 *
 *
 * http://gnunet.wensley.org.uk/
 *
 * Yes this will thoroughly break most of the coding guidelines :-/ at least the first release.
 *
 * test^h^h^h^hhack cycle goes like this, make; ./install; /etc/init.d/gnunet stop; /etc/init.d/gnunet start
 *
 * We use IPv6 addresses because they provide a larger space, and are
 * not as likely to be in use by other applications such as NAT.
 *
 * we also follow the guidance in RFC4193 and use only the 40 bits specified
 * for the randomly generated publickey. This allows nodes to
 * connect subnets to the network.
 *
 * It also allows interoperation with other users of this
 * space such as anonymous internets. We use GNUnet to benefit from
 * its key infrastructure, though other users may well rip fdxx:: bits directly
 * from public keys, using the private key to GNUNET_RSA_sign route announcements.
 *
 * CHANGELOG:
 * 20060110 Change ifconfig/route to ioctl's
 * 20060111 P2P packet includes length of the header.
 * 20060802 Logging for multiple clients
 */

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

/**
 * Identity service, to reset the core.
 */
static GNUNET_Identity_ServiceAPI *identity;
static GNUNET_Session_ServiceAPI *session;

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_ClientHandle **clients_store;
static int clients_entries;
static int clients_capacity;

static int cdebug;
static int interval = 60;
static struct GNUNET_Mutex *lock;

static struct GNUNET_ThreadHandle *tunThreadInfo;

static struct GNUNET_GE_Context *ectx;

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

/* from bluetooth agent */
static tunnel_info *store1 = NULL;
static int entries1 = 0;
static int capacity1 = 0;

 /**
 * Pipe to communicate with select thread
 * Used to tell it there is something to do...
 */
static int signalingPipe[2];

/** is thread to stop? */
static int running = 0;

static int admin_fd;
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

/* here we define a constant to limit the growth of your routing tables, and hence memory consumption
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

static route_info *route_store = NULL;
static int route_entries = 0;
static int route_capacity = 0;

static route_info *realised_store = NULL;
static int realised_entries = 0;
static int realised_capacity = 0;

/** send given string to client */
static void
cprintf (struct GNUNET_ClientHandle *c, int t, const char *format, ...)
{
  va_list args;
  int r = -1;
  int size = 100;
  GNUNET_MessageHeader *b = NULL, *nb = NULL;

  if ((b = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + size)) == NULL)
    {
      return;
    }
  while (1)
    {
      va_start (args, format);
      r = VSNPRINTF ((char *) (b + 1), size, format, args);
      va_end (args);
      if (r > -1 && r < size)
        break;
      if (r > -1)
        {
          size = r + 1;
        }
      else
        {
          size *= 2;
        }
      if ((nb =
           GNUNET_realloc (b, sizeof (GNUNET_MessageHeader) + size)) == NULL)
        {
          GNUNET_free (b);
          return;
        }
      else
        {
          b = nb;
        }
    }
  b->type = htons (t);
  b->size = htons (sizeof (GNUNET_MessageHeader) + strlen ((char *) (b + 1)));
  if (c != NULL)
    {
      coreAPI->cs_send_to_client (c, b, GNUNET_YES);
    }
  else
    {
      for (r = 0; r < clients_entries; r++)
        {
          coreAPI->cs_send_to_client (*(clients_store + r), b, GNUNET_YES);
        }
    }
  GNUNET_free (b);
}

#define VLOG if ((cdebug & (GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST)) > 0) cprintf(NULL,GNUNET_CS_PROTO_VPN_MSG,

/** Test if two GNUNET_RSA_PublicKey are equal or not */
static int
isEqualP (const GNUNET_RSA_PublicKey * first,
          const GNUNET_RSA_PublicKey * second)
{
  int i;
  int ln = maxi (first->sizen, second->sizen);
  int sn = mini (first->sizen, second->sizen);

  /* compare common mode modulus */
  if (memcmp
      ((first->key) + ((first->sizen) - sn),
       (second->key) + ((second->sizen) - sn), sn) != 0)
    return GNUNET_NO;

  /* difference before n should be 0 */
  for (i = 0; i < (first->sizen) - sn; i++)
    {
      if (*(first->key + i) != 0)
        return GNUNET_NO;
    }
  for (i = 0; i < (second->sizen) - sn; i++)
    {
      if (*(second->key + i) != 0)
        return GNUNET_NO;
    }

  /* compare common mode exponent */
  if (memcmp ((first->key) + ln, (second->key) + ln, GNUNET_RSA_KEY_LEN - ln)
      != 0)
    return GNUNET_NO;

  for (i = first->sizen; i < ln; i++)
    {
      if (*(first->key + i) != 0)
        return GNUNET_NO;
    }
  for (i = second->sizen; i < ln; i++)
    {
      if (*(second->key + i) != 0)
        return GNUNET_NO;
    }

  return GNUNET_YES;
}

/**
 * clear out the prototype routes table
 * called at start or when we know a peer changes its route table.
 */
static void
init_router ()
{
  int reqcapacity;
  route_info *reqstore;
  reqcapacity = sizeof (route_info);
  if (reqcapacity > route_capacity)
    {
      reqstore = GNUNET_realloc (route_store, reqcapacity);
      if (reqstore == NULL)
        return;                 /* not enough ram, cannot init! */
      route_store = reqstore;
      route_capacity = reqcapacity;
    }
  route_entries = 1;
  route_store->hops = 0;        /* us! */
  route_store->tunnel = -1;     /* n/a! */
  route_store->owner = *(identity->getPublicPrivateKey ());     /* us! */
}

/**
 * clear out the actual route at startup only
 */
static void
init_realised ()
{
  int reqcapacity;
  route_info *reqstore;
  reqcapacity = sizeof (route_info);
  if (reqcapacity > realised_capacity)
    {
      reqstore = GNUNET_realloc (realised_store, reqcapacity);
      if (reqstore == NULL)
        return;                 /* not enough ram, cannot init! */
      realised_store = reqstore;
      realised_capacity = reqcapacity;
    }
  realised_entries = 1;
  realised_store->hops = 0;     /* us! */
  realised_store->tunnel = -1;  /* n/a! */
  realised_store->owner = *(identity->getPublicPrivateKey ());  /* us! */
}

/* adds a route to prototype route table, unless it has same GNUNET_RSA_PublicKey and tunnel as another entry */
static void
add_route (GNUNET_RSA_PublicKey * them, int hops, int tunnel)
{
  int i;
  route_info *rstore;
  int rcapacity;

  for (i = 0; i < route_entries; i++)
    {
      if (isEqualP (them, &(route_store + i)->owner))
        {
          if ((route_store + i)->hops == 0)
            {
              /* we don't store alternative routes to ourselves,
               * as we already know how to route to ourself
               */
              VLOG _("Not storing route to myself from peer %d\n"), tunnel);
              return;
            }
          if ((route_store + i)->tunnel == tunnel)
            {
              /* also, we only keep one route to a node per peer,
               * but store the lowest hop count that the peer is advertising for that node.
               */
              (route_store + i)->hops = mini ((route_store + i)->hops, hops);
              VLOG
                _
                ("Duplicate route to node from peer %d, choosing minimum hops"),
                tunnel);
              return;
            }
        }
    }

  route_entries++;
  rcapacity = route_entries * sizeof (route_info);
  if (rcapacity > route_capacity)
    {
      rstore = GNUNET_realloc (route_store, rcapacity);
      if (rstore == NULL)
        {
          route_entries--;
          return;               /* not enough ram, we will have to drop this route. */
        }
      route_capacity = rcapacity;
      route_store = rstore;
    }
  /*
   * we really should keep the route table in ascending hop count order...
   */
  if (route_entries > 0)
    {
      i = route_entries - 1;    /* i = insert location */
      while ((i > 0) && ((route_store + (i - 1))->hops > hops))
        {
          (route_store + i)->hops = (route_store + (i - 1))->hops;
          (route_store + i)->tunnel = (route_store + (i - 1))->hops;
          (route_store + i)->owner = (route_store + (i - 1))->owner;
          i--;
        }
      VLOG _("Inserting route from peer %d in route table at location %d\n"),
        tunnel, i);
      (route_store + i)->hops = hops;
      (route_store + i)->tunnel = tunnel;
      (route_store + i)->owner = *them;
    }
}

/**
 * Render IPv4 or IPv6 packet info for logging.
 */
static void ipinfo (char *info, const struct ip6_hdr *fp)
{
  struct in_addr fr4;
  struct in_addr to4;

  if ((((const struct iphdr *) fp)->version == 4))
    {
      fr4.s_addr = ((const struct iphdr *) fp)->saddr;
      to4.s_addr = ((const struct iphdr *) fp)->daddr;
      sprintf (info, "IPv4 %s -> ", inet_ntoa (fr4));
      strcat (info, inet_ntoa (to4));
      return;
    }
  if ((((const struct iphdr *) fp)->version == 6))
    {
      sprintf (info,
               "IPv6 %x:%x:%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x:%x:%x",
               ntohs (fp->ip6_src.s6_addr16[0]),
               ntohs (fp->ip6_src.s6_addr16[1]),
               ntohs (fp->ip6_src.s6_addr16[2]),
               ntohs (fp->ip6_src.s6_addr16[3]),
               ntohs (fp->ip6_src.s6_addr16[4]),
               ntohs (fp->ip6_src.s6_addr16[5]),
               ntohs (fp->ip6_src.s6_addr16[6]),
               ntohs (fp->ip6_src.s6_addr16[7]),
               ntohs (fp->ip6_dst.s6_addr16[0]),
               ntohs (fp->ip6_dst.s6_addr16[1]),
               ntohs (fp->ip6_dst.s6_addr16[2]),
               ntohs (fp->ip6_dst.s6_addr16[3]),
               ntohs (fp->ip6_dst.s6_addr16[4]),
               ntohs (fp->ip6_dst.s6_addr16[5]),
               ntohs (fp->ip6_dst.s6_addr16[6]),
               ntohs (fp->ip6_dst.s6_addr16[7]));
      return;
    }
  sprintf (info, "IPv%d ?", ((const struct iphdr *) fp)->version);
}

/** check that ethertype matches ip version for incoming packets from linux specific code */
static int valid_incoming (int len, struct tun_pi *tp, struct ip6_hdr *fp)
{
  char info[100];
  if (len > (65535 - sizeof (struct tun_pi)))
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("RFC4193 Frame length %d is too big for GNUnet!\n"),
                     len);
      return GNUNET_NO;
    }
  if (len < sizeof (struct tun_pi))
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("RFC4193 Frame length %d too small\n"), len);
      return GNUNET_NO;
    }
  if ((ntohs (tp->proto) == ETH_P_IP)
      && (((struct iphdr *) fp)->version == 4))
    {
      return GNUNET_YES;
    }
  else if ((ntohs (tp->proto) == ETH_P_IPV6)
           && (((struct iphdr *) fp)->version == 6))
    {
      ipinfo (info, fp);
      VLOG "-> GNUnet(%d) : %s\n", len - sizeof (struct tun_pi), info);
      return GNUNET_YES;
    }
  GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                 _("RFC4193 Ethertype %x and IP version %x do not match!\n"),
                 ntohs (tp->proto), ((struct iphdr *) fp)->version);
  return GNUNET_NO;
}

/** Test if two GNUNET_PeerIdentity are equal or not */
static int isEqual (const GNUNET_PeerIdentity * first,
                    const GNUNET_PeerIdentity * second)
{
  int i;
  for (i = 0; i < 512 / 8 / sizeof (unsigned int); i++)
    {
      if (first->hashPubKey.bits[i] != second->hashPubKey.bits[i])
        {
          return 0;
        }
    }
  return -1;
}

/**
 * Convert a PeerIdentify into a "random" RFC4193 prefix
 * actually we make the first 40 bits of the GNUNET_hash into the prefix!
 */
static void id2ip (struct GNUNET_ClientHandle *cx,
                   const GNUNET_PeerIdentity * them)
{
  unsigned char a, b, c, d, e;
  a = (them->hashPubKey.bits[0] >> 8) & 0xff;
  b = (them->hashPubKey.bits[0] >> 0) & 0xff;
  c = (them->hashPubKey.bits[1] >> 8) & 0xff;
  d = (them->hashPubKey.bits[1] >> 0) & 0xff;
  e = (them->hashPubKey.bits[2] >> 8) & 0xff;
  cprintf (cx, GNUNET_CS_PROTO_VPN_REPLY, "fd%02x:%02x%02x:%02x%02x", a, b, c,
           d, e);
}

/* convert GNUNET_PeerIdentity into network octet order IPv6 address */
static void id2net (struct in6_addr *buf, const GNUNET_PeerIdentity * them)
{
  unsigned char a, b, c, d, e;
  a = (them->hashPubKey.bits[0] >> 8) & 0xff;
  b = (them->hashPubKey.bits[0] >> 0) & 0xff;
  c = (them->hashPubKey.bits[1] >> 8) & 0xff;
  d = (them->hashPubKey.bits[1] >> 0) & 0xff;
  e = (them->hashPubKey.bits[2] >> 8) & 0xff;

  /* we are unique random */
  buf->s6_addr16[0] = htons (0xfd00 + a);
  buf->s6_addr16[1] = htons (b * 256 + c);
  buf->s6_addr16[2] = htons (d * 256 + e);

  /* IPv6 /48 subnet number is zero */
  buf->s6_addr16[3] = 0;

  /* IPV6 /64 interface is zero */
  buf->s6_addr16[4] = 0;
  buf->s6_addr16[5] = 0;
  buf->s6_addr16[6] = 0;
  buf->s6_addr16[7] = 0;
}

static void setup_tunnel (int n, const GNUNET_PeerIdentity * them)
{
  struct ifreq ifr;
  struct in6_ifreq ifr6;
  struct in6_rtmsg rt;
  int i, used, fd, id = 0;


  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 _("RFC4193 Going to try and make a tunnel in slot %d\n"), n);

  fd = open ("/dev/net/tun", O_RDWR);
  if (fd < 0)
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Cannot open tunnel device because of %s"),
                     strerror (fd));
      GNUNET_GE_DIE_STRERROR (ectx,
                              GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                              GNUNET_GE_BULK, "open");
    }
  memset (&ifr, 0, sizeof (ifr));

  /* IFF_TUN = IP Packets
   * IFF_TAP = Ethernet packets
   *
   * IFF_NO_PI = Do not provide packet information
   */

  /* we know its going to be ipv6 cause the version tells us.
   * except that linux *assumes* it will be sent IPv4 frames
   * unless we configure IFF_PI.... hmmmm.... :-/
   * lets see the tun linux module source
   *
   * this needs PI as type = htons(0x86DD)
   * ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
   * We do need PI otherwise TUNTAP assumes it is receiving IPv4...
   */
  ifr.ifr_flags = IFF_TUN;

  /* try various names until we find a free one */
  do
    {
      used = 0;
      for (i = 0; i < entries1; i++)
        {
          if ((store1 + i)->id == id)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_REQUEST,
                             _
                             ("RFC4193 Create skips gnu%d as we are already using it\n"),
                             id);
              id++;
              used = 1;
            }
        }
      if (used == 0)
        {
          sprintf (ifr.ifr_name, "gnu%d", id);
          if (ioctl (fd, TUNSETIFF, (void *) &ifr) < 0)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_ERROR | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _
                             ("Cannot set tunnel name to %s because of %s\n"),
                             ifr.ifr_name, strerror (errno));
              id++;
              used = 1;
            }
          else
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_ERROR | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _("Configured tunnel name to %s\n"),
                             ifr.ifr_name);
            }
        }
    }
  while (used);


  ioctl (fd, TUNSETNOCSUM, 1);
  memcpy (&((store1 + n)->peer), them, sizeof (GNUNET_PeerIdentity));
  (store1 + n)->id = id;
  (store1 + n)->fd = fd;
  (store1 + n)->active = GNUNET_YES;
  (store1 + n)->route_entry = 0;

  /* tun_alloc can change the tunnel name */
  /* strncpy((store1+n)->name, ifr.ifr_name,IFNAMSIZ); */

  /* here we should give the tunnel an IPv6 address and fake up a route to the other end
   * the format looks like this, and the net/host split is fixed at /48 as in rfc4193
   * local /64
   *    net: my GNUNET_PeerIdentity
   *    subnet: interface number+2
   *    interface: NULL
   *
   * remote /48
   *    net: their GNUNET_PeerIdentity
   *    host: NULL (it's not needed for routes)
   */

  /* Run some system commands to set it up... */
/*  sprintf(cmd, "sudo ifconfig %s up", name);
 *  GNUNET_GE_LOG(ectx, GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST, _("RFC4193 Calling %s\n"), cmd);
 *  system(cmd);
 */

  /* Bring interface up, like system("sudo ifconfig %s up"); */

  /* not needed, we already have the iface name ... strncpy(ifr.ifr_name, name, IFNAMSIZ); */
  if (ioctl (admin_fd, SIOCGIFFLAGS, &ifr) < 0)
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Cannot get socket flags for gnu%d because %s\n"), id,
                     strerror (errno));
    }
  else
    {
      ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
      if (ioctl (admin_fd, SIOCSIFFLAGS, &ifr) < 0)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("Cannot set socket flags for gnu%d because %s\n"),
                         id, strerror (errno));
        }
    }

  /* Seems to go better with lower mtu, aka system("sudo ifconfig %s mtu 1280") */
  ifr.ifr_mtu = 1280;
  if (ioctl (admin_fd, SIOCSIFMTU, &ifr) < 0)
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Cannot set MTU for gnu%d because %s\n"), id,
                     strerror (errno));
    }

  /* lets add an IP address... aka "sudo ifconfig %s add %s:%04x::1/64" */
  if (ioctl (admin_fd, SIOCGIFINDEX, &ifr) < 0)
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Cannot get interface index for gnu%d because %s\n"),
                     id, strerror (errno));
    }
  else
    {
      /* note to self... htons(64) = kernel oops. */
      (store1 + n)->ifindex = ifr.ifr_ifindex;
      ifr6.ifr6_prefixlen = 64;
      ifr6.ifr6_ifindex = ifr.ifr_ifindex;
      id2net (&ifr6.ifr6_addr, coreAPI->myIdentity);
      ifr6.ifr6_addr.s6_addr16[3] = htons (n + VC_START);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                     GNUNET_GE_REQUEST,
                     _("IPv6 ifaddr gnu%d - %x:%x:%x:%x:%x:%x:%x:%x/%d\n"),
                     id, ntohs (ifr6.ifr6_addr.s6_addr16[0]),
                     ntohs (ifr6.ifr6_addr.s6_addr16[1]),
                     ntohs (ifr6.ifr6_addr.s6_addr16[2]),
                     ntohs (ifr6.ifr6_addr.s6_addr16[3]),
                     ntohs (ifr6.ifr6_addr.s6_addr16[4]),
                     ntohs (ifr6.ifr6_addr.s6_addr16[5]),
                     ntohs (ifr6.ifr6_addr.s6_addr16[6]),
                     ntohs (ifr6.ifr6_addr.s6_addr16[7]),
                     ifr6.ifr6_prefixlen);
      if (ioctl (admin_fd, SIOCSIFADDR, &ifr6) < 0)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Cannot set interface IPv6 address for gnu%d because %s\n"),
                         id, strerror (errno));
        }

      /* lets add a route to the peer, aka "#sudo route -A inet6 add %s::/48 dev %s" */
      memset ((char *) &rt, 0, sizeof (struct in6_rtmsg));
      /* rtmsg_ifindex would be zero for routes not specifying a device, such as by gateway */
      rt.rtmsg_ifindex = ifr.ifr_ifindex;
      id2net (&rt.rtmsg_dst, them);
      rt.rtmsg_flags = RTF_UP;
      rt.rtmsg_metric = 1;      /* how many hops to owner of public key */
      rt.rtmsg_dst_len = 48;    /* network prefix len is 48 by standard */
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                     GNUNET_GE_REQUEST,
                     _
                     ("IPv6 route gnu%d - destination %x:%x:%x:%x:%x:%x:%x:%x/%d\n"),
                     id, ntohs (rt.rtmsg_dst.s6_addr16[0]),
                     ntohs (rt.rtmsg_dst.s6_addr16[1]),
                     ntohs (rt.rtmsg_dst.s6_addr16[2]),
                     ntohs (rt.rtmsg_dst.s6_addr16[3]),
                     ntohs (rt.rtmsg_dst.s6_addr16[4]),
                     ntohs (rt.rtmsg_dst.s6_addr16[5]),
                     ntohs (rt.rtmsg_dst.s6_addr16[6]),
                     ntohs (rt.rtmsg_dst.s6_addr16[7]), rt.rtmsg_dst_len);
      if (ioctl (admin_fd, SIOCADDRT, &rt) < 0)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Cannot add route IPv6 address for gnu%s because %s\n"),
                         id, strerror (errno));
        }
    }
}

/**
 * See if we already got a TUN/TAP open for the given GNUnet peer. if not, make one, stick
 * GNUNET_PeerIdentity and the filehandle and name of the TUN/TAP in an array so we remember we did it.
 */
static void checkensure_peer (const GNUNET_PeerIdentity * them,
                              void *callerinfo)
{
  int i;
  tunnel_info *rstore1;
  int rcapacity1;

  /* GNUNET_GE_LOG(ectx, GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST, _("RFC4193 Going to checkensure peer %x then\n"), them->hashPubKey.bits[0]); */
  /* first entry in array will be known as gnu0 */

  /* if a tunnel is already setup, we don't setup another */
  for (i = 0; i < entries1; i++)
    {
      if (isEqual (them, &((store1 + i)->peer)))
        {
          (store1 + i)->active = GNUNET_YES;
          return;
        }
    }

  /*
   * append it at the end.
   */
  entries1++;
  rcapacity1 = entries1 * sizeof (tunnel_info);
  if (rcapacity1 > capacity1)
    {
      rstore1 = GNUNET_realloc (store1, rcapacity1);
      if (rstore1 == NULL)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("RFC4193 We have run out of memory and so I can't store a tunnel for this peer.\n"));
          entries1--;
          return;
        }
      store1 = rstore1;
      capacity1 = rcapacity1;
    }

  /* GNUNET_GE_LOG(ectx, GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST, _("RFC4193 Extending array for new tunnel\n")); */
  setup_tunnel ((entries1 - 1), them);
}

/* make new thread...
 * repeat {
 *   call forAllConnectedNodes, create/destroy tunnels to match connected peers, 1 per peer.
 *  Give new tunnels their IPv6 addresses like "ifconfig gnu0 add fdXX:XXXX:XXXX::/48"
 *   SELECT for incoming packets, unicast those thru gnunet, or (pipe activity = exit this thread) or timeout.
 * }
 * own IPv6 addr is fdXX:XXXX:XXXX::P/48 where X= 40 bits own key, P = gnu0 + 2
 * route add -net fdXX(remote key) dev gnu0 is then used.
 */
static void *tunThread (void *arg)
{
  fd_set readSet;
  fd_set errorSet;
  fd_set writeSet;
  int i, ret, max;
  char tmp[MAXSIG_BUF];
  struct stat statinfo;

  /**
   * IP frames are preceeded by the TUN/TAP header (for Linux) or by the GNUnet header
   * other systems like HURD, etc may use different headers
   */
  char frame[IP_FRAME + HEADER_FRAME];
  struct ip6_hdr *fp;
  struct tun_pi *tp;
  GNUNET_MessageHeader *gp;
  struct timeval timeout;

  /* need the cast otherwise it increments by HEADER_FRAME * sizeof(frame) rather than HEADER_FRAME */
  fp = (struct ip6_hdr *) (((char *) &frame) + HEADER_FRAME);

  /* this trick decrements the pointer by the sizes of the respective structs */
  tp = ((struct tun_pi *) fp) - 1;
  gp = ((GNUNET_MessageHeader *) fp) - 1;
  running = 1;
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 _
                 ("RFC4193 Thread running (frame %d tunnel %d f2f %d) ...\n"),
                 fp, tp, gp);

  GNUNET_mutex_lock (lock);
  while (running)
    {

      FD_ZERO (&readSet);
      FD_ZERO (&errorSet);
      FD_ZERO (&writeSet);

      max = signalingPipe[0];

      if (-1 != FSTAT (signalingPipe[0], &statinfo))
        {
          FD_SET (signalingPipe[0], &readSet);
        }
      else
        {
          GNUNET_GE_DIE_STRERROR (ectx,
                                  GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                  GNUNET_GE_BULK, "fstat");
        }
      for (i = 0; i < entries1; i++)
        {
          FD_SET (((store1 + i)->fd), &readSet);
          max = maxi (max, (store1 + i)->fd);
        }
      GNUNET_mutex_unlock (lock);
      timeout.tv_sec = interval;
      timeout.tv_usec = 0;

      ret = SELECT (max + 1, &readSet, &writeSet, &errorSet, &timeout);
      if (ret < 0)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         "From the vpn select: %s\n", strerror (errno));
          running = 0;
          break;
        }
      if (FD_ISSET (signalingPipe[0], &readSet))
        {
          if (0 >= READ (signalingPipe[0], &tmp[0], MAXSIG_BUF))
            GNUNET_GE_LOG_STRERROR (ectx,
                                    GNUNET_GE_WARNING | GNUNET_GE_BULK |
                                    GNUNET_GE_USER,
                                    "vpn could not read from exit control pipe\n");
        }
      GNUNET_mutex_lock (lock);
      for (i = 0; i < entries1; i++)
        {
          if (FD_ISSET (((store1 + i)->fd), &readSet))
            {
              ret = read (((store1 + i)->fd), tp, IP_FRAME);

              /* goodbye IPv6 packet, enjoy the GNUnet... :-)
               * IP is of course very important so it will enjoy
               * the very highest priority
               */
              if (valid_incoming (ret, tp, fp))
                {
                  gp->type = htons (GNUNET_P2P_PROTO_AIP_IP);
                  gp->size =
                    htons (sizeof (GNUNET_MessageHeader) + ret -
                           sizeof (struct tun_pi));
                  coreAPI->unicast (&((store1 + i)->peer), gp,
                                    GNUNET_EXTREME_PRIORITY, 1);
                  coreAPI->preferTrafficFrom (&((store1 + i)->peer), 1000);
                }
            }
          /* we do this here as we get a race if the p2p handler tries it */
          if (((store1 + i)->active) == 0)
            {
              if (close ((store1 + i)->fd) == 0)
                {
                  GNUNET_GE_LOG (ectx,
                                 GNUNET_GE_INFO | GNUNET_GE_REQUEST |
                                 GNUNET_GE_USER,
                                 _("VPN dropping connection %x\n"), i);
                  *(store1 + i) = *(store1 + (entries1 - 1));
                  entries1--;
                }
              else
                {
                  GNUNET_GE_LOG (ectx,
                                 GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                 GNUNET_GE_USER,
                                 _("VPN cannot drop connection %x\n"), i);
                }
            }
        }
/*
  	if (timeout.tv_sec < (interval / 2)) {
  		for (i = 0; i < entries1; i++) {
  			if (((store1+i)->active) > 0) {
  				if (identity->isBlacklisted(&((store1+i)->peer)), GNUNET_YES) {
  					GNUNET_GE_LOG(ectx, GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER, _("RFC4193 --- whitelist of peer %x\n"),
  						(store1+i)->peer.hashPubKey.bits[0]);
  					identity->whitelistHost(&((store1+i)->peer));
  				}
  			}
  		}
  	}
*/
    }
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 _("RFC4193 Thread exiting\n"));
  GNUNET_mutex_unlock (lock);
  return NULL;
}

/**
 * Pass IP packet to tap. Which tap depends on what the GNUNET_PeerIdentity is.
 * If we've not seen the peer before, create a new TAP and tell our thread about it?
 * else scan the array of TAPS and copy the message into it.
 *
 * Mainly this routine exchanges the GNUNET_MessageHeader on incoming ipv6 packets
 * for a TUN/TAP header for writing it to TUNTAP.
 */
static int handlep2pMSG (const GNUNET_PeerIdentity * sender,
                         const GNUNET_MessageHeader * gp)
{
  int i = 0, fd;
  char loginfo[100];

  GNUNET_MessageHeader *rgp = NULL;
  char frame[IP_FRAME + sizeof (struct tun_pi)];
  const struct ip6_hdr *fp = (struct ip6_hdr *) (gp + 1);
  struct ip6_hdr *new_fp =
    (struct ip6_hdr *) (((char *) &frame) + sizeof (struct tun_pi));
  struct tun_pi *tp = (struct tun_pi *) (&frame);

  switch (ntohs (gp->type))
    {
    case GNUNET_P2P_PROTO_AIP_IP:
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
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_REQUEST,
                             _("VPN IP src not anonymous. drop..\n"));
              return GNUNET_OK;
            }
          if (ntohs (fp->ip6_dst.s6_addr16[0]) < 0xFD00)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_REQUEST,
                             _("VPN IP not anonymous, drop.\n"));
              return GNUNET_OK;
            }
          break;
        case 4:
          tp->proto = htons (ETH_P_IP);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                         GNUNET_GE_REQUEST,
                         _("VPN Received, not anonymous, drop.\n"));
          return GNUNET_OK;
        default:
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("VPN Received unknown IP version %d...\n"),
                         ((struct iphdr *) fp)->version);
          return GNUNET_OK;
        }

      ipinfo (loginfo, fp);

      /* do packet memcpy outside of mutex for speed */
      memcpy (new_fp, fp, ntohs (gp->size) - sizeof (GNUNET_MessageHeader));

      GNUNET_mutex_lock (lock);
      VLOG _("<- GNUnet(%d) : %s\n"),
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
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                     GNUNET_GE_REQUEST,
                     _
                     ("Could not write the tunnelled IP to the OS... Did to setup a tunnel?\n"));
      return GNUNET_OK;
    case GNUNET_P2P_PROTO_PONG:
      GNUNET_mutex_lock (lock);
      checkensure_peer (sender, NULL);
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    case GNUNET_P2P_PROTO_HANG_UP:
      GNUNET_mutex_lock (lock);
      for (i = 0; i < entries1; i++)
        {
          if ((((store1 + i)->fd) > 0) &&
              isEqual (sender, &((store1 + i)->peer)))
            {
              (store1 + i)->active = GNUNET_NO;
            }
        }
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    case GNUNET_P2P_PROTO_AIP_GETROUTE:
        /** peer wants an entry from our routing table */
      VLOG _("Receive route request\n"));
      if (ntohs (gp->size) == (sizeof (GNUNET_MessageHeader) + sizeof (int)))
        {
          i = ntohl (*((int *) fp));
          GNUNET_mutex_lock (lock);
          if (i < realised_entries)
            {
              VLOG _("Prepare route announcement level %d\n"), i);
              rgp =
                GNUNET_malloc (sizeof (GNUNET_MessageHeader) +
                               sizeof (transit_route));
              if (rgp == NULL)
                {
                  GNUNET_mutex_unlock (lock);
                  return GNUNET_OK;
                }
              rgp->size =
                htons (sizeof (GNUNET_MessageHeader) +
                       sizeof (transit_route));
              rgp->type = htons (GNUNET_P2P_PROTO_AIP_ROUTE);
              ((transit_route *) (rgp + 1))->owner =
                (realised_store + i)->owner;
              ((transit_route *) (rgp + 1))->hops =
                htonl ((realised_store + i)->hops);
              GNUNET_mutex_unlock (lock);
              VLOG _("Send route announcement %d with route announce\n"), i);
              /* it must be delivered if possible, but it can wait longer than IP */
              coreAPI->unicast (sender, rgp, GNUNET_EXTREME_PRIORITY, 15);
              GNUNET_free (rgp);
              return GNUNET_OK;
            }
          VLOG _("Send outside table info %d\n"), i);
          rgp = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + sizeof (int));
          if (rgp == NULL)
            {
              GNUNET_mutex_unlock (lock);
              return GNUNET_OK;
            }
          rgp->size = htons (sizeof (GNUNET_MessageHeader) + sizeof (int));
          rgp->type = htons (GNUNET_P2P_PROTO_AIP_ROUTES);
          *((int *) (rgp + 1)) = htonl (realised_entries);
          GNUNET_mutex_unlock (lock);
          coreAPI->unicast (sender, rgp, GNUNET_EXTREME_PRIORITY, 15);
          GNUNET_free (rgp);
          return GNUNET_OK;
        }
      return GNUNET_OK;
    case GNUNET_P2P_PROTO_AIP_ROUTE:
      VLOG _("Receive route announce.\n"));
        /** peer sent us a route, insert it into routing table, then req next entry */
      if (ntohs (gp->size) ==
          (sizeof (GNUNET_MessageHeader) + sizeof (transit_route)))
        {
          GNUNET_mutex_lock (lock);
          VLOG _("Going to try insert route into local table.\n"));
          for (i = 0; i < entries1; i++)
            {
              if (isEqual (sender, &((store1 + i)->peer)))
                {
                  (store1 + i)->active = GNUNET_YES;
                  VLOG _("Inserting with hops %d\n"),
                    ntohl (((transit_route *) (gp + 1))->hops));
                  add_route (&(((transit_route *) (gp + 1))->owner),
                             1 + ntohl (((transit_route *) (gp + 1))->hops),
                             i);
                  if ((store1 + i)->route_entry < GNUNET_VIEW_LIMIT)
                    {
                      (store1 + i)->route_entry++;
                      rgp =
                        GNUNET_malloc (sizeof (GNUNET_MessageHeader) +
                                       sizeof (int));
                      if (rgp == NULL)
                        {
                          GNUNET_mutex_unlock (lock);
                          return GNUNET_OK;
                        }
                      rgp->type = htons (GNUNET_P2P_PROTO_AIP_GETROUTE);
                      rgp->size =
                        htons (sizeof (GNUNET_MessageHeader) + sizeof (int));
                      *((int *) (rgp + 1)) =
                        htonl ((store1 + i)->route_entry);
                      VLOG _("Request level %d from peer %d\n"),
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
    case GNUNET_P2P_PROTO_AIP_ROUTES:
      if (ntohs (gp->size) == (sizeof (GNUNET_MessageHeader) + sizeof (int)))
        {
          /* if this is the last route message, we do route realisation
           * that is, insert the routes into the operating system.
           */
          VLOG _("Receive table limit on peer reached %d\n"),
            ntohl (*((int *) fp)));
/*  		GNUNET_mutex_lock(lock);
  	        for (i = 0; i < entries1; i++) {
          	        if (isEqual(sender, &((store1+i)->peer))) {
  				VLOG _("Storing table limit %d for peer %d\n"), ntohl( *((int*)fp)), i );
  				(store1+i)->route_limit = ntohl( *((int*)fp));
  				break;
  			}
  		}
  		GNUNET_mutex_unlock(lock);
*/ }
      return GNUNET_OK;
    }
  return GNUNET_OK;
}

/* here we copy the prototype route table we are collecting from peers to the actual
 * "realised" route table we distribute to peers, and to the kernel's table.
 */
static void realise (struct GNUNET_ClientHandle *c)
{
  int i, j, found;
  GNUNET_PeerIdentity id;
  int reqcapacity;
  route_info *reqstore;
  struct in6_rtmsg rt;

  GNUNET_mutex_lock (lock);
  /* make sure realised table can take the new routes - if it wont, abort now! */
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 _("realise alloc ram\n"));
  if (route_entries > realised_entries)
    {
      reqcapacity = sizeof (route_info) * route_entries;
      if (reqcapacity > realised_capacity)
        {
          reqstore = GNUNET_realloc (realised_store, reqcapacity);
          if (reqstore == NULL)
            {
              cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                       "I cannot up the ram for realised routes.\n");
              GNUNET_mutex_unlock (lock);
              return;
            }
          realised_store = reqstore;
          realised_capacity = reqcapacity;
        }
    }
  /* add routes that are in the new table but not the old */
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 _("realise add routes\n"));
  for (i = 0; i < route_entries; i++)
    {
      found = 0;
      for (j = 0; j < realised_entries; j++)
        {
          /* compare public key */
          if (isEqualP
              (&(route_store + i)->owner, &(realised_store + j)->owner)
              && ((route_store + i)->hops == (realised_store + j)->hops)
              && ((route_store + i)->tunnel == (realised_store + j)->tunnel))
            {
              found = 1;
            }
        }
      /* we are hops == 0
       * hops == 1 auto added by tunneler
       * hops >= 2 added here!
       */
      if (!(found) && ((route_store + i)->hops > 1))
        {
          /* lets add a route to this long remote node */
          memset ((char *) &rt, 0, sizeof (struct in6_rtmsg));
          /* rtmsg_ifindex would be zero for routes not specifying a device, such as by gateway */
          rt.rtmsg_ifindex = (store1 + ((route_store + i)->tunnel))->ifindex;
          identity->getPeerIdentity (&(route_store + i)->owner, &id);
          id2net (&rt.rtmsg_dst, &id);
          rt.rtmsg_flags = RTF_UP;
          rt.rtmsg_metric = (route_store + i)->hops;
          /* how many hops to owner of public key */
          rt.rtmsg_dst_len = 48;        /* always 48 as per RFC4193 */
          cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                   "Add route gnu%d hops %d dst %x:%x:%x:%x:%x:%x:%x:%x/%d\n",
                   id, rt.rtmsg_metric, ntohs (rt.rtmsg_dst.s6_addr16[0]),
                   ntohs (rt.rtmsg_dst.s6_addr16[1]),
                   ntohs (rt.rtmsg_dst.s6_addr16[2]),
                   ntohs (rt.rtmsg_dst.s6_addr16[3]),
                   ntohs (rt.rtmsg_dst.s6_addr16[4]),
                   ntohs (rt.rtmsg_dst.s6_addr16[5]),
                   ntohs (rt.rtmsg_dst.s6_addr16[6]),
                   ntohs (rt.rtmsg_dst.s6_addr16[7]), rt.rtmsg_dst_len);
          if (ioctl (admin_fd, SIOCADDRT, &rt) < 0)
            {
              cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                       "Cannot add route IPv6 address for gnu%s because %s\n",
                       id, strerror (errno));
            }
        }
    }
  cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, "Removing routes\n");
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 _("realise pull routes\n"));
  /* pull routes that are in the old table but not the new */
  for (i = 0; i < realised_entries; i++)
    {
      found = 0;
      for (j = 0; j < route_entries; j++)
        {
          /* compare public key */
          if (isEqualP
              (&(realised_store + i)->owner, &(route_store + j)->owner)
              && ((realised_store + i)->hops == (route_store + j)->hops)
              && ((realised_store + i)->tunnel == (route_store + j)->tunnel))
            {
              found = 1;
            }
        }
      /* we are hops == 0
       * hops == 1 auto added by tunneler
       * hops >= 2 added here!
       */
      if (!(found) && ((realised_store + i)->hops > 1))
        {
          /* remove the route to this long remote node */
          memset ((char *) &rt, 0, sizeof (struct in6_rtmsg));
          /* rtmsg_ifindex would be zero for routes not specifying a device, such as by gateway */
          rt.rtmsg_ifindex =
            (store1 + ((realised_store + i)->tunnel))->ifindex;
          identity->getPeerIdentity (&(realised_store + i)->owner, &id);
          id2net (&rt.rtmsg_dst, &id);
          rt.rtmsg_flags = RTF_UP;
          rt.rtmsg_metric = (realised_store + i)->hops;
          /* how many hops to owner of public key */
          rt.rtmsg_dst_len = 48;        /* always 48 as per RFC4193 */
          cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                   "Delete route gnu%d hops %d dst %x:%x:%x:%x:%x:%x:%x:%x/%d\n",
                   id, rt.rtmsg_metric, ntohs (rt.rtmsg_dst.s6_addr16[0]),
                   ntohs (rt.rtmsg_dst.s6_addr16[1]),
                   ntohs (rt.rtmsg_dst.s6_addr16[2]),
                   ntohs (rt.rtmsg_dst.s6_addr16[3]),
                   ntohs (rt.rtmsg_dst.s6_addr16[4]),
                   ntohs (rt.rtmsg_dst.s6_addr16[5]),
                   ntohs (rt.rtmsg_dst.s6_addr16[6]),
                   ntohs (rt.rtmsg_dst.s6_addr16[7]), rt.rtmsg_dst_len);
          if (ioctl (admin_fd, SIOCDELRT, &rt) < 0)
            {
              cprintf (c, GNUNET_CS_PROTO_VPN_REPLY,
                       "Cannot del route IPv6 address for gnu%s because %s\n",
                       id, strerror (errno));
            }
        }
    }
  cprintf (c, GNUNET_CS_PROTO_VPN_REPLY, "Copying table\n");
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 _("realise copy table\n"));
  realised_entries = route_entries;
  memcpy (realised_store, route_store, sizeof (route_info) * route_entries);

  GNUNET_mutex_unlock (lock);
}

static void add_client (struct GNUNET_ClientHandle *c)
{
  struct GNUNET_ClientHandle **rstore;
  int i, rcapacity;

  /* we already have them, equality is assumed if the filehandles match */
  for (i = 0; i < clients_entries; i++)
    {
      if (*(clients_store + i) == c)
        return;
    }

  clients_entries++;
  /* do we need more ram to hold the client handle? */
  rcapacity = clients_entries * sizeof (struct GNUNET_ClientHandle *);
  if (rcapacity > clients_capacity)
    {
      rstore = GNUNET_realloc (clients_store, rcapacity);
      if (rstore == NULL)
        {
          clients_entries--;
          /* not enough ram, warn in the logs that they
           * will forego receiving logging
           */
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("Cannot store client info\n"));
          return;
        }
      clients_capacity = rcapacity;
      clients_store = rstore;
    }
  *(clients_store + (clients_entries - 1)) = c;
}

static void remove_client (struct GNUNET_ClientHandle *c)
{
  int i;
  for (i = 0; i < clients_entries; i++)
    {
      if (*(clients_store + i) == c)
        {
          *(clients_store + i) = *(clients_store + (clients_entries - 1));
          clients_entries--;
          return;
        }
    }
}

/** The console client is used to admin/debug vpn */
static int csHandle (struct GNUNET_ClientHandle *c,
                     const GNUNET_MessageHeader * message)
{
  GNUNET_MessageHeader *rgp = NULL;
  int i;
  GNUNET_PeerIdentity id;
  int parameter = ntohs (message->size) - sizeof (GNUNET_MessageHeader);
  char *ccmd = (char *) (message + 1);
  char *parm;

  GNUNET_mutex_lock (lock);
  add_client (c);
  GNUNET_mutex_unlock (lock);
  /* issued command from client */
  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_MSG)
    {
      if (ntohs (message->size) == 0)
        return GNUNET_OK;
    }
  /*    while ((l < ll) && (*(ccmd+cl) > 32)) cl++; */

  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_DEBUGOFF)
    {
      GNUNET_mutex_lock (lock);
      cdebug = 0;
      GNUNET_mutex_unlock (lock);
      cprintf (c, GNUNET_CS_PROTO_VPN_DEBUGOFF, "LOG NOTHING\n");
      return GNUNET_OK;
    }
  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_DEBUGON)
    {
      GNUNET_mutex_lock (lock);
      cdebug = GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST;
      GNUNET_mutex_unlock (lock);
      cprintf (c, GNUNET_CS_PROTO_VPN_DEBUGON, "LOG DEBUG\n");
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
  /* add routes in route but not realised to OS
   * delete routes in realised but not route from OS
   * memcpy routes to realised metric
   */
  if (ntohs (message->type) == GNUNET_CS_PROTO_VPN_REALISE)
    {
      realise (c);
      cprintf (c, GNUNET_CS_PROTO_VPN_REALISE, "Realise done\n");
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

static void clientExitHandler (struct GNUNET_ClientHandle *c)
{
  GNUNET_mutex_lock (lock);
  remove_client (c);
  GNUNET_mutex_unlock (lock);
}


static int makeNonblocking (int handle)
{
#if MINGW
  u_long mode;

  mode = 1;
  if (ioctlsocket (handle, FIONBIO, &mode == SOCKET_ERROR))
    {
      SetErrnoFromWinsockError (WSAGetLastError ());
      return GNUNET_SYSERR;
    }
  else
    {
      /* store the blocking mode */
#if HAVE_PLIBC_FD
      plibc_fd_set_blocking (handle, 0);
#else
      __win_SetHandleBlockingMode (handle, 0);
#endif
    }
#else
  int flags = fcntl (handle, F_GETFL);
  flags |= O_NONBLOCK;
  if (-1 == fcntl (handle, F_SETFL, flags))
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_WARNING | GNUNET_GE_USER |
                              GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE, "fcntl");
      return GNUNET_SYSERR;
    }
#endif
  return GNUNET_OK;
}

/**
 * Module inserted... create thread to listen to TUNTAP and pass
 * these messages on to GNUnet.
 *
 * Also enumerate all current peers and create taps for them.
 *
 */
int initialize_module_vpn (GNUNET_CoreAPIForPlugins * capi)
{
  int pfd;
  char *str = "OK\r\n";

  ectx = capi->ectx;
  lock = GNUNET_mutex_create (GNUNET_NO);

  coreAPI = capi;

  /* Signal to the root init script we want cap_net_admin
   */
  pfd = open ("/var/lib/GNUnet/gnunet.vpn", O_WRONLY);
  if (pfd > -1)
    {
      write (pfd, str, strlen (str));
      close (pfd);
    }
  pfd = open ("/var/lib/GNUnet/gnunet.vpn", O_RDONLY);
  if (pfd > -1)
    {
      read (pfd, str, strlen (str));
      close (pfd);
    }
  unlink ("/var/lib/GNUnet/gnunet.vpn");

  /* system("sudo setpcaps cap_net_admin+eip `pidof gnunetd`"); */

  admin_fd = socket (AF_INET6, SOCK_DGRAM, 0);

  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 _("`%s' initialising RFC4913 module  %d and %d\n"),
                 "template", GNUNET_CS_PROTO_MAX_USED,
                 GNUNET_P2P_PROTO_MAX_USED);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 _("RFC4193 my First 4 hex digits of host id are %x\n"),
                 capi->myIdentity->hashPubKey.bits[0]);

  /* core calls us to receive messages */
  /* get a PONG = peer is online */
  /* get a HANGUP = peer is offline */
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_AIP_IP, &handlep2pMSG))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_AIP_GETROUTE, &handlep2pMSG))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_AIP_ROUTE, &handlep2pMSG))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_AIP_ROUTES, &handlep2pMSG))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_PONG, &handlep2pMSG))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_HANG_UP, &handlep2pMSG))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR == capi->cs_exit_handler_register (&clientExitHandler))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_MSG, &csHandle))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_DEBUGOFF, &csHandle))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_DEBUGON, &csHandle))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_TUNNELS, &csHandle))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_ROUTES, &csHandle))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_REALISED, &csHandle))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_RESET, &csHandle))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_REALISE, &csHandle))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_ADD, &csHandle))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_TRUST, &csHandle))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_VPN_REPLY, &csHandle))
    return GNUNET_SYSERR;

  identity = coreAPI->request_service ("identity");
  session = coreAPI->request_service ("session");

  GNUNET_GE_ASSERT (ectx, identity != NULL);
  GNUNET_GE_ASSERT (ectx, session != NULL);

  init_router ();               /* reqire identity */
  init_realised ();             /* reqire identity */

  PIPE (signalingPipe);
  /* important: make signalingPipe non-blocking
     to avoid stalling on signaling! */
  makeNonblocking (signalingPipe[1]);

  /* Yes we have to make our own thread, cause the GUNnet API is
   * missing some callbacks (Namely CanReadThisFd - SELECT()) that I would like ;-(
   * They may go in the thread that usually monitors the GUI port.
   */
  tunThreadInfo =
    GNUNET_thread_create ((GNUNET_ThreadMainFunction) & tunThread, NULL,
                          128 * 1024);

  /* use capi->unicast to send messages to connected peers */
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "vpn",
                                                                   _
                                                                   ("enables IPv6 over GNUnet (incomplete)")));

  return GNUNET_OK;
}

/**
 * Module uninserted.
 */
void done_module_vpn ()
{
  int i;
  int ret;
  void *returnval;

  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_AIP_IP, &handlep2pMSG);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_AIP_GETROUTE, &handlep2pMSG);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_AIP_ROUTE, &handlep2pMSG);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_AIP_ROUTES, &handlep2pMSG);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_PONG, &handlep2pMSG);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_HANG_UP, &handlep2pMSG);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_MSG, &csHandle);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_DEBUGOFF, &csHandle);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_DEBUGON, &csHandle);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_TUNNELS, &csHandle);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_ROUTES, &csHandle);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_REALISED, &csHandle);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_RESET, &csHandle);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_REALISE, &csHandle);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_ADD, &csHandle);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_TRUST, &csHandle);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_VPN_REPLY, &csHandle);
  coreAPI->cs_exit_handler_unregister (&clientExitHandler);

  GNUNET_GE_LOG (ectx, GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("RFC4193 Waiting for tun thread to end\n"));

  running = 0;
  /* thread should wake up and exit */
  ret = write (signalingPipe[1], &running, sizeof (char));
  if (ret != sizeof (char))
    if (errno != EAGAIN)
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_BULK |
                              GNUNET_GE_USER,
                              "RFC4193 can not tell thread to exit");

  /* wait for it to exit */
  GNUNET_thread_join (tunThreadInfo, &returnval);
  GNUNET_GE_LOG (ectx, GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("RFC4193 The tun thread has ended\n"));

  coreAPI->release_service (identity);
  coreAPI->release_service (session);

  identity = NULL;

  CLOSE (signalingPipe[0]);
  CLOSE (signalingPipe[1]);

  /* bye bye TUNTAP ... */
  for (i = 0; i < entries1; i++)
    {
      if (((store1 + i)->fd) != 0)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                         GNUNET_GE_REQUEST,
                         _("RFC4193 Closing tunnel %d fd %d\n"), i,
                         (store1 + i)->fd);
          close ((store1 + i)->fd);
          (store1 + i)->fd = 0;
        }
    }
  if (store1 != NULL)
    {
      entries1 = 0;
      capacity1 = 0;
      GNUNET_free (store1);
    }
  close (admin_fd);

  GNUNET_mutex_destroy (lock);
  coreAPI = NULL;
}

/* end of template.c */
