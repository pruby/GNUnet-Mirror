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
 * @file applications/vpn/vpn.c
 * @author Michael John Wensley
 * @author Christian Grothoff (code cleanup, breaking things)
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
 *
 * TODO:
 * - consider using linked list for routing tables instead of arrays
 * - find a better solution for /var/lib/gnunet/gnunet.vpn,
 *   at least do not hardwire the path
 * - can we split off TUN code into
 *   individual files without keeping globals?
 * - use PeerIdentities instead of PublicKeys where
 *   possible
 */

#include "vpn.h"
#include "cs.h"
#include "p2p.h"
#include "helper.h"

/**
 * Identity service, to reset the core.
 */
GNUNET_Identity_ServiceAPI *identity;

GNUNET_Session_ServiceAPI *session;

GNUNET_CoreAPIForPlugins *coreAPI;

struct GNUNET_Mutex *lock;

/* from bluetooth agent */
tunnel_info *store1;

int entries1;

route_info *route_store;

int route_entries;

route_info *realised_store;

int realised_entries;

static int interval = 60;

static struct GNUNET_ThreadHandle *tunThreadInfo;

static struct GNUNET_GE_Context *ectx;

static int capacity1;

 /**
 * Pipe to communicate with select thread
 * Used to tell it there is something to do...
 */
static int signalingPipe[2];

/** is thread to stop? */
static int running;

static int admin_fd;

static int route_capacity;

static int realised_capacity;


/**
 * clear out the prototype routes table
 * called at start or when we know a peer changes its route table.
 */
void
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
void
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
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_BULK |
                             GNUNET_GE_ADMIN,
                             _("Not storing route to myself from peer %d\n"),
                             tunnel);
              return;
            }
          if ((route_store + i)->tunnel == tunnel)
            {
              /* also, we only keep one route to a node per peer,
               * but store the lowest hop count that the peer is advertising for that node.
               */
              (route_store + i)->hops = mini ((route_store + i)->hops, hops);
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_BULK |
                             GNUNET_GE_ADMIN,
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
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                     _
                     ("Inserting route from peer %d in route table at location %d\n"),
                     tunnel, i);
      (route_store + i)->hops = hops;
      (route_store + i)->tunnel = tunnel;
      (route_store + i)->owner = *them;
    }
}


/** check that ethertype matches ip version for incoming packets from linux specific code */
static int
valid_incoming (int len, struct tun_pi *tp, struct ip6_hdr *fp)
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
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                     "-> GNUnet(%d) : %s\n", len - sizeof (struct tun_pi),
                     info);
      return GNUNET_YES;
    }
  GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                 _("RFC4193 Ethertype %x and IP version %x do not match!\n"),
                 ntohs (tp->proto), ((struct iphdr *) fp)->version);
  return GNUNET_NO;
}

static void
setup_tunnel (int n, const GNUNET_PeerIdentity * them)
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
                     _("Cannot open tunnel device: %s"), strerror (fd));
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
      id2net (&ifr6.ifr6_addr, coreAPI->my_identity);
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
void
checkensure_peer (const GNUNET_PeerIdentity * them, void *callerinfo)
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
 *   call p2p_connections_iterate, create/destroy tunnels to match connected peers, 1 per peer.
 *  Give new tunnels their IPv6 addresses like "ifconfig gnu0 add fdXX:XXXX:XXXX::/48"
 *   SELECT for incoming packets, ciphertext_send those thru gnunet, or (pipe activity = exit this thread) or timeout.
 * }
 * own IPv6 addr is fdXX:XXXX:XXXX::P/48 where X= 40 bits own key, P = gnu0 + 2
 * route add -net fdXX(remote key) dev gnu0 is then used.
 */
static void *
tunThread (void *arg)
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
                  coreAPI->ciphertext_send (&((store1 + i)->peer), gp,
                                            GNUNET_EXTREME_PRIORITY, 1);
                  coreAPI->p2p_connection_preference_increase (&
                                                               ((store1 +
                                                                 i)->peer),
                                                               1000);
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
 * here we copy the prototype route table we are collecting from peers to the actual
 * "realised" route table we distribute to peers, and to the kernel's table.
 */
static void
realise (void *unused)
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
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_BULK,
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
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                         GNUNET_GE_REQUEST,
                         "Add route gnu%d hops %d dst %x:%x:%x:%x:%x:%x:%x:%x/%d\n",
                         id, rt.rtmsg_metric,
                         ntohs (rt.rtmsg_dst.s6_addr16[0]),
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
                             GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_BULK,
                             "Cannot add route IPv6 address for gnu%s because %s\n",
                             id, strerror (errno));
            }
        }
    }
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 "Removing routes\n");
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
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER |
                         GNUNET_GE_REQUEST,
                         "Delete route gnu%d hops %d dst %x:%x:%x:%x:%x:%x:%x:%x/%d\n",
                         id, rt.rtmsg_metric,
                         ntohs (rt.rtmsg_dst.s6_addr16[0]),
                         ntohs (rt.rtmsg_dst.s6_addr16[1]),
                         ntohs (rt.rtmsg_dst.s6_addr16[2]),
                         ntohs (rt.rtmsg_dst.s6_addr16[3]),
                         ntohs (rt.rtmsg_dst.s6_addr16[4]),
                         ntohs (rt.rtmsg_dst.s6_addr16[5]),
                         ntohs (rt.rtmsg_dst.s6_addr16[6]),
                         ntohs (rt.rtmsg_dst.s6_addr16[7]), rt.rtmsg_dst_len);
          if (ioctl (admin_fd, SIOCDELRT, &rt) < 0)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_BULK,
                             "Cannot del route IPv6 address for gnu%s because %s\n",
                             id, strerror (errno));
            }
        }
    }
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST,
                 _("realise copy table\n"));
  realised_entries = route_entries;
  memcpy (realised_store, route_store, sizeof (route_info) * route_entries);

  GNUNET_mutex_unlock (lock);
}


/**
 * Module inserted... create thread to listen to TUNTAP and pass
 * these messages on to GNUnet.
 *
 * Also enumerate all current peers and create taps for them.
 *
 */
int
initialize_module_vpn (GNUNET_CoreAPIForPlugins * capi)
{
  int pfd;
  char *str = GNUNET_strdup ("OK\r\n");

  ectx = capi->ectx;
  lock = GNUNET_mutex_create (GNUNET_NO);

  coreAPI = capi;

  /* Signal to the root init script we want cap_net_admin
   */
  pfd = open ("/var/lib/gnunet/gnunet.vpn", O_WRONLY);
  if (pfd > -1)
    {
      WRITE (pfd, str, strlen (str));
      CLOSE (pfd);
    }
  pfd = open ("/var/lib/gnunet/gnunet.vpn", O_RDONLY);
  if (pfd > -1)
    {
      READ (pfd, str, strlen (str));
      CLOSE (pfd);
    }
  UNLINK ("/var/lib/gnunet/gnunet.vpn");
  GNUNET_free (str);

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
                 capi->my_identity->hashPubKey.bits[0]);

  /* core calls us to receive messages */
  /* get a PONG = peer is online */
  /* get a HANGUP = peer is offline */
  GNUNET_VPN_p2p_handler_init (capi);
  GNUNET_VPN_cs_handler_init (capi);

  identity = coreAPI->service_request ("identity");
  GNUNET_GE_ASSERT (ectx, identity != NULL);
  session = coreAPI->service_request ("session");

  GNUNET_GE_ASSERT (ectx, session != NULL);

  init_router ();               /* requires identity */
  init_realised ();             /* requires identity */

  PIPE (signalingPipe);
  /* important: make signalingPipe non-blocking
     to avoid stalling on signaling! */
  GNUNET_pipe_make_nonblocking (ectx, signalingPipe[1]);

  /* Yes we have to make our own thread, cause the GUNnet API is
   * missing some callbacks (Namely CanReadThisFd - SELECT()) that I would like ;-(
   * They may go in the thread that usually monitors the GUI port.
   */
  tunThreadInfo = GNUNET_thread_create (&tunThread, NULL, 128 * 1024);
  GNUNET_cron_add_job (capi->cron,
                       &realise,
                       5 * GNUNET_CRON_MINUTES,
                       5 * GNUNET_CRON_MINUTES, NULL);
  /* use capi->ciphertext_send to send messages to connected peers */
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
void
done_module_vpn ()
{
  int i;
  int ret;
  void *returnval;

  GNUNET_cron_del_job (coreAPI->cron,
                       &realise, 5 * GNUNET_CRON_MINUTES, NULL);
  GNUNET_VPN_p2p_handler_done ();
  GNUNET_VPN_cs_handler_done ();

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

  coreAPI->service_release (identity);
  identity = NULL;
  coreAPI->service_release (session);
  session = NULL;

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
          CLOSE ((store1 + i)->fd);
          (store1 + i)->fd = 0;
        }
    }
  if (store1 != NULL)
    {
      entries1 = 0;
      capacity1 = 0;
      GNUNET_free (store1);
    }
  CLOSE (admin_fd);

  GNUNET_mutex_destroy (lock);
  coreAPI = NULL;
}

/* end of vpn.c */
