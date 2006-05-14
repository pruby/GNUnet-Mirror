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
 * from public keys, using the private key to sign route announcements.
 *
 * CHANGELOG:
 * 20060110 Change ifconfig/route to ioctl's
 * 20060111 P2P packet includes length of the header.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"

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
struct in6_ifreq {
	struct in6_addr ifr6_addr;
	__u32 ifr6_prefixlen;
	unsigned int ifr6_ifindex;
};
#endif

/* Would usually go in gnunet_protocols.h */
#define P2P_PROTO_aip_IP 0xfd	/* contains IPv6 frame */
#define P2P_PROTO_aip_ROUTE 0xf0 /* a route to a node */
#define P2P_PROTO_aip_ROUTES 0xf1 /* no more routes in my table */
#define P2P_PROTO_aip_GETROUTE 0xf2 /* request for a table entry from a peer */

/* the idea is that you can use the first subnet number as a persistent identifier for your
 * website, services etc, so numbering of virtual circuits to other nodes begins at 2.
 * If you want to use more subnets locally, you can of course increase this number.
 */
#define VC_START 2

#define CS_PROTO_VPN_MSG 0xfa

#define MAXSIG_BUF 128

/* Here we define the maximum size of any headers that go in front of IP packets
 * it's the maximum of the GNUnet header and any platform headers, such as TUN/TAP's
 * packet information header on Linux.
 */
#define maxi(a,b) ((a)>(b)?(a):(b))
#define mini(a,b) ((a)<(b)?(a):(b))
#define HEADER_FRAME maxi(sizeof(P2P_MESSAGE_HEADER), sizeof(struct tun_pi))

/* we can't actually send messages this long... maybe 2 bytes shorter tho
 * planned includes a way to send yet longer messages
 */
#define IP_FRAME 65536

/**
 * Identity service, to reset the core.
 */
static Identity_ServiceAPI * identity;

static CoreAPIForApplication * coreAPI = NULL;

static ClientHandle client;
static int cdebug = 0;
static int interval = 60;
static Mutex lock;

PTHREAD_T tunThreadInfo;

static int delay_destroyed = -1;

typedef struct {
/*	char name[IFNAMSIZ]; */
	int id;
	int fd;
	int active;
	int route_entry;
	int ifindex;
	PeerIdentity peer;
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
typedef struct {
	/** owner's public key */
	PublicKey owner;
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
 * which is implicit with the sender PeerIdentity anyway.
 *
 * also the fields here are network byte order.
 */
typedef struct {
	PublicKey owner;
	int hops;
} transit_route;
	
static route_info *route_store = NULL;
static int route_entries = 0;
static int route_capacity = 0;

static route_info *realised_store = NULL;
static int realised_entries = 0;
static int realised_capacity = 0;

/** send given string to client */
static void cprintf(ClientHandle c, const char* format, ...) {
	va_list args;
	int r = -1;
	int size = 100;
	CS_MESSAGE_HEADER *b = NULL, *nb = NULL;

	if ((b = MALLOC(sizeof(CS_MESSAGE_HEADER)+size)) == NULL) {
		return;
	}
	while (1) {
		va_start(args, format);
		r = VSNPRINTF((char*)(b+1), size, format, args);
		va_end(args);
		if (r > -1 && r < size)
			break;
		if (r > -1) {
			size = r + 1;
		} else {
			size *= 2;
		}
		if ((nb = REALLOC(b, sizeof(CS_MESSAGE_HEADER) + size)) == NULL) {
			FREE(b);
			return;
		} else {
			b = nb;
		}
	}
	b->type=htons(CS_PROTO_VPN_MSG);
	b->size=htons(sizeof(CS_MESSAGE_HEADER) + strlen((char*)(b+1)));
	coreAPI->sendToClient(c, b);
	FREE(b);
}
#define VLOG if ((cdebug >= LOG_DEBUG) && (client != NULL)) cprintf(client,

/** Test if two PublicKey are equal or not */
static int isEqualP(const PublicKey *first, const PublicKey *second) {
	int i;
	int ln = maxi(first->sizen, second->sizen);
	int sn = mini(first->sizen, second->sizen);
	
	/* compare common mode modulus */
	if (memcmp( (first->key)+((first->sizen)-sn), (second->key)+((second->sizen)-sn), sn) != 0)
		return NO;

	/* difference before n should be 0 */
	for(i = 0; i < (first->sizen)-sn; i++) {
		if (*(first->key+i) != 0)
			return NO;
	}
	for(i = 0; i < (second->sizen)-sn; i++) {
		if (*(second->key+i) != 0)
			return NO;
	}

	/* compare common mode exponent */
	if (memcmp( (first->key)+ln, (second->key)+ln, RSA_KEY_LEN-ln) != 0)
		return NO;

	for(i = first->sizen; i < ln; i++) {
		if (*(first->key+i) != 0)
			return NO;
	}
	for(i = second->sizen; i < ln; i++) {
		if (*(second->key+i) != 0)
			return NO;
	}

	return YES;
}

/** 
 * clear out the prototype routes table
 * called at start or when we know a peer changes its route table.
 */
static void init_router() {
	int reqcapacity;
	route_info *reqstore;	
	reqcapacity = sizeof(route_info);
	if (reqcapacity > route_capacity) {
		reqstore = REALLOC(route_store, reqcapacity);
		if (reqstore == NULL) return; /* not enough ram, cannot init! */
		route_store = reqstore;
		route_capacity = reqcapacity;
	}
	route_entries = 1;
	route_store->hops = 0; /* us! */
	route_store->tunnel = -1; /* n/a! */
	route_store->owner = *(identity->getPublicPrivateKey()); /* us! */
}

/** 
 * clear out the actual route at startup only
 */
static void init_realised() {
	int reqcapacity;
	route_info *reqstore;	
	reqcapacity = sizeof(route_info);
	if (reqcapacity > realised_capacity) {
		reqstore = REALLOC(realised_store, reqcapacity);
		if (reqstore == NULL) return; /* not enough ram, cannot init! */
		realised_store = reqstore;
		realised_capacity = reqcapacity;
	}
	realised_entries = 1;
	realised_store->hops = 0; /* us! */
	realised_store->tunnel = -1; /* n/a! */
	realised_store->owner = *(identity->getPublicPrivateKey()); /* us! */
}

/* adds a route to prototype route table, unless it has same PublicKey and tunnel as another entry */
static void add_route(PublicKey* them, int hops, int tunnel) {
	int i;
	route_info *rstore;
	int rcapacity;	

	for (i = 0; i < route_entries; i++) {
		if (isEqualP(them, &(route_store+i)->owner)) {
			if ((route_store+i)->hops == 0) {
				/* we don't store alternative routes to ourselves,
				 * as we already know how to route to ourself
				 */
				VLOG _("Not storing route to myself from peer %d\n"), tunnel);
				return;
			}
			if ((route_store+i)->tunnel == tunnel) {
				/* also, we only keep one route to a node per peer,
				 * but store the lowest hop count that the peer is advertising for that node.
				 */
				(route_store+i)->hops = mini((route_store+i)->hops, hops);
				VLOG _("Duplicate route to node from peer %d, choosing minimum hops"), tunnel);
				return;
			}
		}
	}

	route_entries++;
        rcapacity = route_entries * sizeof(route_info);
        if (rcapacity > route_capacity) {
       	        rstore = REALLOC(route_store, rcapacity);
               	if (rstore == NULL) { 
			route_entries--;
			return; /* not enough ram, we will have to drop this route. */
		}
               	route_capacity = rcapacity;
               	route_store = rstore;
	}
	/* 
	 * we really should keep the route table in ascending hop count order...
	 */
	if (route_entries > 0) {
		i = route_entries - 1; /* i = insert location */
		while ((i > 0) && ((route_store+(i-1))->hops > hops)) {
			(route_store+i)->hops = (route_store+(i-1))->hops;
			(route_store+i)->tunnel = (route_store+(i-1))->hops;
			(route_store+i)->owner = (route_store+(i-1))->owner;
			i--;
		}
		VLOG _("Inserting route from peer %d in route table at location %d\n"), tunnel, i);
		(route_store+i)->hops = hops;
		(route_store+i)->tunnel = tunnel;
		(route_store+i)->owner = *them;
	}
}

/**
 * Render IPv4 or IPv6 packet info for logging.
 */
static void ipinfo(char *info, const struct ip6_hdr* fp) {
        struct in_addr fr4;
        struct in_addr to4;

	if ((((const struct iphdr*)fp)->version == 4)) {
		fr4.s_addr = ((const struct iphdr*)fp)->saddr;
		to4.s_addr = ((const struct iphdr*)fp)->daddr;
		sprintf(info, "IPv4 %s -> ", inet_ntoa(fr4));
		strcat(info, inet_ntoa(to4));
		return;
	}
	if ((((const struct iphdr*)fp)->version == 6)) {
		sprintf(info, "IPv6 %x:%x:%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x:%x:%x",
			ntohs(fp->ip6_src.s6_addr16[0]),
			ntohs(fp->ip6_src.s6_addr16[1]),
			ntohs(fp->ip6_src.s6_addr16[2]),
			ntohs(fp->ip6_src.s6_addr16[3]),
			ntohs(fp->ip6_src.s6_addr16[4]),
			ntohs(fp->ip6_src.s6_addr16[5]),
			ntohs(fp->ip6_src.s6_addr16[6]),
			ntohs(fp->ip6_src.s6_addr16[7]),
			ntohs(fp->ip6_dst.s6_addr16[0]),
			ntohs(fp->ip6_dst.s6_addr16[1]),
			ntohs(fp->ip6_dst.s6_addr16[2]),
			ntohs(fp->ip6_dst.s6_addr16[3]),
			ntohs(fp->ip6_dst.s6_addr16[4]),
			ntohs(fp->ip6_dst.s6_addr16[5]),
			ntohs(fp->ip6_dst.s6_addr16[6]),
			ntohs(fp->ip6_dst.s6_addr16[7])
		);
		return;
	}
	sprintf(info, "IPv%d ?", ((const struct iphdr*)fp)->version);
}

/** check that ethertype matches ip version for incoming packets from linux specific code */
static int valid_incoming(int len, struct tun_pi* tp, struct ip6_hdr* fp) {
	char info[100];
	if (len > (65535 - sizeof(struct tun_pi))) {
		LOG(LOG_ERROR, _("RFC4193 Frame length %d is too big for GNUnet!\n"), len);
		return NO;
	}
	if (len < sizeof(struct tun_pi)) {
		LOG(LOG_ERROR, _("RFC4193 Frame length %d too small\n"), len);
		return NO;
	}
	if ((ntohs(tp->proto) == ETH_P_IP) && (((struct iphdr*)fp)->version == 4)) {
		return YES;
	} else if ((ntohs(tp->proto) == ETH_P_IPV6) && (((struct iphdr*)fp)->version == 6)) {
		ipinfo(info, fp);
		VLOG "-> GNUnet(%d) : %s\n", len - sizeof(struct tun_pi), info);
		return YES;
	}
	LOG(LOG_ERROR, _("RFC4193 Ethertype %x and IP version %x do not match!\n"),
		ntohs(tp->proto), ((struct iphdr*)fp)->version);
	return NO;
}

/** Test if two PeerIdentity are equal or not */
static int isEqual(const PeerIdentity *first, const PeerIdentity *second) {
	int i;
	for (i = 0; i < 512/8/sizeof(unsigned int); i++) {
		if (first->hashPubKey.bits[i] != second->hashPubKey.bits[i]) {
			return 0;
		}
	}
	return -1;
}

/**
 * Convert a PeerIdentify into a "random" RFC4193 prefix
 * actually we make the first 40 bits of the hash into the prefix!
 */
static void id2ip(ClientHandle cx, const PeerIdentity* them) {
	unsigned char a,b,c,d,e;
	a = (them->hashPubKey.bits[0] >> 8) & 0xff;
	b = (them->hashPubKey.bits[0] >> 0) & 0xff;
	c = (them->hashPubKey.bits[1] >> 8) & 0xff;
	d = (them->hashPubKey.bits[1] >> 0) & 0xff;
	e = (them->hashPubKey.bits[2] >> 8) & 0xff;
	cprintf(cx, "fd%02x:%02x%02x:%02x%02x",a,b,c,d,e);
}
/* convert PeerIdentity into network octet order IPv6 address */
static void id2net(struct in6_addr* buf, const PeerIdentity* them) {
	unsigned char a,b,c,d,e;
	a = (them->hashPubKey.bits[0] >> 8) & 0xff;
	b = (them->hashPubKey.bits[0] >> 0) & 0xff;
	c = (them->hashPubKey.bits[1] >> 8) & 0xff;
	d = (them->hashPubKey.bits[1] >> 0) & 0xff;
	e = (them->hashPubKey.bits[2] >> 8) & 0xff;

	/* we are unique random */
	buf->s6_addr16[0] = htons(0xfd00  + a);
	buf->s6_addr16[1] = htons(b * 256 + c);
	buf->s6_addr16[2] = htons(d * 256 + e);
	
	/* IPv6 /48 subnet number is zero */
	buf->s6_addr16[3] = 0;

	/* IPV6 /64 interface is zero */
	buf->s6_addr16[4] = 0;
	buf->s6_addr16[5] = 0;
	buf->s6_addr16[6] = 0;
	buf->s6_addr16[7] = 0;
}

static void setup_tunnel(int n, const PeerIdentity *them) {
	struct ifreq ifr;
	struct in6_ifreq ifr6;
	struct in6_rtmsg rt;
	int i, used, fd, id = 0;


	LOG(LOG_DEBUG, _("RFC4193 Going to try and make a tunnel in slot %d\n"), n);

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		LOG(LOG_ERROR, _("Cannot open tunnel device because of %s"), strerror(fd));
		DIE_STRERROR("open");
	}
	memset(&ifr, 0, sizeof(ifr));

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
	do {
		used = 0;
		for (i = 0; i < entries1; i++) {
			if ((store1+i)->id == id) { 
				LOG(LOG_DEBUG, _("RFC4193 Create skips gnu%d as we are already using it\n"), id);
				id++;
				used = 1;
			}
		}
		if (used == 0) {
			sprintf(ifr.ifr_name, "gnu%d", id);
			if ( ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
				LOG(LOG_ERROR, _("Cannot set tunnel name to %s because of %s\n"), ifr.ifr_name, strerror(errno));
				id++;
				used = 1;
			} else {
				LOG(LOG_ERROR, _("Configured tunnel name to %s\n"), ifr.ifr_name);
			}
		}
	} while (used);


	ioctl(fd, TUNSETNOCSUM, 1);
	memcpy(&((store1+n)->peer), them, sizeof(PeerIdentity));
	(store1+n)->id = id;
	(store1+n)->fd = fd;
	(store1+n)->active = NO;
	(store1+n)->route_entry = 0;

	/* tun_alloc can change the tunnel name */
	/* strncpy((store1+n)->name, ifr.ifr_name,IFNAMSIZ); */

	/* here we should give the tunnel an IPv6 address and fake up a route to the other end
	 * the format looks like this, and the net/host split is fixed at /48 as in rfc4193
	 * local /64
	 *	net: my PeerIdentity
	 * 	subnet: interface number+2
	 *	interface: NULL
	 *
	 * remote /48
	 * 	net: their PeerIdentity
	 *	host: NULL (it's not needed for routes)
	 */

	/* Run some system commands to set it up... */
/*	sprintf(cmd, "sudo ifconfig %s up", name);
 *	LOG(LOG_DEBUG, _("RFC4193 Calling %s\n"), cmd);
 *	system(cmd);
 */

	/* Bring interface up, like system("sudo ifconfig %s up"); */
	
	/* not needed, we already have the iface name ... strncpy(ifr.ifr_name, name, IFNAMSIZ); */
	if (ioctl(admin_fd, SIOCGIFFLAGS, &ifr) < 0) {
		LOG(LOG_ERROR, _("Cannot get socket flags for gnu%d because %s\n"), id, strerror(errno));
	} else {
	        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl(admin_fd, SIOCSIFFLAGS, &ifr) < 0) {
			LOG(LOG_ERROR, _("Cannot set socket flags for gnu%d because %s\n"), id, strerror(errno));
		}
	}
	
	/* Seems to go better with lower mtu, aka system("sudo ifconfig %s mtu 1280") */
	ifr.ifr_mtu = 1280;
	if (ioctl(admin_fd, SIOCSIFMTU, &ifr) < 0) {
		LOG(LOG_ERROR, _("Cannot set MTU for gnu%d because %s\n"), id, strerror(errno));
	}

	/* lets add an IP address... aka "sudo ifconfig %s add %s:%04x::1/64" */
	if (ioctl(admin_fd, SIOCGIFINDEX, &ifr) < 0) {
		LOG(LOG_ERROR, _("Cannot get interface index for gnu%d because %s\n"), id, strerror(errno));
	} else {
		/* note to self... htons(64) = kernel oops. */
		(store1+n)->ifindex = ifr.ifr_ifindex;
		ifr6.ifr6_prefixlen = 64;
		ifr6.ifr6_ifindex = ifr.ifr_ifindex;
		id2net(&ifr6.ifr6_addr, coreAPI->myIdentity);
		ifr6.ifr6_addr.s6_addr16[3] = htons(n+VC_START);
		LOG(LOG_DEBUG, _("IPv6 ifaddr gnu%d - %x:%x:%x:%x:%x:%x:%x:%x/%d\n"),
			id,
			ntohs(ifr6.ifr6_addr.s6_addr16[0]),
			ntohs(ifr6.ifr6_addr.s6_addr16[1]),
			ntohs(ifr6.ifr6_addr.s6_addr16[2]),
			ntohs(ifr6.ifr6_addr.s6_addr16[3]),
			ntohs(ifr6.ifr6_addr.s6_addr16[4]),
			ntohs(ifr6.ifr6_addr.s6_addr16[5]),
			ntohs(ifr6.ifr6_addr.s6_addr16[6]),
			ntohs(ifr6.ifr6_addr.s6_addr16[7]),
			ifr6.ifr6_prefixlen);
		if (ioctl(admin_fd, SIOCSIFADDR, &ifr6) < 0) {
			LOG(LOG_ERROR, _("Cannot set interface IPv6 address for gnu%d because %s\n"), id, strerror(errno));
		}
		
		/* lets add a route to the peer, aka "sudo route -A inet6 add %s::/48 dev %s" */
		memset((char*)&rt, 0, sizeof(struct in6_rtmsg));
		/* rtmsg_ifindex would be zero for routes not specifying a device, such as by gateway */
		rt.rtmsg_ifindex = ifr.ifr_ifindex;
		id2net(&rt.rtmsg_dst, them);
		rt.rtmsg_flags = RTF_UP;
		rt.rtmsg_metric = 1;   /* how many hops to owner of public key */
		rt.rtmsg_dst_len = 48; /* network prefix len is 48 by standard */
		LOG(LOG_DEBUG, _("IPv6 route gnu%d - destination %x:%x:%x:%x:%x:%x:%x:%x/%d\n"),
			id,
			ntohs(rt.rtmsg_dst.s6_addr16[0]),
			ntohs(rt.rtmsg_dst.s6_addr16[1]),
			ntohs(rt.rtmsg_dst.s6_addr16[2]),
			ntohs(rt.rtmsg_dst.s6_addr16[3]),
			ntohs(rt.rtmsg_dst.s6_addr16[4]),
			ntohs(rt.rtmsg_dst.s6_addr16[5]),
			ntohs(rt.rtmsg_dst.s6_addr16[6]),
			ntohs(rt.rtmsg_dst.s6_addr16[7]),
			rt.rtmsg_dst_len);
		if (ioctl(admin_fd, SIOCADDRT, &rt) < 0) {
			LOG(LOG_ERROR, _("Cannot add route IPv6 address for gnu%s because %s\n"), id, strerror(errno));
		}
	}
}

/**
 * See if we already got a TUN/TAP open for the given GNUnet peer. if not, make one, stick 
 * PeerIdentity and the filehandle and name of the TUN/TAP in an array so we remember we did it. 
 */
static void checkensure_peer(const PeerIdentity *them, void *callerinfo) {
	int i;
	tunnel_info* rstore1;
	int rcapacity1;

	/* LOG(LOG_DEBUG, _("RFC4193 Going to checkensure peer %x then\n"), them->hashPubKey.bits[0]); */
	/* first entry in array will be known as gnu0 */

	/* if a tunnel is already setup, we don't setup another */
	for (i = 0; i < entries1; i++) {
		if (isEqual(them, &((store1+i)->peer))) {
			return;
		}
	}

	/*
	 * append it at the end.
	 */
	entries1++;
	rcapacity1 = entries1 * sizeof(tunnel_info);
	if (rcapacity1 > capacity1) {
		rstore1 = REALLOC(store1, rcapacity1);
		if (rstore1 == NULL) {
			LOG(LOG_ERROR, _("RFC4193 We have run out of memory and so I can't store a tunnel for this peer.\n"));
			entries1--;
			return;
		}
		store1 = rstore1;
		capacity1 = rcapacity1;
	}

	/* LOG(LOG_DEBUG, _("RFC4193 Extending array for new tunnel\n")); */
	setup_tunnel((entries1 - 1), them);
}

/* make new thread...
 * repeat {
 * 	call forAllConnectedNodes, create/destroy tunnels to match connected peers, 1 per peer.
 *	Give new tunnels their IPv6 addresses like "ifconfig gnu0 add fdXX:XXXX:XXXX::/48"
 * 	SELECT for incoming packets, unicast those thru gnunet, or (pipe activity = exit this thread) or timeout.
 * }
 * own IPv6 addr is fdXX:XXXX:XXXX::P/48 where X= 40 bits own key, P = gnu0 + 2
 * route add -net fdXX(remote key) dev gnu0 is then used.
 */
static void * tunThread(void* arg) {
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
	struct ip6_hdr* fp;
	struct tun_pi* tp;
	P2P_MESSAGE_HEADER* gp;
	struct timeval timeout;

	/* need the cast otherwise it increments by HEADER_FRAME * sizeof(frame) rather than HEADER_FRAME */
	fp = (struct ip6_hdr*)(((char*)&frame) + HEADER_FRAME);

	/* this trick decrements the pointer by the sizes of the respective structs */
	tp = ((struct tun_pi*)fp)-1;
	gp = ((P2P_MESSAGE_HEADER*)fp)-1;
	running = 1;
	LOG(LOG_DEBUG, _("RFC4193 Thread running (frame %d tunnel %d f2f %d) ...\n"), fp, tp, gp);

	MUTEX_LOCK(&lock);
	while (running) {

		FD_ZERO(&readSet);
		FD_ZERO(&errorSet);
		FD_ZERO(&writeSet);

		max = signalingPipe[0];

		if (-1 != FSTAT(signalingPipe[0], &statinfo)) {
			FD_SET(signalingPipe[0], &readSet);
		} else {
      			DIE_STRERROR("fstat");
		}
		for (i = 0; i < entries1; i++) {
			FD_SET(((store1+i)->fd), &readSet);
			max = maxi(max,(store1+i)->fd);
		}
		MUTEX_UNLOCK(&lock);
		timeout.tv_sec = interval;
		timeout.tv_usec = 0;

		ret = SELECT(max+1,
			&readSet,
			&writeSet,
			&errorSet,
			&timeout);
		if (ret < 0) {
			running = 0;
			break;
		}
		if (FD_ISSET(signalingPipe[0], &readSet)) {
			if (0 >= READ(signalingPipe[0],
			&tmp[0],
			MAXSIG_BUF))
        		LOG_STRERROR(LOG_WARNING, "read");
		}
		MUTEX_LOCK(&lock);
		for (i = 0; i < entries1; i++) {
			if (FD_ISSET(((store1+i)->fd), &readSet)) {
				ret = read(((store1+i)->fd), tp, IP_FRAME);

				/* goodbye IPv6 packet, enjoy the GNUnet... :-)
				 * IP is of course very important so it will enjoy
				 * the very highest priority
				 */
				if (valid_incoming(ret, tp, fp)) {
					gp->type = htons(P2P_PROTO_aip_IP);
					gp->size = htons(sizeof(P2P_MESSAGE_HEADER) + ret - sizeof(struct tun_pi));
					coreAPI->unicast(&((store1+i)->peer),gp,EXTREME_PRIORITY,1);
					coreAPI->preferTrafficFrom(&((store1+i)->peer),1000);
				}
			}
		}
		if (timeout.tv_sec < (interval / 2)) {
//			for (i = 0; i < entries1; i++) (store1+i)->connected = NO;
//			coreAPI->forAllConnectedNodes(&checkensure_peer, NULL);
			for (i = 0; i < entries1; i++) {
				if (((store1+i)->active) > 0) {
					if (identity->isBlacklistedStrict(&((store1+i)->peer))) {
						LOG(LOG_INFO, _("RFC4193 --- whitelist of peer %x\n"),
							(store1+i)->peer.hashPubKey.bits[0]);
						identity->whitelistHost(&((store1+i)->peer));
					}
				}
				/* This prevents our list of peers becoming too big....
				 * they have never used VPN, and they have disconnected...
				 */
/*				if (((store1+i)->active) == 0) {
 *					LOG(LOG_INFO, _("RFC4193 --- dropping connection %x\n"), i);
 *					close( (store1+i)->fd );
 *					*(store1+i) = *(store1+(entries1-1));
 *					entries1--;
 *				}
 */
			}
		}
	}
	LOG(LOG_DEBUG, _("RFC4193 Thread exiting\n"));
	MUTEX_UNLOCK(&lock);
	return NULL;
}

/**
 * Pass IP packet to tap. Which tap depends on what the PeerIdentity is.
 * If we've not seen the peer before, create a new TAP and tell our thread about it?
 * else scan the array of TAPS and copy the message into it.
 *
 * Mainly this routine exchanges the P2P_MESSAGE_HEADER on incoming ipv6 packets
 * for a TUN/TAP header for writing it to TUNTAP.
 */
static int handlep2pMSG(const PeerIdentity * sender, const P2P_MESSAGE_HEADER * gp) {
	int i = 0, fd;
	char loginfo[100];

	P2P_MESSAGE_HEADER * rgp = NULL;
	char frame[IP_FRAME + sizeof(struct tun_pi)];
        const struct ip6_hdr* fp = (struct ip6_hdr*)(gp+1);
        struct ip6_hdr* new_fp = (struct ip6_hdr*)(((char*)&frame) + sizeof(struct tun_pi));
        struct tun_pi* tp = (struct tun_pi*)(&frame);

	switch (ntohs(gp->type)) {
	case P2P_PROTO_aip_IP:
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
		switch (((struct iphdr*)fp)->version) {
			case 6:
				tp->proto = htons(ETH_P_IPV6);
				if ( ntohs(fp->ip6_src.s6_addr16[0]) < 0xFD00 ) {
					LOG(LOG_DEBUG, _("VPN IP src not anonymous. drop..\n"));
					return OK;
				}
				if ( ntohs(fp->ip6_dst.s6_addr16[0]) < 0xFD00 ) {
					LOG(LOG_DEBUG, _("VPN IP not anonymous, drop.\n"));
					return OK;
				}
				break;
			case 4:
				tp->proto = htons(ETH_P_IP);
				LOG(LOG_DEBUG, _("VPN Received, not anonymous, drop.\n"));
		                return OK;
			default: 
				LOG(LOG_ERROR, _("VPN Received unknown IP version %d...\n"), ((struct iphdr*)fp)->version);
				return OK;
		}

		ipinfo(loginfo, fp);

		/* do packet memcpy outside of mutex for speed */
		memcpy(new_fp, fp, ntohs(gp->size)-sizeof(P2P_MESSAGE_HEADER));

		MUTEX_LOCK(&lock);
		VLOG _("<- GNUnet(%d) : %s\n"), ntohs(gp->size) - sizeof(P2P_MESSAGE_HEADER), loginfo);
	        for (i = 0; i < entries1; i++) {
        	        if (isEqual(sender, &((store1+i)->peer))) {
				fd = ((store1+i)->fd);
	
				(store1+i)->active = YES;

				/* We are only allowed one call to write() per packet.
				 * We need to write packet and packetinfo together in one go.
				 */
				write(fd, tp, ntohs(gp->size) + sizeof(struct tun_pi) - sizeof(P2P_MESSAGE_HEADER));
				coreAPI->preferTrafficFrom(&((store1+i)->peer),1000);
				MUTEX_UNLOCK(&lock);
                        	return OK;
                	}
		}
		/* do not normally get here... but checkensure so any future packets could be routed... */
		checkensure_peer(sender, NULL);
		MUTEX_UNLOCK(&lock);
		LOG(LOG_DEBUG, _("Could not write the tunnelled IP to the OS... Did to setup a tunnel?\n"));
		return OK;
	case p2p_PROTO_PONG:
		MUTEX_LOCK(&lock);
		checkensure_peer(sender, NULL);
		MUTEX_UNLOCK(&lock);
		return OK;
	case P2P_PROTO_hangup:
		/*
		 * Remove node's entry in access table if it did not VPN.
		 */
		MUTEX_LOCK(&lock);
	        for (i = 0; i < entries1; i++) {
	                if ((((store1+i)->fd) > 0) && isEqual(sender, &((store1+i)->peer))) {
				if (((store1+i)->active) == 0) {
					LOG(LOG_INFO, _("RFC4193 -- non-vpn node hangs up. close down gnu%d (%d in %d)\n"),
						(store1+i)->id,  i, entries1);

					close( (store1+i)->fd );
					delay_destroyed = (store1+i)->id;

					*(store1+i) = *(store1+(entries1-1));
					entries1--;
				}

			}
		}
		MUTEX_UNLOCK(&lock);
		return OK;
	case P2P_PROTO_aip_GETROUTE:
		/** peer wants an entry from our routing table */
		VLOG _("Receive route request\n"));
		if (ntohs(gp->size) == (sizeof(P2P_MESSAGE_HEADER) + sizeof(int))) {
			i = ntohl(*((int*)fp));
			MUTEX_LOCK(&lock);
			if (i < realised_entries) {
				VLOG _("Prepare route announcement level %d\n"), i);
				rgp = MALLOC(sizeof(P2P_MESSAGE_HEADER) + sizeof(transit_route));
				if (rgp == NULL) {
					MUTEX_UNLOCK(&lock);
					return OK;
				}
				rgp->size = htons(sizeof(P2P_MESSAGE_HEADER) + sizeof(transit_route));
				rgp->type = htons(P2P_PROTO_aip_ROUTE);
				((transit_route*)(rgp+1))->owner = (realised_store+i)->owner;
				((transit_route*)(rgp+1))->hops = htonl((realised_store+i)->hops);
				MUTEX_UNLOCK(&lock);
				VLOG _("Send route announcement %d with route announce\n"), i);
				/* it must be delivered if possible, but it can wait longer than IP */
				coreAPI->unicast(sender, rgp, EXTREME_PRIORITY, 15);
				FREE(rgp);
				return OK;
			}
			VLOG _("Send outside table info %d\n"), i);
			rgp = MALLOC(sizeof(P2P_MESSAGE_HEADER) + sizeof(int));
			if (rgp == NULL) {
				MUTEX_UNLOCK(&lock);
				return OK;
			}
			rgp->size = htons(sizeof(P2P_MESSAGE_HEADER) + sizeof(int));
			rgp->type = htons(P2P_PROTO_aip_ROUTES);
			*((int*)(rgp+1)) = htonl(realised_entries);
			MUTEX_UNLOCK(&lock);
			coreAPI->unicast(sender, rgp, EXTREME_PRIORITY, 15);
			FREE(rgp);
			return OK;
		}
		return OK;
	case P2P_PROTO_aip_ROUTE:
		VLOG _("Receive route announce.\n"));
		/** peer sent us a route, insert it into routing table, then req next entry */
		if (ntohs(gp->size) == (sizeof(P2P_MESSAGE_HEADER) + sizeof(transit_route))) {
			MUTEX_LOCK(&lock);
			VLOG _("Going to try insert route into local table.\n"));
		        for (i = 0; i < entries1; i++) {
	        	        if (isEqual(sender, &((store1+i)->peer))) {
					(store1+i)->active = YES;
					VLOG _("Inserting with hops %d\n"), ntohl( ((transit_route*)(gp+1))->hops));
					add_route( 	&( ((transit_route*)(gp+1))->owner ), 
							1 + ntohl( ((transit_route*)(gp+1))->hops),
							i);
					if ((store1+i)->route_entry < GNUNET_VIEW_LIMIT) {
						(store1+i)->route_entry++;
						rgp = MALLOC(sizeof(P2P_MESSAGE_HEADER) + sizeof(int));
			                        if (rgp == NULL) {
			                                MUTEX_UNLOCK(&lock);
			                                return OK;
			                        }
						rgp->type = htons(P2P_PROTO_aip_GETROUTE);
						rgp->size = htons(sizeof(P2P_MESSAGE_HEADER) + sizeof(int));
						*((int*)(rgp+1)) = htonl((store1+i)->route_entry);
						VLOG _("Request level %d from peer %d\n"), (store1+i)->route_entry, i);
						coreAPI->unicast(&((store1+i)->peer),rgp,EXTREME_PRIORITY,60);
						FREE(rgp);
					}
					break;
				}
			}
			MUTEX_UNLOCK(&lock);
		}
		return OK;
	case P2P_PROTO_aip_ROUTES:
		if (ntohs(gp->size) == (sizeof(P2P_MESSAGE_HEADER) + sizeof(int))) {
			/* if this is the last route message, we do route realisation
			 * that is, insert the routes into the operating system.
			 */
			VLOG _("Receive table limit on peer reached %d\n"), ntohl( *((int*)fp)) );
/*			MUTEX_LOCK(&lock);
		        for (i = 0; i < entries1; i++) {
	        	        if (isEqual(sender, &((store1+i)->peer))) {
					VLOG _("Storing table limit %d for peer %d\n"), ntohl( *((int*)fp)), i );
					(store1+i)->route_limit = ntohl( *((int*)fp));
					break;
				}
			}
			MUTEX_UNLOCK(&lock);
*/		}
		return OK;
	}
	return OK;
}

/** compare msg from client with given string */
static int iscmd(const int len, const char* ccmd, const char* cmd) {
	if (len != strlen(cmd)) return NO;
	if (strncmp(ccmd, cmd, len)) return NO;
	return YES;
}

/* here we copy the prototype route table we are collecting from peers to the actual
 * "realised" route table we distribute to peers, and to the kernel's table.
 */
static void realise(ClientHandle c) {
	int i, j, found;
	PeerIdentity id;
	int reqcapacity;
	route_info *reqstore;
	struct in6_rtmsg rt;

	cprintf(c, "Realisation in progress\n");
	cprintf(c, "-----------------\n");
	cprintf(c, "\n");
        MUTEX_LOCK(&lock);
	/* make sure realised table can take the new routes - if it wont, abort now! */
	LOG(LOG_DEBUG, _("realise alloc ram\n"));
	if (route_entries > realised_entries) {
		reqcapacity = sizeof(route_info) * route_entries;
		if (reqcapacity > realised_capacity) {
			reqstore = REALLOC(realised_store, reqcapacity);
			if (reqstore == NULL) {
				cprintf(c, "I cannot up the ram for realised routes.\n");
			        MUTEX_UNLOCK(&lock);
				return;
			}
			realised_store = reqstore;
			realised_capacity = reqcapacity;
		}
	}
	/* add routes that are in the new table but not the old */
	LOG(LOG_DEBUG, _("realise add routes\n"));
	for (i = 0; i < route_entries; i++) {
		found = 0;
		for (j = 0; j < realised_entries; j++) {
			/* compare public key */
			if (isEqualP(&(route_store+i)->owner,&(realised_store+j)->owner) &&
				((route_store+i)->hops == (realised_store+j)->hops) &&
				((route_store+i)->tunnel == (realised_store+j)->tunnel)
			) {
				found = 1;
			}
		}
		/* we are hops == 0
		 * hops == 1 auto added by tunneler
		 * hops >= 2 added here!
		 */
		if (!(found) && ((route_store+i)->hops > 1)) {
			/* lets add a route to this long remote node */
			memset((char*)&rt, 0, sizeof(struct in6_rtmsg));
			/* rtmsg_ifindex would be zero for routes not specifying a device, such as by gateway */
			rt.rtmsg_ifindex = (store1+((route_store+i)->tunnel))->ifindex;
			identity->getPeerIdentity(&(route_store+i)->owner, &id);
			id2net(&rt.rtmsg_dst, &id);
			rt.rtmsg_flags = RTF_UP;
			rt.rtmsg_metric = (route_store+i)->hops;
			/* how many hops to owner of public key */
			rt.rtmsg_dst_len = 48; /* always 48 as per RFC4193 */
			cprintf(c, "Add route gnu%d hops %d dst %x:%x:%x:%x:%x:%x:%x:%x/%d\n",
				id,
				rt.rtmsg_metric,
				ntohs(rt.rtmsg_dst.s6_addr16[0]),
				ntohs(rt.rtmsg_dst.s6_addr16[1]),
				ntohs(rt.rtmsg_dst.s6_addr16[2]),
				ntohs(rt.rtmsg_dst.s6_addr16[3]),
				ntohs(rt.rtmsg_dst.s6_addr16[4]),
				ntohs(rt.rtmsg_dst.s6_addr16[5]),
				ntohs(rt.rtmsg_dst.s6_addr16[6]),
				ntohs(rt.rtmsg_dst.s6_addr16[7]),
				rt.rtmsg_dst_len);
			if (ioctl(admin_fd, SIOCADDRT, &rt) < 0) {
				cprintf(c,"Cannot add route IPv6 address for gnu%s because %s\n", id, strerror(errno));
			}
		}
	}
	cprintf(c, "Removing routes\n");
	LOG(LOG_DEBUG, _("realise pull routes\n"));
	/* pull routes that are in the old table but not the new */
	for (i = 0; i < realised_entries; i++) {
		found = 0;
		for (j = 0; j < route_entries; j++) {
			/* compare public key */
			if (isEqualP(&(realised_store+i)->owner,&(route_store+j)->owner) &&
				((realised_store+i)->hops == (route_store+j)->hops) &&
				((realised_store+i)->tunnel == (route_store+j)->tunnel)
			) {
				found = 1;
			}
		}
		/* we are hops == 0
		 * hops == 1 auto added by tunneler
		 * hops >= 2 added here!
		 */
		if (!(found) && ((realised_store+i)->hops > 1)) {
			/* remove the route to this long remote node */
			memset((char*)&rt, 0, sizeof(struct in6_rtmsg));
			/* rtmsg_ifindex would be zero for routes not specifying a device, such as by gateway */
			rt.rtmsg_ifindex = (store1+((realised_store+i)->tunnel))->ifindex;
			identity->getPeerIdentity(&(realised_store+i)->owner, &id);
			id2net(&rt.rtmsg_dst, &id);
			rt.rtmsg_flags = RTF_UP;
			rt.rtmsg_metric = (realised_store+i)->hops;
			/* how many hops to owner of public key */
			rt.rtmsg_dst_len = 48; /* always 48 as per RFC4193 */
			cprintf(c, "Delete route gnu%d hops %d dst %x:%x:%x:%x:%x:%x:%x:%x/%d\n",
				id,
				rt.rtmsg_metric,
				ntohs(rt.rtmsg_dst.s6_addr16[0]),
				ntohs(rt.rtmsg_dst.s6_addr16[1]),
				ntohs(rt.rtmsg_dst.s6_addr16[2]),
				ntohs(rt.rtmsg_dst.s6_addr16[3]),
				ntohs(rt.rtmsg_dst.s6_addr16[4]),
				ntohs(rt.rtmsg_dst.s6_addr16[5]),
				ntohs(rt.rtmsg_dst.s6_addr16[6]),
				ntohs(rt.rtmsg_dst.s6_addr16[7]),
				rt.rtmsg_dst_len);
			if (ioctl(admin_fd, SIOCDELRT, &rt) < 0) {
				cprintf(c,"Cannot del route IPv6 address for gnu%s because %s\n", id, strerror(errno));
			}
		}
	}
	cprintf(c, "Copying table\n");
	LOG(LOG_DEBUG, _("realise copy table\n"));
	realised_entries = route_entries;
	memcpy(realised_store,route_store, sizeof(route_info) * route_entries);

	MUTEX_UNLOCK(&lock);
}

/** The console client is used to admin/debug vpn */
static int csHandle(ClientHandle c, const CS_MESSAGE_HEADER * message) {
	P2P_MESSAGE_HEADER * rgp = NULL;
	int i;
	PeerIdentity id;
	int cl = 1; 
	int cll = ntohs(message->size) - sizeof(CS_MESSAGE_HEADER);
	char* ccmd = (char*)(message+1);
	char* parm;

	MUTEX_LOCK(&lock);
		client = c;
	MUTEX_UNLOCK(&lock);
	/* issued command from client */
	if (ntohs(message->type) == CS_PROTO_VPN_MSG) {
		if (ntohs(message->size) == 0) return OK;
		while ((cl < cll) && (*(ccmd+cl) > 32)) cl++;

		if (iscmd(cl,ccmd,"help")) {
			cprintf(c, "\
Welcome to the GNUnet VPN debugging interface.\n\
Written by Michael John Wensley\n\
commands include: help, debug0, debug1, tunnel, route, reset\r\n\
");
			return OK;
		}
		if (iscmd(cl,ccmd,"debug0")) {
			MUTEX_LOCK(&lock);
				cdebug = LOG_NOTHING;
			MUTEX_UNLOCK(&lock);
			cprintf(c, "LOG NOTHING\n");
			return OK;
		}
		if (iscmd(cl,ccmd,"debug1")) {
			MUTEX_LOCK(&lock);
				cdebug = LOG_DEBUG;
			MUTEX_UNLOCK(&lock);
			cprintf(c, "LOG DEBUG\n");
			return OK;
		}
		if (iscmd(cl,ccmd,"tunnel")) {
			cprintf(c, "Tunnel Information\n");
			cprintf(c, "------------------\n");
			cprintf(c, "\n");
			MUTEX_LOCK(&lock);
			id2ip(c, coreAPI->myIdentity);
			cprintf(c, "::/48 This Node\n");
		        for (i = 0; i < entries1; i++) {
				id2ip(c, &(store1+i)->peer);
				cprintf(c, "::/48 gnu%d active=%s routeentry=%d\n", (store1+i)->id, 
						(store1+i)->active ? _("Yes") : _("No"), 
						(store1+i)->route_entry);
			}
			MUTEX_UNLOCK(&lock);
		}
		if (iscmd(cl,ccmd,"route")) {
			cprintf(c, "Route Information\n");
			cprintf(c, "-----------------\n");
                        cprintf(c, "\n");
                        MUTEX_LOCK(&lock);
			for (i = 0; i < route_entries; i++) {
				identity->getPeerIdentity(&(route_store+i)->owner, &id);
				id2ip(c, &id);
				if ((route_store+i)->hops == 0) {
					cprintf(c, "::/48 hops 0 (This Node)\n");
				} else {
					cprintf(c, "::/48 hops %d tunnel gnu%d\n", (route_store+i)->hops,
						(store1+((route_store+i)->tunnel))->id);
				}
			}
			MUTEX_UNLOCK(&lock);
		}
		if (iscmd(cl,ccmd,"realised")) {
			cprintf(c, "Realised Route Information\n");
			cprintf(c, "-----------------\n");
                        cprintf(c, "\n");
                        MUTEX_LOCK(&lock);
			for (i = 0; i < realised_entries; i++) {
				identity->getPeerIdentity(&(realised_store+i)->owner, &id);
				id2ip(c, &id);
				if ((realised_store+i)->hops == 0) {
					cprintf(c, "::/48 hops 0 (This Node)\n");
				} else {
					cprintf(c, "::/48 hops %d tunnel gnu%d\n", (realised_store+i)->hops,
						(store1+((realised_store+i)->tunnel))->id);
				}
			}
			MUTEX_UNLOCK(&lock);
		}
		/* add routes in route but not realised to OS
		 * delete routes in realised but not route from OS
		 * memcpy routes to realised metric
		 */
		if (iscmd(cl,ccmd,"realise")) {
			realise(c);
		}
		if (iscmd(cl,ccmd,"reset")) {
			cprintf(c, "Rebuilding routing tables\n");
                        cprintf(c, "\n");
                        MUTEX_LOCK(&lock);
			init_router();
		        for (i = 0; i < entries1; i++) {
				(store1+i)->route_entry = 0;
				/* lets send it to everyone - expect response only from VPN enabled nodes tho :-) */
/*				if ((store1+i)->active == YES) { */
					rgp = MALLOC(sizeof(P2P_MESSAGE_HEADER) + sizeof(int));
			                if (rgp == NULL) { break; }
					rgp->type = htons(P2P_PROTO_aip_GETROUTE);
					rgp->size = htons(sizeof(P2P_MESSAGE_HEADER) + sizeof(int));
					*((int*)(rgp+1)) = htonl((store1+i)->route_entry);
					cprintf(c, "Request level %d from peer %d ", (store1+i)->route_entry, i);
					id2ip(c, &((store1+i)->peer));
					cprintf(c, "\n");
					coreAPI->unicast(&((store1+i)->peer),rgp,EXTREME_PRIORITY,60);
					FREE(rgp);
/*				}	*/
			}
			MUTEX_UNLOCK(&lock);
			cprintf(c, "Rebuilding routing tables done\n");
                        cprintf(c, "\n");
		}
		/* not really used any more */
		if (iscmd(cl,ccmd,"fast")) {
			cprintf(c, "Going faster for you.\n");
                        cprintf(c, "\n");
                        MUTEX_LOCK(&lock);
			interval = 2;
			MUTEX_UNLOCK(&lock);
		}
		if (iscmd(cl,ccmd,"trust")) {
			cprintf(c, "Give credit to active nodes...\n");
			MUTEX_LOCK(&lock);
		        for (i = 0; i < entries1; i++) {
				if ((store1+i)->active == YES) {
					cprintf(c, "Uprating peer ");
					id2ip(c, &(store1+i)->peer);
					cprintf(c, " with credit %d\n", identity->changeHostTrust(&(store1+i)->peer, 1000));
				}
			}
			MUTEX_UNLOCK(&lock);
		}
		/* user wants add a peer - actually this does not work very well */
		if (iscmd(cl,ccmd,"add")) {
			if ((cll - cl) > 1) {
				if ((parm = MALLOC(cll - cl)) != NULL) {
					strncpy(parm, ccmd+(cl+1), cll-cl-1);
					*(parm+(cll-cl)) = 0;
					cprintf(c, "Connect %s for ", parm);
					if (OK == enc2hash(parm, &(id.hashPubKey))) {
 						id2ip(c, &id);

						/* this does not seem to work, strangeness with threads and capabilities?
						 * MUTEX_LOCK(&lock);
						 * checkensure_peer(&id, NULL);
						 * MUTEX_UNLOCK(&lock);
						 */

						/* get it off the local blacklist */
						identity->whitelistHost(&id);

						/* req route level 0 */
		                        	rgp = MALLOC(sizeof(P2P_MESSAGE_HEADER) + sizeof(int));
						if (rgp != NULL) { 
	                                        	rgp->type = htons(P2P_PROTO_aip_GETROUTE);
	                                        	rgp->size = htons(sizeof(P2P_MESSAGE_HEADER) + sizeof(int));
							*((int*)(rgp+1)) = 0;
							coreAPI->unicast(&id,rgp,EXTREME_PRIORITY,4);
							cprintf(c, " Sent");
							FREE(rgp);
						}

						cprintf(c, "\n");
						FREE(parm);
					} else {
						cprintf(c, "Could not decode PeerId from parameter.\n");
					}
				} else {
					cprintf(c, "Could not allocate for key.\n");
				}
			} else {
				cprintf(c, "Require key for parameter\n");
			}
		}
	}
	return OK;
}

static void clientExitHandler(ClientHandle c) {
	MUTEX_LOCK(&lock);
	if (c == client)
		client = NULL;
	MUTEX_UNLOCK(&lock);
}

/**
 * Module inserted... create thread to listen to TUNTAP and pass
 * these messages on to GNUnet.
 *
 * Also enumerate all current peers and create taps for them.
 *
 */
int initialize_module_vpn(CoreAPIForApplication * capi) {
	MUTEX_CREATE(&lock);

	/** client to write debug msg to */
	client = NULL;
	coreAPI = capi;

	/* Give GNUnet permission to administrate net interfaces itself. Needs access in /etc/sudoers
	 */
	system("sudo setpcaps cap_net_admin+eip `pidof gnunetd`");
	admin_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	
	LOG(LOG_DEBUG, _("`%s' initialising RFC4913 module  %d and %d\n"), "template", CS_PROTO_MAX_USED, P2P_PROTO_MAX_USED);
	LOG(LOG_DEBUG, _("RFC4193 my First 4 hex digits of host id are %x\n"), capi->myIdentity->hashPubKey.bits[0]);

	/* core calls us to receive messages */
	/* get a PONG = peer is online */
	/* get a HANGUP = peer is offline */
	if (SYSERR == capi->registerHandler(P2P_PROTO_aip_IP, &handlep2pMSG)) return SYSERR;
	if (SYSERR == capi->registerHandler(P2P_PROTO_aip_GETROUTE, &handlep2pMSG)) return SYSERR;
	if (SYSERR == capi->registerHandler(P2P_PROTO_aip_ROUTE, &handlep2pMSG)) return SYSERR;
	if (SYSERR == capi->registerHandler(P2P_PROTO_aip_ROUTES, &handlep2pMSG)) return SYSERR;
	if (SYSERR == capi->registerHandler(p2p_PROTO_PONG, &handlep2pMSG)) return SYSERR;
	if (SYSERR == capi->registerHandler(P2P_PROTO_hangup, &handlep2pMSG)) return SYSERR;
	if (SYSERR == capi->registerClientExitHandler(&clientExitHandler)) return SYSERR;
	if (SYSERR == capi->registerClientHandler(CS_PROTO_VPN_MSG, &csHandle)) return SYSERR;

  	identity = coreAPI->requestService("identity");

	GNUNET_ASSERT(identity != NULL);

	init_router();	/* reqire identity */
	init_realised();	/* reqire identity */

	PIPE(signalingPipe);
	/* important: make signalingPipe non-blocking
		to avoid stalling on signaling! */
	setBlocking(signalingPipe[1], NO);

	/* Yes we have to make our own thread, cause the GUNnet API is
	 * missing some callbacks (Namely CanReadThisFd - SELECT()) that I would like ;-(
	 * They may go in the thread that usually monitors the GUI port.
	 */
	PTHREAD_CREATE(&tunThreadInfo, (PThreadMain) &tunThread, NULL, 128 * 1024);

	/* use capi->unicast to send messages to connected peers */

	setConfigurationString("ABOUT",
                         "template",
                         _("enables IPv6 over GNUnet (incomplete)"));

	return OK;
}

/**
 * Module uninserted.
 */
void done_module_vpn() {
	int i;
	int ret;
	void *returnval;

	coreAPI->unregisterHandler(P2P_PROTO_aip_IP, &handlep2pMSG);
	coreAPI->unregisterHandler(P2P_PROTO_aip_GETROUTE, &handlep2pMSG);
	coreAPI->unregisterHandler(P2P_PROTO_aip_ROUTE, &handlep2pMSG);
	coreAPI->unregisterHandler(P2P_PROTO_aip_ROUTES, &handlep2pMSG);
	coreAPI->unregisterHandler(p2p_PROTO_PONG, &handlep2pMSG);
	coreAPI->unregisterHandler(P2P_PROTO_hangup, &handlep2pMSG);
	coreAPI->unregisterClientHandler(CS_PROTO_VPN_MSG, &csHandle);
	coreAPI->unregisterClientExitHandler(&clientExitHandler);

	LOG(LOG_INFO, _("RFC4193 Waiting for tun thread to end\n"));

	running = 0;
	/* thread should wake up and exit */
	ret = write(signalingPipe[1], &running, sizeof(char));
	if (ret != sizeof(char))
		if (errno != EAGAIN)
      			LOG_STRERROR(LOG_ERROR, "RFC4193 cant tell thread to exit");

	/* wait for it to exit */
	PTHREAD_JOIN(&tunThreadInfo, &returnval);
	LOG(LOG_INFO, _("RFC4193 The tun thread has ended\n"));

  	coreAPI->releaseService(identity);
	identity = NULL;

	closefile(signalingPipe[0]);
	closefile(signalingPipe[1]);

	/* bye bye TUNTAP ... */
	for (i = 0; i < entries1; i++) {
		if (((store1+i)->fd) != 0) {
			LOG(LOG_DEBUG, _("RFC4193 Closing tunnel %d fd %d\n"), i, (store1+i)->fd);
			close((store1+i)->fd);
			(store1+i)->fd = 0;
		}
	}
	if (store1 != NULL) {
		entries1 = 0;
		capacity1 = 0;
		FREE(store1);
	}
	close(admin_fd);

	MUTEX_DESTROY(&lock);
	coreAPI = NULL;
}

/* end of template.c */
