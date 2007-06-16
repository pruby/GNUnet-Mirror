/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2007 Christian Grothoff (and other contributing authors)

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
 * @file transports/udp6.c
 * @brief Implementation of the UDP transport service over IPv6
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include "platform.h"
#include "ip.h"
#include "ip6.h"

#define DEBUG_UDP6 NO

#include "udp_helper.c"

/**
 * Host-Address in a UDP6 network.
 */
typedef struct {
  /**
   * claimed IP of the sender, network byte order
   */
  IP6addr ip;

  /**
   * claimed port of the sender, network byte order
   */
  unsigned short port;

  /**
   * reserved (set to 0 for signature verification)
   */
  unsigned short reserved;

} Host6Address;

/* *********** globals ************* */

static struct GC_Configuration * cfg;

static struct LoadMonitor * load_monitor;

static struct CIDR6Network * filteredNetworks_;

static struct CIDR6Network * allowedNetworks_;

static struct MUTEX * configLock;

/**
 * Get the GNUnet UDP6 port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 *
 * @return the port in host byte order
 */
static unsigned short getGNUnetUDP6Port() {
  struct servent * pse;	/* pointer to service information entry	*/
  unsigned long long port;

 if (-1 == GC_get_configuration_value_number(cfg,
					      "UDP6",
					      "PORT",
					      1,
					      65535,
					      2086,
					      &port)) {
    if ((pse = getservbyname("gnunet", "udp")))
      port = htons(pse->s_port);
    else
      port = 0;
  }
 return (unsigned short) port;
}

/**
 * Allocate and bind a server socket for the UDP6 transport.
 */
static int passivesock(unsigned short port) {
  struct sockaddr_in6 sin;
  int sock;
  const int on = 1;

  sock = SOCKET(PF_INET6,
		SOCK_DGRAM,
		17);
  if (sock < 0)
    GE_DIE_STRERROR(ectx,
		    GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
		    "socket");
  if ( SETSOCKOPT(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 )
    GE_DIE_STRERROR(ectx,
		    GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
		    "setsockopt");
  if (port != 0) {
    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    sin.sin6_port   = htons(port);
    memcpy(&sin.sin6_addr,
	   &in6addr_any,
	   sizeof(IP6addr));
    if (BIND(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
      GE_LOG_STRERROR(ectx,
		      GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
		      "bind");
      GE_LOG(ectx,
	     GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
	     _("Failed to bind to UDP port %d.\n"),
	     port);
      GE_DIE_STRERROR(ectx,
		      GE_FATAL | GE_USER | GE_IMMEDIATE,
		      "bind");
    }
  } /* do not bind if port == 0, then we use send-only! */
  return sock;
}

/**
 * Check if we are explicitly forbidden to communicate with this IP.
 */
static int isBlacklisted(const void * addr,
			 unsigned int addr_len) {
  IP6addr ip;
  int ret;

  if (addr_len == sizeof(IP6addr)) {
    memcpy(&ip,
	   addr,
	   sizeof(IP6addr));
  } else if (addr_len == sizeof(struct sockaddr_in6)) {
    memcpy(&ip,
	   &((struct sockaddr_in6*) addr)->sin6_addr,
	   sizeof(IP6addr));
  } else {
    return SYSERR;
  }
  MUTEX_LOCK(configLock);
  ret = check_ipv6_listed(filteredNetworks_,
			  ip);
  MUTEX_UNLOCK(configLock);
  return ret;
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int isWhitelisted(const void * addr,
			 unsigned int addr_len) {
  IP6addr ip;
  int ret;

  if (addr_len == sizeof(IP6addr)) {
    memcpy(&ip,
	   addr,
	   sizeof(IP6addr));
  } else if (addr_len == sizeof(struct sockaddr_in6)) {
    memcpy(&ip,
	   &((struct sockaddr_in6*) addr)->sin6_addr,
	   sizeof(IP6addr));
  } else {
    return SYSERR;
  }
  ret = OK;
  MUTEX_LOCK(configLock);
  if (allowedNetworks_ != NULL)
    ret = check_ipv6_listed(filteredNetworks_,
			    ip);
  MUTEX_UNLOCK(configLock);
  return ret;
}


static int isRejected(const void * addr,
		      unsigned int addr_len) {
  if ((YES == isBlacklisted(addr,
			    addr_len)) ||
      (YES != isWhitelisted(addr,
			    addr_len)))	
    return YES;
  return NO;
}


/* *************** API implementation *************** */

/**
 * Verify that a hello-Message is correct (a node is reachable at that
 * address). Since the reply will be asynchronous, a method must be
 * called on success.
 *
 * @param hello the hello message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on failure
 */
static int verifyHello(const P2P_hello_MESSAGE * hello) {
  Host6Address * haddr;

  haddr = (Host6Address*) &hello[1];
  if ( (ntohs(hello->senderAddressSize) != sizeof(Host6Address)) ||
       (ntohs(hello->header.size) != P2P_hello_MESSAGE_size(hello)) ||
       (ntohs(hello->header.type) != p2p_PROTO_hello) ||
       (YES == isBlacklisted(&haddr->ip,
			     sizeof(IP6addr))) ||
       (YES != isWhitelisted(&haddr->ip,
			     sizeof(IP6addr))) )
    return SYSERR; /* obviously invalid */
  else {
#if DEBUG_UDP6
    char inet6[INET6_ADDRSTRLEN];
    GE_LOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
	"Verified UDP6 hello from %u.%u.%u.%u:%u.\n",
	inet_ntop(AF_INET6,
		  &haddr->ip,
		  inet6,
		  INET6_ADDRSTRLEN),
	ntohs(haddr->port));
#endif
    return OK;
  }
}

/**
 * Create a hello-Message for the current node. The hello is created
 * without signature and without a timestamp. The GNUnet core will
 * sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static P2P_hello_MESSAGE * createhello() {
  P2P_hello_MESSAGE * msg;
  Host6Address * haddr;
  unsigned short port;

  port = getGNUnetUDP6Port();
  if (port == 0)
    return NULL; /* UDP6 transport configured send-only */

  msg = MALLOC(sizeof(P2P_hello_MESSAGE) + sizeof(Host6Address));
  haddr = (Host6Address*) &msg[1];

  if (SYSERR == getPublicIP6Address(cfg,
				    ectx,				
				    &haddr->ip)) {
    FREE(msg);
    GE_LOG(ectx,
	   GE_WARNING,
	   _("UDP6: Could not determine my public IPv6 address.\n"));
    return NULL;
  }
  haddr->port      = htons(port);
  haddr->reserved        = htons(0);
  msg->senderAddressSize = htons(sizeof(Host6Address));
  msg->protocol          = htons(UDP6_PROTOCOL_NUMBER);
  msg->MTU               = htonl(udpAPI.mtu);
  return msg;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the P2P_hello_MESSAGE identifying the remote node
 * @param message what to send
 * @param size the size of the message
 * @return SYSERR on error, OK on success
 */
static int udp6Send(TSession * tsession,
		    const void * message,
		    const unsigned int size,
		    int importance) {
  UDPMessage * mp;
  P2P_hello_MESSAGE * hello;
  Host6Address * haddr;
  struct sockaddr_in6 sin; /* an Internet endpoint address */
  int ok;
  size_t ssize;
#if DEBUG_UDP6
  char inet6[INET6_ADDRSTRLEN];
#endif

  if (udp_sock == NULL)
    return SYSERR;
  if (size == 0) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  if (size > udpAPI.mtu) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  hello = (P2P_hello_MESSAGE*)tsession->internal;
  if (hello == NULL)
    return SYSERR;

  haddr = (Host6Address*) &hello[1];
  ssize = size + sizeof(UDPMessage);
  mp = MALLOC(ssize);
  mp->header.size = htons(ssize);
  mp->header.type = 0;
  mp->sender   = *coreAPI->myIdentity;
  memcpy(&mp[1],
	 message,
	 size);
  ok = SYSERR;
  memset(&sin, 0, sizeof(sin));
  sin.sin6_family = AF_INET6;
  sin.sin6_port = haddr->port;
  memcpy(&sin.sin6_addr,
	 &haddr->ip.addr,
	 sizeof(IP6addr));
#if DEBUG_UDP6
  GE_LOG(ectx,
	 GE_DEBUG,
	 "Sending message of %u bytes via UDP6 to %s:%d..\n",
	 ssize,
	 inet_ntop(AF_INET6,
		   &sin,
		   inet6,
		   INET6_ADDRSTRLEN),
	 ntohs(sin.sin_port));
#endif
  if (YES == socket_send_to(udp_sock,
			    NC_Nonblocking,
			    mp,
			    ssize,
			    &ssize,
			    (const char*) &sin,
			    sizeof(sin))) {
    ok = OK;
    if (stats != NULL)
      stats->change(stat_bytesSent,
		    ssize);
  } else {
    GE_LOG_STRERROR(ectx,
		    GE_WARNING,
		    "sendto");
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    ssize);
  }
  FREE(mp);
  return ok;
}

/**
 * Start the server process to receive inbound traffic.
 *
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer() {
  int sock;
  unsigned short port;

   /* initialize UDP6 network */
  port = getGNUnetUDP6Port();
  if (port != 0) {
    sock = passivesock(port);
    if (sock == -1)
      return SYSERR;
    selector = select_create("udp6",
			     YES,
			     ectx,
			     load_monitor,
			     sock,
			     sizeof(struct sockaddr_in6),
			     0, /* timeout */
			     &select_message_handler,
			     NULL,
			     &select_accept_handler,
			     &isRejected,
			     &select_close_handler,
			     NULL,
			     64 * 1024);
    if (selector == NULL)
      return SYSERR;
  }
  sock = SOCKET(PF_INET, SOCK_DGRAM, 17);
  if (sock == -1) {
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_ADMIN | GE_BULK,
		    "socket");
    select_destroy(selector);
    selector = NULL;
    return SYSERR;
  }
  udp_sock = socket_create(ectx,
			   load_monitor,
			   sock);
  return OK;
}

/**
 * Reload the configuration. Should never fail.
 */
static int reloadConfiguration() {
  char * ch;

  MUTEX_LOCK(configLock);
  FREENONNULL(filteredNetworks_);
  GC_get_configuration_value_string(cfg,
				    "UDP6",
				    "BLACKLIST",
				    "",
				    &ch);
  filteredNetworks_ = parse_ipv6_network_specification(ectx,
						       ch);
  FREE(ch);
  GC_get_configuration_value_string(cfg,
				    "UDP6",
				    "WHITELIST",
				    "",
				    &ch);
  if (strlen(ch) > 0)
    allowedNetworks_ = parse_ipv6_network_specification(ectx,
							ch);
  else
    allowedNetworks_ = NULL;
  FREE(ch);
  MUTEX_UNLOCK(configLock);
  return 0;
}

/**
 * Convert UDP6 hello to IPv6 address
 */
static int
helloToAddress(const P2P_hello_MESSAGE * hello,
	       void ** sa,
	       unsigned int * sa_len) {
  const Host6Address * haddr = (const Host6Address*) &hello[1];
  struct sockaddr_in6 * serverAddr;
  
  *sa_len = sizeof(struct sockaddr_in6);
  serverAddr = MALLOC(sizeof(struct sockaddr_in6));
  *sa = serverAddr;
  memset(serverAddr,
	 0,
	 sizeof(struct sockaddr_in6));
  serverAddr->sin6_family   = AF_INET6;
  memcpy(&serverAddr->sin6_addr,
	 haddr,
	 sizeof(IP6addr));
  serverAddr->sin6_port = haddr->port;
  return OK;
}

/**
 * The default maximum size of each outbound UDP6 message,
 * optimal value for Ethernet (10 or 100 MBit).
 */
#define MESSAGE_SIZE 1452

/**
 * The exported method. Makes the core api available via a global and
 * returns the udp6 transport API.
 */
TransportAPI * inittransport_udp6(CoreAPIForTransport * core) {
  unsigned long long mtu;

  GE_ASSERT(ectx, sizeof(UDPMessage) == 68);
  coreAPI = core;
  ectx = core->ectx;
  cfg = core->cfg;
  configLock = MUTEX_CREATE(NO);

  reloadConfiguration();
  if (-1 == GC_get_configuration_value_number(cfg,
					      "UDP6",
					      "MTU",
					      sizeof(UDPMessage) + P2P_MESSAGE_OVERHEAD + sizeof(MESSAGE_HEADER) + 32,
					      65500,
					      MESSAGE_SIZE,
					      &mtu)) {
    return NULL;
  }
  if (mtu < 1200)
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_IMMEDIATE,
	   _("MTU %llu for `%s' is probably too low!\n"),
	   mtu,
	   "UDP6");

  udpAPI.protocolNumber       = UDP6_PROTOCOL_NUMBER;
  udpAPI.mtu                  = mtu - sizeof(UDPMessage);
  udpAPI.cost                 = 19950;
  udpAPI.verifyHello           = &verifyHello;
  udpAPI.createhello          = &createhello;
  udpAPI.connect              = &udpConnect;
  udpAPI.send                 = &udp6Send;
  udpAPI.associate            = &udpAssociate;
  udpAPI.disconnect           = &udpDisconnect;
  udpAPI.startTransportServer = &startTransportServer;
  udpAPI.stopTransportServer  = &stopTransportServer;
  udpAPI.helloToAddress       = &helloToAddress;
  udpAPI.testWouldTry         = &testWouldTry;

  return &udpAPI;
}

void donetransport_udp6() {
  MUTEX_DESTROY(configLock);
  FREENONNULL(filteredNetworks_);
}

/* end of udp6.c */
