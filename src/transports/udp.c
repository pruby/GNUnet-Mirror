/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file transports/udp.c
 * @brief Implementation of the UDP transport service
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include "gnunet_upnp_service.h"
#include "ip.h"
#include "platform.h"

#define DEBUG_UDP NO

static UPnP_ServiceAPI * upnp;

#include "udp_helper.c"

/**
 * Host-Address in a UDP network.
 */
typedef struct {
  /**
   * claimed IP of the sender, network byte order
   */
  IPaddr senderIP;

  /**
   * claimed port of the sender, network byte order
   */
  unsigned short senderPort;

  /**
   * reserved (set to 0 for signature verification)
   */
  unsigned short reserved;

} HostAddress;

static struct GC_Configuration * cfg;

static struct LoadMonitor * load_monitor;

static struct CIDRNetwork * filteredNetworks_;

static struct CIDRNetwork * allowedNetworks_;

static struct MUTEX * configLock;

/**
 * Get the GNUnet UDP port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 *
 * @return the port in host byte order
 */
static unsigned short getGNUnetUDPPort() {
  struct servent * pse;	/* pointer to service information entry	*/
  unsigned long long port;

  if (-1 == GC_get_configuration_value_number(cfg,
					      "UDP",
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
 * Allocate and bind a server socket for the UDP transport.
 */
static int listensock(unsigned short port) {
  struct sockaddr_in sin;
  int sock;
  const int on = 1;

  sock = SOCKET(PF_INET, SOCK_DGRAM, 17);
  if (sock < 0) {
    GE_DIE_STRERROR(ectx,
		    GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
		    "socket");
    return -1;
  }
  if ( SETSOCKOPT(sock,
		  SOL_SOCKET,
		  SO_REUSEADDR,
		  &on,
		  sizeof(on)) < 0 ) {
    GE_DIE_STRERROR(ectx,
		    GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
		    "setsockopt");
    return -1;
  }
  GE_ASSERT(NULL, port != 0);
  memset(&sin,
	 0,
	 sizeof(sin));
  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port        = htons(port);
  if (BIND(sock,
	   (struct sockaddr *)&sin,
	   sizeof(sin)) < 0) {
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
    return -1;
  }
  /* do not bind if port == 0, then we use
     send-only! */
  return sock;
}

/**
 * Check if we are explicitly forbidden to communicate with this IP.
 */
static int isBlacklisted(const void * addr,
			 unsigned int addr_len) {
  IPaddr ip;
  int ret;

  if (addr_len == sizeof(struct sockaddr_in)) {
    memcpy(&ip,
	   &((struct sockaddr_in*) addr)->sin_addr,
	   sizeof(IPaddr));
  } else if (addr_len == sizeof(IPaddr)) {
    memcpy(&ip,
	   addr,
	   addr_len);
  } else {
    return SYSERR;
  }
  MUTEX_LOCK(configLock);
  ret = check_ipv4_listed(filteredNetworks_,
			  ip);
  MUTEX_UNLOCK(configLock);
  return ret;
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int isWhitelisted(const void * addr,
			 unsigned int addr_len) {
  IPaddr ip;
  int ret;

  if (addr_len == sizeof(struct sockaddr_in)) {
    memcpy(&ip,
	   &((struct sockaddr_in*) addr)->sin_addr,
	   sizeof(IPaddr));
  } else if (addr_len == sizeof(IPaddr)) {
    memcpy(&ip,
	   addr,
	   addr_len);
  } else {
    return SYSERR;
  }
  ret = OK;
  MUTEX_LOCK(configLock);
  if (allowedNetworks_ != NULL)
    ret = check_ipv4_listed(allowedNetworks_,
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


/**
 * Verify that a hello-Message is correct (a node is reachable at that
 * address). Since the reply will be asynchronous, a method must be
 * called on success.
 *
 * @param helo the hello message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on failure
 */
static int verifyHelo(const P2P_hello_MESSAGE * helo) {
  HostAddress * haddr;

  haddr = (HostAddress*) &helo[1];
  if ( (ntohs(helo->senderAddressSize) != sizeof(HostAddress)) ||
       (ntohs(helo->header.size) != P2P_hello_MESSAGE_size(helo)) ||
       (ntohs(helo->header.type) != p2p_PROTO_hello) ||
       (YES == isBlacklisted(&haddr->senderIP,
			     sizeof(IPaddr))) ||
       (YES != isWhitelisted(&haddr->senderIP,
			     sizeof(IPaddr))) )
    return SYSERR; /* obviously invalid */
  else {
#if DEBUG_UDP
    GE_LOG(ectx, GE_DEBUG | GE_USER | GE_BULK,
	"Verified UDP helo from %u.%u.%u.%u:%u.\n",
	PRIP(ntohl(*(int*)&haddr->senderIP.addr)),
	ntohs(haddr->senderPort));
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
  HostAddress * haddr;
  unsigned short port;

  port = getGNUnetUDPPort();
  if (port == 0)
    return NULL; /* UDP transport configured send-only */

  msg = MALLOC(sizeof(P2P_hello_MESSAGE) + sizeof(HostAddress));
  haddr = (HostAddress*) &msg[1];


  if (! ( ( (upnp != NULL) &&
	    (OK == upnp->get_ip(port,
				"UDP",
				&haddr->senderIP)) ) ||
	  (SYSERR != getPublicIPAddress(cfg,
					ectx,
					&haddr->senderIP)) ) ) {
    FREE(msg);
    GE_LOG(ectx,
	   GE_WARNING | GE_ADMIN | GE_USER | GE_BULK,
	   _("UDP: Could not determine my public IP address.\n"));
    return NULL;  
  }
#if DEBUG_UDP
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_BULK,
	 "UDP uses IP address %u.%u.%u.%u.\n",
	 PRIP(ntohl(*(int*)&haddr->senderIP)));
#endif
  haddr->senderPort      = htons(port);
  haddr->reserved        = htons(0);
  msg->senderAddressSize = htons(sizeof(HostAddress));
  msg->protocol          = htons(UDP_PROTOCOL_NUMBER);
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
static int udpSend(TSession * tsession,
		   const void * message,
		   const unsigned int size,
		   int important) {
  UDPMessage * mp;
  P2P_hello_MESSAGE * helo;
  HostAddress * haddr;
  struct sockaddr_in sin; /* an Internet endpoint address */
  int ok;
  int ssize;
  size_t sent;

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
  helo = (P2P_hello_MESSAGE*)tsession->internal;
  if (helo == NULL)
    return SYSERR;

  haddr = (HostAddress*) &helo[1];
  ssize = size + sizeof(UDPMessage);
  mp = MALLOC(ssize);
  mp->header.size = htons(ssize);
  mp->header.type = 0;
  mp->sender = *(coreAPI->myIdentity);
  memcpy(&mp[1],
	 message,
	 size);
  ok = SYSERR;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = haddr->senderPort;

  GE_ASSERT(ectx, sizeof(struct in_addr) == sizeof(IPaddr));
  memcpy(&sin.sin_addr,
	 &haddr->senderIP,
	 sizeof(IPaddr));
#if DEBUG_UDP
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_BULK,
	 "Sending message of %d bytes via UDP to %u.%u.%u.%u:%u.\n",
	 ssize,
	 PRIP(ntohl(*(int*)&sin.sin_addr)),
	 ntohs(sin.sin_port));
#endif
  if (YES == socket_send_to(udp_sock,
			    NC_Nonblocking,
			    mp,
			    ssize,
			    &sent,
			    (const char *) &sin,
			    sizeof(sin))) {
    ok = OK;
    if (stats != NULL)
      stats->change(stat_bytesSent,
		    sent);
  } else {
    GE_LOG(ectx,
	   GE_WARNING | GE_ADMIN | GE_BULK,
	   _("Failed to send message of size %d via UDP to %u.%u.%u.%u:%u: %s\n"),
	   ssize,
	   PRIP(ntohl(*(int*)&sin.sin_addr)),
	   ntohs(sin.sin_port),
	   STRERROR(errno));
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
static int startTransportServer(void) {
  int sock;
  unsigned short port;

  GE_ASSERT(ectx, selector == NULL);
   /* initialize UDP network */
  port = getGNUnetUDPPort();
  if (port != 0) {
    sock = listensock(port);
    if (sock == -1)
      return SYSERR;
    selector = select_create("udp",
			     YES,
			     ectx,
			     load_monitor,
			     sock,
			     sizeof(struct sockaddr_in),
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
  GE_ASSERT(ectx, udp_sock != NULL);
  return OK;
}

/**
 * Reload the configuration. Should never fail.
 */
static int reloadConfiguration() {
  char * ch;

  MUTEX_LOCK(configLock);
  FREENONNULL(filteredNetworks_);
  FREENONNULL(allowedNetworks_);
  ch = NULL;
  GC_get_configuration_value_string(cfg,
				    "UDP",
				    "BLACKLIST",
				    "",
				    &ch);
  filteredNetworks_ = parse_ipv4_network_specification(ectx,
						       ch);
  FREE(ch);
  ch = NULL;
  GC_get_configuration_value_string(cfg,
				    "UDP",
				    "WHITELIST",
				    "",
				    &ch);
  if (strlen(ch) > 0)
    allowedNetworks_ = parse_ipv4_network_specification(ectx,
							ch);
  else
    allowedNetworks_ = NULL;
  FREE(ch);
  MUTEX_UNLOCK(configLock);
  return 0;
}

/**
 * Convert UDP address to a string.
 */
static char * 
addressToString(const P2P_hello_MESSAGE * hello,
		int do_resolve) {
  char * ret;
  const HostAddress * haddr = (const HostAddress*) &hello[1];
  size_t n;
  const char * hn = "";
  struct hostent * ent;

#if HAVE_GETHOSTBYADDR
  if (do_resolve) {
    ent = gethostbyaddr(haddr,
			sizeof(IPaddr),
			AF_INET);
    if (ent != NULL)
      hn = ent->h_name;
  }    
#endif
  n = 4*4+6+6 + strlen(hn) + 10;
  ret = MALLOC(n);
  if (strlen(hn) > 0) {
    SNPRINTF(ret,
	     n,
	     "%s (%u.%u.%u.%u) UDP (%u)",
	     hn,
	     PRIP(ntohl(*(int*)&haddr->senderIP.addr)),
	     ntohs(haddr->senderPort));
  } else {
    SNPRINTF(ret,
	     n,
	     "%u.%u.%u.%u UDP (%u)",
	     PRIP(ntohl(*(int*)&haddr->senderIP.addr)),
	     ntohs(haddr->senderPort));
  }
  return ret;
}

/**
 * The default maximum size of each outbound UDP message,
 * optimal value for Ethernet (10 or 100 MBit).
 */
#define MESSAGE_SIZE 1472

/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 */
TransportAPI * inittransport_udp(CoreAPIForTransport * core) {
  unsigned long long mtu;

  ectx = core->ectx;
  cfg = core->cfg;
  load_monitor = core->load_monitor;
  GE_ASSERT(ectx, sizeof(HostAddress) == 8);
  GE_ASSERT(ectx, sizeof(UDPMessage) == 68);
  coreAPI = core;
  if (-1 == GC_get_configuration_value_number(cfg,
					      "UDP",
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
	   "UDP");
  if (GC_get_configuration_value_yesno(cfg,
				       "UDP",
				       "UPNP",
				       YES) == YES) {
    upnp = coreAPI->requestService("upnp");
    
    if (upnp == NULL)
			GE_LOG(ectx,
	   		GE_ERROR | GE_USER | GE_IMMEDIATE,
	   		"The UPnP service could not be loaded. To disable UPnP, set the " \
	   		"configuration option \"UPNP\" in section \"UDP\" to \"NO\"\n");	
	}
  stats = coreAPI->requestService("stats");
  if (stats != NULL) {
    stat_bytesReceived
      = stats->create(gettext_noop("# bytes received via UDP"));
    stat_bytesSent
      = stats->create(gettext_noop("# bytes sent via UDP"));
    stat_bytesDropped
      = stats->create(gettext_noop("# bytes dropped by UDP (outgoing)"));
  }
  configLock = MUTEX_CREATE(NO);
  reloadConfiguration();
  udpAPI.protocolNumber       = UDP_PROTOCOL_NUMBER;
  udpAPI.mtu                  = mtu - sizeof(UDPMessage);
  udpAPI.cost                 = 20000;
  udpAPI.verifyHelo           = &verifyHelo;
  udpAPI.createhello          = &createhello;
  udpAPI.connect              = &udpConnect;
  udpAPI.send                 = &udpSend;
  udpAPI.associate            = &udpAssociate;
  udpAPI.disconnect           = &udpDisconnect;
  udpAPI.startTransportServer = &startTransportServer;
  udpAPI.stopTransportServer  = &stopTransportServer;
  udpAPI.addressToString      = &addressToString;
  udpAPI.testWouldTry         = &testWouldTry;

  return &udpAPI;
}

void donetransport_udp() {
  if (stats != NULL) {
    coreAPI->releaseService(stats);
    stats = NULL;
  }
  if (upnp != NULL) {
    coreAPI->releaseService(upnp);
    upnp = NULL;
  }
  MUTEX_DESTROY(configLock);
  configLock = NULL;
  FREENONNULL(filteredNetworks_);
  coreAPI = NULL;
}

/* end of udp.c */
