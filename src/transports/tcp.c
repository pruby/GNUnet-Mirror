/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file transports/tcp.c
 * @brief Implementation of the TCP transport service
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_upnp_service.h"
#include "gnunet_stats_service.h"
#include "platform.h"
#include "ip.h"

#define DEBUG_TCP NO

/**
 * after how much time of the core not being associated with a tcp
 * connection anymore do we close it?
 */
#define TCP_TIMEOUT (30 * cronSECONDS)

#define TARGET_BUFFER_SIZE 4092

#include "tcp_helper.c"

/**
 * Host-Address in a TCP network.
 */
typedef struct {
  /**
   * claimed IP of the sender, network byte order
   */
  IPaddr ip;

  /**
   * claimed port of the sender, network byte order
   */
  unsigned short port;

  /**
   * reserved (set to 0 for signature verification)
   */
  unsigned short reserved;

} HostAddress;

/* *********** globals ************* */

static TransportAPI tcpAPI;

static UPnP_ServiceAPI * upnp;

static struct CIDRNetwork * filteredNetworks_;

static struct CIDRNetwork * allowedNetworks_;

static struct GC_Configuration * cfg;

static struct MUTEX * tcpblacklistlock;

/**
 * Check if we are allowed to connect to the given IP.
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
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_ADMIN | GE_BULK,
	   "Rejecting connection (invalid address length %u)\n",
	   addr_len);
#endif
    return SYSERR;
  }
  MUTEX_LOCK(tcpblacklistlock);
  ret = check_ipv4_listed(filteredNetworks_,
			  ip);
  MUTEX_UNLOCK(tcpblacklistlock);
#if DEBUG_TCP
  if (ret != OK) 
    GE_LOG(ectx,
	   GE_DEBUG | GE_ADMIN | GE_BULK,
	   "Rejecting connection from address %u.%u.%u.%u (blacklisted)\n",
	   PRIP(ntohl(*(int*)addr)));
#endif
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
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_ADMIN | GE_BULK,
	   "Rejecting connection (invalid address length %u)\n",
	   addr_len);
#endif
    return SYSERR;
  }
  ret = OK;
  MUTEX_LOCK(tcpblacklistlock);
  if (allowedNetworks_ != NULL)
    ret = check_ipv4_listed(allowedNetworks_,
			    ip);
  MUTEX_UNLOCK(tcpblacklistlock);
  if (ret != OK) {
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_ADMIN | GE_BULK,
	   "Rejecting HELLO from address %u.%u.%u.%u (not whitelisted)\n",
	   PRIP(ntohl(*(int*)addr)));
#endif
  }
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
 * Get the GNUnet UDP port from the configuration,
 * or from /etc/services if it is not specified in
 * the config file.
 */
static unsigned short getGNUnetTCPPort() {
  struct servent * pse;	/* pointer to service information entry	*/
  unsigned long long port;

  if (-1 == GC_get_configuration_value_number(cfg,
					      "TCP",
					      "PORT",
					      0,
					      65535,
					      2086,
					      &port)) {
    if ((pse = getservbyname("gnunet", "tcp")))
      port = htons(pse->s_port);
    else
      port = 0;
  }
  return (unsigned short) port;
}

/**
 * Verify that a Hello-Message is correct (a node
 * is reachable at that address). Since the reply
 * will be asynchronous, a method must be called on
 * success.
 * @param helo the Hello message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on error
 */
static int verifyHelo(const P2P_hello_MESSAGE * helo) {
  HostAddress * haddr;

  haddr = (HostAddress*) &helo[1];
  if ( (ntohs(helo->senderAddressSize) != sizeof(HostAddress)) ||
       (ntohs(helo->header.size) != P2P_hello_MESSAGE_size(helo)) ||
       (ntohs(helo->header.type) != p2p_PROTO_hello) ||
       (ntohs(helo->protocol) != TCP_PROTOCOL_NUMBER) ||
       (YES == isBlacklisted(&haddr->ip,
			     sizeof(IPaddr))) ||
       (YES != isWhitelisted(&haddr->ip,
			     sizeof(IPaddr))) ) {
#if DEBUG_TCP
    EncName enc;

    hash2enc(&helo->senderIdentity.hashPubKey,
	     &enc);
    GE_LOG(ectx,
	   GE_DEBUG | GE_ADMIN | GE_BULK,
	   "Rejecting HELLO from `%s'\n",
	   &enc);
#endif
    return SYSERR; /* obviously invalid */
  } 
  return OK;
}

/**
 * Create a hello-Message for the current node. The hello is
 * created without signature and without a timestamp. The
 * GNUnet core will sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static P2P_hello_MESSAGE * createhello() {
  P2P_hello_MESSAGE * msg;
  HostAddress * haddr;
  unsigned short port;

  port = getGNUnetTCPPort();
  if (0 == port) {
    static int once = 0;
    if (once == 0) {
      once = 1;
#if DEBUG_TCP
      GE_LOG(ectx,
	     GE_DEBUG | GE_USER | GE_BULK,
	     "TCP port is 0, will only send using TCP.\n");
#endif
    }
    return NULL; /* TCP transport is configured SEND-only! */
  }
  msg = (P2P_hello_MESSAGE *) MALLOC(sizeof(P2P_hello_MESSAGE) + sizeof(HostAddress));
  haddr = (HostAddress*) &msg[1];

  if (! ( ( (upnp != NULL) &&
	    (OK == upnp->get_ip(port,
				"TCP",
				&haddr->ip)) ) ||
	  (SYSERR != getPublicIPAddress(cfg,
					ectx,
					&haddr->ip)) ) ) {
    FREE(msg);
    GE_LOG(ectx,
	   GE_WARNING | GE_ADMIN | GE_USER | GE_BULK,
	   _("TCP: Could not determine my public IP address.\n"));
    return NULL;  
  }
#if DEBUG_TCP
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_REQUEST,
	 "TCP uses IP address %u.%u.%u.%u.\n",
	 PRIP(ntohl(*(int*)&haddr->ip)));
#endif
  haddr->port = htons(port);
  haddr->reserved = htons(0);
  msg->senderAddressSize = htons(sizeof(HostAddress));
  msg->protocol = htons(TCP_PROTOCOL_NUMBER);
  msg->MTU = htonl(tcpAPI.mtu);
  return msg;
}

/**
 * Establish a connection to a remote node.
 *
 * @param helo the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return OK on success, SYSERR if the operation failed
 */
static int tcpConnect(const P2P_hello_MESSAGE * helo,
		      TSession ** tsessionPtr) {
  static int zero = 0;
  HostAddress * haddr;
  int sock;
  struct sockaddr_in soaddr;
  struct SocketHandle * s;
  int i;

  if (selector == NULL)
    return SYSERR;
  haddr = (HostAddress*) &helo[1];
#if DEBUG_TCP
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_BULK,
	 "Creating TCP connection to %u.%u.%u.%u:%u.\n",
	 PRIP(ntohl(*(int*)&haddr->ip.addr)),
	 ntohs(haddr->port));
#endif
  sock = SOCKET(PF_INET,
		SOCK_STREAM,
		6); /* 6: TCP */
  if (sock == -1) {
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_ADMIN | GE_BULK,
		    "socket");
    return SYSERR;
  }
  s = socket_create(ectx,
		    coreAPI->load_monitor,
		    sock);
#if TCP_SYNCNT
  /* only try a single packet to establish connection,
     if that does not work, abort instantly */
  setsockopt(sock,
	     IPPROTO_TCP,
	     TCP_SYNCNT,
	     &zero,
	     sizeof(zero));
#endif
  if (-1 == socket_set_blocking(s, NO)) {
    socket_destroy(s);
    return SYSERR;
  }
  memset(&soaddr,
	 0,
	 sizeof(soaddr));
  soaddr.sin_family = AF_INET;

  GE_ASSERT(ectx, 
	    sizeof(struct in_addr) == sizeof(IPaddr));
  memcpy(&soaddr.sin_addr,
	 &haddr->ip,
	 sizeof(IPaddr));
  soaddr.sin_port = haddr->port;
  i = CONNECT(sock,
	      (struct sockaddr*)&soaddr,
	      sizeof(soaddr));
  if ( (i < 0) &&
       (errno != EINPROGRESS) ) {
    GE_LOG(ectx,
	   GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
	   _("Cannot connect to %u.%u.%u.%u:%u: %s\n"),
	   PRIP(ntohl(*(int*)&haddr->ip)),
	   ntohs(haddr->port),
	   STRERROR(errno));
    socket_destroy(s);
    return SYSERR;
  }
#if DEBUG_TCP
  GE_LOG(ectx,
	 GE_DEBUG | GE_DEVELOPER | GE_USER | GE_BULK,
	 "Establishing connection to %u.%u.%u.%u:%u\n",
	 PRIP(ntohl(*(int*)&haddr->ip)),
	 ntohs(haddr->port));
#endif
  return tcpConnectHelper(helo,
			  s,
			  tcpAPI.protocolNumber,
			  tsessionPtr);
}

/**
 * Start the server process to receive inbound traffic.
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer(void) {
  struct sockaddr_in serverAddr;
  const int on = 1;
  unsigned short port;
  int s;

  if (selector != NULL) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  port = getGNUnetTCPPort();
  if (port != 0) {
    s = SOCKET(PF_INET,
	       SOCK_STREAM,
	       0);
    if (s < 0) {
      GE_LOG_STRERROR(ectx,
		      GE_ERROR | GE_ADMIN | GE_BULK,
		      "socket");
      return SYSERR;
    }
    if (SETSOCKOPT(s,
		   SOL_SOCKET,
		   SO_REUSEADDR,
		   &on,
		   sizeof(on)) < 0 )
      GE_DIE_STRERROR(ectx,
		      GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
		      "setsockopt");
    memset((char *) &serverAddr,
	   0,
	   sizeof(serverAddr));
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port        = htons(getGNUnetTCPPort());
    if (BIND(s,
	     (struct sockaddr *) &serverAddr,
	     sizeof(serverAddr)) < 0) {
      GE_LOG_STRERROR(ectx,
		      GE_ERROR | GE_ADMIN | GE_IMMEDIATE,
		    "bind");
      GE_LOG(ectx,
	     GE_ERROR | GE_ADMIN | GE_IMMEDIATE,
	   _("Failed to start transport service on port %d.\n"),
	     getGNUnetTCPPort());
      if (0 != CLOSE(s))
	GE_LOG_STRERROR(ectx,
			GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			"close");
      return SYSERR;
    }
  } else {
    s = -1; /* no listening! */
  }
  selector = select_create("tcp",
			   NO,
			   ectx,
			   coreAPI->load_monitor,
			   s,
			   sizeof(struct sockaddr_in),
			   TCP_TIMEOUT,
			   &select_message_handler,
			   NULL,
			   &select_accept_handler,
			   &isRejected,
			   &select_close_handler,
			   NULL,
			   128 * 1024);
  return OK;
}

/**
 * Reload the configuration. Should never fail (keep old
 * configuration on error, syslog errors!)
 */
static int reloadConfiguration(void * ctx,
			       struct GC_Configuration * cfg,
			       struct GE_Context * ectx,
			       const char * section,
			       const char * option) {
  char * ch;

  if (0 != strcmp(section, "TCP"))
    return 0; /* fast path */
	
  MUTEX_LOCK(tcpblacklistlock);
  FREENONNULL(filteredNetworks_);
  FREENONNULL(allowedNetworks_);
  ch = NULL;
  GC_get_configuration_value_string(cfg,
				    "TCP",
				    "BLACKLIST",
				    "",
				    &ch);
  filteredNetworks_ = parse_ipv4_network_specification(ectx,
						       ch);
  FREE(ch);
  ch = NULL;
  GC_get_configuration_value_string(cfg,
				    "TCP",
				    "WHITELIST",
				    "",
				    &ch);
  if (strlen(ch) > 0)
    allowedNetworks_ = parse_ipv4_network_specification(ectx,
							ch);
  else
    allowedNetworks_ = NULL;
  FREE(ch);
  MUTEX_UNLOCK(tcpblacklistlock);
  /* TODO: error handling! */
  return 0;
}

/**
 * Convert TCP address to a string.
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
	     "%s (%u.%u.%u.%u) TCP (%u)",
	     hn,
	     PRIP(ntohl(*(int*)&haddr->ip.addr)),
	     ntohs(haddr->port));
  } else {
    SNPRINTF(ret,
	     n,
	     "%u.%u.%u.%u TCP (%u)",
	     PRIP(ntohl(*(int*)&haddr->ip.addr)),
	     ntohs(haddr->port));
  }
  return ret;
}


/* ******************** public API ******************** */

/**
 * The exported method. Makes the core api available
 * via a global and returns the udp transport API.
 */
TransportAPI * inittransport_tcp(CoreAPIForTransport * core) {
  ectx = core->ectx;
  cfg = core->cfg;
  GE_ASSERT(ectx, sizeof(HostAddress) == 8);
  GE_ASSERT(ectx, sizeof(MESSAGE_HEADER) == 4);
  GE_ASSERT(ectx, sizeof(TCPWelcome) == 68);
  tcplock = MUTEX_CREATE(YES);
  tcpblacklistlock = MUTEX_CREATE(YES);
  if (0 != GC_attach_change_listener(cfg,
				     &reloadConfiguration,
				     NULL)) {
    MUTEX_DESTROY(tcplock);
    MUTEX_DESTROY(tcpblacklistlock);
    tcplock = NULL;
    tcpblacklistlock = NULL;
    return NULL;
  }
  coreAPI = core;
  if (GC_get_configuration_value_yesno(cfg,
				       "TCP",
				       "UPNP",
				       YES) == YES) {
    upnp = coreAPI->requestService("upnp");
    
    if (upnp == NULL) {
      GE_LOG(ectx,
	     GE_ERROR | GE_USER | GE_IMMEDIATE,
	     _("The UPnP service could not be loaded. To disable UPnP, set the " \
	       "configuration option \"UPNP\" in section \"TCP\" to \"NO\"\n"));	

    }
  }
  stats = coreAPI->requestService("stats");
  if (stats != NULL) {
    stat_bytesReceived
      = stats->create(gettext_noop("# bytes received via TCP"));
    stat_bytesSent
      = stats->create(gettext_noop("# bytes sent via TCP"));
    stat_bytesDropped
      = stats->create(gettext_noop("# bytes dropped by TCP (outgoing)"));
  }
  tcpAPI.protocolNumber       = TCP_PROTOCOL_NUMBER;
  tcpAPI.mtu                  = 0;
  tcpAPI.cost                 = 20000; /* about equal to udp */
  tcpAPI.verifyHelo           = &verifyHelo;
  tcpAPI.createhello          = &createhello;
  tcpAPI.connect              = &tcpConnect;
  tcpAPI.associate            = &tcpAssociate;
  tcpAPI.send                 = &tcpSend;
  tcpAPI.disconnect           = &tcpDisconnect;
  tcpAPI.startTransportServer = &startTransportServer;
  tcpAPI.stopTransportServer  = &stopTransportServer;
  tcpAPI.addressToString      = &addressToString;
  tcpAPI.testWouldTry         = &tcpTestWouldTry;

  return &tcpAPI;
}

void donetransport_tcp() {
  GC_detach_change_listener(cfg,
			    &reloadConfiguration,
			    NULL);
  if (stats != NULL) {
    coreAPI->releaseService(stats);
    stats = NULL;
  }
  if (upnp != NULL) {
    coreAPI->releaseService(upnp);
    upnp = NULL;
  }
  FREENONNULL(filteredNetworks_);
  FREENONNULL(allowedNetworks_);
  MUTEX_DESTROY(tcplock);
  MUTEX_DESTROY(tcpblacklistlock);
}

/* end of tcp.c */
