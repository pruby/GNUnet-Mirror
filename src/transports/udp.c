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
#include "platform.h"
#include "ip.h"

#define DEBUG_UDP NO

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

/**
 * Message-Packet header.
 */
typedef struct {
  /**
   * this struct is *preceded* by MESSAGE_PARTs - until
   * size-sizeof(UDPMessage)!
   */

  /**
   * size of the message, in bytes, including this header.
   */
  unsigned short size;

  /**
   * Currently always 0.
   */
  unsigned short reserved;

  /**
   * What is the identity of the sender (hash of public key)
   */
  PeerIdentity sender;

} UDPMessage;

/* *********** globals ************* */

/* apis (our advertised API and the core api ) */
static CoreAPIForTransport * coreAPI;
static TransportAPI udpAPI;

static Stats_ServiceAPI * stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;


/**
 * thread that listens for inbound messages
 */
static PTHREAD_T dispatchThread;

/**
 * the socket that we receive all data from
 */
static int udp_sock = -1;

/**
 * Semaphore for communication with the
 * udp server thread.
 */
static Semaphore * serverSignal;
static int udp_shutdown = YES;

/**
 * configuration
 */
static struct CIDRNetwork * filteredNetworks_ = NULL;
static Mutex configLock;

/**
 * Keep used port locally, the one in the configuration
 * may change and then we would not be able to send
 * the shutdown signal!
 */
static unsigned short port;


/**
 * Get the GNUnet UDP port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 *
 * @return the port in host byte order
 */
static unsigned short getGNUnetUDPPort() {
  struct servent * pse;	/* pointer to service information entry	*/
  unsigned short port;

  port = (unsigned short) getConfigurationInt("UDP",
					      "PORT");
  if (port == 0) { /* try lookup in services */
    if ((pse = getservbyname("gnunet", "udp")))
      port = ntohs(pse->s_port);
    else
      errexit(_("Cannot determine port to bind to. "
		" Define in configuration file in section `%s' under `%s' "
		"or in `%s' under %s/%s.\n"),
	      "UDP",
	      "PORT",
	      "/etc/services",
	      "udp",
	      "gnunet");
  }
  return port;
}

/**
 * Allocate and bind a server socket for the UDP transport.
 */
static int passivesock(unsigned short port) {
  struct sockaddr_in sin;
  int sock;
  const int on = 1;

  sock = SOCKET(PF_INET, SOCK_DGRAM, UDP_PROTOCOL_NUMBER);
  if (sock < 0)
    DIE_STRERROR("socket");
  if ( SETSOCKOPT(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0 )
    DIE_STRERROR("setsockopt");
  if (port != 0) {
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port        = htons(port);
    if (BIND(sock,
	     (struct sockaddr *)&sin,
	     sizeof(sin)) < 0) {
      LOG_STRERROR(LOG_FATAL, "bind");
      errexit(_("Failed to bind to UDP port %d.\n"),
		port);
    }
  } /* do not bind if port == 0, then we use
       send-only! */
  return sock;
}

/**
 * Check if we are explicitly forbidden to communicate with this IP.
 */
static int isBlacklisted(IPaddr ip) {
  int ret;

  MUTEX_LOCK(&configLock);
  ret = checkIPListed(filteredNetworks_,
		      ip);
  MUTEX_UNLOCK(&configLock);
  return ret;
}

/**
 * Listen on the given socket and distribute the packets to the UDP
 * handler.
 */
static void * listenAndDistribute() {
  struct sockaddr_in incoming;
  socklen_t addrlen = sizeof(incoming);
  int size;
  EncName enc;
  P2P_PACKET * mp;
  UDPMessage udpm;
  IPaddr ipaddr;
  int error;
  int pending;
  int ret;
  fd_set readSet;
  fd_set errorSet;
  fd_set writeSet;

  SEMAPHORE_UP(serverSignal);
  while (udp_shutdown == NO) {
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    FD_ZERO(&errorSet);
    FD_SET(udp_sock, &readSet);
    ret = SELECT(udp_sock + 1, &readSet, &writeSet, &errorSet, NULL);
    if (ret == -1) {
      if (udp_shutdown == YES)
	break;
      if (errno == EINTR)
	continue;
      DIE_STRERROR("select");
    }
    if (! FD_ISSET(udp_sock, &readSet))
      continue;
    pending = 0;
    /* @todo FIXME in PlibC */
#ifdef MINGW
    error = ioctlsocket(udp_sock,
#else
    error = ioctl(udp_sock,
#endif
		  FIONREAD,
		  &pending);
    if (error != 0) {
      LOG_STRERROR(LOG_ERROR, "ioctl");
      continue;
    }
    if (pending <= 0) {
      LOG(LOG_WARNING,
	  _("UDP: select returned, but ioctl reports %d bytes available!\n"),
	  pending);
      if (pending == 0) {
      	/* maybe empty UDP packet was sent (see report on bug-gnunet,
	   5/11/6; read 0 bytes from UDP just to kill potential empty packet! */
	memset(&incoming,
	       0, 
	       sizeof(struct sockaddr_in));
	RECVFROM(udp_sock,
		 NULL,
		 0,
		 0,
		 (struct sockaddr * )&incoming,
		 &addrlen);	
      }
      continue;
    }   
    if (pending >= 65536) {
      BREAK();
      continue;
    }   
    mp = MALLOC(sizeof(P2P_PACKET));
    mp->msg = MALLOC(pending);    
    memset(&incoming,
	   0,
	   sizeof(struct sockaddr_in));
    if (udp_shutdown == YES) {
      FREE(mp->msg);
      FREE(mp);
      break;
    }
    size = RECVFROM(udp_sock,
		    mp->msg,
		    pending,
		    0,
		    (struct sockaddr * )&incoming,
		    &addrlen);
    if ( (size < 0) ||
	 (udp_shutdown == YES) ) {
      FREE(mp->msg);
      FREE(mp);
      if (udp_shutdown == NO) {
	if ( (errno == EINTR) ||
	     (errno == EAGAIN) ||
	     (errno == ECONNREFUSED) ) 
	  continue;	
      }
      if (udp_shutdown == NO)
	LOG_STRERROR(LOG_ERROR, "recvfrom");
      break; /* die/shutdown */
    }
    incrementBytesReceived(size);
    stats->change(stat_bytesReceived,
		  size);

    if ((unsigned int)size <= sizeof(UDPMessage)) {
      LOG(LOG_INFO,
	  _("Received invalid UDP message from %u.%u.%u.%u:%u, dropping.\n"),
	  PRIP(ntohl(*(int*)&incoming.sin_addr)),
	  ntohs(incoming.sin_port));
      FREE(mp->msg);
      FREE(mp);
      continue;
    }
    memcpy(&udpm,
	   &((char*)mp->msg)[size - sizeof(UDPMessage)],
	   sizeof(UDPMessage));

    IFLOG(LOG_DEBUG,
	  hash2enc(&udpm.sender.hashPubKey,
		   &enc));
#if DEBUG_UDP
    LOG(LOG_DEBUG,
	"received %d bytes via UDP from %u.%u.%u.%u:%u (%s)\n",
	size,
	PRIP(ntohl(*(int*)&incoming.sin_addr)),
	ntohs(incoming.sin_port),
	&enc);
#endif
    /* quick test of the packet, if failed, repeat! */
    if (size != ntohs(udpm.size)) {
      LOG(LOG_WARNING,
	  _("Packet received from %u.%u.%u.%u:%u (UDP) failed format check.\n"),
	  PRIP(ntohl(*(int*)&incoming.sin_addr)),
	  ntohs(incoming.sin_port));
      FREE(mp->msg);
      FREE(mp);
      continue;
    }
    GNUNET_ASSERT(sizeof(struct in_addr) == sizeof(IPaddr));
    memcpy(&ipaddr,
	   &incoming.sin_addr,
	   sizeof(struct in_addr));
    if (YES == isBlacklisted(ipaddr)) {
      LOG(LOG_WARNING,
	  _("%s: Rejected connection from blacklisted "
	    "address %u.%u.%u.%u.\n"),
	  "UDP",
	  PRIP(ntohl(*(int*)&incoming.sin_addr)));
      FREE(mp->msg);
      FREE(mp);
      continue;
    }
    /* message ok, fill in mp and pass to core */
    mp->tsession = NULL;
    mp->size     = ntohs(udpm.size) - sizeof(UDPMessage);
    mp->sender   = udpm.sender;
    coreAPI->receive(mp);
  }
  /* shutdown */
  SEMAPHORE_UP(serverSignal);
  return NULL;
}


/* *************** API implementation *************** */

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
       (YES == isBlacklisted(haddr->senderIP)) )
    return SYSERR; /* obviously invalid */
  else {
#if DEBUG_UDP
    LOG(LOG_DEBUG,
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

  if ( ( (udp_shutdown == YES) && (getGNUnetUDPPort() == 0) ) ||
       ( (udp_shutdown == NO) && (port == 0) ) )
    return NULL; /* UDP transport configured send-only */

  msg = MALLOC(sizeof(P2P_hello_MESSAGE) + sizeof(HostAddress));
  haddr = (HostAddress*) &msg[1];

  if (SYSERR == getPublicIPAddress(&haddr->senderIP)) {
    FREE(msg);
    LOG(LOG_WARNING,
	_("UDP: Could not determine my public IP address.\n"));
    return NULL;
  }
#if DEBUG_UDP
  LOG(LOG_DEBUG,
      "UDP uses IP address %u.%u.%u.%u.\n",
      PRIP(ntohl(*(int*)&haddr->senderIP)));
#endif
  if (udp_shutdown == YES)
    haddr->senderPort      = htons(getGNUnetUDPPort());
  else
    haddr->senderPort      = htons(port);
  haddr->reserved        = htons(0);
  msg->senderAddressSize = htons(sizeof(HostAddress));
  msg->protocol          = htons(UDP_PROTOCOL_NUMBER);
  msg->MTU               = htonl(udpAPI.mtu);
  return msg;
}

/**
 * Establish a connection to a remote node.
 * @param helo the hello-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @return OK on success, SYSERR if the operation failed
 */
static int udpConnect(const P2P_hello_MESSAGE * helo,
		      TSession ** tsessionPtr) {
  TSession * tsession;
  HostAddress * haddr;

  tsession = MALLOC(sizeof(TSession));
  tsession->internal = MALLOC(P2P_hello_MESSAGE_size(helo));
  memcpy(tsession->internal,
	 helo,
	 P2P_hello_MESSAGE_size(helo));
  tsession->ttype = udpAPI.protocolNumber;
  haddr = (HostAddress*) &helo[1];
#if DEBUG_UDP
  LOG(LOG_DEBUG,
      "Connecting via UDP to %u.%u.%u.%u:%u.\n",
      PRIP(ntohl(*(int*)&haddr->senderIP.addr)),
      ntohs(haddr->senderPort));
#endif
   (*tsessionPtr) = tsession;
  return OK;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 */
int udpAssociate(TSession * tsession) {
  return SYSERR; /* UDP connections can never be associated */
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
		   const unsigned int size) {
  char * msg;
  UDPMessage mp;
  P2P_hello_MESSAGE * helo;
  HostAddress * haddr;
  struct sockaddr_in sin; /* an Internet endpoint address */
  int ok;
  int ssize;

  if (udp_shutdown == YES)
    return SYSERR;
  if (size == 0) {
    BREAK();
    return SYSERR;
  }
  if (size > udpAPI.mtu) {
    BREAK();
    return SYSERR;
  }
  helo = (P2P_hello_MESSAGE*)tsession->internal;
  if (helo == NULL)
    return SYSERR;

  haddr = (HostAddress*) &helo[1];
  ssize = size + sizeof(UDPMessage);
  msg       = MALLOC(ssize);
  mp.size   = htons(ssize);
  mp.reserved = 0;
  mp.sender = *(coreAPI->myIdentity);
  memcpy(&msg[size],
	 &mp,
	 sizeof(UDPMessage));
  memcpy(msg,
	 message,
	 size);
  ok = SYSERR;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = haddr->senderPort;

  GNUNET_ASSERT(sizeof(struct in_addr) == sizeof(IPaddr));
  memcpy(&sin.sin_addr,
	 &haddr->senderIP,
	 sizeof(IPaddr));
#if DEBUG_UDP
  LOG(LOG_DEBUG,
      "Sending message of %d bytes via UDP to %u.%u.%u.%u:%u.\n",
      ssize,
      PRIP(ntohl(*(int*)&sin.sin_addr)),
      ntohs(sin.sin_port));
#endif
  if (ssize == SENDTO(udp_sock,
		      msg,
		      ssize,
		      0, /* no flags */
		      (struct sockaddr*) &sin,
		      sizeof(sin))) {
    ok = OK;
    stats->change(stat_bytesSent,
		  ssize);
  } else {
    LOG(LOG_WARNING,
	_("Failed to send message of size %d via UDP to %u.%u.%u.%u:%u: %s\n"),
	ssize,
	PRIP(ntohl(*(int*)&sin.sin_addr)),
	ntohs(sin.sin_port),
	STRERROR(errno));
    stats->change(stat_bytesDropped,
		  ssize);
  }
  incrementBytesSent(ssize);
  FREE(msg);
  return ok;
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int udpDisconnect(TSession * tsession) {
  if (tsession != NULL) {
    if (tsession->internal != NULL)
      FREE(tsession->internal);
    FREE(tsession);
  }
  return OK;
}

/**
 * Start the server process to receive inbound traffic.
 *
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer(void) {
   /* initialize UDP network */
  port = getGNUnetUDPPort();
  udp_sock = passivesock(port);
  if (port != 0) {
    udp_shutdown = NO;
    serverSignal = SEMAPHORE_NEW(0);
    if (0 != PTHREAD_CREATE(&dispatchThread,
			    (PThreadMain) &listenAndDistribute,
			    NULL,
			    4*1024)) {
      SEMAPHORE_FREE(serverSignal);
      serverSignal = NULL;
      return SYSERR;
    }
    SEMAPHORE_DOWN(serverSignal);
  } else {
    memset(&dispatchThread,
	   0,
	   sizeof(PTHREAD_T)); /* zero-out */
  }
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int stopTransportServer() {
  GNUNET_ASSERT(udp_sock != -1);
  if (udp_shutdown == NO) {
    /* stop the thread, first set shutdown
       to YES, then ensure that the thread
       actually sees the flag by sending
       a dummy message of 1 char */
    udp_shutdown = YES;
    if (serverSignal != NULL) {
      char msg = '\0';
      struct sockaddr_in sin;
      void * unused;
      int mySock;

      mySock = SOCKET(PF_INET, SOCK_DGRAM, UDP_PROTOCOL_NUMBER);
      if (mySock < 0)
	DIE_STRERROR("socket");
      /* send to loopback */
      sin.sin_family = AF_INET;
      sin.sin_port = htons(port);
      *(int*)&sin.sin_addr = htonl(0x7F000001); /* 127.0.0.1 = localhost */
      SENDTO(mySock,
	     &msg,
	     sizeof(msg),
	     0,
	     (struct sockaddr*) &sin,
	     sizeof(sin));
      PTHREAD_KILL(&dispatchThread, SIGALRM);  /* sometimes LO is firewalled, try alternative */
      SEMAPHORE_DOWN(serverSignal);
      SEMAPHORE_FREE(serverSignal);
      PTHREAD_JOIN(&dispatchThread, &unused);
    }
  }
  closefile(udp_sock);
  udp_sock = -1;
  return OK;
}

/**
 * Reload the configuration. Should never fail.
 */
static void reloadConfiguration(void) {
  char * ch;

  MUTEX_LOCK(&configLock);
  FREENONNULL(filteredNetworks_);
  ch = getConfigurationString("UDP",
			      "BLACKLIST");
  if (ch == NULL)
    filteredNetworks_ = parseRoutes("");
  else {
    filteredNetworks_ = parseRoutes(ch);
    FREE(ch);
  }
  MUTEX_UNLOCK(&configLock);
}

/**
 * Convert UDP address to a string.
 */
static char * addressToString(const P2P_hello_MESSAGE * helo) {
  char * ret;
  HostAddress * haddr;
  size_t n;

  haddr = (HostAddress*) &helo[1];
  n = 4*4+6+6;
  ret = MALLOC(n);
  SNPRINTF(ret,
	   n,
	   "%u.%u.%u.%u:%u (UDP)",
	   PRIP(ntohl(*(int*)&haddr->senderIP.addr)),
	   ntohs(haddr->senderPort));
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
  int mtu;

  GNUNET_ASSERT(sizeof(HostAddress) == 8);
  GNUNET_ASSERT(sizeof(UDPMessage) == 68);
  coreAPI = core;
  stats = coreAPI->requestService("stats");
  if (stats != NULL) {
    stat_bytesReceived
      = stats->create(gettext_noop("# bytes received via UDP"));
    stat_bytesSent
      = stats->create(gettext_noop("# bytes sent via UDP"));
    stat_bytesDropped
      = stats->create(gettext_noop("# bytes dropped by UDP (outgoing)"));
  }

  MUTEX_CREATE(&configLock);
  reloadConfiguration();
  mtu = getConfigurationInt("UDP",
			    "MTU");
  if (mtu == 0)
    mtu = MESSAGE_SIZE;
  if (mtu < 1200)
    LOG(LOG_ERROR,
	_("MTU for `%s' is probably too low (fragmentation not implemented!)\n"),
	"UDP");

  udpAPI.protocolNumber       = UDP_PROTOCOL_NUMBER;
  udpAPI.mtu                  = mtu - sizeof(UDPMessage);
  udpAPI.cost                 = 20000;
  udpAPI.verifyHelo           = &verifyHelo;
  udpAPI.createhello           = &createhello;
  udpAPI.connect              = &udpConnect;
  udpAPI.send                 = &udpSend;
  udpAPI.sendReliable         = &udpSend; /* can't increase reliability */
  udpAPI.associate            = &udpAssociate;
  udpAPI.disconnect           = &udpDisconnect;
  udpAPI.startTransportServer = &startTransportServer;
  udpAPI.stopTransportServer  = &stopTransportServer;
  udpAPI.reloadConfiguration  = &reloadConfiguration;
  udpAPI.addressToString      = &addressToString;

  return &udpAPI;
}

void donetransport_udp() {
  coreAPI->releaseService(stats);
  MUTEX_DESTROY(&configLock);
  FREENONNULL(filteredNetworks_);
  coreAPI = NULL;
}

/* end of udp.c */
