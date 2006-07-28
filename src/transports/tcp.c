/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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

/**
 * Initial handshake message. Note that the beginning
 * must match the CS_MESSAGE_HEADER since we are using tcpio.
 */
typedef struct {
  MESSAGE_HEADER header;

  /**
   * Identity of the node connecting (TCP client)
   */
  PeerIdentity clientIdentity;
} TCPWelcome;

/**
 * Transport Session handle.
 */
typedef struct {
  /**
   * the tcp socket (used to identify this connection with selector)
   */
  struct SocketHandle * sock;

  /**
   * number of users of this session (reference count)
   */
  int users;

  /**
   * mutex for synchronized access to 'users'
   */
  struct MUTEX * lock;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  PeerIdentity sender;

  /**
   * Are we still expecting the welcome? (YES/NO)
   */
  int expectingWelcome;

} TCPSession;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static CoreAPIForTransport * coreAPI;

static TransportAPI tcpAPI;

static Stats_ServiceAPI * stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

/* configuration */
static struct CIDRNetwork * filteredNetworks_;

static struct SelectHandle * selector;

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

static struct MUTEX * tcplock;

/* ******************** helper functions *********************** */

/**
 * Check if we are allowed to connect to the given IP.
 */
static int isBlacklisted(IPaddr ip) {
  int ret;

  MUTEX_LOCK(tcplock);
  ret = check_ipv4_listed(filteredNetworks_,
			  ip);
  MUTEX_UNLOCK(tcplock);
  return ret;
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
					      1,
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
 * Disconnect from a remote node. May only be called
 * on sessions that were aquired by the caller first.
 * For the core, aquiration means to call associate or
 * connect. The number of disconnects must match the
 * number of calls to connect+associate.
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int tcpDisconnect(TSession * tsession) {
  TCPSession * tcpsession = tsession->internal;

  GE_ASSERT(ectx, tcpsession != NULL);
  MUTEX_LOCK(tcpsession->lock);
  tcpsession->users--;
  if (tcpsession->users > 0) {
    MUTEX_UNLOCK(tcpsession->lock);
    return OK;
  }  
  select_disconnect(selector,
		    tcpsession->sock);
  MUTEX_UNLOCK(tcpsession->lock);
  MUTEX_DESTROY(tcpsession->lock);
  FREE(tcpsession);  
  FREE(tsession);
  return OK;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed. Associate can also be
 * called to test if it would be possible to associate the session
 * later, in this case the argument session is NULL. This can be used
 * to test if the connection must be closed by the core or if the core
 * can assume that it is going to be self-managed (if associate
 * returns OK and session was NULL, the transport layer is responsible
 * for eventually freeing resources associated with the tesession). If
 * session is not NULL, the core takes responsbility for eventually
 * calling disconnect.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 */
static int tcpAssociate(TSession * tsession) {
  TCPSession * tcpSession;

  GE_ASSERT(ectx, tsession != NULL);
  tcpSession = tsession->internal;
  MUTEX_LOCK(tcpSession->lock);
  tcpSession->users++;
  MUTEX_UNLOCK(tcpSession->lock);
  return OK;
}

/**
 * The socket of session i has data waiting, process!
 *
 * This function may only be called if the tcplock is
 * already held by the caller.
 */
static int select_message_handler(void * mh_cls,
				  struct SelectHandle * sh,
				  struct SocketHandle * sock,
				  void * sock_ctx,
				  const MESSAGE_HEADER * msg) {
  TSession * tsession = sock_ctx;
  TCPSession * tcpSession;
  unsigned int len;
  P2P_PACKET * mp;
  const TCPWelcome * welcome;

  if (SYSERR == tcpAssociate(tsession))
    return SYSERR;
  len = ntohs(msg->size);
  tcpSession = tsession->internal;
  if (YES == tcpSession->expectingWelcome) {    
    welcome = (const TCPWelcome*) msg;
    if ( (ntohs(welcome->header.type) != 0) ||
	 (len != sizeof(TCPWelcome)) ) {
      tcpDisconnect(tsession);
      return SYSERR;    
    }
    tcpSession->expectingWelcome = NO;
    tcpSession->sender = welcome->clientIdentity;
  } else {
    /* send msg to core! */
    if (len <= sizeof(MESSAGE_HEADER)) {
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_BULK,
	     _("Received malformed message from tcp-peer connection. Closing.\n"));
      tcpDisconnect(tsession);
      return SYSERR;
    }
    mp      = MALLOC(sizeof(P2P_PACKET));
    mp->msg = MALLOC(len - sizeof(MESSAGE_HEADER));
    memcpy(mp->msg,
	   &msg[1],
	   len - sizeof(MESSAGE_HEADER));
    mp->sender   = tcpSession->sender;
    mp->size     = len - sizeof(MESSAGE_HEADER);
    mp->tsession = tsession;
    coreAPI->receive(mp);
  }
  tcpDisconnect(tsession);
  return OK;
}


/**
 * Create a new session for an inbound connection on the given
 * socket. Adds the session to the array of sessions watched
 * by the select thread.
 */
static void * select_accept_handler(void * ah_cls,
				    struct SelectHandle * sh,
				    struct SocketHandle * sock,
				    const void * addr,
				    unsigned int addr_len) {
  TSession * tsession;
  TCPSession * tcpSession;
  IPaddr ip;

  if (addr_len != sizeof(IPaddr))
    return NULL;
  memcpy(&ip,
	 addr,
	 addr_len);
  if (isBlacklisted(ip))
    return NULL;
  tcpSession = MALLOC(sizeof(TCPSession));
  tcpSession->sock = sock;
  /* fill in placeholder identity to mark that we
     are waiting for the welcome message */
  tcpSession->sender = *(coreAPI->myIdentity);
  tcpSession->expectingWelcome = YES;
  tcpSession->lock = MUTEX_CREATE(YES);
  tcpSession->users = 1; /* us only, core has not seen this tsession! */
  tsession = MALLOC(sizeof(TSession));
  tsession->ttype = TCP_PROTOCOL_NUMBER;
  tsession->internal = tcpSession;

  return tsession;
}					

static void select_close_handler(void * ch_cls,
				 struct SelectHandle * sh,
				 struct SocketHandle * sock,
				 void * sock_ctx) {
  TSession * tsession = sock_ctx;
  tcpDisconnect(tsession);
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the handle identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @return SYSERR on error, OK on success
 */
static int tcpSend(TSession * tsession,
		   const void * msg,
		   const unsigned int size,
		   int important) {
  TCPSession * tcpSession;
  MESSAGE_HEADER * mp;
  int ok;

  tcpSession = tsession->internal;
  if (size >= MAX_BUFFER_SIZE - sizeof(MESSAGE_HEADER)) {
    GE_BREAK(ectx, 0);
    return SYSERR; /* too big */
  }
  if (selector == NULL) {
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    size);
    return SYSERR;
  }
  if (size == 0) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  if (tcpSession->sock == NULL) {
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    size);
    return SYSERR; /* other side closed connection */
  }
  mp = MALLOC(sizeof(MESSAGE_HEADER) + size);
  mp->size = htons(size + sizeof(MESSAGE_HEADER));
  mp->type = 0;
  memcpy(&mp[1],
	 msg,
	 size);
  ok = select_write(selector,
		    tcpSession->sock,
		    mp,
		    NO,
		    important);
  FREE(mp);
  return ok;
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
       (YES == isBlacklisted(haddr->ip)) )
    return SYSERR; /* obviously invalid */
  else
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
      GE_LOG(ectx,
	     GE_DEBUG | GE_USER | GE_BULK, 
	     "TCP port is 0, will only send using TCP.\n");
    }
    return NULL; /* TCP transport is configured SEND-only! */
  }
  msg = (P2P_hello_MESSAGE *) MALLOC(sizeof(P2P_hello_MESSAGE) + sizeof(HostAddress));
  haddr = (HostAddress*) &msg[1];

  if (SYSERR == getPublicIPAddress(cfg,
				   ectx,
				   &haddr->ip)) {
    FREE(msg);
    GE_LOG(ectx,
	   GE_WARNING | GE_ADMIN | GE_USER | GE_BULK,
	   _("Could not determine my public IP address.\n"));
    return NULL;
  }
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_BULK, 
	 "TCP uses IP address %u.%u.%u.%u.\n",
	 PRIP(ntohl(*(int*)&haddr->ip)));
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
  HostAddress * haddr;
  TCPWelcome welcome;
  int sock;
  TSession * tsession;
  TCPSession * tcpSession;
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
  if (-1 == socket_set_blocking(s, NO)) {
    socket_destroy(s);
    return SYSERR;
  }
  memset(&soaddr,
	 0,
	 sizeof(soaddr));
  soaddr.sin_family = AF_INET;

  GE_ASSERT(ectx, sizeof(struct in_addr) == sizeof(IPaddr));
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
  tcpSession = MALLOC(sizeof(TCPSession));
  tcpSession->sock = s;
  tsession = MALLOC(sizeof(TSession));
  tsession->internal = tcpSession;
  tsession->ttype = tcpAPI.protocolNumber;
  tcpSession->lock = MUTEX_CREATE(YES);
  tcpSession->users = 2; /* caller + us */
  tcpSession->sender = helo->senderIdentity;
  tcpSession->expectingWelcome = NO;
  MUTEX_LOCK(tcplock);
  select_connect(selector,
		 tcpSession->sock,
		 tsession);

  /* send our node identity to the other side to fully establish the
     connection! */
  welcome.header.size
    = htons(sizeof(TCPWelcome));
  welcome.header.type
    = htons(0);
  welcome.clientIdentity
    = *(coreAPI->myIdentity);
  if (SYSERR == tcpSend(tsession,
			&welcome.header,
			sizeof(TCPWelcome),
			YES)) {
    tcpDisconnect(tsession);
    MUTEX_UNLOCK(tcplock);
    return SYSERR;
  }
  MUTEX_UNLOCK(tcplock);
  *tsessionPtr = tsession;
  return OK;
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
  if (port == 0) { 
    /* read-only TCP */
    return OK;
  }
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
  selector = select_create(ectx,
			   coreAPI->load_monitor,
			   s,
			   sizeof(IPaddr),
			   0, /* timeout */
			   &select_message_handler,
			   NULL,
			   &select_accept_handler,
			   NULL,
			   &select_close_handler,
			   NULL,
			   0 /* memory quota */ );
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). Maybe restarted later!
 */
static int stopTransportServer() {
  if (selector != NULL) {
    select_destroy(selector);
    selector = NULL;
  }
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
    return OK; /* fast path */
	
  MUTEX_LOCK(tcplock);
  FREENONNULL(filteredNetworks_);
  if (0 != GC_get_configuration_value_string(cfg,
					     "TCP",
					     "BLACKLIST",
					     NULL,
					     &ch)) 
    filteredNetworks_ = parse_ipv4_network_specification(ectx,
							 "");
  else {
    filteredNetworks_ = parse_ipv4_network_specification(ectx,
							 ch);
    FREE(ch);
  }
  MUTEX_UNLOCK(tcplock);
  /* TODO: error handling! */
  return OK;
}

/**
 * Convert TCP address to a string.
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
	   "%u.%u.%u.%u:%u (TCP)",
	   PRIP(ntohl(*(int*)&haddr->ip.addr)),
	   ntohs(haddr->port));
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
  if (0 != GC_attach_change_listener(cfg,
				     &reloadConfiguration,
				     NULL)) {
    MUTEX_DESTROY(tcplock);
    tcplock = NULL;
    return NULL;
  }
  coreAPI = core;
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

  return &tcpAPI;
}

void donetransport_tcp() {
  GC_detach_change_listener(cfg,
			    &reloadConfiguration,
			    NULL);
  coreAPI->releaseService(stats);
  stats = NULL;
  FREENONNULL(filteredNetworks_);
  MUTEX_DESTROY(tcplock);
}

/* end of tcp.c */
