/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * TCP Message-Packet header.
 */
typedef struct {
  /**
   * size of the message, in bytes, excluding this header;
   * max 65535; we do NOT want to make this field an int
   * because then a malicious peer could cause us to allocate
   * lots of memory -- this bounds it by 64k/peer.
   * Field is in network byte order.
   */
  unsigned short size;

  /**
   * For alignment, always 0.
   */
  unsigned short reserved;

  /**
   * This struct is followed by MESSAGE_PARTs - until size is reached
   * There is no "end of message".
   */
} TCPP2P_PACKET;

/**
 * Initial handshake message. Note that the beginning
 * must match the CS_MESSAGE_HEADER since we are using tcpio.
 */
typedef struct {
  TCPP2P_PACKET header;

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
   * the tcp socket
   */
  struct SocketHandle * sock;

  /**
   * number of users of this session
   */
  int users;

  /**
   * Last time this connection was used
   */
  cron_t lastUse;

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
  if (tsession->internal != NULL) {
    TCPSession * tcpsession = tsession->internal;

    MUTEX_LOCK(tcpsession->lock);
    tcpsession->users--;
    if (tcpsession->users > 0) {
      MUTEX_UNLOCK(tcpsession->lock);
      return OK;
    }
    MUTEX_UNLOCK(tcpsession->lock);
    MUTEX_DESTROY(tcpsession->lock);
    FREE(tcpsession->rbuff);
    FREENONNULL(tcpsession->wbuff);
    tcpsession->wbuff = NULL;
    FREE(tcpsession);
  }
  FREE(tsession);
  return OK;
}

/**
 * Remove a session, either the other side closed the connection
 * or we have otherwise reason to believe that it should better
 * be killed. Destroy session closes the session as far as the
 * TCP layer is concerned, but since the core may still have
 * references to it, tcpDisconnect may not instantly free all
 * the associated resources. <p>
 *
 * destroySession may only be called if the tcplock is already
 * held.
 *
 * @param i index to the session handle
 */
static void destroySession(int i) {
  TCPSession * tcpSession;

  tcpSession = tsessions[i]->internal;
  if (tcpSession->sock != NULL)
    socket_destroy(tcpSession->sock);
  tcpSession->sock = NULL;
  tcpDisconnect(tsessions[i]);
  tsessions[i] = tsessions[--tsessionCount];
  tsessions[tsessionCount] = NULL;
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

  if (tsession == NULL) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  tcpSession = (TCPSession*) tsession->internal;
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
static int readAndProcess(int i) {
  TSession * tsession;
  TCPSession * tcpSession;
  unsigned int len;
  int ret;
  TCPP2P_PACKET * pack;
  P2P_PACKET * mp;
  size_t recvd;

  tsession = tsessions[i];
  if (SYSERR == tcpAssociate(tsession))
    return SYSERR;
  tcpSession = tsession->internal;
  if (tcpSession->rsize == tcpSession->pos) {
    /* read buffer too small, grow */
    GROW(tcpSession->rbuff,
	 tcpSession->rsize,
	 tcpSession->rsize * 2);
  }
  ret = socket_recv(tcpSession->sock,
		    NC_Blocking | NC_IgnoreInt, 
		    &tcpSession->rbuff[tcpSession->pos],
		    tcpSession->rsize - tcpSession->pos,
		    &recvd);
  tcpSession->lastUse = get_time();
  if (ret != OK) {
    tcpDisconnect(tsession);
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK,
	   "READ on socket %d returned 0 bytes, closing connection\n",
	   tcpSession->sock);
#endif
    return SYSERR; /* other side closed connection */
  }
  tcpSession->pos += recvd;

  while (tcpSession->pos > 2) {
    len = ntohs(((TCPP2P_PACKET*)&tcpSession->rbuff[0])->size)
      + sizeof(TCPP2P_PACKET);
    if (len > tcpSession->rsize) /* if message larger than read buffer, grow! */
      GROW(tcpSession->rbuff,
	   tcpSession->rsize,
	   len);
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK,
	   "Read %d bytes on socket %d, expecting %d for full message\n",
	   tcpSession->pos,
	   tcpSession->sock,
	   len);
#endif
    if (tcpSession->pos < len) {
      tcpDisconnect(tsession);
      return OK;
    }

    /* complete message received, let's check what it is */
    if (YES == tcpSession->expectingWelcome) {
      TCPWelcome * welcome;
#if DEBUG_TCP
      EncName enc;
#endif

      welcome = (TCPWelcome*) &tcpSession->rbuff[0];
      if ( (ntohs(welcome->header.reserved) != 0) ||
	   (ntohs(welcome->header.size)
	    != sizeof(TCPWelcome) - sizeof(TCPP2P_PACKET)) ) {
	GE_LOG(ectx,
	       GE_WARNING | GE_USER | GE_BULK,
	       _("Expected welcome message on tcp connection, "
		 "got garbage (%u, %u). Closing.\n"),
	       ntohs(welcome->header.reserved),
	       ntohs(welcome->header.size));
	tcpDisconnect(tsession);
	return SYSERR;
      }
      tcpSession->expectingWelcome = NO;
      tcpSession->sender = welcome->clientIdentity;
#if DEBUG_TCP
      IF_GELOG(ectx,
	       GE_DEBUG | GE_USER | GE_BULK,
	       hash2enc(&tcpSession->sender.hashPubKey,
			&enc));
      GE_LOG(etcx,
	     GE_DEBUG | GE_USER | GE_BULK,
	     "tcp welcome message from `%s' received\n",
	     &enc);
#endif
      memmove(&tcpSession->rbuff[0],
	      &tcpSession->rbuff[sizeof(TCPWelcome)],
	      tcpSession->pos - sizeof(TCPWelcome));
      tcpSession->pos -= sizeof(TCPWelcome);
      len = ntohs(((TCPP2P_PACKET*)&tcpSession->rbuff[0])->size)
	+ sizeof(TCPP2P_PACKET);
    }
    if ( (tcpSession->pos < 2) ||
	 (tcpSession->pos < len) ) {
      tcpDisconnect(tsession);
      return OK;
    }

    pack = (TCPP2P_PACKET*)&tcpSession->rbuff[0];
    /* send msg to core! */
    if (len <= sizeof(TCPP2P_PACKET)) {
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_BULK,
	     _("Received malformed message (size %u)"
	       " from tcp-peer connection. Closing.\n"),
	     len);
      tcpDisconnect(tsession);
      return SYSERR;
    }
    mp      = MALLOC(sizeof(P2P_PACKET));
    mp->msg = MALLOC(len - sizeof(TCPP2P_PACKET));
    memcpy(mp->msg,
	   &pack[1],
	   len - sizeof(TCPP2P_PACKET));
    mp->sender   = tcpSession->sender;
    mp->size     = len - sizeof(TCPP2P_PACKET);
    mp->tsession = tsession;
#if DEBUG_TCP
    {
      EncName enc;
      
      IF_GELOG(ectx,
	       GE_DEBUG | GE_USER | GE_BULK,
	       hash2enc(&mp->sender.hashPubKey, 
	       &enc);      
      GE_LOG(ectx,
	     GE_DEBUG | GE_USER | GE_BULK,
	     "tcp transport received %u bytes from %s (CRC %u), forwarding to core\n",
	     mp->size, 
	     &enc, 
	     crc32N(tcpSession->rbuff, 
		    tcpSession->pos));
    }
#endif
    coreAPI->receive(mp);
    /* finally, shrink buffer adequately */
    memmove(&tcpSession->rbuff[0],
	    &tcpSession->rbuff[len],
	    tcpSession->pos - len);
    tcpSession->pos -= len;
    if ( (tcpSession->pos + 1024 < tcpSession->rsize) &&
	 (tcpSession->rsize > 4 * 1024) ) {
      /* read buffer far too large, shrink! */
      GROW(tcpSession->rbuff,
	   tcpSession->rsize,
	   tcpSession->pos + 1024);
    }
  }
  tcpDisconnect(tsession);
  return OK;
}

/**
 * Add a new session to the array watched by the select thread.  Grows
 * the array if needed.  If the caller wants to do anything useful
 * with the return value, it must have the lock on tcplock before
 * calling.  It is ok to call this function without holding tcplock if
 * the return value is ignored.
 */
static unsigned int addTSession(TSession * tsession) {
  unsigned int i;

  MUTEX_LOCK(tcplock);
  if (tsessionCount == tsessionArrayLength)
    GROW(tsessions,
	 tsessionArrayLength,
	 tsessionArrayLength * 2);
  i = tsessionCount;
  tsessions[tsessionCount++] = tsession;
  MUTEX_UNLOCK(tcplock);
  return i;
}

/**
 * Create a new session for an inbound connection on the given
 * socket. Adds the session to the array of sessions watched
 * by the select thread.
 */
static void createNewSession(int sock) {
  TSession * tsession;
  TCPSession * tcpSession;

  tcpSession = MALLOC(sizeof(TCPSession));
  tcpSession->pos = 0;
  tcpSession->rsize = 2 * 1024 + sizeof(TCPP2P_PACKET);
  tcpSession->rbuff = MALLOC(tcpSession->rsize);
  tcpSession->wpos = 0;
  tcpSession->wbuff = NULL;
  tcpSession->wsize = 0;
  tcpSession->sock = socket_create(ectx,
				   load_monitor,
				   sock);
  /* fill in placeholder identity to mark that we
     are waiting for the welcome message */
  tcpSession->sender = *(coreAPI->myIdentity);
  tcpSession->expectingWelcome = YES;
  tcpSession->lock = MUTEX_CREATE(YES);
  tcpSession->users = 1; /* us only, core has not seen this tsession! */
  tcpSession->lastUse = get_time();
  tsession = MALLOC(sizeof(TSession));
  tsession->ttype = TCP_PROTOCOL_NUMBER;
  tsession->internal = tcpSession;
  addTSession(tsession);
}					

/**
 * Send a message (already encapsulated if needed) via the
 * tcp socket (or enqueue if sending now would block).
 *
 * @param tcpSession the session to use for sending
 * @param mp the message to send
 * @param ssize the size of the message
 * @return OK if message send or queued, NO if queue is full and
 * message was dropped, SYSERR on error
 */
static int tcpDirectSend(TCPSession * tcpSession,
			 void * mp,
			 unsigned int ssize) {
  size_t ret;
  int success;

#if DEBUG_TCP
  {
    EncName enc;
    
    IF_GELOG(ectx,
	     GE_DEBUG | GE_USER | GE_BULK,
	     hash2enc(&tcpSession->sender.hashPubKey,
		      &enc));    
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK,
	   "tcpDirectSend called to transmit %u bytes to %s (CRC %u).\n",
	   ssize,
	   &enc,
	   crc32N(mp, ssize));
  }
#endif	
  if (tcp_shutdown == YES) {
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK,
	   "tcpDirectSend called while TCP transport is shutdown.\n");		
#endif	
    return SYSERR;
  }
  if (tcpSession->sock == NULL) {
#if DEBUG_TCP
    LOG(LOG_INFO,
	"tcpDirectSend called, but socket is closed\n");
#endif
    return SYSERR;
  }
  if (ssize == 0) {
    GE_BREAK(ectx, 0); /* size 0 not allowed */
    return SYSERR;
  }
  MUTEX_LOCK(tcplock);
  if (tcpSession->wpos > 0) {
    /* select already pending... */
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK,	   
	   "write already pending, will not take additional message.\n");
#endif
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    ssize);
    MUTEX_UNLOCK(tcplock);
    return NO;
  }
#if DEBUG_TCP
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_BULK, 
	 "TCP: trying to send %u bytes\n",
	 ssize);
#endif
  success = socket_send(tcpSession->sock,
			NC_Nonblocking,
			mp,
			ssize,
			&ret);
  if (success == SYSERR) {
#if DEBUG_TCP
    LOG_STRERROR(LOG_INFO, "send");
#endif
    MUTEX_UNLOCK(tcplock);
    return SYSERR;
  }
  if (success == NO)
    ret = 0;
  if (stats != NULL)
    stats->change(stat_bytesSent,
		  ret);

#if DEBUG_TCP
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_BULK, 
	 "TCP: transmitted %u bytes\n",
	 ret);
#endif

  if (ret < ssize) {/* partial send */
    if (tcpSession->wsize < ssize - ret) {
      GROW(tcpSession->wbuff,
	   tcpSession->wsize,
	   ssize - ret);
    }
    memcpy(tcpSession->wbuff,
	   mp + ret,
	   ssize - ret);
    tcpSession->wpos = ssize - ret;
    signalSelect(); /* select set changed! */
  }
  tcpSession->lastUse = get_time();
  MUTEX_UNLOCK(tcplock);
  return OK;
}

/**
 * Send a message (already encapsulated if needed) via the
 * tcp socket.  Block if required.
 *
 * @param tcpSession the session to use for sending
 * @param mp the message to send
 * @param ssize the size of the message
 * @return OK if message send or queued, NO if queue is full and
 * message was dropped, SYSERR on error
 */
static int tcpDirectSendReliable(TCPSession * tcpSession,
				 void * mp,
				 unsigned int ssize) {
  int ok;

#if DEBUG_TCP
  {
    EncName enc;
    
    IF_GELOC(ectx,
	     GE_DEBUG | GE_USER | GE_BULK, 
	     hash2enc(&tcpSession->sender.hashPubKey, 
		      &enc));    
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK, 
	   "tcpDirectSendReliable called to transmit %u bytes to %s (CRC %u).\n",
	   ssize, 
	   &enc,
	   crc32N(mp, ssize));
  }
#endif	
  if (tcp_shutdown == YES) {
#if DEBUG_TCP
    LOG(LOG_INFO,
	"tcpDirectSendReliable called, but TCP service is shutdown\n");
#endif
    return SYSERR;
  }
  if (tcpSession->sock == NULL) {
#if DEBUG_TCP
    LOG(LOG_INFO,
	"tcpDirectSendReliable called, but socket is closed\n");
#endif
    return SYSERR;
  }
  if (ssize == 0) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  MUTEX_LOCK(tcplock);
  if (tcpSession->wpos > 0) {
    unsigned int old = tcpSession->wpos;
    GROW(tcpSession->wbuff,
	 tcpSession->wsize,
	 tcpSession->wpos + ssize);
    tcpSession->wpos += ssize;
    memcpy(&tcpSession->wbuff[old],
	   mp,
	   ssize);
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK, 
	   "tcpDirectSendReliable appended message to send buffer.\n");
#endif	

    ok = OK;
  } else {
    ok = tcpDirectSend(tcpSession,
		       mp,
		       ssize);
  }
  MUTEX_UNLOCK(tcplock);
  return ok;
}

/**
 * Send a message to the specified remote node with
 * increased reliability (i.e. grow TCP send buffer
 * above one frame if needed).
 *
 * @param tsession the P2P_hello_MESSAGE identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @return SYSERR on error, OK on success, NO on temporary error
 */
static int tcpSendReliable(TSession * tsession,
			   const void * msg,
			   const unsigned int size) {
  TCPP2P_PACKET * mp;
  int ok;

  if (size >= MAX_BUFFER_SIZE)
    return SYSERR;
  if (tcp_shutdown == YES)
    return SYSERR;
  if (size == 0) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  if (((TCPSession*)tsession->internal)->sock == NULL)
    return SYSERR; /* other side closed connection */
  mp = MALLOC(sizeof(TCPP2P_PACKET) + size);
  memcpy(&mp[1],
	 msg,
	 size);
  mp->size = htons(size);
  mp->reserved = 0;
  ok = tcpDirectSendReliable(tsession->internal,
			     mp,
			     size + sizeof(TCPP2P_PACKET));
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
  int i;
  HostAddress * haddr;
  TCPWelcome welcome;
  int sock;
  TSession * tsession;
  TCPSession * tcpSession;
  struct sockaddr_in soaddr;
  struct SocketHandle * s;

  if (tcp_shutdown == YES)
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
		    load_monitor,
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
  tcpSession->wpos = 0;
  tcpSession->wbuff = NULL;
  tcpSession->wsize = 0;
  tcpSession->rsize = 2 * 1024 + sizeof(TCPP2P_PACKET);
  tcpSession->rbuff = MALLOC(tcpSession->rsize);
  tsession = MALLOC(sizeof(TSession));
  tsession->internal = tcpSession;
  tsession->ttype = tcpAPI.protocolNumber;
  tcpSession->lock = MUTEX_CREATE(YES);
  tcpSession->users = 2; /* caller + us */
  tcpSession->pos = 0;
  tcpSession->lastUse = get_time();
  tcpSession->sender = helo->senderIdentity;
  tcpSession->expectingWelcome = NO;
  MUTEX_LOCK(tcplock);
  i = addTSession(tsession);

  /* send our node identity to the other side to fully establish the
     connection! */
  welcome.header.size
    = htons(sizeof(TCPWelcome) - sizeof(TCPP2P_PACKET));
  welcome.header.reserved
    = htons(0);
  welcome.clientIdentity
    = *(coreAPI->myIdentity);
  if (SYSERR == tcpDirectSend(tcpSession,
			      &welcome,
			      sizeof(TCPWelcome))) {
    destroySession(i);
    tcpDisconnect(tsession);
    MUTEX_UNLOCK(tcplock);
    return SYSERR;
  }
  MUTEX_UNLOCK(tcplock);
  signalSelect();

  *tsessionPtr = tsession;
  return OK;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the P2P_hello_MESSAGE identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @return SYSERR on error, OK on success
 */
static int tcpSend(TSession * tsession,
		   const void * msg,
		   const unsigned int size) {
  TCPP2P_PACKET * mp;
  int ok;

#if DEBUG_TCP
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_BULK, 
	 "tcpSend called to transmit %u bytes.\n",
	 size);
#endif	
  if (size >= MAX_BUFFER_SIZE) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }

  if (tcp_shutdown == YES) {
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK, 
	   "tcpSend called while TCP is shutdown.\n");
#endif	
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    size);
    return SYSERR;
  }
  if (size == 0) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  if (((TCPSession*)tsession->internal)->sock == NULL) {
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK, 
	   "tcpSend called after other side closed connection.\n");
#endif
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    size);
    return SYSERR; /* other side closed connection */
  }
  mp = MALLOC(sizeof(TCPP2P_PACKET) + size);
  memcpy(&mp[1],
	 msg,
	 size);
  mp->size = htons(size);
  mp->reserved = 0;
  /* if we would have less than TARGET_BUFFER_SIZE in buffers,
     do reliable send */
  if (((TCPSession*)tsession->internal)->wpos + size < TARGET_BUFFER_SIZE)
    ok = tcpDirectSendReliable(tsession->internal,
			       mp,
			       size + sizeof(TCPP2P_PACKET));
  else
    ok = tcpDirectSend(tsession->internal,
		       mp,
		       size + sizeof(TCPP2P_PACKET));
  FREE(mp);
  return ok;
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

  if (serverSignal != NULL) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  serverSignal = SEMAPHORE_CREATE(0);
  tcp_shutdown = NO;

  if (0 != PIPE(tcp_pipe)) {
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_ADMIN | GE_BULK,
		    "pipe");
    return SYSERR;
  }
  setBlocking(tcp_pipe[1], NO);

  port = getGNUnetTCPPort();
  if (port != 0) { /* if port == 0, this is a read-only
		      business! */
    s = SOCKET(PF_INET,
	       SOCK_STREAM,
	       0);
    if (s < 0) {
      GE_LOG_STRERROR(ectx,
		      GE_ERROR | GE_ADMIN | GE_BULK,
		      "socket");
      if (0 != CLOSE(tcp_pipe[0]))
 	GE_LOG_STRERROR(ectx,
			GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			"close");
      if (0 != CLOSE(tcp_pipe[1]))
 	GE_LOG_STRERROR(ectx,
			GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			"close");
      SEMAPHORE_DESTROY(serverSignal);
      serverSignal = NULL;
      tcp_shutdown = YES;
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
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_INFO | GE_USER | GE_BULK,
	   "starting %s peer server on port %d\n",
	   "tcp",
	   ntohs(serverAddr.sin_port));
#endif
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
      SEMAPHORE_DESTROY(serverSignal);
      serverSignal = NULL;
      return SYSERR;
    }
    if (0 != LISTEN(s, 5))
      GE_LOG_STRERROR(ectx,
		      GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE, 
		      "listen");
    tcp_sock = socket_create(ectx,
			     load_monitor,
			     s);
  } else
    tcp_sock = NULL;

  /* FIXME: call network/select code! */
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). Maybe restarted later!
 */
static int stopTransportServer() {
  void * unused;
  int haveThread;

  if (tcp_shutdown == YES)
    return OK;
  tcp_shutdown = YES;
  signalSelect();
  if (serverSignal != NULL) {
    haveThread = YES;
    SEMAPHORE_DOWN(serverSignal, YES);
    SEMAPHORE_DESTROY(serverSignal);
  } else
    haveThread = NO;
  serverSignal = NULL;
  if (0 != CLOSE(tcp_pipe[1]))
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
		    "close");
  if (0 != CLOSE(tcp_pipe[0])) 
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
		    "close");
  if (tcp_sock != NULL) {
    socket_destroy(tcp_sock);
    tcp_sock = NULL;
  }
  if (haveThread == YES)
    PTHREAD_JOIN(listenThread, &unused);
  return OK;
}

/**
 * Reload the configuration. Should never fail (keep old
 * configuration on error, syslog errors!)
 */
static void reloadConfiguration() {
  char * ch;

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
  load_monitor = core->load_monitor;
  GE_ASSERT(ectx, sizeof(HostAddress) == 8);
  GE_ASSERT(ectx, sizeof(TCPP2P_PACKET) == 4);
  GE_ASSERT(ectx, sizeof(TCPWelcome) == 68);
  tcplock = MUTEX_CREATE(YES);
  reloadConfiguration();
  tsessionCount = 0;
  tsessionArrayLength = 0;
  GROW(tsessions,
       tsessionArrayLength,
       32);
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
  tcpAPI.createhello           = &createhello;
  tcpAPI.connect              = &tcpConnect;
  tcpAPI.associate            = &tcpAssociate;
  tcpAPI.send                 = &tcpSend;
  tcpAPI.sendReliable         = &tcpSendReliable;
  tcpAPI.disconnect           = &tcpDisconnect;
  tcpAPI.startTransportServer = &startTransportServer;
  tcpAPI.stopTransportServer  = &stopTransportServer;
  tcpAPI.reloadConfiguration  = &reloadConfiguration;
  tcpAPI.addressToString      = &addressToString;

  return &tcpAPI;
}

void donetransport_tcp() {
  int i;

  coreAPI->releaseService(stats);
  stats = NULL;
  for (i=tsessionCount-1;i>=0;i--)
    destroySession(i);
  GROW(tsessions,
       tsessionArrayLength,
       0);
  FREENONNULL(filteredNetworks_);
  MUTEX_DESTROY(tcplock);
}

/* end of tcp.c */
