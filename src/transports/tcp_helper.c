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
 * @file transports/tcp_helper.c
 * @brief common functions for the TCP services
 * @author Christian Grothoff
 */

typedef int (*BlacklistedTester)(const void * addr,
				 unsigned int addr_len);

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

  /**
   * number of users of this session (reference count)
   */
  int users;

  /**
   * Is this session active with select?
   */
  int in_select;

} TCPSession;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static CoreAPIForTransport * coreAPI;

static Stats_ServiceAPI * stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

static struct SelectHandle * selector;

static struct GE_Context * ectx;

static struct MUTEX * tcplock;

static int tcpDisconnect(TSession * tsession) {
  TCPSession * tcpsession = tsession->internal;

  GE_ASSERT(ectx, selector != NULL);
  MUTEX_LOCK(tcpsession->lock);
  GE_ASSERT(ectx, tcpsession->users > 0);
  tcpsession->users--;
  if ( (tcpsession->users > 0) ||
       (tcpsession->in_select == YES) ) {
    MUTEX_UNLOCK(tcpsession->lock);
    return OK;
  }
#if DEBUG_TCP
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_BULK,
	 "TCP disconnect closes socket session.\n");
#endif
  select_disconnect(selector,
		    tcpsession->sock);
  if (tcpsession->in_select == NO) {
    MUTEX_UNLOCK(tcpsession->lock);
    MUTEX_DESTROY(tcpsession->lock);
    FREE(tcpsession);
    FREE(tsession);
  } else {
    MUTEX_UNLOCK(tcpsession->lock);
  }
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
 * The socket of session has data waiting, process!
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

  if (SYSERR == tcpAssociate(tsession)) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  len = ntohs(msg->size);
  if (stats != NULL)
    stats->change(stat_bytesReceived,
		  len);
  tcpSession = tsession->internal;
  if (YES == tcpSession->expectingWelcome) {
    welcome = (const TCPWelcome*) msg;
    if ( (ntohs(welcome->header.type) != 0) ||
	 (len != sizeof(TCPWelcome)) ) {
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_BULK,
	     _("Received malformed message instead of welcome message. Closing.\n"));
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
  BlacklistedTester blt = ah_cls;
  TSession * tsession;
  TCPSession * tcpSession;

  if (NO != blt(addr, addr_len)) {
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK,
	   "Rejecting TCP connection (blacklisted).\n");
#endif
    return NULL;
  }
#if DEBUG_TCP
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_BULK,
	 "Accepting TCP connection.\n");
#endif
  tcpSession = MALLOC(sizeof(TCPSession));
  tcpSession->sock = sock;
  /* fill in placeholder identity to mark that we
     are waiting for the welcome message */
  tcpSession->sender = *(coreAPI->myIdentity);
  tcpSession->expectingWelcome = YES;
  tcpSession->lock = MUTEX_CREATE(YES);
  tcpSession->users = 0;
  tcpSession->in_select = YES;
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
  TCPSession * tcpSession = tsession->internal;

  MUTEX_LOCK(tcpSession->lock);
  tcpSession->in_select = NO;
  if (tcpSession->users == 0) {
    MUTEX_UNLOCK(tcpSession->lock);
    MUTEX_DESTROY(tcpSession->lock);
    FREE(tcpSession);
    FREE(tsession);
  } else {
    MUTEX_UNLOCK(tcpSession->lock);
  }
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
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK,
	   "Could not sent TCP message -- tcp transport is down.\n");
#endif
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
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK,
	   "Could not sent TCP message -- other side closed connection.\n");
#endif
    return SYSERR; /* other side closed connection */
  }
  mp = MALLOC(sizeof(MESSAGE_HEADER) + size);
  mp->size = htons(size + sizeof(MESSAGE_HEADER));
  mp->type = 0;
  memcpy(&mp[1],
	 msg,
	 size);
#if DEBUG_TCP
  GE_LOG(ectx,
	 GE_DEBUG | GE_DEVELOPER | GE_BULK,
	 "Transport asks select to queue message of size %u\n",
	 size);
#endif
  ok = select_write(selector,
		    tcpSession->sock,
		    mp,
		    NO,
		    important);
  if ( (OK == ok) &&
       (stats != NULL) )
    stats->change(stat_bytesSent,
		  size);

  FREE(mp);
  return ok;
}

/**
 * Test if the transport would even try to send
 * a message of the given size and importance
 * for the given session.<br>
 * This function is used to check if the core should
 * even bother to construct (and encrypt) this kind
 * of message.
 *
 * @return YES if the transport would try (i.e. queue
 *         the message or call the OS to send),
 *         NO if the transport would just drop the message,
 *         SYSERR if the size/session is invalid
 */
static int tcpTestWouldTry(TSession * tsession,
			   const unsigned int size,
			   int important) {
  TCPSession * tcpSession = tsession->internal;

  if (size >= MAX_BUFFER_SIZE - sizeof(MESSAGE_HEADER)) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  if (selector == NULL) 
    return SYSERR;
  if (size == 0) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  if (tcpSession->sock == NULL) 
    return SYSERR; /* other side closed connection */  
  return select_would_try(selector,
			  tcpSession->sock,
			  size,
			  NO,
			  important);
}


/**
 * Establish a connection to a remote node.
 *
 * @param helo the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return OK on success, SYSERR if the operation failed
 */
static int tcpConnectHelper(const P2P_hello_MESSAGE * helo,
			    struct SocketHandle * s,
			    unsigned int protocolNumber,
			    TSession ** tsessionPtr) {
  TCPWelcome welcome;
  TSession * tsession;
  TCPSession * tcpSession;

  tcpSession = MALLOC(sizeof(TCPSession));
  tcpSession->sock = s;
  tsession = MALLOC(sizeof(TSession));
  tsession->internal = tcpSession;
  tsession->ttype = protocolNumber;
  tcpSession->lock = MUTEX_CREATE(YES);
  tcpSession->users = 1; /* caller */
  tcpSession->in_select = NO;
  tcpSession->sender = helo->senderIdentity;
  tcpSession->expectingWelcome = NO;
  MUTEX_LOCK(tcplock);
  if (OK ==
      select_connect(selector,
		     tcpSession->sock,
		     tsession))
    tcpSession->in_select = YES;

  /* send our node identity to the other side to fully establish the
     connection! */
  welcome.header.size
    = htons(sizeof(TCPWelcome));
  welcome.header.type
    = htons(0);
  welcome.clientIdentity
    = *(coreAPI->myIdentity);
  if (SYSERR == select_write(selector,
			     s,			
			     &welcome.header,
			     NO,
			     YES)) {
#if DEBUG_TCP
    GE_LOG(ectx,
	   GE_DEBUG | GE_USER | GE_BULK,
	   "Could not sent TCP welcome message, closing connection.\n");
#endif
    /* disconnect caller -- error! */
    tcpDisconnect(tsession);
    MUTEX_UNLOCK(tcplock);
    return SYSERR;
  } else if (stats != NULL)
    stats->change(stat_bytesSent,
		  sizeof(TCPWelcome));
  MUTEX_UNLOCK(tcplock);
  *tsessionPtr = tsession;
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

/* end of tcp_helper.c */
