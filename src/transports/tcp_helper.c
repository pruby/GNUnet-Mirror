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

static Stats_ServiceAPI * stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

static struct SelectHandle * selector;

static struct GE_Context * ectx;

static struct MUTEX * tcplock;

static int tcpDisconnect(TSession * tsession) {
  TCPSession * tcpsession = tsession->internal;

  MUTEX_LOCK(tcpsession->lock);
  tcpsession->users--;
  if (tcpsession->users > 0) {
    MUTEX_UNLOCK(tcpsession->lock);
    return OK;
  }  
  MUTEX_UNLOCK(tcpsession->lock);
  select_disconnect(selector,
		    tcpsession->sock);
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

  if (SYSERR == tcpAssociate(tsession))
    return SYSERR;
  len = ntohs(msg->size);
  if (stats != NULL)
    stats->change(stat_bytesReceived,
		  len);
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
  BlacklistedTester blt = ah_cls;
  TSession * tsession;
  TCPSession * tcpSession;

  if (NO != blt(addr, addr_len))
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
  TCPSession * tcpsession = tsession->internal;

  GE_ASSERT(ectx, tcpsession != NULL);
  MUTEX_DESTROY(tcpsession->lock);
  FREE(tcpsession);  
  FREE(tsession);
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
