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

typedef int (*BlacklistedTester) (const void *addr, unsigned int addr_len);

/**
 * Initial handshake message. Note that the beginning
 * must match the CS_MESSAGE_HEADER since we are using tcpio.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Identity of the node connecting (TCP client)
   */
  GNUNET_PeerIdentity clientIdentity;
} TCPWelcome;

/**
 * Transport Session handle.
 */
typedef struct TCPSession
{

  struct TCPSession *next;

  /**
   * the tcp socket (used to identify this connection with selector)
   */
  struct GNUNET_SocketHandle *sock;

  /**
   * Our tsession.
   */
  GNUNET_TSession *tsession;

  /**
   * mutex for synchronized access to 'users'
   */
  struct GNUNET_Mutex *lock;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  GNUNET_PeerIdentity sender;

  /**
   * Are we still expecting the welcome? (GNUNET_YES/GNUNET_NO)
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

  void *accept_addr;

  unsigned int addr_len;

} TCPSession;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static GNUNET_CoreAPIForTransport *coreAPI;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

static struct GNUNET_SelectHandle *selector;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_Mutex *tcplock;

static struct TCPSession *sessions;


/**
 * You must hold the tcplock when calling this
 * function (and should not hold the tcpsession's lock
 * any more).
 */
static void
freeTCPSession (TCPSession * tcpsession)
{
  TCPSession *pos;
  TCPSession *prev;

  GNUNET_mutex_destroy (tcpsession->lock);
  GNUNET_free_non_null (tcpsession->accept_addr);
  pos = sessions;
  prev = NULL;
  while (pos != NULL)
    {
      if (pos == tcpsession)
        {
          if (prev == NULL)
            sessions = pos->next;
          else
            prev->next = pos->next;
          break;
        }
      prev = pos;
      pos = pos->next;
    }
  GNUNET_mutex_unlock (tcplock);
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_OK ==
                    coreAPI->
                    connection_assert_tsession_unused (tcpsession->tsession));
  GNUNET_mutex_lock (tcplock);
  GNUNET_free (tcpsession->tsession);
  GNUNET_free (tcpsession);
}

static int
tcpDisconnect (GNUNET_TSession * tsession)
{
  TCPSession *tcpsession = tsession->internal;

  GNUNET_GE_ASSERT (ectx, selector != NULL);
  GNUNET_mutex_lock (tcplock);
  GNUNET_mutex_lock (tcpsession->lock);
  GNUNET_GE_ASSERT (ectx, tcpsession->users > 0);
  tcpsession->users--;
  if ((tcpsession->users > 0) || (tcpsession->in_select == GNUNET_YES))
    {
      if (tcpsession->users == 0)
        GNUNET_select_change_timeout (selector, tcpsession->sock,
                                      TCP_FAST_TIMEOUT);
      GNUNET_mutex_unlock (tcpsession->lock);
      GNUNET_mutex_unlock (tcplock);
      return GNUNET_OK;
    }
  GNUNET_mutex_unlock (tcpsession->lock);
  GNUNET_mutex_unlock (tcplock);
#if DEBUG_TCP
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                 "TCP disconnect closes socket session.\n");
#endif
  GNUNET_select_disconnect (selector, tcpsession->sock);
  GNUNET_mutex_lock (tcplock);
  freeTCPSession (tcpsession);
  GNUNET_mutex_unlock (tcplock);
  return GNUNET_OK;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed. Associate can also be
 * called to test if it would be possible to associate the session
 * later, in this case the argument session is NULL. This can be used
 * to test if the connection must be closed by the core or if the core
 * can assume that it is going to be self-managed (if associate
 * returns GNUNET_OK and session was NULL, the transport layer is responsible
 * for eventually freeing resources associated with the tesession). If
 * session is not NULL, the core takes responsbility for eventually
 * calling disconnect.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return GNUNET_OK if the session could be associated,
 *         GNUNET_SYSERR if not.
 */
static int
tcpAssociate (GNUNET_TSession * tsession)
{
  TCPSession *tcpSession;

  GNUNET_GE_ASSERT (ectx, tsession != NULL);
  tcpSession = tsession->internal;
  GNUNET_mutex_lock (tcpSession->lock);
  if ((tcpSession->users == 0) && (tcpSession->in_select == GNUNET_YES))
    GNUNET_select_change_timeout (selector, tcpSession->sock, TCP_TIMEOUT);
  tcpSession->users++;

  GNUNET_mutex_unlock (tcpSession->lock);
  return GNUNET_OK;
}

/**
 * The socket of session has data waiting, process!
 *
 * This function may only be called if the tcplock is
 * already held by the caller.
 */
static int
select_message_handler (void *mh_cls,
                        struct GNUNET_SelectHandle *sh,
                        struct GNUNET_SocketHandle *sock,
                        void *sock_ctx, const GNUNET_MessageHeader * msg)
{
  GNUNET_TSession *tsession = sock_ctx;
  TCPSession *tcpSession;
  unsigned int len;
  GNUNET_TransportPacket *mp;
  const TCPWelcome *welcome;

  if (GNUNET_SYSERR == tcpAssociate (tsession))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  len = ntohs (msg->size);
  if (stats != NULL)
    stats->change (stat_bytesReceived, len);
  tcpSession = tsession->internal;
  if (GNUNET_YES == tcpSession->expectingWelcome)
    {
      /* at this point, we should be the only user! */
      GNUNET_GE_ASSERT (NULL, tcpSession->users == 1);

      welcome = (const TCPWelcome *) msg;
      if ((ntohs (welcome->header.type) != 0) || (len != sizeof (TCPWelcome)))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _
                         ("Received malformed message instead of welcome message. Closing.\n"));
          tcpDisconnect (tsession);
          return GNUNET_SYSERR;
        }
      tcpSession->expectingWelcome = GNUNET_NO;
      tcpSession->sender = welcome->clientIdentity;
      tsession->peer = welcome->clientIdentity;
      if (tcpSession->accept_addr != NULL)
        GNUNET_IP_set_address_for_peer_identity (&welcome->clientIdentity,
                                                 tcpSession->accept_addr,
                                                 tcpSession->addr_len);
    }
  else
    {
      /* send msg to core! */
      if (len <= sizeof (GNUNET_MessageHeader))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _
                         ("Received malformed message from tcp-peer connection. Closing.\n"));
          tcpDisconnect (tsession);
          return GNUNET_SYSERR;
        }
      mp = GNUNET_malloc (sizeof (GNUNET_TransportPacket));
      mp->msg = GNUNET_malloc (len - sizeof (GNUNET_MessageHeader));
      memcpy (mp->msg, &msg[1], len - sizeof (GNUNET_MessageHeader));
      mp->sender = tcpSession->sender;
      mp->size = len - sizeof (GNUNET_MessageHeader);
      mp->tsession = tsession;
      coreAPI->receive (mp);
    }
  tcpDisconnect (tsession);
  return GNUNET_OK;
}


/**
 * Create a new session for an inbound connection on the given
 * socket. Adds the session to the array of sessions watched
 * by the select thread.
 */
static void *
select_accept_handler (void *ah_cls,
                       struct GNUNET_SelectHandle *sh,
                       struct GNUNET_SocketHandle *sock,
                       const void *addr, unsigned int addr_len)
{
  BlacklistedTester blt = ah_cls;
  GNUNET_TSession *tsession;
  TCPSession *tcpSession;

  GNUNET_GE_ASSERT (NULL, sock != NULL);
  if (GNUNET_NO != blt (addr, addr_len))
    {
#if DEBUG_TCP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                     "Rejecting TCP connection (blacklisted).\n");
#endif
      return NULL;
    }
#if DEBUG_TCP
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                 "Accepting TCP connection.\n");
#endif
  tcpSession = GNUNET_malloc (sizeof (TCPSession));
  memset (tcpSession, 0, sizeof (TCPSession));
  tcpSession->sock = sock;
  /* fill in placeholder identity to mark that we
     are waiting for the welcome message */
  tcpSession->sender = *(coreAPI->myIdentity);
  tcpSession->expectingWelcome = GNUNET_YES;
  tcpSession->lock = GNUNET_mutex_create (GNUNET_YES);
  tcpSession->users = 0;
  tcpSession->in_select = GNUNET_YES;

  tsession = GNUNET_malloc (sizeof (GNUNET_TSession));
  memset (tsession, 0, sizeof (GNUNET_TSession));
  tsession->ttype = GNUNET_TRANSPORT_PROTOCOL_NUMBER_TCP;
  tsession->internal = tcpSession;
  tcpSession->tsession = tsession;
  tsession->peer = *(coreAPI->myIdentity);
  if (addr_len > sizeof (GNUNET_IPv4Address))
    {
      tcpSession->accept_addr = GNUNET_malloc (addr_len);
      memcpy (tcpSession->accept_addr,
              (struct sockaddr_in *) addr, sizeof (struct sockaddr_in));
      tcpSession->addr_len = addr_len;
    }
  else
    {
      GNUNET_GE_BREAK (NULL, 0);
      tcpSession->addr_len = 0;
      tcpSession->accept_addr = NULL;
    }
  GNUNET_mutex_lock (tcplock);
  tcpSession->next = sessions;
  sessions = tcpSession;
  GNUNET_mutex_unlock (tcplock);
  return tsession;
}

static void
select_close_handler (void *ch_cls,
                      struct GNUNET_SelectHandle *sh,
                      struct GNUNET_SocketHandle *sock, void *sock_ctx)
{
  GNUNET_TSession *tsession = sock_ctx;
  TCPSession *tcpSession = tsession->internal;

#if DEBUG_TCP
  GNUNET_EncName enc;

  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
            GNUNET_hash_to_enc (&tcpSession->sender.hashPubKey, &enc));
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "Closed TCP socket of `%s'.\n", &enc);
#endif
  GNUNET_mutex_lock (tcplock);
  GNUNET_mutex_lock (tcpSession->lock);
  tcpSession->in_select = GNUNET_NO;
  if (tcpSession->users == 0)
    {
      GNUNET_mutex_unlock (tcpSession->lock);
      freeTCPSession (tcpSession);
    }
  else
    {
      GNUNET_mutex_unlock (tcpSession->lock);
    }
  GNUNET_mutex_unlock (tcplock);
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the handle identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
tcpSend (GNUNET_TSession * tsession,
         const void *msg, unsigned int size, int important)
{
  TCPSession *tcpSession;
  GNUNET_MessageHeader *mp;
  int ok;

  tcpSession = tsession->internal;
  if (size >= GNUNET_MAX_BUFFER_SIZE - sizeof (GNUNET_MessageHeader))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;     /* too big */
    }
  if (tcpSession->in_select == GNUNET_NO)
    {
#if DEBUG_TCP
      GNUNET_EncName enc;

      IF_GELOG (ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                GNUNET_hash_to_enc (&tcpSession->sender.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                     "Cannot send message - TCP socket of `%s' already closed!\n",
                     &enc);
#endif
      return GNUNET_SYSERR;
    }
  if (selector == NULL)
    {
      if (stats != NULL)
        stats->change (stat_bytesDropped, size);
#if DEBUG_TCP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                     "Could not sent TCP message -- tcp transport is down.\n");
#endif
      return GNUNET_SYSERR;
    }
  if (size == 0)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (tcpSession->sock == NULL)
    {
      if (stats != NULL)
        stats->change (stat_bytesDropped, size);
#if DEBUG_TCP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                     "Could not sent TCP message -- other side closed connection.\n");
#endif
      return GNUNET_SYSERR;     /* other side closed connection */
    }
  mp = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + size);
  mp->size = htons (size + sizeof (GNUNET_MessageHeader));
  mp->type = 0;
  memcpy (&mp[1], msg, size);
#if DEBUG_TCP
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "Transport asks select to queue message of size %u\n", size);
#endif
  ok =
    GNUNET_select_write (selector, tcpSession->sock, mp, GNUNET_NO,
                         important);
  if ((GNUNET_OK == ok) && (stats != NULL))
    stats->change (stat_bytesSent, size + sizeof (GNUNET_MessageHeader));

  GNUNET_free (mp);
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
 * @return GNUNET_YES if the transport would try (i.e. queue
 *         the message or call the OS to send),
 *         GNUNET_NO if the transport would just drop the message,
 *         GNUNET_SYSERR if the size/session is invalid
 */
static int
tcpTestWouldTry (GNUNET_TSession * tsession, const unsigned int size,
                 int important)
{
  TCPSession *tcpSession = tsession->internal;

  if (size >= GNUNET_MAX_BUFFER_SIZE - sizeof (GNUNET_MessageHeader))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (selector == NULL)
    return GNUNET_SYSERR;
  if (size == 0)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (tcpSession->sock == NULL)
    return GNUNET_SYSERR;       /* other side closed connection */
  return GNUNET_select_test_write_now (selector, tcpSession->sock, size,
                                       GNUNET_NO, important);
}


/**
 * Establish a connection to a remote node.
 *
 * @param helo the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
tcpConnectHelper (const GNUNET_MessageHello * hello,
                  struct GNUNET_SocketHandle *s,
                  unsigned int protocolNumber, GNUNET_TSession ** tsessionPtr)
{
  TCPWelcome welcome;
  GNUNET_TSession *tsession;
  TCPSession *tcpSession;

  tcpSession = GNUNET_malloc (sizeof (TCPSession));
  memset (tcpSession, 0, sizeof (TCPSession));
  tcpSession->addr_len = 0;
  tcpSession->accept_addr = NULL;
  tcpSession->sock = s;
  tsession = GNUNET_malloc (sizeof (GNUNET_TSession));
  memset (tsession, 0, sizeof (GNUNET_TSession));
  tsession->internal = tcpSession;
  tsession->ttype = protocolNumber;
  tsession->peer = hello->senderIdentity;
  tcpSession->tsession = tsession;
  tcpSession->lock = GNUNET_mutex_create (GNUNET_YES);
  tcpSession->users = 1;        /* caller */
  tcpSession->in_select = GNUNET_NO;
  tcpSession->sender = hello->senderIdentity;
  tcpSession->expectingWelcome = GNUNET_NO;
  GNUNET_mutex_lock (tcplock);
  if (GNUNET_OK ==
      GNUNET_select_connect (selector, tcpSession->sock, tsession))
    tcpSession->in_select = GNUNET_YES;

  /* send our node identity to the other side to fully establish the
     connection! */
  welcome.header.size = htons (sizeof (TCPWelcome));
  welcome.header.type = htons (0);
  welcome.clientIdentity = *(coreAPI->myIdentity);
  if (GNUNET_OK !=
      GNUNET_select_write (selector, s, &welcome.header, GNUNET_NO,
                           GNUNET_YES))
    {
#if DEBUG_TCP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                     "Could not sent TCP welcome message, closing connection.\n");
#endif
      /* disconnect caller -- error! */
      tcpDisconnect (tsession);
      GNUNET_mutex_unlock (tcplock);
      return GNUNET_SYSERR;
    }
  else if (stats != NULL)
    stats->change (stat_bytesSent, sizeof (TCPWelcome));
  tcpSession->next = sessions;
  sessions = tcpSession;
  GNUNET_mutex_unlock (tcplock);
  *tsessionPtr = tsession;
  return GNUNET_OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). Maybe restarted later!
 */
static int
stopTransportServer ()
{
  if (selector != NULL)
    {
      GNUNET_select_destroy (selector);
      selector = NULL;
    }
  return GNUNET_OK;
}

/* end of tcp_helper.c */
