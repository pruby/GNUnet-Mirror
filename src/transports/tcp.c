/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_upnp_service.h"
#include "gnunet_stats_service.h"
#include "ip.h"

#define DEBUG_TCP GNUNET_NO

/**
 * after how much time of the core not being associated with a tcp
 * connection anymore do we close it?
 *
 * Needs to be larger than SECONDS_INACTIVE_DROP in
 * core's connection.s
 */
#define TCP_TIMEOUT (600 * GNUNET_CRON_SECONDS)

/**
 * after how much time of the core not being associated with a tcp
 * connection anymore do we close it?
 *
 * Needs to be larger than SECONDS_INACTIVE_DROP in
 * core's connection.s
 */
#define TCP_FAST_TIMEOUT (5 * GNUNET_CRON_SECONDS)

#define TARGET_BUFFER_SIZE 4092

/**
 * Initial handshake message. Note that the beginning
 * must match the GNUNET_MessageHeader since we are using tcpio.
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

  /**
   * Address of the other peer (from accept)
   */
  void *accept_addr;

  /**
   * Length of accept_addr.
   */
  unsigned int addr_len;

} TCPSession;

#define MY_TRANSPORT_NAME "TCP"
#include "common.c"

/* *********** globals ************* */


static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

static struct GNUNET_SelectHandle *selector;

static struct TCPSession *sessions;

/**
 * You must hold the lock when calling this
 * function (and should not hold the tcpsession's lock
 * any more).
 */
static void
tcp_session_free (TCPSession * tcpsession)
{
  TCPSession *pos;
  TCPSession *prev;

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
  GNUNET_mutex_unlock (lock);
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    GNUNET_OK ==
                    coreAPI->tsession_assert_unused (tcpsession->tsession));
  GNUNET_mutex_lock (lock);
  GNUNET_free (tcpsession->tsession);
  GNUNET_free (tcpsession);
}

static int
tcp_disconnect (GNUNET_TSession * tsession)
{
  TCPSession *tcpsession = tsession->internal;

  GNUNET_GE_ASSERT (coreAPI->ectx, selector != NULL);
  GNUNET_mutex_lock (lock);
  GNUNET_GE_ASSERT (coreAPI->ectx, tcpsession->users > 0);
  tcpsession->users--;
  if ((tcpsession->users > 0) || (tcpsession->in_select == GNUNET_YES))
    {
      if (tcpsession->users == 0)
        GNUNET_select_change_timeout (selector, tcpsession->sock,
                                      TCP_FAST_TIMEOUT);
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }
  GNUNET_mutex_unlock (lock);
  GNUNET_select_disconnect (selector, tcpsession->sock);
  GNUNET_mutex_lock (lock);
  tcp_session_free (tcpsession);
  GNUNET_mutex_unlock (lock);
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
tcp_associate (GNUNET_TSession * tsession)
{
  TCPSession *tcpSession;

  GNUNET_GE_ASSERT (coreAPI->ectx, tsession != NULL);
  tcpSession = tsession->internal;
  GNUNET_mutex_lock (lock);
  if (tcpSession->in_select == GNUNET_YES)
    GNUNET_select_change_timeout (selector, tcpSession->sock, TCP_TIMEOUT);
  tcpSession->users++;
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * The socket of session has data waiting, process!
 *
 * This function may only be called if the lock is
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

  if (GNUNET_SYSERR == tcp_associate (tsession))
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
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
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Received malformed message via %s. Ignored.\n"),
                         MY_TRANSPORT_NAME);
          tcp_disconnect (tsession);
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
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Received malformed message via %s. Ignored.\n"),
                         MY_TRANSPORT_NAME);
          tcp_disconnect (tsession);
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
  tcp_disconnect (tsession);
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
  GNUNET_TSession *tsession;
  TCPSession *tcpSession;

  GNUNET_GE_ASSERT (NULL, sock != NULL);
  if (GNUNET_NO != is_rejected_tester (addr, addr_len))
    return NULL;
  tcpSession = GNUNET_malloc (sizeof (TCPSession));
  memset (tcpSession, 0, sizeof (TCPSession));
  tcpSession->sock = sock;
  /* fill in placeholder identity to mark that we
     are waiting for the welcome message */
  tcpSession->sender = *(coreAPI->my_identity);
  tcpSession->expectingWelcome = GNUNET_YES;
  tcpSession->users = 0;
  tcpSession->in_select = GNUNET_YES;

  tsession = GNUNET_malloc (sizeof (GNUNET_TSession));
  memset (tsession, 0, sizeof (GNUNET_TSession));
  tsession->ttype = GNUNET_TRANSPORT_PROTOCOL_NUMBER_TCP;
  tsession->internal = tcpSession;
  tcpSession->tsession = tsession;
  tsession->peer = *(coreAPI->my_identity);
  if (addr_len > 0)
    {
      tcpSession->accept_addr = GNUNET_malloc (addr_len);
      memcpy (tcpSession->accept_addr, addr, sizeof (struct sockaddr_in));
    }
  tcpSession->addr_len = addr_len;
  GNUNET_mutex_lock (lock);
  tcpSession->next = sessions;
  sessions = tcpSession;
  GNUNET_mutex_unlock (lock);
  return tsession;
}

static void
select_close_handler (void *ch_cls,
                      struct GNUNET_SelectHandle *sh,
                      struct GNUNET_SocketHandle *sock, void *sock_ctx)
{
  GNUNET_TSession *tsession = sock_ctx;
  TCPSession *tcpSession = tsession->internal;

  GNUNET_mutex_lock (lock);
  tcpSession->in_select = GNUNET_NO;
  if (tcpSession->users == 0)
    tcp_session_free (tcpSession);
  GNUNET_mutex_unlock (lock);
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
tcp_send (GNUNET_TSession * tsession,
          const void *msg, unsigned int size, int important)
{
  TCPSession *tcpSession;
  GNUNET_MessageHeader *mp;
  int ok;

  tcpSession = tsession->internal;
  if (size >= GNUNET_MAX_BUFFER_SIZE - sizeof (GNUNET_MessageHeader))
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;     /* too big */
    }
  if (tcpSession->in_select == GNUNET_NO)
    return GNUNET_SYSERR;
  if (selector == NULL)
    {
      if (stats != NULL)
        stats->change (stat_bytesDropped, size);
      return GNUNET_SYSERR;
    }
  if (size == 0)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  if (tcpSession->sock == NULL)
    {
      if (stats != NULL)
        stats->change (stat_bytesDropped, size);
      return GNUNET_SYSERR;     /* other side closed connection */
    }
  mp = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + size);
  mp->size = htons (size + sizeof (GNUNET_MessageHeader));
  mp->type = 0;
  memcpy (&mp[1], msg, size);
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
tcp_test_would_try (GNUNET_TSession * tsession, unsigned int size,
                    int important)
{
  TCPSession *tcpSession = tsession->internal;

  if (size >= GNUNET_MAX_BUFFER_SIZE - sizeof (GNUNET_MessageHeader))
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  if (selector == NULL)
    return GNUNET_SYSERR;
  if (size == 0)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
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
tcp_connect_helper (const GNUNET_MessageHello * hello,
                    struct GNUNET_SocketHandle *s,
                    unsigned int protocolNumber,
                    GNUNET_TSession ** tsessionPtr)
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
  tcpSession->users = 1;        /* caller */
  tcpSession->in_select = GNUNET_NO;
  tcpSession->sender = hello->senderIdentity;
  tcpSession->expectingWelcome = GNUNET_NO;
  GNUNET_mutex_lock (lock);
  if (GNUNET_OK ==
      GNUNET_select_connect (selector, tcpSession->sock, tsession))
    {
      tcpSession->in_select = GNUNET_YES;
      GNUNET_select_change_timeout (selector, tcpSession->sock, TCP_TIMEOUT);
    }
  /* send our node identity to the other side to fully establish the
     connection! */
  welcome.header.size = htons (sizeof (TCPWelcome));
  welcome.header.type = htons (0);
  welcome.clientIdentity = *(coreAPI->my_identity);
  if (GNUNET_OK !=
      GNUNET_select_write (selector, s, &welcome.header, GNUNET_NO,
                           GNUNET_YES))
    {
      /* disconnect caller -- error! */
      tcp_disconnect (tsession);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  else if (stats != NULL)
    stats->change (stat_bytesSent, sizeof (TCPWelcome));
  tcpSession->next = sessions;
  sessions = tcpSession;
  GNUNET_mutex_unlock (lock);
  *tsessionPtr = tsession;
  return GNUNET_OK;
}

/**
 * Establish a connection to a remote node.
 *
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
tcp_connect (const GNUNET_MessageHello * hello,
             GNUNET_TSession ** tsessionPtr, int may_reuse)
{
#if TCP_SYNCNT
  static int zero = 0;
#endif
  const HostAddress *haddr;
  int sock;
  struct sockaddr_in soaddr4;
  struct sockaddr_in6 soaddr6;
  struct sockaddr *soaddr;
  socklen_t soaddrlen;
  struct GNUNET_SocketHandle *s;
  int i;
  TCPSession *session;
  unsigned short available;

  if (selector == NULL)
    return GNUNET_SYSERR;
  if (may_reuse != GNUNET_NO)
    {
      GNUNET_mutex_lock (lock);
      session = sessions;
      while (session != NULL)
        {
          if (0 == memcmp (&session->sender,
                           &hello->senderIdentity,
                           sizeof (GNUNET_PeerIdentity)))
            {
              if (session->in_select)
                {
                  session->users++;
                  if (session->in_select == GNUNET_YES)
                    GNUNET_select_change_timeout (selector,
                                                  session->sock, TCP_TIMEOUT);
                  GNUNET_mutex_unlock (lock);
                  *tsessionPtr = session->tsession;
                  return GNUNET_OK;
                }
            }
          session = session->next;
        }
      GNUNET_mutex_unlock (lock);
    }
  haddr = (const HostAddress *) &hello[1];
  available = ntohs (haddr->availability) & available_protocols;
  if (available == (VERSION_AVAILABLE_IPV4 | VERSION_AVAILABLE_IPV6))
    {
      if (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 2) == 0)
        available = VERSION_AVAILABLE_IPV4;
      else
        available = VERSION_AVAILABLE_IPV6;
    }
  if ((available & VERSION_AVAILABLE_IPV4) > 0)
    sock = SOCKET (PF_INET, SOCK_STREAM, 0);
  else if ((available & VERSION_AVAILABLE_IPV6) > 0)
    sock = SOCKET (PF_INET6, SOCK_STREAM, 0);
  else
    return GNUNET_SYSERR;       /* incompatible */
  if (sock == -1)
    {
      GNUNET_GE_LOG_STRERROR (coreAPI->ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_BULK, "socket");
      return GNUNET_SYSERR;
    }
  s = GNUNET_socket_create (coreAPI->ectx, coreAPI->load_monitor, sock);
#if TCP_SYNCNT
  /* only try a single packet to establish connection,
     if that does not work, abort instantly */
  setsockopt (sock, IPPROTO_TCP, TCP_SYNCNT, &zero, sizeof (zero));
#endif
  if (-1 == GNUNET_socket_set_blocking (s, GNUNET_NO))
    {
      GNUNET_socket_destroy (s);
      return GNUNET_SYSERR;
    }
  memset (&soaddr, 0, sizeof (soaddr));
  if ((available & VERSION_AVAILABLE_IPV4) > 0)
    {
      soaddr4.sin_family = AF_INET;
      memcpy (&soaddr4.sin_addr, &haddr->ipv4, sizeof (struct in_addr));
      soaddr4.sin_port = haddr->port;
      soaddr = (struct sockaddr *) &soaddr4;
      soaddrlen = sizeof (soaddr4);
    }
  else
    {
      soaddr6.sin6_family = AF_INET6;
      memcpy (&soaddr6.sin6_addr, &haddr->ipv6, sizeof (struct in6_addr));
      soaddr6.sin6_port = haddr->port;
      soaddr = (struct sockaddr *) &soaddr6;
      soaddrlen = sizeof (soaddr6);
    }
  i = CONNECT (sock, soaddr, soaddrlen);
  if ((i < 0) && (errno != EINPROGRESS) && (errno != EWOULDBLOCK))
    {
      GNUNET_GE_LOG_STRERROR (coreAPI->ectx,
                              GNUNET_GE_DEBUG | GNUNET_GE_ADMIN |
                              GNUNET_GE_USER | GNUNET_GE_BULK, "connect");
      GNUNET_socket_destroy (s);
      return GNUNET_SYSERR;
    }
  return tcp_connect_helper (hello, s, myAPI.protocol_number, tsessionPtr);
}

/**
 * Start the server process to receive inbound traffic.
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
tcp_transport_server_start ()
{
  struct sockaddr_in serverAddrv4;
  struct sockaddr_in6 serverAddrv6;
  struct sockaddr *serverAddr;
  socklen_t addrlen;
  const int on = 1;
  unsigned short port;
  int s;

  if (selector != NULL)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  port = get_port ();
  if (port != 0)
    {
      available_protocols = VERSION_AVAILABLE_NONE;
      if ((GNUNET_YES ==
           GNUNET_GC_get_configuration_value_yesno (cfg, "GNUNETD",
                                                    "DISABLE-IPV6",
                                                    GNUNET_YES))
          || (0 > (s = SOCKET (PF_INET6, SOCK_STREAM, 0))))
        {
          s = SOCKET (PF_INET, SOCK_STREAM, 0);
          if (s < 0)
            {
              GNUNET_GE_LOG_STRERROR (coreAPI->ectx,
                                      GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                      GNUNET_GE_BULK, "socket");
              return GNUNET_SYSERR;
            }
          available_protocols = VERSION_AVAILABLE_IPV4;
        }
      else
        {
          available_protocols =
            VERSION_AVAILABLE_IPV6 | VERSION_AVAILABLE_IPV4;
        }
      if (SETSOCKOPT (s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
        GNUNET_GE_DIE_STRERROR (coreAPI->ectx,
                                GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                GNUNET_GE_IMMEDIATE, "setsockopt");
      if (available_protocols == VERSION_AVAILABLE_IPV4)
        {
          memset (&serverAddr, 0, sizeof (serverAddr));
          serverAddrv4.sin_family = AF_INET;
          serverAddrv4.sin_addr.s_addr = INADDR_ANY;
          serverAddrv4.sin_port = htons (port);
          serverAddr = (struct sockaddr *) &serverAddrv4;
          addrlen = sizeof (serverAddrv4);
        }
      else
        {
          memset (&serverAddrv6, 0, sizeof (serverAddrv6));
          serverAddrv6.sin6_family = AF_INET6;
          serverAddrv6.sin6_addr = in6addr_any;
          serverAddrv6.sin6_port = htons (port);
          serverAddr = (struct sockaddr *) &serverAddrv6;
          addrlen = sizeof (serverAddrv6);
        }
      if (BIND (s, serverAddr, addrlen) < 0)
        {
          GNUNET_GE_LOG_STRERROR (coreAPI->ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                  GNUNET_GE_IMMEDIATE, "bind");
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                         GNUNET_GE_IMMEDIATE,
                         _("Failed to bind to %s port %d.\n"),
                         MY_TRANSPORT_NAME, port);
          if (0 != CLOSE (s))
            GNUNET_GE_LOG_STRERROR (coreAPI->ectx,
                                    GNUNET_GE_ERROR | GNUNET_GE_USER |
                                    GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                                    "close");
          return GNUNET_SYSERR;
        }
    }
  else
    {
      s = -1;                   /* no listening! */
      addrlen = 0;
      available_protocols = VERSION_AVAILABLE_IPV6 | VERSION_AVAILABLE_IPV4;
    }
  selector = GNUNET_select_create ("tcp",
                                   GNUNET_NO,
                                   coreAPI->ectx,
                                   coreAPI->load_monitor,
                                   s,
                                   addrlen,
                                   TCP_FAST_TIMEOUT,
                                   &select_message_handler,
                                   NULL,
                                   &select_accept_handler,
                                   NULL,
                                   &select_close_handler,
                                   NULL, 128 * 1024 /* max memory */ ,
                                   128 /* max sockets */ );
  return GNUNET_OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). Maybe restarted later!
 */
static int
tcp_transport_server_stop ()
{
  if (selector != NULL)
    {
      GNUNET_select_destroy (selector);
      selector = NULL;
    }
  if (get_port () == 0)
    available_protocols = VERSION_AVAILABLE_NONE;
  return GNUNET_OK;
}

/* ******************** public API ******************** */

/**
 * The exported method. Makes the core api available
 * via a global and returns the udp transport API.
 */
GNUNET_TransportAPI *
inittransport_tcp (GNUNET_CoreAPIForTransport * core)
{
  cfg = core->cfg;
  GNUNET_GE_ASSERT (coreAPI->ectx, sizeof (GNUNET_MessageHeader) == 4);
  GNUNET_GE_ASSERT (coreAPI->ectx, sizeof (TCPWelcome) == 68);
  GNUNET_GE_ASSERT (coreAPI->ectx, sizeof (HostAddress) == 24);
  lock = GNUNET_mutex_create (GNUNET_YES);
  if (0 !=
      GNUNET_GC_attach_change_listener (cfg, &reload_configuration, NULL))
    {
      GNUNET_mutex_destroy (lock);
      lock = NULL;
      return NULL;
    }
  coreAPI = core;
  if (GNUNET_GC_get_configuration_value_yesno
      (cfg, MY_TRANSPORT_NAME, "UPNP", GNUNET_YES) == GNUNET_YES)
    {
      upnp = coreAPI->service_request ("upnp");

      if (upnp == NULL)
        {
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_USER |
                         GNUNET_GE_IMMEDIATE,
                         _
                         ("The UPnP service could not be loaded. To disable UPnP, set the "
                          "configuration option \"UPNP\" in section \"%s\" to \"NO\"\n"),
                         MY_TRANSPORT_NAME);

        }
    }
  stats = coreAPI->service_request ("stats");
  if (stats != NULL)
    {
      stat_bytesReceived
        = stats->create (gettext_noop ("# bytes received via TCP"));
      stat_bytesSent = stats->create (gettext_noop ("# bytes sent via TCP"));
      stat_bytesDropped
        = stats->create (gettext_noop ("# bytes dropped by TCP (outgoing)"));
    }
  myAPI.protocol_number = GNUNET_TRANSPORT_PROTOCOL_NUMBER_TCP;
  myAPI.mtu = 0;
  myAPI.cost = 20000;           /* about equal to udp */
  myAPI.hello_verify = &verify_hello;
  myAPI.hello_create = &create_hello;
  myAPI.connect = &tcp_connect;
  myAPI.associate = &tcp_associate;
  myAPI.send = &tcp_send;
  myAPI.disconnect = &tcp_disconnect;
  myAPI.server_start = &tcp_transport_server_start;
  myAPI.server_stop = &tcp_transport_server_stop;
  myAPI.hello_to_address = &hello_to_address;
  myAPI.send_now_test = &tcp_test_would_try;

  return &myAPI;
}

void
donetransport_tcp ()
{
  do_shutdown ();
}

/* end of tcp.c */
