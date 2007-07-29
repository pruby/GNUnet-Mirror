/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file transports/tcp6.c
 * @brief Implementation of the TCP6 transport service over IPv6
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include "platform.h"
#include "ip.h"
#include "ip6.h"

#define DEBUG_TCP6 NO

/**
 * after how much time of the core not being associated with a tcp6
 * connection anymore do we close it?
 *
 * Needs to be larger than SECONDS_INACTIVE_DROP in
 * core's connection.s
 */
#define TCP_TIMEOUT 600 * cronSECONDS

/**
 * after how much time of the core not being associated with a tcp
 * connection anymore do we close it?
 *
 * Needs to be larger than SECONDS_INACTIVE_DROP in
 * core's connection.s
 */
#define TCP_FAST_TIMEOUT (5 * cronSECONDS)

#define TARGET_BUFFER_SIZE 4092

#include "tcp_helper.c"

/**
 * @brief Host-Address in a TCP6 network.
 */
typedef struct
{
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

static TransportAPI tcp6API;

static struct CIDR6Network *filteredNetworks_;

static struct CIDR6Network *allowedNetworks_;

static struct GC_Configuration *cfg;

static struct MUTEX *tcpblacklistlock;

/* ******************** helper functions *********************** */

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
isBlacklisted (const void *addr, unsigned int addr_len)
{
  IP6addr ip;
  int ret;

  if (addr_len == sizeof (IP6addr))
    {
      memcpy (&ip, addr, sizeof (IP6addr));
    }
  else if (addr_len == sizeof (struct sockaddr_in6))
    {
      memcpy (&ip,
              &((struct sockaddr_in6 *) addr)->sin6_addr, sizeof (IP6addr));
    }
  else
    {
      return SYSERR;
    }
  MUTEX_LOCK (tcpblacklistlock);
  ret = check_ipv6_listed (filteredNetworks_, ip);
  MUTEX_UNLOCK (tcpblacklistlock);
  return ret;
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
isWhitelisted (const void *addr, unsigned int addr_len)
{
  IP6addr ip;
  int ret;

  if (addr_len == sizeof (IP6addr))
    {
      memcpy (&ip, addr, sizeof (IP6addr));
    }
  else if (addr_len == sizeof (struct sockaddr_in6))
    {
      memcpy (&ip,
              &((struct sockaddr_in6 *) addr)->sin6_addr, sizeof (IP6addr));
    }
  else
    {
      return SYSERR;
    }
  ret = OK;
  MUTEX_LOCK (tcpblacklistlock);
  if (allowedNetworks_ != NULL)
    ret = check_ipv6_listed (filteredNetworks_, ip);
  MUTEX_UNLOCK (tcpblacklistlock);
  return ret;
}

static int
isRejected (const void *addr, unsigned int addr_len)
{
  if ((YES == isBlacklisted (addr,
                             addr_len)) ||
      (YES != isWhitelisted (addr, addr_len)))
    return YES;
  return NO;
}

/**
 * Get the GNUnet UDP port from the configuration,
 * or from /etc/services if it is not specified in
 * the config file.
 */
static unsigned short
getGNUnetTCP6Port ()
{
  struct servent *pse;          /* pointer to service information entry        */
  unsigned long long port;

  if (-1 == GC_get_configuration_value_number (cfg,
                                               "TCP6",
                                               "PORT", 1, 65535, 2086, &port))
    {
      if ((pse = getservbyname ("gnunet", "tcp6")))
        port = htons (pse->s_port);
      else
        port = 0;
    }
  return (unsigned short) port;
}

/**
 * Verify that a hello-Message is correct (a node
 * is reachable at that address). Since the reply
 * will be asynchronous, a method must be called on
 * success.
 * @param hello the hello message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on error
 */
static int
verifyHello (const P2P_hello_MESSAGE * hello)
{
  Host6Address *haddr;

  haddr = (Host6Address *) & hello[1];
  if ((ntohs (hello->senderAddressSize) != sizeof (Host6Address)) ||
      (ntohs (hello->header.size) != P2P_hello_MESSAGE_size (hello)) ||
      (ntohs (hello->header.type) != p2p_PROTO_hello) ||
      (ntohs (hello->protocol) != TCP6_PROTOCOL_NUMBER) ||
      (YES == isBlacklisted (&haddr->ip,
                             sizeof (IP6addr))) ||
      (YES != isWhitelisted (&haddr->ip, sizeof (IP6addr))))
    return SYSERR;              /* obviously invalid */
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
static P2P_hello_MESSAGE *
createhello ()
{
  P2P_hello_MESSAGE *msg;
  Host6Address *haddr;
  unsigned short port;

  port = getGNUnetTCP6Port ();
  if (0 == port)
    {
#if DEBUG_TCP6
      GE_LOG (ectx, GE_DEBUG, "TCP6 port is 0, will only send using TCP6\n");
#endif
      return NULL;              /* TCP6 transport is configured SEND-only! */
    }
  msg =
    (P2P_hello_MESSAGE *) MALLOC (sizeof (P2P_hello_MESSAGE) +
                                  sizeof (Host6Address));
  haddr = (Host6Address *) & msg[1];

  if (SYSERR == getPublicIP6Address (cfg, ectx, &haddr->ip))
    {
      FREE (msg);
      GE_LOG (ectx,
              GE_WARNING | GE_USER | GE_BULK,
              _("Could not determine my public IPv6 address.\n"));
      return NULL;
    }
  haddr->port = htons (port);
  haddr->reserved = htons (0);
  msg->senderAddressSize = htons (sizeof (Host6Address));
  msg->protocol = htons (TCP6_PROTOCOL_NUMBER);
  msg->MTU = htonl (tcp6API.mtu);
  return msg;
}

/**
 * Establish a connection to a remote node.
 *
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return OK on success, SYSERR if the operation failed
 */
static int
tcp6Connect (const P2P_hello_MESSAGE * hello, TSession ** tsessionPtr,
             int may_reuse)
{
  int i;
  Host6Address *haddr;
  int sock;
  char hostname[INET6_ADDRSTRLEN];
  struct addrinfo hints, *res, *res0;
  int rtn;
  struct SocketHandle *s;
  TCPSession *session;

  if (selector == NULL)
    return SYSERR;
  if (NO != may_reuse)
    {
      MUTEX_LOCK (tcplock);
      session = sessions;
      while (session != NULL)
        {
          if (0 == memcmp (&session->sender,
                           &hello->senderIdentity, sizeof (PeerIdentity)))
            {
              MUTEX_LOCK (session->lock);
              if (session->in_select)
                {
                  session->users++;
                  MUTEX_UNLOCK (session->lock);
                  MUTEX_UNLOCK (tcplock);
                  *tsessionPtr = session->tsession;
                  return OK;
                }
              MUTEX_UNLOCK (session->lock);
            }
          session = session->next;
        }
    }
  MUTEX_UNLOCK (tcplock);
  haddr = (Host6Address *) & hello[1];
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = PF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  inet_ntop (AF_INET6, haddr, hostname, INET6_ADDRSTRLEN);
  rtn = getaddrinfo (hostname, NULL, &hints, &res0);
  if (rtn != 0)
    {
      GE_LOG (ectx,
              GE_WARNING | GE_ADMIN | GE_BULK,
              _("`%s': unknown service: %s\n"),
              __FUNCTION__, gai_strerror (rtn));
      return SYSERR;
    }

#if DEBUG_TCP6
  GE_LOG (ectx,
          GE_DEBUG,
          "Creating TCP6 connection to %s:%d\n",
          inet_ntop (AF_INET6,
                     haddr,
                     &hostname, INET6_ADDRSTRLEN), ntohs (haddr->port));
#endif

  sock = -1;
  s = NULL;
  for (res = res0; res; res = res->ai_next)
    {
      if (res->ai_family != PF_INET6)
        continue;
      sock = SOCKET (res->ai_family, res->ai_socktype, res->ai_protocol);
      if (sock < 0)
        {
          GE_LOG_STRERROR (ectx, GE_WARNING | GE_ADMIN | GE_BULK, "socket");
          sock = -1;
          continue;
        }
      s = socket_create (ectx, coreAPI->load_monitor, sock);
      if (-1 == socket_set_blocking (s, NO))
        {
          socket_destroy (s);
          freeaddrinfo (res0);
          return SYSERR;
        }
      ((struct sockaddr_in6 *) (res->ai_addr))->sin6_port = haddr->port;
      i = CONNECT (sock, res->ai_addr, res->ai_addrlen);
      if ((i < 0) && (errno != EINPROGRESS) && (errno != EWOULDBLOCK))
        {
          GE_LOG_STRERROR (ectx, GE_WARNING | GE_ADMIN | GE_BULK, "connect");
          socket_destroy (s);
          s = NULL;
          sock = -1;
          continue;
        }
      break;
    }
  freeaddrinfo (res0);
  if (sock == -1)
    return SYSERR;
  GE_ASSERT (ectx, s != NULL);
  return tcpConnectHelper (hello, s, tcp6API.protocolNumber, tsessionPtr);
}

/**
 * Start the server process to receive inbound traffic.
 * @return OK on success, SYSERR if the operation failed
 */
static int
startTransportServer ()
{
  struct sockaddr_in6 serverAddr;
  const int on = 1;
  unsigned short port;
  int s;

  if (selector != NULL)
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  port = getGNUnetTCP6Port ();
  if (port != 0)
    {
      s = SOCKET (PF_INET6, SOCK_STREAM, 0);
      if (s < 0)
        {
          GE_LOG_STRERROR (ectx, GE_ERROR | GE_ADMIN | GE_BULK, "socket");
          return SYSERR;
        }
      if (SETSOCKOPT (s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
        GE_DIE_STRERROR (ectx,
                         GE_FATAL | GE_ADMIN | GE_IMMEDIATE, "setsockopt");
      memset ((char *) &serverAddr, 0, sizeof (serverAddr));
      serverAddr.sin6_family = AF_INET6;
      serverAddr.sin6_flowinfo = 0;
      serverAddr.sin6_addr = in6addr_any;
      serverAddr.sin6_port = htons (getGNUnetTCP6Port ());
      if (BIND (s, (struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0)
        {
          GE_LOG_STRERROR (ectx, GE_ERROR | GE_ADMIN | GE_IMMEDIATE, "bind");
          GE_LOG (ectx,
                  GE_ERROR | GE_ADMIN | GE_IMMEDIATE,
                  _("Failed to start transport service on port %d.\n"),
                  getGNUnetTCP6Port ());
          if (0 != CLOSE (s))
            GE_LOG_STRERROR (ectx,
                             GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
                             "close");
          return SYSERR;
        }
    }
  else
    {
      s = -1;
    }
  selector = select_create ("tcp6",
                            NO,
                            ectx,
                            coreAPI->load_monitor,
                            s,
                            sizeof (IPaddr),
                            TCP_FAST_TIMEOUT,
                            &select_message_handler,
                            NULL,
                            &select_accept_handler,
                            &isRejected,
                            &select_close_handler,
                            NULL, 128 * 1024 /* max memory */ ,
                            128 /* max sockets */ );
  return OK;
}

/**
 * Reload the configuration. Should never fail (keep old
 * configuration on error, syslog errors!)
 */
static int
reloadConfiguration (void *ctx,
                     struct GC_Configuration *cfg,
                     struct GE_Context *ectx,
                     const char *section, const char *option)
{
  char *ch;

  if (0 != strcmp (section, "TCP6"))
    return 0;                   /* fast path */
  MUTEX_LOCK (tcpblacklistlock);
  FREENONNULL (filteredNetworks_);
  FREENONNULL (allowedNetworks_);
  GC_get_configuration_value_string (cfg, "TCP6", "BLACKLIST", "", &ch);
  filteredNetworks_ = parse_ipv6_network_specification (ectx, ch);
  FREE (ch);
  GC_get_configuration_value_string (cfg, "TCP6", "WHITELIST", "", &ch);
  if (strlen (ch) > 0)
    allowedNetworks_ = parse_ipv6_network_specification (ectx, ch);
  else
    allowedNetworks_ = NULL;
  FREE (ch);

  MUTEX_UNLOCK (tcpblacklistlock);
  return 0;
}

/**
 * Convert TCP6  hello to IPv6 address
 */
static int
helloToAddress (const P2P_hello_MESSAGE * hello,
                void **sa, unsigned int *sa_len)
{
  const Host6Address *haddr = (const Host6Address *) &hello[1];
  struct sockaddr_in6 *serverAddr;

  *sa_len = sizeof (struct sockaddr_in6);
  serverAddr = MALLOC (sizeof (struct sockaddr_in6));
  *sa = serverAddr;
  memset (serverAddr, 0, sizeof (struct sockaddr_in6));
  serverAddr->sin6_family = AF_INET6;
  memcpy (&serverAddr->sin6_addr, haddr, sizeof (IP6addr));
  serverAddr->sin6_port = haddr->port;
  return OK;
}


/* ******************** public API ******************** */

/**
 * The exported method. Makes the core api available
 * via a global and returns the udp transport API.
 */
TransportAPI *
inittransport_tcp6 (CoreAPIForTransport * core)
{
  ectx = core->ectx;
  cfg = core->cfg;
  tcplock = MUTEX_CREATE (YES);
  tcpblacklistlock = MUTEX_CREATE (YES);
  if (0 != GC_attach_change_listener (cfg, &reloadConfiguration, NULL))
    {
      MUTEX_DESTROY (tcplock);
      MUTEX_DESTROY (tcpblacklistlock);
      tcplock = NULL;
      tcpblacklistlock = NULL;
      return NULL;
    }
  coreAPI = core;
  stats = coreAPI->requestService ("stats");
  if (stats != NULL)
    {
      stat_bytesReceived
        = stats->create (gettext_noop ("# bytes received via TCP6"));
      stat_bytesSent = stats->create (gettext_noop ("# bytes sent via TCP6"));
      stat_bytesDropped
        = stats->create (gettext_noop ("# bytes dropped by TCP6 (outgoing)"));
    }
  tcp6API.protocolNumber = TCP6_PROTOCOL_NUMBER;
  tcp6API.mtu = 0;
  tcp6API.cost = 19950;         /* about equal to udp6 */
  tcp6API.verifyHello = &verifyHello;
  tcp6API.createhello = &createhello;
  tcp6API.connect = &tcp6Connect;
  tcp6API.associate = &tcpAssociate;
  tcp6API.send = &tcpSend;
  tcp6API.disconnect = &tcpDisconnect;
  tcp6API.startTransportServer = &startTransportServer;
  tcp6API.stopTransportServer = &stopTransportServer;
  tcp6API.helloToAddress = &helloToAddress;
  tcp6API.testWouldTry = &tcpTestWouldTry;

  return &tcp6API;
}

void
donetransport_tcp6 ()
{
  GC_detach_change_listener (cfg, &reloadConfiguration, NULL);
  coreAPI->releaseService (stats);
  stats = NULL;
  FREENONNULL (filteredNetworks_);
  MUTEX_DESTROY (tcplock);
  MUTEX_DESTROY (tcpblacklistlock);
}

/* end of tcp6.c */
