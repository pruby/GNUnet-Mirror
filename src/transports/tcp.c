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

#include "tcp_helper.c"

/**
 * Host-Address in a TCP network.
 */
typedef struct
{
  /**
   * claimed IP of the sender, network byte order
   */
  GNUNET_IPv4Address ip;

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

static GNUNET_TransportAPI tcpAPI;

static GNUNET_UPnP_ServiceAPI *upnp;

static struct GNUNET_IPv4NetworkSet *filteredNetworks_;

static struct GNUNET_IPv4NetworkSet *allowedNetworks_;

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_Mutex *tcpblacklistlock;

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
isBlacklisted (const void *addr, unsigned int addr_len)
{
  GNUNET_IPv4Address ip;
  int ret;

  if (addr_len == sizeof (struct sockaddr_in))
    {
      memcpy (&ip, &((struct sockaddr_in *) addr)->sin_addr,
              sizeof (GNUNET_IPv4Address));
    }
  else if (addr_len == sizeof (GNUNET_IPv4Address))
    {
      memcpy (&ip, addr, addr_len);
    }
  else
    {
#if DEBUG_TCP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     "Rejecting connection (invalid address length %u)\n",
                     addr_len);
#endif
      return GNUNET_SYSERR;
    }
  if (ip.addr == 0)
    return GNUNET_SYSERR;
  GNUNET_mutex_lock (tcpblacklistlock);
  ret = GNUNET_check_ipv4_listed (filteredNetworks_, ip);
  GNUNET_mutex_unlock (tcpblacklistlock);
#if DEBUG_TCP
  if (ret != GNUNET_NO)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_DEBUG | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                   "Rejecting connection from address %u.%u.%u.%u (blacklisted)\n",
                   GNUNET_PRIP (ntohl (*(int *) addr)));
#endif
  return ret;
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
isWhitelisted (const void *addr, unsigned int addr_len)
{
  GNUNET_IPv4Address ip;
  int ret;

  if (addr_len == sizeof (struct sockaddr_in))
    {
      memcpy (&ip, &((struct sockaddr_in *) addr)->sin_addr,
              sizeof (GNUNET_IPv4Address));
    }
  else if (addr_len == sizeof (GNUNET_IPv4Address))
    {
      memcpy (&ip, addr, addr_len);
    }
  else
    {
#if DEBUG_TCP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     "Rejecting connection (invalid address length %u)\n",
                     addr_len);
#endif
      return GNUNET_SYSERR;
    }
  ret = GNUNET_YES;
  GNUNET_mutex_lock (tcpblacklistlock);
  if (allowedNetworks_ != NULL)
    ret = GNUNET_check_ipv4_listed (allowedNetworks_, ip);
  GNUNET_mutex_unlock (tcpblacklistlock);
  if (ret != GNUNET_YES)
    {
#if DEBUG_TCP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     "Rejecting HELLO from address %u.%u.%u.%u (not whitelisted)\n",
                     GNUNET_PRIP (ntohl (*(int *) addr)));
#endif
    }
  return ret;
}

static int
isRejected (const void *addr, unsigned int addr_len)
{
  if ((GNUNET_NO != isBlacklisted (addr,
                                   addr_len)) ||
      (GNUNET_YES != isWhitelisted (addr, addr_len)))
    return GNUNET_YES;
  return GNUNET_NO;
}

/**
 * Get the GNUnet UDP port from the configuration,
 * or from /etc/services if it is not specified in
 * the config file.
 */
static unsigned short
getGNUnetTCPPort ()
{
  struct servent *pse;          /* pointer to service information entry        */
  unsigned long long port;

  if (-1 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      "TCP",
                                                      "PORT", 0, 65535, 2086,
                                                      &port))
    {
      if ((pse = getservbyname ("gnunet", "tcp")))
        port = htons (pse->s_port);
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
 * @param hello the Hello message to verify
 *        (the signature/crc have been verified before)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
verifyHello (const GNUNET_MessageHello * hello)
{
  HostAddress *haddr;

  haddr = (HostAddress *) & hello[1];
  if ((ntohs (hello->senderAddressSize) != sizeof (HostAddress)) ||
      (ntohs (hello->header.size) != GNUNET_sizeof_hello (hello)) ||
      (ntohs (hello->header.type) != GNUNET_P2P_PROTO_HELLO) ||
      (ntohs (hello->protocol) != GNUNET_TRANSPORT_PROTOCOL_NUMBER_TCP) ||
      (GNUNET_YES == isBlacklisted (&haddr->ip,
                                    sizeof (GNUNET_IPv4Address))) ||
      (GNUNET_YES != isWhitelisted (&haddr->ip, sizeof (GNUNET_IPv4Address))))
    {
#if DEBUG_TCP
      GNUNET_EncName enc;

      GNUNET_hash_to_enc (&hello->senderIdentity.hashPubKey, &enc);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     "Rejecting HELLO from `%s'\n", &enc);
#endif
      return GNUNET_SYSERR;     /* obviously invalid */
    }
  return GNUNET_OK;
}

/**
 * Create a hello-Message for the current node. The hello is
 * created without signature and without a timestamp. The
 * GNUnet core will GNUNET_RSA_sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static GNUNET_MessageHello *
createhello ()
{
  static HostAddress last_addr;
  GNUNET_MessageHello *msg;
  HostAddress *haddr;
  unsigned short port;

  port = getGNUnetTCPPort ();
  if (0 == port)
    {
      static int once = 0;
      if (once == 0)
        {
          once = 1;
#if DEBUG_TCP
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                         "TCP port is 0, will only send using TCP.\n");
#endif
        }
      return NULL;              /* TCP transport is configured SEND-only! */
    }
  msg = GNUNET_malloc (sizeof (GNUNET_MessageHello) + sizeof (HostAddress));
  haddr = (HostAddress *) & msg[1];

  if (!(((upnp != NULL) &&
         (GNUNET_OK == upnp->get_ip (port,
                                     "TCP",
                                     &haddr->ip))) ||
        (GNUNET_SYSERR !=
         GNUNET_IP_get_public_ipv4_address (cfg, ectx, &haddr->ip))))
    {
      GNUNET_free (msg);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     _("TCP: Could not determine my public IP address.\n"));
      return NULL;
    }
  haddr->port = htons (port);
  haddr->reserved = htons (0);
  if (0 != memcmp (haddr, &last_addr, sizeof (HostAddress)))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                     "TCP uses IP address %u.%u.%u.%u.\n",
                     GNUNET_PRIP (ntohl (*(int *) &haddr->ip)));
      last_addr = *haddr;
    }
  msg->senderAddressSize = htons (sizeof (HostAddress));
  msg->protocol = htons (GNUNET_TRANSPORT_PROTOCOL_NUMBER_TCP);
  msg->MTU = htonl (tcpAPI.mtu);
  return msg;
}

/**
 * Establish a connection to a remote node.
 *
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
tcpConnect (const GNUNET_MessageHello * hello, GNUNET_TSession ** tsessionPtr,
            int may_reuse)
{
  static int zero = 0;
  HostAddress *haddr;
  int sock;
  struct sockaddr_in soaddr;
  struct GNUNET_SocketHandle *s;
  int i;
  TCPSession *session;

  if (selector == NULL)
    return GNUNET_SYSERR;
  if (may_reuse != GNUNET_NO)
    {
      GNUNET_mutex_lock (tcplock);
      session = sessions;
      while (session != NULL)
        {
          if (0 == memcmp (&session->sender,
                           &hello->senderIdentity,
                           sizeof (GNUNET_PeerIdentity)))
            {
              GNUNET_mutex_lock (session->lock);
              if (session->in_select)
                {
                  session->users++;
                  GNUNET_mutex_unlock (session->lock);
                  GNUNET_mutex_unlock (tcplock);
                  *tsessionPtr = session->tsession;
                  return GNUNET_OK;
                }
              GNUNET_mutex_unlock (session->lock);
            }
          session = session->next;
        }
      GNUNET_mutex_unlock (tcplock);
    }
  haddr = (HostAddress *) & hello[1];
#if DEBUG_TCP
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                 "Creating TCP connection to %u.%u.%u.%u:%u.\n",
                 GNUNET_PRIP (ntohl (*(int *) &haddr->ip.addr)),
                 ntohs (haddr->port));
#endif
  sock = SOCKET (PF_INET, SOCK_STREAM, 6);      /* 6: TCP */
  if (sock == -1)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_BULK, "socket");
      return GNUNET_SYSERR;
    }
  s = GNUNET_socket_create (ectx, coreAPI->load_monitor, sock);
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
  soaddr.sin_family = AF_INET;

  GNUNET_GE_ASSERT (ectx,
                    sizeof (struct in_addr) == sizeof (GNUNET_IPv4Address));
  memcpy (&soaddr.sin_addr, &haddr->ip, sizeof (GNUNET_IPv4Address));
  soaddr.sin_port = haddr->port;
  i = CONNECT (sock, (struct sockaddr *) &soaddr, sizeof (soaddr));
  if ((i < 0) && (errno != EINPROGRESS) && (errno != EWOULDBLOCK))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     _("Cannot connect to %u.%u.%u.%u:%u: %s\n"),
                     GNUNET_PRIP (ntohl (*(int *) &haddr->ip)),
                     ntohs (haddr->port), STRERROR (errno));
      GNUNET_socket_destroy (s);
      return GNUNET_SYSERR;
    }
#if DEBUG_TCP
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_DEVELOPER | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "Establishing connection to %u.%u.%u.%u:%u\n",
                 GNUNET_PRIP (ntohl (*(int *) &haddr->ip)),
                 ntohs (haddr->port));
#endif
  return tcpConnectHelper (hello, s, tcpAPI.protocolNumber, tsessionPtr);
}

/**
 * Start the server process to receive inbound traffic.
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
startTransportServer ()
{
  struct sockaddr_in serverAddr;
  const int on = 1;
  unsigned short port;
  int s;

  if (selector != NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  port = getGNUnetTCPPort ();
  if (port != 0)
    {
      s = SOCKET (PF_INET, SOCK_STREAM, 0);
      if (s < 0)
        {
          GNUNET_GE_LOG_STRERROR (ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                  GNUNET_GE_BULK, "socket");
          return GNUNET_SYSERR;
        }
      if (SETSOCKOPT (s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
        GNUNET_GE_DIE_STRERROR (ectx,
                                GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                GNUNET_GE_IMMEDIATE, "setsockopt");
      memset ((char *) &serverAddr, 0, sizeof (serverAddr));
      serverAddr.sin_family = AF_INET;
      serverAddr.sin_addr.s_addr = htonl (INADDR_ANY);
      serverAddr.sin_port = htons (getGNUnetTCPPort ());
      if (BIND (s, (struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0)
        {
          GNUNET_GE_LOG_STRERROR (ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                  GNUNET_GE_IMMEDIATE, "bind");
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                         GNUNET_GE_IMMEDIATE,
                         _("Failed to start transport service on port %d.\n"),
                         getGNUnetTCPPort ());
          if (0 != CLOSE (s))
            GNUNET_GE_LOG_STRERROR (ectx,
                                    GNUNET_GE_ERROR | GNUNET_GE_USER |
                                    GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                                    "close");
          return GNUNET_SYSERR;
        }
    }
  else
    {
      s = -1;                   /* no listening! */
    }
  selector = GNUNET_select_create ("tcp",
                                   GNUNET_NO,
                                   ectx,
                                   coreAPI->load_monitor,
                                   s,
                                   sizeof (struct sockaddr_in),
                                   TCP_FAST_TIMEOUT,
                                   &select_message_handler,
                                   NULL,
                                   &select_accept_handler,
                                   &isRejected,
                                   &select_close_handler,
                                   NULL, 128 * 1024 /* max memory */ ,
                                   128 /* max sockets */ );
  return GNUNET_OK;
}

/**
 * Reload the configuration. Should never fail (keep old
 * configuration on error, syslog errors!)
 */
static int
reloadConfiguration (void *ctx,
                     struct GNUNET_GC_Configuration *cfg,
                     struct GNUNET_GE_Context *ectx,
                     const char *section, const char *option)
{
  char *ch;

  if (0 != strcmp (section, "TCP"))
    return 0;                   /* fast path */

  GNUNET_mutex_lock (tcpblacklistlock);
  GNUNET_free_non_null (filteredNetworks_);
  GNUNET_free_non_null (allowedNetworks_);
  ch = NULL;
  GNUNET_GC_get_configuration_value_string (cfg, "TCP", "BLACKLIST", "", &ch);
  filteredNetworks_ = GNUNET_parse_ipv4_network_specification (ectx, ch);
  GNUNET_free (ch);
  ch = NULL;
  GNUNET_GC_get_configuration_value_string (cfg, "TCP", "WHITELIST", "", &ch);
  if (strlen (ch) > 0)
    allowedNetworks_ = GNUNET_parse_ipv4_network_specification (ectx, ch);
  else
    allowedNetworks_ = NULL;
  GNUNET_free (ch);
  GNUNET_mutex_unlock (tcpblacklistlock);
  /* TODO: error handling! */
  return 0;
}

/**
 * Convert TCP hello to IP address
 */
static int
helloToAddress (const GNUNET_MessageHello * hello,
                void **sa, unsigned int *sa_len)
{
  const HostAddress *haddr = (const HostAddress *) &hello[1];
  struct sockaddr_in *serverAddr;

  *sa_len = sizeof (struct sockaddr_in);
  serverAddr = GNUNET_malloc (sizeof (struct sockaddr_in));
  *sa = serverAddr;
  memset (serverAddr, 0, sizeof (struct sockaddr_in));
  serverAddr->sin_family = AF_INET;
  memcpy (&serverAddr->sin_addr, haddr, sizeof (GNUNET_IPv4Address));
  serverAddr->sin_port = haddr->port;
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
  ectx = core->ectx;
  cfg = core->cfg;
  GNUNET_GE_ASSERT (ectx, sizeof (HostAddress) == 8);
  GNUNET_GE_ASSERT (ectx, sizeof (GNUNET_MessageHeader) == 4);
  GNUNET_GE_ASSERT (ectx, sizeof (TCPWelcome) == 68);
  tcplock = GNUNET_mutex_create (GNUNET_YES);
  tcpblacklistlock = GNUNET_mutex_create (GNUNET_YES);
  if (0 != GNUNET_GC_attach_change_listener (cfg, &reloadConfiguration, NULL))
    {
      GNUNET_mutex_destroy (tcplock);
      GNUNET_mutex_destroy (tcpblacklistlock);
      tcplock = NULL;
      tcpblacklistlock = NULL;
      return NULL;
    }
  coreAPI = core;
  if (GNUNET_GC_get_configuration_value_yesno (cfg, "TCP", "UPNP", GNUNET_YES)
      == GNUNET_YES)
    {
      upnp = coreAPI->request_service ("upnp");

      if (upnp == NULL)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_USER |
                         GNUNET_GE_IMMEDIATE,
                         _
                         ("The UPnP service could not be loaded. To disable UPnP, set the "
                          "configuration option \"UPNP\" in section \"TCP\" to \"NO\"\n"));

        }
    }
  stats = coreAPI->request_service ("stats");
  if (stats != NULL)
    {
      stat_bytesReceived
        = stats->create (gettext_noop ("# bytes received via TCP"));
      stat_bytesSent = stats->create (gettext_noop ("# bytes sent via TCP"));
      stat_bytesDropped
        = stats->create (gettext_noop ("# bytes dropped by TCP (outgoing)"));
    }
  tcpAPI.protocolNumber = GNUNET_TRANSPORT_PROTOCOL_NUMBER_TCP;
  tcpAPI.mtu = 0;
  tcpAPI.cost = 20000;          /* about equal to udp */
  tcpAPI.verifyHello = &verifyHello;
  tcpAPI.createhello = &createhello;
  tcpAPI.connect = &tcpConnect;
  tcpAPI.associate = &tcpAssociate;
  tcpAPI.send = &tcpSend;
  tcpAPI.disconnect = &tcpDisconnect;
  tcpAPI.startTransportServer = &startTransportServer;
  tcpAPI.stopTransportServer = &stopTransportServer;
  tcpAPI.helloToAddress = &helloToAddress;
  tcpAPI.testWouldTry = &tcpTestWouldTry;

  return &tcpAPI;
}

void
donetransport_tcp ()
{
  GNUNET_GC_detach_change_listener (cfg, &reloadConfiguration, NULL);
  if (stats != NULL)
    {
      coreAPI->release_service (stats);
      stats = NULL;
    }
  if (upnp != NULL)
    {
      coreAPI->release_service (upnp);
      upnp = NULL;
    }
  GNUNET_free_non_null (filteredNetworks_);
  GNUNET_free_non_null (allowedNetworks_);
  GNUNET_mutex_destroy (tcplock);
  GNUNET_mutex_destroy (tcpblacklistlock);
}

/* end of tcp.c */
