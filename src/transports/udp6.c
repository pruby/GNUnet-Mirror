/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2007 Christian Grothoff (and other contributing authors)

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
 * @file transports/udp6.c
 * @brief Implementation of the UDP transport service over IPv6
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include "platform.h"
#include "ip.h"
#include "ip6.h"

#define DEBUG_UDP6 GNUNET_NO

#include "udp_helper.c"

/**
 * Host-Address in a UDP6 network.
 */
typedef struct
{
  /**
   * claimed IP of the sender, network byte order
   */
  GNUNET_IPv6Address ip;

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

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_LoadMonitor *load_monitor;

static struct GNUNET_IPv6NetworkSet *filteredNetworks_;

static struct GNUNET_IPv6NetworkSet *allowedNetworks_;

static struct GNUNET_Mutex *configLock;

/**
 * Get the GNUnet UDP6 port from the configuration, or from
 * /etc/services if it is not specified in the config file.
 *
 * @return the port in host byte order
 */
static unsigned short
getGNUnetUDP6Port ()
{
  struct servent *pse;          /* pointer to service information entry        */
  unsigned long long port;

  if (-1 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      "UDP6",
                                                      "PORT", 1, 65535, 2086,
                                                      &port))
    {
      if ((pse = getservbyname ("gnunet", "udp")))
        port = htons (pse->s_port);
      else
        port = 0;
    }
  return (unsigned short) port;
}

/**
 * Allocate and bind a server socket for the UDP6 transport.
 */
static int
passivesock (unsigned short port)
{
  struct sockaddr_in6 sin;
  int sock;
  const int on = 1;

  sock = SOCKET (PF_INET6, SOCK_DGRAM, 17);
  if (sock < 0)
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                            GNUNET_GE_IMMEDIATE, "socket");
  if (SETSOCKOPT (sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                            GNUNET_GE_IMMEDIATE, "setsockopt");
  if (port != 0)
    {
      memset (&sin, 0, sizeof (sin));
      sin.sin6_family = AF_INET6;
      sin.sin6_port = htons (port);
      memcpy (&sin.sin6_addr, &in6addr_any, sizeof (GNUNET_IPv6Address));
      if (BIND (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
          GNUNET_GE_LOG_STRERROR (ectx,
                                  GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                  GNUNET_GE_IMMEDIATE, "bind");
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                         GNUNET_GE_IMMEDIATE,
                         _("Failed to bind to UDP port %d.\n"), port);
          GNUNET_GE_DIE_STRERROR (ectx,
                                  GNUNET_GE_FATAL | GNUNET_GE_USER |
                                  GNUNET_GE_IMMEDIATE, "bind");
        }
    }                           /* do not bind if port == 0, then we use send-only! */
  return sock;
}

/**
 * Check if we are explicitly forbidden to communicate with this IP.
 */
static int
isBlacklisted (const void *addr, unsigned int addr_len)
{
  GNUNET_IPv6Address ip;
  int ret;

  if (addr_len == sizeof (GNUNET_IPv6Address))
    {
      memcpy (&ip, addr, sizeof (GNUNET_IPv6Address));
    }
  else if (addr_len == sizeof (struct sockaddr_in6))
    {
      memcpy (&ip,
              &((struct sockaddr_in6 *) addr)->sin6_addr,
              sizeof (GNUNET_IPv6Address));
    }
  else
    {
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_lock (configLock);
  ret = GNUNET_check_ipv6_listed (filteredNetworks_, ip);
  GNUNET_mutex_unlock (configLock);
  return ret;
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
isWhitelisted (const void *addr, unsigned int addr_len)
{
  GNUNET_IPv6Address ip;
  int ret;

  if (addr_len == sizeof (GNUNET_IPv6Address))
    {
      memcpy (&ip, addr, sizeof (GNUNET_IPv6Address));
    }
  else if (addr_len == sizeof (struct sockaddr_in6))
    {
      memcpy (&ip,
              &((struct sockaddr_in6 *) addr)->sin6_addr,
              sizeof (GNUNET_IPv6Address));
    }
  else
    {
      return GNUNET_SYSERR;
    }
  ret = GNUNET_OK;
  GNUNET_mutex_lock (configLock);
  if (allowedNetworks_ != NULL)
    ret = GNUNET_check_ipv6_listed (filteredNetworks_, ip);
  GNUNET_mutex_unlock (configLock);
  return ret;
}


static int
isRejected (const void *addr, unsigned int addr_len)
{
  if ((GNUNET_YES == isBlacklisted (addr,
                                    addr_len)) ||
      (GNUNET_YES != isWhitelisted (addr, addr_len)))
    return GNUNET_YES;
  return GNUNET_NO;
}


/* *************** API implementation *************** */

/**
 * Verify that a hello-Message is correct (a node is reachable at that
 * address). Since the reply will be asynchronous, a method must be
 * called on success.
 *
 * @param hello the hello message to verify
 *        (the signature/crc have been verified before)
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
verifyHello (const GNUNET_MessageHello * hello)
{
  Host6Address *haddr;

  haddr = (Host6Address *) & hello[1];
  if ((ntohs (hello->senderAddressSize) != sizeof (Host6Address)) ||
      (ntohs (hello->header.size) != GNUNET_sizeof_hello (hello)) ||
      (ntohs (hello->header.type) != GNUNET_P2P_PROTO_HELLO) ||
      (GNUNET_YES == isBlacklisted (&haddr->ip,
                                    sizeof (GNUNET_IPv6Address))) ||
      (GNUNET_YES != isWhitelisted (&haddr->ip, sizeof (GNUNET_IPv6Address))))
    return GNUNET_SYSERR;       /* obviously invalid */
  else
    {
#if DEBUG_UDP6
      char inet6[INET6_ADDRSTRLEN];
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Verified UDP6 hello from %u.%u.%u.%u:%u.\n",
                     inet_ntop (AF_INET6, &haddr->ip, inet6,
                                INET6_ADDRSTRLEN), ntohs (haddr->port));
#endif
      return GNUNET_OK;
    }
}

/**
 * Create a hello-Message for the current node. The hello is created
 * without signature and without a timestamp. The GNUnet core will
 * GNUNET_RSA_sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static GNUNET_MessageHello *
createhello ()
{
  GNUNET_MessageHello *msg;
  Host6Address *haddr;
  unsigned short port;

  port = getGNUnetUDP6Port ();
  if (port == 0)
    return NULL;                /* UDP6 transport configured send-only */

  msg = GNUNET_malloc (sizeof (GNUNET_MessageHello) + sizeof (Host6Address));
  haddr = (Host6Address *) & msg[1];

  if (GNUNET_SYSERR == getPublicIP6Address (cfg, ectx, &haddr->ip))
    {
      GNUNET_free (msg);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING,
                     _
                     ("UDP6: Could not determine my public IPv6 address.\n"));
      return NULL;
    }
  haddr->port = htons (port);
  haddr->reserved = htons (0);
  msg->senderAddressSize = htons (sizeof (Host6Address));
  msg->protocol = htons (GNUNET_TRANSPORT_PROTOCOL_NUMBER_UDP6);
  msg->MTU = htonl (udpAPI.mtu);
  return msg;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the GNUNET_MessageHello identifying the remote node
 * @param message what to send
 * @param size the size of the message
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
udp6Send (GNUNET_TSession * tsession,
          const void *message, const unsigned int size, int importance)
{
  UDPMessage *mp;
  GNUNET_MessageHello *hello;
  Host6Address *haddr;
  struct sockaddr_in6 sin;      /* an Internet endpoint address */
  int ok;
  size_t ssize;
#if DEBUG_UDP6
  char inet6[INET6_ADDRSTRLEN];
#endif

  if (udp_sock == NULL)
    return GNUNET_SYSERR;
  if (size == 0)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (size > udpAPI.mtu)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  hello = (GNUNET_MessageHello *) tsession->internal;
  if (hello == NULL)
    return GNUNET_SYSERR;

  haddr = (Host6Address *) & hello[1];
  ssize = size + sizeof (UDPMessage);
  mp = GNUNET_malloc (ssize);
  mp->header.size = htons (ssize);
  mp->header.type = 0;
  mp->sender = *coreAPI->myIdentity;
  memcpy (&mp[1], message, size);
  ok = GNUNET_SYSERR;
  memset (&sin, 0, sizeof (sin));
  sin.sin6_family = AF_INET6;
  sin.sin6_port = haddr->port;
  memcpy (&sin.sin6_addr, &haddr->ip.addr, sizeof (GNUNET_IPv6Address));
#if DEBUG_UDP6
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG,
                 "Sending message of %u bytes via UDP6 to %s:%d..\n",
                 ssize,
                 inet_ntop (AF_INET6,
                            &sin, inet6, INET6_ADDRSTRLEN),
                 ntohs (sin.sin_port));
#endif
  if (GNUNET_YES == GNUNET_socket_send_to (udp_sock,
                                           GNUNET_NC_NONBLOCKING,
                                           mp,
                                           ssize,
                                           &ssize, (const char *) &sin,
                                           sizeof (sin)))
    {
      ok = GNUNET_OK;
      if (stats != NULL)
        stats->change (stat_bytesSent, ssize);
    }
  else
    {
      GNUNET_GE_LOG_STRERROR (ectx, GNUNET_GE_WARNING, "sendto");
      if (stats != NULL)
        stats->change (stat_bytesDropped, ssize);
    }
  GNUNET_free (mp);
  return ok;
}

/**
 * Start the server process to receive inbound traffic.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
startTransportServer ()
{
  int sock;
  unsigned short port;

  /* initialize UDP6 network */
  port = getGNUnetUDP6Port ();
  if (port != 0)
    {
      sock = passivesock (port);
      if (sock == -1)
        return GNUNET_SYSERR;
      selector = GNUNET_select_create ("udp6", GNUNET_YES, ectx, load_monitor, sock, sizeof (struct sockaddr_in6), 0,   /* timeout */
                                       &select_message_handler,
                                       NULL,
                                       &select_accept_handler,
                                       &isRejected,
                                       &select_close_handler,
                                       NULL, 64 * 1024,
                                       16 /* max sockets */ );
      if (selector == NULL)
        return GNUNET_SYSERR;
    }
  sock = SOCKET (PF_INET, SOCK_DGRAM, 17);
  if (sock == -1)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_BULK, "socket");
      GNUNET_select_destroy (selector);
      selector = NULL;
      return GNUNET_SYSERR;
    }
  udp_sock = GNUNET_socket_create (ectx, load_monitor, sock);
  return GNUNET_OK;
}

/**
 * Reload the configuration. Should never fail.
 */
static int
reloadConfiguration ()
{
  char *ch;

  GNUNET_mutex_lock (configLock);
  GNUNET_free_non_null (filteredNetworks_);
  GNUNET_GC_get_configuration_value_string (cfg, "UDP6", "BLACKLIST", "",
                                            &ch);
  filteredNetworks_ = GNUNET_parse_ipv6_network_specification (ectx, ch);
  GNUNET_free (ch);
  GNUNET_GC_get_configuration_value_string (cfg, "UDP6", "WHITELIST", "",
                                            &ch);
  if (strlen (ch) > 0)
    allowedNetworks_ = GNUNET_parse_ipv6_network_specification (ectx, ch);
  else
    allowedNetworks_ = NULL;
  GNUNET_free (ch);
  GNUNET_mutex_unlock (configLock);
  return 0;
}

/**
 * Convert UDP6 hello to IPv6 address
 */
static int
helloToAddress (const GNUNET_MessageHello * hello,
                void **sa, unsigned int *sa_len)
{
  const Host6Address *haddr = (const Host6Address *) &hello[1];
  struct sockaddr_in6 *serverAddr;

  *sa_len = sizeof (struct sockaddr_in6);
  serverAddr = GNUNET_malloc (sizeof (struct sockaddr_in6));
  *sa = serverAddr;
  memset (serverAddr, 0, sizeof (struct sockaddr_in6));
  serverAddr->sin6_family = AF_INET6;
  memcpy (&serverAddr->sin6_addr, haddr, sizeof (GNUNET_IPv6Address));
  serverAddr->sin6_port = haddr->port;
  return GNUNET_OK;
}

/**
 * The default maximum size of each outbound UDP6 message,
 * optimal value for Ethernet (10 or 100 MBit).
 */
#define MESSAGE_SIZE 1452

/**
 * The exported method. Makes the core api available via a global and
 * returns the udp6 transport API.
 */
GNUNET_TransportAPI *
inittransport_udp6 (GNUNET_CoreAPIForTransport * core)
{
  unsigned long long mtu;

  GNUNET_GE_ASSERT (ectx, sizeof (UDPMessage) == 68);
  coreAPI = core;
  ectx = core->ectx;
  cfg = core->cfg;
  configLock = GNUNET_mutex_create (GNUNET_NO);

  reloadConfiguration ();
  if (-1 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      "UDP6",
                                                      "MTU",
                                                      sizeof (UDPMessage) +
                                                      GNUNET_P2P_MESSAGE_OVERHEAD
                                                      +
                                                      sizeof
                                                      (GNUNET_MessageHeader) +
                                                      32, 65500,
                                                      MESSAGE_SIZE, &mtu))
    {
      return NULL;
    }
  if (mtu < 1200)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                   _("MTU %llu for `%s' is probably too low!\n"), mtu,
                   "UDP6");
  stats = coreAPI->request_service ("stats");
  if (stats != NULL)
    {
      stat_bytesReceived
        = stats->create (gettext_noop ("# bytes received via UDP6"));
      stat_bytesSent = stats->create (gettext_noop ("# bytes sent via UDP6"));
      stat_bytesDropped
        = stats->create (gettext_noop ("# bytes dropped by UDP6 (outgoing)"));
      stat_udpConnected
        = stats->create (gettext_noop ("# UDP6 connections (right now)"));
    }
  udpAPI.protocolNumber = GNUNET_TRANSPORT_PROTOCOL_NUMBER_UDP6;
  udpAPI.mtu = mtu - sizeof (UDPMessage);
  udpAPI.cost = 19950;
  udpAPI.verifyHello = &verifyHello;
  udpAPI.createhello = &createhello;
  udpAPI.connect = &udpConnect;
  udpAPI.send = &udp6Send;
  udpAPI.associate = &udpAssociate;
  udpAPI.disconnect = &udpDisconnect;
  udpAPI.startTransportServer = &startTransportServer;
  udpAPI.stopTransportServer = &stopTransportServer;
  udpAPI.helloToAddress = &helloToAddress;
  udpAPI.testWouldTry = &testWouldTry;

  return &udpAPI;
}

void
donetransport_udp6 ()
{
  if (stats != NULL)
    {
      coreAPI->release_service (stats);
      stats = NULL;
    }
  GNUNET_mutex_destroy (configLock);
  GNUNET_free_non_null (filteredNetworks_);
}

/* end of udp6.c */
