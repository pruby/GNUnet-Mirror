/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file server/tcpserver.c
 * @brief TCP server (gnunetd-client communication using util/network_client/tcpio.c).
 * @author Christian Grothoff
 *
 * TODO: configuration management (signaling of configuration change)
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"

#include "tcpserver.h"
#include "handler.h"
#include "startup.h"

#define DEBUG_TCPHANDLER GNUNET_NO

#define TIME_HANDLERS GNUNET_NO

/**
 * Array of the message handlers.
 */
static GNUNET_ClientRequestHandler *handlers = NULL;

/**
 * Number of handlers in the array (max, there
 * may be NULL pointers in it!)
 */
static unsigned int max_registeredType = 0;

/**
 * Handlers to call if client exits.
 */
static GNUNET_ClientExitHandler *exitHandlers;

/**
 * How many entries are in exitHandlers?
 */
static unsigned int exitHandlerCount;

/**
 * Mutex to guard access to the handler array.
 */
static struct GNUNET_Mutex *handlerlock;

/**
 * The thread that waits for new connections.
 */
static struct GNUNET_SelectHandle *selector;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

/**
 * Per-client data structure.
 */
typedef struct GNUNET_ClientHandle
{

  struct GNUNET_SocketHandle *sock;

} ClientHandle;

/**
 * Configuration...
 */
static struct GNUNET_IPv4NetworkSet *trustedNetworksV4;
static struct GNUNET_IPv6NetworkSet *trustedNetworksV6;

/**
 * Is this IP labeled as trusted for CS connections?
 */
static int
isWhitelisted4 (const struct in_addr *ip)
{
  return GNUNET_check_ipv4_listed (trustedNetworksV4, ip);
}

/**
 * Is this IP labeled as trusted for CS connections?
 */
static int
isWhitelisted6 (const struct in6_addr *ip)
{
  return GNUNET_check_ipv6_listed (trustedNetworksV6, ip);
}

static int
shutdownHandler (struct GNUNET_ClientHandle *client,
                 const GNUNET_MessageHeader * msg)
{
  int ret;

  if (ntohs (msg->size) != sizeof (GNUNET_MessageHeader))
    {
      GNUNET_GE_LOG (NULL,
                     GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("The `%s' request received from client is malformed.\n"),
                     "shutdown");
      return GNUNET_SYSERR;
    }
  GNUNET_GE_LOG (NULL,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 "Shutdown request from client accepted.\n");
  ret = GNUNET_CORE_cs_send_result_to_client (client, GNUNET_OK);
  GNUNET_CORE_shutdown (cfg, 0);
  return ret;
}

int
GNUNET_CORE_cs_register_exit_handler (GNUNET_ClientExitHandler callback)
{
  GNUNET_mutex_lock (handlerlock);
  GNUNET_array_grow (exitHandlers, exitHandlerCount, exitHandlerCount + 1);
  exitHandlers[exitHandlerCount - 1] = callback;
  GNUNET_mutex_unlock (handlerlock);
  return GNUNET_OK;
}

int
GNUNET_CORE_cs_exit_handler_unregister (GNUNET_ClientExitHandler callback)
{
  int i;

  GNUNET_mutex_lock (handlerlock);
  for (i = 0; i < exitHandlerCount; i++)
    {
      if (exitHandlers[i] == callback)
        {
          exitHandlers[i] = exitHandlers[exitHandlerCount - 1];
          GNUNET_array_grow (exitHandlers, exitHandlerCount,
                             exitHandlerCount - 1);
          GNUNET_mutex_unlock (handlerlock);
          return GNUNET_OK;
        }
    }
  GNUNET_mutex_unlock (handlerlock);
  return GNUNET_SYSERR;
}

static void *
select_accept_handler (void *ah_cls,
                       struct GNUNET_SelectHandle *sh,
                       struct GNUNET_SocketHandle *sock,
                       const void *addr, unsigned int addr_len)
{
  struct GNUNET_ClientHandle *session;
  struct in_addr ip4;
  struct in6_addr ip6;
  struct sockaddr_in *a4;
  struct sockaddr_in6 *a6;

  if (addr_len == sizeof (struct sockaddr_in6))
    {
      a6 = (struct sockaddr_in6 *) addr;

      memcpy (&ip6, &a6->sin6_addr, sizeof (struct in6_addr));
      /* get embedded ipv4 address in case address embedding is used */
      memcpy (&ip4,
              &((char *) &ip6)[sizeof (struct in6_addr) -
                               sizeof (struct in_addr)],
              sizeof (struct in_addr));
      if ((!isWhitelisted6 (&ip6))
          &&
          (!(((IN6_IS_ADDR_V4COMPAT (&a6->sin6_addr))
              || (IN6_IS_ADDR_V4MAPPED (&a6->sin6_addr)))
             && (isWhitelisted4 (&ip4)))))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                         "Rejected connection from untrusted client\n");
          return NULL;
        }
    }
  else if (addr_len == sizeof (struct sockaddr_in))
    {
      a4 = (struct sockaddr_in *) addr;
      memcpy (&ip4, &a4->sin_addr, sizeof (struct in_addr));
      if (!isWhitelisted4 (&ip4))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                         "Rejected connection from untrusted client\n");
          return NULL;
        }
    }
  else
    {
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;
    }
  session = GNUNET_malloc (sizeof (ClientHandle));
  session->sock = sock;
  return session;
}

static void
select_close_handler (void *ch_cls,
                      struct GNUNET_SelectHandle *sh,
                      struct GNUNET_SocketHandle *sock, void *sock_ctx)
{
  ClientHandle *session = sock_ctx;
  int i;

  GNUNET_mutex_lock (handlerlock);
  for (i = 0; i < exitHandlerCount; i++)
    exitHandlers[i] (session);
  GNUNET_mutex_unlock (handlerlock);
  GNUNET_free (session);
}

/**
 * Send a message to the client identified by the handle.  Note that
 * the core will typically buffer these messages as much as possible
 * and only return errors if it runs out of buffers.  Returning GNUNET_OK
 * on the other hand does NOT confirm delivery since the actual
 * transfer happens asynchronously.
 *
 * @param force GNUNET_YES if this message MUST be queued
 */
int
GNUNET_CORE_cs_send_to_client (struct GNUNET_ClientHandle *handle,
                               const GNUNET_MessageHeader * message,
                               int force)
{
  return GNUNET_select_write (selector, handle->sock, message, GNUNET_NO,
                              force);
}

int
GNUNET_CORE_cs_test_send_to_client_now (struct GNUNET_ClientHandle *handle,
                                        unsigned int size, int force)
{
  return GNUNET_select_test_write_now (selector, handle->sock,
                                       size, GNUNET_NO, force);
}

void
GNUNET_CORE_cs_terminate_client_connection (struct GNUNET_ClientHandle *sock)
{
  GNUNET_select_disconnect (selector, sock->sock);
}

static int
select_message_handler (void *mh_cls,
                        struct GNUNET_SelectHandle *sh,
                        struct GNUNET_SocketHandle *sock,
                        void *sock_ctx, const GNUNET_MessageHeader * msg)
{
  struct GNUNET_ClientHandle *sender = sock_ctx;
  unsigned short ptyp;
  GNUNET_ClientRequestHandler callback;
#if TIME_HANDLERS
  GNUNET_CronTime start;
#endif

  ptyp = htons (msg->type);
  GNUNET_mutex_lock (handlerlock);
  if ((ptyp >= max_registeredType) || (NULL == (callback = handlers[ptyp])))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                     "Message of type %d not understood: no handler registered\n",
                     ptyp);
      GNUNET_mutex_unlock (handlerlock);
      return GNUNET_SYSERR;
    }
#if TIME_HANDLERS
  start = GNUNET_get_time ();
#endif
  if (GNUNET_OK != callback (sender, msg))
    {
#if 0
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                     "Message of type %d caused error in handler\n", ptyp);
#endif
      GNUNET_mutex_unlock (handlerlock);
      return GNUNET_SYSERR;
    }
#if TIME_HANDLERS
  if (GNUNET_get_time () - start > GNUNET_CRON_SECONDS)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_INFO | GNUNET_GE_DEVELOPER |
                   GNUNET_GE_IMMEDIATE,
                   "Handling message of type %u took %llu s\n", ptyp,
                   (GNUNET_get_time () - start) / GNUNET_CRON_SECONDS);
#endif
  GNUNET_mutex_unlock (handlerlock);
  return GNUNET_OK;
}

/**
 * Get the GNUnet TCP port from the configuration.
 */
static unsigned short
getGNUnetPort ()
{
  unsigned long long port;

  if (-1 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      "NETWORK",
                                                      "PORT", 1, 65535, 2087,
                                                      &port))
    port = 0;
  return (unsigned short) port;
}

static int
startTCPServer ()
{
  int listenerFD;
  int listenerPort;
  struct sockaddr_in6 serverAddr6;
  struct sockaddr_in serverAddr4;
  struct sockaddr *serverAddr;
  socklen_t socklen;
  const int on = 1;
  char *ch;

  listenerPort = getGNUnetPort ();
  if (listenerPort == 0)
    return GNUNET_SYSERR;
  if ((GNUNET_YES ==
       GNUNET_GC_get_configuration_value_yesno (cfg, "GNUNETD",
                                                "DISABLE-IPV6", GNUNET_YES))
      || (-1 == (listenerFD = SOCKET (PF_INET6, SOCK_STREAM, 0))))
    {
      listenerFD = SOCKET (PF_INET, SOCK_STREAM, 0);
      if (listenerFD < 0)
        {
          GNUNET_GE_LOG_STRERROR (ectx,
                                  GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                  GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                                  "socket");
          return GNUNET_SYSERR;
        }
      memset (&serverAddr4, 0, sizeof (serverAddr4));
      serverAddr4.sin_family = AF_INET;
      ch = NULL;
      GNUNET_GC_get_configuration_value_string (cfg,
                                                "NETWORK",
                                                "TRUSTED",
                                                "127.0.0.0/8;", &ch);
      if ((0 == strcmp (ch, "127.0.0.0/8;")) ||
          (0 == strcmp (ch, "localhost;")) ||
          (0 == strcmp (ch, "127.0.0.1;")))
        {
          serverAddr4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
        }
      else
        {
          serverAddr4.sin_addr.s_addr = htonl (INADDR_ANY);
        }
      GNUNET_free (ch);
      serverAddr4.sin_port = htons (listenerPort);
      socklen = sizeof (serverAddr4);
      serverAddr = (struct sockaddr *) &serverAddr4;
    }
  else
    {
      memset (&serverAddr6, 0, sizeof (serverAddr6));
      serverAddr6.sin6_family = AF_INET6;
      serverAddr6.sin6_addr = in6addr_any;
      serverAddr6.sin6_port = htons (listenerPort);


      socklen = sizeof (serverAddr6);
      serverAddr = (struct sockaddr *) &serverAddr6;
    }
  /* fill in the inet address structure */
  if (SETSOCKOPT (listenerFD, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
    GNUNET_GE_LOG_STRERROR (ectx,
                            GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                            GNUNET_GE_BULK, "setsockopt");
  /* bind the socket */
  if (BIND (listenerFD, serverAddr, socklen) < 0)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_IMMEDIATE, "bind");
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_FATAL | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_IMMEDIATE,
                     _
                     ("`%s' failed for port %d. Is gnunetd already running?\n"),
                     "bind", listenerPort);
      CLOSE (listenerFD);
      return GNUNET_SYSERR;
    }
  selector = GNUNET_select_create ("tcpserver", GNUNET_NO, ectx, NULL, listenerFD, socklen, 0,  /* no timeout */
                                   &select_message_handler,
                                   NULL,
                                   &select_accept_handler,
                                   NULL,
                                   &select_close_handler,
                                   NULL, 0 /* no memory quota */ ,
                                   256 /* max sockets */ );
  if (selector == NULL)
    {
      CLOSE (listenerFD);       /* maybe closed already
                                   depending on how GNUNET_select_create
                                   failed... */
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

int
GNUNET_CORE_cs_done ()
{
  if (selector != NULL)
    GNUNET_CORE_stop_cs_server ();      /* just to be sure; used mostly
                                           for the benefit of gnunet-update
                                           and other gnunet-tools that are
                                           not gnunetd */
  GNUNET_CORE_unregister_handler (GNUNET_CS_PROTO_SHUTDOWN_REQUEST,
                                  &shutdownHandler);
  GNUNET_array_grow (handlers, max_registeredType, 0);
  GNUNET_array_grow (exitHandlers, exitHandlerCount, 0);
  GNUNET_free_non_null (trustedNetworksV4);
  GNUNET_free_non_null (trustedNetworksV6);
  return GNUNET_OK;
}

void __attribute__ ((constructor)) GNUNET_CORE_cs_ltdl_init ()
{
  handlerlock = GNUNET_mutex_create (GNUNET_YES);
}

void __attribute__ ((destructor)) GNUNET_CORE_cs_ltdl_fini ()
{
  GNUNET_mutex_destroy (handlerlock);
  handlerlock = NULL;
}

/**
 * Initialize the TCP port and listen for incoming client connections.
 */
int
GNUNET_CORE_cs_init (struct GNUNET_GE_Context *e,
                     struct GNUNET_GC_Configuration *c)
{
  char *ch;

  cfg = c;
  ectx = e;

  /* move to reload-configuration method! */
  ch = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_string (cfg,
                                                      "NETWORK",
                                                      "TRUSTED",
                                                      "127.0.0.0/8;", &ch))
    return GNUNET_SYSERR;
  GNUNET_GE_ASSERT (ectx, ch != NULL);
  trustedNetworksV4 = GNUNET_parse_ipv4_network_specification (ectx, ch);
  if (trustedNetworksV4 == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_FATAL | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                     GNUNET_GE_IMMEDIATE,
                     _
                     ("Malformed network specification in the configuration in section `%s' for entry `%s': %s\n"),
                     "NETWORK", "TRUSTED", ch);
      GNUNET_free (ch);
      return GNUNET_SYSERR;
    }
  GNUNET_free (ch);

  if (GNUNET_YES !=
      GNUNET_GC_get_configuration_value_yesno (cfg, "GNUNETD", "DISABLE-IPV6",
                                               GNUNET_YES))
    {
      ch = NULL;
      if (-1 == GNUNET_GC_get_configuration_value_string (cfg,
                                                          "NETWORK",
                                                          "TRUSTED6",
                                                          "::1;", &ch))
        return GNUNET_SYSERR;
      GNUNET_GE_ASSERT (ectx, ch != NULL);
      trustedNetworksV6 = GNUNET_parse_ipv6_network_specification (ectx, ch);
      if (trustedNetworksV6 == NULL)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_FATAL | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                         GNUNET_GE_IMMEDIATE,
                         _
                         ("Malformed network specification in the configuration in section `%s' for entry `%s': %s\n"),
                         "NETWORK", "TRUSTED6", ch);
          GNUNET_free (ch);
          return GNUNET_SYSERR;
        }
      GNUNET_free (ch);
    }

  GNUNET_CORE_register_handler (GNUNET_CS_PROTO_SHUTDOWN_REQUEST,
                                &shutdownHandler);
  if ((GNUNET_NO ==
       GNUNET_GC_get_configuration_value_yesno (cfg, "TCPSERVER", "DISABLE",
                                                GNUNET_NO))
      && (GNUNET_OK != startTCPServer ()))
    {
      GNUNET_CORE_cs_done ();
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * Shutdown the module.
 */
int
GNUNET_CORE_stop_cs_server ()
{
  if (selector != NULL)
    {
      GNUNET_select_destroy (selector);
      selector = NULL;
    }
  return GNUNET_OK;
}

/**
 * Register a method as a handler for specific message
 * types.
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        GNUNET_SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return GNUNET_OK on success, GNUNET_SYSERR if there is already a
 *         handler for that type
 */
int
GNUNET_CORE_register_handler (unsigned short type,
                              GNUNET_ClientRequestHandler callback)
{
  GNUNET_mutex_lock (handlerlock);
  if (type < max_registeredType)
    {
      if (handlers[type] != NULL)
        {
          GNUNET_mutex_unlock (handlerlock);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER |
                         GNUNET_GE_BULK,
                         _
                         ("Registering failed, message type %d already in use.\n"),
                         type);
          return GNUNET_SYSERR;
        }
    }
  else
    GNUNET_array_grow (handlers, max_registeredType, type + 8);
  handlers[type] = callback;
  GNUNET_mutex_unlock (handlerlock);
  return GNUNET_OK;
}

/**
 * Unregister a method as a handler for specific message
 * types.
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        GNUNET_SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return GNUNET_OK on success, GNUNET_SYSERR if there is no or another
 *         handler for that type
 */
int
GNUNET_CORE_unregister_handler (unsigned short type,
                                GNUNET_ClientRequestHandler callback)
{
  GNUNET_mutex_lock (handlerlock);
  if (type < max_registeredType)
    {
      if (handlers[type] != callback)
        {
          GNUNET_mutex_unlock (handlerlock);
          return GNUNET_SYSERR; /* another handler present */
        }
      else
        {
          handlers[type] = NULL;
          GNUNET_mutex_unlock (handlerlock);
          return GNUNET_OK;     /* success */
        }
    }
  else
    {                           /* can't be there */
      GNUNET_mutex_unlock (handlerlock);
      return GNUNET_SYSERR;
    }
}

/**
 * Send a return value to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return GNUNET_SYSERR on error, GNUNET_OK if the return value was
 *         send successfully
 */
int
GNUNET_CORE_cs_send_result_to_client (struct GNUNET_ClientHandle *sock,
                                      int ret)
{
  GNUNET_MessageReturnValue rv;

  rv.header.size = htons (sizeof (GNUNET_MessageReturnValue));
  rv.header.type = htons (GNUNET_CS_PROTO_RETURN_VALUE);
  rv.return_value = htonl (ret);
  return GNUNET_CORE_cs_send_to_client (sock, &rv.header, GNUNET_YES);
}

/**
 * Send an error message to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param message the error message to send via TCP
 * @return GNUNET_SYSERR on error, GNUNET_OK if the return value was
 *         send successfully
 */
int
GNUNET_CORE_cs_send_error_to_client (struct GNUNET_ClientHandle *sock,
                                     GNUNET_GE_KIND kind, const char *message)
{
  GNUNET_MessageReturnErrorMessage *rv;
  size_t msgLen;
  int ret;

  msgLen = strlen (message);
  msgLen = ((msgLen + 3) >> 2) << 2;
  if (msgLen > 60000)
    msgLen = 60000;
  rv = GNUNET_malloc (sizeof (GNUNET_MessageReturnErrorMessage) + msgLen);
  memset (rv, 0, sizeof (GNUNET_MessageReturnErrorMessage) + msgLen);
  rv->header.size =
    htons (sizeof (GNUNET_MessageReturnErrorMessage) + msgLen);
  rv->header.type = htons (GNUNET_CS_PROTO_RETURN_ERROR);
  rv->kind = htonl (kind);
  memcpy (&rv[1], message, strlen (message));
  ret = GNUNET_CORE_cs_send_to_client (sock, &rv->header, GNUNET_YES);
  GNUNET_free (rv);
  return ret;
}

/**
 * Check if a handler is registered for a given
 * message type.
 *
 * @param type the message type
 * @return number of registered handlers (0 or 1)
 */
unsigned int
GNUNET_CORE_cs_test_handler_registered (unsigned short type)
{
  GNUNET_mutex_lock (handlerlock);
  if (type < max_registeredType)
    {
      if (handlers[type] != NULL)
        {
          GNUNET_mutex_unlock (handlerlock);
          return 1;
        }
    }
  GNUNET_mutex_unlock (handlerlock);
  return 0;
}

static void
freeClientLogContext (void *ctx)
{
}

static void
confirmClientLogContext (void *ctx)
{
}

static void
logClientLogContext (void *ctx,
                     GNUNET_GE_KIND kind, const char *date, const char *msg)
{
  GNUNET_CORE_cs_send_error_to_client (ctx, kind, msg);
}

struct GNUNET_GE_Context *
GNUNET_CORE_cs_create_client_log_context (struct GNUNET_ClientHandle *handle)
{
  return GNUNET_GE_create_context_callback (GNUNET_GE_USER |
                                            GNUNET_GE_EVENTKIND |
                                            GNUNET_GE_ROUTEKIND,
                                            &logClientLogContext,
                                            handle,
                                            &freeClientLogContext,
                                            &confirmClientLogContext);
}

/* end of tcpserver.c */
