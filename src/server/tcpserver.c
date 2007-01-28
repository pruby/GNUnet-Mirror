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
 * @brief TCP server (gnunetd-client communication using util/tcpio.c).
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

#define DEBUG_TCPHANDLER NO

/**
 * Array of the message handlers.
 */
static CSHandler * handlers = NULL;

/**
 * Number of handlers in the array (max, there
 * may be NULL pointers in it!)
 */
static unsigned int max_registeredType = 0;

/**
 * Handlers to call if client exits.
 */
static ClientExitHandler * exitHandlers;

/**
 * How many entries are in exitHandlers?
 */
static unsigned int exitHandlerCount;

/**
 * Mutex to guard access to the handler array.
 */
static struct MUTEX * handlerlock;

/**
 * The thread that waits for new connections.
 */
static struct SelectHandle * selector;

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

/**
 * Per-client data structure.
 */
typedef struct ClientHandle {

  struct SocketHandle * sock;

} ClientHandle;

/**
 * Configuration...
 */
static struct CIDRNetwork * trustedNetworks_ = NULL;

/**
 * Is this IP labeled as trusted for CS connections?
 */
static int isWhitelisted(IPaddr ip) {
  return check_ipv4_listed(trustedNetworks_,
			   ip);
}

static int shutdownHandler(struct ClientHandle * client,
                           const MESSAGE_HEADER * msg) {
  int ret;

  if (ntohs(msg->size) != sizeof(MESSAGE_HEADER)) {
    GE_LOG(NULL,
	   GE_WARNING | GE_USER | GE_BULK,
	   _("The `%s' request received from client is malformed.\n"),
	   "shutdown");
    return SYSERR;
  }
  GE_LOG(NULL,
	 GE_INFO | GE_USER | GE_REQUEST,
	 "shutdown request accepted from client\n");
  ret = sendTCPResultToClient(client,
			      OK);
  shutdown_gnunetd(cfg, 0);
  return ret;
}

int registerClientExitHandler(ClientExitHandler callback) {
  MUTEX_LOCK(handlerlock);
  GROW(exitHandlers,
       exitHandlerCount,
       exitHandlerCount+1);
  exitHandlers[exitHandlerCount-1] = callback;
  MUTEX_UNLOCK(handlerlock);
  return OK;
}

int unregisterClientExitHandler(ClientExitHandler callback) {
  int i;

  MUTEX_LOCK(handlerlock);
  for (i=0;i<exitHandlerCount;i++) {
    if (exitHandlers[i] == callback) {
      exitHandlers[i] = exitHandlers[exitHandlerCount-1];
      GROW(exitHandlers,
	   exitHandlerCount,
	   exitHandlerCount-1);
      MUTEX_UNLOCK(handlerlock);
      return OK;
    }
  }
  MUTEX_UNLOCK(handlerlock);
  return SYSERR;
}

static void * select_accept_handler(void * ah_cls,
				    struct SelectHandle * sh,
				    struct SocketHandle * sock,
				    const void * addr,
				    unsigned int addr_len) {
  struct ClientHandle * session;
  IPaddr ip;
  struct sockaddr_in * a;

  if (addr_len != sizeof(struct sockaddr_in))
    return NULL;
  a = (struct sockaddr_in *) addr;
  memcpy(&ip,
	 &a->sin_addr,
	 sizeof(IPaddr));
  if (! isWhitelisted(ip))
    return NULL;
  session = MALLOC(sizeof(ClientHandle));
  session->sock = sock;
  return session;
}

static void select_close_handler(void * ch_cls,
				 struct SelectHandle * sh,
				 struct SocketHandle * sock,
				 void * sock_ctx) {
  ClientHandle * session = sock_ctx;
  int i;

  MUTEX_LOCK(handlerlock);
  for (i=0;i<exitHandlerCount;i++)
    exitHandlers[i](session);
  MUTEX_UNLOCK(handlerlock);
  FREE(session);
}

/**
 * Send a message to the client identified by the handle.  Note that
 * the core will typically buffer these messages as much as possible
 * and only return errors if it runs out of buffers.  Returning OK
 * on the other hand does NOT confirm delivery since the actual
 * transfer happens asynchronously.
 */
int sendToClient(struct ClientHandle * handle,
		 const MESSAGE_HEADER * message) {
#if DEBUG_TCPHANDLER
  GE_LOG(ectx,
	 GE_DEBUG | GE_DEVELOPER | GE_REQUEST,
	 "%s: sending reply to client\n",
	 __FUNCTION__);
#endif
  return select_write(selector,
		      handle->sock,
		      message,
		      NO,
		      YES);
}

void terminateClientConnection(struct ClientHandle * sock) {
  select_disconnect(selector,
		    sock->sock);
}

static int select_message_handler(void * mh_cls,
				  struct SelectHandle * sh,
				  struct SocketHandle * sock,
				  void * sock_ctx,
				  const MESSAGE_HEADER * msg) {
  struct ClientHandle * sender = sock_ctx;
  unsigned short ptyp;
  CSHandler callback;

  ptyp = htons(msg->type);
  MUTEX_LOCK(handlerlock);
  if (ptyp >= max_registeredType) {
    GE_LOG(ectx,
	   GE_INFO | GE_USER | GE_BULK,
	   "%s: Message of type %d not understood: no handler registered\n",
	   __FUNCTION__,
	   ptyp,
	   max_registeredType);
    MUTEX_UNLOCK(handlerlock);
    return SYSERR;
  }
  callback = handlers[ptyp];
  if (callback == NULL) {
    GE_LOG(ectx,
	   GE_INFO | GE_USER | GE_BULK,
	   "%s: Message of type %d not understood: no handler registered\n",
	   __FUNCTION__,
	   ptyp);
    MUTEX_UNLOCK(handlerlock);
    return SYSERR;
  } else {
    if (OK != callback(sender,
		       msg)) {
#if 0
      GE_LOG(ectx,
	     GE_INFO | GE_USER | GE_BULK,
	     "%s: Message of type %d caused error in handler\n",
	     __FUNCTION__,
	     ptyp);
#endif
      MUTEX_UNLOCK(handlerlock);
      return SYSERR;
    }
  }
  MUTEX_UNLOCK(handlerlock);
  return OK;
}

/**
 * Get the GNUnet TCP port from the configuration.
 */
static unsigned short getGNUnetPort() {
  unsigned long long port;

  if (-1 == GC_get_configuration_value_number(cfg,
					      "NETWORK",
					      "PORT",
					      1,
					      65535,
					      2087,
					      &port))
    port = 0;
  return (unsigned short) port;
}

static int startTCPServer() {
  int listenerFD;
  int listenerPort;
  struct sockaddr_in serverAddr;
  const int on = 1;

  listenerPort = getGNUnetPort();
  if (listenerPort == 0)
    return SYSERR;
  listenerFD = SOCKET(PF_INET,
		      SOCK_STREAM,
		      0);
  if (listenerFD < 0) {
    GE_LOG_STRERROR(ectx,
		    GE_FATAL | GE_ADMIN | GE_USER | GE_IMMEDIATE,
		    "socket");
    return SYSERR;
  }
  /* fill in the inet address structure */
  memset(&serverAddr,
	 0,
	 sizeof(serverAddr));
  serverAddr.sin_family
    = AF_INET;
  serverAddr.sin_addr.s_addr
    = htonl(INADDR_ANY);
  serverAddr.sin_port
    = htons(listenerPort);
  if ( SETSOCKOPT(listenerFD,
		  SOL_SOCKET,
		  SO_REUSEADDR,
		  &on,
		  sizeof(on)) < 0 )
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_ADMIN | GE_BULK,
		    "setsockopt");
  /* bind the socket */
  if (BIND(listenerFD,
	   (struct sockaddr *) &serverAddr,
	   sizeof(serverAddr)) < 0) {
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_ADMIN | GE_IMMEDIATE,
		    "bind");
    GE_LOG(ectx,
	   GE_FATAL | GE_ADMIN | GE_USER | GE_IMMEDIATE,
	   _("`%s' failed for port %d. Is gnunetd already running?\n"),
	   "bind",
	   listenerPort);
    return SYSERR;
  }
  selector = select_create("tcpserver",
			   NO,
			   ectx,
			   NULL,
			   listenerFD,
			   sizeof(struct sockaddr_in),
			   0, /* no timeout */
			   &select_message_handler,
			   NULL,
			   &select_accept_handler,
			   NULL,
			   &select_close_handler,
			   NULL,
			   0 /* no memory quota */);
  if (selector == NULL) {
    CLOSE(listenerFD);
    return SYSERR;
  }
  return OK;
}

int doneTCPServer() {
  if (selector != NULL)
    stopTCPServer(); /* just to be sure; used mostly
			for the benefit of gnunet-update
			and other gnunet-tools that are
			not gnunetd */
  unregisterCSHandler(CS_PROTO_SHUTDOWN_REQUEST,
		      &shutdownHandler);
  MUTEX_DESTROY(handlerlock);
  handlerlock = NULL;
  GROW(handlers,
       max_registeredType,
       0);
  GROW(exitHandlers,
       exitHandlerCount,
       0);
  FREE(trustedNetworks_);
  return OK;
}

/**
 * Initialize the TCP port and listen for incoming client connections.
 */
int initTCPServer(struct GE_Context * e,
		  struct GC_Configuration * c) {
  char * ch;

  cfg = c;
  ectx = e;

  /* move to reload-configuration method! */
  ch = NULL;
  if (-1 == GC_get_configuration_value_string(cfg,
					      "NETWORK",
					      "TRUSTED",
					      "127.0.0.0/8;",
					      &ch))
    return SYSERR;
  GE_ASSERT(ectx, ch != NULL);
  trustedNetworks_ = parse_ipv4_network_specification(ectx,
						      ch);
  if (trustedNetworks_ == NULL) {
    GE_LOG(ectx,
	   GE_FATAL | GE_USER | GE_ADMIN | GE_IMMEDIATE,
	   _("Malformed network specification in the configuration in section `%s' for entry `%s': %s\n"),
	   "NETWORK",
	   "TRUSTED",
	   ch);
    FREE(ch);
    return SYSERR;
  }
  FREE(ch);
  handlerlock = MUTEX_CREATE(YES);

  registerCSHandler(CS_PROTO_SHUTDOWN_REQUEST,
		    &shutdownHandler);
  if ( (NO == GC_get_configuration_value_yesno(cfg,
					       "TCPSERVER",
					       "DISABLE",
					       NO)) &&
       (OK != startTCPServer()) ) {
    doneTCPServer();
    return SYSERR;
  }
  return OK;
}

/**
 * Shutdown the module.
 */
int stopTCPServer() {
  if (selector != NULL) {
    select_destroy(selector);
    selector = NULL;
  }
  return OK;
}

/**
 * Register a method as a handler for specific message
 * types.
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return OK on success, SYSERR if there is already a
 *         handler for that type
 */
int registerCSHandler(unsigned short type,
		      CSHandler callback) {
  MUTEX_LOCK(handlerlock);
  if (type < max_registeredType) {
    if (handlers[type] != NULL) {
      MUTEX_UNLOCK(handlerlock);
      GE_LOG(ectx,
	     GE_WARNING | GE_DEVELOPER | GE_BULK,
	     _("%s failed, message type %d already in use.\n"),
	     __FUNCTION__,
	     type);
      return SYSERR;
    }
  } else
    GROW(handlers,
	 max_registeredType,
	 type + 8);
  handlers[type] = callback;
  MUTEX_UNLOCK(handlerlock);
  return OK;
}

/**
 * Unregister a method as a handler for specific message
 * types.
 *
 * @param type the message type
 * @param callback the method to call if a message of
 *        that type is received, if the callback returns
 *        SYSERR, processing of the message is discontinued
 *        afterwards (all other parts are ignored)
 * @return OK on success, SYSERR if there is no or another
 *         handler for that type
 */
int unregisterCSHandler(unsigned short type,
			CSHandler callback) {
  MUTEX_LOCK(handlerlock);
  if (type < max_registeredType) {
    if (handlers[type] != callback) {
      MUTEX_UNLOCK(handlerlock);
      return SYSERR; /* another handler present */
    } else {
      handlers[type] = NULL;
      MUTEX_UNLOCK(handlerlock);
      return OK; /* success */
    }
  } else {  /* can't be there */
    MUTEX_UNLOCK(handlerlock);
    return SYSERR;
  }
}

/**
 * Send a return value to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return SYSERR on error, OK if the return value was
 *         send successfully
 */
int sendTCPResultToClient(struct ClientHandle * sock,
			  int ret) {
  RETURN_VALUE_MESSAGE rv;

  rv.header.size
    = htons(sizeof(RETURN_VALUE_MESSAGE));
  rv.header.type
    = htons(CS_PROTO_RETURN_VALUE);
  rv.return_value
    = htonl(ret);
  return sendToClient(sock,
		      &rv.header);
}

/**
 * Send an error message to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param message the error message to send via TCP
 * @return SYSERR on error, OK if the return value was
 *         send successfully
 */
int sendTCPErrorToClient(struct ClientHandle * sock,
			 GE_KIND kind,
			 const char * message) {
  RETURN_ERROR_MESSAGE * rv;
  size_t msgLen;
  int ret;

  msgLen = strlen(message);
  msgLen = ((msgLen + 3) >> 2) << 2;
  if (msgLen > 60000)
    msgLen = 60000;
  rv = MALLOC(sizeof(RETURN_ERROR_MESSAGE) + msgLen);
  memset(rv,
	 0,
	 sizeof(RETURN_ERROR_MESSAGE) + msgLen);
  rv->header.size
    = htons(sizeof(MESSAGE_HEADER) + msgLen);
  rv->header.type
    = htons(CS_PROTO_RETURN_ERROR);
  rv->kind
    = htonl(kind);
  memcpy(&rv[1],
	 message,
	 strlen(message));
  ret = sendToClient(sock,
		     &rv->header);
  FREE(rv);
  return ret;
}
			
/**
 * Check if a handler is registered for a given
 * message type.
 *
 * @param type the message type
 * @return number of registered handlers (0 or 1)
 */
unsigned int isCSHandlerRegistered(unsigned short type) {
  MUTEX_LOCK(handlerlock);
  if (type < max_registeredType) {
    if (handlers[type] != NULL) {
      MUTEX_UNLOCK(handlerlock);
      return 1;
    }
  }
  MUTEX_UNLOCK(handlerlock);
  return 0;
}

static void freeClientLogContext(void * ctx) { }

static void confirmClientLogContext(void * ctx) { }

static void logClientLogContext(void * ctx,
				GE_KIND kind,
				const char * date,
				const char * msg) {
  sendTCPErrorToClient(ctx,
		       kind,
		       msg);
}

struct GE_Context *
createClientLogContext(GE_KIND mask,
		       struct ClientHandle * handle) {
  return GE_create_context_callback(mask,
				    &logClientLogContext,
				    handle,
				    &freeClientLogContext,
				    &confirmClientLogContext);
}

/* end of tcpserver.c */
