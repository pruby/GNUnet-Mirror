/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"

#include "tcpserver.h"
#include "handler.h"

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
 * Mutex to guard access to the handler array.
 */
static Mutex handlerlock;

/**
 * Mutex to guard access to the client list.
 */
static Mutex clientlock;

/**
 * The thread that waits for new connections.
 */
static PTHREAD_T TCPLISTENER_listener_;

/**
 * Pipe to communicate with select thread
 */
static int signalingPipe[2];

/**
 * Handlers to call if client exits.
 */
static ClientExitHandler * exitHandlers = NULL;

/**
 * How many entries are in exitHandlers?
 */
static unsigned int exitHandlerCount = 0;

/**
 * Signals for control-thread to server-thread communication
 */
static Semaphore * serverSignal = NULL;

/**
 * Should the select-thread exit?
 */
static int tcpserver_keep_running = NO;

/**
 * Per-client data structure (kept in linked list).  Also: the opaque
 * handle for client connections passed by the core to the CSHandlers.
 */
typedef struct ClientH {
  /**
   * Socket to communicate with the client.
   */
  int sock;

  char * readBuffer;
  unsigned int readBufferPos;
  unsigned int readBufferSize;

  char * writeBuffer;
  unsigned int writeBufferSize;

  CS_MESSAGE_HEADER ** writeQueue;
  unsigned int writeQueueSize;

  ClientHandle next;
} ClientThreadHandle;


/**
 * Start of the linked list of client structures.
 */
static ClientHandle clientList = NULL;


/**
 * Configuration...
 */
static struct CIDRNetwork * trustedNetworks_ = NULL;

/**
 * Is this IP labeled as trusted for CS connections?
 */
static int isWhitelisted(IPaddr ip) {
  return checkIPListed(trustedNetworks_,
		       ip);
}

static void signalSelect() {
  char i = 0;
  int ret;

#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "signaling select.\n");
#endif
  ret = WRITE(signalingPipe[1],
	      &i,
	      sizeof(char));
  if (ret != sizeof(char))
    if (errno != EAGAIN)
      LOG_STRERROR(LOG_ERROR, "write");
}

int registerClientExitHandler(ClientExitHandler callback) {
  MUTEX_LOCK(&handlerlock);
  GROW(exitHandlers,
       exitHandlerCount,
       exitHandlerCount+1);
  exitHandlers[exitHandlerCount-1] = callback;
  MUTEX_UNLOCK(&handlerlock);
  return OK;
}

/**
 * The client identified by 'session' has disconnected.  Close the
 * socket, free the buffers, unlink session from the linked list.
 */
void terminateClientConnection(ClientHandle session) {
  ClientHandle prev;
  ClientHandle pos;
  int i;

#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "Destroying session %p.\n",
      session);
#endif
  /* avoid deadlock: give up the lock while
     the client is processing; since only (!) the
     select-thread can possibly free handle/readbuffer,
     releasing the lock here is safe. */
  MUTEX_UNLOCK(&clientlock);
  MUTEX_LOCK(&handlerlock);
  for (i=0;i<exitHandlerCount;i++)
    exitHandlers[i](session);
  MUTEX_UNLOCK(&handlerlock);
  MUTEX_LOCK(&clientlock);
  prev = NULL;
  pos = clientList;
  while (pos != session) {
    GNUNET_ASSERT(pos != NULL);
    prev = pos;
    pos = pos->next;
  }
  if (prev == NULL)
    clientList = session->next;
  else
    prev->next = session->next;
  closefile(session->sock);
  GROW(session->writeBuffer,
       session->writeBufferSize,
       0);
  GROW(session->readBuffer,
       session->readBufferSize,
       0);
  for (i=session->writeQueueSize-1;i>=0;i--)
    FREE(session->writeQueue[i]);
  GROW(session->writeQueue,
       session->writeQueueSize,
       0);
  FREE(session);
}

int unregisterClientExitHandler(ClientExitHandler callback) {
  int i;

  MUTEX_LOCK(&handlerlock);
  for (i=0;i<exitHandlerCount;i++) {
    if (exitHandlers[i] == callback) {
      exitHandlers[i] = exitHandlers[exitHandlerCount-1];
      GROW(exitHandlers,
	   exitHandlerCount,
	   exitHandlerCount-1);
      MUTEX_UNLOCK(&handlerlock);
      return OK;
    }
  }
  MUTEX_UNLOCK(&handlerlock);
  return SYSERR;
}

/**
 * Send a message to the client identified by the handle.  Note that
 * the core will typically buffer these messages as much as possible
 * and only return SYSERR if it runs out of buffers.  Returning OK
 * on the other hand does NOT confirm delivery since the actual
 * transfer happens asynchronously.
 */
int sendToClient(ClientHandle handle,
		 const CS_MESSAGE_HEADER * message) {
  CS_MESSAGE_HEADER * cpy;

#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "Sending message to client %p.\n",
      handle);
#endif
  cpy = MALLOC(ntohs(message->size));
  memcpy(cpy, message, ntohs(message->size));
  MUTEX_LOCK(&clientlock);
  GROW(handle->writeQueue,
       handle->writeQueueSize,
       handle->writeQueueSize+1);
  handle->writeQueue[handle->writeQueueSize-1] = cpy;
  MUTEX_UNLOCK(&clientlock);
  signalSelect();
  return OK;
}

/**
 * Handle a message (that was decrypted if needed).
 * Checks the CRC and if that's ok, processes the
 * message by calling the registered handler for
 * each message part.
 */
static int processHelper(CS_MESSAGE_HEADER * msg,
			 ClientHandle sender) {
  unsigned short ptyp;
  CSHandler callback;

#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "Processing message from %p.\n",
      sender);
#endif
  ptyp = htons(msg->type);
  MUTEX_LOCK(&handlerlock);
  if (ptyp >= max_registeredType) {
    LOG(LOG_INFO,
	"%s: Message of type %d not understood: no handler registered\n",
	__FUNCTION__,
	ptyp,
	max_registeredType);
    MUTEX_UNLOCK(&handlerlock);
    return SYSERR;
  }
  callback = handlers[ptyp];
  if (callback == NULL) {
    LOG(LOG_INFO,
	"%s: Message of type %d not understood: no handler registered\n",
	__FUNCTION__,
	ptyp);
    MUTEX_UNLOCK(&handlerlock);
    return SYSERR;
  } else {
    if (OK != callback(sender,
		       msg)) {
      MUTEX_UNLOCK(&handlerlock);
      return SYSERR;
    }
  }
  MUTEX_UNLOCK(&handlerlock);
  return OK;
}

/**
 * Handle data available on the TCP socket descriptor. This method
 * first aquires a slot to register this socket for the writeBack
 * method (@see writeBack) and then demultiplexes all TCP traffic
 * received to the appropriate handlers.
 * @param sockDescriptor the socket that we are listening to (fresh)
 */
static int readAndProcess(ClientHandle handle) {
  unsigned int len;
  int ret;

#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "Reading from client %p.\n",
      handle);
#endif
  ret = READ(handle->sock,
	     &handle->readBuffer[handle->readBufferPos],
	     handle->readBufferSize - handle->readBufferPos);
  if (ret == 0) {
#if DEBUG_TCPHANDLER
    LOG(LOG_DEBUG,
	"Read 0 bytes from client %p (socket %d). Closing.\n",
	handle,
	handle->sock);
#endif
    return SYSERR; /* other side closed connection */
  }
#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "Read %d bytes from client %p.\n",
      ret,
      handle);
#endif
  if (ret < 0) {
    if ( (errno == EINTR) ||
	 (errno == EAGAIN) )
      return OK;
    LOG_STRERROR(LOG_WARNING, "read");
    return SYSERR;
  }
  handle->readBufferPos += ret;
  ret = OK;
  while (ret == OK) {
    if (handle->readBufferPos < sizeof(CS_MESSAGE_HEADER))
      return OK;
    len = ntohs(((CS_MESSAGE_HEADER*)handle->readBuffer)->size);
#if DEBUG_TCPHANDLER
    LOG(LOG_DEBUG,
	"Total size is %u bytes, have %u.\n",
	len,
      handle->readBufferPos);
#endif
    if (len > handle->readBufferSize) /* if MTU larger than expected, grow! */
      GROW(handle->readBuffer,
	   handle->readBufferSize,
	   len);
    if (handle->readBufferPos < len)
      return OK;
    /* avoid deadlock: give up the lock while
       the client is processing; since only (!) the
       select-thread can possibly free handle/readbuffer,
     releasing the lock here is safe. */
    MUTEX_UNLOCK(&clientlock);
    ret = processHelper((CS_MESSAGE_HEADER*)handle->readBuffer,
		      handle);
    MUTEX_LOCK(&clientlock);
    /* finally, shrink buffer adequately */
    memmove(&handle->readBuffer[0],
	  &handle->readBuffer[len],
	    handle->readBufferPos - len);
    handle->readBufferPos -= len;
  }
  return ret;
}

/**
 * Initialize the TCP port and listen for incoming connections.
 */
static void * tcpListenMain(void * unused) {
  int max;
  int ret;
  int listenerFD;
  socklen_t lenOfIncomingAddr;
  int listenerPort;
  struct sockaddr_in serverAddr, clientAddr;
  const int on = 1;
  ClientHandle pos;
  struct stat buf;
  fd_set readSet;
  fd_set errorSet;
  fd_set writeSet;
  int success;

  listenerPort = getGNUnetPort();
  /* create the socket */
  while ( (listenerFD = SOCKET(PF_INET,
			       SOCK_STREAM,
			       0)) < 0) {
    DIE_STRERROR("socket");
    sleep(30);
  }

  /* fill in the inet address structure */
  memset((char *) &serverAddr,
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
		  &on, sizeof(on)) < 0 )
    LOG_STRERROR(LOG_ERROR, "setsockopt");

  /* bind the socket */
  if (BIND(listenerFD,
	   (struct sockaddr *) &serverAddr,
	   sizeof(serverAddr)) < 0) {
    errexit(_("`%s' failed for port %d: %s. Is gnunetd already running?\n"),
	    "bind",
	    listenerPort,
	    STRERROR(errno));
  }

  /* start listening for new connections */
  LISTEN(listenerFD, 5); /* max: 5 pending, unhandled connections */
  SEMAPHORE_UP(serverSignal);

  MUTEX_LOCK(&clientlock);
  /* process incoming data */
  while (tcpserver_keep_running == YES) {
    FD_ZERO(&readSet);
    FD_ZERO(&errorSet);
    FD_ZERO(&writeSet);
    if (-1 != FSTAT(listenerFD, &buf)) {
      FD_SET(listenerFD, &readSet);
    } else {
      DIE_STRERROR("fstat");
    }
    if (-1 != FSTAT(signalingPipe[0], &buf)) {
      FD_SET(signalingPipe[0], &readSet);
    } else {
      DIE_STRERROR("fstat");
    }
    max = signalingPipe[0];
    if (listenerFD > max)
      max = listenerFD;
    pos = clientList;
    while (pos != NULL) {
      int sock = pos->sock;
      if (-1 != FSTAT(sock, &buf)) {
	FD_SET(sock, &errorSet);
	if ( (pos->writeBufferSize > 0) ||
	     (pos->writeQueueSize > 0) )
	  FD_SET(sock, &writeSet); /* we have a pending write request? */
	else
	  FD_SET(sock, &readSet); /* ONLY read if no writes are pending! */
	if (sock > max)
	  max = sock;
      } else {
	ClientHandle ch;

	LOG_STRERROR(LOG_ERROR, "fstat");
	ch = pos->next;
	terminateClientConnection(pos);
	pos = ch;
	continue;
      }
      pos = pos->next;
    }
    MUTEX_UNLOCK(&clientlock);
    ret = SELECT(max+1,
		 &readSet,
		 &writeSet,
		 &errorSet,
		 NULL);
    MUTEX_LOCK(&clientlock);
    if ( (ret == -1) &&
	 ( (errno == EAGAIN) || (errno == EINTR) ) )
      continue;
    if (ret == -1) {
      if (errno == EBADF) {
	LOG_STRERROR(LOG_ERROR, "select");
      } else {
	DIE_STRERROR("select");
      }
    }
    if (FD_ISSET(listenerFD, &readSet)) {
      int sock;

      lenOfIncomingAddr = sizeof(clientAddr);
      sock = ACCEPT(listenerFD,
		    (struct sockaddr *)&clientAddr,
		    &lenOfIncomingAddr);
      if (sock != -1) {	
	/* verify clientAddr for eligibility here (ipcheck-style,
	   user should be able to specify who is allowed to connect,
	   otherwise we just close and reject the communication! */

	IPaddr ipaddr;

#if 0
	printConnectionBuffer();
#endif
	GNUNET_ASSERT(sizeof(struct in_addr) == sizeof(IPaddr));
	memcpy(&ipaddr,
	       &clientAddr.sin_addr,
	       sizeof(struct in_addr));

	if (NO == isWhitelisted(ipaddr)) {
	  LOG(LOG_WARNING,
	      _("Rejected unauthorized connection from %u.%u.%u.%u.\n"),
	      PRIP(ntohl(*(int*)&clientAddr.sin_addr)));
	  closefile(sock);
	} else {
	  ClientHandle ch
	    = MALLOC(sizeof(ClientThreadHandle));
#if DEBUG_TCPHANDLER
	  LOG(LOG_DEBUG,
	      "Accepting connection from %u.%u.%u.%u (socket: %d).\n",
	      PRIP(ntohl(*(int*)&clientAddr.sin_addr)),
	      sock);
#endif
	  ch->sock = sock;
	  ch->readBufferSize = 2048;
	  ch->readBuffer = MALLOC(ch->readBufferSize);
	  ch->readBufferPos = 0;
	  ch->writeBuffer = NULL;
	  ch->writeBufferSize = 0;
	  ch->writeQueue = NULL;
	  ch->writeQueueSize = 0;
	  ch->next = clientList;
	  clientList = ch;
	}
      } else {
	LOG_STRERROR(LOG_INFO, "accept");
      }
    }

    if (FD_ISSET(signalingPipe[0], &readSet)) {
      /* allow reading multiple signals in one go in case we get many
	 in one shot... */

#define MAXSIG_BUF 128
      char buf[MAXSIG_BUF];

#if DEBUG_TCPHANDLER
      LOG(LOG_DEBUG,
	  "tcpserver eats signal.\n");
#endif
      /* just a signal to refresh sets, eat and continue */
      if (0 >= READ(signalingPipe[0],
		    &buf[0],
		    MAXSIG_BUF))
	LOG_STRERROR(LOG_WARNING, "read");
    }

    pos = clientList;
    while (pos != NULL) {
      int sock = pos->sock;
      if (FD_ISSET(sock, &readSet)) {
#if DEBUG_TCPHANDLER
	LOG(LOG_DEBUG,
	    "tcpserver reads from %p (socket %d)\n",
	    pos,
	    sock);
#endif
	if (SYSERR == readAndProcess(pos)) {
	  ClientHandle ch
	    = pos->next;
	  terminateClientConnection(pos);
	  pos = ch;
	  continue;
	}
      }
      if (FD_ISSET(sock, &writeSet)) {
	size_t ret;
	
#if DEBUG_TCPHANDLER
	LOG(LOG_DEBUG,
	    "tcpserver writes to %p.\n",
	    pos);
#endif
	if (pos->writeBufferSize == 0) {
	  if (pos->writeQueueSize > 0) {
	    unsigned int len;
	    len = ntohs(pos->writeQueue[0]->size);
	    pos->writeBuffer = (char*)pos->writeQueue[0];
	    pos->writeBufferSize = len;
	    for (len=0;len<pos->writeQueueSize-1;len++)
	      pos->writeQueue[len] = pos->writeQueue[len+1];
	    GROW(pos->writeQueue,
		 pos->writeQueueSize,
		 pos->writeQueueSize-1);
	  } else {
	    BREAK(); /* entry in write set but no messages pending! */
	  }
	}
try_again:
	success = SEND_NONBLOCKING(sock,
                                   pos->writeBuffer,
                                   pos->writeBufferSize,
                                   &ret);
	if (success == SYSERR) {
	  ClientHandle ch
	    = pos->next;
	  LOG_STRERROR(LOG_INFO, "send");
	  terminateClientConnection(pos);
	  pos = ch;
	  continue;
	} else if (success == NO) {
	  /* this should only happen under Win9x because
	     of a bug in the socket implementation (KB177346).
	     Let's sleep and try again. */
	  gnunet_util_sleep(20);
	  goto try_again;
	}
	if (ret == 0) {
	  ClientHandle ch
	    = pos->next;
          /* send only returns 0 on error (other side closed connection),
	     so close the session */
	  terminateClientConnection(pos);
	  pos = ch;
	  continue;
	}
	if (ret == pos->writeBufferSize) {
	  FREENONNULL(pos->writeBuffer);
	  pos->writeBuffer = NULL;
	  pos->writeBufferSize = 0;
	} else {
	  memmove(pos->writeBuffer,
		  &pos->writeBuffer[ret],
		  pos->writeBufferSize - ret);
	  pos->writeBufferSize -= ret;
	}
      }

      if (FD_ISSET(sock, &errorSet)) {
#if DEBUG_TCPHANDLER
	LOG(LOG_DEBUG,
	    "tcpserver error on connection %p.\n",
	    pos);
#endif
	ClientHandle ch
	  = pos->next;
	terminateClientConnection(pos);
	pos = ch;
	continue;
      }
      pos = pos->next;
    }
  } /* while tcpserver_keep_running */

  /* shutdown... */
  closefile(listenerFD);

  /* close all sessions */
  while (clientList != NULL)
    terminateClientConnection(clientList);

  MUTEX_UNLOCK(&clientlock);
  SEMAPHORE_UP(serverSignal);  /* signal shutdown */
  return NULL;
}


/**
 * Initialize the TCP port and listen for incoming client connections.
 */
int initTCPServer() {
  char * ch;
  if (tcpserver_keep_running == YES) {
    BREAK();
    return SYSERR;
  }

  ch = getConfigurationString("NETWORK",
			      "TRUSTED");
  if (ch == NULL) {
    trustedNetworks_ = parseRoutes("127.0.0.0/8;"); /* by default, trust localhost only */
  } else {
    trustedNetworks_ = parseRoutes(ch);
    if (trustedNetworks_ == NULL)
      errexit(_("Malformed network specification in the configuration in section `%s' for entry `%s': %s\n"),
	      "NETWORK",
	      "TRUSTED",
	      ch);
    FREE(ch);
  }

  PIPE(signalingPipe);
  /* important: make signalingPipe non-blocking
     to avoid stalling on signaling! */
  setBlocking(signalingPipe[1], NO);

  MUTEX_CREATE_RECURSIVE(&handlerlock);
  MUTEX_CREATE_RECURSIVE(&clientlock);
  if (testConfigurationString("TCPSERVER",
			      "DISABLE",
			      "YES"))
    return OK;
  tcpserver_keep_running = YES;
  serverSignal = SEMAPHORE_NEW(0);
  if (0 == PTHREAD_CREATE(&TCPLISTENER_listener_,
			  &tcpListenMain,
			  NULL,
			  64*1024)) {
    SEMAPHORE_DOWN(serverSignal);
  } else {
    LOG_STRERROR(LOG_FAILURE, "pthread_create");
    SEMAPHORE_FREE(serverSignal);
    serverSignal = NULL;
    tcpserver_keep_running = NO;
    MUTEX_DESTROY(&handlerlock);
    MUTEX_DESTROY(&clientlock);
    return SYSERR;
  }

  return OK;
}

/**
 * Shutdown the module.
 */
int stopTCPServer() {
  void * unused;

  if ( ( tcpserver_keep_running == YES) &&
       ( serverSignal != NULL) ) {
#if DEBUG_TCPHANDLER
    LOG(LOG_DEBUG,
	"stopping TCP server\n");
#endif
    /* stop server thread */
    tcpserver_keep_running = NO;
    signalSelect();
    SEMAPHORE_DOWN(serverSignal);
    SEMAPHORE_FREE(serverSignal);
    serverSignal = NULL;
    PTHREAD_JOIN(&TCPLISTENER_listener_,
		 &unused);
    return OK;
  } else {
    if (testConfigurationString("TCPSERVER",
				"DISABLE",
				"YES"))
      return OK;
    return SYSERR;
  }
}

int doneTCPServer() {
  stopTCPServer(); /* just to be sure; used mostly
		      for the benefit of gnunet-update
		      and other gnunet-tools that are
		      not gnunetd */
#if DEBUG_TCPHANDLER
  LOG(LOG_DEBUG,
      "entering %s\n", __FUNCTION__);
#endif
  closefile(signalingPipe[0]);
  closefile(signalingPipe[1]);
  /* free data structures */
  MUTEX_DESTROY(&handlerlock);
  MUTEX_DESTROY(&clientlock);
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
  MUTEX_LOCK(&handlerlock);
  if (type < max_registeredType) {
    if (handlers[type] != NULL) {
      MUTEX_UNLOCK(&handlerlock);
      LOG(LOG_WARNING,
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
  MUTEX_UNLOCK(&handlerlock);
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
  MUTEX_LOCK(&handlerlock);
  if (type < max_registeredType) {
    if (handlers[type] != callback) {
      MUTEX_UNLOCK(&handlerlock);
      return SYSERR; /* another handler present */
    } else {
      handlers[type] = NULL;
      MUTEX_UNLOCK(&handlerlock);
      return OK; /* success */
    }
  } else {  /* can't be there */
    MUTEX_UNLOCK(&handlerlock);
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
int sendTCPResultToClient(ClientHandle sock,
			  int ret) {
  CS_returnvalue_MESSAGE rv;

  rv.header.size
    = htons(sizeof(CS_returnvalue_MESSAGE));
  rv.header.type
    = htons(CS_PROTO_RETURN_VALUE);
  rv.return_value
    = htonl(ret);
  return sendToClient(sock,
		      &rv.header);
}
			
/**
 * Check if a handler is registered for a given
 * message type.
 *
 * @param type the message type
 * @return number of registered handlers (0 or 1)
 */
unsigned int isCSHandlerRegistered(unsigned short type) {
  MUTEX_LOCK(&handlerlock);
  if (type < max_registeredType) {
    if (handlers[type] != NULL) {
      MUTEX_UNLOCK(&handlerlock);
      return 1;
    }
  }
  MUTEX_UNLOCK(&handlerlock);
  return 0;
}

/* end of tcpserver.c */
