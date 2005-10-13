/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
#include "platform.h"
#include "ip6.h"

#define DEBUG_TCP6 NO

/**
 * after how much time of the core not being associated with a tcp6
 * connection anymore do we close it?
 */
#define TCP6_TIMEOUT 30 * cronSECONDS

#define TARGET_BUFFER_SIZE 4092

/**
 * @brief Host-Address in a TCP6 network.
 */
typedef struct {
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

/**
 * @brief TCP6 Message-Packet header.
 */
typedef struct {
  /**
   * size of the message, in bytes, including this header;
   * max 65536-header (network byte order)
   */
  unsigned short size;

  /**
   * For alignment, always 0.
   */
  unsigned short reserved;

} TCP6P2P_PACKET;

/**
 * Initial handshake message. Note that the beginning
 * must match the CS_MESSAGE_HEADER since we are using tcp6io.
 */
typedef struct {
  TCP6P2P_PACKET header;

  /**
   * Identity of the node connecting (TCP6 client)
   */
  PeerIdentity clientIdentity;
} TCP6Welcome;

/**
 * @brief TCP6 Transport Session handle.
 */
typedef struct {
  /**
   * the tcp6 socket
   */
  int sock;

  /**
   * number of users of this session
   */
  int users;

  /**
   * Last time this connection was used
   */
  cron_t lastUse;

  /**
   * mutex for synchronized access to 'users'
   */
  Mutex lock;

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
   * Current read position in the buffer.
   */
  unsigned int pos;

  /**
   * Current size of the buffer.
   */
  unsigned int rsize;

  /**
   * The read buffer.
   */
  char * rbuff;

  /**
   * Position in the write buffer
   */
  unsigned int wpos;

  /**
   * The write buffer.
   */
  char * wbuff;

  /**
   * Size of the write buffer
   */
  unsigned int wsize;

} TCP6Session;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static CoreAPIForTransport * coreAPI;
static TransportAPI tcp6API;

/**
 * one thread for listening for new connections,
 * and for reading on all open sockets
 */
static PTHREAD_T listenThread;

/**
 * sock is the tcp6 socket that we listen on for new inbound
 * connections.
 */
static int tcp6_sock;

/**
 * tcp6_pipe is used to signal the thread that is
 * blocked in a select call that the set of sockets to listen
 * to has changed.
 */
static int tcp6_pipe[2];

/**
 * Array of currently active TCP6 sessions.
 */
static TSession ** tsessions = NULL;
static unsigned int tsessionCount;
static unsigned int tsessionArrayLength;

/* configuration */
static struct CIDR6Network * filteredNetworks_;

/**
 * Lock for access to mutable state of the module,
 * that is the configuration and the tsessions array.
 * Note that we ONLY need to synchronize access to
 * the tsessions array when adding or removing sessions,
 * since removing is done only by one thread and we just
 * need to avoid another thread adding an element at the
 * same point in time. We do not need to synchronize at
 * every access point since adding new elements does not
 * prevent the select thread from operating and removing
 * is done by the only therad that reads from the array.
 */
static Mutex tcp6lock;

/**
 * Semaphore used by the server-thread to signal that
 * the server has been started -- and later again to
 * signal that the server has been stopped.
 */
static Semaphore * serverSignal = NULL;
static int tcp6_shutdown = YES;

/* ******************** helper functions *********************** */

/**
 * Check if we are allowed to connect to the given IP.
 */
static int isBlacklisted(IP6addr * ip) {
  int ret;

  MUTEX_LOCK(&tcp6lock);
  ret = checkIP6Listed(filteredNetworks_,
		       ip);
  MUTEX_UNLOCK(&tcp6lock);
  return ret;
}

/**
 * Write to the pipe to wake up the select thread (the set of
 * files to watch has changed).
 */
static void signalSelect() {
  char i = 0;
  int ret;

  ret = WRITE(tcp6_pipe[1],
	      &i,
	      sizeof(char));
  if (ret != sizeof(char))
    LOG_STRERROR(LOG_ERROR, "write");
}

/**
 * Disconnect from a remote node. May only be called
 * on sessions that were aquired by the caller first.
 * For the core, aquiration means to call associate or
 * connect. The number of disconnects must match the
 * number of calls to connect+associate.
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int tcp6Disconnect(TSession * tsession) {
  if (tsession->internal != NULL) {
    TCP6Session * tcp6session = tsession->internal;

    MUTEX_LOCK(&tcp6session->lock);
    tcp6session->users--;
    if (tcp6session->users > 0) {
      MUTEX_UNLOCK(&tcp6session->lock);
      return OK;
    }
    MUTEX_UNLOCK(&tcp6session->lock);
    MUTEX_DESTROY(&tcp6session->lock);
    FREE(tcp6session->rbuff);
    FREENONNULL(tcp6session->wbuff);
    FREE(tcp6session);
    FREE(tsession);
  }
  return OK;
}

/**
 * Remove a session, either the other side closed the connection
 * or we have otherwise reason to believe that it should better
 * be killed. Destroy session closes the session as far as the
 * TCP6 layer is concerned, but since the core may still have
 * references to it, tcp6Disconnect may not instantly free all
 * the associated resources. <p>
 *
 * destroySession may only be called if the tcp6lock is already
 * held.
 *
 * @param i index to the session handle
 */
static void destroySession(int i) {
  TCP6Session * tcp6Session;

  tcp6Session = tsessions[i]->internal;
  if (-1 != tcp6Session->sock)
    if (0 != SHUTDOWN(tcp6Session->sock, SHUT_RDWR))
      LOG_STRERROR(LOG_EVERYTHING, "shutdown");
  closefile(tcp6Session->sock);
  tcp6Session->sock = -1;
  tcp6Disconnect(tsessions[i]);
  tsessions[i] = tsessions[--tsessionCount];
  tsessions[tsessionCount] = NULL;
}

/**
 * Get the GNUnet UDP port from the configuration,
 * or from /etc/services if it is not specified in
 * the config file.
 */
static unsigned short getGNUnetTCP6Port() {
  struct servent * pse;	/* pointer to service information entry	*/
  unsigned short port;

  port = (unsigned short) getConfigurationInt("TCP6",
					      "PORT");
  if (port == 0) { /* try lookup in services */
    if ((pse = getservbyname("gnunet", "tcp6")))
      port = htons(pse->s_port);
  }
  return port;
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
static int tcp6Associate(TSession * tsession) {
  TCP6Session * tcp6Session;

  GNUNET_ASSERT(tsession != NULL);
  tcp6Session = (TCP6Session*) tsession->internal;
  MUTEX_LOCK(&tcp6Session->lock);
  tcp6Session->users++;
  MUTEX_UNLOCK(&tcp6Session->lock);
  return OK;
}

/**
 * The socket of session i has data waiting, process!
 *
 * This function may only be called if the tcp6lock is
 * already held by the caller.
 */
static int readAndProcess(int i) {
  TSession * tsession;
  TCP6Session * tcp6Session;
  unsigned int len;
  int ret;
  TCP6P2P_PACKET * pack;
  P2P_PACKET * mp;

  tsession = tsessions[i];
  if (SYSERR == tcp6Associate(tsession))
    return SYSERR;
  tcp6Session = tsession->internal;
  if (tcp6Session->rsize == tcp6Session->pos) {
    /* read buffer too small, grow */
    GROW(tcp6Session->rbuff,
	 tcp6Session->rsize,
	 tcp6Session->rsize * 2);
  }
  ret = READ(tcp6Session->sock,
	     &tcp6Session->rbuff[tcp6Session->pos],
	     tcp6Session->rsize - tcp6Session->pos);
  cronTime(&tcp6Session->lastUse);
  if (ret == 0) {
    tcp6Disconnect(tsession);
#if DEBUG_TCP6
    LOG(LOG_DEBUG,
	"READ on socket %d returned 0 bytes, closing connection\n",
	tcpSession->sock);
#endif
    return SYSERR; /* other side closed connection */
  }
  if (ret < 0) {
    if ( (errno == EINTR) ||
	 (errno == EAGAIN) ) {
#if DEBUG_TCP
      LOG_STRERROR(LOG_DEBUG, "read");
#endif
      tcp6Disconnect(tsession);
      return OK;
    }
#if DEBUG_TCP
    LOG_STRERROR(LOG_INFO, "read");
#endif
    tcp6Disconnect(tsession);
    return SYSERR;
  }
  incrementBytesReceived(ret);
  tcp6Session->pos += ret;

  while (tcp6Session->pos > 2) {
    len = ntohs(((TCP6P2P_PACKET*)&tcp6Session->rbuff[0])->size) + sizeof(TCP6P2P_PACKET);
    if (len > tcp6Session->rsize) /* if MTU larger than expected, grow! */
      GROW(tcp6Session->rbuff,
	   tcp6Session->rsize,
	   len);
#if DEBUG_TCP6
    LOG(LOG_DEBUG,
	"Read %d bytes on socket %d, expecting %d for full message\n",
	tcp6Session->pos,
	tcp6Session->sock,
	len);
#endif
    if (tcp6Session->pos < len) {
      tcp6Disconnect(tsession);
      return OK;
    }

    /* complete message received, let's check what it is */
    if (YES == tcp6Session->expectingWelcome) {
      TCP6Welcome * welcome;
#if DEBUG_TCP6
      EncName hex;
#endif

      welcome = (TCP6Welcome*) &tcp6Session->rbuff[0];
      if ( (ntohs(welcome->header.reserved) != 0) ||
	   (ntohs(welcome->header.size) != sizeof(TCP6Welcome) - sizeof(TCP6P2P_PACKET)) ) {
	LOG(LOG_WARNING,
	    _("Expected welcome message on tcp connection, got garbage. Closing.\n"));
	tcp6Disconnect(tsession);
	return SYSERR;
      }
      tcp6Session->expectingWelcome = NO;
      tcp6Session->sender = welcome->clientIdentity;
#if DEBUG_TCP6
      IFLOG(LOG_DEBUG,
	    hash2enc(&tcp6Session->sender.hashPubKey,
		     &enc));
      LOG(LOG_DEBUG,
	  "tcp6 welcome message from %s received\n",
	  &enc);
#endif
      memmove(&tcp6Session->rbuff[0],
	      &tcp6Session->rbuff[sizeof(TCP6Welcome)],
	      tcp6Session->pos - sizeof(TCP6Welcome));
      tcp6Session->pos -= sizeof(TCP6Welcome);
      len = ntohs(((TCP6P2P_PACKET*)&tcp6Session->rbuff[0])->size) + sizeof(TCP6P2P_PACKET);
    }
    if ( (tcp6Session->pos < 2) ||
	 (tcp6Session->pos < len) ) {
      tcp6Disconnect(tsession);
      return OK;
    }

    pack = (TCP6P2P_PACKET*)&tcp6Session->rbuff[0];
    /* send msg to core! */
    if (len <= sizeof(TCP6P2P_PACKET)) {
      LOG(LOG_WARNING,
	  _("Received malformed message from tcp6-peer connection. Closing connection.\n"));
      tcp6Disconnect(tsession);
      return SYSERR;
    }
    mp      = MALLOC(sizeof(P2P_PACKET));
    mp->msg = MALLOC(len - sizeof(TCP6P2P_PACKET));
    memcpy(mp->msg,
	   &pack[1],
	   len - sizeof(TCP6P2P_PACKET));
    mp->sender   = tcp6Session->sender;
    mp->size     = len - sizeof(TCP6P2P_PACKET);
    mp->tsession = tsession;
#if DEBUG_TCP6
    LOG(LOG_DEBUG,
	"tcp6 transport received %d bytes, forwarding to core\n",
	mp->size);
#endif
    coreAPI->receive(mp);

    if (tcp6Session->pos < len) {
      BREAK();
      tcp6Disconnect(tsession);
      return SYSERR;
    }
    /* finally, shrink buffer adequately */
    memmove(&tcp6Session->rbuff[0],
	    &tcp6Session->rbuff[len],
	    tcp6Session->pos - len);
    tcp6Session->pos -= len;	
    if ( (tcp6Session->pos * 4 < tcp6Session->rsize) &&
	 (tcp6Session->rsize > 4 * 1024) ) {
      /* read buffer far too large, shrink! */
      GROW(tcp6Session->rbuff,
	   tcp6Session->rsize,
	   tcp6Session->pos + 1024);
    }
  }
  tcp6Disconnect(tsession);
  return OK;
}

/**
 * Add a new session to the array watched by the select thread.  Grows
 * the array if needed.  If the caller wants to do anything useful
 * with the return value, it must have the lock on tcp6lock before
 * calling.  It is ok to call this function without holding tcp6lock if
 * the return value is ignored.
 */
static unsigned int addTSession(TSession * tsession) {
  unsigned int i;

  MUTEX_LOCK(&tcp6lock);
  if (tsessionCount == tsessionArrayLength)
    GROW(tsessions,
	 tsessionArrayLength,
	 tsessionArrayLength * 2);
  i = tsessionCount;
  tsessions[tsessionCount++] = tsession;
  MUTEX_UNLOCK(&tcp6lock);
  return i;
}

/**
 * Create a new session for an inbound connection on the given
 * socket. Adds the session to the array of sessions watched
 * by the select thread.
 */
static void createNewSession(int sock) {
  TSession * tsession;
  TCP6Session * tcp6Session;

  tcp6Session = MALLOC(sizeof(TCP6Session));
  tcp6Session->pos = 0;
  tcp6Session->rsize = 2 * 1024 + sizeof(TCP6P2P_PACKET);
  tcp6Session->rbuff = MALLOC(tcp6Session->rsize);
  tcp6Session->wpos = 0;
  tcp6Session->wbuff = NULL;
  tcp6Session->sock = sock;
  /* fill in placeholder identity to mark that we
     are waiting for the welcome message */
  tcp6Session->sender = *(coreAPI->myIdentity);
  tcp6Session->expectingWelcome = YES;
  MUTEX_CREATE_RECURSIVE(&tcp6Session->lock);
  tcp6Session->users = 1; /* us only, core has not seen this tsession! */
  cronTime(&tcp6Session->lastUse);
  tsession = MALLOC(sizeof(TSession));
  tsession->ttype = TCP6_PROTOCOL_NUMBER;
  tsession->internal = tcp6Session;
  addTSession(tsession);
}					

/**
 * Main method for the thread listening on the tcp6 socket and all tcp6
 * connections. Whenever a message is received, it is forwarded to the
 * core. This thread waits for activity on any of the TCP6 connections
 * and processes deferred (async) writes and buffers reads until an
 * entire message has been received.
 */
static void * tcp6ListenMain() {
  struct sockaddr_in6 clientAddr;
  fd_set readSet;
  fd_set errorSet;
  fd_set writeSet;
  struct stat buf;
  socklen_t lenOfIncomingAddr;
  int i;
  int max;
  int ret;

  if (tcp6_sock != -1)
    if (0 != LISTEN(tcp6_sock, 5))
      LOG_STRERROR(LOG_ERROR, "listen");
  SEMAPHORE_UP(serverSignal); /* we are there! */
  MUTEX_LOCK(&tcp6lock);
  while (tcp6_shutdown == NO) {
    FD_ZERO(&readSet);
    FD_ZERO(&errorSet);
    FD_ZERO(&writeSet);
    if (tcp6_sock != -1) {
      if (isSocketValid(tcp6_sock)) {
	FD_SET(tcp6_sock, &readSet);
      } else {
	LOG_STRERROR(LOG_ERROR, "isSocketValid");
	tcp6_sock = -1; /* prevent us from error'ing all the time */
      }
    } else
      LOG(LOG_DEBUG,
	  "TCP6 server socket not open!\n");
    if (tcp6_pipe[0] != -1) {
      if (-1 != FSTAT(tcp6_pipe[0], &buf)) {
	FD_SET(tcp6_pipe[0], &readSet);
      } else {
	LOG_STRERROR(LOG_ERROR, "fstat");
	tcp6_pipe[0] = -1; /* prevent us from error'ing all the time */	
      }
    }
    max = tcp6_pipe[0];
    if (tcp6_sock > tcp6_pipe[0])
      max = tcp6_sock;
    for (i=0;i<tsessionCount;i++) {
      TCP6Session * tcp6Session = tsessions[i]->internal;
      int sock = tcp6Session->sock;
      if (sock != -1) {
	if (isSocketValid(sock)) {
	  FD_SET(sock, &readSet);
	  FD_SET(sock, &errorSet);
	  if (tcp6Session->wpos > 0)
	    FD_SET(sock, &writeSet); /* do we have a pending write request? */
	} else {
	  LOG_STRERROR(LOG_ERROR, "isSocketValid");
	  destroySession(i);
	}
      } else {
	BREAK();
	destroySession(i);
      }
      if (sock > max)
	max = sock;
    }
    MUTEX_UNLOCK(&tcp6lock);
    ret = SELECT(max+1, &readSet, &writeSet, &errorSet, NULL);
    MUTEX_LOCK(&tcp6lock);
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
    if (tcp6_sock != -1) {
      if (FD_ISSET(tcp6_sock, &readSet)) {
	int sock;
	
	lenOfIncomingAddr = sizeof(clientAddr);
	sock = ACCEPT(tcp6_sock,
		      (struct sockaddr *)&clientAddr,
		      &lenOfIncomingAddr);
	if (sock != -1) {	
	  /* verify clientAddr for eligibility here (ipcheck-style,
	     user should be able to specify who is allowed to connect,
	     otherwise we just close and reject the communication! */  	
	  GNUNET_ASSERT(sizeof(struct in6_addr) == sizeof(IP6addr));
	  if (YES == isBlacklisted((IP6addr*)&clientAddr.sin6_addr)) {
	    char inet6[INET6_ADDRSTRLEN];
	    LOG(LOG_INFO,
		_("%s: Rejected connection from blacklisted address %s.\n"),
		"TCP6",
		inet_ntop(AF_INET6,
			  &clientAddr,
			  inet6,
			  INET6_ADDRSTRLEN));
	    SHUTDOWN(sock, 2);
	    closefile(sock);
	  } else
	    createNewSession(sock);
	} else {
	  LOG_STRERROR(LOG_INFO, "accept");
	}
      }
    }
    if (FD_ISSET(tcp6_pipe[0], &readSet)) {
      /* allow reading multiple signals in one go in case we get many
	 in one shot... */

#define MAXSIG_BUF 128
      char buf[MAXSIG_BUF];
      /* just a signal to refresh sets, eat and continue */
      if (0 >= READ(tcp6_pipe[0],
		    &buf[0],
		    MAXSIG_BUF)) {
	LOG_STRERROR(LOG_WARNING, "read");
      }
    }
    for (i=0;i<tsessionCount;i++) {
      TCP6Session * tcp6Session = tsessions[i]->internal;
      int sock = tcp6Session->sock;
      if (FD_ISSET(sock, &readSet)) {
	if (SYSERR == readAndProcess(i)) {
	  destroySession(i);
	  i--;
	  continue;
	}
      }
      if (FD_ISSET(sock, &writeSet)) {
	size_t ret;
	int success;

try_again_1:
	success = SEND_NONBLOCKING(sock,
				   tcp6Session->wbuff,
				   tcp6Session->wpos,
				   &ret);
	if (success == SYSERR) {
	  LOG_STRERROR(LOG_WARNING, "send");
	  destroySession(i);
	  i--;
	  continue;
        } else if (success == NO) {
  	  /* this should only happen under Win9x because
  	     of a bug in the socket implementation (KB177346).
  	     Let's sleep and try again. */
  	  gnunet_util_sleep(20);
  	  goto try_again_1;
        }
        if (ret == 0) {
          /* send only returns 0 on error (other side closed connection),
	   * so close the session */
	  destroySession(i);
	  i--;
	  continue;
	}
	if ((unsigned int)ret == tcp6Session->wpos) {
	  FREENONNULL(tcp6Session->wbuff);
	  tcp6Session->wbuff = NULL;
	  tcp6Session->wpos  = 0;
	  tcp6Session->wsize = 0;
	} else {
	  memmove(tcp6Session->wbuff,
		  &tcp6Session->wbuff[ret],
		  tcp6Session->wpos - ret);
	  tcp6Session->wpos -= ret;
	}
      }
      if (FD_ISSET(sock, &errorSet)) {
	destroySession(i);
	i--;
	continue;
      }
      if ( ( tcp6Session->users == 1) &&
	   (cronTime(NULL) > tcp6Session->lastUse + TCP6_TIMEOUT) ) {
	destroySession(i);
	i--;
	continue;
      }
    }
  }
  /* shutdown... */
  if (tcp6_sock != -1) {
    closefile(tcp6_sock);
    tcp6_sock = -1;
  }
  /* close all sessions */
  while (tsessionCount > 0)
    destroySession(0);
  MUTEX_UNLOCK(&tcp6lock);
  SEMAPHORE_UP(serverSignal); /* we are there! */
  return NULL;
} /* end of tcp6 listen main */

/**
 * Send a message (already encapsulated if needed) via the
 * tcp6 socket (or enqueue if sending now would block).
 *
 * @param tcp6Session the session to use for sending
 * @param mp the message to send
 * @param ssize the size of the message
 * @return OK if message send or queued, NO if queue is full and
 * message was dropped, SYSERR on error
 */
static int tcp6DirectSend(TCP6Session * tcp6Session,
			  void * mp,
			  unsigned int ssize) {
  size_t ret;
  int success;

  if (tcp6_shutdown == YES)
    return SYSERR;
  if (tcp6Session->sock == -1) {
#if DEBUG_TCP6
    LOG(LOG_INFO,
	"tcp6DirectSend called, but socket is closed\n");
#endif
    return SYSERR;
  }
  if (ssize == 0) {
    BREAK();
    return SYSERR;
  }
  MUTEX_LOCK(&tcp6lock);
  if (tcp6Session->wpos > 0) {
    MUTEX_UNLOCK(&tcp6lock);
    return NO;
  }
  success = SEND_NONBLOCKING(tcp6Session->sock,
			     mp,
			     ssize,
			     &ret);
  if (success == SYSERR) {
    LOG_STRERROR(LOG_INFO, "send");
    MUTEX_UNLOCK(&tcp6lock);
    return SYSERR;
  }
  if (success == NO)
    ret = 0;

  if (ret < ssize) { /* partial send */
    if (tcp6Session->wsize < ssize - ret) {
      GROW(tcp6Session->wbuff,
	   tcp6Session->wsize,
	   ssize - ret);
    }
    memcpy(tcp6Session->wbuff,
	   mp + ret,
	   ssize - ret);
    tcp6Session->wpos = ssize - ret;
    signalSelect(); /* select set changed! */
  }
  MUTEX_UNLOCK(&tcp6lock);
  cronTime(&tcp6Session->lastUse);
  incrementBytesSent(ssize);
  return OK;
}


/**
 * Send a message (already encapsulated if needed) via the
 * tcp6 socket.  Block if required.
 *
 * @param tcp6Session the session to use for sending
 * @param mp the message to send
 * @param ssize the size of the message
 * @return OK if message send or queued, NO if queue is full and
 * message was dropped, SYSERR on error
 */
static int tcp6DirectSendReliable(TCP6Session * tcp6Session,
				  void * mp,
				  unsigned int ssize) {
  int ok;

  if (tcp6Session->sock == -1) {
#if DEBUG_TCP6
    LOG(LOG_INFO,
	"tcp6DirectSendReliable called, but socket is closed\n");
#endif
    return SYSERR;
  }
  if (ssize == 0) {
    BREAK();
    return SYSERR;
  }
  MUTEX_LOCK(&tcp6lock);
  if (tcp6Session->wpos > 0) {
    unsigned int old = tcp6Session->wpos;
    /* reliable: grow send-buffer above limit! */
    GROW(tcp6Session->wbuff,
	 tcp6Session->wsize,
	 tcp6Session->wpos + ssize);
    tcp6Session->wpos += ssize;
    memcpy(&tcp6Session->wbuff[old],
	   mp,
	   ssize);
    ok = OK;
  } else {
    ok = tcp6DirectSend(tcp6Session,
			mp,
			ssize);
  }
  MUTEX_UNLOCK(&tcp6lock);
  return ok;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the P2P_hello_MESSAGE identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @return SYSERR on error, OK on success, NO if queue is full
 */
static int tcp6SendReliable(TSession * tsession,
			   const void * msg,
			   const unsigned int size) {
  TCP6P2P_PACKET * mp;
  int ok;

  if (size >= MAX_BUFFER_SIZE)
    return SYSERR;
  if (tcp6_shutdown == YES)
    return SYSERR;
  if (size == 0) {
    BREAK();
    return SYSERR;
  }
  if (((TCP6Session*)tsession->internal)->sock == -1)
    return SYSERR; /* other side closed connection */
  mp = MALLOC(sizeof(TCP6P2P_PACKET) + size);
  memcpy(&mp[1],
	 msg,
	 size);
  mp->size = htons(size);
  mp->reserved = 0;
  ok = tcp6DirectSendReliable(tsession->internal,
			      mp,
			      size + sizeof(TCP6P2P_PACKET));
  FREE(mp);
  return ok;
}


/**
 * Verify that a hello-Message is correct (a node
 * is reachable at that address). Since the reply
 * will be asynchronous, a method must be called on
 * success.
 * @param helo the hello message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on error
 */
static int verifyHelo(const P2P_hello_MESSAGE * helo) {
  Host6Address * haddr;

  haddr = (Host6Address*) &helo[1];
  if ( (ntohs(helo->senderAddressSize) != sizeof(Host6Address)) ||
       (ntohs(helo->header.size) != P2P_hello_MESSAGE_size(helo)) ||
       (ntohs(helo->header.type) != p2p_PROTO_hello) ||
       (ntohs(helo->protocol) != TCP6_PROTOCOL_NUMBER) ||
       (YES == isBlacklisted(&haddr->ip)) )
    return SYSERR; /* obviously invalid */
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
static P2P_hello_MESSAGE * createhello() {
  P2P_hello_MESSAGE * msg;
  Host6Address * haddr;
  unsigned short port;

  port = getGNUnetTCP6Port();
  if (0 == port) {
    LOG(LOG_DEBUG,
	"TCP6 port is 0, will only send using TCP6\n");
    return NULL; /* TCP6 transport is configured SEND-only! */
  }
  msg = (P2P_hello_MESSAGE *) MALLOC(sizeof(P2P_hello_MESSAGE) + sizeof(Host6Address));
  haddr = (Host6Address*) &msg[1];

  if (SYSERR == getPublicIP6Address(&haddr->ip)) {
    FREE(msg);
    LOG(LOG_WARNING,
	_("Could not determine my public IPv6 address.\n"));
    return NULL;
  }
  haddr->port = htons(port);
  haddr->reserved = htons(0);
  msg->senderAddressSize = htons(sizeof(Host6Address));
  msg->protocol = htons(TCP6_PROTOCOL_NUMBER);
  msg->MTU = htonl(tcp6API.mtu);
  return msg;
}

/**
 * Establish a connection to a remote node.
 *
 * @param helo the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return OK on success, SYSERR if the operation failed
 */
static int tcp6Connect(const P2P_hello_MESSAGE * helo,
		       TSession ** tsessionPtr) {
  int i;
  Host6Address * haddr;
  TCP6Welcome welcome;
  int sock;
  TSession * tsession;
  TCP6Session * tcp6Session;
  char hostname[INET6_ADDRSTRLEN];
  struct addrinfo hints, *res, *res0;
  int rtn;

  if (tcp6_shutdown == YES)
    return SYSERR;
  haddr = (Host6Address*) &helo[1];

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  inet_ntop(AF_INET6,
	    haddr,
	    hostname,
	    INET6_ADDRSTRLEN);
  rtn = getaddrinfo(hostname, NULL, &hints, &res0);
  if (rtn != 0) {
    LOG(LOG_WARNING,	
	_("`%s': unknown service: %s\n"),
	__FUNCTION__,
	gai_strerror(rtn));
    return SYSERR;
  }

#if DEBUG_TCP6
  LOG(LOG_DEBUG,
      "Creating TCP6 connection to %s:%d\n",
      inet_ntop(AF_INET6,
		haddr,
		&hostname,
		INET6_ADDRSTRLEN),
      ntohs(haddr->port));
#endif

  sock = -1;
  for (res=res0; res; res=res->ai_next) {
    if (res->ai_family != PF_INET6)
      continue;
    sock = SOCKET(res->ai_family,
		  res->ai_socktype,
		  res->ai_protocol);
    if (sock < 0)
      continue;
    if (0 != setBlocking(sock, NO)) {
      closefile(sock);
      LOG_STRERROR(LOG_FAILURE, "setBlocking");
      return SYSERR;
    }
    ((struct sockaddr_in6*)(res->ai_addr))->sin6_port
      = haddr->port;
    i = CONNECT(sock,
		res->ai_addr,
		res->ai_addrlen);
    if ( (i < 0) &&
	 (errno != EINPROGRESS) ) {
      LOG_STRERROR(LOG_WARNING, "connect");
      closefile(sock);
      sock = -1;
      continue;
    }
    break;
  }
  freeaddrinfo(res0);
  if (sock == -1) {
    LOG_STRERROR(LOG_FAILURE, "socket");
    return SYSERR;
  }
  if (0 != setBlocking(sock, NO)) {
    LOG_STRERROR(LOG_FAILURE, "setBlocking");
    closefile(sock);
    return SYSERR;
  }
  tcp6Session = MALLOC(sizeof(TCP6Session));
  tcp6Session->sock = sock;
  tcp6Session->wpos = 0;
  tcp6Session->wbuff = NULL;
  tcp6Session->rsize = 2 * 1024 + sizeof(TCP6P2P_PACKET);
  tcp6Session->rbuff = MALLOC(tcp6Session->rsize);
  tsession = MALLOC(sizeof(TSession));
  tsession->internal = tcp6Session;
  tsession->ttype = tcp6API.protocolNumber;
  MUTEX_CREATE_RECURSIVE(&tcp6Session->lock);
  tcp6Session->users = 2; /* caller + us */
  tcp6Session->pos = 0;
  cronTime(&tcp6Session->lastUse);
  memcpy(&tcp6Session->sender,
	 &helo->senderIdentity,
	 sizeof(PeerIdentity));
  tcp6Session->expectingWelcome = NO;
  MUTEX_LOCK(&tcp6lock);
  i = addTSession(tsession);

  /* send our node identity to the other side to fully establish the
     connection! */
  welcome.header.size = htons(sizeof(TCP6Welcome) - sizeof(TCP6P2P_PACKET));
  welcome.header.reserved = htons(0);
  memcpy(&welcome.clientIdentity,
	 coreAPI->myIdentity,
	 sizeof(PeerIdentity));
  if (SYSERR == tcp6DirectSend(tcp6Session,
			       &welcome,
			       sizeof(TCP6Welcome))) {
    destroySession(i);
    tcp6Disconnect(tsession);
    MUTEX_UNLOCK(&tcp6lock);
    return SYSERR;
  }
  MUTEX_UNLOCK(&tcp6lock);
  signalSelect();

  *tsessionPtr = tsession;
  return OK;
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the P2P_hello_MESSAGE identifying the remote node
 * @param msg the message
 * @param size the size of the message
 * @return SYSERR on error, OK on success
 */
static int tcp6Send(TSession * tsession,
		    const void * msg,
		    const unsigned int size) {
  TCP6P2P_PACKET * mp;
  int ok;

  if (size >= MAX_BUFFER_SIZE)
    return SYSERR;
  if (tcp6_shutdown == YES)
    return SYSERR;
  if (size == 0) {
    BREAK();
    return SYSERR;
  }
  if (((TCP6Session*)tsession->internal)->sock == -1)
    return SYSERR; /* other side closed connection */
  mp = MALLOC(sizeof(TCP6P2P_PACKET) + size);
  memcpy(&mp[1],
	 msg,
	 size);
  mp->size = htons(size);
  mp->reserved = 0;
  if (((TCP6Session*)tsession->internal)->wpos + size < TARGET_BUFFER_SIZE)
    ok = tcp6DirectSendReliable(tsession->internal,
				mp,
				size + sizeof(TCP6P2P_PACKET));
  else
    ok = tcp6DirectSend(tsession->internal,
			mp,
			size + sizeof(TCP6P2P_PACKET));
  FREE(mp);
  return ok;
}

/**
 * Start the server process to receive inbound traffic.
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer(void) {
  struct sockaddr_in6 serverAddr;
  const int on = 1;
  unsigned short port;

  if (serverSignal != NULL) {
    BREAK();
    return SYSERR;
  }
  serverSignal = SEMAPHORE_NEW(0);
  tcp6_shutdown = NO;

  if (0 != PIPE(tcp6_pipe)) {
    LOG_STRERROR(LOG_ERROR, "pipe");
    return SYSERR;
  }
  setBlocking(tcp6_pipe[1], NO);

  port = getGNUnetTCP6Port();
  if (port != 0) { /* if port == 0, this is a read-only
		      business! */
    tcp6_sock = SOCKET(PF_INET6,
		       SOCK_STREAM,
		       0);
    if (tcp6_sock < 0) {
      LOG_STRERROR(LOG_FAILURE, "socket");
      closefile(tcp6_pipe[0]);
      closefile(tcp6_pipe[1]);
      SEMAPHORE_FREE(serverSignal);
      serverSignal = NULL;
      tcp6_shutdown = YES;
      return SYSERR;
    }
    if (SETSOCKOPT(tcp6_sock,
		   SOL_SOCKET,
		   SO_REUSEADDR,
		   &on,
		   sizeof(on)) < 0 )
      DIE_STRERROR("setsockopt");
    memset((char *) &serverAddr,
	   0,
	   sizeof(serverAddr));
    serverAddr.sin6_family   = AF_INET6;
    serverAddr.sin6_flowinfo = 0;
    serverAddr.sin6_addr     = in6addr_any;
    serverAddr.sin6_port     = htons(getGNUnetTCP6Port());
#if DEBUG_TCP6
    LOG(LOG_INFO,
	"starting tcp6 peer server on port %d\n",
	ntohs(serverAddr.sin6_port));
#endif
    if (BIND(tcp6_sock,
	     (struct sockaddr *) &serverAddr,
	     sizeof(serverAddr)) < 0) {
      LOG_STRERROR(LOG_ERROR, "bind");
      LOG(LOG_ERROR,
	  _("Failed to start transport service on port %d.\n"),
	  getGNUnetTCP6Port());
      closefile(tcp6_sock);
      tcp6_sock = -1;
      SEMAPHORE_FREE(serverSignal);
      serverSignal = NULL;
      return SYSERR;
    }
  } else
    tcp6_sock = -1;
  if (0 == PTHREAD_CREATE(&listenThread,
			  (PThreadMain) &tcp6ListenMain,
			  NULL,
			  4092)) {
    SEMAPHORE_DOWN(serverSignal); /* wait for server to be up */
  } else {
    LOG_STRERROR(LOG_ERROR,
		 "pthread_create");
    closefile(tcp6_sock);
    SEMAPHORE_FREE(serverSignal);
    serverSignal = NULL;
    return SYSERR;
  }
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). Maybe restarted later!
 */
static int stopTransportServer() {
  void * unused;
  int haveThread;

  if (tcp6_shutdown == YES)
    return OK;
  tcp6_shutdown = YES;
  signalSelect();
  if (serverSignal != NULL) {
    haveThread = YES;
    SEMAPHORE_DOWN(serverSignal);
    SEMAPHORE_FREE(serverSignal);
  } else
    haveThread = NO;
  serverSignal = NULL;
  closefile(tcp6_pipe[1]);
  closefile(tcp6_pipe[0]);
  if (tcp6_sock != -1) {
    closefile(tcp6_sock);
    tcp6_sock = -1;
  }
  if (haveThread == YES)
    PTHREAD_JOIN(&listenThread, &unused);
  return OK;
}

/**
 * Reload the configuration. Should never fail (keep old
 * configuration on error, syslog errors!)
 */
static void reloadConfiguration(void) {
  char * ch;

  MUTEX_LOCK(&tcp6lock);
  FREENONNULL(filteredNetworks_);
  ch = getConfigurationString("TCP6",
			      "BLACKLIST");
  if (ch == NULL)
    filteredNetworks_ = parseRoutes6("");
  else {
    filteredNetworks_ = parseRoutes6(ch);
    FREE(ch);
  }
  MUTEX_UNLOCK(&tcp6lock);
}

/**
 * Convert TCP6 address to a string.
 */
static char * addressToString(const P2P_hello_MESSAGE * helo) {
  char * ret;
  char inet6[INET6_ADDRSTRLEN];
  Host6Address * haddr;

  haddr = (Host6Address*) &helo[1];
  ret = MALLOC(INET6_ADDRSTRLEN+16);
  SNPRINTF(ret,
	   INET6_ADDRSTRLEN+16,
	   "%s:%d (TCP6)",
	   inet_ntop(AF_INET6,
		     haddr,
		     inet6,
		     INET6_ADDRSTRLEN),
	   ntohs(haddr->port));
  return ret;
}


/* ******************** public API ******************** */

/**
 * The exported method. Makes the core api available
 * via a global and returns the udp transport API.
 */
TransportAPI * inittransport_tcp6(CoreAPIForTransport * core) {
  MUTEX_CREATE_RECURSIVE(&tcp6lock);
  reloadConfiguration();
  tsessionCount = 0;
  tsessionArrayLength = 0;
  GROW(tsessions,
       tsessionArrayLength,
       32);
  coreAPI = core;
  tcp6API.protocolNumber       = TCP6_PROTOCOL_NUMBER;
  tcp6API.mtu                  = 0;
  tcp6API.cost                 = 19950; /* about equal to udp6 */
  tcp6API.verifyHelo           = &verifyHelo;
  tcp6API.createhello           = &createhello;
  tcp6API.connect              = &tcp6Connect;
  tcp6API.associate            = &tcp6Associate;
  tcp6API.send                 = &tcp6Send;
  tcp6API.sendReliable         = &tcp6SendReliable;
  tcp6API.disconnect           = &tcp6Disconnect;
  tcp6API.startTransportServer = &startTransportServer;
  tcp6API.stopTransportServer  = &stopTransportServer;
  tcp6API.reloadConfiguration  = &reloadConfiguration;
  tcp6API.addressToString      = &addressToString;

  return &tcp6API;
}

void donetransport_tcp6() {
  int i;

  for (i=0;i<tsessionCount;i++)
    LOG(LOG_DEBUG,
	"tsessions array still contains %p\n",
	tsessions[i]);
  GROW(tsessions,
       tsessionArrayLength,
       0);
  FREENONNULL(filteredNetworks_);
  MUTEX_DESTROY(&tcp6lock);
}

/* end of tcp6.c */
