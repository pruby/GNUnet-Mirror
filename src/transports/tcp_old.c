/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file transports/tcp_old.c
 * @brief Implementation of the TCP transport service (0.7.0 compatible)
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "gnunet_stats_service.h"
#include "platform.h"
#include "ip.h"

#define DEBUG_TCP NO

/**
 * after how much time of the core not being associated with a tcp
 * connection anymore do we close it?
 */
#define TCP_TIMEOUT (30 * cronSECONDS)

#define TARGET_BUFFER_SIZE 4092

/**
 * Host-Address in a TCP network.
 */
typedef struct {
  /**
   * claimed IP of the sender, network byte order
   */
  IPaddr ip;

  /**
   * claimed port of the sender, network byte order
   */
  unsigned short port;

  /**
   * reserved (set to 0 for signature verification)
   */
  unsigned short reserved;

} HostAddress;

/**
 * TCP Message-Packet header.
 */
typedef struct {
  /**
   * size of the message, in bytes, excluding this header;
   * max 65535; we do NOT want to make this field an int
   * because then a malicious peer could cause us to allocate
   * lots of memory -- this bounds it by 64k/peer.
   * Field is in network byte order.
   */
  unsigned short size;

  /**
   * For alignment, always 0.
   */
  unsigned short reserved;

  /**
   * This struct is followed by MESSAGE_PARTs - until size is reached
   * There is no "end of message".
   */
} TCPP2P_PACKET;

/**
 * Initial handshake message. Note that the beginning
 * must match the CS_MESSAGE_HEADER since we are using tcpio.
 */
typedef struct {
  TCPP2P_PACKET header;

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
   * the tcp socket
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

  /**
   * Current read position in the buffer.
   */
  unsigned int pos;

  /**
   * Current size of the read buffer.
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

} TCPSession;

/* *********** globals ************* */

/**
 * apis (our advertised API and the core api )
 */
static CoreAPIForTransport * coreAPI;
static TransportAPI tcpAPI;

static Stats_ServiceAPI * stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

/**
 * one thread for listening for new connections,
 * and for reading on all open sockets
 */
static struct PTHREAD * listenThread;

/**
 * sock is the tcp socket that we listen on for new inbound
 * connections.
 */
static int tcp_sock;

/**
 * tcp_pipe is used to signal the thread that is
 * blocked in a select call that the set of sockets to listen
 * to has changed.
 */
static int tcp_pipe[2];

/**
 * Array of currently active TCP sessions.
 */
static TSession ** tsessions = NULL;
static unsigned int tsessionCount;
static unsigned int tsessionArrayLength;

/* configuration */
static struct CIDRNetwork * filteredNetworks_;

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
static struct MUTEX * tcplock;

/**
 * Semaphore used by the server-thread to signal that
 * the server has been started -- and later again to
 * signal that the server has been stopped.
 */
static struct SEMAPHORE * serverSignal = NULL;

static int tcp_shutdown = YES;

/* ******************** helper functions *********************** */

/**
 * Write to the pipe to wake up the select thread (the set of
 * files to watch has changed).
 */
static void signalSelect() {
  char i = 0;

  WRITE(tcp_pipe[1],
	&i,
	sizeof(char));
}

/**
 * Disconnect from a remote node. May only be called
 * on sessions that were acquired by the caller first.
 * For the core, aquiration means to call associate or
 * connect. The number of disconnects must match the
 * number of calls to connect+associate.
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int tcpDisconnect(TSession * tsession) {
  if (tsession->internal != NULL) {
    TCPSession * tcpsession = tsession->internal;

    MUTEX_LOCK(tcpsession->lock);
    tcpsession->users--;
    if (tcpsession->users > 0) {
      MUTEX_UNLOCK(tcpsession->lock);
      return OK;
    }
    MUTEX_UNLOCK(tcpsession->lock);
    MUTEX_DESTROY(tcpsession->lock);
    FREE(tcpsession->rbuff);
    FREENONNULL(tcpsession->wbuff);
    tcpsession->wbuff = NULL;
    FREE(tcpsession);
  }
  FREE(tsession);
  return OK;
}

/**
 * Remove a session, either the other side closed the connection
 * or we have otherwise reason to believe that it should better
 * be killed. Destroy session closes the session as far as the
 * TCP layer is concerned, but since the core may still have
 * references to it, tcpDisconnect may not instantly free all
 * the associated resources. <p>
 *
 * destroySession may only be called if the tcplock is already
 * held.
 *
 * @param i index to the session handle
 */
static void destroySession(int i) {
  TCPSession * tcpSession;

  tcpSession = tsessions[i]->internal;
  if (tcpSession->sock != -1)
    SHUTDOWN(tcpSession->sock, SHUT_RDWR);
  CLOSE(tcpSession->sock);
  tcpSession->sock = -1;
  tcpDisconnect(tsessions[i]);
  tsessions[i] = tsessions[--tsessionCount];
  tsessions[tsessionCount] = NULL;
}

/**
 * Get the GNUnet UDP port from the configuration,
 * or from /etc/services if it is not specified in
 * the config file.
 */
static unsigned short getGNUnetTCPPort() {
  return 2089; /* so far unused port */
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

  if (tsession == NULL) {
    return SYSERR;
  }
  tcpSession = (TCPSession*) tsession->internal;
  MUTEX_LOCK(tcpSession->lock);
  tcpSession->users++;
  MUTEX_UNLOCK(tcpSession->lock);
  return OK;
}

/**
 * The socket of session i has data waiting, process!
 *
 * This function may only be called if the tcplock is
 * already held by the caller.
 */
static int readAndProcess(int i) {
  TSession * tsession;
  TCPSession * tcpSession;
  unsigned int len;
  int ret;
  TCPP2P_PACKET * pack;
  P2P_PACKET * mp;

  tsession = tsessions[i];
  if (SYSERR == tcpAssociate(tsession))
    return SYSERR;
  tcpSession = tsession->internal;
  if (tcpSession->rsize == tcpSession->pos) {
    /* read buffer too small, grow */
    GROW(tcpSession->rbuff,
	 tcpSession->rsize,
	 tcpSession->rsize * 2);
  }
  ret = READ(tcpSession->sock,
	     &tcpSession->rbuff[tcpSession->pos],
	     tcpSession->rsize - tcpSession->pos);
  if (ret > 0) {
    if (stats != NULL)
      stats->change(stat_bytesReceived,
		    ret);
    if (coreAPI->load_monitor != NULL)
      os_network_monitor_notify_transmission(coreAPI->load_monitor,
					     Download,
					     ret);
  }
  tcpSession->lastUse = get_time();
  if (ret == 0) {
    tcpDisconnect(tsession);
    return SYSERR; /* other side closed connection */
  }
  if (ret < 0) {
    if ( (errno == EINTR) ||
	 (errno == EAGAIN) ) {
      tcpDisconnect(tsession);
      return OK;
    }
    tcpDisconnect(tsession);
    return SYSERR;
  }
  tcpSession->pos += ret;

  while (tcpSession->pos > 2) {
    len = ntohs(((TCPP2P_PACKET*)&tcpSession->rbuff[0])->size)
      + sizeof(TCPP2P_PACKET);
    if (len > tcpSession->rsize) /* if message larger than read buffer, grow! */
      GROW(tcpSession->rbuff,
	   tcpSession->rsize,
	   len);
    if (tcpSession->pos < len) {
      tcpDisconnect(tsession);
      return OK;
    }

    /* complete message received, let's check what it is */
    if (YES == tcpSession->expectingWelcome) {
      TCPWelcome * welcome;

      welcome = (TCPWelcome*) &tcpSession->rbuff[0];
      if ( (ntohs(welcome->header.reserved) != 0) ||
	   (ntohs(welcome->header.size)
	    != sizeof(TCPWelcome) - sizeof(TCPP2P_PACKET)) ) {
	tcpDisconnect(tsession);
	return SYSERR;
      }
      tcpSession->expectingWelcome = NO;
      tcpSession->sender = welcome->clientIdentity;
      memmove(&tcpSession->rbuff[0],
	      &tcpSession->rbuff[sizeof(TCPWelcome)],
	      tcpSession->pos - sizeof(TCPWelcome));
      tcpSession->pos -= sizeof(TCPWelcome);
      len = ntohs(((TCPP2P_PACKET*)&tcpSession->rbuff[0])->size)
	+ sizeof(TCPP2P_PACKET);
    }
    if ( (tcpSession->pos < 2) ||
	 (tcpSession->pos < len) ) {
      tcpDisconnect(tsession);
      return OK;
    }

    pack = (TCPP2P_PACKET*)&tcpSession->rbuff[0];
    /* send msg to core! */
    if (len <= sizeof(TCPP2P_PACKET)) {
      tcpDisconnect(tsession);
      return SYSERR;
    }
    mp      = MALLOC(sizeof(P2P_PACKET));
    mp->msg = MALLOC(len - sizeof(TCPP2P_PACKET));
    memcpy(mp->msg,
	   &pack[1],
	   len - sizeof(TCPP2P_PACKET));
    mp->sender   = tcpSession->sender;
    mp->size     = len - sizeof(TCPP2P_PACKET);
    mp->tsession = tsession;
    coreAPI->receive(mp);
    /* finally, shrink buffer adequately */
    memmove(&tcpSession->rbuff[0],
	    &tcpSession->rbuff[len],
	    tcpSession->pos - len);
    tcpSession->pos -= len;
    if ( (tcpSession->pos + 1024 < tcpSession->rsize) &&
	 (tcpSession->rsize > 4 * 1024) ) {
      /* read buffer far too large, shrink! */
      GROW(tcpSession->rbuff,
	   tcpSession->rsize,
	   tcpSession->pos + 1024);
    }
  }
  tcpDisconnect(tsession);
  return OK;
}

/**
 * Add a new session to the array watched by the select thread.  Grows
 * the array if needed.  If the caller wants to do anything useful
 * with the return value, it must have the lock on tcplock before
 * calling.  It is ok to call this function without holding tcplock if
 * the return value is ignored.
 */
static unsigned int addTSession(TSession * tsession) {
  unsigned int i;

  MUTEX_LOCK(tcplock);
  if (tsessionCount == tsessionArrayLength)
    GROW(tsessions,
	 tsessionArrayLength,
	 tsessionArrayLength * 2);
  i = tsessionCount;
  tsessions[tsessionCount++] = tsession;
  MUTEX_UNLOCK(tcplock);
  return i;
}

/**
 * Create a new session for an inbound connection on the given
 * socket. Adds the session to the array of sessions watched
 * by the select thread.
 */
static void createNewSession(int sock) {
  TSession * tsession;
  TCPSession * tcpSession;

  tcpSession = MALLOC(sizeof(TCPSession));
  tcpSession->pos = 0;
  tcpSession->rsize = 2 * 1024 + sizeof(TCPP2P_PACKET);
  tcpSession->rbuff = MALLOC(tcpSession->rsize);
  tcpSession->wpos = 0;
  tcpSession->wbuff = NULL;
  tcpSession->wsize = 0;
  tcpSession->sock = sock;
  /* fill in placeholder identity to mark that we
     are waiting for the welcome message */
  tcpSession->sender = *(coreAPI->myIdentity);
  tcpSession->expectingWelcome = YES;
  tcpSession->lock = MUTEX_CREATE(YES);
  tcpSession->users = 1; /* us only, core has not seen this tsession! */
  tcpSession->lastUse = get_time();
  tsession = MALLOC(sizeof(TSession));
  tsession->ttype = TCP_OLD_PROTOCOL_NUMBER;
  tsession->internal = tcpSession;
  addTSession(tsession);
}					


/**
 * Depending on doBlock, enable or disable the nonblocking mode
 * of socket s.
 *
 * @param doBlock use YES to change the socket to blocking, NO to non-blocking
 * @return Upon successful completion, it returns zero, otherwise -1
 */
static int setBlocking(int s, int doBlock) {
#if MINGW
  u_long l = !doBlock;
  if (ioctlsocket(s, FIONBIO, &l) == SOCKET_ERROR) {
    SetErrnoFromWinsockError(WSAGetLastError());

    return -1;
  } else {
    /* store the blocking mode */
    __win_SetHandleBlockingMode(s, doBlock);
    return 0;
  }
#else
  int flags = fcntl(s, F_GETFL);
  if (doBlock)
    flags &= ~O_NONBLOCK;
  else
    flags |= O_NONBLOCK;

  return fcntl(s,
	       F_SETFL,
	       flags);
#endif
}

/**
 * Do a NONBLOCKING write on the given socket.
 * Write at most max bytes from buf.
 * Interrupts are ignored (cause a re-try).
 *
 * The caller must be prepared to the fact that this function
 * may fail with EWOULDBLOCK in any case (Win32).
 *
 * @param s socket
 * @param buf buffer to send
 * @param max maximum number of bytes to send
 * @param sent number of bytes actually sent
 * @return SYSERR on error, YES on success or
 *         NO if the operation would have blocked.
 */
static int SEND_NONBLOCKING(int s,
		     const void * buf,
		     size_t max,
		     size_t * sent) {
  int flags;

  setBlocking(s, NO);

#ifdef SOMEBSD
    flags = MSG_DONTWAIT;
#elif SOLARIS
    flags = MSG_DONTWAIT;
#elif OSX
    {
    const int __tmp = 1;
    if (setsockopt(s, 
		   SOL_SOCKET,
		   SO_NOSIGPIPE,
		   (void *)&__tmp, 
		   sizeof(__tmp)) != 0)
      GE_LOG_STRERROR(NULL,
		      GE_WARNING | GE_ADMIN | GE_BULK,
		      "setsockopt");
    }
    flags = MSG_DONTWAIT;
#elif CYGWIN
	flags = MSG_NOSIGNAL;
#elif LINUX
	flags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
    /* pray */
	flags = 0;
#endif

  do {
    *sent = (size_t) SEND(s,
	                  buf,
	                  max,
	                  flags);

  } while ( (*sent == -1) &&
	    (errno == EINTR) );

  setBlocking(s, YES);

  if ( (*sent == SYSERR) &&
       ( (errno == EWOULDBLOCK)
	 || (errno == EAGAIN) ) )
    return NO;
  else if ( (*sent < 0) || (*sent > max) )
    return SYSERR;
  if (coreAPI->load_monitor != NULL)
    os_network_monitor_notify_transmission(coreAPI->load_monitor,
					   Upload,
					   *sent);
  return YES;
}

/**
 * Check if socket is valid
 * @return 1 if valid, 0 otherwise
 */
static int isSocketValid(int s)
{
#ifndef MINGW
  struct stat buf;
  return -1 != fstat(s, &buf);
#else
  long l;
  return ioctlsocket(s, FIONREAD, &l) != SOCKET_ERROR;
#endif
}

/**
 * Main method for the thread listening on the tcp socket and all tcp
 * connections. Whenever a message is received, it is forwarded to the
 * core. This thread waits for activity on any of the TCP connections
 * and processes deferred (async) writes and buffers reads until an
 * entire message has been received.
 */
static void * tcpListenMain() {
  struct sockaddr_in clientAddr;
  fd_set readSet;
  fd_set errorSet;
  fd_set writeSet;
  struct stat buf;
  socklen_t lenOfIncomingAddr;
  int i;
  int max;
  int ret;

  if (tcp_sock != -1)
    LISTEN(tcp_sock, 5);
  SEMAPHORE_UP(serverSignal); /* we are there! */
  MUTEX_LOCK(tcplock);
  while (tcp_shutdown == NO) {
    FD_ZERO(&readSet);
    FD_ZERO(&errorSet);
    FD_ZERO(&writeSet);
    if (tcp_sock != -1) {
      if (isSocketValid(tcp_sock)) {
	FD_SET(tcp_sock, &readSet);
      } else {	
	tcp_sock = -1; /* prevent us from error'ing all the time */
      }
    }
    if (tcp_pipe[0] != -1) {
      if (-1 != FSTAT(tcp_pipe[0], &buf)) {
	FD_SET(tcp_pipe[0], &readSet);
      } else {
	tcp_pipe[0] = -1; /* prevent us from error'ing all the time */	
      }
    }
    max = tcp_pipe[0];
    if (tcp_sock > tcp_pipe[0])
      max = tcp_sock;
    for (i=0;i<tsessionCount;i++) {
      TCPSession * tcpSession = tsessions[i]->internal;
      int sock = tcpSession->sock;
      if (sock != -1) {
	if (isSocketValid(sock)) {
	  FD_SET(sock, &readSet);
	  FD_SET(sock, &errorSet);
	  if (tcpSession->wpos > 0)
	    FD_SET(sock, &writeSet); /* do we have a pending write request? */
	} else {
	  destroySession(i);
	}
      } else {
	destroySession(i);
      }
      if (sock > max)
	max = sock;
    }
    MUTEX_UNLOCK(tcplock);
    ret = SELECT(max+1, &readSet, &writeSet, &errorSet, NULL);
    MUTEX_LOCK(tcplock);
    if ( (ret == -1) &&
	 ( (errno == EAGAIN) || (errno == EINTR) ) )
      continue;
    if (tcp_sock != -1) {
      if (FD_ISSET(tcp_sock, &readSet)) {
	int sock;
	
	lenOfIncomingAddr = sizeof(clientAddr);
	/* make sure we do not block */
	setBlocking(tcp_sock, NO);
	sock = ACCEPT(tcp_sock,
		      (struct sockaddr *)&clientAddr,
		      &lenOfIncomingAddr);
	if (sock != -1) {	
	  /* verify clientAddr for eligibility here (ipcheck-style,
	     user should be able to specify who is allowed to connect,
	     otherwise we just close and reject the communication! */

	  IPaddr ipaddr;
	  memcpy(&ipaddr,
		 &clientAddr.sin_addr,
		 sizeof(struct in_addr));

	  createNewSession(sock);	
	}
      }
    }
    if (FD_ISSET(tcp_pipe[0], &readSet)) {
      /* allow reading multiple signals in one go in case we get many
	 in one shot... */
#define MAXSIG_BUF 128
      char buf[MAXSIG_BUF];
      /* just a signal to refresh sets, eat and continue */
      if (0 >= READ(tcp_pipe[0],
		    &buf[0],
		    MAXSIG_BUF)) {
      }
    }
    for (i=0;i<tsessionCount;i++) {
      TCPSession * tcpSession = tsessions[i]->internal;
      int sock = tcpSession->sock;
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
				   tcpSession->wbuff,
				   tcpSession->wpos,
				   &ret);
	if ( (success == SYSERR) || (ret == (size_t) -1) ) {
	  destroySession(i);
	  i--;
	  continue;
        } else if (success == NO) {
  	  /* this should only happen under Win9x because
  	     of a bug in the socket implementation (KB177346).
  	     Let's sleep and try again. */
  	  PTHREAD_SLEEP(20);
  	  goto try_again_1;
        }
	if (stats != NULL)
	  stats->change(stat_bytesSent,
			ret);

	if (ret == 0) {
          /* send only returns 0 on error (other side closed connection),
	   * so close the session */
	  destroySession(i);
	  i--;
	  continue;
	}
	if (ret == tcpSession->wpos) {
	  FREENONNULL(tcpSession->wbuff);
	  tcpSession->wbuff = NULL;
	  tcpSession->wpos  = 0;
	  tcpSession->wsize = 0;
	} else {
	  memmove(tcpSession->wbuff,
		  &tcpSession->wbuff[ret],
		  tcpSession->wpos - ret);
	  tcpSession->wpos -= ret;
	}
      }
      if (FD_ISSET(sock, &errorSet)) {
	destroySession(i);
	i--;
	continue;
      }
      if ( ( tcpSession->users == 1) &&
	   (get_time() > tcpSession->lastUse + TCP_TIMEOUT) ) {
	destroySession(i);
	i--;
	continue;
      }
    }
  }
  /* shutdown... */
  if (tcp_sock != -1) {
    CLOSE(tcp_sock);
    tcp_sock = -1;
  }
  /* close all sessions */
  while (tsessionCount > 0)
    destroySession(0);
  MUTEX_UNLOCK(tcplock);
  SEMAPHORE_UP(serverSignal); /* we are there! */
  return NULL;
} /* end of tcp listen main */

/**
 * Send a message (already encapsulated if needed) via the
 * tcp socket (or enqueue if sending now would block).
 *
 * @param tcpSession the session to use for sending
 * @param mp the message to send
 * @param ssize the size of the message
 * @return OK if message send or queued, NO if queue is full and
 * message was dropped, SYSERR on error
 */
static int tcpDirectSend(TCPSession * tcpSession,
			 void * mp,
			 unsigned int ssize) {
  size_t ret;
  int success;

  if (tcp_shutdown == YES) 
    return SYSERR;  
  if (tcpSession->sock == -1) 
    return SYSERR;  
  if (ssize == 0) 
    return SYSERR;  
  MUTEX_LOCK(tcplock);
  if (tcpSession->wpos > 0) {
    /* select already pending... */
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    ssize);
    MUTEX_UNLOCK(tcplock);
    return NO;
  }
  success = SEND_NONBLOCKING(tcpSession->sock,
			     mp,
			     ssize,
			     &ret);
  if (success == SYSERR) {
    MUTEX_UNLOCK(tcplock);
    return SYSERR;
  }
  if (success == NO)
    ret = 0;
  if (stats != NULL)
    stats->change(stat_bytesSent,
		  ret);

  if (ret < ssize) {/* partial send */
    if (tcpSession->wsize < ssize - ret) {
      GROW(tcpSession->wbuff,
	   tcpSession->wsize,
	   ssize - ret);
    }
    memcpy(tcpSession->wbuff,
	   mp + ret,
	   ssize - ret);
    tcpSession->wpos = ssize - ret;
    signalSelect(); /* select set changed! */
  }
  tcpSession->lastUse = get_time();
  MUTEX_UNLOCK(tcplock);
  return OK;
}

/**
 * Send a message (already encapsulated if needed) via the
 * tcp socket.  Block if required.
 *
 * @param tcpSession the session to use for sending
 * @param mp the message to send
 * @param ssize the size of the message
 * @return OK if message send or queued, NO if queue is full and
 * message was dropped, SYSERR on error
 */
static int tcpDirectSendReliable(TCPSession * tcpSession,
				 void * mp,
				 unsigned int ssize) {
  int ok;

  if (tcp_shutdown == YES) 
    return SYSERR;  
  if (tcpSession->sock == -1) 
    return SYSERR;  
  if (ssize == 0)
    return SYSERR;
  MUTEX_LOCK(tcplock);
  if (tcpSession->wpos > 0) {
    unsigned int old = tcpSession->wpos;
    GROW(tcpSession->wbuff,
	 tcpSession->wsize,
	 tcpSession->wpos + ssize);
    tcpSession->wpos += ssize;
    memcpy(&tcpSession->wbuff[old],
	   mp,
	   ssize);
    ok = OK;
  } else {
    ok = tcpDirectSend(tcpSession,
		       mp,
		       ssize);
  }
  MUTEX_UNLOCK(tcplock);
  return ok;
}

/**
 * Verify that a Hello-Message is correct (a node
 * is reachable at that address). Since the reply
 * will be asynchronous, a method must be called on
 * success.
 * @param helo the Hello message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on error
 */
static int verifyHelo(const P2P_hello_MESSAGE * helo) {
  HostAddress * haddr;

  haddr = (HostAddress*) &helo[1];
  if ( (ntohs(helo->senderAddressSize) != sizeof(HostAddress)) ||
       (ntohs(helo->header.size) != P2P_hello_MESSAGE_size(helo)) ||
       (ntohs(helo->header.type) != p2p_PROTO_hello) ||
       (ntohs(helo->protocol) != TCP_OLD_PROTOCOL_NUMBER) )
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
  HostAddress * haddr;
  unsigned short port;

  port = getGNUnetTCPPort();
  if (0 == port) {
    static int once = 0;
    if (once == 0) {
      once = 1;
    }
    return NULL; /* TCP transport is configured SEND-only! */
  }
  msg = (P2P_hello_MESSAGE *) MALLOC(sizeof(P2P_hello_MESSAGE) + sizeof(HostAddress));
  haddr = (HostAddress*) &msg[1];

  if (SYSERR == getPublicIPAddress(coreAPI->cfg,
				   coreAPI->ectx,
				   &haddr->ip)) {
    FREE(msg);
    return NULL;
  }
  haddr->port = htons(port);
  haddr->reserved = htons(0);
  msg->senderAddressSize = htons(sizeof(HostAddress));
  msg->protocol = htons(TCP_OLD_PROTOCOL_NUMBER);
  msg->MTU = htonl(tcpAPI.mtu);
  return msg;
}

/**
 * Establish a connection to a remote node.
 *
 * @param helo the hello-Message for the target node
 * @param tsessionPtr the session handle that is set
 * @return OK on success, SYSERR if the operation failed
 */
static int tcpConnect(const P2P_hello_MESSAGE * helo,
		      TSession ** tsessionPtr) {
  int i;
  HostAddress * haddr;
  TCPWelcome welcome;
  int sock;
  TSession * tsession;
  TCPSession * tcpSession;
  struct sockaddr_in soaddr;

  if (tcp_shutdown == YES)
    return SYSERR;
  haddr = (HostAddress*) &helo[1];
  sock = SOCKET(PF_INET,
		SOCK_STREAM,
		6); /* 6: TCP */
  if (sock == -1) {
    return SYSERR;
  }
#ifndef OSX
  if (0 != setBlocking(sock, NO)) {
    CLOSE(sock);
    return SYSERR;
  }
#endif
  memset(&soaddr,
	 0,
	 sizeof(soaddr));
  soaddr.sin_family = AF_INET;

  memcpy(&soaddr.sin_addr,
	 &haddr->ip,
	 sizeof(IPaddr));
  soaddr.sin_port = haddr->port;
  i = CONNECT(sock,
	      (struct sockaddr*)&soaddr,
	      sizeof(soaddr));
  if ( (i < 0) &&
       (errno != EINPROGRESS) ) {
    CLOSE(sock);
    return SYSERR;
  }
  if (0 != setBlocking(sock, NO)) {
    CLOSE(sock);
    return SYSERR;
  }
  tcpSession = MALLOC(sizeof(TCPSession));
  tcpSession->sock = sock;
  tcpSession->wpos = 0;
  tcpSession->wbuff = NULL;
  tcpSession->wsize = 0;
  tcpSession->rsize = 2 * 1024 + sizeof(TCPP2P_PACKET);
  tcpSession->rbuff = MALLOC(tcpSession->rsize);
  tsession = MALLOC(sizeof(TSession));
  tsession->internal = tcpSession;
  tsession->ttype = tcpAPI.protocolNumber;
  tcpSession->lock = MUTEX_CREATE(YES);
  tcpSession->users = 2; /* caller + us */
  tcpSession->pos = 0;
  tcpSession->lastUse = get_time();
  tcpSession->sender = helo->senderIdentity;
  tcpSession->expectingWelcome = NO;
  MUTEX_LOCK(tcplock);
  i = addTSession(tsession);

  /* send our node identity to the other side to fully establish the
     connection! */
  welcome.header.size
    = htons(sizeof(TCPWelcome) - sizeof(TCPP2P_PACKET));
  welcome.header.reserved
    = htons(0);
  welcome.clientIdentity
    = *(coreAPI->myIdentity);
  if (SYSERR == tcpDirectSend(tcpSession,
			      &welcome,
			      sizeof(TCPWelcome))) {
    destroySession(i);
    tcpDisconnect(tsession);
    MUTEX_UNLOCK(tcplock);
    return SYSERR;
  }
  MUTEX_UNLOCK(tcplock);
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
static int tcpSend(TSession * tsession,
		   const void * msg,
		   unsigned int size,
		   int important) {
  TCPP2P_PACKET * mp;
  int ok;

  if (size >= MAX_BUFFER_SIZE) 
    return SYSERR; 
  if (tcp_shutdown == YES) {
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    size);
    return SYSERR;
  }
  if (size == 0) 
    return SYSERR;  
  if (((TCPSession*)tsession->internal)->sock == -1) {
    if (stats != NULL)
      stats->change(stat_bytesDropped,
		    size);
    return SYSERR; /* other side closed connection */
  }
  mp = MALLOC(sizeof(TCPP2P_PACKET) + size);
  memcpy(&mp[1],
	 msg,
	 size);
  mp->size = htons(size);
  mp->reserved = 0;
  /* if we would have less than TARGET_BUFFER_SIZE in buffers,
     do reliable send */
  if (((TCPSession*)tsession->internal)->wpos + size < TARGET_BUFFER_SIZE)
    ok = tcpDirectSendReliable(tsession->internal,
			       mp,
			       size + sizeof(TCPP2P_PACKET));
  else
    ok = tcpDirectSend(tsession->internal,
		       mp,
		       size + sizeof(TCPP2P_PACKET));
  FREE(mp);
  return ok;
}

/**
 * Start the server process to receive inbound traffic.
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer(void) {
  struct sockaddr_in serverAddr;
  const int on = 1;
  unsigned short port;

  if (serverSignal != NULL) {
    return SYSERR;
  }
  serverSignal = SEMAPHORE_CREATE(0);
  tcp_shutdown = NO;

  if (0 != PIPE(tcp_pipe))
    return SYSERR;
  setBlocking(tcp_pipe[1], NO);

  port = getGNUnetTCPPort();
  if (port != 0) { /* if port == 0, this is a read-only
		      business! */
    tcp_sock = SOCKET(PF_INET,
		      SOCK_STREAM,
		      0);
    if (tcp_sock < 0) {
      CLOSE(tcp_pipe[0]);
      CLOSE(tcp_pipe[1]);
      SEMAPHORE_DESTROY(serverSignal);
      serverSignal = NULL;
      tcp_shutdown = YES;
      return SYSERR;
    }
    if (0 != SETSOCKOPT(tcp_sock,
			SOL_SOCKET,
			SO_REUSEADDR,
			&on,
			sizeof(on))) 
      GE_LOG_STRERROR(NULL,
		      GE_WARNING | GE_ADMIN | GE_BULK,
		      "setsockopt");
    memset((char *) &serverAddr,
	   0,
	   sizeof(serverAddr));
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port        = htons(getGNUnetTCPPort());
    if (BIND(tcp_sock,
	     (struct sockaddr *) &serverAddr,
	     sizeof(serverAddr)) < 0) {
      CLOSE(tcp_sock);
      tcp_sock = -1;
      SEMAPHORE_DESTROY(serverSignal);
      serverSignal = NULL;
      return SYSERR;
    }
  } else
    tcp_sock = -1;
  listenThread = PTHREAD_CREATE((PThreadMain) &tcpListenMain,
				NULL,
				4092);
  SEMAPHORE_DOWN(serverSignal, YES); /* wait for server to be up */
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound
 * traffic). Maybe restarted later!
 */
static int stopTransportServer() {
  void * unused;
  int haveThread;

  if (tcp_shutdown == YES)
    return OK;
  tcp_shutdown = YES;
  signalSelect();
  if (serverSignal != NULL) {
    haveThread = YES;
    SEMAPHORE_DOWN(serverSignal, YES);
    SEMAPHORE_DESTROY(serverSignal);
  } else
    haveThread = NO;
  serverSignal = NULL;
  CLOSE(tcp_pipe[1]);
  CLOSE(tcp_pipe[0]);
  if (tcp_sock != -1) {
    CLOSE(tcp_sock);
    tcp_sock = -1;
  }
  if (haveThread == YES)
    PTHREAD_JOIN(listenThread, &unused);
  return OK;
}

/**
 * Convert TCP address to a string.
 */
static char * 
addressToString(const P2P_hello_MESSAGE * hello,
		int do_resolve) {
  char * ret;
  const HostAddress * haddr = (const HostAddress*) &hello[1];
  size_t n;
  const char * hn = "";
  struct hostent * ent;

#if HAVE_GETHOSTBYADDR
  if (do_resolve) {
    ent = gethostbyaddr(haddr,
			sizeof(IPaddr),
			AF_INET);
    if (ent != NULL)
      hn = ent->h_name;
  }    
#endif
  n = 4*4+6+6 + strlen(hn) + 10;
  ret = MALLOC(n);
  if (strlen(hn) > 0) {
    SNPRINTF(ret,
	     n,
	     "%s (%u.%u.%u.%u) TCP (%u)",
	     hn,
	     PRIP(ntohl(*(int*)&haddr->ip.addr)),
	     ntohs(haddr->port));
  } else {
    SNPRINTF(ret,
	     n,
	     "%u.%u.%u.%u TCP (%u)",
	     PRIP(ntohl(*(int*)&haddr->ip.addr)),
	     ntohs(haddr->port));
  }
  return ret;
}

static int testWouldTry(TSession * tsession,
			unsigned int size,
			int important) {
  if (size >= MAX_BUFFER_SIZE) 
    return SYSERR;
  if (tcp_shutdown == YES) 
    return SYSERR;  
  if (size == 0) 
    return SYSERR;
  if ( (((TCPSession*)tsession->internal)->wpos + size < TARGET_BUFFER_SIZE) ||
       (((TCPSession*)tsession->internal)->wpos == 0) )
    return YES;
  return NO;
}

/* ******************** public API ******************** */

/**
 * The exported method. Makes the core api available
 * via a global and returns the udp transport API.
 */
TransportAPI * inittransport_tcp_old(CoreAPIForTransport * core) {
  tcplock = MUTEX_CREATE(YES);
  tsessionCount = 0;
  tsessionArrayLength = 0;
  GROW(tsessions,
       tsessionArrayLength,
       32);
  coreAPI = core;
  stats = coreAPI->requestService("stats");
  if (stats != NULL) {
    stat_bytesReceived
      = stats->create(gettext_noop("# bytes received via TCP-OLD"));
    stat_bytesSent
      = stats->create(gettext_noop("# bytes sent via TCP-OLD"));
    stat_bytesDropped
      = stats->create(gettext_noop("# bytes dropped by TCP-OLD (outgoing)"));
  }
  tcpAPI.protocolNumber       = TCP_OLD_PROTOCOL_NUMBER;
  tcpAPI.mtu                  = 0;
  tcpAPI.cost                 = 20000; /* about equal to udp */
  tcpAPI.verifyHelo           = &verifyHelo;
  tcpAPI.createhello          = &createhello;
  tcpAPI.connect              = &tcpConnect;
  tcpAPI.associate            = &tcpAssociate;
  tcpAPI.send                 = &tcpSend;
  tcpAPI.disconnect           = &tcpDisconnect;
  tcpAPI.startTransportServer = &startTransportServer;
  tcpAPI.stopTransportServer  = &stopTransportServer;
  tcpAPI.addressToString      = &addressToString;
  tcpAPI.testWouldTry         = &testWouldTry;

  return &tcpAPI;
}

void donetransport_tcp_old() {
  int i;

  if (stats != NULL)
    coreAPI->releaseService(stats);
  stats = NULL;
  for (i=tsessionCount-1;i>=0;i--)
    destroySession(i);
  GROW(tsessions,
       tsessionArrayLength,
       0);
  FREENONNULL(filteredNetworks_);
  MUTEX_DESTROY(tcplock);
}

/* end of tcp.c */
