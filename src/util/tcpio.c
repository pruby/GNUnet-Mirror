/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @file util/tcpio.c
 * @brief code for synchronized access to TCP streams
 * @author Christian Grothoff
 *
 * Generic TCP code for reliable, mostly blocking, record-oriented TCP
 * connections. GNUnet uses the "tcpio" code for trusted client-server
 * (e.g. gnunet-gtk to gnunetd via loopback) communications.  Note
 * that an unblocking write is also provided since if both client and
 * server use blocking IO, both may block on a write and cause a
 * mutual inter-process deadlock.
 *
 * Since we do not want other peers (!) to be able to block a peer by
 * not reading from the TCP stream, the peer-to-peer TCP transport
 * uses unreliable, buffered, non-blocking, record-oriented TCP code
 * with a select call to reduce the number of threads which is
 * provided in transports/tcp.c.
 */

#include "gnunet_util.h"
#include "platform.h"

#define DEBUG_TCPIO 0

/**
 * Initialize a GNUnet client socket.
 * @param port the portnumber in host byte order
 * @param ip IP of the host to connect to, in network byte order
 * @param result the SOCKET (filled in)
 * @return OK if successful, SYSERR on failure
 */
int initGNUnetClientSocketIP(unsigned short port,
			     IPaddr ip,
			     GNUNET_TCP_SOCKET * result) {
  result->ip = ip;
  result->port = port;
  result->socket = -1; /* closed */
  result->outBufLen = 0;
  result->outBufPending = NULL;
  MUTEX_CREATE(&result->readlock);
  MUTEX_CREATE(&result->writelock);
  return OK;
}

/**
 * Initialize a GNUnet client socket.
 * @param port the portnumber in host byte order
 * @param hostname the name of the host to connect to
 * @param result the SOCKET (filled in)
 * @return OK if successful, SYSERR on failure
 */
int initGNUnetClientSocket(unsigned short port,
			   const char * hostname,
			   GNUNET_TCP_SOCKET * result) {
  struct hostent * he;

#if DEBUG_TCPIO
  LOG(LOG_DEBUG,
      "Connecting to host '%s:%d'.\n",
      hostname,
      port);
#endif
  he = GETHOSTBYNAME(hostname); 
  if (he == NULL) {
    LOG(LOG_ERROR,
	_("Could not find IP of host '%s': %s\n"),
	hostname,
	hstrerror(h_errno));
    return SYSERR;
  }  
  result->ip.addr = (unsigned int) ((struct in_addr*)he->h_addr)->s_addr;
  result->port = port;
  result->socket = -1; /* closed */
  result->outBufLen = 0;
  result->outBufPending = NULL;
  MUTEX_CREATE(&result->readlock);
  MUTEX_CREATE(&result->writelock);
  return OK;
}

/**
 * Initialize a GNUnet server socket.
 * @param sock the open socket
 * @param result the SOCKET (filled in)
 * @return OK (always successful)
 */
int initGNUnetServerSocket(int sock,
			   GNUNET_TCP_SOCKET * result) {
  result->ip.addr = 0;
  result->port = 0;
  result->socket = sock;
  result->outBufLen = 0;
  result->outBufPending = NULL;
  MUTEX_CREATE(&result->readlock);
  MUTEX_CREATE(&result->writelock);
  return OK;
}

/**
 * Check if a socket is open. Will ALWAYS return 'true'
 * for a valid client socket (even if the connection is
 * closed), but will return false for a closed server socket.
 * @return 1 if open, 0 if closed
 */
int isOpenConnection(GNUNET_TCP_SOCKET * sock) {
  return (sock->socket != -1); 
}

/**
 * Check a socket, open and connect if it is closed and it is a client-socket.
 */
int checkSocket(GNUNET_TCP_SOCKET * sock) {
  int res;
  struct sockaddr_in soaddr;
  fd_set rset;
  fd_set wset;
  fd_set eset;
  struct timeval timeout;
  int ret;
  int wasSockBlocking;

  if (sock->socket != -1)
    return OK;
  sock->socket = SOCKET(PF_INET, SOCK_STREAM, 6); /* 6: TCP */
  if (sock->socket == -1) {
    LOG_STRERROR(LOG_FAILURE, "socket");
    return SYSERR;
  }

  wasSockBlocking = isSocketBlocking(sock->socket);
	setBlocking(sock->socket, NO);
	     
  soaddr.sin_family = AF_INET;
  GNUNET_ASSERT(sizeof(struct in_addr) == sizeof(sock->ip.addr));
  memcpy(&soaddr.sin_addr,
	 &sock->ip.addr,
	 sizeof(struct in_addr));
  soaddr.sin_port = htons(sock->port);
  res = CONNECT(sock->socket, 
		(struct sockaddr*)&soaddr,
		sizeof(soaddr));
  if ( (res < 0) &&
       (errno != EINPROGRESS) ) {
    LOG(LOG_INFO,
	_("Cannot connect to %u.%u.%u.%u:%u: %s\n"),
	PRIP(ntohl(*(int*)&sock->ip.addr)),
	sock->port,
	STRERROR(errno));
    CLOSE(sock->socket);
    sock->socket = -1;
    return SYSERR;
  }

  /* we call select() first with a timeout of 5s to
     avoid blocking on a later write indefinitely;
     this is mostly needed for gnunet-testbed to keep
     working if an advertised testbed-client is behind
     a firewall and unreachable.  But it is also nice
     if a local firewall decides to just drop the TCP
     handshake...*/
  FD_ZERO(&rset);
  FD_ZERO(&wset);
  FD_ZERO(&eset);
  FD_SET(sock->socket, &wset);
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  ret = SELECT(sock->socket+1, &rset, &wset, &eset, &timeout);
  if ( (ret == -1) ||
       (! FD_ISSET(sock->socket,
		   &wset)) ) {
    LOG(LOG_INFO,
	_("Cannot connect to %u.%u.%u.%u:%u: %s\n"),
	PRIP(ntohl(*(int*)&sock->ip.addr)),
	sock->port,
	STRERROR(errno));
    return SYSERR;
  }
  setBlocking(sock->socket, wasSockBlocking);

  return OK;
}

/**
 * Write to a GNUnet TCP socket.  Will also potentially complete the
 * sending of a previous non-blocking writeToSocket call.
 *
 * @param sock the socket to write to
 * @param buffer the buffer to write
 * @return OK if the write was sucessful, otherwise SYSERR.
 */
int writeToSocket(GNUNET_TCP_SOCKET * sock,
		  const CS_HEADER * buffer) {
  int res;
  int size;

  if (SYSERR == checkSocket(sock))
    return SYSERR;
  size = ntohs(buffer->size);
  MUTEX_LOCK(&sock->writelock);

  /* write pending data from prior non-blocking call
     -- but this time use blocking IO! */
  if (sock->outBufLen > 0) {
    res = SEND_BLOCKING_ALL(sock->socket,
			    sock->outBufPending,
			    sock->outBufLen);
    if (res < 0) {
      if (errno == EAGAIN) {
	MUTEX_UNLOCK(&sock->writelock);
	return SYSERR; /* can not send right now;
			  but do NOT close socket in this case! */
      }      
      LOG_STRERROR(LOG_INFO, "send");
      closeSocketTemporarily(sock);
      MUTEX_UNLOCK(&sock->writelock);
      return SYSERR;
    }
    FREE(sock->outBufPending);
    sock->outBufPending = NULL;
    sock->outBufLen = 0;
  }

  res = SEND_BLOCKING_ALL(sock->socket,
			  buffer,
			  size);
  if (res < 0) {
    if (errno == EAGAIN) {
      MUTEX_UNLOCK(&sock->writelock);
      return SYSERR; /* would block, can not send right now;
			but do NOT close socket in this case! */
    }
    LOG_STRERROR(LOG_INFO, "send");
    closeSocketTemporarily(sock);
    MUTEX_UNLOCK(&sock->writelock);
    return SYSERR;
  }
  MUTEX_UNLOCK(&sock->writelock);
  return OK;
}


/**
 * Write to a GNUnet TCP socket non-blocking.  Note that it is
 * possible that only a part of the message is send and that tcpio
 * buffers the rest until the next writeToSocket operation.  If that
 * buffer is full or if send did not transmit any byte of the message,
 * NO is returned to indicate that the write failed (would have
 * blocked).
 *
 * @param sock the socket to write to
 * @param buffer the buffer to write
 * @return OK if the write was sucessful, NO if it would have blocked and was not performed,
 *         otherwise SYSERR.
 */
int writeToSocketNonBlocking(GNUNET_TCP_SOCKET * sock,
			     const CS_HEADER * buffer) {
  int res;
  int size;
  
  if (SYSERR == checkSocket(sock))
    return SYSERR;
  MUTEX_LOCK(&sock->writelock);
  if (sock->outBufLen > 0) {
    SEND_NONBLOCKING(sock->socket,
	             sock->outBufPending,
		     sock->outBufLen,
		     &res);
    if (res < 0) {
      if ( (errno == EWOULDBLOCK) ||
	   (errno == EAGAIN) ) {
	MUTEX_UNLOCK(&sock->writelock);
	return NO; 
      }
      LOG_STRERROR(LOG_INFO, "write");
      closeSocketTemporarily(sock);
      MUTEX_UNLOCK(&sock->writelock);
      return SYSERR;
    }
    if ((unsigned int)res < sock->outBufLen) {
      memcpy(sock->outBufPending,
	     &((char*)sock->outBufPending)[res],
	     sock->outBufLen - res);
      sock->outBufLen -= res;
      MUTEX_UNLOCK(&sock->writelock);
      return SYSERR;      
    }
    /* completely send out deferred buffer, so
       we can in fact continue! */
    FREENONNULL(sock->outBufPending);
    sock->outBufPending = NULL;
    sock->outBufLen = 0;
  }

  size = ntohs(buffer->size);

  SEND_NONBLOCKING(sock->socket,
		   (char*)buffer,
		    size,
		    &res);
  if (res < 0) {
    if ( (errno == EWOULDBLOCK) ||
	 (errno == EAGAIN) ) {
      MUTEX_UNLOCK(&sock->writelock);
      return NO; /* would block, can not send right now;
		    but do NOT close socket in this case;
		    do not use SYSERR as return value
		    since this is not an error! */
    }
    LOG_STRERROR(LOG_INFO, "send");
    closeSocketTemporarily(sock);
    MUTEX_UNLOCK(&sock->writelock);
    return SYSERR;
  }
  if (res != size) {
    sock->outBufPending = MALLOC(size - res);
    memcpy(sock->outBufPending,
	   &((char*)buffer)[res],
	   size - res);
    sock->outBufLen = size - res;
    MUTEX_UNLOCK(&sock->writelock);
    return OK; /* return OK here means that the message will be transmitted,
		  though it may be a bit later (on the next call, in fact). */
  }
  MUTEX_UNLOCK(&sock->writelock);
  return OK;
}

/**
 * Read from a GNUnet TCP socket.
 * @param sock the socket
 * @param buffer the buffer to write data to
 * @return OK if the read was successful, SYSERR if the socket
 *         was closed by the other side (if the socket is a
 *         client socket and is used again, tcpio will attempt
 *         to re-establish the connection [temporary error]).
 */
int readFromSocket(GNUNET_TCP_SOCKET * sock,
		   CS_HEADER ** buffer) {
  int res;
  unsigned int pos;
  char * buf;
  unsigned short size;

  if (SYSERR == checkSocket(sock))
    return SYSERR;
   
  MUTEX_LOCK(&sock->readlock);
  pos = 0;
  res = 0;

  pos = RECV_BLOCKING_ALL(sock->socket,
			  &size,
			  sizeof(unsigned short));
  if (pos != sizeof(unsigned short)) {
#if DEBUG_TCPIO    
    LOG_STRERROR(LOG_INFO, "recv");
#endif
    closeSocketTemporarily(sock);
    MUTEX_UNLOCK(&sock->readlock);
    return SYSERR; /* other side closed socket or invalid header */
  }
  size = ntohs(size);
  if (size < sizeof(CS_HEADER)) {
#if DEBUG_TCPIO    
    LOG_STRERROR(LOG_INFO, "recv");
#endif
    closeSocketTemporarily(sock);
    MUTEX_UNLOCK(&sock->readlock);
    return SYSERR; /* invalid header */
  } 

  buf = (char*) *buffer;
  if (buf == NULL) 
    buf = MALLOC(size);

  res = RECV_BLOCKING_ALL(sock->socket,
			  &buf[pos],
			  size - pos);

  if (res != (int)(size - pos)) {  /* error, abort */
    LOG_STRERROR(LOG_INFO, "recv");
    closeSocketTemporarily(sock);
    if (*buffer == NULL)
      FREE(buf);
    MUTEX_UNLOCK(&sock->readlock);
    return SYSERR;
  }    
#if DEBUG_TCPIO
  LOG(LOG_DEBUG,
      "Successfully received %d bytes from TCP socket.\n",
      size);
#endif
  MUTEX_UNLOCK(&sock->readlock);
  *buffer = (CS_HEADER*) buf;
  (*buffer)->size = htons(size);
  return OK; /* success */
}

/**
 * Close a GNUnet TCP socket for now (use to temporarily close
 * a TCP connection that will probably not be used for a long
 * time; the socket will still be auto-reopened by the
 * readFromSocket/writeToSocket methods if it is a client-socket).
 */
void closeSocketTemporarily(GNUNET_TCP_SOCKET * sock) {
  if (sock == NULL)
    return;
  if (sock->socket != -1) {
    int i;

    i = sock->socket;
#if DEBUG_TCPIO
    LOG(LOG_DEBUG,
	"TCP: closing socket %d.\n",
	sock->socket);
#endif
    sock->socket = -1;
    if (0 != SHUTDOWN(i, SHUT_RDWR)) 
      LOG_STRERROR(LOG_DEBUG, "shutdown");
    CLOSE(i);
  }
  sock->outBufLen = 0;
  FREENONNULL(sock->outBufPending);
  sock->outBufPending = NULL;  
}

/**
 * Destroy a socket for good. If you use this socket afterwards,
 * you must first invoke initializeSocket, otherwise the operation
 * will fail.
 */
void destroySocket(GNUNET_TCP_SOCKET * sock) {
  closeSocketTemporarily(sock);
  sock->ip.addr = 0;
  sock->port = 0;
  sock->outBufLen = 0;
  FREENONNULL(sock->outBufPending);
  sock->outBufPending = NULL;
  MUTEX_DESTROY(&sock->readlock);
  MUTEX_DESTROY(&sock->writelock);
}


/*  end of tcpio.c */
