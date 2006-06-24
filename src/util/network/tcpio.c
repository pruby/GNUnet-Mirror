/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/network/tcpio.c
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

#define DEBUG_TCPIO NO

/**
 * Struct to refer to a GNUnet TCP connection.
 * This is more than just a socket because if the server
 * drops the connection, the client automatically tries
 * to reconnect (and for that needs connection information).
 */
typedef struct GNUNET_TCP_SOCKET {

  /**
   * the socket handle, -1 if invalid / not life
   */
  struct SocketHandle * socket;

  /**
   * the following is the IP for the remote host for client-sockets,
   * as returned by gethostbyname("hostname"); server sockets should
   * use 0.
   */
  IPaddr ip;

  /**
   * the port number, in host byte order
   */
  unsigned short port;

  /**
   * Write buffer length for non-blocking writes.
   */
  unsigned int outBufLen;

  /**
   * Write buffer for non-blocking writes.
   */
  void * outBufPending;

  struct Mutex * readlock;

  struct Mutex * writelock;

  struct CE_Context * ectx;

} GNUNET_TCP_SOCKET;


/**
 * Return the port-number (in host byte order)
 */
static unsigned short getGNUnetPort() {
  // TODO!
  static unsigned short port;
  const char *setting;

  if (port != 0)
    return port;
  if (testConfigurationString("GNUNETD",
			      "_MAGIC_",
			      "YES"))
    setting = "PORT";
  else
    setting = "CLIENT-PORT";

  port = (unsigned short) getConfigurationInt("NETWORK",
					      setting);
  if (port == 0) {
    errexit(_("Cannot determine port of gnunetd server. "
	      "Define in configuration file in section `%s' under `%s'.\n"),
	    "NETWORK",
	    setting);
  }
  return port;
}

/**
 * Configuration: get the GNUnetd host where the client
 * should connect to (via TCP)
 * @return the name of the host
 */
static const char * getGNUnetdHost() {
  // TODO!
  static char * res;

  if (res != NULL)
    return res;
  res = getConfigurationString("NETWORK",
			       "HOST");
  if (res == NULL)
    res = "localhost";
  return res;
}

/**
 * Initialize a GNUnet server socket.
 * @param sock the open socket
 * @param result the SOCKET (filled in)
 * @return OK (always successful)
 */
struct ClientServerConnection * 
client_connection_create(struct GE_Context * ectx,
			 struct GC_Configuration * cfg,
			 struct SocketHandle * sock) {
  // TODO!
  result->ip.addr = 0;
  result->port = 0;
  result->socket = sock;
  result->outBufLen = 0;
  result->outBufPending = NULL;
  MUTEX_CREATE(&result->readlock);
  MUTEX_CREATE(&result->writelock);
  return result;
}


/**
 * Get a GNUnet TCP socket that is connected to gnunetd.
 */
struct ClientServerConnection * 
daemon_connection_create(struct GE_Context * ectx,
			 struct GC_Configuration * cfg) {
  // TODO!
  struct ClientServerConnection * sock;
  const char * host;

  result->ip = ip;
  result->port = port;
  result->socket = -1; /* closed */
  result->outBufLen = 0;
  result->outBufPending = NULL;
  MUTEX_CREATE(&result->readlock);
  MUTEX_CREATE(&result->writelock);

  if (OK != GN_getHostByName(hostname,
			     &result->ip)) 
    return SYSERR;

  sock = MALLOC(sizeof(struct ClientServerConnection));
  host = getGNUnetdHost();
  if (SYSERR == initGNUnetClientSocket(getGNUnetPort(),
				       host,
				       sock)) {
    LOG(LOG_ERROR,
	_("Could not connect to gnunetd.\n"));
    FREE(sock);
    return NULL;
  }
  return sock;
}

void connection_close_temporarily(struct ClientServerConnection * sock) {
  // TODO!
  int i;
  GE_ASSERT(NULL, sock != NULL);
  if (sock->socket != -1) {
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

void connection_destroy(struct ClientServerConnection * sock) {
  connection_close_temporarily(sock);
  sock->ip.addr = 0;
  sock->port = 0;
  sock->outBufLen = 0;
  FREENONNULL(sock->outBufPending);
  sock->outBufPending = NULL;
  MUTEX_DESTROY(sock->readlock);
  MUTEX_DESTROY(sock->writelock);
  FREE(sock);
}

int connection_test_open(struct ClientServerConnection * sock) {
  return (sock->socket != -1);
}

/**
 * Check a socket, open and connect if it is closed and it is a client-socket.
 */
int connection_ensure_connected(struct ClientServerConnection * sock) {
  // TODO!
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
    closefile(sock->socket);
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
  if (sock->socket < 0)
    return SYSERR;
  FD_SET(sock->socket, &wset);
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  ret = SELECT(sock->socket+1, &rset, &wset, &eset, &timeout);
  if ( (ret == -1) ||
       (sock->socket == -1) ||
       (! FD_ISSET(sock->socket,
		   &wset)) ) {
    LOG(LOG_INFO,
	_("Cannot connect to %u.%u.%u.%u:%u: %s\n"),
	PRIP(ntohl(*(int*)&sock->ip.addr)),
	sock->port,
	STRERROR(errno));
    setBlocking(sock->socket, wasSockBlocking);
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
int connection_write(struct ClientServerConnection * sock,
		     const MESSAGE_HEADER * buffer) {
  // TODO!
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

int connection_read(struct ClientServerConnection * sock,
		    MESSAGE_HEADER ** buffer) {
  int res;
  unsigned int pos;
  char * buf;
  unsigned short size;

  if (OK != connection_ensure_connected(sock))
    return SYSERR;
  
  MUTEX_LOCK(sock->readlock);
  pos = 0;
  res = 0;
  if ( (OK != socket_recv(sock->handle,
			  NC_Complete,
			  &size,
			  sizeof(unsigned short),
			  &pos)) ||
       (pos != sizeof(unsigned short)) ) {
    connection_close_temporarily(sock);
    MUTEX_UNLOCK(sock->readlock);
    return SYSERR;
  }
  size = ntohs(size);
  if (size < sizeof(MESSAGE_HEADER)) {
    connection_close_temporarily(sock);
    MUTEX_UNLOCK(sock->readlock);
    return SYSERR; /* invalid header */
  }

  buf = MALLOC(size);
  if ( (OK != socket_recv(sock->handle,
			  NC_Complete,
			  &buf[pos],
			  size - pos,
			  &pos)) ||
       (pos != sizeof(unsigned short) + size) ) {
    connection_close_temporarily(sock);
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
  *buffer = (MESSAGE_HEADER*) buf;
  (*buffer)->size = htons(size);
  return OK; /* success */
}



/**
 * CS communication: simple return value
 */
typedef struct {

  /**
   * The CS header (values: sizeof(CS_returnvalue_MESSAGE) + error-size, CS_PROTO_RETURN_VALUE)
   */
  MESSAGE_HEADER header;

  /**
   * The return value (network byte order)
   */
  int return_value;

} RETURN_VALUE_MESSAGE;

/**
 * Obtain a return value from a remote call from TCP.
 *
 * @param sock the TCP socket
 * @param ret the return value from TCP
 * @return SYSERR on error, OK if the return value was read
 * successfully
 */
int connection_read_result(struct ClientServerConnection * sock,
			   int * ret) {
  RETURN_VALUE_MESSAGE * rv;

  rv = NULL;
  if (SYSERR == connection_read(sock,
				(MESSAGE_HEADER **) &rv)) 
    return SYSERR;
  if ( (ntohs(rv->header.size) != sizeof(RETURN_VALUE_MESSAGE)) ||
       (ntohs(rv->header.type) != CS_PROTO_RETURN_VALUE) ) {
    GE_LOG(sock->ectx,
	   GE_WARNING | GE_DEVELOPER | GE_BULK,
	   _("`%s' failed, reply invalid!\n"),
	   __FUNCTION__);
    FREE(rv);
    return SYSERR;
  }
  *ret = ntohl(rv->return_value);
  FREE(rv);
  return OK;
}

/**
 * Send a return value to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return SYSERR on error, OK if the return value was
 *         send successfully
 */
int connection_write_result(struct ClientServerConnection * sock,
			    int ret) {
  RETURN_VALUE_MESSAGE rv;

  rv.header.size
    = htons(sizeof(CS_returnvalue_MESSAGE));
  rv.header.type
    = htons(CS_PROTO_RETURN_VALUE);
  rv.return_value
    = htonl(ret);
  return connection_write(sock,
			  &rv.header,
			  YES);
}

/**
 * Send a return value that indicates
 * a serious error to the other side.
 *
 * @param sock the TCP socket
 * @param mask GE_MASK 
 * @param date date string
 * @param msg message string
 * @return SYSERR on error, OK if the error code was send
 *         successfully
 */
int connection_write_error(struct ClientServerConnection * sock,
			   GE_KIND mask,
			   const char * date,
			   const char * msg) {
  return SYSERR; /* not implemented! */
}




/*  end of tcpio.c */
