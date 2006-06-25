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

#include "gnunet_util_network.h"
#include "gnunet_util_os.h"
#include "gnunet_util_config.h"
#include "gnunet_protocols.h"
#include "platform.h"

#define DEBUG_TCPIO NO

/**
 * Struct to refer to a GNUnet TCP connection.
 * This is more than just a socket because if the server
 * drops the connection, the client automatically tries
 * to reconnect (and for that needs connection information).
 */
typedef struct ClientServerConnection {

  /**
   * the socket handle, NULL if not life
   */
  struct SocketHandle * sock;

  struct MUTEX * readlock;
  
  struct MUTEX * writelock;

  struct GE_Context * ectx;

  struct GC_Configuration * cfg;

  /**
   * If this is gnunetd's server socket, then we cannot
   * automatically reconnect after closing the connection
   * (since it is an "accept" that gives the socket).<p>
   *
   * If this is NO, we should query the configuration and
   * automagically try to reconnect.
   */
  int isServerSocket;

} ClientServerConnection;


/**
 * Return the port-number (in host byte order)
 * @return 0 on error
 */
static unsigned short getGNUnetPort(struct GE_Context * ectx,
				    struct GC_Configuration * cfg) {
  unsigned long long port;

  port = 2087;
  if (-1 == GC_get_configuration_value_number(cfg,
					      "NETWORK",
					      "PORT",
					      1,
					      65535,
					      2087,
					      &port)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_BULK,
	   _("Could not find valid value for PORT in section NETWORK."));
    return 0;
  }
  return (unsigned short) port;
}

/**
 * Configuration: get the GNUnetd host where the client
 * should connect to (via TCP)
 *
 * @return the name of the host, NULL on error
 */
static char * getGNUnetdHost(struct GE_Context * ectx,
			     struct GC_Configuration * cfg) {
  char * res;

  res = NULL;
  if (-1 == GC_get_configuration_value_string(cfg,
					      "NETWORK",
					      "HOST",
					      "localhost",
					      &res)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_BULK,
	   _("Could not find valid value for HOST in section NETWORK."));
    return NULL;
  }
  return res;
}

struct ClientServerConnection * 
client_connection_create(struct GE_Context * ectx,
			 struct GC_Configuration * cfg,
			 struct SocketHandle * sock) {
  ClientServerConnection * result;

  result = MALLOC(sizeof(ClientServerConnection));  
  result->sock = sock;
  result->readlock = MUTEX_CREATE(NO);
  result->writelock = MUTEX_CREATE(NO);
  result->ectx = ectx;
  result->cfg = cfg;
  result->isServerSocket = YES;
  return result;
}


/**
 * Get a GNUnet TCP socket that is connected to gnunetd.
 */
struct ClientServerConnection * 
daemon_connection_create(struct GE_Context * ectx,
			 struct GC_Configuration * cfg) {
  ClientServerConnection * result;

  result = MALLOC(sizeof(ClientServerConnection));  
  result->sock = NULL;
  result->readlock = MUTEX_CREATE(NO);
  result->writelock = MUTEX_CREATE(NO);
  result->ectx = ectx;
  result->cfg = cfg;
  result->isServerSocket = NO;
  return result;
}

void connection_close_temporarily(struct ClientServerConnection * sock) {
  if (sock->sock != NULL) {
    socket_destroy(sock->sock);
    sock->sock = NULL;
  }
}

void connection_destroy(struct ClientServerConnection * sock) {
  connection_close_temporarily(sock);
  MUTEX_DESTROY(sock->readlock);
  MUTEX_DESTROY(sock->writelock);
  FREE(sock);
}

int connection_test_open(struct ClientServerConnection * sock) {
  return (sock->sock != NULL);
}

/**
 * Check a socket, open and connect if it is closed and it is a client-socket.
 */
int connection_ensure_connected(struct ClientServerConnection * sock) {
  struct sockaddr_in soaddr;
  fd_set rset;
  fd_set wset;
  fd_set eset;
  struct timeval timeout;
  int ret;
  int osock;
  unsigned short port;
  char * host;
  IPaddr ip;

  if (sock->sock != NULL)
    return OK;
  port = getGNUnetPort(sock->ectx,
		       sock->cfg);
  if (port == 0)
    return SYSERR;
  host = getGNUnetdHost(sock->ectx, 
			sock->cfg);
  if (host == NULL)
    return SYSERR;
  if (SYSERR == get_host_by_name(sock->ectx, 
				 host,
				 &ip)) {
    FREE(host);
    return SYSERR;
  }
  osock = SOCKET(PF_INET, SOCK_STREAM, 6); /* 6: TCP */
  if (osock == -1) {
    GE_LOG_STRERROR(sock->ectx,
		    GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
		    "socket");
    FREE(host);
    return SYSERR;
  }
  sock->sock = socket_create(sock->ectx,
			     NULL,
			     osock);
  socket_set_blocking(sock->sock, NO);
  soaddr.sin_family = AF_INET;
  GE_ASSERT(sock->ectx,
	    sizeof(struct in_addr) == sizeof(IPaddr));
  memcpy(&soaddr.sin_addr,
	 &ip,
	 sizeof(struct in_addr));
  soaddr.sin_port = htons(port);
  ret = CONNECT(osock,
		(struct sockaddr*)&soaddr,
		sizeof(soaddr));
  if ( (ret < 0) &&
       (errno != EINPROGRESS) ) {
    GE_LOG(sock->ectx,
	   GE_WARNING | GE_USER | GE_BULK,
	   _("Cannot connect to %s:u: %s\n"),
	   host,
	   port,
	   STRERROR(errno));
    socket_destroy(sock->sock);
    FREE(host);
    return SYSERR;
  }
  /* we call select() first with a timeout of 5s to
     avoid blocking on a later write indefinitely;
     Important if a local firewall decides to just drop 
     the TCP handshake...*/
  FD_ZERO(&rset);
  FD_ZERO(&wset);
  FD_ZERO(&eset);
  FD_SET(osock, &wset);
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  ret = SELECT(osock + 1, 
	       &rset,
	       &wset,
	       &eset, 
	       &timeout);
  if ( (ret == -1) ||
       (! FD_ISSET(osock,
		   &wset)) ) {
    GE_LOG(sock->ectx,
	   GE_WARNING | GE_USER | GE_BULK,
	   _("Cannot connect to %s:u: %s\n"),
	   host,
	   port,
	   STRERROR(errno));
    socket_destroy(sock->sock);
    FREE(host);
    return SYSERR;
  }
  FREE(host);
  socket_set_blocking(sock->sock, YES);
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
  size_t size;
  size_t sent;
  int res;

  if (SYSERR == connection_ensure_connected(sock))
    return SYSERR;
  size = ntohs(buffer->size);
  MUTEX_LOCK(sock->writelock);
  res = socket_send(sock->sock,
		    NC_Complete,
		    buffer,
		    size,
		    &sent);
  if ( (res != YES) ||
       (sent != size) ) {
    connection_close_temporarily(sock);
    MUTEX_UNLOCK(sock->writelock);
    return SYSERR;
  }
  MUTEX_UNLOCK(sock->writelock);
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
  if ( (OK != socket_recv(sock->sock,
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
  if ( (OK != socket_recv(sock->sock,
			  NC_Complete,
			  &buf[pos],
			  size - pos,
			  &pos)) ||
       (pos != sizeof(unsigned short) + size) ) {
    connection_close_temporarily(sock);
    FREE(buf);
    MUTEX_UNLOCK(sock->readlock);
    return SYSERR;
  }
#if DEBUG_TCPIO
  LOG(LOG_DEBUG,
      "Successfully received %d bytes from TCP socket.\n",
      size);
#endif
  MUTEX_UNLOCK(sock->readlock);
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
    = htons(sizeof(RETURN_VALUE_MESSAGE));
  rv.header.type
    = htons(CS_PROTO_RETURN_VALUE);
  rv.return_value
    = htonl(ret);
  return connection_write(sock,
			  &rv.header);
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
