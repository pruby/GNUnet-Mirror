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

  struct MUTEX * destroylock;

  struct GE_Context * ectx;

  struct GC_Configuration * cfg;

  int dead;

} ClientServerConnection;


/**
 * Return the port-number (in host byte order)
 * @return 0 on error
 */
static unsigned short getGNUnetPort(struct GE_Context * ectx,
				    struct GC_Configuration * cfg) {
  char * res;
  char * pos;
  unsigned int port;

  res = NULL;
  if (-1 == GC_get_configuration_value_string(cfg,
					      "NETWORK",
					      "HOST",
					      "localhost:2087",
					      &res)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_BULK,
	   _("Could not find valid value for HOST in section NETWORK."));
    return 2087;
  }
  pos = strstr(res, ":");
  if (pos == NULL) {
    FREE(res);
    return 2087;
  }
  pos++;
  if (1 != SSCANF(pos, "%u", &port)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_BULK,
	   _("Syntax error in configuration entry HOST in section NETWORK: `%s'"),
	   pos);
    FREE(res);
    return 2087;
  }
  FREE(res);
  return (unsigned short) port;
}

/**
 * Configuration: get the GNUnetd host where the client
 * should connect to (via TCP)
 *
 * @return the name of the host, NULL on error
 */
static char *
getGNUnetdHost(struct GE_Context * ectx,
	       struct GC_Configuration * cfg) {
  char * res;
  char * pos;

  res = NULL;
  if (-1 == GC_get_configuration_value_string(cfg,
					      "NETWORK",
					      "HOST",
					      "localhost:2087",
					      &res)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_BULK,
	   _("Could not find valid value for HOST in section NETWORK."));
    return NULL;
  }
  pos = strstr(res, ":");
  if (pos != NULL)
    *pos = '\0';
  return res;
}

struct ClientServerConnection *
client_connection_create(struct GE_Context * ectx,
			 struct GC_Configuration * cfg) {
  ClientServerConnection * result;

  result = MALLOC(sizeof(ClientServerConnection));
  result->sock = NULL;
  result->readlock = MUTEX_CREATE(NO);
  result->writelock = MUTEX_CREATE(NO);
  result->destroylock = MUTEX_CREATE(YES);
  result->ectx = ectx;
  result->cfg = cfg;
  return result;
}

void connection_close_temporarily(struct ClientServerConnection * sock) {
  GE_ASSERT(NULL, sock != NULL);
  MUTEX_LOCK(sock->destroylock);
  if (sock->sock != NULL) {
    socket_close(sock->sock);
    MUTEX_LOCK(sock->readlock);
    MUTEX_LOCK(sock->writelock);
    socket_destroy(sock->sock);
    sock->sock = NULL;
    MUTEX_UNLOCK(sock->writelock);
    MUTEX_UNLOCK(sock->readlock);
  }
  MUTEX_UNLOCK(sock->destroylock);
}

void connection_close_forever(struct ClientServerConnection * sock) {
  GE_ASSERT(NULL, sock != NULL);
  MUTEX_LOCK(sock->destroylock);
  if (sock->sock != NULL) {
    socket_close(sock->sock);
    MUTEX_LOCK(sock->readlock);
    MUTEX_LOCK(sock->writelock);
    socket_destroy(sock->sock);
    sock->sock = NULL;
    sock->dead = YES;
    MUTEX_UNLOCK(sock->writelock);
    MUTEX_UNLOCK(sock->readlock);
  } else {
    sock->dead = YES;
  }
  MUTEX_UNLOCK(sock->destroylock);
}

void connection_destroy(struct ClientServerConnection * sock) {
  GE_ASSERT(NULL, sock != NULL);
  connection_close_forever(sock);
  MUTEX_DESTROY(sock->readlock);
  MUTEX_DESTROY(sock->writelock);
  MUTEX_DESTROY(sock->destroylock);
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

  GE_ASSERT(NULL, sock != NULL);
  if (sock->sock != NULL)
    return OK;
  if (sock->dead == YES)
    return SYSERR;
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
  MUTEX_LOCK(sock->destroylock);
  if (sock->sock != NULL) {
    FREE(host);
    MUTEX_UNLOCK(sock->destroylock);
    return OK;
  }
  if (sock->dead == YES) {
    FREE(host);
    MUTEX_UNLOCK(sock->destroylock);
    return SYSERR;
  }
  osock = SOCKET(PF_INET, SOCK_STREAM, 6); /* 6: TCP */
  if (osock == -1) {
    GE_LOG_STRERROR(sock->ectx,
		    GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
		    "socket");
    FREE(host);
    MUTEX_UNLOCK(sock->destroylock);
    return SYSERR;
  }
  sock->sock = socket_create(sock->ectx,
			     NULL,
			     osock);
  socket_set_blocking(sock->sock, NO);
  memset(&soaddr,
	 0,
	 sizeof(soaddr));
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
  if ( (ret != 0) &&
       (errno != EINPROGRESS) ) {
    GE_LOG(sock->ectx,
	   GE_WARNING | GE_USER | GE_BULK,
	   _("Cannot connect to %s:%u: %s\n"),
	   host,
	   port,
	   STRERROR(errno));
    socket_destroy(sock->sock);
    sock->sock = NULL;
    FREE(host);
    MUTEX_UNLOCK(sock->destroylock);
    return SYSERR;
  }
  /* we call select() first with a timeout of WAIT_SECONDS to
     avoid blocking on a later write indefinitely;
     Important if a local firewall decides to just drop
     the TCP handshake...*/
  FD_ZERO(&rset);
  FD_ZERO(&wset);
  FD_ZERO(&eset);
  FD_SET(osock, &wset);
  FD_SET(osock, &eset);
#define WAIT_SECONDS 1
  timeout.tv_sec = WAIT_SECONDS;
  timeout.tv_usec = 0;
  errno = 0;
  ret = SELECT(osock + 1,
	       &rset,
	       &wset,
	       &eset,
	       &timeout);
  if (ret == -1) {
    if (errno != EINTR)
      GE_LOG_STRERROR(sock->ectx,
		      GE_WARNING | GE_USER | GE_BULK,
		      "select");
    socket_destroy(sock->sock);
    sock->sock = NULL;
    FREE(host);
    MUTEX_UNLOCK(sock->destroylock);
    return SYSERR;
  }
  if (FD_ISSET(osock,
	       &eset)) {
    GE_LOG(sock->ectx,
	   GE_WARNING | GE_USER | GE_BULK,
	   _("Error connecting to %s:%u\n"),
	   host,
	   port);
    socket_destroy(sock->sock);
    sock->sock = NULL;
    FREE(host);
    MUTEX_UNLOCK(sock->destroylock);
    return SYSERR;
  }
  if (! FD_ISSET(osock,
		 &wset)) {
    GE_LOG(sock->ectx,
	   GE_WARNING | GE_USER | GE_BULK,
	   _("Failed to connect to %s:%u in %ds\n"),
	   host,
	   port,
	   WAIT_SECONDS);
    socket_destroy(sock->sock);
    sock->sock = NULL;
    FREE(host);
    MUTEX_UNLOCK(sock->destroylock);
    return SYSERR;
  }
  FREE(host);
  socket_set_blocking(sock->sock, YES);
  MUTEX_UNLOCK(sock->destroylock);
  return OK;
}

/**
 * Write to a GNUnet TCP socket.  Will also potentially complete the
 * sending of a previous non-blocking connection_write call.
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

  MUTEX_LOCK(sock->destroylock);
  MUTEX_LOCK(sock->writelock);
  if (SYSERR == connection_ensure_connected(sock)) {
    MUTEX_UNLOCK(sock->writelock);
    MUTEX_UNLOCK(sock->destroylock);
    return SYSERR;
  }
  MUTEX_UNLOCK(sock->destroylock);
  GE_ASSERT(NULL, sock->sock != NULL);
  size = ntohs(buffer->size);
  res = socket_send(sock->sock,
		    NC_Complete,
		    buffer,
		    size,
		    &sent);
  if ( (res != YES) ||
       (sent != size) ) {
    MUTEX_UNLOCK(sock->writelock);
    connection_close_temporarily(sock);
    return SYSERR;
  }
  MUTEX_UNLOCK(sock->writelock);
  return OK;
}

int connection_read(struct ClientServerConnection * sock,
		    MESSAGE_HEADER ** buffer) {
  int res;
  size_t pos;
  char * buf;
  unsigned short size;
  RETURN_ERROR_MESSAGE * rem;

  MUTEX_LOCK(sock->destroylock);
  MUTEX_LOCK(sock->readlock);
  if (OK != connection_ensure_connected(sock)) {
    MUTEX_UNLOCK(sock->readlock);
    MUTEX_UNLOCK(sock->destroylock);
    return SYSERR;
  }
  MUTEX_UNLOCK(sock->destroylock);
  GE_ASSERT(NULL, sock->sock != NULL);
  while (1) {
    pos = 0;
    res = 0;
    if ( (OK != socket_recv(sock->sock,
			    NC_Complete,
			    &size,
			    sizeof(unsigned short),
			    &pos)) ||
	 (pos != sizeof(unsigned short)) ) {
      MUTEX_UNLOCK(sock->readlock);
      connection_close_temporarily(sock);
      return SYSERR;
    }
    size = ntohs(size);
    if (size < sizeof(MESSAGE_HEADER)) {
      GE_BREAK(sock->ectx, 0);
      MUTEX_UNLOCK(sock->readlock);
      connection_close_temporarily(sock);
      return SYSERR; /* invalid header */
    }

    buf = MALLOC(size);
    if ( (OK != socket_recv(sock->sock,
			    NC_Complete,
			    &buf[pos],
			    size - pos,
			    &pos)) ||
	 (pos + sizeof(unsigned short) != size) ) {
      FREE(buf);
      MUTEX_UNLOCK(sock->readlock);
      connection_close_temporarily(sock);
      return SYSERR;
    }
#if DEBUG_TCPIO
    GE_LOG(sock->ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Successfully received %d bytes from TCP socket.\n",
	   size);
#endif
    *buffer = (MESSAGE_HEADER*) buf;
    (*buffer)->size = htons(size);

    if (ntohs((*buffer)->type) != CS_PROTO_RETURN_ERROR)
      break; /* got actual message! */
    rem = (RETURN_ERROR_MESSAGE*) *buffer;
    if (ntohs(rem->header.size) < sizeof(RETURN_ERROR_MESSAGE)) {
      GE_BREAK(sock->ectx, 0);
      MUTEX_UNLOCK(sock->readlock);
      connection_close_temporarily(sock);
      FREE(buf);
      return SYSERR;
    }
    size = ntohs(rem->header.size) - sizeof(RETURN_ERROR_MESSAGE);
    GE_LOG(sock->ectx,
	   ntohl(rem->kind),
	   "%.*s",
	   (int) size,
	   &rem[1]);
    FREE(rem);
  } /* while (1) */
  MUTEX_UNLOCK(sock->readlock);
  return OK; /* success */
}

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

/*  end of tcpio.c */
