/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006, 2008 Christian Grothoff (and other contributing authors)

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

#define DEBUG_TCPIO GNUNET_NO

/**
 * Struct to refer to a GNUnet TCP connection.
 * This is more than just a socket because if the server
 * drops the connection, the client automatically tries
 * to reconnect (and for that needs connection information).
 */
typedef struct GNUNET_ClientServerConnection
{

  /**
   * the socket handle, NULL if not live
   */
  struct GNUNET_SocketHandle *sock;

  struct GNUNET_Mutex *readlock;

  struct GNUNET_Mutex *writelock;

  struct GNUNET_Mutex *destroylock;

  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  int dead;

} ClientServerConnection;


/**
 * Return the port-number (in host byte order)
 * @return 0 on error
 */
static unsigned short
getGNUnetPort (struct GNUNET_GE_Context *ectx,
               struct GNUNET_GC_Configuration *cfg)
{
  char *res;
  char *pos;
  unsigned int port;

  res = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_string (cfg,
                                                      "NETWORK",
                                                      "HOST",
                                                      "localhost:2087", &res))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("Could not find valid value for HOST in section NETWORK."));
      return 2087;
    }
  pos = strstr (res, ":");
  if (pos == NULL)
    {
      GNUNET_free (res);
      return 2087;
    }
  pos++;
  if (1 != SSCANF (pos, "%u", &port))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("Syntax error in configuration entry HOST in section NETWORK: `%s'"),
                     pos);
      GNUNET_free (res);
      return 2087;
    }
  GNUNET_free (res);
  return (unsigned short) port;
}

/**
 * Configuration: get the GNUnetd host where the client
 * should connect to (via TCP)
 *
 * @return the name of the host, NULL on error
 */
static char *
getGNUnetdHost (struct GNUNET_GE_Context *ectx,
                struct GNUNET_GC_Configuration *cfg)
{
  char *res;
  char *pos;

  res = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_string (cfg,
                                                      "NETWORK",
                                                      "HOST",
                                                      "localhost:2087", &res))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("Could not find valid value for HOST in section NETWORK."));
      return NULL;
    }
  pos = strstr (res, ":");
  if (pos != NULL)
    *pos = '\0';
  return res;
}

struct GNUNET_ClientServerConnection *
GNUNET_client_connection_create (struct GNUNET_GE_Context *ectx,
                                 struct GNUNET_GC_Configuration *cfg)
{
  ClientServerConnection *result;

  result = GNUNET_malloc (sizeof (ClientServerConnection));
  result->sock = NULL;
  result->readlock = GNUNET_mutex_create (GNUNET_NO);
  result->writelock = GNUNET_mutex_create (GNUNET_NO);
  result->destroylock = GNUNET_mutex_create (GNUNET_YES);
  result->ectx = ectx;
  result->cfg = cfg;
  return result;
}

void
GNUNET_client_connection_close_temporarily (struct
                                            GNUNET_ClientServerConnection
                                            *sock)
{
  GNUNET_GE_ASSERT (NULL, sock != NULL);
  GNUNET_mutex_lock (sock->destroylock);
  if (sock->sock != NULL)
    {
      GNUNET_socket_close (sock->sock);
      GNUNET_mutex_lock (sock->readlock);
      GNUNET_mutex_lock (sock->writelock);
      GNUNET_socket_destroy (sock->sock);
      sock->sock = NULL;
      GNUNET_mutex_unlock (sock->writelock);
      GNUNET_mutex_unlock (sock->readlock);
    }
  GNUNET_mutex_unlock (sock->destroylock);
}

void
GNUNET_client_connection_close_forever (struct GNUNET_ClientServerConnection
                                        *sock)
{
  GNUNET_GE_ASSERT (NULL, sock != NULL);
  GNUNET_mutex_lock (sock->destroylock);
  if (sock->sock != NULL)
    {
      GNUNET_socket_close (sock->sock);
      GNUNET_mutex_lock (sock->readlock);
      GNUNET_mutex_lock (sock->writelock);
      GNUNET_socket_destroy (sock->sock);
      sock->sock = NULL;
      sock->dead = GNUNET_YES;
      GNUNET_mutex_unlock (sock->writelock);
      GNUNET_mutex_unlock (sock->readlock);
    }
  else
    {
      sock->dead = GNUNET_YES;
    }
  GNUNET_mutex_unlock (sock->destroylock);
}

void
GNUNET_client_connection_destroy (struct GNUNET_ClientServerConnection *sock)
{
  GNUNET_GE_ASSERT (NULL, sock != NULL);
  GNUNET_client_connection_close_forever (sock);
  GNUNET_mutex_destroy (sock->readlock);
  GNUNET_mutex_destroy (sock->writelock);
  GNUNET_mutex_destroy (sock->destroylock);
  GNUNET_free (sock);
}

int
GNUNET_client_connection_test_connected (struct GNUNET_ClientServerConnection
                                         *sock)
{
  return (sock->sock != NULL);
}

/**
 * Check a socket, open and connect if it is closed.  This code
 * supports IPv4 and IPv6 (and may try both).  It also waits a bounded
 * amount of time for the connection to succeed and may even retry the
 * same IP version a few times since gnunetd may just be starting or
 * out of sockets; hence this code could fail on first attempt, will
 * then wait a few milliseconds, retry and conceivably succeed.  Since
 * this is then done for multiple address families, the whole thing is
 * slightly more complicated then your ordinary connect call.  Not to
 * mention that the code also supports another thread coming in in the
 * middle and closing the socket for good -- or even opening it!
 */
int
GNUNET_client_connection_ensure_connected (struct
                                           GNUNET_ClientServerConnection
                                           *sock)
{
  /* list of address families to try for connecting,
     in order of preference */
  static int addr_families[] = {
#ifdef AF_UNSPEC
    AF_UNSPEC,
#endif
#ifdef AF_INET6
    AF_INET6,
#endif
    AF_INET,
    -1
  };
  GNUNET_CronTime select_start;
  struct sockaddr *soaddr;
  socklen_t socklen;
  fd_set rset;
  fd_set wset;
  fd_set eset;
  struct timeval timeout;
  int ret;
  int osock;
  unsigned short port;
  char *host;
  int af_index;
  int soerr;
  socklen_t soerrlen;
  int tries;

  GNUNET_GE_ASSERT (NULL, sock != NULL);
  if (sock->sock != NULL)
    return GNUNET_OK;
  if (sock->dead == GNUNET_YES)
    return GNUNET_SYSERR;
  port = getGNUnetPort (sock->ectx, sock->cfg);
  if (port == 0)
    return GNUNET_SYSERR;
  host = getGNUnetdHost (sock->ectx, sock->cfg);
  if (host == NULL)
    return GNUNET_SYSERR;
  af_index = 0;
  /* we immediately advance if there is a DNS lookup error
   * (which would likely persist) or a socket API error
   * (which would equally likely persist).  We retry a
   * few times with a small delay if we may just be having
   * a connection issue.
   */
#define TRIES_PER_AF 2
#ifdef WINDOWS
  #define DELAY_PER_RETRY (5000 * GNUNET_CRON_MILLISECONDS)
#else
  #define DELAY_PER_RETRY (50 * GNUNET_CRON_MILLISECONDS)
#endif
#define ADVANCE() do { af_index++; tries = TRIES_PER_AF; } while(0)
#define RETRY() do { tries--; if (tries == 0) { ADVANCE(); } else { GNUNET_thread_sleep(DELAY_PER_RETRY); } } while (0)
  tries = TRIES_PER_AF;
  /* loop over all possible address families */
  while (1)
    {
      if (addr_families[af_index] == -1)
        {
          GNUNET_GE_LOG (sock->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Error connecting to %s:%u. Is the daemon running?\n"), host, port);
          return GNUNET_SYSERR;
        }
      soaddr = NULL;
      socklen = 0;
      if (GNUNET_SYSERR ==
          GNUNET_get_ip_from_hostname (sock->ectx, host,
                                       addr_families[af_index], &soaddr,
                                       &socklen))
        {
          ADVANCE ();
          continue;
        }
      GNUNET_mutex_lock (sock->destroylock);
      if (sock->sock != NULL)
        {
          GNUNET_free (host);
          GNUNET_mutex_unlock (sock->destroylock);
          GNUNET_free (soaddr);
          return GNUNET_OK;
        }
      if (sock->dead == GNUNET_YES)
        {
          GNUNET_free (host);
          GNUNET_mutex_unlock (sock->destroylock);
          GNUNET_free (soaddr);
          return GNUNET_SYSERR;
        }
      if (soaddr->sa_family == AF_INET)
        {
          ((struct sockaddr_in *) soaddr)->sin_port = htons (port);
          osock = SOCKET (PF_INET, SOCK_STREAM, 0);
        }
      else
        {
#ifdef PF_INET6
          ((struct sockaddr_in6 *) soaddr)->sin6_port = htons (port);
          osock = SOCKET (PF_INET6, SOCK_STREAM, 0);
#else
          osock = -1;
          errno = EAFNOSUPPORT;
#endif
        }
      if (osock == -1)
        {
          GNUNET_GE_LOG_STRERROR (sock->ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_USER |
                                  GNUNET_GE_ADMIN | GNUNET_GE_BULK, "socket");
          GNUNET_mutex_unlock (sock->destroylock);
          GNUNET_free (soaddr);
          ADVANCE ();
          continue;
        }
      sock->sock = GNUNET_socket_create (sock->ectx, NULL, osock);
      GNUNET_socket_set_blocking (sock->sock, GNUNET_NO);
      ret = CONNECT (osock, soaddr, socklen);
      GNUNET_free (soaddr);
      if ((ret != 0) && (errno != EINPROGRESS) && (errno != EWOULDBLOCK))
        {
          GNUNET_GE_LOG (sock->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Cannot connect to %s:%u: %s\n"),
                         host, port, STRERROR (errno));
          GNUNET_socket_destroy (sock->sock);
          sock->sock = NULL;
          GNUNET_mutex_unlock (sock->destroylock);
          if (errno == ECONNREFUSED)
            RETRY ();           /* gnunetd may just be restarting */
          else
            ADVANCE ();
          continue;
        }
      /* we call select() first with a timeout of WAIT_SECONDS to
         avoid blocking on a later write indefinitely;
         Important if a local firewall decides to just drop
         the TCP handshake... */
      FD_ZERO (&rset);
      FD_ZERO (&wset);
      FD_ZERO (&eset);
      FD_SET (osock, &wset);
      FD_SET (osock, &eset);
      timeout.tv_sec = 0;
      timeout.tv_usec = DELAY_PER_RETRY * TRIES_PER_AF * 1000;
      errno = 0;
      select_start = GNUNET_get_time ();
      ret = SELECT (osock + 1, &rset, &wset, &eset, &timeout);
      if (ret == -1)
        {
          if (errno != EINTR)
            GNUNET_GE_LOG_STRERROR (sock->ectx,
                                    GNUNET_GE_WARNING | GNUNET_GE_USER |
                                    GNUNET_GE_BULK, "select");
          GNUNET_socket_destroy (sock->sock);
          sock->sock = NULL;
          GNUNET_mutex_unlock (sock->destroylock);
          if ((GNUNET_get_time () - select_start >
               TRIES_PER_AF * DELAY_PER_RETRY) || (errno != EINTR))
            ADVANCE ();         /* spend enough time trying here */
          else
            RETRY ();
          continue;
        }
      if ((FD_ISSET (osock, &eset)) || (!FD_ISSET (osock, &wset)))
        {
          GNUNET_socket_destroy (sock->sock);
          sock->sock = NULL;
          GNUNET_mutex_unlock (sock->destroylock);
          if (GNUNET_get_time () - select_start >
              TRIES_PER_AF * DELAY_PER_RETRY)
            ADVANCE ();         /* spend enough time trying here */
          else
            RETRY ();
          continue;
        }
      soerr = 0;
      soerrlen = sizeof (soerr);

      ret = GETSOCKOPT (osock, SOL_SOCKET, SO_ERROR, &soerr, &soerrlen);
      if (ret != 0)
        GNUNET_GE_LOG_STRERROR (sock->ectx,
                                GNUNET_GE_WARNING | GNUNET_GE_USER |
                                GNUNET_GE_BULK, "getsockopt");
      if ((soerr != 0) || (ret != 0 && (errno == ENOTSOCK || errno == EBADF)))
        {
          GNUNET_socket_destroy (sock->sock);
          sock->sock = NULL;
          GNUNET_mutex_unlock (sock->destroylock);
          if (GNUNET_get_time () - select_start >
              TRIES_PER_AF * DELAY_PER_RETRY)
            ADVANCE ();         /* spend enough time trying here */
          else
            RETRY ();
          continue;
        }
      /* yayh! connected! */
      break;
    }
  GNUNET_free (host);
  GNUNET_socket_set_blocking (sock->sock, GNUNET_YES);
  GNUNET_mutex_unlock (sock->destroylock);
#undef ADVANCE
#undef RETRY
#undef TRIES_PER_AF
#undef DELAY_PER_RETRY
  return GNUNET_OK;
}

/**
 * Write to a GNUnet TCP socket.  Will also potentially complete the
 * sending of a previous non-blocking GNUNET_client_connection_write call.
 *
 * @param sock the socket to write to
 * @param buffer the buffer to write
 * @return GNUNET_OK if the write was sucessful, otherwise GNUNET_SYSERR.
 */
int
GNUNET_client_connection_write (struct GNUNET_ClientServerConnection *sock,
                                const GNUNET_MessageHeader * buffer)
{
  size_t size;
  size_t sent;
  int res;

  GNUNET_mutex_lock (sock->destroylock);
  GNUNET_mutex_lock (sock->writelock);
  if (GNUNET_SYSERR == GNUNET_client_connection_ensure_connected (sock))
    {
      GNUNET_mutex_unlock (sock->writelock);
      GNUNET_mutex_unlock (sock->destroylock);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_unlock (sock->destroylock);
  GNUNET_GE_ASSERT (NULL, sock->sock != NULL);
  size = ntohs (buffer->size);
  res =
    GNUNET_socket_send (sock->sock, GNUNET_NC_COMPLETE_TRANSFER, buffer, size,
                        &sent);
  if ((res != GNUNET_YES) || (sent != size))
    {
      GNUNET_mutex_unlock (sock->writelock);
      GNUNET_client_connection_close_temporarily (sock);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_unlock (sock->writelock);
  return GNUNET_OK;
}

int
GNUNET_client_connection_read (struct GNUNET_ClientServerConnection *sock,
                               GNUNET_MessageHeader ** buffer)
{
  int res;
  size_t pos;
  char *buf;
  unsigned short size;
  GNUNET_MessageReturnErrorMessage *rem;

  GNUNET_mutex_lock (sock->destroylock);
  GNUNET_mutex_lock (sock->readlock);
  if (GNUNET_OK != GNUNET_client_connection_ensure_connected (sock))
    {
      GNUNET_mutex_unlock (sock->readlock);
      GNUNET_mutex_unlock (sock->destroylock);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_unlock (sock->destroylock);
  GNUNET_GE_ASSERT (NULL, sock->sock != NULL);
  while (1)
    {
      pos = 0;
      res = 0;
      if ((GNUNET_OK != GNUNET_socket_recv (sock->sock,
                                            GNUNET_NC_COMPLETE_TRANSFER,
                                            &size,
                                            sizeof (unsigned short),
                                            &pos))
          || (pos != sizeof (unsigned short)))
        {
          GNUNET_mutex_unlock (sock->readlock);
          GNUNET_client_connection_close_temporarily (sock);
          return GNUNET_SYSERR;
        }
      size = ntohs (size);
      if (size < sizeof (GNUNET_MessageHeader))
        {
          GNUNET_GE_BREAK (sock->ectx, 0);
          GNUNET_mutex_unlock (sock->readlock);
          GNUNET_client_connection_close_temporarily (sock);
          return GNUNET_SYSERR; /* invalid header */
        }

      buf = GNUNET_malloc (size);
      if ((GNUNET_OK != GNUNET_socket_recv (sock->sock,
                                            GNUNET_NC_COMPLETE_TRANSFER,
                                            &buf[pos],
                                            size - pos,
                                            &pos)) ||
          (pos + sizeof (unsigned short) != size))
        {
          GNUNET_free (buf);
          GNUNET_mutex_unlock (sock->readlock);
          GNUNET_client_connection_close_temporarily (sock);
          return GNUNET_SYSERR;
        }
#if DEBUG_TCPIO
      GNUNET_GE_LOG (sock->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Successfully received %d bytes from TCP socket.\n",
                     size);
#endif
      *buffer = (GNUNET_MessageHeader *) buf;
      (*buffer)->size = htons (size);

      if (ntohs ((*buffer)->type) != GNUNET_CS_PROTO_RETURN_ERROR)
        break;                  /* got actual message! */
      rem = (GNUNET_MessageReturnErrorMessage *) * buffer;
      if (ntohs (rem->header.size) <
          sizeof (GNUNET_MessageReturnErrorMessage))
        {
          GNUNET_GE_BREAK (sock->ectx, 0);
          GNUNET_mutex_unlock (sock->readlock);
          GNUNET_client_connection_close_temporarily (sock);
          GNUNET_free (buf);
          return GNUNET_SYSERR;
        }
      size =
        ntohs (rem->header.size) - sizeof (GNUNET_MessageReturnErrorMessage);
      GNUNET_GE_LOG (sock->ectx, ntohl (rem->kind), "%.*s", (int) size,
                     &rem[1]);
      GNUNET_free (rem);
    }                           /* while (1) */
  GNUNET_mutex_unlock (sock->readlock);
  return GNUNET_OK;             /* success */
}

/**
 * Obtain a return value from a remote call from TCP.
 *
 * @param sock the TCP socket
 * @param ret the return value from TCP
 * @return GNUNET_SYSERR on error, GNUNET_OK if the return value was read
 * successfully
 */
int
GNUNET_client_connection_read_result (struct GNUNET_ClientServerConnection
                                      *sock, int *ret)
{
  GNUNET_MessageReturnValue *rv;

  rv = NULL;
  if (GNUNET_SYSERR ==
      GNUNET_client_connection_read (sock, (GNUNET_MessageHeader **) & rv))
    return GNUNET_SYSERR;
  if ((ntohs (rv->header.size) != sizeof (GNUNET_MessageReturnValue)) ||
      (ntohs (rv->header.type) != GNUNET_CS_PROTO_RETURN_VALUE))
    {
      GNUNET_GE_LOG (sock->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                     _
                     ("Reading result from gnunetd failed, reply invalid!\n"));
      GNUNET_free (rv);
      return GNUNET_SYSERR;
    }
  *ret = ntohl (rv->return_value);
  GNUNET_free (rv);
  return GNUNET_OK;
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
GNUNET_client_connection_write_result (struct GNUNET_ClientServerConnection
                                       *sock, int ret)
{
  GNUNET_MessageReturnValue rv;

  rv.header.size = htons (sizeof (GNUNET_MessageReturnValue));
  rv.header.type = htons (GNUNET_CS_PROTO_RETURN_VALUE);
  rv.return_value = htonl (ret);
  return GNUNET_client_connection_write (sock, &rv.header);
}

/*  end of tcpio.c */
