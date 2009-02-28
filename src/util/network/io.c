/*
     This file is part of GNUnet.
     (C) 2003, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/network/io.c
 * @brief (network) input/output operations
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_network.h"
#include "network.h"

#define DEBUG_IO GNUNET_NO

#ifndef MINGW
static struct GNUNET_SignalHandlerContext *sctx;

static void
catcher ()
{
}
#endif

void __attribute__ ((constructor)) GNUNET_network_io_init ()
{
#ifndef MINGW
  sctx = GNUNET_signal_handler_install (SIGPIPE, &catcher);
#else
  InitWinEnv (NULL);
#endif
}

void __attribute__ ((destructor)) GNUNET_network_io_fini ()
{
#ifndef MINGW
  GNUNET_signal_handler_uninstall (SIGPIPE, &catcher, sctx);
  sctx = NULL;
#else
  ShutdownWinEnv ();
#endif
}


struct GNUNET_SocketHandle *
GNUNET_socket_create (struct GNUNET_GE_Context *ectx,
                      struct GNUNET_LoadMonitor *mon, int osSocket)
{
  SocketHandle *ret;

  ret = GNUNET_malloc (sizeof (SocketHandle));
  ret->ectx = ectx;
  ret->mon = mon;
  ret->handle = osSocket;
  ret->checksum = -ret->handle;
  return ret;
}

struct GNUNET_SocketHandle *
GNUNET_socket_create_connect_to_host (struct GNUNET_LoadMonitor *mon, 
				      const char *host,
				      unsigned short port)
{
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
  struct sockaddr *soaddr;
  socklen_t socklen;
  int af_index;
  int soerr;
  socklen_t soerrlen;
  int tries;
  struct timeval timeout;
  GNUNET_CronTime select_start;
  int osock;
  int iret;
  struct GNUNET_SocketHandle *ret;
  fd_set wset;
 
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
	return NULL; // FIXME: return never-ready socket instead!       
      soaddr = NULL;
      socklen = 0;
      if (GNUNET_SYSERR ==
          GNUNET_get_ip_from_hostname (NULL, host,
                                       addr_families[af_index], &soaddr,
                                       &socklen))
        {
          ADVANCE ();
          continue;
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
          GNUNET_free (soaddr);
          ADVANCE ();
          continue;
        }
      ret = GNUNET_socket_create(NULL, mon, osock);
      GNUNET_socket_set_blocking (ret, GNUNET_NO);
      iret = CONNECT (osock, soaddr, socklen);
      GNUNET_free (soaddr);
      if ((ret != 0) && (errno != EINPROGRESS) && (errno != EWOULDBLOCK))
        {
          GNUNET_GE_LOG (NULL,
                         GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Cannot connect to %s:%u: %s\n"),
                         host, port, STRERROR (errno));
          GNUNET_socket_destroy (ret);
          ret = NULL;
          if (errno == ECONNREFUSED)
            RETRY ();           /* service may just be restarting */
          else
            ADVANCE ();
          continue;
        }
      /* we call select() first with a timeout of WAIT_SECONDS to
         avoid blocking on a later write indefinitely;
         Important if a local firewall decides to just drop
         the TCP handshake... */
      FD_ZERO (&wset);
      FD_SET (osock, &wset);
      timeout.tv_sec = 0;
      timeout.tv_usec = DELAY_PER_RETRY * TRIES_PER_AF * 1000;
      errno = 0;
      select_start = GNUNET_get_time ();
      iret = SELECT (osock + 1, NULL, &wset, NULL, &timeout);
      if (iret == -1)
        {
          if (errno != EINTR)
            GNUNET_GE_LOG_STRERROR (NULL,
                                    GNUNET_GE_WARNING | GNUNET_GE_USER |
                                    GNUNET_GE_BULK, "select");
          GNUNET_socket_destroy (ret);
          ret = NULL;
          if ((GNUNET_get_time () - select_start >
               TRIES_PER_AF * DELAY_PER_RETRY) || (errno != EINTR))
            ADVANCE ();         /* spend enough time trying here */
          else
            RETRY ();
          continue;
        }
      if (! FD_ISSET (osock, &wset))
        {
          GNUNET_socket_destroy (ret);
          ret = NULL;
          if (GNUNET_get_time () - select_start >
              TRIES_PER_AF * DELAY_PER_RETRY)
            ADVANCE ();         /* spend enough time trying here */
          else
            RETRY ();
          continue;
        }
      soerr = 0;
      soerrlen = sizeof (soerr);
      iret = GETSOCKOPT (osock, SOL_SOCKET, SO_ERROR, &soerr, &soerrlen);
      if (iret != 0)
        GNUNET_GE_LOG_STRERROR (NULL,
                                GNUNET_GE_WARNING | GNUNET_GE_USER |
                                GNUNET_GE_BULK, "getsockopt");
      if ((soerr != 0) || (iret != 0 && (errno == ENOTSOCK || errno == EBADF)))
        {
          GNUNET_socket_destroy (ret);
          ret = NULL;
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
  return ret;
}

void
GNUNET_socket_close (struct GNUNET_SocketHandle *s)
{
  GNUNET_GE_ASSERT (NULL, s != NULL);
  if ((0 != SHUTDOWN (s->handle, SHUT_RDWR)) &&
#ifdef OSX
      (errno != EINVAL) &&      /* OS X returns these instead of ENOTCONN */
      (errno != EHOSTDOWN) && (errno != EHOSTUNREACH) &&
#endif
      (errno != ENOTCONN))
    GNUNET_GE_LOG_STRERROR (s->ectx,
                            GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                            GNUNET_GE_BULK, "shutdown");
  if (0 != CLOSE (s->handle))
    GNUNET_GE_LOG_STRERROR (s->ectx,
                            GNUNET_GE_WARNING | GNUNET_GE_USER |
                            GNUNET_GE_DEVELOPER | GNUNET_GE_BULK, "close");
  s->handle = -1;
  s->checksum = 1;
}

void
GNUNET_socket_destroy (struct GNUNET_SocketHandle *s)
{
  GNUNET_GE_ASSERT (NULL, s != NULL);
  if (s->handle != -1)
    {
#ifdef LINUX
      unsigned int option;
      option = 1;               /* 1s only */
      SETSOCKOPT (s->handle,
                  IPPROTO_TCP, TCP_LINGER2, &option, sizeof (unsigned int));

#endif
      if ((0 != SHUTDOWN (s->handle, SHUT_RDWR)) &&
#ifdef OSX
          (errno != EINVAL) &&  /* OS X returns these instead of ENOTCONN */
          (errno != EHOSTDOWN) && (errno != EHOSTUNREACH) &&
#endif
#ifdef FREEBSD
          (errno != ECONNRESET) &&
#endif
#ifdef OPENBSD
          (errno != EINVAL) &&
#endif
          (errno != ENOTCONN))
        GNUNET_GE_LOG_STRERROR (s->ectx,
                                GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                GNUNET_GE_BULK, "shutdown");
      if (0 != CLOSE (s->handle))
        GNUNET_GE_LOG_STRERROR (s->ectx,
                                GNUNET_GE_WARNING | GNUNET_GE_USER |
                                GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                                "close");
    }
  GNUNET_free (s);
}

/* TODO: log errors! */
#if OSX || FREEBSD
static int
socket_set_nosigpipe (struct GNUNET_SocketHandle *s, int dontSigPipe)
{
  return setsockopt (s->handle,
                     SOL_SOCKET, SO_NOSIGPIPE,
                     (void *) &dontSigPipe, sizeof (dontSigPipe));
}
#endif

/* TODO: log errors! */
int
GNUNET_socket_set_blocking (struct GNUNET_SocketHandle *s, int doBlock)
{
#if MINGW
  u_long mode;

  mode = !doBlock;
#if HAVE_PLIBC_FD
  if (ioctlsocket (plibc_fd_get_handle (s->handle), FIONBIO, &mode) ==
      SOCKET_ERROR)
#else
  if (ioctlsocket (s->handle, FIONBIO, &mode) == SOCKET_ERROR)
#endif
    {
      SetErrnoFromWinsockError (WSAGetLastError ());

      return -1;
    }
  else
    {
      /* store the blocking mode */
#if HAVE_PLIBC_FD
      plibc_fd_set_blocking (s->handle, doBlock);
#else
      __win_SetHandleBlockingMode (s->handle, doBlock);
#endif
      return 0;
    }
#else
  int flags = fcntl (s->handle, F_GETFL);
  if (doBlock)
    flags &= ~O_NONBLOCK;
  else
    flags |= O_NONBLOCK;
  return fcntl (s->handle, F_SETFL, flags);
#endif
}

int
GNUNET_socket_test_blocking (struct GNUNET_SocketHandle *s)
{
#ifndef MINGW
  return (fcntl (s->handle, F_GETFL) & O_NONBLOCK) ? GNUNET_NO : GNUNET_YES;
#else
#if HAVE_PLIBC_FD
  return plibc_fd_get_blocking (s->handle);
#else
  return __win_IsHandleMarkedAsBlocking (s->handle);
#endif
#endif
}

int
GNUNET_socket_recv (struct GNUNET_SocketHandle *s,
                    GNUNET_NC_KIND nc, void *buf, size_t max, size_t * read)
{
  int flags;
  size_t pos;
  size_t ret;

  GNUNET_GE_ASSERT (NULL, s->checksum == -s->handle);
  GNUNET_socket_set_blocking (s, 0 != (nc & GNUNET_NC_BLOCKING));
  flags = 0;
#ifdef CYGWIN
  flags |= MSG_NOSIGNAL;
#elif OSX || FREEBSD
  socket_set_nosigpipe (s, 0 == (nc & GNUNET_NC_IGNORE_INT));
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
#elif SOLARIS
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
#elif LINUX
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
  flags |= MSG_NOSIGNAL;
#else
  /* good luck */
#endif
  pos = 0;
  do
    {
      GNUNET_GE_ASSERT (NULL, s->checksum == -s->handle);
      GNUNET_GE_ASSERT (NULL, max > pos);
      ret = (size_t) RECV (s->handle, &((char *) buf)[pos], max - pos, flags);
      GNUNET_GE_ASSERT (NULL, s->checksum == -s->handle);
      if ((ret == (size_t) - 1) &&
          (errno == EINTR) && (0 != (nc & GNUNET_NC_IGNORE_INT)))
        {
          if (GNUNET_shutdown_test () == GNUNET_YES)
            return GNUNET_SYSERR;
          continue;
        }
      if ((ret == (size_t) - 1) || (ret > max - pos))
        {
          if (errno == EINTR)
            {
              *read = pos;
              return GNUNET_YES;
            }
          if (errno == EWOULDBLOCK)
            {
              if (0 != (nc & GNUNET_NC_BLOCKING))
                continue;
              *read = pos;
              return (pos == 0) ? GNUNET_NO : GNUNET_YES;
            }
#if DEBUG_IO
          GNUNET_GE_LOG_STRERROR (s->ectx,
                                  GNUNET_GE_DEBUG | GNUNET_GE_USER |
                                  GNUNET_GE_REQUEST, "recv");
#endif
          *read = pos;
          return GNUNET_SYSERR;
        }
      if (ret == 0)
        {
          /* most likely: other side closed connection */
          *read = pos;
          return GNUNET_SYSERR;
        }
      if (s->mon != NULL)
        GNUNET_network_monitor_notify_transmission (s->mon,
                                                    GNUNET_ND_DOWNLOAD, ret);
      GNUNET_GE_ASSERT (NULL, pos + ret >= pos);
      pos += ret;
    }
  while ((pos < max) && (0 != (nc & GNUNET_NC_BLOCKING)));
  *read = pos;
  return GNUNET_YES;
}

int
GNUNET_socket_recv_from (struct GNUNET_SocketHandle *s,
                         GNUNET_NC_KIND nc,
                         void *buf,
                         size_t max,
                         size_t * read, char *from, unsigned int *fromlen)
{
  int flags;
  size_t pos;
  size_t ret;

  GNUNET_socket_set_blocking (s, 0 != (nc & GNUNET_NC_BLOCKING));
  flags = 0;
#ifdef CYGWIN
  flags |= MSG_NOSIGNAL;
#elif OSX || FREEBSD
  socket_set_nosigpipe (s, 0 == (nc & GNUNET_NC_IGNORE_INT));
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
#elif SOLARIS
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
#elif LINUX
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
  flags |= MSG_NOSIGNAL;
#else
  /* good luck */
#endif
  pos = 0;
  do
    {
      ret = (size_t) RECVFROM (s->handle,
                               &((char *) buf)[pos],
                               max - pos,
                               flags, (struct sockaddr *) from, fromlen);
      if ((ret == (size_t) - 1) &&
          (errno == EINTR) && (0 != (nc & GNUNET_NC_IGNORE_INT)))
        continue;
      if ((ret == (size_t) - 1) || (ret > max - pos))
        {
          if (errno == EINTR)
            {
              *read = pos;
              return GNUNET_YES;
            }
          if (errno == EWOULDBLOCK)
            {
              if (0 != (nc & GNUNET_NC_BLOCKING))
                continue;
              *read = pos;
              return (pos == 0) ? GNUNET_NO : GNUNET_YES;
            }
          GNUNET_GE_LOG_STRERROR (s->ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_USER |
                                  GNUNET_GE_BULK | GNUNET_GE_DEVELOPER,
                                  "recvfrom");
          *read = pos;
          return GNUNET_SYSERR;
        }
      if (ret == 0)
        {
          /* most likely: other side closed connection */
          *read = pos;
          return GNUNET_SYSERR;
        }
      if (s->mon != NULL)
        GNUNET_network_monitor_notify_transmission (s->mon,
                                                    GNUNET_ND_DOWNLOAD, ret);
      pos += ret;
    }
  while ((pos < max) && (0 != (nc & GNUNET_NC_BLOCKING)));
  *read = pos;
  return GNUNET_YES;
}

int
GNUNET_socket_send (struct GNUNET_SocketHandle *s,
                    GNUNET_NC_KIND nc, const void *buf, size_t max,
                    size_t * sent)
{
  int flags;
  size_t pos;
  size_t ret;

  GNUNET_socket_set_blocking (s, 0 != (nc & GNUNET_NC_BLOCKING));
  flags = 0;
#if SOLARIS
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
#elif OSX || FREEBSD
  socket_set_nosigpipe (s, 0 == (nc & GNUNET_NC_IGNORE_INT));
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
#elif CYGWIN
  flags |= MSG_NOSIGNAL;
#elif LINUX
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
  flags |= MSG_NOSIGNAL;
#else
  /* pray */
#endif

  pos = 0;
  do
    {
      ret = (size_t) SEND (s->handle, &((char *) buf)[pos], max - pos, flags);
      if ((ret == (size_t) - 1) &&
          (errno == EINTR) && (0 != (nc & GNUNET_NC_IGNORE_INT)))
        continue;
      if ((ret == (size_t) - 1) || (ret > max - pos))
        {
          if (errno == EINTR)
            {
              *sent = pos;
              return GNUNET_YES;
            }
          if (errno == EWOULDBLOCK)
            {
              if (0 != (nc & GNUNET_NC_BLOCKING))
                continue;
              *sent = pos;
              return (pos == 0) ? GNUNET_NO : GNUNET_YES;
            }
#if DEBUG_IO
          GNUNET_GE_LOG_STRERROR (s->ectx,
                                  GNUNET_GE_DEBUG | GNUNET_GE_USER |
                                  GNUNET_GE_REQUEST, "send");
#endif
          *sent = pos;
          return GNUNET_SYSERR;
        }
      if (ret == 0)
        {
          /* strange error; most likely: other side closed connection */
          *sent = pos;
          return GNUNET_SYSERR;
        }
      if (s->mon != NULL)
        GNUNET_network_monitor_notify_transmission (s->mon, GNUNET_ND_UPLOAD,
                                                    ret);
      pos += ret;
    }
  while ((pos < max) && (0 != (nc & GNUNET_NC_BLOCKING)));
  *sent = pos;
  return GNUNET_YES;
}

int
GNUNET_socket_send_to (struct GNUNET_SocketHandle *s,
                       GNUNET_NC_KIND nc,
                       const void *buf,
                       size_t max,
                       size_t * sent, const char *dst, unsigned int dstlen)
{
  int flags;
  size_t pos;
  size_t ret;

  GNUNET_socket_set_blocking (s, 0 != (nc & GNUNET_NC_BLOCKING));
  flags = 0;
#if SOLARIS
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
#elif OSX || FREEBSD
  socket_set_nosigpipe (s, 0 == (nc & GNUNET_NC_IGNORE_INT));
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
#elif CYGWIN
  flags |= MSG_NOSIGNAL;
#elif LINUX
  if (0 == (nc & GNUNET_NC_BLOCKING))
    flags |= MSG_DONTWAIT;
  flags |= MSG_NOSIGNAL;
#else
  /* pray */
#endif

  pos = 0;
  do
    {
      ret = (size_t) SENDTO (s->handle,
                             &((char *) buf)[pos],
                             max - pos,
                             flags, (const struct sockaddr *) dst, dstlen);
      if ((ret == (size_t) - 1) &&
          (errno == EINTR) && (0 != (nc & GNUNET_NC_IGNORE_INT)))
        continue;
      if ((ret == (size_t) - 1) || (ret > max - pos))
        {
          if (errno == EINTR)
            {
              *sent = pos;
              return GNUNET_YES;
            }
          if (errno == EWOULDBLOCK)
            {
              if (0 != (nc & GNUNET_NC_BLOCKING))
                continue;
              *sent = pos;
              return (pos == 0) ? GNUNET_NO : GNUNET_YES;
            }
#if DEBUG_IO
          GNUNET_GE_LOG_STRERROR (s->ectx,
                                  GNUNET_GE_DEBUG | GNUNET_GE_USER |
                                  GNUNET_GE_REQUEST, "sendto");
#endif
          *sent = pos;
          return GNUNET_SYSERR;
        }
      if (ret == 0)
        {
          /* strange error; most likely: other side closed connection */
          *sent = pos;
          return GNUNET_SYSERR;
        }
      if (s->mon != NULL)
        GNUNET_network_monitor_notify_transmission (s->mon, GNUNET_ND_UPLOAD,
                                                    ret);
      pos += ret;
    }
  while ((pos < max) && (0 != (nc & GNUNET_NC_BLOCKING)));
  *sent = pos;
  return GNUNET_YES;
}

/**
 * Check if socket is valid
 * @return 1 if valid, 0 otherwise
 */
int
GNUNET_socket_test_valid (struct GNUNET_SocketHandle *s)
{
#ifndef MINGW
  struct stat buf;
  return -1 != fstat (s->handle, &buf);
#else
  return _win_isSocketValid (s->handle);
#endif
}


/* end of io.c */
