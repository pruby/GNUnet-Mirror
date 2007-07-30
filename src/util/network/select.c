/*
     This file is part of GNUnet.
     (C) 2003, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file util/network/select.c
 * @brief (network) input/output operations
 * @author Christian Grothoff
 */

#include "gnunet_util_network.h"
#include "platform.h"
#include "network.h"

#define DEBUG_SELECT NO

/**
 * Select Session handle.
 */
typedef struct
{

  /**
   * the socket
   */
  struct SocketHandle *sock;

  /**
   * Client connection context.
   */
  void *sock_ctx;

  /**
   * The read buffer.
   */
  char *rbuff;

  /**
   * The write buffer.
   */
  char *wbuff;

  cron_t lastUse;

  /**
   * Set to 0 initially, set to a much lower value
   * if a "fast timeout" is desired.
   */
  cron_t timeout;

  /**
   * 0 : can be destroyed
   * 1 : if destruction is required, it must be delayed
   * -1: delayed destruction required
   * 2 : destruction in progress
   */
  int locked;

  /**
   * Do not read from this socket until the
   * current write is complete.
   */
  int no_read;

  /**
   * Current read position in the buffer.
   */
  unsigned int pos;

  /**
   * Current size of the read buffer.
   */
  unsigned int rsize;

  /**
   * Position in the write buffer (for sending)
   */
  unsigned int wspos;

  /**
   * Position in the write buffer (for appending)
   */
  unsigned int wapos;

  /**
   * Size of the write buffer
   */
  unsigned int wsize;

} Session;

typedef struct SelectHandle
{

  const char *description;

  /**
   * mutex for synchronized access
   */
  struct MUTEX *lock;

  /**
   * one thread for listening for new connections,
   * and for reading on all open sockets
   */
  struct PTHREAD *thread;

  /**
   * sock is the tcp socket that we listen on for new inbound
   * connections.  Maybe NULL if we are not listening.
   */
  struct SocketHandle *listen_sock;

  struct GE_Context *ectx;

  struct LoadMonitor *load_monitor;

  /**
   * Array of currently active TCP sessions.
   */
  Session **sessions;

  SelectMessageHandler mh;

  SelectAcceptHandler ah;

  SelectCloseHandler ch;

  void *mh_cls;

  void *ah_cls;

  void *ch_cls;

  cron_t timeout;

  /**
   * tcp_pipe is used to signal the thread that is
   * blocked in a select call that the set of sockets to listen
   * to has changed.
   */
  int signal_pipe[2];

  int is_udp;

  unsigned int sessionCount;

  unsigned int sessionArrayLength;

  int shutdown;

  unsigned int max_addr_len;

  unsigned int memory_quota;

  int socket_quota;

} SelectHandle;

static void
add_to_select_set (struct SocketHandle *s, fd_set * set, int *max)
{
  FD_SET (s->handle, set);
  if (*max < s->handle)
    *max = s->handle;
}

/**
 * Write to the pipe to wake up the select thread (the set of
 * files to watch has changed).
 */
static void
signalSelect (SelectHandle * sh)
{
  static char i = '\0';
  int ret;

#if DEBUG_SELECT
  GE_LOG (sh->ectx,
          GE_DEBUG | GE_DEVELOPER | GE_BULK, "Signaling select %p.\n", sh);
#endif
  ret = WRITE (sh->signal_pipe[1], &i, sizeof (char));
  if (ret != sizeof (char))
    GE_LOG_STRERROR (sh->ectx, GE_ERROR | GE_ADMIN | GE_BULK, "write");
}

/**
 * Destroy the given session by closing the socket,
 * releasing the buffers and removing it from the
 * select set.
 *
 * This function may only be called if the tcplock is
 * already held by the caller.
 */
static void
destroySession (SelectHandle * sh, Session * s)
{
  int i;

  if (s->locked == 1)
    {
      s->locked = -1;
      return;
    }
  if (s->locked == 2)
    return;                     /* already in process of destroying! */
  s->locked = 2;
#if DEBUG_SELECT
  GE_LOG (sh->ectx,
          GE_DEBUG | GE_DEVELOPER | GE_BULK,
          "Destroying session %p of select %p with %u in read and %u in write buffer.\n",
          s, sh, s->rsize, s->wsize);
#endif
#if 0
  if ((s->pos > 0) || (s->wapos > s->wspos))
    fprintf (stderr,
             "Destroying session %p of select %p with loss of %u in read and %u in write buffer.\n",
             s, sh, s->pos, s->wapos - s->wspos);
#endif
  for (i = 0; i < sh->sessionCount; i++)
    {
      if (sh->sessions[i] == s)
        {
          sh->sessions[i] = sh->sessions[sh->sessionCount - 1];
          sh->sessionCount--;
          break;
        }
    }
  if (sh->sessionCount * 2 < sh->sessionArrayLength)
    GROW (sh->sessions, sh->sessionArrayLength, sh->sessionCount);
  MUTEX_UNLOCK (sh->lock);
  sh->ch (sh->ch_cls, sh, s->sock, s->sock_ctx);
  MUTEX_LOCK (sh->lock);
  socket_destroy (s->sock);
  sh->socket_quota++;
  GROW (s->rbuff, s->rsize, 0);
  GROW (s->wbuff, s->wsize, 0);
  FREE (s);
}

/**
 * The socket of a session has data waiting, read and
 * process!
 *
 * This function may only be called if the lock is
 * already held by the caller.
 * @return OK for success, SYSERR if session was destroyed
 */
static int
readAndProcess (SelectHandle * sh, Session * session)
{
  const MESSAGE_HEADER *pack;
  int ret;
  size_t recvd;
  unsigned short len;

  if (session->rsize == session->pos)
    {
      /* read buffer too small, grow */
      GROW (session->rbuff, session->rsize, session->rsize + 1024);
    }
  ret = socket_recv (session->sock,
                     NC_Nonblocking | NC_IgnoreInt,
                     &session->rbuff[session->pos],
                     session->rsize - session->pos, &recvd);
#if DEBUG_SELECT
  GE_LOG (sh->ectx,
          GE_DEBUG | GE_DEVELOPER | GE_BULK,
          "Receiving from session %p of select %p return %d-%u (%s).\n",
          sh, session, ret, recvd, STRERROR (errno));
#endif
  if (ret != OK)
    {
      destroySession (sh, session);
      return SYSERR;            /* other side closed connection */
    }
  session->pos += recvd;
  while ((sh->shutdown == NO) && (session->pos >= sizeof (MESSAGE_HEADER)))
    {
      pack = (const MESSAGE_HEADER *) &session->rbuff[0];
      len = ntohs (pack->size);
      /* check minimum size */
      if (len < sizeof (MESSAGE_HEADER))
        {
          GE_LOG (sh->ectx,
                  GE_WARNING | GE_USER | GE_BULK,
                  _
                  ("Received malformed message (too small) from connection. Closing.\n"));
          destroySession (sh, session);
          return SYSERR;
        }
      if (len > session->rsize) /* if message larger than read buffer, grow! */
        GROW (session->rbuff, session->rsize, len);

      /* do we have the entire message? */
      if (session->pos < len)
        break;                  /* wait for more */
      if (session->locked == 0)
        session->locked = 1;
      MUTEX_UNLOCK (sh->lock);
      if (OK != sh->mh (sh->mh_cls,
                        sh, session->sock, session->sock_ctx, pack))
        {
          MUTEX_LOCK (sh->lock);
          if (session->locked == 1)
            session->locked = 0;
          destroySession (sh, session);
          return SYSERR;
        }
      MUTEX_LOCK (sh->lock);
      if (session->locked == -1)
        {
          session->locked = 0;
          destroySession (sh, session);
          return OK;
        }
      if (session->locked == 1)
        session->locked = 0;
      /* shrink buffer adequately */
      memmove (&session->rbuff[0], &session->rbuff[len], session->pos - len);
      session->pos -= len;
    }
  session->lastUse = get_time ();
  return OK;
}

/**
 * The socket of a session has data waiting that can be
 * transmitted, do it!
 *
 * This function may only be called if the lock is
 * already held by the caller.
 * @return OK for success, SYSERR if session was destroyed
 */
static int
writeAndProcess (SelectHandle * sh, Session * session)
{
  SocketHandle *sock;
  int ret;
  size_t size;

#if DEBUG_SELECT
  GE_LOG (sh->ectx,
          GE_DEBUG | GE_DEVELOPER | GE_BULK,
          "Write and process called for session %p of select %p status %d.\n",
          sh, session, sh->shutdown);
#endif
  sock = session->sock;
  while (sh->shutdown == NO)
    {
      ret = socket_send (sock,
                         NC_Nonblocking,
                         &session->wbuff[session->wspos],
                         session->wapos - session->wspos, &size);
#if DEBUG_SELECT
      GE_LOG (sh->ectx,
              GE_DEBUG | GE_DEVELOPER | GE_BULK,
              "Sending %d bytes from session %p of select %p return %d.\n",
              session->wapos - session->wspos, sh, session, ret);
#endif
      if (ret == SYSERR)
        {
          GE_LOG_STRERROR (sh->ectx,
                           GE_WARNING | GE_USER | GE_ADMIN | GE_BULK, "send");
          destroySession (sh, session);
          return SYSERR;
        }
      if (ret == OK)
        {
          if (size == 0)
            {
              /* send only returns 0 on error (happens if
                 other side closed connection), so close
                 the session */
              destroySession (sh, session);
              return SYSERR;
            }
          session->wspos += size;
          if (session->wspos == session->wapos)
            {
              /* free compaction! */
              session->wspos = 0;
              session->wapos = 0;
              session->no_read = NO;
              if (session->wsize > sh->memory_quota)
                {
                  /* if we went over quota before because of
                     force, use this opportunity to shrink
                     back to size! */
                  GROW (session->wbuff, session->wsize, sh->memory_quota);
                }
            }
          break;
        }
      GE_ASSERT (sh->ectx, ret == NO);
      /* this should only happen under Win9x because
         of a bug in the socket implementation (KB177346).
         Let's sleep and try again. */
      PTHREAD_SLEEP (20 * cronMILLIS);
    }
  session->lastUse = get_time ();
  return OK;
}

/**
 * Thread that selects until it is signaled to shut down.
 */
static void *
selectThread (void *ctx)
{
  struct SelectHandle *sh = ctx;
  char *clientAddr;
  fd_set readSet;
  fd_set errorSet;
  fd_set writeSet;
  struct stat buf;
  socklen_t lenOfIncomingAddr;
  int i;
  int max;
  int ret;
  int s;
  void *sctx;
  SocketHandle *sock;
  Session *session;
  size_t size;
  int old_errno;

  clientAddr = MALLOC (sh->max_addr_len);
  MUTEX_LOCK (sh->lock);
  while (sh->shutdown == NO)
    {
      FD_ZERO (&readSet);
      FD_ZERO (&errorSet);
      FD_ZERO (&writeSet);
      if (sh->signal_pipe[0] != -1)
        {
          if (-1 == FSTAT (sh->signal_pipe[0], &buf))
            {
              GE_LOG_STRERROR (sh->ectx,
                               GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                               "fstat");
              sh->signal_pipe[0] = -1;  /* prevent us from error'ing all the time */
            }
          else
            {
              FD_SET (sh->signal_pipe[0], &readSet);
            }
        }
      max = sh->signal_pipe[0];
      if (sh->listen_sock != NULL)
        {
          if (!socket_test_valid (sh->listen_sock))
            {
              socket_destroy (sh->listen_sock);
              GE_LOG (sh->ectx,
                      GE_USER | GE_ERROR | GE_BULK,
                      _("select listen socket for `%s' not valid!\n"),
                      sh->description);
              sh->listen_sock = NULL;   /* prevent us from error'ing all the time */
            }
          else
            {
              add_to_select_set (sh->listen_sock, &readSet, &max);
            }
        }
      for (i = 0; i < sh->sessionCount; i++)
        {
          Session *session = sh->sessions[i];
          struct SocketHandle *sock = session->sock;

          if (!socket_test_valid (sock))
            {
#if DEBUG_SELECT
              GE_LOG (sh->ectx,
                      GE_DEBUG | GE_DEVELOPER | GE_BULK,
                      "Select %p destroys invalid client handle %p\n",
                      sh, session);
#endif
              destroySession (sh, session);
            }
          else
            {
              add_to_select_set (sock, &errorSet, &max);
              if (session->no_read != YES)
                add_to_select_set (sock, &readSet, &max);
              GE_ASSERT (NULL, session->wapos >= session->wspos);
              if (session->wapos > session->wspos)
                add_to_select_set (sock, &writeSet, &max);      /* do we have a pending write request? */
            }
        }
      MUTEX_UNLOCK (sh->lock);
      ret = SELECT (max + 1, &readSet, &writeSet, &errorSet, NULL);
      old_errno = errno;
      MUTEX_LOCK (sh->lock);
      if ((ret == -1) && ((old_errno == EAGAIN) || (old_errno == EINTR)))
        continue;
      if (ret == -1)
        {
          errno = old_errno;
          if (errno == EBADF)
            {
              GE_LOG_STRERROR (sh->ectx,
                               GE_DEBUG | GE_DEVELOPER | GE_BULK, "select");
            }
          else
            {
              GE_DIE_STRERROR (sh->ectx,
                               GE_FATAL | GE_ADMIN | GE_USER | GE_IMMEDIATE,
                               "select");
            }
          continue;
        }
      if (sh->is_udp == NO)
        {
          if ((sh->listen_sock != NULL) &&
              (FD_ISSET (sh->listen_sock->handle, &readSet)))
            {
              lenOfIncomingAddr = sh->max_addr_len;
              memset (clientAddr, 0, lenOfIncomingAddr);
              /* make sure this is non-blocking */
              socket_set_blocking (sh->listen_sock, NO);
              s = ACCEPT (sh->listen_sock->handle,
                          (struct sockaddr *) clientAddr, &lenOfIncomingAddr);
              if (s == -1)
                {
                  GE_LOG_STRERROR (sh->ectx,
                                   GE_WARNING | GE_ADMIN | GE_BULK, "accept");
                  GE_LOG (sh->ectx,
                          GE_WARNING | GE_ADMIN | GE_BULK,
                          "Select %s failed to accept!\n", sh->description);
                  if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
                    continue;   /* not good, but not fatal either */
                  break;
                }
              if (sh->socket_quota <= 0)
                {
                  SHUTDOWN (s, SHUT_WR);
                  CLOSE (s);
                  s = -1;
                  continue;
                }
              sh->socket_quota--;
#if DEBUG_SELECT
              GE_LOG (sh->ectx,
                      GE_DEBUG | GE_DEVELOPER | GE_BULK,
                      "Select %p is accepting connection: %d\n", sh, s);
#endif
              sock = socket_create (sh->ectx, sh->load_monitor, s);
              MUTEX_UNLOCK (sh->lock);
              sctx = sh->ah (sh->ah_cls,
                             sh, sock, clientAddr, lenOfIncomingAddr);
              MUTEX_LOCK (sh->lock);
#if DEBUG_SELECT
              GE_LOG (sh->ectx,
                      GE_DEBUG | GE_DEVELOPER | GE_BULK,
                      "Select %p is accepting connection: %p\n", sh, sctx);
#endif
              if (sctx == NULL)
                {
                  socket_destroy (sock);
                  sh->socket_quota++;
                }
              else
                {
                  session = MALLOC (sizeof (Session));
                  memset (session, 0, sizeof (Session));
                  session->sock = sock;
                  session->sock_ctx = sctx;
                  session->lastUse = get_time ();
                  if (sh->sessionArrayLength == sh->sessionCount)
                    GROW (sh->sessions,
                          sh->sessionArrayLength, sh->sessionArrayLength + 4);
                  sh->sessions[sh->sessionCount++] = session;
                }
            }
        }
      else
        {                       /* is_udp == YES */
          if ((sh->listen_sock != NULL) &&
              (FD_ISSET (sh->listen_sock->handle, &readSet)))
            {
              int pending;
              int udp_sock;
              int error;
              socklen_t optlen;

              udp_sock = sh->listen_sock->handle;
              lenOfIncomingAddr = sh->max_addr_len;
              memset (clientAddr, 0, lenOfIncomingAddr);
              pending = 0;
              optlen = sizeof (pending);
#ifdef OSX
              error = GETSOCKOPT (udp_sock,
                                  SOL_SOCKET, SO_NREAD, &pending, &optlen);
#elif MINGW
              error = ioctlsocket (udp_sock, FIONREAD, &pending);
#else
              error = ioctl (udp_sock, FIONREAD, &pending);
#endif
              if ((error != 0) || (optlen != sizeof (pending)))
                {
                  GE_LOG_STRERROR (sh->ectx,
                                   GE_ERROR | GE_ADMIN | GE_BULK, "ioctl");
                  pending = 65535;      /* max */
                }
#if DEBUG_SELECT
              GE_LOG (sh->ectx,
                      GE_DEBUG | GE_DEVELOPER | GE_BULK,
                      "Select %p is preparing to receive %u bytes from UDP\n",
                      sh, pending);
#endif
              GE_ASSERT (sh->ectx, pending >= 0);
              if (pending >= 65536)
                pending = 65536;
              if (pending == 0)
                {
                  /* maybe empty UDP packet was sent (see report on bug-gnunet,
                     5/11/6; read 0 bytes from UDP just to kill potential empty packet! */
                  socket_recv_from (sh->listen_sock,
                                    NC_Nonblocking,
                                    NULL,
                                    0, &size, clientAddr, &lenOfIncomingAddr);
                }
              else
                {
                  char *msg;

                  msg = MALLOC (pending);
                  size = 0;
                  ret = socket_recv_from (sh->listen_sock,
                                          NC_Nonblocking,
                                          msg,
                                          pending,
                                          &size,
                                          clientAddr, &lenOfIncomingAddr);
                  if (ret == SYSERR)
                    {
                      socket_close (sh->listen_sock);
                    }
                  else if (ret == OK)
                    {
                      /* validate msg format! */
                      const MESSAGE_HEADER *hdr;

                      /* if size < pending, set pending to size */
                      if (size < pending)
                        pending = size;
                      hdr = (const MESSAGE_HEADER *) msg;
                      if ((size == pending) &&
                          (size >= sizeof (MESSAGE_HEADER)) &&
                          (ntohs (hdr->size) == size))
                        {
                          void *sctx;

                          MUTEX_UNLOCK (sh->lock);
                          sctx = sh->ah (sh->ah_cls,
                                         sh,
                                         NULL, clientAddr, lenOfIncomingAddr);
                          MUTEX_LOCK (sh->lock);
                          if (sctx != NULL)
                            {
#if DEBUG_SELECT
                              GE_LOG (sh->ectx,
                                      GE_DEBUG | GE_DEVELOPER | GE_BULK,
                                      "Select %p is passing %u bytes from UDP to handler\n",
                                      sh, size);
#endif
                              sh->mh (sh->mh_cls, sh, NULL, sctx, hdr);
                              sh->ch (sh->ch_cls, sh, NULL, sctx);
                            }
                          else
                            {
#if DEBUG_SELECT
                              GE_LOG (sh->ectx,
                                      GE_DEBUG | GE_DEVELOPER | GE_BULK,
                                      "Error in select %p -- connection refused\n",
                                      sh);
#endif
                            }
                        }
                      else
                        {
#if DEBUG_SELECT
                          GE_BREAK (sh->ectx, size == pending);
                          GE_BREAK (sh->ectx,
                                    size >= sizeof (MESSAGE_HEADER));
                          GE_BREAK (sh->ectx,
                                    (size >= sizeof (MESSAGE_HEADER))
                                    && (ntohs (hdr->size) == size));
#endif
                        }
                    }
                  FREE (msg);
                }
            }
        }                       /* end UDP processing */
      if (FD_ISSET (sh->signal_pipe[0], &readSet))
        {
          /* allow reading multiple signals in one go in case we get many
             in one shot... */
#define MAXSIG_BUF 128
          char buf[MAXSIG_BUF];
          /* just a signal to refresh sets, eat and continue */
          if (0 >= READ (sh->signal_pipe[0], &buf[0], MAXSIG_BUF))
            {
              GE_LOG_STRERROR (sh->ectx,
                               GE_WARNING | GE_USER | GE_BULK, "read");
            }
        }
      for (i = 0; i < sh->sessionCount; i++)
        {
          session = sh->sessions[i];
          sock = session->sock;
          if ((FD_ISSET (sock->handle, &readSet)) &&
              (SYSERR == readAndProcess (sh, session)))
            {
              i--;
              continue;
            }
          if ((FD_ISSET (sock->handle, &writeSet)) &&
              (SYSERR == writeAndProcess (sh, session)))
            {
              i--;
              continue;
            }
          if (FD_ISSET (sock->handle, &errorSet))
            {
              destroySession (sh, session);
              i--;
              continue;
            }
          if (((sh->timeout != 0) &&
               (get_time () > session->lastUse + sh->timeout)) ||
              ((session->timeout != 0) &&
               (get_time () > session->lastUse + session->timeout)))
            {
              destroySession (sh, session);
              i--;
              continue;
            }
        }
    }
  sh->description = "DEAD";
  MUTEX_UNLOCK (sh->lock);
  FREE (clientAddr);
  return NULL;
}

static int
makePipeNonblocking (struct GE_Context *ectx, int handle)
{
#if MINGW
  DWORD mode;

  mode = PIPE_NOWAIT;

  if (SetNamedPipeHandleState ((HANDLE) handle, &mode, NULL, NULL))
    __win_SetHandleBlockingMode (handle, 0);
  /* don't report errors because Win9x doesn't support SetNamedPipeHandleState() */
#else
  int flags = fcntl (handle, F_GETFL);
  flags |= O_NONBLOCK;
  if (-1 == fcntl (handle, F_SETFL, flags))
    {
      GE_LOG_STRERROR (ectx,
                       GE_WARNING | GE_USER | GE_ADMIN | GE_IMMEDIATE,
                       "fcntl");
      return SYSERR;
    }
#endif
  return OK;
}

/**
 * Start a select thread that will accept connections
 * from the given socket and pass messages read to the
 * given message handler.
 *
 * @param sock the listen socket
 * @param max_addr_len maximum expected length of addresses for
 *        connections accepted on the given socket
 * @param mon maybe NULL
 * @param memory_quota amount of memory available for
 *        queueing messages (in bytes)
 * @return NULL on error
 */
SelectHandle *
select_create (const char *description,
               int is_udp,
               struct GE_Context * ectx,
               struct LoadMonitor * mon,
               int sock,
               unsigned int max_addr_len,
               cron_t timeout,
               SelectMessageHandler mh,
               void *mh_cls,
               SelectAcceptHandler ah,
               void *ah_cls,
               SelectCloseHandler ch,
               void *ch_cls, unsigned int memory_quota, int socket_quota)
{
  SelectHandle *sh;

  if ((is_udp == NO) && (sock != -1) && (0 != LISTEN (sock, 5)))
    {
      GE_LOG_STRERROR (ectx, GE_ERROR | GE_USER | GE_IMMEDIATE, "listen");
      return NULL;
    }
  GE_ASSERT (ectx, description != NULL);
  sh = MALLOC (sizeof (SelectHandle));
  memset (sh, 0, sizeof (SelectHandle));
  sh->is_udp = is_udp;
  sh->description = description;
  if (0 != PIPE (sh->signal_pipe))
    {
      GE_LOG_STRERROR (ectx, GE_ERROR | GE_USER | GE_IMMEDIATE, "pipe");
      FREE (sh);
      return NULL;
    }
  if (OK != makePipeNonblocking (sh->ectx, sh->signal_pipe[0]))
    {
      if ((0 != CLOSE (sh->signal_pipe[0])) ||
          (0 != CLOSE (sh->signal_pipe[1])))
        GE_LOG_STRERROR (ectx, GE_ERROR | GE_IMMEDIATE | GE_ADMIN, "close");
      FREE (sh);
      return NULL;
    }

  sh->shutdown = NO;
  sh->ectx = ectx;
  sh->load_monitor = mon;
  sh->max_addr_len = max_addr_len;
  sh->mh = mh;
  sh->mh_cls = mh_cls;
  sh->ah = ah;
  sh->ah_cls = ah_cls;
  sh->ch = ch;
  sh->ch_cls = ch_cls;
  sh->memory_quota = memory_quota;
  sh->socket_quota = socket_quota;
  sh->timeout = timeout;
  sh->lock = MUTEX_CREATE (YES);
  if (sock != -1)
    sh->listen_sock = socket_create (ectx, mon, sock);
  else
    sh->listen_sock = NULL;
  sh->thread = PTHREAD_CREATE (&selectThread, sh, 256 * 1024);
  if (sh->thread == NULL)
    {
      GE_LOG_STRERROR (ectx,
                       GE_ERROR | GE_IMMEDIATE | GE_ADMIN, "pthread_create");
      if (sh->listen_sock != NULL)
        socket_destroy (sh->listen_sock);
      if ((0 != CLOSE (sh->signal_pipe[0])) ||
          (0 != CLOSE (sh->signal_pipe[1])))
        GE_LOG_STRERROR (ectx, GE_ERROR | GE_IMMEDIATE | GE_ADMIN, "close");
      MUTEX_DESTROY (sh->lock);
      FREE (sh);
      return NULL;
    }
  return sh;
}

/**
 * Terminate the select thread, close the socket and
 * all associated connections.
 */
void
select_destroy (struct SelectHandle *sh)
{
  void *unused;

#if DEBUG_SELECT
  GE_LOG (sh->ectx,
          GE_DEBUG | GE_DEVELOPER | GE_BULK, "Destroying select %p\n", sh);
#endif
  sh->shutdown = YES;
  signalSelect (sh);
  PTHREAD_STOP_SLEEP (sh->thread);
  PTHREAD_JOIN (sh->thread, &unused);
  sh->thread = NULL;
  MUTEX_LOCK (sh->lock);
  while (sh->sessionCount > 0)
    destroySession (sh, sh->sessions[0]);
  GROW (sh->sessions, sh->sessionArrayLength, 0);
  MUTEX_UNLOCK (sh->lock);
  MUTEX_DESTROY (sh->lock);
  if (0 != CLOSE (sh->signal_pipe[1]))
    GE_LOG_STRERROR (sh->ectx,
                     GE_ERROR | GE_USER | GE_ADMIN | GE_BULK, "close");
  if (0 != CLOSE (sh->signal_pipe[0]))
    GE_LOG_STRERROR (sh->ectx,
                     GE_ERROR | GE_USER | GE_ADMIN | GE_BULK, "close");
  if (sh->listen_sock != NULL)
    socket_destroy (sh->listen_sock);
  FREE (sh);
}

/**
 * Queue the given message with the select thread.
 *
 * @param mayBlock if YES, blocks this thread until message
 *        has been sent
 * @param force message is important, queue even if
 *        there is not enough space
 * @return OK if the message was sent or queued,
 *         NO if there was not enough memory to queue it,
 *         SYSERR if the sock does not belong with this select
 */
int
select_write (struct SelectHandle *sh,
              struct SocketHandle *sock,
              const MESSAGE_HEADER * msg, int mayBlock, int force)
{
  Session *session;
  int i;
  unsigned short len;
  char *newBuffer;
  unsigned int newBufferSize;

#if DEBUG_SELECT
  GE_LOG (sh->ectx,
          GE_DEBUG | GE_DEVELOPER | GE_BULK,
          "Adding message of size %u to %p of select %p\n",
          ntohs (msg->size), sock, sh);
#endif
  session = NULL;
  len = ntohs (msg->size);
  MUTEX_LOCK (sh->lock);
  for (i = 0; i < sh->sessionCount; i++)
    if (sh->sessions[i]->sock == sock)
      {
        session = sh->sessions[i];
        break;
      }
  if (session == NULL)
    {
      MUTEX_UNLOCK (sh->lock);
      return SYSERR;
    }
  GE_ASSERT (NULL, session->wapos >= session->wspos);
  if ((force == NO) &&
      (((sh->memory_quota > 0) &&
        (session->wapos - session->wspos + len > sh->memory_quota)) ||
       ((sh->memory_quota == 0) &&
        (session->wapos - session->wspos + len > MAX_MALLOC_CHECKED / 2))))
    {
      /* not enough free space, not allowed to grow that much */
      MUTEX_UNLOCK (sh->lock);
      return NO;
    }
  if (session->wsize - session->wapos < len)
    {
      /* need to make space in some way or other */
      if (session->wapos - session->wspos + len <= session->wsize)
        {
          /* can compact buffer to get space */
          memmove (session->wbuff,
                   &session->wbuff[session->wspos],
                   session->wapos - session->wspos);
          session->wapos -= session->wspos;
          session->wspos = 0;
        }
      else
        {
          /* need to grow buffer */
          newBufferSize = session->wsize;
          if (session->wsize == 0)
            newBufferSize = 4092;
          while (newBufferSize < len + session->wapos - session->wspos)
            newBufferSize *= 2;
          if ((sh->memory_quota > 0) &&
              (newBufferSize > sh->memory_quota) && (force == NO))
            newBufferSize = sh->memory_quota;
          GE_ASSERT (NULL,
                     newBufferSize >= len + session->wapos - session->wspos);
          newBuffer = MALLOC (newBufferSize);
          memcpy (newBuffer,
                  &session->wbuff[session->wspos],
                  session->wapos - session->wspos);
          FREENONNULL (session->wbuff);
          session->wbuff = newBuffer;
          session->wsize = newBufferSize;
          session->wapos = session->wapos - session->wspos;
          session->wspos = 0;
        }
    }
  GE_ASSERT (NULL, session->wapos + len <= session->wsize);
  memcpy (&session->wbuff[session->wapos], msg, len);
  session->wapos += len;
  if (mayBlock)
    session->no_read = YES;
  MUTEX_UNLOCK (sh->lock);
  signalSelect (sh);
  return OK;
}


/**
 */
int
select_update_closure (struct SelectHandle *sh,
                       struct SocketHandle *sock,
                       void *old_sock_ctx, void *new_sock_ctx)
{
  Session *session;
  int i;

  session = NULL;
  MUTEX_LOCK (sh->lock);
  for (i = 0; i < sh->sessionCount; i++)
    if (sh->sessions[i]->sock == sock)
      {
        session = sh->sessions[i];
        break;
      }
  if (session == NULL)
    {
      MUTEX_UNLOCK (sh->lock);
      return SYSERR;
    }
  GE_ASSERT (NULL, session->sock_ctx == old_sock_ctx);
  session->sock_ctx = new_sock_ctx;
  MUTEX_UNLOCK (sh->lock);
  return OK;
}

/**
 * Add another (already connected) socket to the set of
 * sockets managed by the select.
 */
int
select_connect (struct SelectHandle *sh,
                struct SocketHandle *sock, void *sock_ctx)
{
  Session *session;

#if DEBUG_SELECT
  GE_LOG (sh->ectx,
          GE_DEBUG | GE_DEVELOPER | GE_BULK,
          "Adding connection %p to selector %p\n", sock, sh);
#endif
  session = MALLOC (sizeof (Session));
  memset (session, 0, sizeof (Session));
  session->sock = sock;
  session->sock_ctx = sock_ctx;
  session->lastUse = get_time ();
  MUTEX_LOCK (sh->lock);
  if (sh->sessionArrayLength == sh->sessionCount)
    GROW (sh->sessions, sh->sessionArrayLength, sh->sessionArrayLength + 4);
  sh->sessions[sh->sessionCount++] = session;
  sh->socket_quota--;
  MUTEX_UNLOCK (sh->lock);
  signalSelect (sh);
  return OK;
}

static Session *
findSession (struct SelectHandle *sh, struct SocketHandle *sock)
{
  int i;

  for (i = 0; i < sh->sessionCount; i++)
    if (sh->sessions[i]->sock == sock)
      return sh->sessions[i];
  return NULL;
}

/**
 * Close the associated socket and remove it from the
 * set of sockets managed by select.
 */
int
select_disconnect (struct SelectHandle *sh, struct SocketHandle *sock)
{
  Session *session;

#if DEBUG_SELECT
  GE_LOG (sh->ectx,
          GE_DEBUG | GE_DEVELOPER | GE_BULK,
          "Removing connection %p from selector %p\n", sock, sh);
#endif
  MUTEX_LOCK (sh->lock);
  session = findSession (sh, sock);
  if (session == NULL)
    {
      MUTEX_UNLOCK (sh->lock);
      return SYSERR;
    }
  destroySession (sh, session);
  MUTEX_UNLOCK (sh->lock);
  signalSelect (sh);
  return OK;
}

/**
 * Change the timeout for this socket to a custom
 * value.  Use 0 to use the default timeout for
 * this select.
 */
int
select_change_timeout (struct SelectHandle *sh,
                       struct SocketHandle *sock, cron_t timeout)
{
  Session *session;

  MUTEX_LOCK (sh->lock);
  session = findSession (sh, sock);
  if (session == NULL)
    {
      MUTEX_UNLOCK (sh->lock);
      return SYSERR;
    }
  session->timeout = timeout;
  MUTEX_UNLOCK (sh->lock);
  return OK;
}


/**
 * Would select queue or send the given message at this time?
 *
 * @param mayBlock if YES, blocks this thread until message
 *        has been sent
 * @param size size of the message
 * @param force message is important, queue even if
 *        there is not enough space
 * @return OK if the message would be sent or queued,
 *         NO if there was not enough memory to queue it,
 *         SYSERR if the sock does not belong with this select
 */
int
select_would_try (struct SelectHandle *sh,
                  struct SocketHandle *sock,
                  unsigned int size, int mayBlock, int force)
{
  Session *session;

  MUTEX_LOCK (sh->lock);
  session = findSession (sh, sock);
  if (session == NULL)
    {
      MUTEX_UNLOCK (sh->lock);
      return SYSERR;
    }
  GE_ASSERT (NULL, session->wapos >= session->wspos);
  if ((sh->memory_quota > 0) &&
      (session->wapos - session->wspos + size > sh->memory_quota) &&
      (force == NO))
    {
      /* not enough free space, not allowed to grow that much */
      MUTEX_UNLOCK (sh->lock);
      return NO;
    }
  MUTEX_UNLOCK (sh->lock);
  return YES;
}
