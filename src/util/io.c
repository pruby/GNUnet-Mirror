/*
     This file is part of GNUnet.
     (C) 2003 Christian Grothoff (and other contributing authors)

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
 * @file util/io.c
 * @brief (network) input/output operations
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

/* some systems send us signals, so we'd better
   catch them (& ignore) */
#ifndef LINUX
static void catcher(int sig) {
  LOG(LOG_INFO,
      _("Caught signal %d.\n"),
      sig);
  /* re-install signal handler! */
  signal(sig, catcher);
}


#endif

void gnunet_util_initIO() {
#if ! (defined(LINUX) || defined(MINGW))
  if ( SIG_ERR == signal(SIGPIPE, SIG_IGN))
    if ( SIG_ERR == signal(SIGPIPE, catcher))
      LOG_STRERROR(LOG_WARNING, "signal");
#endif
}

void gnunet_util_doneIO() {
}

/**
 * Depending on doBlock, enable or disable the nonblocking mode
 * of socket s.
 *
 * @param doBlock use YES to change the socket to blocking, NO to non-blocking
 * @return Upon successful completion, it returns zero, otherwise -1
 */
int setBlocking(int s, int doBlock) {
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
 * Check whether the socket is blocking
 * @param s the socket
 * @return YES if blocking, NO non-blocking
 */
int isSocketBlocking(int s)
{
#ifndef MINGW
 return (fcntl(s, F_GETFL) & O_NONBLOCK) ? NO : YES;
#else
  return __win_IsHandleMarkedAsBlocking(s);
#endif
}

/* recv wrappers */

/**
 * Do a NONBLOCKING read on the given socket.  Note that in order to
 * avoid blocking, the caller MUST have done a select call before
 * calling this function. Though the caller must be prepared to the
 * fact that this function may fail with EWOULDBLOCK in any case (Win32).
 *
 * @brief Reads at most max bytes to buf. Interrupts are IGNORED.
 * @param s socket
 * @param buf buffer
 * @param max maximum number of bytes to read
 * @param read number of bytes actually read.
 *             0 is returned if no more bytes can be read
 * @return SYSERR on error, YES on success or NO if the operation
 *         would have blocked
 */
int RECV_NONBLOCKING(int s,
		     void * buf,
		     size_t max,
		     size_t *read) {
  int flags;

  setBlocking(s, NO);

#ifdef CYGWIN
    flags = MSG_NOSIGNAL;
#elif OSX
    flags = 0;
#elif SOMEBSD || SOLARIS
    flags = MSG_DONTWAIT;
#elif LINUX
    flags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
    /* good luck */
    flags = 0;
#endif

  do {
    *read = (size_t) RECV(s,
	                  buf,
	                  max,
	                  flags);
  } while ( ( *read == -1) && ( errno == EINTR) );

  setBlocking(s, YES);

  if (*read == SYSERR && (errno == EWOULDBLOCK || errno == EAGAIN))
    return NO;
  else if ( (*read < 0) || (*read > max) )
    return SYSERR;

  return YES;
}

/**
 * Do a BLOCKING read on the given socket.  Read len bytes (if needed
 * try multiple reads).  Interrupts are ignored.
 *
 * @return SYSERR if len bytes could not be read,
 *   otherwise the number of bytes read (must be len)
 */
int RECV_BLOCKING_ALL(int s,
		      void * buf,
		      size_t len) {
  size_t pos;
  int i, flags;

  pos = 0;
  setBlocking(s, YES);

  while (pos < len) {
#if LINUX || CYGWIN
    flags = MSG_NOSIGNAL;
#else
    flags = 0;
#endif

    i = RECV(s,
	     &((char*)buf)[pos],
	     len - pos,
	     flags);

    if ( (i == -1) && (errno == EINTR) )
      continue;
    if (i <= 0)
    {
      setBlocking(s, NO);
      return SYSERR;
    }
    pos += i;
  }
  GNUNET_ASSERT(pos == len);

  setBlocking(s, NO);

  return pos;
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
int SEND_NONBLOCKING(int s,
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
    /* As braindead as Win32? */
    flags = 0;
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

  if (*sent == SYSERR && (errno == EWOULDBLOCK || errno == EAGAIN))
    return NO;
  else if ( (*sent < 0) || (*sent > max) )
    return SYSERR;

  return YES;
}

/**
 * Do a BLOCKING write on the given socket.  Write len bytes (if
 * needed do multiple write).  Interrupts are ignored (cause a
 * re-try).
 *
 * @return SYSERR if len bytes could not be send,
 *   otherwise the number of bytes transmitted (must be len)
 */
int SEND_BLOCKING_ALL(int s,
		      const void * buf,
		      size_t len) {
  size_t pos;
  int i, flags;

  pos = 0;
  setBlocking(s, YES);
  while (pos < len) {
#if CYGWIN || LINUX
    flags = MSG_NOSIGNAL;
#else
    flags = 0;
#endif
    i = SEND(s,
	     &((char*)buf)[pos],
	     len - pos,
	     flags);

    if ( (i == -1) &&
	 (errno == EINTR) )
      continue; /* ingnore interrupts */
    if (i <= 0) {
      if (i == -1)
	LOG_STRERROR(LOG_WARNING, "send");
      return SYSERR;
    }
    pos += i;
  }
  setBlocking(s, NO);
  GNUNET_ASSERT(pos == len);
  return pos;
}

/**
 * Check if socket is valid
 * @return 1 if valid, 0 otherwise
 */
int isSocketValid(int s)
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
 * Open a file
 */
int fileopen(const char *filename, int oflag, ...)
{
  int mode;
  char *fn;

#ifdef MINGW
  char szFile[_MAX_PATH + 1];
  long lRet;

  if ((lRet = plibc_conv_to_win_path(filename, szFile)) != ERROR_SUCCESS)
  {
    errno = ENOENT;
    SetLastError(lRet);

    return -1;
  }
  fn = szFile;
#else
  fn = (char *) filename;
#endif

  if (oflag & O_CREAT)
  {
    va_list arg;
    va_start(arg, oflag);
    mode = va_arg(arg, int);
    va_end(arg);
  }
  else
  {
    mode = 0;
  }

#ifdef MINGW
  /* Set binary mode */
  oflag |= O_BINARY;
#endif

  return open(fn, oflag, mode);
}

/* end of io.c */
