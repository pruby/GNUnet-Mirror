/*
     This file is part of GNUnet.
     (C) 2001 - 2004 Christian Grothoff (and other contributing authors)

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
 * @file include/platform.h
 * @brief plaform specifics
 *
 * @author Nils Durner
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#ifndef HAVE_USED_CONFIG_H
#define HAVE_USED_CONFIG_H
#include "config.h"
#endif


/* configuration options */

#define VERBOSE_STATS 0


#ifdef CYGWIN
 #include <sys/reent.h>
 #define _REENT_ONLY
#endif

#include <pthread.h>
#ifdef CYGWIN
 #undef _REENT_ONLY
#endif

#ifdef _MSC_VER
 #include <Winsock2.h>
#else
#ifndef MINGW
 #include <netdb.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <netinet/tcp.h>
 #include <netinet/in.h>
 #include <pwd.h>
 #include <sys/ioctl.h>
#else
 #include "winproc.h"
#endif
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#ifndef _MSC_VER
#include <ltdl.h> /* KLB_FIX */
#endif
#include <errno.h>
#include <signal.h>
#ifndef _MSC_VER
#include <unistd.h> /* KLB_FIX */
#endif
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _MSC_VER 
#include <dirent.h> /* KLB_FIX */
#endif
#include <fcntl.h>
#include <math.h>

#if TIME_WITH_SYS_TIME
 #include <sys/time.h>
 #include <time.h>
#else
 #if HAVE_SYS_TIME_H
  #include <sys/time.h>
 #else
  #include <time.h>
 #endif
#endif

/* if we have both openssl & libgcrypt, stick 
   to openssl for now (who has the obscure
   libgcrypt CVS version that works for us!?...) */
#if USE_OPENSSL
 #if USE_GCRYPT
  #undef USE_GCRYPT
  #define USE_GCRYPT 0
 #endif
#endif

#ifdef SOMEBSD
 #include <net/if.h>
#endif
#ifdef FREEBSD
 #include <semaphore.h>
#endif
#ifdef OSX
#include <semaphore.h>
#endif
#ifdef LINUX
#include <net/if.h>
#endif
#ifdef SOLARIS
#include <sys/sockio.h>
#include <sys/loadavg.h>
#include <semaphore.h>
#endif
#ifdef CYGWIN
#include <windows.h>
#include <cygwin/if.h>
#endif
#include <errno.h>

#include <limits.h>

#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#include <locale.h>
#include "gettext.h"


#ifdef CYGWIN
 #define SIOCGIFCONF     _IOW('s', 100, struct ifconf) /* get if list */
 #define SIOCGIFFLAGS    _IOW('s', 101, struct ifreq) /* Get if flags */
 #define SIOCGIFADDR     _IOW('s', 102, struct ifreq) /* Get if addr */
#endif


/**
 * Open a file
 */
int OPEN(const char *filename, int oflag, ...);

#ifndef MINGW
 #define DIR_SEPARATOR '/'
 #define DIR_SEPARATOR_STR "/"

 #define CREAT(p, m) creat(p, m)
 #undef FOPEN
 #define FOPEN(f, m) fopen(f, m)
 #define OPENDIR(d) opendir(d)
 #define CHDIR(d) chdir(d)
 #define RMDIR(f) rmdir(f)
 #define ACCESS(p, m) access(p, m)
 #define CHMOD(f, p) chmod(f, p)
 #define FSTAT(h, b) fstat(h, b)
 #define PIPE(h) pipe(h)
 #define REMOVE(p) remove(p)
 #define RENAME(o, n) rename(o, n)
 #define STAT(p, b) stat(p, b)
 #define UNLINK(f) unlink(f)
 #define WRITE(f, b, n) write(f, b, n)
 #define READ(f, b, n) read(f, b, n)
 #define GN_FREAD(b, s, c, f) fread(b, s, c, f)
 #define GN_FWRITE(b, s, c, f) fwrite(b, s, c, f)
 #define SYMLINK(a, b) symlink(a, b)
 #define STRERROR(i) strerror(i)
 #define ACCEPT(s, a, l) accept(s, a, l)
 #define BIND(s, n, l) bind(s, n, l)
 #define CONNECT(s, n, l) connect(s, n, l)
 #define GETPEERNAME(s, n, l) getpeername(s, n, l)
 #define GETSOCKNAME(s, n, l) getsockname(s, n, l)
 #define GETSOCKOPT(s, l, o, v, p) getsockopt(s, l, o, v, p)
 #define LISTEN(s, b) listen(s, b)
 #define RECV(s, b, l, f) recv(s, b, l, f)
 #define RECVFROM(s, b, l, f, r, o) recvfrom(s, b, l, f, r, o)
 #define SELECT(n, r, w, e, t) select(n, r, w, e, t)
 #define SEND(s, b, l, f) send(s, b, l, f)
 #define SENDTO(s, b, l, f, o, n) sendto(s, b, l, f, o, n)
 #define SETSOCKOPT(s, l, o, v, n) setsockopt(s, l, o, v, n)
 #define SHUTDOWN(s, h) shutdown(s, h)
 #define SOCKET(a, t, p) socket(a, t, p)
 #define GETHOSTBYADDR(a, l, t) gethostbyname(a, l, t)
 #define GETHOSTBYNAME(n) gethostbyname(n)
#else
 #define DIR_SEPARATOR '\\'
 #define DIR_SEPARATOR_STR "\\"

 #define CREAT(p, m) _win_creat(p, m)
 #define FOPEN(f, m) _win_fopen(f, m)
 #define OPENDIR(d) _win_opendir(d)
 #define CHDIR(d) _win_chdir(d)
 #define FSTAT(h, b) _win_fstat(h, b)
 #define RMDIR(f) _win_rmdir(f)
 #define ACCESS(p, m) _win_access(p, m)
 #define CHMOD(f, p) _win_chmod(f, p)
 #define PIPE(h) _win_pipe(h)
 #define REMOVE(p) _win_remove(p)
 #define RENAME(o, n) _win_rename(o, n)
 #define STAT(p, b) _win_stat(p, b)
 #define UNLINK(f) _win_unlink(f)
 #define WRITE(f, b, n) _win_write(f, b, n)
 #define READ(f, b, n) _win_read(f, b, n)
 #define GN_FREAD(b, s, c, f) _win_fread(b, s, c, f)
 #define GN_FWRITE(b, s, c, f) _win_fwrite(b, s, c, f)
 #define SYMLINK(a, b) _win_symlink(a, b)
 #define STRERROR(i) _win_strerror(i)
 #define ACCEPT(s, a, l) _win_accept(s, a, l)
 #define BIND(s, n, l) _win_bind(s, n, l)
 #define CONNECT(s, n, l) _win_connect(s, n, l)
 #define GETPEERNAME(s, n, l) _win_getpeername(s, n, l)
 #define GETSOCKNAME(s, n, l) _win_getsockname(s, n, l) 
 #define GETSOCKOPT(s, l, o, v, p) _win_getsockopt(s, l, o, v, p)
 #define LISTEN(s, b) _win_listen(s, b)
 #define RECV(s, b, l, f) _win_recv(s, b, l, f)
 #define RECVFROM(s, b, l, f, r, o) _win_recvfrom(s, b, l, f, r, o)
 #define SELECT(n, r, w, e, t) _win_select(n, r, w, e, t)
 #define SEND(s, b, l, f) _win_send(s, b, l, f)
 #define SENDTO(s, b, l, f, o, n) _win_sendto(s, b, l, f, o, n)
 #define SETSOCKOPT(s, l, o, v, n) _win_setsockopt(s, l, o, v, n)
 #define SHUTDOWN(s, h) _win_shutdown(s, h)
 #define SOCKET(a, t, p) _win_socket(a, t, p)
 #define GETHOSTBYADDR(a, l, t) _win_gethostbyname(a, l, t)
 #define GETHOSTBYNAME(n) _win_gethostbyname(n)
#endif

#ifdef OSX
 #define socklen_t unsigned int
#endif

#if !HAVE_ATOLL
long long atoll(const char *nptr);
#endif

#endif
