/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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

#define ALLOW_EXTRA_CHECKS  YES

#include "plibc.h"

/**
 * For strptime (glibc2 needs this).
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
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
 #include <sys/wait.h>
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
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
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

/**
 * GNU gettext support macro.
 */
#define _(String) dgettext("GNUnet",String)

#ifdef CYGWIN
 #define SIOCGIFCONF     _IOW('s', 100, struct ifconf) /* get if list */
 #define SIOCGIFFLAGS    _IOW('s', 101, struct ifreq) /* Get if flags */
 #define SIOCGIFADDR     _IOW('s', 102, struct ifreq) /* Get if addr */
#endif

#ifndef MINGW
#include <sys/mman.h>
#endif

#ifdef OSX
 #define socklen_t unsigned int
#endif

#if !HAVE_ATOLL
long long atoll(const char *nptr);
#endif

#if ENABLE_NLS
#include "langinfo.h"
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

#endif
