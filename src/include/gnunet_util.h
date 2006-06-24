/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util.h
 * @brief public interface to libgnunetutil
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 *
 * Features:
 * - threading (semaphore, pthreads, cron)
 * - basic libc wrappers (malloc, strdup, iconv)
 * - disk io (filesize, read, write, copy, remove, scan directory)
 * - network io (client socket, read, write, nonblocking, etc.)
 * - process management
 * - lots of other small functions
 * ??: sort/regroup ?? 
 */

#ifndef GNUNET_UTIL_H
#define GNUNET_UTIL_H

#ifdef MINGW
  #include <windows.h>
  #include <iphlpapi.h>
  #include <Ntsecapi.h>
  #include <lm.h>
  
  #define HAVE_STAT64 1
#endif

/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */
#include <stdlib.h>

/* add prototypes of sublibraries */
#include "gnunet_util_error.h"
#include "gnunet_util_config.h"
#include "gnunet_util_string.h"
#include "gnunet_util_disk.h"
#include "gnunet_util_threads.h"
#include "gnunet_util_getopt.h"
#include "gnunet_util_network.h"
#include "gnunet_util_os.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#define DEFAULT_CLIENT_CONFIG_FILE "~/.gnunet/gnunet.conf"
#define DEFAULT_DAEMON_DIR         "/etc"
#define DEFAULT_DAEMON_CONFIG_FILE DEFAULT_DAEMON_DIR"/gnunetd.conf"
#define VAR_DIRECTORY              "/var/lib"
#define VAR_DAEMON_DIRECTORY       VAR_DIRECTORY"/gnunet"
#define VAR_DAEMON_CONFIG_FILE     VAR_DAEMON_DIRECTORY"/gnunetd.conf"
#define GNUNET_HOME_DIRECTORY      "~/.gnunet"
#define HOME_DAEMON_CONFIG_FILE    GNUNET_HOME_DIRECTORY"/gnunetd.conf"


/* **************** constants ****************** */

/**
 * Just the version number of GNUnet-util implementation.
 * Encoded as
 * 0.6.1-4 => 0x00060104
 * 4.5.2   => 0x04050200
 *
 * Note that this version number is changed whenever
 * something changes GNUnet-util.  It does not have
 * to match exactly with the GNUnet version number;
 * especially the least significant bits may change
 * frequently, even between different SVN versions.
 */
#define GNUNET_UTIL_VERSION 0x00070004

/* CHRISTIAN: move this to gnunet_core.h or _protocols.h ? */

/**
 * Highest legal priority or trust value
 */
#define MAX_PRIO 0x7FFFFFFF


/* NILS: I would love to see the 
   next two methods in PLIBC */

/**
 * TIME prototype. "man time".
 */
TIME_T TIME(TIME_T * t);

/**
 * "man ctime_r".
 * @return character sequence describing the time,
 *  must be freed by caller
 */
char * GN_CTIME(const TIME_T * t);

/** NILS: the next one should be removed from gnunetutil --
    we should not have anything win32 specific in here! */

/**
 * @brief Format a Windows specific error code
 */
char *winErrorStr(const char *prefix, 
		  int dwErr);


/**
 * Initialize the util module.
 * @param argc the number of arguments
 * @param argv the command line arguments
 * @param parser parser to call at the right moment
 * @return OK on success, SYSERR if we should abort
 */
int initUtil(int argc,
	     char * argv[],
	     CommandLineParser parser);


/**
 * Shutdown the util services in proper order.
 */
void doneUtil(void);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_H */
#endif
/* end of gnunet_util.h */
