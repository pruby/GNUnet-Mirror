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
#include "gnunet_util_network_client.h"
#include "gnunet_util_crypto.h"
#include "gnunet_util_error_loggers.h"
#include "gnunet_util_containers.h"
#include "gnunet_util_cron.h"
#include "gnunet_util_boot.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

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
#define GNUNET_UTIL_VERSION 0x00070300

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_UTIL_H */
#endif
/* end of gnunet_util.h */
