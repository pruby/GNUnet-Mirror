/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_boot.h
 * @brief command line parsing and --help formatting
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_UTIL_BOOT_H
#define GNUNET_UTIL_BOOT_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util.h"


/**
 * Run a standard GNUnet startup sequence
 * (initialize loggers and configuration,
 * parse options).
 *
 * @param configurationFileName pointer to location
 *        where configuration file name will be stored
 *        (possibly updated by command line option parser)
 * @return -1 on error, position of next
 *  command-line argument to be processed in argv
 *  otherwise
 */
int GNUNET_init (int argc,
                 char *const *argv,
                 const char *binaryName,
                 char **configurationFileName,
                 const struct GNUNET_CommandLineOption *options,
                 struct GNUNET_GE_Context **ectx,
                 struct GNUNET_GC_Configuration **cfg);

/**
 * Free resources allocated during GNUnet_init.
 */
void GNUNET_fini (struct GNUNET_GE_Context *ectx,
                  struct GNUNET_GC_Configuration *cfg);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_UTIL_GETOPT_H */
#endif
/* end of gnunet_util_boot.h */
