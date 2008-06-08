/*
     This file is part of GNUnet
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
 * @file src/util/getopt/printversion.c
 * @brief implements --version
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_string.h"
#include "gnunet_util_getopt.h"

int
GNUNET_getopt_print_version_ (GNUNET_CommandLineProcessorContext * ctx,
                              void *scls,
                              const char *option, const char *value)
{
  const char *version = scls;

  printf ("%s v%s\n", ctx->binaryName, version);
  return GNUNET_SYSERR;
}

/* end of printversion.c */
