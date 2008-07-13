/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file util/error/error_test.c
 * @brief testcase for the error module
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

static void
my_log (void *ctx, GNUNET_GE_KIND kind, const char *date, const char *msg)
{
  unsigned int *c = ctx;
  (*c)++;
}



int
main (int argc, char *argv[])
{
  struct GNUNET_GE_Context *ectx;
  unsigned int failureCount = 0;
  unsigned int logs = 0;

  ectx = GNUNET_GE_create_context_callback (GNUNET_GE_ALL,
                                            &my_log, &logs, NULL, NULL);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_USER | GNUNET_GE_WARNING |
                 GNUNET_GE_BULK, "Testing...\n");
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_USER | GNUNET_GE_WARNING |
                 GNUNET_GE_BULK, "Testing...\n");
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_USER | GNUNET_GE_WARNING |
                 GNUNET_GE_BULK, "Testing...\n");
  /* the last 2 calls should be merged (repated bulk messages!) */
  GNUNET_GE_free_context (ectx);
  if (logs != 2)
    failureCount++;
  if (failureCount != 0)
    {
      fprintf (stderr, "\n\n%d TESTS FAILED!\n\n", failureCount);
      return -1;
    }
  return 0;
}                               /* end of main */

/* end of error_test.c */
