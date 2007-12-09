/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/statuscallstest.c
 * @brief testcase for util/os/statuscalls.c
 */

#include "gnunet_util.h"
#include "platform.h"

int
main (int argc, char *argv[])
{
  static long k;
  int ret;
  GNUNET_CronTime start;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;

  ectx = GNUNET_GE_create_context_stderr (GNUNET_NO,
                                          GNUNET_GE_WARNING | GNUNET_GE_ERROR
                                          | GNUNET_GE_FATAL | GNUNET_GE_USER |
                                          GNUNET_GE_ADMIN |
                                          GNUNET_GE_DEVELOPER |
                                          GNUNET_GE_IMMEDIATE |
                                          GNUNET_GE_BULK);
  GNUNET_GE_setDefaultContext (ectx);
  cfg = GNUNET_GC_create ();
  GNUNET_GE_ASSERT (ectx, cfg != NULL);
  GNUNET_os_init (ectx);
  /* need to run each phase for more than 10s since
     statuscalls only refreshes that often... */
  start = GNUNET_get_time ();
  while (start + 12 * GNUNET_CRON_SECONDS > GNUNET_get_time ())
    GNUNET_thread_sleep (1);
  start = GNUNET_get_time ();
  ret = GNUNET_cpu_get_load (ectx, cfg);
  while (start + 60 * GNUNET_CRON_SECONDS > GNUNET_get_time ())
    k++;                        /* do some processing to drive load up */
  if (ret > GNUNET_cpu_get_load (ectx, cfg))
    {
      printf ("busy loop decreased CPU load: %d < %d.\n",
              ret, GNUNET_cpu_get_load (ectx, cfg));
      ret = 1;
    }
  else
    {
      ret = 0;
    }
  GNUNET_GC_free (cfg);
  GNUNET_GE_free_context (ectx);
  return ret;
}
