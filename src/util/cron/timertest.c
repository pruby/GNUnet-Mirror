/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/cron/timertest.c
 * @brief tests precision of timing for cron
 */

#include "gnunet_util.h"
#include "gnunet_util_cron.h"
#include "platform.h"

static void
semaphore_up (void *ctx)
{
  struct GNUNET_Semaphore *sem = ctx;
  GNUNET_semaphore_up (sem);
}

static struct GNUNET_CronManager *cron;

static int
check ()
{
  struct GNUNET_Semaphore *sem;
  unsigned long long cumDelta;
  GNUNET_CronTime now;
  GNUNET_CronTime last;
  int i;

  sem = GNUNET_semaphore_create (0);

  cumDelta = 0;

#define MAXV2 1500
#define INCR2 113
  for (i = 50; i < MAXV2 + 50; i += INCR2)
    {
      last = GNUNET_get_time ();
      GNUNET_cron_add_job (cron, &semaphore_up, i * GNUNET_CRON_MILLISECONDS,
                           0, sem);
      GNUNET_semaphore_down (sem, GNUNET_YES);
      now = GNUNET_get_time ();
      if (now < last + i)
        now = last + i - now;
      else
        now = now - (last + i);
      cumDelta += now;
#if VERBOSE
      FPRINTF (stderr,
               "Sleep interrupted by signal within %llu ms of deadline (intended delay: %d ms).\n",
               now, i);
#endif
    }
  FPRINTF (stdout,
           "Sleep interrupt precision is %llums. ",
           cumDelta / (MAXV2 / INCR2));
  if (cumDelta <= 10 * GNUNET_CRON_MILLISECONDS * MAXV2 / INCR2)
    fprintf (stdout, "Timer precision is excellent.\n");
  else if (cumDelta <= 50 * GNUNET_CRON_MILLISECONDS * MAXV2 / INCR2)   /* 50ms average deviation */
    fprintf (stdout, "Timer precision is good.\n");
  else if (cumDelta > 250 * GNUNET_CRON_MILLISECONDS * MAXV2 / INCR2)
    fprintf (stdout, "Timer precision is awful.\n");
  else
    fprintf (stdout, "Timer precision is acceptable.\n");

  GNUNET_semaphore_destroy (sem);
  return 0;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;

  cron = GNUNET_cron_create (NULL);
  GNUNET_cron_start (cron);
  failureCount += check ();
  GNUNET_cron_stop (cron);
  GNUNET_cron_destroy (cron);
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of timertest.c */
