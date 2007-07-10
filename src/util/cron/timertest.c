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
  struct SEMAPHORE *sem = ctx;
  SEMAPHORE_UP (sem);
}

static struct CronManager *cron;

static int
check ()
{
  struct SEMAPHORE *sem;
  unsigned long long cumDelta;
  cron_t now;
  cron_t last;
  int i;

  sem = SEMAPHORE_CREATE (0);

  cumDelta = 0;

#define MAXV2 1500
#define INCR2 113
  for (i = 50; i < MAXV2 + 50; i += INCR2)
    {
      last = get_time ();
      cron_add_job (cron, &semaphore_up, i * cronMILLIS, 0, sem);
      SEMAPHORE_DOWN (sem, YES);
      now = get_time ();
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
  if (cumDelta <= 10 * cronMILLIS * MAXV2 / INCR2)
    fprintf (stdout, "Timer precision is excellent.\n");
  else if (cumDelta <= 50 * cronMILLIS * MAXV2 / INCR2) /* 50ms average deviation */
    fprintf (stdout, "Timer precision is good.\n");
  else if (cumDelta > 250 * cronMILLIS * MAXV2 / INCR2)
    fprintf (stdout, "Timer precision is awful.\n");
  else
    fprintf (stdout, "Timer precision is acceptable.\n");

  SEMAPHORE_DESTROY (sem);
  return 0;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;

  cron = cron_create (NULL);
  cron_start (cron);
  failureCount += check ();
  cron_stop (cron);
  cron_destroy (cron);
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of timertest.c */
