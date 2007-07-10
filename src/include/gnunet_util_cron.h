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
 * @file include/gnunet_util_cron.h
 * @brief periodic job runner
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_UTIL_CRON_H
#define GNUNET_UTIL_CRON_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util.h"

/**
 * Type of a cron-job method.
 */
typedef void (*CronJob) (void *);

struct CronManager;

struct CronManager *cron_create (struct GE_Context *ectx);

void cron_destroy (struct CronManager *mgr);

void cron_start (struct CronManager *mgr);

void cron_stop (struct CronManager *mgr);

/**
 * Stop running cron-jobs for a short time.  This method may only be
 * called by a thread that is not holding any locks.  It will cause
 * a deadlock if this method is called from within a cron-job and
 * checkself is NO.  If checkself is YES and this method is called
 * within a cron-job, nothing happens.
 *
 * @param checkself, if YES and this thread is the cron thread, do nothing
 */
void cron_suspend (struct CronManager *mgr, int checkself);

/**
 * Resume running cron-jobs.  Call must be matched by
 * previous call to cron_suspend_jobs with identical
 * arguments.
 *
 * @param checkself, if YES and this thread is the cron thread, do nothing
 */
void cron_resume_jobs (struct CronManager *mgr, int checkself);

/**
 * Is the cron-thread currently running?
 */
int cron_test_running (struct CronManager *mgr);

/**
 * Add a cron-job to the delta list.
 * @param method which method should we run
 * @param delta how many milliseconds until we run the method
 * @param deltaRepeat if this is a periodic, the time between
 *        the runs, otherwise 0.
 * @param data argument to pass to the method
 */
void cron_add_job (struct CronManager *mgr,
                   CronJob method,
                   unsigned int delta, unsigned int deltaRepeat, void *data);

/**
 * If the specified cron-job exists in th delta-list, move it to the
 * head of the list.  If it is running, do nothing.  If it is does not
 * exist and is not running, add it to the list to run it next.
 *
 * @param method which method should we run
 * @param deltaRepeat if this is a periodic, the time between
 *        the runs, otherwise 0.
 * @param data extra argument to calls to method, freed if
 *        non-null and cron is shutdown before the job is
 *        run and/or delCronJob is called
 */
void cron_advance_job (struct CronManager *mgr,
                       CronJob method, unsigned int deltaRepeat, void *data);

/**
 * Remove first matching cron-job from the list. This method should
 * only be called while cron is suspended or stopped, or from a cron
 * job that deletes another cron job.  If cron is not suspended or
 * stopped, it may be running the method that is to be deleted, which
 * could be bad (in this case, the deletion will not affect the
 * running job and may return before the running job has terminated).
 *
 * @param method which method is listed?
 * @param repeat which repeat factor was chosen?
 * @param data what was the data given to the method
 * @return the number of jobs removed (0 or 1)
 */
int cron_del_job (struct CronManager *mgr,
                  CronJob method, unsigned int repeat, void *data);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_UTIL_CRON_H */
#endif
/* end of gnunet_util_cron.h */
