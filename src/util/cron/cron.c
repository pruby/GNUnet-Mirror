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
 * @file util/pthreads/cron.c
 * @author Christian Grothoff
 * @brief Module for periodic background (cron) jobs.
 *
 * The module only uses one thread, thus every cron-job must be
 * short-lived, should never block for an indefinite amount of
 * time. Specified deadlines are only a guide-line, the 10ms
 * timer-resolution is only an upper-bound on the possible precision,
 * in practice it will be worse (depending on the other cron-jobs).
 *
 * If you need to schedule a long-running or blocking cron-job,
 * run a function that will start another thread that will
 * then run the actual job.
 */

#include "gnunet_util.h"
#include "gnunet_util_cron.h"
#include "platform.h"

#define DEBUG_CRON GNUNET_NO

#if DEBUG_CRON
#define HAVE_PRINT_CRON_TAB 1
#else
#define HAVE_PRINT_CRON_TAB 0
#endif

/**
 * The initial size of the cron-job table
 */
#define INIT_CRON_JOBS 16

/**
 * how long do we sleep at most? In some systems, the
 * signal-interrupted sleep does not work nicely, so to ensure
 * progress, we should rather wake up periodically. (But we don't want
 * to burn too much CPU time doing busy waiting; every 2s strikes a
 * good balance)
 */
#define MAXSLEEP 2000

#define CHECK_ASSERTS 1

/* change this value to artificially speed up all
   GNUnet cron timers by this factor. E.g. with 10,
   a cron-job scheduled after 1 minute in the code
   will occur after 6 seconds. This is useful for
   testing bugs that would otherwise occur only after
   a long time.

   For releases, this value should always be 1 */
#define SPEED_UP 1

/** number of cron units (ms) in a second */
#define CRON_UNIT_TO_SECONDS (1000 / SPEED_UP)

/** number of us [usec] in a cron-unit (1000) */
#define MICROSEC_TO_CRON_UNIT (1000 * SPEED_UP)


/**
 * @brief The Delta-list for the cron jobs.
 */
typedef struct
{

  /**
   * The method to call at that point.
   */
  GNUNET_CronJob method;

  /**
   * data ptr (argument to the method)
   */
  void *data;

  /**
   * The start-time for this event (in milliseconds).
   */
  GNUNET_CronTime delta;

  /**
   * for cron-jobs: when this should be repeated
   * automatically, 0 if this was a once-only job
   */
  unsigned int deltaRepeat;

  /**
   * The index of the next entry in the delta list
   * after this one (-1 for none)
   */
  int next;

} UTIL_cron_DeltaListEntry;

typedef struct GNUNET_CronManager
{

  /**
   * The lock for the delta-list.
   */
  struct GNUNET_Mutex *deltaListLock_;

  /**
   * The delta-list of waiting tasks.
   */
  UTIL_cron_DeltaListEntry *deltaList_;

  /**
   * The currently running job.
   */
  GNUNET_CronJob runningJob_;

  void *runningData_;

  struct GNUNET_GE_Context *ectx;

  /**
   * The cron thread.
   */
  struct GNUNET_ThreadHandle *cron_handle;

  struct GNUNET_Semaphore *cron_signal;

  struct GNUNET_Semaphore *cron_signal_up;

  struct GNUNET_Mutex *inBlockLock_;

  unsigned int runningRepeat_;

  /**
   * The current size of the DeltaList.
   */
  unsigned int deltaListSize_;

  /**
   * The first empty slot in the delta-list.
   */
  int firstFree_;

  /**
   * The first empty slot in the delta-list.
   */
  int firstUsed_;

  /**
   * Set to yes if we are shutting down or shut down.
   */
  int cron_shutdown;

  /**
   * Are we in block?
   */
  int inBlock;

  struct GNUNET_Semaphore *sig;

} CronManager;


struct GNUNET_CronManager *
GNUNET_cron_create (struct GNUNET_GE_Context *ectx)
{
  struct GNUNET_CronManager *cron;
  unsigned int i;

  cron = GNUNET_malloc (sizeof (CronManager));
  memset (cron, 0, sizeof (CronManager));
  cron->deltaListSize_ = INIT_CRON_JOBS;
  cron->deltaList_
    =
    GNUNET_malloc (sizeof (UTIL_cron_DeltaListEntry) * cron->deltaListSize_);
  for (i = 0; i < cron->deltaListSize_; i++)
    cron->deltaList_[i].next = i - 1;
  cron->firstFree_ = cron->deltaListSize_ - 1;
  cron->deltaListLock_ = GNUNET_mutex_create (GNUNET_YES);
  cron->inBlockLock_ = GNUNET_mutex_create (GNUNET_NO);
  cron->runningJob_ = NULL;
  cron->firstUsed_ = -1;
  cron->cron_signal_up = GNUNET_semaphore_create (0);
  cron->ectx = ectx;
  cron->cron_shutdown = GNUNET_YES;
  cron->sig = NULL;
  return cron;
}


static void
noJob (void *unused)
{
#if DEBUG_CRON
  GNUNET_GE_LOG (NULL,
                 GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "In noJob.\n");
#endif
}

void
GNUNET_cron_stop (struct GNUNET_CronManager *cron)
{
  void *unused;

#if DEBUG_CRON
  GNUNET_GE_LOG (cron->ectx,
                 GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "Stopping cron\n");
#endif
  cron->cron_shutdown = GNUNET_YES;
  GNUNET_cron_add_job (cron, &noJob, 0, 0, NULL);
  GNUNET_semaphore_down (cron->cron_signal, GNUNET_YES);
  GNUNET_semaphore_destroy (cron->cron_signal);
  cron->cron_signal = NULL;
  GNUNET_thread_join (cron->cron_handle, &unused);
#if DEBUG_CRON
  GNUNET_GE_LOG (NULL,
                 GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "Cron stopped\n");
#endif
}

/**
 * GNUNET_CronJob to suspend the cron thread
 * until it is resumed.
 */
static void
block (void *cls)
{
  struct GNUNET_CronManager *cron = cls;
  int ok = GNUNET_SYSERR;

  if (cron->sig != NULL)
    GNUNET_semaphore_up (cron->sig);
  while (ok == GNUNET_SYSERR)
    {
      GNUNET_semaphore_down (cron->cron_signal_up, GNUNET_YES);
      GNUNET_mutex_lock (cron->inBlockLock_);
      cron->inBlock--;
      if (cron->inBlock == 0)
        ok = GNUNET_OK;
      GNUNET_mutex_unlock (cron->inBlockLock_);
    }
}

void
GNUNET_cron_suspend_jobs (struct GNUNET_CronManager *cron, int checkSelf)
{
  if ((GNUNET_YES == checkSelf) &&
      (cron->cron_shutdown == GNUNET_NO) &&
      (GNUNET_NO != GNUNET_thread_test_self (cron->cron_handle)))
    return;
  GNUNET_GE_ASSERT (NULL,
                    GNUNET_NO == GNUNET_thread_test_self (cron->cron_handle));
  GNUNET_mutex_lock (cron->inBlockLock_);
  cron->inBlock++;
  if (cron->inBlock == 1)
    {
      cron->sig = GNUNET_semaphore_create (0);
      GNUNET_cron_add_job (cron, &block, 0, 0, cron);
      GNUNET_semaphore_down (cron->sig, GNUNET_YES);
      GNUNET_semaphore_destroy (cron->sig);
      cron->sig = NULL;
    }
  GNUNET_mutex_unlock (cron->inBlockLock_);
}

int
GNUNET_cron_test_running (struct GNUNET_CronManager *cron)
{
  if ((GNUNET_NO == cron->cron_shutdown) || (cron->inBlock > 0))
    return GNUNET_YES;
  else
    return GNUNET_NO;
}

void
GNUNET_cron_resume_jobs (struct GNUNET_CronManager *cron, int checkSelf)
{
  if ((GNUNET_YES == checkSelf) &&
      (cron->cron_shutdown == GNUNET_NO) &&
      (GNUNET_NO != GNUNET_thread_test_self (cron->cron_handle)))
    return;
  GNUNET_GE_ASSERT (NULL, cron->inBlock > 0);
  GNUNET_semaphore_up (cron->cron_signal_up);
}

static void
abortSleep (struct GNUNET_CronManager *cron)
{
  if (cron->cron_signal == NULL)
    return;                     /* cron_handle not valid */
  GNUNET_thread_stop_sleep (cron->cron_handle);
}


#if HAVE_PRINT_CRON_TAB
/**
 * Print the cron-tab.
 */
void
printCronTab (struct GNUNET_CronManager *cron)
{
  int jobId;
  UTIL_cron_DeltaListEntry *tab;
  GNUNET_CronTime now;

  now = GNUNET_get_time ();
  GNUNET_mutex_lock (cron->deltaListLock_);

  jobId = cron->firstUsed_;
  while (jobId != -1)
    {
      tab = &cron->deltaList_[jobId];
      GNUNET_GE_LOG (NULL,
                     GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                     "%3u: delta %8lld CU --- method %p --- repeat %8u CU\n",
                     jobId, tab->delta - now, (int) tab->method,
                     tab->deltaRepeat);
      jobId = tab->next;
    }
  GNUNET_mutex_unlock (cron->deltaListLock_);
}
#endif

void
GNUNET_cron_advance_job (struct GNUNET_CronManager *cron,
                         GNUNET_CronJob method, unsigned int deltaRepeat,
                         void *data)
{
  UTIL_cron_DeltaListEntry *job;
  UTIL_cron_DeltaListEntry *last;
  int jobId;

#if DEBUG_CRON
  GNUNET_GE_LOG (NULL,
                 GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "Advancing job %p-%p\n", method, data);
#endif
  GNUNET_mutex_lock (cron->deltaListLock_);
  jobId = cron->firstUsed_;
  if (jobId == -1)
    {
      /* not in queue - do nothing! */
      GNUNET_mutex_unlock (cron->deltaListLock_);
      return;
    }
  last = NULL;
  job = &cron->deltaList_[jobId];
  while ((job->method != method) ||
         (job->data != data) || (job->deltaRepeat != deltaRepeat))
    {
      last = job;
      if (job->next == -1)
        {
          /* not in queue; add if not running */
          if ((method != cron->runningJob_) ||
              (data != cron->runningData_) ||
              (deltaRepeat != cron->runningRepeat_))
            {
              GNUNET_cron_add_job (cron, method, 0, deltaRepeat, data);
            }
          GNUNET_mutex_unlock (cron->deltaListLock_);
          return;
        }
      jobId = job->next;
      job = &cron->deltaList_[jobId];
    }
  /* ok, found it; remove, re-add with time 0 */
  GNUNET_cron_del_job (cron, method, deltaRepeat, data);
  GNUNET_cron_add_job (cron, method, 0, deltaRepeat, data);
  GNUNET_mutex_unlock (cron->deltaListLock_);
}

void
GNUNET_cron_add_job (struct GNUNET_CronManager *cron,
                     GNUNET_CronJob method,
                     unsigned int delta, unsigned int deltaRepeat, void *data)
{
  UTIL_cron_DeltaListEntry *entry;
  UTIL_cron_DeltaListEntry *pos;
  int last;
  int current;

#if DEBUG_CRON
  GNUNET_GE_LOG (cron->ectx,
                 GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "Adding job %p-%p to fire in %d CU\n", method, data, delta);
#endif

  GNUNET_mutex_lock (cron->deltaListLock_);
  if (cron->firstFree_ == -1)
    {                           /* need to grow */
      unsigned int i;

      GNUNET_array_grow (cron->deltaList_, cron->deltaListSize_,
                         cron->deltaListSize_ * 2);
      for (i = cron->deltaListSize_ / 2; i < cron->deltaListSize_; i++)
        cron->deltaList_[i].next = i - 1;
      cron->deltaList_[cron->deltaListSize_ / 2].next = -1;
      cron->firstFree_ = cron->deltaListSize_ - 1;
    }
  entry = &cron->deltaList_[cron->firstFree_];
  entry->method = method;
  entry->data = data;
  entry->deltaRepeat = deltaRepeat;
  entry->delta = GNUNET_get_time () + delta;
  if (cron->firstUsed_ == -1)
    {
      cron->firstUsed_ = cron->firstFree_;
      cron->firstFree_ = entry->next;
      entry->next = -1;         /* end of list */
      GNUNET_mutex_unlock (cron->deltaListLock_);
      /* interrupt sleeping cron-thread! */
      abortSleep (cron);
      return;
    }
  /* no, there are jobs waiting */
  last = -1;
  current = cron->firstUsed_;
  pos = &cron->deltaList_[current];

  while (entry->delta > pos->delta)
    {
      if (pos->next != -1)
        {
          last = current;
          current = pos->next;
          pos = &cron->deltaList_[current];
        }
      else
        {                       /* append */
          pos->next = cron->firstFree_;
          cron->firstFree_ = entry->next;
          entry->next = -1;
          GNUNET_mutex_unlock (cron->deltaListLock_);
#if HAVE_PRINT_CRON_TAB
          printCronTab ();
#endif
          return;
        }
    }
  /* insert before pos */
  if (last == -1)
    {
      cron->firstUsed_ = cron->firstFree_;
      abortSleep (cron);
    }
  else
    {
      cron->deltaList_[last].next = cron->firstFree_;
#if HAVE_PRINT_CRON_TAB
      printCronTab ();
#endif
    }
  cron->firstFree_ = entry->next;
  entry->next = current;
  GNUNET_mutex_unlock (cron->deltaListLock_);
}

/**
 * Process the cron-job at the beginning of the waiting queue, that
 * is, remove, invoke, and re-insert if it is a periodical job. Make
 * sure the cron job is held when calling this method, but
 * note that it will be released briefly for the time
 * where the job is running (the job to run may add other
 * jobs!)
 */
static void
runJob (struct GNUNET_CronManager *cron)
{
  UTIL_cron_DeltaListEntry *job;
  int jobId;
  GNUNET_CronJob method;
  void *data;
  unsigned int repeat;

  jobId = cron->firstUsed_;
  if (jobId == -1)
    return;                     /* no job to be done */
  job = &cron->deltaList_[jobId];
  method = job->method;
  cron->runningJob_ = method;
  data = job->data;
  cron->runningData_ = data;
  repeat = job->deltaRepeat;
  cron->runningRepeat_ = repeat;
  /* remove from queue */
  cron->firstUsed_ = job->next;
  job->next = cron->firstFree_;
  cron->firstFree_ = jobId;
  GNUNET_mutex_unlock (cron->deltaListLock_);
  /* re-insert */
  if (repeat > 0)
    {
#if DEBUG_CRON
      GNUNET_GE_LOG (cron->ectx,
                     GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                     "adding periodic job %p-%p to run again in %u\n",
                     method, data, repeat);
#endif
      GNUNET_cron_add_job (cron, method, repeat, repeat, data);
    }
  /* run */
#if DEBUG_CRON
  GNUNET_GE_LOG (cron->ectx,
                 GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "running job %p-%p\n", method, data);
#endif
  method (data);
  GNUNET_mutex_lock (cron->deltaListLock_);
  cron->runningJob_ = NULL;
#if DEBUG_CRON
  GNUNET_GE_LOG (cron->ectx,
                 GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "job %p-%p done\n", method, data);
#endif
}

/**
 * The main-method of cron.
 */
static void *
cron_main_method (void *ctx)
{
  struct GNUNET_CronManager *cron = ctx;
  GNUNET_CronTime now;
  GNUNET_CronTime next;

  while (cron->cron_shutdown == GNUNET_NO)
    {
#if HAVE_PRINT_CRON_TAB
      printCronTab (cron);
#endif
      now = GNUNET_get_time ();
      next = now + 0xFFFFFFFF;
      GNUNET_mutex_lock (cron->deltaListLock_);
      while ((cron->cron_shutdown == GNUNET_NO) && (cron->firstUsed_ != -1))
        {
          now = GNUNET_get_time ();
          next = cron->deltaList_[cron->firstUsed_].delta;
          if (next <= now)
            {
#if DEBUG_CRON
              GNUNET_GE_LOG (cron->ectx,
                             GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_BULK, "running cron job, table is\n");
              printCronTab (cron);
#endif
              runJob (cron);
#if DEBUG_CRON
              GNUNET_GE_LOG (cron->ectx,
                             GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_BULK, "job run, new table is\n");
              printCronTab (cron);
#endif
            }
          else
            break;
        }
      GNUNET_mutex_unlock (cron->deltaListLock_);
      next = next - now;        /* how long to sleep */
#if DEBUG_CRON
      GNUNET_GE_LOG (cron->ectx,
                     GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                     "Sleeping at %llu for %llu CU (%llu s, %llu CU)\n",
                     now, next, next / GNUNET_CRON_SECONDS, next);
#endif
      if (next > MAXSLEEP)
        next = MAXSLEEP;
      if (cron->cron_shutdown == GNUNET_NO)
        GNUNET_thread_sleep (next);
#if DEBUG_CRON
      GNUNET_GE_LOG (cron->ectx,
                     GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                     "woke up at  %llu - %lld CS late\n",
                     GNUNET_get_time (), GNUNET_get_time () - (now + next));
#endif
    }
  GNUNET_semaphore_up (cron->cron_signal);
#if DEBUG_CRON
  GNUNET_GE_LOG (cron->ectx,
                 GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "Cron thread exits.\n");
  printCronTab (cron);
#endif
  return NULL;
}


/**
 * Make sure to call stopCron before calling this method!
 */
void
GNUNET_cron_destroy (struct GNUNET_CronManager *cron)
{
  int i;

  GNUNET_GE_ASSERT (cron->ectx, cron->cron_signal == NULL);
  i = cron->firstUsed_;
  while (i != -1)
    {
      GNUNET_free_non_null (cron->deltaList_[i].data);
      i = cron->deltaList_[i].next;
    }
  GNUNET_mutex_destroy (cron->deltaListLock_);
  GNUNET_mutex_destroy (cron->inBlockLock_);
  GNUNET_free (cron->deltaList_);
  GNUNET_semaphore_destroy (cron->cron_signal_up);
  GNUNET_free (cron);
}

/**
 * Start the cron jobs.
 */
void
GNUNET_cron_start (struct GNUNET_CronManager *cron)
{
  GNUNET_GE_ASSERT (cron->ectx, cron->cron_signal == NULL);
  cron->cron_shutdown = GNUNET_NO;
  cron->cron_signal = GNUNET_semaphore_create (0);
  /* large stack, we don't know for sure
     what the cron jobs may be doing */
  cron->cron_handle =
    GNUNET_thread_create (&cron_main_method, cron, 256 * 1024);
  if (cron->cron_handle == 0)
    GNUNET_GE_DIE_STRERROR (cron->ectx,
                            GNUNET_GE_FATAL | GNUNET_GE_ADMIN | GNUNET_GE_USER
                            | GNUNET_GE_BULK, "pthread_create");
}

int
GNUNET_cron_del_job (struct GNUNET_CronManager *cron,
                     GNUNET_CronJob method, unsigned int repeat, void *data)
{
  UTIL_cron_DeltaListEntry *job;
  UTIL_cron_DeltaListEntry *last;
  int jobId;

#if DEBUG_CRON
  GNUNET_GE_LOG (cron->ectx,
                 GNUNET_GE_STATUS | GNUNET_GE_DEVELOPER | GNUNET_GE_BULK,
                 "deleting job %p-%p\n", method, data);
#endif
  GNUNET_mutex_lock (cron->deltaListLock_);
  jobId = cron->firstUsed_;
  if (jobId == -1)
    {
      GNUNET_mutex_unlock (cron->deltaListLock_);
      return 0;
    }
  last = NULL;
  job = &cron->deltaList_[jobId];
  while ((job->method != method) ||
         (job->data != data) || (job->deltaRepeat != repeat))
    {
      last = job;
      if (job->next == -1)
        {
          GNUNET_mutex_unlock (cron->deltaListLock_);
          return 0;
        }
      jobId = job->next;
      job = &cron->deltaList_[jobId];
    }
  if (last != NULL)
    last->next = job->next;
  else
    cron->firstUsed_ = job->next;
  job->next = cron->firstFree_;
  cron->firstFree_ = jobId;
  job->method = NULL;
  job->data = NULL;
  job->deltaRepeat = 0;
  GNUNET_mutex_unlock (cron->deltaListLock_);
  return 1;
}





/* end of cron.c */
