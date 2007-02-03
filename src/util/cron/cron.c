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

#define DEBUG_CRON NO

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
typedef struct {

  /**
   * The method to call at that point.
   */
  CronJob method;

  /**
   * data ptr (argument to the method)
   */
  void * data;

  /**
   * The start-time for this event (in milliseconds).
   */
  cron_t delta;

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

typedef struct CronManager {

  /**
   * The lock for the delta-list.
   */
  struct MUTEX * deltaListLock_;

  /**
   * The delta-list of waiting tasks.
   */
  UTIL_cron_DeltaListEntry * deltaList_;

  /**
   * The currently running job.
   */
  CronJob runningJob_;

  void * runningData_;

  struct GE_Context * ectx;

  /**
   * The cron thread.
   */
  struct PTHREAD * cron_handle;

  struct SEMAPHORE * cron_signal;

  struct SEMAPHORE * cron_signal_up;

  struct MUTEX * inBlockLock_;

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

  struct SEMAPHORE * sig;

} CronManager;


struct CronManager * cron_create(struct GE_Context * ectx) {
  struct CronManager * cron;
  unsigned int i;

  cron = MALLOC(sizeof(CronManager));
  memset(cron, 0, sizeof(CronManager));
  cron->deltaListSize_ = INIT_CRON_JOBS;
  cron->deltaList_
    = MALLOC(sizeof(UTIL_cron_DeltaListEntry) * cron->deltaListSize_);
  for (i=0;i<cron->deltaListSize_;i++)
    cron->deltaList_[i].next = i-1;
  cron->firstFree_ = cron->deltaListSize_-1;
  cron->deltaListLock_ = MUTEX_CREATE(YES);
  cron->inBlockLock_ = MUTEX_CREATE(NO);
  cron->runningJob_ = NULL;
  cron->firstUsed_  = -1;
  cron->cron_signal_up = SEMAPHORE_CREATE(0);
  cron->ectx = ectx;
  cron->cron_shutdown = NO;
  cron->sig = NULL;
  return cron;
}


static void noJob(void * unused) {
#if DEBUG_CRON
  GE_LOG(NULL,
	 GE_STATUS | GE_DEVELOPER | GE_BULK,
	 "In noJob.\n");
#endif
}

void cron_stop(struct CronManager * cron) {
  void * unused;

#if DEBUG_CRON
  GE_LOG(cron->ectx,
	 GE_STATUS | GE_DEVELOPER | GE_BULK,
	 "Stopping cron\n");
#endif
  cron->cron_shutdown = YES;
  cron_add_job(cron,
	       &noJob,
	       0,
	       0,
	       NULL);
  SEMAPHORE_DOWN(cron->cron_signal, YES);
  SEMAPHORE_DESTROY(cron->cron_signal);
  cron->cron_signal = NULL;
  PTHREAD_JOIN(cron->cron_handle, &unused);
#if DEBUG_CRON
  GE_LOG(NULL,
	 GE_STATUS | GE_DEVELOPER | GE_BULK,
	 "Cron stopped\n");
#endif
}

/**
 * CronJob to suspend the cron thread
 * until it is resumed.
 */
static void block(void * cls) {
  struct CronManager * cron = cls;
  int ok = SYSERR;

  if (cron->sig != NULL)
    SEMAPHORE_UP(cron->sig);
  while (ok == SYSERR) {
    SEMAPHORE_DOWN(cron->cron_signal_up, YES);
    MUTEX_LOCK(cron->inBlockLock_);
    cron->inBlock--;
    if (cron->inBlock == 0)
      ok = OK;
    MUTEX_UNLOCK(cron->inBlockLock_);
  }
}
				
void cron_suspend(struct CronManager * cron,
		  int checkSelf) {
  if ( (YES == checkSelf) &&
       (cron->cron_shutdown == NO) &&
       (NO != PTHREAD_TEST_SELF(cron->cron_handle)) )
    return;
  GE_ASSERT(NULL, NO == PTHREAD_TEST_SELF(cron->cron_handle));
  MUTEX_LOCK(cron->inBlockLock_);
  cron->inBlock++;
  if (cron->inBlock == 1) {
    cron->sig = SEMAPHORE_CREATE(0);
    cron_add_job(cron,
		 &block,
		 0,
		 0,
		 cron);
    SEMAPHORE_DOWN(cron->sig, YES);
    SEMAPHORE_DESTROY(cron->sig);
    cron->sig = NULL;
  }
  MUTEX_UNLOCK(cron->inBlockLock_);
}

int cron_test_running(struct CronManager * cron) {
  if ( (NO == cron->cron_shutdown) || (cron->inBlock > 0) )
    return YES;
  else
    return NO;
}

void cron_resume_jobs(struct CronManager * cron,
		      int checkSelf) {
  if ( (YES == checkSelf) &&
       (cron->cron_shutdown == NO) &&
       (NO != PTHREAD_TEST_SELF(cron->cron_handle)) )
    return;
  GE_ASSERT(NULL, cron->inBlock > 0);
  SEMAPHORE_UP(cron->cron_signal_up);
}

static void abortSleep(struct CronManager * cron) {
  if (cron->cron_signal == NULL)
    return; /* cron_handle not valid */
  PTHREAD_STOP_SLEEP(cron->cron_handle);
}


#if HAVE_PRINT_CRON_TAB
/**
 * Print the cron-tab.
 */
void printCronTab(struct CronManager * cron) {
  int jobId;
  UTIL_cron_DeltaListEntry * tab;
  cron_t now;

  now = get_time();
  MUTEX_LOCK(cron->deltaListLock_);

  jobId = cron->firstUsed_;
  while (jobId != -1) {
    tab = &cron->deltaList_[jobId];
    GE_LOG(NULL,
	   GE_STATUS | GE_DEVELOPER | GE_BULK,
	   "%3u: delta %8lld CU --- method %p --- repeat %8u CU\n",
	   jobId,
	   tab->delta - now,
	   (int)tab->method,
	   tab->deltaRepeat);
    jobId = tab->next;
  }
  MUTEX_UNLOCK(cron->deltaListLock_);
}
#endif

void cron_advance_job(struct CronManager * cron,
		      CronJob method,
		      unsigned int deltaRepeat,
		      void * data) {
  UTIL_cron_DeltaListEntry * job;
  UTIL_cron_DeltaListEntry * last;
  int jobId;

#if DEBUG_CRON
  GE_LOG(NULL,
	 GE_STATUS | GE_DEVELOPER | GE_BULK,
	 "Advancing job %p-%p\n",
	 method,
	 data);
#endif
  MUTEX_LOCK(cron->deltaListLock_);
  jobId = cron->firstUsed_;
  if (jobId == -1) {
    /* not in queue - do nothing! */
    MUTEX_UNLOCK(cron->deltaListLock_);
    return;
  }
  last = NULL;
  job = &cron->deltaList_[jobId];
  while ( (job->method != method) ||
	  (job->data != data) ||
	  (job->deltaRepeat != deltaRepeat) ) {
    last = job;
    if (job->next == -1) {
      /* not in queue; add if not running */
      if ( (method != cron->runningJob_) ||
	   (data != cron->runningData_) ||
	   (deltaRepeat != cron->runningRepeat_) ) {
	cron_add_job(cron,
		     method,
		     0,
		     deltaRepeat,
		     data);
      }
      MUTEX_UNLOCK(cron->deltaListLock_);
      return;
    }
    jobId = job->next;
    job = &cron->deltaList_[jobId];
  }
  /* ok, found it; remove, re-add with time 0 */
  cron_del_job(cron,
	       method,
	       deltaRepeat,
	       data);
  cron_add_job(cron,
	       method,
	       0,
	       deltaRepeat,
	       data);
  MUTEX_UNLOCK(cron->deltaListLock_);
}

void cron_add_job(struct CronManager * cron,
		  CronJob method,
		  unsigned int delta,
		  unsigned int deltaRepeat,
		  void * data) {
  UTIL_cron_DeltaListEntry * entry;
  UTIL_cron_DeltaListEntry * pos;
  int last;
  int current;

#if DEBUG_CRON
  GE_LOG(cron->ectx,
	 GE_STATUS | GE_DEVELOPER | GE_BULK,
	 "Adding job %p-%p to fire in %d CU\n",
	 method,
	 data,
	 delta);
#endif

  MUTEX_LOCK(cron->deltaListLock_);
  if (cron->firstFree_ == -1) { /* need to grow */
    unsigned int i;

    GROW(cron->deltaList_,
	 cron->deltaListSize_,
	 cron->deltaListSize_ * 2);
    for (i=cron->deltaListSize_/2;i<cron->deltaListSize_;i++)
      cron->deltaList_[i].next = i-1;
    cron->deltaList_[cron->deltaListSize_/2].next = -1;
    cron->firstFree_ = cron->deltaListSize_-1;
  }
  entry = &cron->deltaList_[cron->firstFree_];
  entry->method = method;
  entry->data = data;
  entry->deltaRepeat = deltaRepeat;
  entry->delta = get_time() + delta;
  if (cron->firstUsed_ == -1) {
    cron->firstUsed_
      = cron->firstFree_;
    cron->firstFree_
      = entry->next;
    entry->next = -1; /* end of list */
    MUTEX_UNLOCK(cron->deltaListLock_);
    /* interrupt sleeping cron-thread! */
    abortSleep(cron);
    return;
  }
  /* no, there are jobs waiting */
  last = -1;
  current = cron->firstUsed_;
  pos = &cron->deltaList_[current];

  while (entry->delta > pos->delta) {
    if (pos->next != -1) {
      last = current;
      current = pos->next;
      pos = &cron->deltaList_[current];
    } else { /* append */
      pos->next = cron->firstFree_;
      cron->firstFree_
	= entry->next;
      entry->next = -1;
      MUTEX_UNLOCK(cron->deltaListLock_);
#if HAVE_PRINT_CRON_TAB
      printCronTab();
#endif
      return;
    }
  }
  /* insert before pos */
  if (last == -1) {
    cron->firstUsed_ = cron->firstFree_;
    abortSleep(cron);
  } else {
    cron->deltaList_[last].next = cron->firstFree_;
#if HAVE_PRINT_CRON_TAB
    printCronTab();
#endif
  }
  cron->firstFree_
    = entry->next;
  entry->next = current;
  MUTEX_UNLOCK(cron->deltaListLock_);
}

/**
 * Process the cron-job at the beginning of the waiting queue, that
 * is, remove, invoke, and re-insert if it is a periodical job. Make
 * sure the cron job is held when calling this method, but
 * note that it will be released briefly for the time
 * where the job is running (the job to run may add other
 * jobs!)
 */
static void runJob(struct CronManager * cron) {
  UTIL_cron_DeltaListEntry * job;
  int jobId;
  CronJob method;
  void * data;
  unsigned int repeat;

  jobId = cron->firstUsed_;
  if (jobId == -1)
    return; /* no job to be done */
  job    = &cron->deltaList_[jobId];
  method = job->method;
  cron->runningJob_ = method;
  data   = job->data;
  cron->runningData_ = data;
  repeat = job->deltaRepeat;
  cron->runningRepeat_ = repeat;
  /* remove from queue */
  cron->firstUsed_
    = job->next;
  job->next
    = cron->firstFree_;
  cron->firstFree_ = jobId;
  MUTEX_UNLOCK(cron->deltaListLock_);
  /* re-insert */
  if (repeat > 0) {
#if DEBUG_CRON
    GE_LOG(cron->ectx,
	   GE_STATUS | GE_DEVELOPER | GE_BULK,
	   "adding periodic job %p-%p to run again in %u\n",
	   method,
	   data,
	   repeat);
#endif
    cron_add_job(cron,
		 method,
		 repeat,
		 repeat,
		 data);
  }
  /* run */
#if DEBUG_CRON
  GE_LOG(cron->ectx,
	 GE_STATUS | GE_DEVELOPER | GE_BULK,
	 "running job %p-%p\n",
	 method,
	 data);
#endif
  method(data);
  MUTEX_LOCK(cron->deltaListLock_);
  cron->runningJob_ = NULL;
#if DEBUG_CRON
  GE_LOG(cron->ectx,
	 GE_STATUS | GE_DEVELOPER | GE_BULK,
	 "job %p-%p done\n",
	 method,
	 data);
#endif
}

/**
 * The main-method of cron.
 */
static void * cron_main_method(void * ctx) {
  struct CronManager * cron = ctx;
  cron_t now;
  cron_t next;

  while (cron->cron_shutdown == NO) {
#if HAVE_PRINT_CRON_TAB
    printCronTab(cron);
#endif
    now = get_time();
    next = now + 0xFFFFFFFF;
    MUTEX_LOCK(cron->deltaListLock_);
    while (cron->firstUsed_ != -1) {
      now = get_time();
      next = cron->deltaList_[cron->firstUsed_].delta;
      if (next <= now) {
#if DEBUG_CRON
	GE_LOG(cron->ectx,
	       GE_STATUS | GE_DEVELOPER | GE_BULK,
	       "running cron job, table is\n");
	printCronTab(cron);
#endif
	runJob(cron);
#if DEBUG_CRON
	GE_LOG(cron->ectx,
	       GE_STATUS | GE_DEVELOPER | GE_BULK,
	       "job run, new table is\n");
	printCronTab(cron);
#endif
      } else
	break;
    }
    MUTEX_UNLOCK(cron->deltaListLock_);
    next = next - now; /* how long to sleep */
#if DEBUG_CRON
    GE_LOG(cron->ectx,
	   GE_STATUS | GE_DEVELOPER | GE_BULK,
	   "Sleeping at %llu for %llu CU (%llu s, %llu CU)\n",
	   now,
	   next,
	   next / cronSECONDS,
	   next);
#endif
    if (next > MAXSLEEP)
      next = MAXSLEEP;
    if (cron->cron_shutdown == NO)
      PTHREAD_SLEEP(next);
#if DEBUG_CRON
    GE_LOG(cron->ectx,
	   GE_STATUS | GE_DEVELOPER | GE_BULK,
	   "woke up at  %llu - %lld CS late\n",
	   get_time(),
	   get_time() - (now+next));
#endif
  }
  SEMAPHORE_UP(cron->cron_signal);
#if DEBUG_CRON
  GE_LOG(cron->ectx,
	 GE_STATUS | GE_DEVELOPER | GE_BULK,
	 "Cron thread exits.\n");
  printCronTab(cron);
#endif
  return NULL;
}


/**
 * Make sure to call stopCron before calling this method!
 */
void cron_destroy(struct CronManager * cron) {
  int i;

  GE_ASSERT(cron->ectx,
	    cron->cron_signal == NULL);
  i = cron->firstUsed_;
  while (i != -1) {
    FREENONNULL(cron->deltaList_[i].data);
    i = cron->deltaList_[i].next;
  }
  MUTEX_DESTROY(cron->deltaListLock_);
  MUTEX_DESTROY(cron->inBlockLock_);
  FREE(cron->deltaList_);
  SEMAPHORE_DESTROY(cron->cron_signal_up);
  FREE(cron);
}

/**
 * Start the cron jobs.
 */
void cron_start(struct CronManager * cron) {
  GE_ASSERT(cron->ectx,
	    cron->cron_signal == NULL);
  cron->cron_shutdown = NO;
  cron->cron_signal = SEMAPHORE_CREATE(0);
  /* large stack, we don't know for sure
     what the cron jobs may be doing */
  cron->cron_handle = PTHREAD_CREATE(&cron_main_method,
				     cron,
				     256 * 1024);
  if (cron->cron_handle == 0)
    GE_DIE_STRERROR(cron->ectx,
		    GE_FATAL | GE_ADMIN | GE_USER | GE_BULK,
		    "pthread_create");
}

int cron_del_job(struct CronManager * cron,
		 CronJob method,
		 unsigned int repeat,
		 void * data) {
  UTIL_cron_DeltaListEntry * job;
  UTIL_cron_DeltaListEntry * last;
  int jobId;

#if DEBUG_CRON
  GE_LOG(cron->ectx,
	 GE_STATUS | GE_DEVELOPER | GE_BULK,
	 "deleting job %p-%p\n",
	 method,
	 data);
#endif
  MUTEX_LOCK(cron->deltaListLock_);
  jobId = cron->firstUsed_;
  if (jobId == -1) {
    MUTEX_UNLOCK(cron->deltaListLock_);
    return 0;
  }
  last = NULL;
  job = &cron->deltaList_[jobId];
  while ( (job->method != method) ||
	  (job->data != data) ||
	  (job->deltaRepeat != repeat) ) {
    last = job;
    if (job->next == -1) {
      MUTEX_UNLOCK(cron->deltaListLock_);
      return 0;
    }
    jobId = job->next;
    job = &cron->deltaList_[jobId];
  }
  if (last != NULL)
    last->next = job->next;
  else
    cron->firstUsed_ = job->next;
  job->next
    = cron->firstFree_;
  cron->firstFree_ = jobId;
  job->method = NULL;
  job->data = NULL;
  job->deltaRepeat = 0;
  MUTEX_UNLOCK(cron->deltaListLock_);
  return 1;
}





/* end of cron.c */
