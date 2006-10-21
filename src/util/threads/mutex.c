/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file util/threads/mutex.c
 * @brief implementation of mutual exclusion
 */

#include "gnunet_util_threads.h"
#include "gnunet_util_error.h"
#include "gnunet_util_string.h"
#include "platform.h"

#if SOLARIS || FREEBSD || OSX
#include <semaphore.h>
#endif
#if SOMEBSD
# include <pthread_np.h>
# include <sys/file.h>
#endif
#if LINUX
# include <sys/sem.h>
#endif
#ifdef _MSC_VER
#include <pthread.h>
#include <semaphore.h>
#endif

#ifndef PTHREAD_MUTEX_NORMAL
#ifdef PTHREAD_MUTEX_TIMED_NP
#define PTHREAD_MUTEX_NORMAL PTHREAD_MUTEX_TIMED_NP
#else
#define PTHREAD_MUTEX_NORMAL NULL
#endif
#endif

/**
 * This prototype is somehow missing in various Linux pthread
 * include files. But we need it and it seems to be available
 * on all pthread-systems so far. Odd.
 */
#ifndef _MSC_VER
extern int pthread_mutexattr_setkind_np(pthread_mutexattr_t *attr,
					int kind);
#endif


typedef struct MUTEX {
  pthread_mutex_t pt;
} Mutex;

Mutex * MUTEX_CREATE(int isRecursive) {
  pthread_mutexattr_t attr;
  Mutex * mut;
#if WINDOWS
  attr = NULL;
#endif

  pthread_mutexattr_init(&attr);
  if (isRecursive) {
#if LINUX
    GE_ASSERT(NULL,
	      0 == pthread_mutexattr_setkind_np
	      (&attr,
	       PTHREAD_MUTEX_RECURSIVE_NP));
#elif SOMEBSD || FREEBSD || FREEBSD5
    GE_ASSERT(NULL,
	      0 == pthread_mutexattr_setkind_np
	      (&attr,
	       PTHREAD_MUTEX_RECURSIVE));
#elif SOLARIS || OSX || WINDOWS
    GE_ASSERT(NULL,
	      0 == pthread_mutexattr_settype
	      (&attr,
	       PTHREAD_MUTEX_RECURSIVE));
#endif
  } else {
#if LINUX
    GE_ASSERT(NULL,
	      0 == pthread_mutexattr_setkind_np
	      (&attr,
	       PTHREAD_MUTEX_ERRORCHECK_NP));
#else
    GE_ASSERT(NULL,
	      0 == pthread_mutexattr_settype
	      (&attr,
	       PTHREAD_MUTEX_ERRORCHECK));
#endif
  }
  mut = MALLOC(sizeof(Mutex));
  GE_ASSERT(NULL,
	    0 == pthread_mutex_init(&mut->pt,
				    &attr));
  return mut;
}

void MUTEX_DESTROY(Mutex * mutex) {
  GE_ASSERT(NULL, mutex != NULL);
  errno = 0;
  GE_ASSERT(NULL,
	    0 == pthread_mutex_destroy(&mutex->pt));
  FREE(mutex);
}

#define DEBUG_LOCK_DELAY NO

void MUTEX_LOCK(Mutex * mutex) {
  int ret;
#if DEBUG_LOCK_DELAY
  cron_t start;
#endif

  GE_ASSERT(NULL, mutex != NULL);
#if DEBUG_LOCK_DELAY
  start = get_time();
#endif
  ret = pthread_mutex_lock(&mutex->pt);
#if DEBUG_LOCK_DELAY
  start = get_time() - start;
  if (start > 10)
    printf("Locking took %llu ms!\n",
	   start);
#endif
  if (ret != 0) {
    if (ret == EINVAL)
      GE_LOG(NULL,
	     GE_FATAL | GE_DEVELOPER | GE_USER | GE_IMMEDIATE,
	     _("Invalid argument for `%s'.\n"),
	     "pthread_mutex_lock");
    if (ret == EDEADLK)
      GE_LOG(NULL,
	     GE_FATAL | GE_DEVELOPER | GE_USER | GE_IMMEDIATE,
	     _("Deadlock due to `%s'.\n"),
	      "pthread_mutex_lock");
    GE_ASSERT(NULL, 0);
  }
}

void MUTEX_UNLOCK(Mutex * mutex) {
  int ret;

  GE_ASSERT(NULL, mutex != NULL);
  ret = pthread_mutex_unlock(&mutex->pt);
  if (ret != 0) {
    if (ret == EINVAL)
      GE_LOG(NULL,
	     GE_FATAL | GE_DEVELOPER | GE_USER | GE_IMMEDIATE,
	     _("Invalid argument for `%s'.\n"),
	     "pthread_mutex_lock");
    if (ret == EPERM)
      GE_LOG(NULL,
	     GE_FATAL | GE_DEVELOPER | GE_USER | GE_IMMEDIATE,
	     _("Permission denied for `%s'.\n"),
	     "pthread_mutex_unlock");
    GE_ASSERT(NULL, 0);
  }
}

/* end of mutex.c */
