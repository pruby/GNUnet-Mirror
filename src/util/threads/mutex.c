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

#include "platform.h"
#include "gnunet_util_threads.h"
#include "gnunet_util_error.h"
#include "gnunet_util_string.h"

#if SOLARIS || GNUNET_freeBSD || OSX
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
extern int pthread_mutexattr_setkind_np (pthread_mutexattr_t * attr,
                                         int kind);
#endif


typedef struct GNUNET_Mutex
{
  pthread_mutex_t pt;
  const char *locked_file;
  GNUNET_CronTime locked_time;
  unsigned int locked_line;
  unsigned int locked_depth;
} Mutex;

Mutex *
GNUNET_mutex_create (int isRecursive)
{
  pthread_mutexattr_t attr;
  Mutex *mut;
#if WINDOWS
  attr = NULL;
#endif

  pthread_mutexattr_init (&attr);
  if (isRecursive)
    {
#if LINUX
      GNUNET_GE_ASSERT (NULL,
                        0 == pthread_mutexattr_setkind_np
                        (&attr, PTHREAD_MUTEX_RECURSIVE_NP));
#elif SOMEBSD || GNUNET_freeBSD || GNUNET_freeBSD5
      GNUNET_GE_ASSERT (NULL,
                        0 == pthread_mutexattr_setkind_np
                        (&attr, PTHREAD_MUTEX_RECURSIVE));
#elif SOLARIS || OSX || WINDOWS
      GNUNET_GE_ASSERT (NULL,
                        0 == pthread_mutexattr_settype
                        (&attr, PTHREAD_MUTEX_RECURSIVE));
#endif
    }
  else
    {
#if LINUX
      GNUNET_GE_ASSERT (NULL,
                        0 == pthread_mutexattr_setkind_np
                        (&attr, PTHREAD_MUTEX_ERRORCHECK_NP));
#else
      GNUNET_GE_ASSERT (NULL,
                        0 == pthread_mutexattr_settype
                        (&attr, PTHREAD_MUTEX_ERRORCHECK));
#endif
    }
  mut = GNUNET_malloc (sizeof (Mutex));
  memset (mut, 0, sizeof (Mutex));
  GNUNET_GE_ASSERT (NULL, 0 == pthread_mutex_init (&mut->pt, &attr));
  return mut;
}

void
GNUNET_mutex_destroy (Mutex * mutex)
{
  int ret;
  GNUNET_GE_ASSERT (NULL, mutex != NULL);
  errno = 0;
  ret = pthread_mutex_destroy (&mutex->pt);
  GNUNET_GE_ASSERT (NULL, 0 == ret);
  GNUNET_free (mutex);
}

void
GNUNET_mutex_lock_at_file_line_ (Mutex * mutex, const char *file,
                                 unsigned int line)
{
  int ret;
  GNUNET_CronTime start;
  GNUNET_CronTime end;

  GNUNET_GE_ASSERT_FL (NULL, mutex != NULL, file, line);
  start = GNUNET_get_time ();
  ret = pthread_mutex_lock (&mutex->pt);
  end = GNUNET_get_time ();
  if ((end - start > GNUNET_REALTIME_LIMIT) && (GNUNET_REALTIME_LIMIT != 0))
    {
      GNUNET_GE_LOG (NULL,
                     GNUNET_GE_DEVELOPER | GNUNET_GE_WARNING |
                     GNUNET_GE_IMMEDIATE,
                     _("Real-time delay violation (%llu ms) at %s:%u\n"),
                     end - start, file, line);
    }
  if (ret != 0)
    {
      if (ret == EINVAL)
        GNUNET_GE_LOG (NULL,
                       GNUNET_GE_FATAL | GNUNET_GE_DEVELOPER | GNUNET_GE_USER
                       | GNUNET_GE_IMMEDIATE,
                       _("Invalid argument for `%s'.\n"),
                       "pthread_mutex_lock");
      if (ret == EDEADLK)
        GNUNET_GE_LOG (NULL,
                       GNUNET_GE_FATAL | GNUNET_GE_DEVELOPER | GNUNET_GE_USER
                       | GNUNET_GE_IMMEDIATE, _("Deadlock due to `%s'.\n"),
                       "pthread_mutex_lock");
      GNUNET_GE_ASSERT_FL (NULL, 0, file, line);
    }
  if (mutex->locked_depth++ == 0)
    {
      mutex->locked_file = file;
      mutex->locked_line = line;
      mutex->locked_time = end;
    }
}

void
GNUNET_mutex_unlock (Mutex * mutex)
{
  int ret;
  GNUNET_CronTime now;

  GNUNET_GE_ASSERT (NULL, mutex != NULL);
  if (0 == --mutex->locked_depth)
    {
      now = GNUNET_get_time ();
      if ((now - mutex->locked_time > GNUNET_REALTIME_LIMIT) &&
          (GNUNET_REALTIME_LIMIT != 0))
        GNUNET_GE_LOG (NULL,
                       GNUNET_GE_DEVELOPER | GNUNET_GE_WARNING |
                       GNUNET_GE_IMMEDIATE,
                       _("Lock acquired for too long (%llu ms) at %s:%u\n"),
                       now - mutex->locked_time, mutex->locked_file,
                       mutex->locked_line);
      mutex->locked_file = NULL;
      mutex->locked_line = 0;
      mutex->locked_time = 0;
    }
  ret = pthread_mutex_unlock (&mutex->pt);
  if (ret != 0)
    {
      if (ret == EINVAL)
        GNUNET_GE_LOG (NULL,
                       GNUNET_GE_FATAL | GNUNET_GE_DEVELOPER | GNUNET_GE_USER
                       | GNUNET_GE_IMMEDIATE,
                       _("Invalid argument for `%s'.\n"),
                       "pthread_mutex_lock");
      if (ret == EPERM)
        GNUNET_GE_LOG (NULL,
                       GNUNET_GE_FATAL | GNUNET_GE_DEVELOPER | GNUNET_GE_USER
                       | GNUNET_GE_IMMEDIATE,
                       _("Permission denied for `%s'.\n"),
                       "pthread_mutex_unlock");
      GNUNET_GE_ASSERT (NULL, 0);
    }
}

/* end of mutex.c */
