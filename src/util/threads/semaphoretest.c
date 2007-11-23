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
 * @file util/threads/semaphoretest.c
 * @brief testcase for util/threads/semaphore.c
 */

#include "gnunet_util.h"
#include "platform.h"

#include <sys/types.h>

static struct GNUNET_Mutex *lock;

static struct GNUNET_Semaphore *sem;

static volatile int sv;

static volatile int tv;

static void *
lockIt (void *unused)
{
  sv = 0;
  while (sv == 0)
    GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);        /* busy waiting may not always work */
  GNUNET_mutex_lock (lock);
  sv = 1;
  GNUNET_mutex_unlock (lock);
  sv = 2;
  tv = 2;
  return NULL;
}

static void *
bigStack (void *unused)
{
  int i;
  char big[1024 * 100];

  for (i = 0; i < 1024 * 100; i++)
    big[i] = (char) i;
  return NULL;
}

static int
testPTHREAD_CREATE ()
{
  struct GNUNET_ThreadHandle *pt;
  void *unused;

  sv = -1;
  tv = 0;
  lock = GNUNET_mutex_create (GNUNET_NO);
  pt = GNUNET_thread_create (&lockIt, NULL, 1024);
  while (tv != 2)
    {
      sv = 1;
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);      /* busy waiting may not always work */
    }
  GNUNET_thread_join (pt, &unused);
  GNUNET_mutex_destroy (lock);
  pt = GNUNET_thread_create (&bigStack, NULL, 1024 * 100 + 25000);      /* fails by segfault */
  GNUNET_thread_join (pt, &unused);
  return 0;
}

static int
testMutex ()
{
  struct GNUNET_ThreadHandle *pt;
  void *unused;

  lock = GNUNET_mutex_create (GNUNET_NO);

  sv = 1;
  tv = 0;
  pt = GNUNET_thread_create (&lockIt, NULL, 1024);
  while (sv == 1)
    GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);        /* busy waiting may not always work */
  GNUNET_mutex_lock (lock);
  sv = 5;                       /* release lockIt from while sv==0 loop,
                                   blocks it on lock */

  if (sv != 5)
    {
      GNUNET_mutex_unlock (lock);
      while (tv != 2)
        GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);    /* busy waiting may not always work */
      GNUNET_mutex_destroy (lock);
      printf ("MUTEX test failed at %s:%u\n", __FILE__, __LINE__);
      return 1;                 /* error */
    }
  else
    {
      GNUNET_mutex_unlock (lock);
      while (tv != 2)
        GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);    /* busy waiting may not always work */
      GNUNET_thread_join (pt, &unused);
      GNUNET_mutex_destroy (lock);
      return 0;                 /* ok */
    }
}

static int
testRecursiveMutex ()
{
  int i;

  lock = GNUNET_mutex_create (GNUNET_YES);
  for (i = 0; i < 50; i++)
    GNUNET_mutex_lock (lock);
  for (i = 0; i < 50; i++)
    GNUNET_mutex_unlock (lock);
  GNUNET_mutex_destroy (lock);
  return 0;                     /* ok -- fails by hanging! */
}

static void *
semUpDown (void *unused)
{
  int i;

  for (i = 0; i < 42; i++)
    GNUNET_semaphore_down (sem, GNUNET_YES);    /* fails by blocking */
  if (GNUNET_semaphore_down (sem, GNUNET_NO) != GNUNET_SYSERR)
    {
      GNUNET_semaphore_destroy (sem);
      printf ("GNUNET_semaphore_down_NONBLOCKING failed at %s:%u\n"
              "Testcase deadlocked.\n", __FILE__, __LINE__);
      return NULL;              /* will halt testcase! */
    }
  for (i = 0; i < 42; i++)
    GNUNET_semaphore_up (sem);
  return NULL;
}

static int
testSemaphore ()
{
  int i;
  struct GNUNET_ThreadHandle *pt;
  void *unused;

  sem = GNUNET_semaphore_create (42);
  for (i = 0; i < 42; i++)
    GNUNET_semaphore_down (sem, GNUNET_YES);    /* fails by blocking */
  if (GNUNET_semaphore_down (sem, GNUNET_NO) != GNUNET_SYSERR)
    {
      GNUNET_semaphore_destroy (sem);
      printf ("GNUNET_semaphore_down_NONBLOCKING failed at %s:%u\n",
              __FILE__, __LINE__);
      return 1;
    }
  for (i = 0; i < 42; i++)
    GNUNET_semaphore_up (sem);
  for (i = 0; i < 42; i++)
    if (GNUNET_SYSERR == GNUNET_semaphore_down (sem, GNUNET_NO))
      {
        GNUNET_semaphore_destroy (sem);
        printf
          ("GNUNET_semaphore_down_NONBLOCKING failed at %s:%u iteration %d\n",
           __FILE__, __LINE__, i);
        return 1;
      }
  if (GNUNET_semaphore_down (sem, GNUNET_NO) != GNUNET_SYSERR)
    {
      GNUNET_semaphore_destroy (sem);
      printf ("GNUNET_semaphore_down_NONBLOCKING failed at %s:%u\n",
              __FILE__, __LINE__);
      return 1;
    }
  pt = GNUNET_thread_create (&semUpDown, NULL, 1024);
  for (i = 0; i < 42; i++)
    GNUNET_semaphore_up (sem);
  GNUNET_thread_join (pt, &unused);
  for (i = 0; i < 42; i++)
    GNUNET_semaphore_down (sem, GNUNET_YES);
  if (GNUNET_semaphore_down (sem, GNUNET_NO) != GNUNET_SYSERR)
    {
      GNUNET_semaphore_destroy (sem);
      printf ("GNUNET_semaphore_down_NONBLOCKING failed at %s:%u\n",
              __FILE__, __LINE__);
      return 1;
    }
  return 0;
}

int
main (int argc, char *argv[])
{
  int ret = 0;

  ret += testPTHREAD_CREATE ();
  ret += testMutex ();
  ret += testRecursiveMutex ();
  ret += testSemaphore ();
  return ret;
}
