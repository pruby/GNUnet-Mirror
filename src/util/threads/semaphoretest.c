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

static struct MUTEX *lock;

static struct SEMAPHORE *sem;

static volatile int sv;

static volatile int tv;

static void *
lockIt (void *unused)
{
  sv = 0;
  while (sv == 0)
    PTHREAD_SLEEP (50 * cronMILLIS);    /* busy waiting may not always work */
  MUTEX_LOCK (lock);
  sv = 1;
  MUTEX_UNLOCK (lock);
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
  struct PTHREAD *pt;
  void *unused;

  sv = -1;
  tv = 0;
  lock = MUTEX_CREATE (NO);
  pt = PTHREAD_CREATE (&lockIt, NULL, 1024);
  while (tv != 2)
    {
      sv = 1;
      PTHREAD_SLEEP (50 * cronMILLIS);  /* busy waiting may not always work */
    }
  PTHREAD_JOIN (pt, &unused);
  MUTEX_DESTROY (lock);
  pt = PTHREAD_CREATE (&bigStack, NULL, 1024 * 100 + 25000);    /* fails by segfault */
  PTHREAD_JOIN (pt, &unused);
  return 0;
}

static int
testMutex ()
{
  struct PTHREAD *pt;
  void *unused;

  lock = MUTEX_CREATE (NO);

  sv = 1;
  tv = 0;
  pt = PTHREAD_CREATE (&lockIt, NULL, 1024);
  while (sv == 1)
    PTHREAD_SLEEP (50 * cronMILLIS);    /* busy waiting may not always work */
  MUTEX_LOCK (lock);
  sv = 5;                       /* release lockIt from while sv==0 loop,
                                   blocks it on lock */

  if (sv != 5)
    {
      MUTEX_UNLOCK (lock);
      while (tv != 2)
        PTHREAD_SLEEP (50 * cronMILLIS);        /* busy waiting may not always work */
      MUTEX_DESTROY (lock);
      printf ("MUTEX test failed at %s:%u\n", __FILE__, __LINE__);
      return 1;                 /* error */
    }
  else
    {
      MUTEX_UNLOCK (lock);
      while (tv != 2)
        PTHREAD_SLEEP (50 * cronMILLIS);        /* busy waiting may not always work */
      PTHREAD_JOIN (pt, &unused);
      MUTEX_DESTROY (lock);
      return 0;                 /* ok */
    }
}

static int
testRecursiveMutex ()
{
  int i;

  lock = MUTEX_CREATE (YES);
  for (i = 0; i < 50; i++)
    MUTEX_LOCK (lock);
  for (i = 0; i < 50; i++)
    MUTEX_UNLOCK (lock);
  MUTEX_DESTROY (lock);
  return 0;                     /* ok -- fails by hanging! */
}

static void *
semUpDown (void *unused)
{
  int i;

  for (i = 0; i < 42; i++)
    SEMAPHORE_DOWN (sem, YES);  /* fails by blocking */
  if (SEMAPHORE_DOWN (sem, NO) != SYSERR)
    {
      SEMAPHORE_DESTROY (sem);
      printf ("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n"
              "Testcase deadlocked.\n", __FILE__, __LINE__);
      return NULL;              /* will halt testcase! */
    }
  for (i = 0; i < 42; i++)
    SEMAPHORE_UP (sem);
  return NULL;
}

static int
testSemaphore ()
{
  int i;
  struct PTHREAD *pt;
  void *unused;

  sem = SEMAPHORE_CREATE (42);
  for (i = 0; i < 42; i++)
    SEMAPHORE_DOWN (sem, YES);  /* fails by blocking */
  if (SEMAPHORE_DOWN (sem, NO) != SYSERR)
    {
      SEMAPHORE_DESTROY (sem);
      printf ("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n",
              __FILE__, __LINE__);
      return 1;
    }
  for (i = 0; i < 42; i++)
    SEMAPHORE_UP (sem);
  for (i = 0; i < 42; i++)
    if (SYSERR == SEMAPHORE_DOWN (sem, NO))
      {
        SEMAPHORE_DESTROY (sem);
        printf ("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u iteration %d\n",
                __FILE__, __LINE__, i);
        return 1;
      }
  if (SEMAPHORE_DOWN (sem, NO) != SYSERR)
    {
      SEMAPHORE_DESTROY (sem);
      printf ("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n",
              __FILE__, __LINE__);
      return 1;
    }
  pt = PTHREAD_CREATE (&semUpDown, NULL, 1024);
  for (i = 0; i < 42; i++)
    SEMAPHORE_UP (sem);
  PTHREAD_JOIN (pt, &unused);
  for (i = 0; i < 42; i++)
    SEMAPHORE_DOWN (sem, YES);
  if (SEMAPHORE_DOWN (sem, NO) != SYSERR)
    {
      SEMAPHORE_DESTROY (sem);
      printf ("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n",
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
