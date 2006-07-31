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
 * @file test/semaphore.c
 * @brief testcase for util/threads/semaphore.c
 */

#include "gnunet_util.h"
#include "platform.h"

#include <sys/types.h>
#ifndef MINGW             /* PORT-ME MINGW */


static Mutex lock;

static Semaphore * sem;

static volatile int sv;

static volatile int tv;

static void lockIt() {
  sv = 0;
  fprintf(stderr, ".");
  while (sv == 0)
    PTHREAD_SLEEP(50 * cronMILLIS); /* busy waiting may not always work */
  MUTEX_LOCK(&lock);
  sv = 1;
  MUTEX_UNLOCK(&lock);
  sv = 2;
  tv = 2;
}

static void bigStack() {
  int i;
  char big[1024 * 100];

  fprintf(stderr, ".");
  for (i=0;i<1024*100;i++)
    big[i] = (char) i;
}

static int testPTHREAD_CREATE() {
  PTHREAD_T pt;
  void * unused;

  sv = -1; tv = 0;
  fprintf(stderr, ".");
  MUTEX_CREATE(&lock);
  PTHREAD_CREATE(&pt,
		 (PThreadMain)&lockIt,
		 NULL,
		 1024);
  PTHREAD_DETACH(&pt);
  while (tv != 2) {
    sv = 1;
    PTHREAD_SLEEP(50 * cronMILLIS); /* busy waiting may not always work */
  }
  MUTEX_DESTROY(&lock);
  PTHREAD_CREATE(&pt,
		 (PThreadMain)&bigStack,
		 NULL,
		 1024*100 + 25000); /* fails by segfault */
  PTHREAD_JOIN(&pt, &unused);
  return 0;
}

static int testMutex() {
  PTHREAD_T pt;
  void * unused;
  MUTEX_CREATE(&lock);

  sv = 1;
  tv = 0;
  PTHREAD_CREATE(&pt,
		 (PThreadMain)&lockIt,
		 NULL,
		 1024);
  while (sv == 1)
    PTHREAD_SLEEP(50 * cronMILLIS); /* busy waiting may not always work */
  MUTEX_LOCK(&lock);
  sv = 5; /* release lockIt from while sv==0 loop,
	     blocks it on lock */
  fprintf(stderr, ".");

  if (sv != 5) {
    MUTEX_UNLOCK(&lock);
    while (tv != 2)
      PTHREAD_SLEEP(50 * cronMILLIS); /* busy waiting may not always work */
    MUTEX_DESTROY(&lock);
    printf("MUTEX test failed at %s:%u\n",
	   __FILE__, __LINE__);
    return 1; /* error */
  } else {
    MUTEX_UNLOCK(&lock);
    while (tv != 2)
      PTHREAD_SLEEP(50 * cronMILLIS); /* busy waiting may not always work */
    PTHREAD_JOIN(&pt, &unused);
    MUTEX_DESTROY(&lock);
    return 0; /* ok */
  }
}

static int testRecursiveMutex() {
  int i;

  fprintf(stderr, ".");
  MUTEX_CREATE_RECURSIVE(&lock);
  for (i=0;i<50;i++)
    MUTEX_LOCK(&lock);
  for (i=0;i<50;i++)
    MUTEX_UNLOCK(&lock);
  MUTEX_DESTROY(&lock);
  return 0; /* ok -- fails by hanging!*/
}

static void semUpDown() {
  int i;

  fprintf(stderr, ".");
  for (i=0;i<42;i++)
    SEMAPHORE_DOWN(sem); /* fails by blocking */
  if (SEMAPHORE_DOWN_NONBLOCKING(sem) != SYSERR) {
    SEMAPHORE_DESTROY(sem);
    printf("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n"
	   "Testcase deadlocked.\n",
	   __FILE__, __LINE__);
    return; /* will halt testcase! */
  }
  for (i=0;i<42;i++)
    SEMAPHORE_UP(sem);
}

static int testSemaphore() {
  int i;
  PTHREAD_T pt;
  void * unused;

  sem = SEMAPHORE_NEW(42);
  fprintf(stderr, ".");
  for (i=0;i<42;i++)
    SEMAPHORE_DOWN(sem); /* fails by blocking */
  if (SEMAPHORE_DOWN_NONBLOCKING(sem) != SYSERR) {
    SEMAPHORE_DESTROY(sem);
    printf("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n",
	   __FILE__, __LINE__);
    return 1;
  }
  for (i=0;i<42;i++)
    SEMAPHORE_UP(sem);
  for (i=0;i<42;i++)
    if (OK != SEMAPHORE_DOWN_NONBLOCKING(sem)) {
      SEMAPHORE_DESTROY(sem);
      printf("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n",
	     __FILE__, __LINE__);
      return 1;
    }
  if (SEMAPHORE_DOWN_NONBLOCKING(sem) != SYSERR) {
    SEMAPHORE_DESTROY(sem);
    printf("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n",
	   __FILE__, __LINE__);
    return 1;
  }
  fprintf(stderr, ".");
  PTHREAD_CREATE(&pt,
		 (PThreadMain)&semUpDown,
		 NULL,
		 1024);
  for (i=0;i<42;i++)
    SEMAPHORE_UP(sem);
  PTHREAD_JOIN(&pt, &unused);
  for (i=0;i<42;i++)
    SEMAPHORE_DOWN(sem);
  if (SEMAPHORE_DOWN_NONBLOCKING(sem) != SYSERR) {
    SEMAPHORE_DESTROY(sem);
    printf("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n",
	   __FILE__, __LINE__);
    return 1;
  }
  return 0;
}

/**
 * Perform option parsing from the command line.
 */
static int parseCommandLine(int argc,
			    char * argv[]) {
  char c;

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      { "loglevel",1, 0, 'L' },
      { "config",  1, 0, 'c' },
      { 0,0,0,0 }
    };

    c = GNgetopt_long(argc,
		      argv,
		      "c:L:",
		      long_options,
		      &option_index);

    if (c == -1)
      break;  /* No more flags to process */

    switch(c) {
    case 'L':
      FREENONNULL(setConfigurationString("GNUNET",
					 "LOGLEVEL",
					 GNoptarg));
      break;
    case 'c':
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    } /* end of parsing commandline */
  }
  return OK;
}
#endif /* PORT-ME MINGW */

int main(int argc, char * argv[]){
  int ret = 0;

#ifndef MINGW
  initUtil(argc, argv, &parseCommandLine);
  ret += testPTHREAD_CREATE();
  ret += testMutex();
  ret += testRecursiveMutex();
  ret += testSemaphore();
  fprintf(stderr, "\n");
  doneUtil();
#endif
  return ret;
}
