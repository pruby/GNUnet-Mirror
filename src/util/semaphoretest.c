/** 
 * @file test/hashtest.c
 * @brief testcase for util/semaphore.c
 */

#include "gnunet_util.h"
#include "platform.h"

#include <sys/types.h>
#ifndef MINGW             /* FIXME MINGW */
 #include <sys/wait.h>


static Mutex lock;

static Semaphore * sem;

static volatile int sv;

static volatile int tv;

static IPC_Semaphore * ipc;

static void lockIt() {
  sv = 0;
  fprintf(stderr, ".");
  while (sv == 0) 
    gnunet_util_sleep(50 * cronMILLIS); /* busy waiting may not always work */
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
    gnunet_util_sleep(50 * cronMILLIS); /* busy waiting may not always work */
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
    gnunet_util_sleep(50 * cronMILLIS); /* busy waiting may not always work */
  MUTEX_LOCK(&lock);
  sv = 5; /* release lockIt from while sv==0 loop,
	     blocks it on lock */
  fprintf(stderr, ".");
  
  if (sv != 5) {
    MUTEX_UNLOCK(&lock);
    while (tv != 2) 
      gnunet_util_sleep(50 * cronMILLIS); /* busy waiting may not always work */
    MUTEX_DESTROY(&lock);
    printf("MUTEX test failed at %s:%u\n",
	   __FILE__, __LINE__);
    return 1; /* error */
  } else {
    MUTEX_UNLOCK(&lock);
    while (tv != 2) 
      gnunet_util_sleep(50 * cronMILLIS); /* busy waiting may not always work */
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
    SEMAPHORE_FREE(sem);
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
    SEMAPHORE_FREE(sem);
    printf("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n",
	   __FILE__, __LINE__);
    return 1;
  }
  for (i=0;i<42;i++)
    SEMAPHORE_UP(sem);
  for (i=0;i<42;i++)
    if (OK != SEMAPHORE_DOWN_NONBLOCKING(sem)) {
      SEMAPHORE_FREE(sem);
      printf("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n",
	     __FILE__, __LINE__);
      return 1;
    }
  if (SEMAPHORE_DOWN_NONBLOCKING(sem) != SYSERR) {
    SEMAPHORE_FREE(sem);
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
    SEMAPHORE_FREE(sem);
    printf("SEMAPHORE_DOWN_NONBLOCKING failed at %s:%u\n",
	   __FILE__, __LINE__);
    return 1;
  }
  return 0;
}

static int testIPCSemaphore() {
  pid_t me;
  int cnt;
  int i;
  int j;
  FILE * fd;  
  int ret;
  int si;
  int sw;

  ret = 0;
  REMOVE("/tmp/gnunet_ipc_xchange");
  REMOVE("/tmp/gnunet_ipc_semtest");
  me = fork();
  sw = me;

  ipc = IPC_SEMAPHORE_NEW("/tmp/gnunet_ipc_semtest",
			  0);
  for (cnt=0;cnt<3;cnt++) {
    if (sw == 0) {
      for (i=0;i<6;i++) {
	IPC_SEMAPHORE_DOWN(ipc);
	fd = FOPEN("/tmp/gnunet_ipc_xchange",
		       "a+");
	if (fd == NULL) {
	  printf("Could not open testfile for reading: %s\n",
		 STRERROR(errno));
	  ret = 1;
	  goto END;
	}
	fseek(fd, 4*i, SEEK_SET);
	si = GN_FREAD(&j, 4, 1, fd);
	while (si == 0)
	  si = GN_FREAD(&j, 4, 1, fd);
	if (si != 1) {
	  printf("Could not read from testfile: %d - %s at %s:%d\n",
		 si,
		 STRERROR(errno),
		 __FILE__,
		 __LINE__);
	  ret = 1;
	  goto END;
	}
	fclose(fd);  
	if (j != i+cnt) {
	  printf("IPC test failed at cnt=%d i=%d j=%d %s:%u\n",
		 cnt, i, j, __FILE__, __LINE__);
	  ret = 1;
	  goto END;
	} else
	  fprintf(stderr, ".");
      } 
      REMOVE("/tmp/gnunet_ipc_xchange");     
      sw = 1;
    } else {
      for (i=0;i<6;i++) {
	sleep(1);
	fd = FOPEN("/tmp/gnunet_ipc_xchange",
		       "w+");
	if (fd == NULL) {
	  printf("Could not open testfile for writing: %s\n",
		 STRERROR(errno));
	  ret = 1;
	  goto END;
	}
	fseek(fd, 4*i, SEEK_SET);
	j=cnt+i;
	if (1 != GN_FWRITE(&j, 4, 1, fd)) {
	  printf("Could not write to testfile: %s\n",
		 STRERROR(errno));
	  ret = 1;
	  goto END;
	}
	fclose(fd);
	IPC_SEMAPHORE_UP(ipc);
      }      
      fprintf(stderr, ".");
      sleep(2); /* give reader ample time to finish */
      sw = 0;
    }
  }
 END:
  IPC_SEMAPHORE_FREE(ipc);
  REMOVE("/tmp/gnunet_ipc_xchange");
  if (me == 0) {
    exit(ret);
  } else {
    LOG(LOG_DEBUG,
	" waiting for other process to exit.\n");
    if (-1 == waitpid(me, &j, 0))
      LOG(LOG_ERROR,
	  " waitpid failed: %s\n",
	  STRERROR(errno));
    if ((! WIFEXITED(j)) || WEXITSTATUS(j) == 1)
      ret = 1; /* error in child */
  }
  return ret;
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
#endif /* FIXME MINGW */

int main(int argc, char * argv[]){
  int ret = 0;

#ifndef MINGW
  initUtil(argc, argv, &parseCommandLine);
  ret += testPTHREAD_CREATE();
  ret += testMutex();
  ret += testRecursiveMutex();
  ret += testSemaphore();
  ret += testIPCSemaphore();
  fprintf(stderr, "\n");
  doneUtil();
#endif
  return ret;
}
