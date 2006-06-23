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
 * @file util/os/semaphore.c
 * @brief functions related to IPC synchronization
 */

#include "gnunet_util_os.h"
#include "platform.h"

#if SOLARIS || FREEBSD || OSX
#include <semaphore.h>
#endif
#if SOMEBSD
# include <sys/file.h>
#endif
#if LINUX
# include <sys/ipc.h>
# include <sys/sem.h>
#endif
#ifdef _MSC_VER
#include <semaphore.h>
#endif

/**
 * Shall we use error-checking (slow)
 * mutexes (e.g. for debugging)
 */
#define USE_CHECKING_MUTEX 1

typedef struct IPC_SEMAPHORE {
  struct GE_Context * ectx;
#if SOLARIS || FREEBSD5 || OSX
  sem_t * internal;
#elif WINDOWS
  HANDLE internal;
#elif LINUX
  int internal;
  char * filename;
#elif SOMEBSD
  int initialValue;
  int fd;
  Mutex internalLock;
  char * filename;
#elif _MSC_VER
  int internal; /* KLB_FIX */
  char * filename;
#else
  /* PORT-ME! */
#endif
} IPC_Semaphore;


#if LINUX
/* IPC semaphore kludging for linux */

/* Why don't we start at count 0 and increment when opening? */
#define PROCCOUNT 10000

/**
 * Implementation for a single semaphore actually uses three :
 *
 * 0 : actual semaphore value
 * 1 : process counter
 * 2 : lock
 */

/* Various operations */
static struct sembuf op_lock[2] = {
  {2, 0, 0},        /* wait for [2] (lock) to equal 0 */
  {2, 1, SEM_UNDO}  /* then increment [2] to 1 - this locks it */
  /* UNDO to release the lock if processes exits */                               /* before explicitly unlocking */
};
static struct sembuf op_unlock[1] = {
  {2, -1, SEM_UNDO} /* decrement [2] (lock) back to 0 */
};
static struct sembuf    op_endcreate[2] = {
  {1, -1, SEM_UNDO},/* decrement [1] (proc counter) with undo on exit */
  /* UNDO to adjust proc counter if process exits
     before explicitly calling sem_close() */
  {2, -1, SEM_UNDO} /* then decrement [2] (lock) back to 0 */
};
static struct sembuf    op_close[3] = {
  {2, 0, 0},        /* wait for [2] (lock) to equal 0 */
  {2, 1, SEM_UNDO}, /* then increment [2] to 1 - this locks it */
  {1, 1, SEM_UNDO}  /* then increment [1] (proc counter) */
};
#endif

#if SOMEBSD
static void FLOCK(int fd,
		  int operation) {
  int ret;

  ret = -1;
  while (ret == -1) {
    ret = flock(fd, 
		operation);
    if (ret == -1) {
      if (errno != EINTR) {
	GE_LOG_STRERROR(NULL,
			GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
			"flock");
	return; 
      }
    }
  }
  fsync(fd);
}
static int LSEEK(int fd,
		 off_t pos, 
		 int mode) {
  int ret;
  ret = lseek(fd, 
	      pos, 
	      mode);
  if (ret == -1)
    GE_LOG_STRERROR(NULL,
		    GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
		    "lseek");
  return ret;
}
#endif

IPC_Semaphore * 
IPC_SEMAPHORE_CREATE(struct GE_Context * ectx,
		     const char * basename,
		     const unsigned int initialValue) {
  /* Could older FreeBSD use this too since this code can shorten the IPC name */
#if SOLARIS || OSX || FREEBSD5
  char * noslashBasename;
  int i;
  IPC_Semaphore * rret;
  IPC_Semaphore_Internal * ret;

  ret = MALLOC(sizeof(IPC_Semaphore));
  ret->ectx = ectx;
  noslashBasename = STRDUP(basename);
  for (i=strlen(noslashBasename);i>0;i--)
    if (noslashBasename[i] == '/')
      noslashBasename[i] = '.'; /* first character MUST be /, but Solaris
				   forbids it afterwards */
  noslashBasename[0] = '/';
  ret->internal = sem_open(noslashBasename,
			   O_CREAT,
			   S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP, /* 660 */
			   initialValue);
  while ( (ret->internal == (void *) SEM_FAILED)
	  && (errno == ENAMETOOLONG) ) {
    if (strlen(noslashBasename) < 4)
      break; /* definitely OS error... */
    noslashBasename[strlen(noslashBasename)/2] = '\0'; /* cut in half */
    ret->internal = sem_open(noslashBasename,
			     O_CREAT,
			     S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP, /* 660 */
			     initialValue);			
  }
  if (ret->internal == (void *) SEM_FAILED) 
    GE_DIE_STRERROR_FILE(ectx,
			 GE_FATAL | GE_USER | GE_DEVELOPER | GE_IMMEDIATE,
			 "sem_open",
			 noslashBasename);
  FREE(noslashBasename);
  return ret;

  /* *********************** fix from here *********** */
#elif WINDOWS
  char * noslashBasename;
  int i;
  IPC_Semaphore * rret;
  IPC_Semaphore_Internal * ret;
  SECURITY_ATTRIBUTES sec;
  DWORD dwErr;

  rret = MALLOC(sizeof(IPC_Semaphore));
  ret = MALLOC(sizeof(IPC_Semaphore_Internal));
  rret->platform = ret;
  noslashBasename = STRDUP(basename);
  for (i=strlen(noslashBasename);i>0;i--)
    if (noslashBasename[i] == '\\')
      noslashBasename[i] = '.'; /* must not contain backslashes */

  sec.nLength = sizeof(SECURITY_ATTRIBUTES);
  sec.bInheritHandle = TRUE;
  sec.lpSecurityDescriptor = NULL;

  ret->internal = CreateSemaphore(&sec, initialValue, LONG_MAX, noslashBasename);
  dwErr = GetLastError();
  if (! ret->internal && dwErr == ERROR_ALREADY_EXISTS) {
    ret->internal = OpenSemaphore(SEMAPHORE_MODIFY_STATE, TRUE, noslashBasename);
    dwErr = GetLastError();
  }
  if (! ret->internal) {
    LOG(LOG_FAILURE, _("Can't create semaphore: %i"), dwErr);
    DIE_FILE_STRERROR("sem_open", noslashBasename);
  }
  FREE(noslashBasename);
  return rret;
#elif LINUX
  union semun {
      int             val;
      struct semid_ds *buf;
      ushort          *array;
  } semctl_arg;
  IPC_Semaphore * rret;
  IPC_Semaphore_Internal * ret;
  key_t key;
  FILE * fp;
  int pcount;

  rret = MALLOC(sizeof(IPC_Semaphore));
  ret = MALLOC(sizeof(IPC_Semaphore_Internal));
  rret->platform = ret;

  fp = FOPEN(basename, "a+");
  if (NULL == fp) {
    LOG_FILE_STRERROR_FL(LOG_FATAL,
			 "fopen",
			 basename,
			 filename,
			 linenumber);
    FREE(rret);
    FREE(ret);
    return NULL;
  }
  fclose(fp);

  key = ftok(basename,'g');

again:

  ret->internal = semget(key, 3, IPC_CREAT|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);

  if (ret->internal == -1)
    DIE_STRERROR_FL("semget", filename, linenumber);
  if (semop(ret->internal, &op_lock[0], 2) < 0) {
    if (errno == EINVAL)
      goto again;
    else
      DIE_STRERROR_FL("semop", filename, linenumber);
  }

  /* get process count */
  if ( (pcount = semctl(ret->internal, 1, GETVAL, 0)) < 0)
    DIE_STRERROR_FL("semctl", filename, linenumber);
  if (pcount==0) {
     semctl_arg.val = initialValue;
     if (semctl(ret->internal, 0, SETVAL, semctl_arg) < 0)
       DIE_STRERROR_FL("semtcl", filename, linenumber);
     semctl_arg.val = PROCCOUNT;
     if (semctl(ret->internal, 1, SETVAL, semctl_arg) < 0)
       DIE_STRERROR_FL("semtcl", filename, linenumber);
  }

  if (semop(ret->internal, &op_endcreate[0], 2) < 0)
     DIE_STRERROR_FL("semop", filename, linenumber);

  ret->filename = STRDUP(basename);
  return rret;
#elif SOMEBSD
  int fd;
  int cnt;
  IPC_Semaphore * rret;
  IPC_Semaphore_Internal * ret;

  rret = MALLOC(sizeof(IPC_Semaphore));
  ret = MALLOC(sizeof(IPC_Semaphore_Internal));
  rret->platform = ret;

  MUTEX_CREATE(&ret->internalLock);
  ret->filename = STRDUP(basename);
  fd = -1;
  while (fd == -1) {
    fd = fileopen(basename,
	      O_CREAT|O_RDWR|O_EXCL,
	      S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP /* 660 */);
    if ( (fd == -1) &&
	 (errno == EEXIST) ) {
      /* try without creation */
      fd = fileopen(basename,
		O_RDWR,
		S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP /* 660 */);
      /* possibly the file was deleted in the meantime,
	 then try again with O_CREAT! */
      if ( (fd == -1) &&
	   (errno != ENOENT) )
	break;
    }
  }
  if (fd == -1) {
    LOG_FILE_STRERROR(LOG_ERROR, "open", ret->filename);
    MUTEX_DESTROY(&ret->internalLock);
    FREE(ret->filename);
    FREE(ret);
    FREE(rret);
    return NULL;
  }
  FLOCK(fd, LOCK_EX);
  if (sizeof(int) != READ(fd, &cnt, sizeof(int))) {
    cnt = htonl(initialValue);
    LSEEK(fd, 0, SEEK_SET);
    if (sizeof(int) != WRITE(fd, &cnt, sizeof(int)))
      LOG_FILE_STRERROR(LOG_WARNING, "write", basename);
  }
  LSEEK(fd, sizeof(int), SEEK_SET);
  if (sizeof(int) != READ(fd, &cnt, sizeof(int)))
    cnt = htonl(1);
  else
    cnt = htonl(ntohl(cnt)+1);
  LSEEK(fd, sizeof(int), SEEK_SET);
  if (sizeof(int) != WRITE(fd, &cnt, sizeof(int)))
     LOG_FILE_STRERROR(LOG_WARNING, "write", basename);
  FLOCK(fd, LOCK_UN);
  ret->fd = fd;
  ret->initialValue = initialValue;
  return rret;
#else
 #ifndef _MSC_VER
   #warning Port IPC.
   return NULL;
 #else
   return NULL;
 #endif
#endif
}

void ipc_semaphore_up_(IPC_Semaphore * rsem,
		       const char * filename,
		       const int linenumber) {
  IPC_Semaphore_Internal * sem;
  if (rsem == NULL) /* error on creation, optimistic execution; good luck */
    return;
  sem = rsem->platform;
#if SOLARIS || OSX || FREEBSD5
  if (0 != sem_post(sem->internal))
    LOG(LOG_WARNING,
	"sem_post signaled error: %s at %s:%d\n",
	STRERROR(errno),
	filename,
	linenumber);
#elif WINDOWS
  if (!ReleaseSemaphore(sem->internal, 1, NULL))
    LOG(LOG_WARNING,
      "ReleaseSemaphore signaled error: %i at %s:%d\n",
      GetLastError(),
      filename,
      linenumber);
#elif LINUX
  {
    struct sembuf sops = {0,1,SEM_UNDO};

    if (0 != semop(sem->internal,&sops,1))
      LOG(LOG_WARNING,
	  "semop signaled error: %s at %s:%d\n",
	  STRERROR(errno),
	  filename,
	  linenumber);
  }
#elif SOMEBSD
  {
    int cnt;


    MUTEX_LOCK(&sem->internalLock);
    FLOCK(sem->fd, LOCK_EX);
    LSEEK(sem->fd, 0, SEEK_SET);
    if (sizeof(int) != READ(sem->fd, &cnt, sizeof(int))) {
      LOG(LOG_WARNING,
	  "could not read IPC semaphore count (%s) at %s:%d!\n",
	  STRERROR(errno),
	  __FILE__,
	  __LINE__);
      MUTEX_UNLOCK(&sem->internalLock);
      return;
    }
    cnt = htonl(ntohl(cnt)+1);
    LSEEK(sem->fd, 0, SEEK_SET);
    if (sizeof(int) != WRITE(sem->fd, &cnt, sizeof(int)))
      LOG(LOG_WARNING,
	  "could not write to IPC file %s (%s) at %s:%d\n",
	  sem->filename,
	  STRERROR(errno),
	  __FILE__,
	  __LINE__);
    FLOCK(sem->fd, LOCK_UN);
    MUTEX_UNLOCK(&sem->internalLock);
  }
#endif
}

void ipc_semaphore_down_(IPC_Semaphore * rsem,
			 const char * filename,
			 const int linenumber) {
  IPC_Semaphore_Internal * sem;

  if (rsem == NULL) /* error on creation, optimistic execution; good luck */
    return;
  sem = rsem->platform;
#if OSX || SOLARIS || FREEBSD5
  while (0 != sem_wait(sem->internal)) {
    switch(errno) {
    case EINTR:
      break;
    case EINVAL:
      errexit(" ipc_semaphore_down called on invalid semaphore (in %s:%d)\n",
	      filename,
	      linenumber);
    case EDEADLK:
      errexit(" ipc_semaphore_down caused deadlock! (in %s:%d)\n",
	      filename,
	      linenumber);
    case EAGAIN:
      LOG(LOG_WARNING,
	  "did not expect EAGAIN from sem_wait (in %s:%d).\n",
	  filename,
	  linenumber);
      break;
    default:
      LOG(LOG_ERROR,
	  "did not expect %s from sem_wait at %s:%d\n",
	  STRERROR(errno),
	  filename,
	  linenumber);
      break;
    }
  }
#elif WINDOWS
  if (WaitForSingleObject(sem->internal, INFINITE) == WAIT_FAILED)
    LOG(LOG_WARNING,
      "WaitForSingleObject signaled error: %s at %s:%d\n",
      STRERROR(errno),
      filename,
      linenumber);
#elif LINUX
  {
    struct sembuf sops = {0,-1,SEM_UNDO};

    while (0 != semop(sem->internal,&sops,1)) {
      switch(errno) {
      case EINTR:
	break;
      case EINVAL:
	errexit(" ipc_semaphore_down called on invalid semaphore (in %s:%d)\n",
		filename,
		linenumber);
      case EAGAIN:
	LOG(LOG_WARNING,
	    "did not expect EAGAIN from sem_wait (in %s:%d).\n",
	    filename,
	    linenumber);
	break;
      default:
	LOG(LOG_ERROR,
	    "did not expect %s from sem_wait at %s:%d\n",
	    STRERROR(errno),
	    filename,
	    linenumber);
	break;
      }
    }
  }
#elif SOMEBSD
  {
    int cnt;

    MUTEX_LOCK(&sem->internalLock);
    FLOCK(sem->fd, LOCK_EX);
    cnt = ntohl(0);
    while (htonl(cnt) == 0) {
      LSEEK(sem->fd, 0, SEEK_SET);
      if (sizeof(int) != READ(sem->fd, &cnt, sizeof(int))) {
	LOG(LOG_WARNING,
	    "could not read IPC semaphore count (%s) at %s:%d!\n",
	    STRERROR(errno),
	    __FILE__,
	    __LINE__);
	FLOCK(sem->fd, LOCK_UN);
	MUTEX_UNLOCK(&sem->internalLock);
	return;
      }
      if (htonl(cnt) == 0) {
	/* busy wait! */
	FLOCK(sem->fd, LOCK_UN);
	gnunet_util_sleep(50 * cronMILLIS);
	FLOCK(sem->fd, LOCK_EX);
      }
    }

    cnt = htonl(ntohl(cnt)-1);
    LSEEK(sem->fd, 0, SEEK_SET);
    if (sizeof(int) != WRITE(sem->fd, &cnt, sizeof(int)))
      LOG(LOG_WARNING,
	  "could not write update to IPC file %s at %s:%d\n",
	  sem->filename,
	  __FILE__,
	  __LINE__);
    FLOCK(sem->fd, LOCK_UN);
    MUTEX_UNLOCK(&sem->internalLock);
  }
#else
#endif
}

void ipc_semaphore_free_(IPC_Semaphore * rsem,
			 const char * filename,
			 const int linenumber) {
  IPC_Semaphore_Internal * sem;
  if (rsem == NULL) /* error on creation, optimistic execution; good luck */
    return;
  sem = rsem->platform;
  FREE(rsem);
#if SOLARIS || OSX || FREEBSD5
  if (0 != sem_close(sem->internal))
    LOG(LOG_WARNING,
	"sem_close signaled error: %s at %s:%d\n",
	STRERROR(errno),
	filename,
	linenumber);
#elif WINDOWS
  if (!CloseHandle(sem->internal))
    LOG(LOG_WARNING,
    "CloseHandle signaled error: %i at %s:%d\n",
    GetLastError(),
    filename,
    linenumber);
#elif LINUX
  {
    int pcount;

    if (semop(sem->internal, &op_close[0], 3) < 0)
      LOG(LOG_WARNING,
	  "semop signaled error: %s at %s:%d\n",
	  STRERROR(errno),
	  filename,
	  linenumber);

    if ( (pcount = semctl(sem->internal, 1, GETVAL, 0)) < 0)
      LOG(LOG_WARNING,
	  "semctl: %s at %s:%d\n",
	  STRERROR(errno),
	  filename,
	  linenumber);
    if (pcount > PROCCOUNT)
      LOG(LOG_WARNING,
	  "pcount too large at %s:%d\n",
	  filename,
	  linenumber);
    else if (pcount == PROCCOUNT) {
      if (0 != semctl(sem->internal,0,IPC_RMID,0))
	LOG(LOG_WARNING,
	    "semctl signaled error: %s at %s:%d\n",
	    STRERROR(errno),
	    filename,
	    linenumber);
      UNLINK(sem->filename);
    } else {
      if (semop(sem->internal, &op_unlock[0], 1) < 0)
	LOG(LOG_WARNING,
	    "semop %s %s:%d\n",
	    STRERROR(errno),
	    filename,
	    linenumber);
    }
    FREE(sem->filename);
  }
#elif SOMEBSD
  {
    int cnt;

    MUTEX_DESTROY(&sem->internalLock);
    FLOCK(sem->fd, LOCK_EX);
    LSEEK(sem->fd, sizeof(int), SEEK_SET);
    if (sizeof(int) == READ(sem->fd, &cnt, sizeof(int))) {
      cnt = htonl(ntohl(cnt)-1);
      LSEEK(sem->fd, sizeof(int), SEEK_SET);
      if (sizeof(int) != WRITE(sem->fd, &cnt, sizeof(int)))
	LOG(LOG_WARNING,
	    "could not write to IPC file %s at %s:%d\n",
	    sem->filename,
	    __FILE__,
	    __LINE__);
      if (ntohl(cnt) == 0) {
	UNLINK(sem->filename);
      }
    } else
      LOG(LOG_WARNING,
	  "could not read process count of IPC %s at %s:%d\n",
	  sem->filename,
	  __FILE__,
	  __LINE__);
    FREE(sem->filename);
    FLOCK(sem->fd, LOCK_UN);
    closefile(sem->fd);
  }
#else
#endif
  FREE(sem);
}


/* end of semaphore.c */
