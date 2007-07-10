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
 *
 * TODO: implement non-blocking semaphore down!
 */

#include "gnunet_util_os.h"
#include "gnunet_util_string.h"
#include "gnunet_util_error.h"
#include "gnunet_util_threads.h"
#include "gnunet_util_disk.h"
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

typedef struct IPC_SEMAPHORE
{
  struct GE_Context *ectx;
#if SOLARIS || FREEBSD5 || OSX
  sem_t *internal;
#elif WINDOWS
  HANDLE internal;
#elif LINUX
  int internal;
  char *filename;
#elif SOMEBSD
  int initialValue;
  int fd;
  struct MUTEX *internalLock;
  char *filename;
#elif _MSC_VER
  int internal;                 /* KLB_FIX */
  char *filename;
#else
  /* PORT-ME! */
#endif
} IPC_SEMAPHORE;


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
  {2, 0, 0},                    /* wait for [2] (lock) to equal 0 */
  {2, 1, SEM_UNDO}              /* then increment [2] to 1 - this locks it */
  /* UNDO to release the lock if processes exits *//* before explicitly unlocking */
};
static struct sembuf op_unlock[1] = {
  {2, -1, SEM_UNDO}             /* decrement [2] (lock) back to 0 */
};
static struct sembuf op_endcreate[2] = {
  {1, -1, SEM_UNDO},            /* decrement [1] (proc counter) with undo on exit */
  /* UNDO to adjust proc counter if process exits
     before explicitly calling sem_close() */
  {2, -1, SEM_UNDO}             /* then decrement [2] (lock) back to 0 */
};
static struct sembuf op_close[3] = {
  {2, 0, 0},                    /* wait for [2] (lock) to equal 0 */
  {2, 1, SEM_UNDO},             /* then increment [2] to 1 - this locks it */
  {1, 1, SEM_UNDO}              /* then increment [1] (proc counter) */
};
#endif

#if SOMEBSD
static void
FLOCK (int fd, int operation)
{
  int ret;

  ret = -1;
  while (ret == -1)
    {
      ret = flock (fd, operation);
      if (ret == -1)
        {
          if (errno != EINTR)
            {
              GE_LOG_STRERROR (NULL,
                               GE_ERROR | GE_USER | GE_ADMIN | GE_BULK,
                               "flock");
              return;
            }
        }
    }
  fsync (fd);
}
static int
LSEEK (int fd, off_t pos, int mode)
{
  int ret;
  ret = lseek (fd, pos, mode);
  if (ret == -1)
    GE_LOG_STRERROR (NULL, GE_ERROR | GE_USER | GE_ADMIN | GE_BULK, "lseek");
  return ret;
}
#endif

struct IPC_SEMAPHORE *
IPC_SEMAPHORE_CREATE (struct GE_Context *ectx,
                      const char *basename, const unsigned int initialValue)
{
  /* Could older FreeBSD use this too since this code can shorten the IPC name */
#if SOLARIS || OSX || FREEBSD5
  char *noslashBasename;
  int i;
  struct IPC_SEMAPHORE *ret;

  ret = MALLOC (sizeof (struct IPC_SEMAPHORE));
  ret->ectx = ectx;
  noslashBasename = string_expandFileName (ectx, basename);
  for (i = strlen (noslashBasename); i > 0; i--)
    if (noslashBasename[i] == '/')
      noslashBasename[i] = '.'; /* first character MUST be /, but Solaris
                                   forbids it afterwards */
  noslashBasename[0] = '/';
  ret->internal = sem_open (noslashBasename, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,    /* 660 */
                            initialValue);
  while ((ret->internal == (void *) SEM_FAILED) && (errno == ENAMETOOLONG))
    {
      char *halfBasename;

      if (strlen (noslashBasename) < 4)
        break;                  /* definitely OS error... */
      /* FIXME: this might cause unintended mapping to same names */
      halfBasename = noslashBasename + strlen (noslashBasename) / 2;    /* cut in half */
      halfBasename[0] = '/';
      ret->internal = sem_open (halfBasename, O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,   /* 660 */
                                initialValue);
    }
  if (ret->internal == (void *) SEM_FAILED)
    GE_DIE_STRERROR_FILE (ectx,
                          GE_FATAL | GE_USER | GE_DEVELOPER | GE_IMMEDIATE,
                          "sem_open", noslashBasename);
  FREE (noslashBasename);
  return ret;
#elif WINDOWS
  char *noslashBasename;
  int i;
  struct IPC_SEMAPHORE *ret;
  SECURITY_ATTRIBUTES sec;
  DWORD dwErr;

  ret = MALLOC (sizeof (struct IPC_SEMAPHORE));
  ret->ectx = ectx;
  noslashBasename = string_expandFileName (ectx, basename);
  for (i = strlen (noslashBasename); i > 0; i--)
    if (noslashBasename[i] == '\\')
      noslashBasename[i] = '.'; /* must not contain backslashes */

  sec.nLength = sizeof (SECURITY_ATTRIBUTES);
  sec.bInheritHandle = TRUE;
  sec.lpSecurityDescriptor = NULL;

  ret->internal =
    CreateSemaphore (&sec, initialValue, LONG_MAX, noslashBasename);
  dwErr = GetLastError ();
  if (!ret->internal && dwErr == ERROR_ALREADY_EXISTS)
    {
      ret->internal =
        OpenSemaphore (SEMAPHORE_MODIFY_STATE, TRUE, noslashBasename);
      dwErr = GetLastError ();
    }
  if (!ret->internal)
    {
      GE_LOG (ectx,
              GE_FATAL | GE_USER | GE_DEVELOPER | GE_BULK,
              _("Can't create semaphore: %i"), dwErr);
      GE_DIE_STRERROR_FILE (ectx,
                            GE_FATAL | GE_USER | GE_DEVELOPER | GE_BULK,
                            "OpenSemaphore", noslashBasename);
    }
  FREE (noslashBasename);
  return ret;
#elif LINUX
  union semun
  {
    int val;
    struct semid_ds *buf;
    ushort *array;
  } semctl_arg;
  struct IPC_SEMAPHORE *ret;
  key_t key;
  FILE *fp;
  int pcount;
  char *ebasename;

  ret = MALLOC (sizeof (struct IPC_SEMAPHORE));
  ret->ectx = ectx;
  ebasename = string_expandFileName (ectx, basename);
  disk_directory_create_for_file (ectx, ebasename);
  fp = FOPEN (ebasename, "a+");
  if (NULL == fp)
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_ERROR | GE_USER | GE_BULK, "fopen", ebasename);
      FREE (ret);
      FREE (ebasename);
      return NULL;
    }
  fclose (fp);

  key = ftok (ebasename, 'g');

again:
  ret->internal = semget (key,
                          3,
                          IPC_CREAT | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  if (ret->internal == -1)
    GE_DIE_STRERROR (ectx, GE_FATAL | GE_USER | GE_IMMEDIATE, "semget");
  if (semop (ret->internal, &op_lock[0], 2) < 0)
    {
      if (errno == EINVAL)
        goto again;
      else
        GE_DIE_STRERROR (ectx, GE_FATAL | GE_USER | GE_IMMEDIATE, "semop");
    }

  /* get process count */
  if ((pcount = semctl (ret->internal, 1, GETVAL, 0)) < 0)
    GE_DIE_STRERROR (ectx, GE_FATAL | GE_USER | GE_IMMEDIATE, "semctl");
  if (pcount == 0)
    {
      semctl_arg.val = initialValue;
      if (semctl (ret->internal, 0, SETVAL, semctl_arg) < 0)
        GE_DIE_STRERROR (ectx, GE_FATAL | GE_USER | GE_IMMEDIATE, "semtcl");
      semctl_arg.val = PROCCOUNT;
      if (semctl (ret->internal, 1, SETVAL, semctl_arg) < 0)
        GE_DIE_STRERROR (ectx, GE_FATAL | GE_USER | GE_IMMEDIATE, "semtcl");
    }

  if (semop (ret->internal, &op_endcreate[0], 2) < 0)
    GE_DIE_STRERROR (ectx, GE_FATAL | GE_USER | GE_IMMEDIATE, "semop");
  ret->filename = ebasename;
  return ret;
#elif SOMEBSD
  int fd;
  int cnt;
  struct IPC_SEMAPHORE *ret;

  ret = MALLOC (sizeof (struct IPC_SEMAPHORE));
  ret->ectx = ectx;

  MUTEX_CREATE (&ret->internalLock);
  ret->filename = STRDUP (basename);
  fd = -1;
  while (fd == -1)
    {
      fd = disk_file_open (ectx,
                           basename,
                           O_CREAT | O_RDWR | O_EXCL,
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP /* 660 */ );
      if ((fd == -1) && (errno == EEXIST))
        {
          /* try without creation */
          fd = disk_file_open (ectx, basename, O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP    /* 660 */
            );
          /* possibly the file was deleted in the meantime,
             then try again with O_CREAT! */
          if ((fd == -1) && (errno != ENOENT))
            break;
        }
    }
  if (fd == -1)
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_ERROR | GE_USER | GE_BULK,
                            "open", ret->filename);
      MUTEX_DESTROY (&ret->internalLock);
      FREE (ret->filename);
      FREE (ret);
      return NULL;
    }
  FLOCK (fd, LOCK_EX);
  if (sizeof (int) != READ (fd, &cnt, sizeof (int)))
    {
      cnt = htonl (initialValue);
      LSEEK (fd, 0, SEEK_SET);
      if (sizeof (int) != WRITE (fd, &cnt, sizeof (int)))
        GE_LOG_STRERROR_FILE (ectx,
                              GE_ERROR | GE_USER | GE_BULK,
                              "write", basename);
    }
  LSEEK (fd, sizeof (int), SEEK_SET);
  if (sizeof (int) != READ (fd, &cnt, sizeof (int)))
    cnt = htonl (1);
  else
    cnt = htonl (ntohl (cnt) + 1);
  LSEEK (fd, sizeof (int), SEEK_SET);
  if (sizeof (int) != WRITE (fd, &cnt, sizeof (int)))
    GE_LOG_STRERROR_FILE (ectx,
                          GE_WARNING | GE_USER | GE_BULK, "write", basename);
  FLOCK (fd, LOCK_UN);
  ret->fd = fd;
  ret->initialValue = initialValue;
  return ret;
#else
#ifndef _MSC_VER
#warning Port IPC.
  return NULL;
#else
  return NULL;
#endif
#endif
}

void
IPC_SEMAPHORE_UP (struct IPC_SEMAPHORE *sem)
{
  if (sem == NULL)              /* error on creation, optimistic execution; good luck */
    return;
#if SOLARIS || OSX || FREEBSD5
  if (0 != sem_post (sem->internal))
    GE_LOG_STRERROR (sem->ectx, GE_WARNING | GE_USER | GE_BULK, "sem_post");
#elif WINDOWS
  if (!ReleaseSemaphore (sem->internal, 1, NULL))
    GE_LOG (sem->ectx, GE_WARNING | GE_USER | GE_BULK,
            "ReleaseSemaphore signaled error: %i\n", GetLastError ());
#elif LINUX
  {
    struct sembuf sops = { 0, 1, SEM_UNDO };

    if (0 != semop (sem->internal, &sops, 1))
      GE_LOG_STRERROR (sem->ectx, GE_WARNING | GE_USER | GE_BULK, "semop");
  }
#elif SOMEBSD
  {
    int cnt;

    MUTEX_LOCK (&sem->internalLock);
    FLOCK (sem->fd, LOCK_EX);
    LSEEK (sem->fd, 0, SEEK_SET);
    if (sizeof (int) != READ (sem->fd, &cnt, sizeof (int)))
      {
        GE_LOG_STRERROR_FILE (sem->ectx,
                              GE_WARNING | GE_USER | GE_BULK,
                              "read", sem->filename);
        FLOCK (sem->fd, LOCK_UN);
        MUTEX_UNLOCK (&sem->internalLock);
        return;
      }
    cnt = htonl (ntohl (cnt) + 1);
    LSEEK (sem->fd, 0, SEEK_SET);
    if (sizeof (int) != WRITE (sem->fd, &cnt, sizeof (int)))
      GE_LOG_STRERROR_FILE (sem->ectx,
                            GE_WARNING | GE_USER | GE_BULK,
                            "write", sem->filename);
    FLOCK (sem->fd, LOCK_UN);
    MUTEX_UNLOCK (&sem->internalLock);
  }
#endif
}

/* FIXME: add support for mayBlock! */
int
IPC_SEMAPHORE_DOWN (struct IPC_SEMAPHORE *sem, int mayBlock)
{
  if (sem == NULL)              /* error on creation, optimistic execution; good luck */
    return OK;
#if OSX || SOLARIS || FREEBSD5
  while (0 != sem_wait (sem->internal))
    {
      if ((errno == EINTR) || (errno == EAGAIN))
        continue;
      GE_DIE_STRERROR (sem->ectx,
                       GE_FATAL | GE_USER | GE_IMMEDIATE, "sem_wait");
    }
  return OK;
#elif WINDOWS
  if (WaitForSingleObject (sem->internal, INFINITE) == WAIT_FAILED)
    GE_LOG_STRERROR (sem->ectx,
                     GE_WARNING | GE_USER | GE_BULK, "WaitForSingleObject");
  return OK;
#elif LINUX
  {
    struct sembuf sops = { 0, -1, SEM_UNDO };

    while (0 != semop (sem->internal, &sops, 1))
      {
        if ((errno == EINTR) || (errno == EAGAIN))
          continue;
        GE_DIE_STRERROR (sem->ectx,
                         GE_FATAL | GE_USER | GE_IMMEDIATE, "semop");
      }
    return OK;
  }
#elif SOMEBSD
  {
    int cnt;

    MUTEX_LOCK (&sem->internalLock);
    FLOCK (sem->fd, LOCK_EX);
    cnt = ntohl (0);
    while (htonl (cnt) == 0)
      {
        LSEEK (sem->fd, 0, SEEK_SET);
        if (sizeof (int) != READ (sem->fd, &cnt, sizeof (int)))
          {
            GE_LOG_STRERROR_FILE (sem->ectx,
                                  GE_WARNING | GE_USER | GE_BULK,
                                  "read", sem->filename);
            FLOCK (sem->fd, LOCK_UN);
            MUTEX_UNLOCK (&sem->internalLock);
            return SYSERR;
          }
        if (htonl (cnt) == 0)
          {
            /* busy wait! */
            FLOCK (sem->fd, LOCK_UN);
            PTHREAD_SLEEP (50 * cronMILLIS);
            FLOCK (sem->fd, LOCK_EX);
          }
      }

    cnt = htonl (ntohl (cnt) - 1);
    LSEEK (sem->fd, 0, SEEK_SET);
    if (sizeof (int) != WRITE (sem->fd, &cnt, sizeof (int)))
      GE_LOG_STRERROR_FILE (sem->ectx,
                            GE_WARNING | GE_USER | GE_BULK,
                            "write", sem->filename);
    FLOCK (sem->fd, LOCK_UN);
    MUTEX_UNLOCK (&sem->internalLock);
  }
  return OK;
#else
  return OK;
#endif
}

void
IPC_SEMAPHORE_DESTROY (struct IPC_SEMAPHORE *sem)
{
  if (sem == NULL)              /* error on creation, optimistic execution; good luck */
    return;
#if SOLARIS || OSX || FREEBSD5
  if (0 != sem_close (sem->internal))
    GE_LOG_STRERROR (sem->ectx, GE_USER | GE_WARNING | GE_BULK, "sem_close");
#elif WINDOWS
  if (!CloseHandle (sem->internal))
    GE_LOG (sem->ectx,
            GE_USER | GE_WARNING | GE_BULK,
            "CloseHandle signaled error: %i\n", GetLastError ());
#elif LINUX
  {
    int pcount;

    if (semop (sem->internal, &op_close[0], 3) < 0)
      GE_LOG_STRERROR (sem->ectx, GE_USER | GE_WARNING | GE_BULK, "semop");
    if ((pcount = semctl (sem->internal, 1, GETVAL, 0)) < 0)
      GE_LOG_STRERROR (sem->ectx, GE_USER | GE_WARNING | GE_BULK, "semctl");
    if (pcount > PROCCOUNT)
      {
        GE_BREAK (sem->ectx, 0);
      }
    else if (pcount == PROCCOUNT)
      {
        if (0 != semctl (sem->internal, 0, IPC_RMID, 0))
          GE_LOG_STRERROR (sem->ectx,
                           GE_USER | GE_WARNING | GE_BULK, "semctl");
        UNLINK (sem->filename);
      }
    else
      {
        if (semop (sem->internal, &op_unlock[0], 1) < 0)
          GE_LOG_STRERROR (sem->ectx,
                           GE_USER | GE_WARNING | GE_BULK, "semop");
      }
    FREE (sem->filename);
  }
#elif SOMEBSD
  {
    int cnt;

    MUTEX_DESTROY (&sem->internalLock);
    FLOCK (sem->fd, LOCK_EX);
    LSEEK (sem->fd, sizeof (int), SEEK_SET);
    if (sizeof (int) == READ (sem->fd, &cnt, sizeof (int)))
      {
        cnt = htonl (ntohl (cnt) - 1);
        LSEEK (sem->fd, sizeof (int), SEEK_SET);
        if (sizeof (int) != WRITE (sem->fd, &cnt, sizeof (int)))
          GE_LOG_STRERROR (sem->ectx,
                           GE_WARNING | GE_USER | GE_BULK, "write");
        if (ntohl (cnt) == 0)
          UNLINK (sem->filename);
      }
    else
      GE_LOG_STRERROR (sem->ectx, GE_WARNING | GE_USER | GE_BULK, "read");
    FLOCK (sem->fd, LOCK_UN);
    disk_file_close (sem->ectx, sem->filename, sem->fd);
    FREE (sem->filename);
  }
#else
#endif
  FREE (sem);
}


/* end of semaphore.c */
