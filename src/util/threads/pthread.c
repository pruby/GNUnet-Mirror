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
 * @file util/threads/pthread.c
 * @brief implementation of pthread start/join/sleep
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
#endif

typedef struct PTHREAD
{
  pthread_t pt;
} PThread;

/**
 * Returns YES if pt is the handle for THIS thread.
 */
int
PTHREAD_TEST_SELF (PThread * handle)
{
  if (handle == NULL)
    return NO;
#if HAVE_PTHREAD_EQUAL
  if (pthread_equal (pthread_self (), handle->pt))
#else
#if HAVE_NEW_PTHREAD_T
  if (handle->pt->p == pthread_self ().p)
#else
  if (handle->pt == pthread_self ())
#endif
#endif
    return YES;
  else
    return NO;
}

/**
 * Get the handle for THIS thread.
 */
PThread *
PTHREAD_GET_SELF ()
{
  PThread *ret;
  ret = MALLOC (sizeof (PThread));
  ret->pt = pthread_self ();
  return ret;
}

/**
 * Release handle for a thread.
 */
void
PTHREAD_REL_SELF (PThread * handle)
{
  FREE (handle);
}

/**
 * Create a thread. Use this method instead of pthread_create since
 * BSD may only give a 1k stack otherwise.
 *
 * @param handle handle to the pthread (for detaching, join)
 * @param main the main method of the thread
 * @param arg the argument to main
 * @param stackSize the size of the stack of the thread in bytes.
 *        Note that if the stack overflows, some OSes (seen under BSD)
 *        will just segfault and gdb will give a messed-up stacktrace.
 * @return see pthread_create
 */
PThread *
PTHREAD_CREATE (PThreadMain main, void *arg, unsigned int stackSize)
{
  PThread *handle;
#ifndef LINUX
  pthread_attr_t stack_size_custom_attr;
#endif
  int ret;

  handle = MALLOC (sizeof (PThread));
#ifdef MINGW
  memset (handle, 0, sizeof (PThread));
#endif
#ifndef LINUX
  pthread_attr_init (&stack_size_custom_attr);
  pthread_attr_setstacksize (&stack_size_custom_attr, stackSize);
#endif
  ret = pthread_create (&handle->pt,
#ifndef LINUX
                        &stack_size_custom_attr,
#else
                        NULL,
#endif
                        main, arg);
  if (ret != 0)
    {
      FREE (handle);
      return NULL;
    }
  return handle;
}

void
PTHREAD_JOIN_FL (PThread * handle,
                 void **ret, const char *file, unsigned int line)
{
  cron_t start;
  cron_t end;
  int k;

  GE_ASSERT (NULL, handle != NULL);
  GE_ASSERT (NULL, NO == PTHREAD_TEST_SELF (handle));
  start = get_time ();
  k = pthread_join (handle->pt, ret);
  end = get_time ();
  if ((end - start > REALTIME_LIMIT) && (REALTIME_LIMIT != 0))
    {
      GE_LOG (NULL,
              GE_DEVELOPER | GE_WARNING | GE_IMMEDIATE,
              _("Real-time delay violation (%llu ms) at %s:%u\n"),
              end - start, file, line);
    }
  FREE (handle);
  switch (k)
    {
    case 0:
      return;
    case ESRCH:
      GE_LOG (NULL,
              GE_FATAL | GE_USER | GE_DEVELOPER | GE_IMMEDIATE,
              _("`%s' failed with error code %s: %s\n"),
              "pthread_join", "ESRCH", STRERROR (errno));
      break;
    case EINVAL:
      GE_LOG (NULL,
              GE_FATAL | GE_USER | GE_DEVELOPER | GE_IMMEDIATE,
              _("`%s' failed with error code %s: %s\n"),
              "pthread_join", "EINVAL", STRERROR (errno));
    case EDEADLK:
      GE_LOG (NULL,
              GE_FATAL | GE_USER | GE_DEVELOPER | GE_IMMEDIATE,
              _("`%s' failed with error code %s: %s\n"),
              "pthread_join", "EDEADLK", STRERROR (errno));
    default:
      GE_LOG (NULL,
              GE_FATAL | GE_USER | GE_DEVELOPER | GE_IMMEDIATE,
              _("`%s' failed with error code %d: %s\n"),
              "pthread_join", k, STRERROR (errno));
    }
  GE_ASSERT (NULL, 0);
}

#ifdef WINDOWS
/**
 * @brief Called if a sleeping thread is interrupted
 */
static void CALLBACK
__PTHREAD_SIGNALED (DWORD sig)
{
}
#else
static void
sigalrmHandler (int sig)
{
}
#endif


/**
 * Sleep for the specified time interval.  Use PTHREAD_STOP_SLEEP to
 * wake the thread up early.  Caller is responsible to check that the
 * sleep was long enough.
 */
void
PTHREAD_SLEEP (unsigned long long delay)
{
#if LINUX || SOLARIS || SOMEBSD || OSX
  struct timespec req;
  struct timespec rem;
#elif WINDOWS
#else
  int ret;
  struct timeval timeout;
#endif

  /* actual sleep */
#if LINUX || SOLARIS || SOMEBSD || OSX
  req.tv_sec = delay / 1000;    /* ms -> seconds */
  req.tv_nsec = (delay - req.tv_sec * 1000) * 1000 * 1000;      /* ms -> ns */
  rem.tv_sec = 0;
  rem.tv_nsec = 0;
  if ((0 != nanosleep (&req, &rem)) && (errno != EINTR))
    GE_LOG_STRERROR (NULL, GE_WARNING | GE_USER | GE_BULK, "nanosleep");

#elif WINDOWS
  SleepEx (delay, TRUE);
#else
  /* fall back to select */
  timeout.tv_sec = delay / CRON_UNIT_TO_SECONDS;
  timeout.tv_usec
    = (delay - timeout.tv_sec * CRON_UNIT_TO_SECONDS) * MICROSEC_TO_CRON_UNIT;
  ret = SELECT (0, NULL, NULL, NULL, &timeout);
  if ((ret == -1) && (errno != EINTR))
    GE_LOG_STRERROR (NULL, GE_WARNING | GE_USER | GE_BULK, "select");
#endif

}

void
PTHREAD_STOP_SLEEP (PThread * handle)
{
  int ret;

  if (handle == NULL)
    return;
#ifdef WINDOWS
  ret = QueueUserAPC ((PAPCFUNC) __PTHREAD_SIGNALED,
                      pthread_getw32threadhandle_np (handle->pt),
                      0) != 0 ? 0 : EINVAL;
#else
  ret = pthread_kill (handle->pt, SIGALRM);
#endif
  switch (ret)
    {
    case 0:
      break;                    /* ok */
    case EINVAL:
      GE_LOG (NULL,
              GE_ERROR | GE_USER | GE_DEVELOPER | GE_BULK,
              _("`%s' failed with error code %s: %s\n"),
              "pthread_kill", "EINVAL", STRERROR (ret));
      break;
    case ESRCH:
      /* ignore, thread might have already exited by chance */
      break;
    default:
      GE_LOG (NULL,
              GE_ERROR | GE_USER | GE_DEVELOPER | GE_BULK,
              _("`%s' failed with error code %d: %s\n"),
              "pthread_kill", ret, STRERROR (ret));
      break;
    }
}

#ifndef MINGW
static struct sigaction sig;
static struct sigaction old;
#endif


/**
 * Initialize the signal handlers, etc.
 */
void __attribute__ ((constructor)) pthread_handlers_ltdl_init ()
{
  /* make sure SIGALRM does not kill us */
#ifndef MINGW
  memset (&sig, 0, sizeof (struct sigaction));
  memset (&old, 0, sizeof (struct sigaction));
  sig.sa_flags = SA_NODEFER;
  sig.sa_handler = &sigalrmHandler;
  if (0 != sigaction (SIGALRM, &sig, &old))
    GE_LOG_STRERROR (NULL, GE_WARNING | GE_ADMIN | GE_BULK, "sigaction");
#else
  InitWinEnv (NULL);
#endif
}

void __attribute__ ((destructor)) pthread_handlers_ltdl_fini ()
{
#ifndef MINGW
  if (0 != sigaction (SIGALRM, &old, &sig))
    GE_LOG_STRERROR (NULL, GE_WARNING | GE_ADMIN | GE_BULK, "sigaction");
#else
  ShutdownWinEnv ();
#endif
}

/* end of pthread.c */
