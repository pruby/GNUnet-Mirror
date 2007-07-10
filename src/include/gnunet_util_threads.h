/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_threads.h
 * @brief pthreads wapper and thread related services
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_UTIL_THREADS_H
#define GNUNET_UTIL_THREADS_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Time for absolute times used by cron (64 bit)
 */
typedef unsigned long long cron_t;


/**
 * @brief constants to specify time
 */
#define cronMILLIS ((cron_t)1)
#define cronSECONDS ((cron_t)(1000 * cronMILLIS))
#define cronMINUTES ((cron_t) (60 * cronSECONDS))
#define cronHOURS ((cron_t)(60 * cronMINUTES))
#define cronDAYS ((cron_t)(24 * cronHOURS))
#define cronWEEKS ((cron_t)(7 * cronDAYS))
#define cronMONTHS ((cron_t)(30 * cronDAYS))
#define cronYEARS ((cron_t)(365 * cronDAYS))

/**
 * How long will we accept locks to be held before
 * reporting that there maybe a problem?  Set to
 * zero to disable reporting.
 */
#define REALTIME_LIMIT (000 * cronMILLIS)

/**
 * Main method of a thread.
 */
typedef void *(*PThreadMain) (void *);

/**
 * @brief Encapsulation of a pthread handle.
 */
struct PTHREAD;

/**
 * @brief Structure for MUTual EXclusion (Mutex).
 */
struct MUTEX;

/**
 * @brief semaphore abstraction (for pthreads)
 */
struct SEMAPHORE;

/**
 * Returns YES if pt is the handle for THIS thread.
 */
int PTHREAD_TEST_SELF (struct PTHREAD *pt);

/**
 * Get the handle for THIS thread.
 */
struct PTHREAD *PTHREAD_GET_SELF (void);

/**
 * Release handle for a thread (should have been
 * obtained using PTHREAD_GET_SELF).
 */
void PTHREAD_REL_SELF (struct PTHREAD *pt);

/**
 * Create a thread. Use this method instead of pthread_create since
 * BSD may only give a 1k stack otherwise.
 *
 * @param main the main method of the thread
 * @param arg the argument to main
 * @param stackSize the size of the stack of the thread in bytes.
 *        Note that if the stack overflows, some OSes (seen under BSD)
 *        will just segfault and gdb will give a messed-up stacktrace.
 * @return the handle
 */
struct PTHREAD *PTHREAD_CREATE (PThreadMain main,
                                void *arg, unsigned int stackSize);



/**
 * Wait for the other thread to terminate.  May only be called
 * once per created thread, the handle is afterwards invalid.
 *
 * @param ret set to the return value of the other thread.
 */
void PTHREAD_JOIN_FL (struct PTHREAD *handle,
                      void **ret, const char *file, unsigned int line);

/**
 * Wait for the other thread to terminate.  May only be called
 * once per created thread, the handle is afterwards invalid.
 *
 * @param ret set to the return value of the other thread.
 */
#define PTHREAD_JOIN(handle,ret) PTHREAD_JOIN_FL(handle,ret,__FILE__,__LINE__)

/**
 * Sleep for the specified time interval.  PTHREAD_STOP_SLEEP can be
 * used to interrupt the sleep.  Caller is responsible to check that
 * the sleep was long enough.
 *
 * @param time how long to sleep (in milli seconds)
 */
void PTHREAD_SLEEP (cron_t time);

/**
 * Get the current time (in cron-units).
 *
 * @return the current time
 */
cron_t get_time (void);

/**
 * Stop the sleep of anothe thread.
 */
void PTHREAD_STOP_SLEEP (struct PTHREAD *handle);

struct MUTEX *MUTEX_CREATE (int isRecursive);

void MUTEX_DESTROY (struct MUTEX *mutex);

void MUTEX_LOCK_FL (struct MUTEX *mutex, const char *file, unsigned int line);

#define MUTEX_LOCK(mutex) MUTEX_LOCK_FL(mutex, __FILE__, __LINE__)

void MUTEX_UNLOCK (struct MUTEX *mutex);

struct SEMAPHORE *SEMAPHORE_CREATE (int value);

void SEMAPHORE_DESTROY (struct SEMAPHORE *sem);

/**
 * @param block set to NO to never block (and
 *        thus fail if semaphore counter is 0)
 * @return SYSERR if would block, otherwise
 *  new count value after change
 */
int SEMAPHORE_DOWN_FL (struct SEMAPHORE *sem,
                       int mayblock,
                       int longwait, const char *file, unsigned int line);


/**
 * @param block set to NO to never block (and
 *        thus fail if semaphore counter is 0)
 * @return SYSERR if would block, otherwise
 *  new count value after change
 */
#define SEMAPHORE_DOWN(sem, mayblock) SEMAPHORE_DOWN_FL(sem, mayblock, YES, __FILE__, __LINE__)


/**
 * Like SEMAPHORE_DOWN, just with the expectation
 * that this operation does not take a long time.
 * (used for debugging unexpected high-latency
 * behavior).
 *
 * @param block set to NO to never block (and
 *        thus fail if semaphore counter is 0)
 * @return SYSERR if would block, otherwise
 *  new count value after change
 */
#define SEMAPHORE_DOWN_FAST(sem, mayblock) SEMAPHORE_DOWN_FL(sem, mayblock, NO, __FILE__, __LINE__)

/**
 * function increments the semaphore and signals any threads that
 * are blocked waiting a change in the semaphore.
 *
 * @return new count value of the semaphore after increment
 */
int SEMAPHORE_UP (struct SEMAPHORE *sem);

/**
 * Programatically shutdown the application.
 */
void GNUNET_SHUTDOWN_INITIATE (void);

/**
 * Test if the shutdown has been initiated.
 *
 * @return YES if we are shutting down, NO otherwise
 */
int GNUNET_SHUTDOWN_TEST (void);

/**
 * Wait until the shutdown has been initiated.  This
 * should be called by the main thread (if it has
 * nothing better to do) to wait for a user signal
 * (or other thread) to initiate the shutdown.
 */
void GNUNET_SHUTDOWN_WAITFOR (void);

struct SignalHandlerContext;

/**
 * A signal handler.  Since different OSes have different signatures
 * for their handlers, the API only gives the most restrictive
 * signature -- no arguments, no return value.  Note that this will
 * work even if the OS expects a function with arguments.  However,
 * the implementation must guarantee that this handler is not called
 * for signals other than the one that it has been registered for.
 */
typedef void (*SignalHandler) (void);

/**
 * Install a signal handler that will be run if the
 * given signal is received.
 */
struct SignalHandlerContext *signal_handler_install (int signal,
                                                     SignalHandler handler);

void signal_handler_uninstall (int signal,
                               SignalHandler handler,
                               struct SignalHandlerContext *ctx);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_UTIL_THREADS_H */
#endif
/* end of gnunet_util_threads.h */
