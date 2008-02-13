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
typedef unsigned long long GNUNET_CronTime;


/**
 * @brief constants to specify time
 */
#define GNUNET_CRON_MILLISECONDS ((GNUNET_CronTime)1L)
#define GNUNET_CRON_SECONDS ((GNUNET_CronTime)(1000 * GNUNET_CRON_MILLISECONDS))
#define GNUNET_CRON_MINUTES ((GNUNET_CronTime) (60 * GNUNET_CRON_SECONDS))
#define GNUNET_CRON_HOURS ((GNUNET_CronTime)(60 * GNUNET_CRON_MINUTES))
#define GNUNET_CRON_DAYS ((GNUNET_CronTime)(24 * GNUNET_CRON_HOURS))
#define GNUNET_CRON_WEEKS ((GNUNET_CronTime)(7 * GNUNET_CRON_DAYS))
#define GNUNET_CRON_MONTHS ((GNUNET_CronTime)(30 * GNUNET_CRON_DAYS))
#define GNUNET_CRON_YEARS ((GNUNET_CronTime)(365 * GNUNET_CRON_DAYS))

/**
 * How long will we accept locks to be held before
 * reporting that there maybe a problem?  Set to
 * zero to disable reporting.
 */
#define GNUNET_REALTIME_LIMIT (000 * GNUNET_CRON_MILLISECONDS)

/**
 * Main method of a thread.
 */
typedef void *(*GNUNET_ThreadMainFunction) (void *);

/**
 * @brief Encapsulation of a pthread handle.
 */
struct GNUNET_ThreadHandle;

/**
 * @brief Structure for MUTual EXclusion (Mutex).
 */
struct GNUNET_Mutex;

/**
 * @brief semaphore abstraction (for pthreads)
 */
struct GNUNET_Semaphore;

/**
 * Returns GNUNET_YES if pt is the handle for THIS thread.
 */
int GNUNET_thread_test_self (struct GNUNET_ThreadHandle *pt);

/**
 * Get the handle for THIS thread.
 */
struct GNUNET_ThreadHandle *GNUNET_thread_get_self (void);

/**
 * Release handle for a thread (should have been
 * obtained using GNUNET_thread_get_self).
 */
void GNUNET_thread_release_self (struct GNUNET_ThreadHandle *pt);

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
struct GNUNET_ThreadHandle *GNUNET_thread_create (GNUNET_ThreadMainFunction
                                                  main, void *arg,
                                                  unsigned int stackSize);



/**
 * Wait for the other thread to terminate.  May only be called
 * once per created thread, the handle is afterwards invalid.
 *
 * @param ret set to the return value of the other thread.
 */
void GNUNET_thread_join_at_file_line_ (struct GNUNET_ThreadHandle *handle,
                                       void **ret, const char *file,
                                       unsigned int line);

/**
 * Wait for the other thread to terminate.  May only be called
 * once per created thread, the handle is afterwards invalid.
 *
 * @param ret set to the return value of the other thread.
 */
#define GNUNET_thread_join(handle,ret) GNUNET_thread_join_at_file_line_(handle,ret,__FILE__,__LINE__)

/**
 * Sleep for the specified time interval.  GNUNET_thread_stop_sleep can be
 * used to interrupt the sleep.  Caller is responsible to check that
 * the sleep was long enough.
 *
 * @param time how long to sleep (in milli seconds)
 */
void GNUNET_thread_sleep (GNUNET_CronTime time);

/**
 * Get the current time (in cron-units).
 *
 * @return the current time
 */
GNUNET_CronTime GNUNET_get_time (void);

/**
 * Stop the sleep of another thread.
 */
void GNUNET_thread_stop_sleep (struct GNUNET_ThreadHandle *handle);

struct GNUNET_Mutex *GNUNET_mutex_create (int isRecursive);

void GNUNET_mutex_destroy (struct GNUNET_Mutex *mutex);

void GNUNET_mutex_lock_at_file_line_ (struct GNUNET_Mutex *mutex,
                                      const char *file, unsigned int line);

#define GNUNET_mutex_lock(mutex) GNUNET_mutex_lock_at_file_line_(mutex, __FILE__, __LINE__)

void GNUNET_mutex_unlock (struct GNUNET_Mutex *mutex);

struct GNUNET_Semaphore *GNUNET_semaphore_create (int value);

void GNUNET_semaphore_destroy (struct GNUNET_Semaphore *sem);

/**
 * @param block set to GNUNET_NO to never block (and
 *        thus fail if semaphore counter is 0)
 * @return GNUNET_SYSERR if would block, otherwise
 *  new count value after change
 */
int GNUNET_semaphore_down_at_file_line_ (struct GNUNET_Semaphore *sem,
                                         int mayblock,
                                         int longwait, const char *file,
                                         unsigned int line);


/**
 * @param block set to GNUNET_NO to never block (and
 *        thus fail if semaphore counter is 0)
 * @return GNUNET_SYSERR if would block, otherwise
 *  new count value after change
 */
#define GNUNET_semaphore_down(sem, mayblock) GNUNET_semaphore_down_at_file_line_(sem, mayblock, GNUNET_YES, __FILE__, __LINE__)


/**
 * Like GNUNET_semaphore_down, just with the expectation
 * that this operation does not take a long time.
 * (used for debugging unexpected high-latency
 * behavior).
 *
 * @param block set to GNUNET_NO to never block (and
 *        thus fail if semaphore counter is 0)
 * @return GNUNET_SYSERR if would block, otherwise
 *  new count value after change
 */
#define GNUNET_semaphore_down_fast(sem, mayblock) GNUNET_semaphore_down_at_file_line_(sem, mayblock, GNUNET_NO, __FILE__, __LINE__)

/**
 * function increments the semaphore and signals any threads that
 * are blocked waiting a change in the semaphore.
 *
 * @return new count value of the semaphore after increment
 */
int GNUNET_semaphore_up (struct GNUNET_Semaphore *sem);

/**
 * Programatically shutdown the application.
 */
void GNUNET_shutdown_initiate (void);

/**
 * Test if the shutdown has been initiated.
 *
 * @return GNUNET_YES if we are shutting down, GNUNET_NO otherwise
 */
int GNUNET_shutdown_test (void);

/**
 * Wait until the shutdown has been initiated.  This
 * should be called by the main thread (if it has
 * nothing better to do) to wait for a user signal
 * (or other thread) to initiate the shutdown.
 */
void GNUNET_shutdown_wait_for (void);

struct GNUNET_SignalHandlerContext;

/**
 * A signal handler.  Since different OSes have different signatures
 * for their handlers, the API only gives the most restrictive
 * signature -- no arguments, no return value.  Note that this will
 * work even if the OS expects a function with arguments.  However,
 * the implementation must guarantee that this handler is not called
 * for signals other than the one that it has been registered for.
 */
typedef void (*GNUNET_SignalHandler) (void);

/**
 * Install a signal handler that will be run if the
 * given signal is received.
 */
struct GNUNET_SignalHandlerContext *GNUNET_signal_handler_install (int signal,
                                                                   GNUNET_SignalHandler
                                                                   handler);

void GNUNET_signal_handler_uninstall (int signal,
                                      GNUNET_SignalHandler handler,
                                      struct GNUNET_SignalHandlerContext
                                      *ctx);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_UTIL_THREADS_H */
#endif
/* end of gnunet_util_threads.h */
