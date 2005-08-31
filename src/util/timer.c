/*
     This file is part of GNUnet.
     (C) 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file util/timer.c
 * @brief abstraction of the time and sleep functions
 * @author Christian Grothoff
 *
 * GNUnet uses both 32-bit and 64-bit timer values.
 *
 * 32-bit timers are measured in seconds and are used
 * for some of the messages exchanged over
 * the network.  We don't really care if they overrun
 * in 2037, as long as the relative times are correct.<p>
 * The type used for these values is TIME_T since
 * some architectures use 64-bit time_t values.
 * We wrap all time() calls into "TIME()" calls and
 * replace time_t with a GNUnet internal, 32-bit
 * TIME_T type.
 *
 * <p>
 * GNUnet also uses 64-bit cron_t timer values.
 * This is a milli-second precision timer that is
 * mostly used for internal timers.  Some
 * network messages also use milli-second precision,
 * but these are so far always relative times which
 * are again represented as 32-bit (int) values.
 * <p>
 *
 * Consequently, whenever handling times in GNUnet,
 * watch out for the types and units involved.
 */

#include "gnunet_util.h"
#include "platform.h"

/* change this value to artificially speed up all
   GNUnet cron timers by this factor. E.g. with 10,
   a cron-job scheduled after 1 minute in the code
   will occur after 6 seconds. This is useful for
   testing bugs that would otherwise occur only after
   a long time.

   For releases, this value should always be 1 */
#define SPEED_UP 1

/** number of cron units (ms) in a second */
#define CRON_UNIT_TO_SECONDS (1000 / SPEED_UP)

/** number of ns [usec] in a cron-unit (1000000) */
#define NANOSEC_TO_CRON_UNIT (1000 * 1000 * SPEED_UP)

/** number of us [usec] in a cron-unit (1000) */
#define MICROSEC_TO_CRON_UNIT (1000 * SPEED_UP)


/**
 * Sleep for the specified time interval.  A signal interrupts the
 * sleep.  Caller is responsible to check that the sleep was long
 * enough.
 *
 * @return 0 if there was no interrupt, 1 if there was, -1 on error.
 */
int gnunet_util_sleep(cron_t delay) {
#if LINUX || SOLARIS || SOMEBSD || OSX
  struct timespec req;
  struct timespec rem;
  req.tv_sec
    = delay / CRON_UNIT_TO_SECONDS;
  req.tv_nsec
    = (delay - req.tv_sec * CRON_UNIT_TO_SECONDS)
    * NANOSEC_TO_CRON_UNIT;
  rem.tv_sec = 0;
  rem.tv_nsec = 0;
  if (0 != nanosleep(&req, &rem)) {
    if (errno == EINTR) {
      return 1;
    } else {
      LOG_STRERROR(LOG_WARNING, "nanosleep");
      return -1;
    }
  } else
    return 0;
#elif WINDOWS
  SleepEx(delay, TRUE);
  return 0; /* interrupt information is just an information, but
	       not strict; error handling is, well, lacking,
	       but this is Win32... */
#else
  /* fall back to select */
  int ret;
  struct timeval timeout;

  timeout.tv_sec
    = delay / CRON_UNIT_TO_SECONDS;
  timeout.tv_usec
    = (delay - timeout.tv_sec * CRON_UNIT_TO_SECONDS)
    * MICROSEC_TO_CRON_UNIT;
  ret = SELECT(0, NULL, NULL, NULL, &timeout);
  if (ret == -1) {
    if (errno == EINTR) {
      return 1;
    } else {
      LOG_STRERROR(LOG_WARNING, "select");
      return -1;
    }
  }
  return 0;
#endif
}

/**
 * Get the current time (works just as "time", just that we use the
 * unit of time that the cron-jobs use (and is 64 bit)).
 *
 * @param setme will set the current time if non-null
 * @return the current time
 */
cron_t cronTime(cron_t * setme) {
  cron_t res;
  struct timeval tv;
#ifndef WINDOWS
  struct timezone tz; /* man page says it's obsolete, but
			 I'd rather not pass a NULL pointer */

  gettimeofday(&tv, &tz);
#else
  gettimeofday(&tv, NULL);
#endif
  res =
    (((cron_t)tv.tv_sec) * CRON_UNIT_TO_SECONDS) +
    (tv.tv_usec / MICROSEC_TO_CRON_UNIT);
  if (setme != NULL)
    *setme = res;
  return res;
}

/**
 * TIME prototype. "man time".
 */
TIME_T TIME(TIME_T * t) {
  TIME_T now;

  now = (TIME_T) time(NULL); /* potential 64-bit to 32-bit conversion!*/
  if (t != NULL)
    *t = now;
  return now;
}

/**
 * "man ctime_r".  Automagically expands the 32-bit
 * GNUnet time value to a 64-bit value of the current
 * epoc if needed.
 */
char * GN_CTIME(const TIME_T * t) {
  TIME_T now;
  time_t tnow;

  tnow = time(NULL);
  now = (TIME_T) tnow;
  tnow = tnow - now + *t;
#ifdef ctime_r
  return ctime_r(&tnow, MALLOC(32));
#else
  return STRDUP(ctime(&tnow));
#endif
}

/**
 * Give relative time in human-readable fancy format.
 */
char * timeIntervalToFancyString(cron_t delta) {
  const char * unit = _(/* time unit */ "ms");
  char * ret;

  if (delta > 5 * 1000) {
    delta = delta / 1000;
    unit = _(/* time unit */ "s");
    if (delta > 5 * 60) {
      delta = delta / 60;
      unit = _(/* time unit */ "m");
      if (delta > 5 * 60) {
	delta = delta / 60;
	unit = _(/* time unit */ "h");
	if (delta > 5 * 24) {
	  delta = delta / 24;
	  unit = _(/* time unit */ " days");	
	}	
      }		
    }	
  }	
  ret = MALLOC(32);
  SNPRINTF(ret,
	   32,
	   "%llu%s",
	   delta,
	   unit);
  return ret;
}

/* end of timer.c */
