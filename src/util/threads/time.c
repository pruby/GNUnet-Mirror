/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/threads/time.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_threads.h"

/**
 * Get the current time (works just as "time", just that we use the
 * unit of time that the cron-jobs use (and is 64 bit)).
 *
 * @return the current time
 */
cron_t get_time() {
  struct timeval tv;
#ifndef WINDOWS
  struct timezone tz; /* man page says it's obsolete, but
			 I'd rather not pass a NULL pointer */

  gettimeofday(&tv, &tz);
#else
  gettimeofday(&tv, NULL);
#endif
  return (((cron_t)tv.tv_sec) * 1000) + (tv.tv_usec / 1000);
}
