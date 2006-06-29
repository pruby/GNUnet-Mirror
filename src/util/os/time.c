/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/time.c
 * @brief wrappers for time functions
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_os.h"
#include "gnunet_util_string.h"

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
