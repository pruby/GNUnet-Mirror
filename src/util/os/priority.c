/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/priority.c
 * @brief Methods to set process priority
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util_error.h"
#include "gnunet_util_os.h"

/**
 * Set our process priority
 */
int os_set_process_priority(struct GE_Context * ectx,
			    const char * str) {
  int prio = 0;

  GE_ASSERT(ectx,
	    str != NULL);
  /* We support four levels (NORMAL, ABOVE NORMAL, BELOW NORMAL, HIGH and IDLE)
   * and the usual numeric nice() increments */
  if (strcmp(str, "NORMAL") == 0)
#ifdef MINGW
    prio = NORMAL_PRIORITY_CLASS;
#else
  prio = 0;
#endif
  else if (strcmp(str, "ABOVE NORMAL") == 0)
#ifdef MINGW
    prio = ABOVE_NORMAL_PRIORITY_CLASS;
#else
  prio = -5;
#endif
  else if (strcmp(str, "BELOW NORMAL") == 0)
#ifdef MINGW
    prio = BELOW_NORMAL_PRIORITY_CLASS;
#else
  prio = 10;
#endif
  else if (strcmp(str, "HIGH") == 0)
#ifdef MINGW
    prio = HIGH_PRIORITY_CLASS;
#else
  prio = -10;
#endif
  else if (strcmp(str, "IDLE") == 0)
#ifdef MINGW
    prio = IDLE_PRIORITY_CLASS;
#else
  prio = 19;
#endif
  else {
    if (1 != sscanf(str,
		    "%d",
		    &prio)) {
      GE_LOG(ectx,
	     GE_USER | GE_BULK | GE_ERROR,
	     _("Invalid process priority `%s'\n"),
	     str);
      return SYSERR;
    }

#ifdef MINGW
  /* Convert the nice increment to a priority class */
    if (prio == 0)
      prio = NORMAL_PRIORITY_CLASS;
    else if (prio > 0 && prio <= 10)
      prio = BELOW_NORMAL_PRIORITY_CLASS;
    else if (prio > 0)
      prio = IDLE_PRIORITY_CLASS;
    else if (prio < 0 && prio >= -10)
      prio = ABOVE_NORMAL_PRIORITY_CLASS;
    else if (prio < 0)
      prio = HIGH_PRIORITY_CLASS;
#endif
  }

  /* Set process priority */
#ifdef MINGW
  SetPriorityClass(GetCurrentProcess(), prio);
#else
  errno = 0;
  nice(prio);
  if (errno != 0) {
    GE_LOG_STRERROR(ectx,
		    GE_WARNING | GE_ADMIN | GE_BULK,
		    "nice");
    return SYSERR;
  }
#endif
  return OK;
}

