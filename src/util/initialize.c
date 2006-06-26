/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/initialize.c
 * @brief functions to initializing libgnunetutil in the proper order.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"

/**
 * Set our process priority
 */
static void setProcessPrio(const char * str) {
  int prio = 0;

  if (str) {
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
      prio = atoi(str);

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
    if (errno != 0)
      GE_LOG_STRERROR(NULL,
		      GE_WARNING | GE_ADMIN | GE_BULK,
		      "nice");
#endif
  }
}

/**
 * Initialize the util library. Use argc, argv and the given parser
 * for processing command-line options <strong>after</strong> the
 * configuration module was initialized, but <strong>before</strong> logging
 * and other configuration-dependent features are started.
 */
int initUtil(int argc,
	     char * argv[]) {

#ifdef MINGW
  if (InitWinEnv() != ERROR_SUCCESS)
  	return SYSERR;
#endif
#if ENABLE_NLS
  setlocale (LC_ALL, "");
  BINDTEXTDOMAIN("GNUnet", LOCALEDIR);
  textdomain("GNUnet");
#endif
  /*  if (argc > 0)
    setConfigurationString("MAIN",
			   "ARGV[0]",
			   argv[0]);*/
  // setProcessPrio();
  return OK;
}

void doneUtil() {
#ifdef MINGW
  ShutdownWinEnv();
#endif
}


/* end of initialize.c */
