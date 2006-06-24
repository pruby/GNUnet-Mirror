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

void initState();

/**
 * Clean shutdown of the state module
 */
void doneState();

/**
 * The following method is called in order to initialize the status
 * calls routines. After that it is safe to call each of the status
 * calls separately
 */
void initStatusCalls();

/**
 * Shutdown the module.
 */
void doneStatusCalls();

void gnunet_util_initIO();
void gnunet_util_doneIO();

/**
 * Initialize controlThread.
 */
void initCron();

/**
 * Make sure to call stopCron before calling this method!
 */
void doneCron();

/**
 * Set our process priority
 */
void setProcessPrio() {
  char *str;
  int prio = 0;

  /* Get setting as string */
  str = getConfigurationString(testConfigurationString("GNUNETD",
						       "_MAGIC_",
						       "YES")
			       ? "GNUNETD"
			       : "GNUNET",
			       "PROCESS-PRIORITY");
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
      LOG_STRERROR(LOG_WARNING, "nice");
#endif
    FREE(str);
  }
}

static int initStatus;

/**
 * Initialize the util library. Use argc, argv and the given parser
 * for processing command-line options <strong>after</strong> the
 * configuration module was initialized, but <strong>before</strong> logging
 * and other configuration-dependent features are started.
 */
int initUtil(int argc,
	     char * argv[],
	     CommandLineParser parser) {

#ifdef MINGW
  if (InitWinEnv() != ERROR_SUCCESS)
  	return SYSERR;
#endif
#if ENABLE_NLS
  setlocale (LC_ALL, "");
  BINDTEXTDOMAIN("GNUnet", LOCALEDIR);
  textdomain("GNUnet");
#endif
  gnunet_util_initIO();
  initConfiguration();
  if (argc > 0)
    setConfigurationString("MAIN",
			   "ARGV[0]",
			   argv[0]);
  initCron();
  if (parser != NULL)
    if (SYSERR == parser(argc, argv))
      return SYSERR;
  readConfiguration();
  setProcessPrio();
  initLogging();
  initStatus = testConfigurationString("GNUNETD",
				       "_MAGIC_",
				       "YES");
  if (initStatus)
    initStatusCalls();
  initState();
  return OK;
}

void doneUtil() {
  if (initStatus) {
    doneStatusCalls();
    initStatus = 0;
  }
  doneCron();
  doneState();
  LOG(LOG_MESSAGE,
      _("Shutdown complete.\n"));
#ifdef MINGW
  ShutdownWinEnv();
#endif
  gnunet_util_doneIO();
}




char * winErrorStr(const char *prefix, 
		   int dwErr) {
#ifdef WINDOWS
  char *err, *ret;
  int mem;
  
  if (! FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		      NULL, 
		      (DWORD) dwErr, 
		      MAKELANGID(LANG_NEUTRAL, 
				 SUBLANG_DEFAULT), 
		      (LPTSTR) &err,
		      0,
		      NULL )) {
    err = "";
  }
  
  mem = strlen(err) + strlen(prefix) + 20;
  ret = (char *) malloc(mem);
  
  snprintf(ret, mem, "%s: %s (#%u)", 
	   prefix, 
	   err, 
	   dwErr);
  LocalFree(err);
  return ret;
#else
	return NULL;
#endif
}




/* end of initialize.c */
