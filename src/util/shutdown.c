/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @file util/shutdown.c
 * @brief code to allow clean shutdown of application with signals
 * @author Christian Grothoff
 *
 * Helper code for writing proper termination code when an application
 * receives a SIGTERM/SIGHUP etc.
 */

#include "gnunet_util.h"
#include "platform.h"

/**
 * Semaphore used to signal "shutdown"
 */
static Semaphore * shutdown_signal = NULL;
static int shutdown_active;

/**
 * Stop the application.
 * @param signum is ignored
 */
void run_shutdown(int signum) {
  if (shutdown_signal != NULL) {
    shutdown_active = YES;
    SEMAPHORE_UP(shutdown_signal);  
  }
}

/**
 * Stop the application under Windows.
 * @param signum is ignored
 */
#ifdef MINGW
BOOL WINAPI run_shutdown_win(DWORD dwCtrlType)
{
  switch(dwCtrlType)
  {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
    case CTRL_LOGOFF_EVENT:
      run_shutdown(1);
  }
  
  return TRUE;
}
#endif


/**
 * Test if the shutdown has been initiated.
 * @return YES if we are shutting down, NO otherwise
 */
int testShutdown() {
  return shutdown_active;
}

/**
 * Initialize the signal handlers, etc.
 */
void initializeShutdownHandlers() {
#ifndef MINGW
  struct sigaction sig;
  struct sigaction oldsig;
#endif

  if (shutdown_signal != NULL)
    errexit(" initializeShutdownHandlers called twice!\n");
  shutdown_signal = SEMAPHORE_NEW(0); 
  shutdown_active = NO;
#ifndef MINGW
  sig.sa_handler = &run_shutdown;
  sigemptyset(&sig.sa_mask);
#ifdef SA_INTERRUPT
  sig.sa_flags = SA_INTERRUPT; /* SunOS */
#else
  sig.sa_flags = SA_RESTART;
#endif    
  sigaction(SIGINT,  &sig, &oldsig);
  sigaction(SIGTERM, &sig, &oldsig);
  sigaction(SIGQUIT, &sig, &oldsig);
#else
  SetConsoleCtrlHandler(&run_shutdown_win, TRUE);
#endif
}

/**
 * Wait until the shutdown has been initiated.
 */
void wait_for_shutdown() {
  SEMAPHORE_DOWN(shutdown_signal);
}

void doneShutdownHandlers() {
#ifndef MINGW
  struct sigaction sig;
  struct sigaction oldsig;

  sig.sa_handler = SIG_DFL;
  sigemptyset(&sig.sa_mask);
#ifdef SA_INTERRUPT
  sig.sa_flags = SA_INTERRUPT; /* SunOS */
#else
  sig.sa_flags = SA_RESTART;
#endif
  sigaction(SIGINT,  &sig, &oldsig);
  sigaction(SIGTERM, &sig, &oldsig);
  sigaction(SIGQUIT, &sig, &oldsig);
#else
  SetConsoleCtrlHandler(&run_shutdown_win, FALSE);
#endif

  SEMAPHORE_FREE(shutdown_signal);
  shutdown_signal = NULL;
}

/* end of shutdown.c */
