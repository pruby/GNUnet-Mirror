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
 * @file util/threads/shutdown.c
 * @brief code to allow clean shutdown of application with signals
 * @author Christian Grothoff
 *
 * Helper code for writing proper termination code when an application
 * receives a SIGTERM/SIGHUP etc.
 */

#include "gnunet_util_threads.h"
#include "gnunet_util_error.h"
#include "gnunet_util_string.h"
#include "platform.h"

/**
 * Semaphore used to signal "shutdown"
 */
static struct SEMAPHORE * shutdown_signal;

static int shutdown_active;

void GNUNET_SHUTDOWN_INITIATE() {
  GE_ASSERT(NULL, shutdown_signal != NULL);
  shutdown_active = YES;
  SEMAPHORE_UP(shutdown_signal);
}

int GNUNET_SHUTDOWN_TEST() {
  return shutdown_active;
}

void GNUNET_SHUTDOWN_WAITFOR() {
  SEMAPHORE_DOWN(shutdown_signal, YES);
}

#ifdef MINGW
BOOL WINAPI run_shutdown_win(DWORD dwCtrlType) {
  switch(dwCtrlType) {
  case CTRL_C_EVENT:
  case CTRL_CLOSE_EVENT:
  case CTRL_SHUTDOWN_EVENT:
  case CTRL_LOGOFF_EVENT:
    GNUNET_SHUTDOWN_INITIATE();
  }
  return TRUE;
}
#else
static void run_shutdown(int signum) {
  GNUNET_SHUTDOWN_INITIATE();
}
#endif

/**
 * Initialize the signal handlers, etc.
 */
void __attribute__ ((constructor)) shutdown_handlers_ltdl_init() {
#ifndef MINGW
  struct sigaction sig;
  struct sigaction oldsig;
#endif

  GE_ASSERT(NULL, shutdown_signal == NULL);
  GE_ASSERT(NULL, shutdown_active == NO);
  shutdown_signal = SEMAPHORE_CREATE(0);
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

void __attribute__ ((destructor)) shutdown_handlers_ltdl_fini() {
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
  SEMAPHORE_DESTROY(shutdown_signal);
  shutdown_signal = NULL;
}

/* end of shutdown.c */
