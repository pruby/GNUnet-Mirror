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
static struct GNUNET_Semaphore *shutdown_signal;

static int shutdown_active;

static struct GNUNET_SignalHandlerContext *shc_int;

static struct GNUNET_SignalHandlerContext *shc_term;

static struct GNUNET_SignalHandlerContext *shc_quit;

void
GNUNET_shutdown_initiate ()
{
  GNUNET_GE_ASSERT (NULL, shutdown_signal != NULL);
  shutdown_active = GNUNET_YES;
  GNUNET_semaphore_up (shutdown_signal);
}

int
GNUNET_shutdown_test ()
{
  return shutdown_active;
}

void
GNUNET_shutdown_wait_for ()
{
  GNUNET_semaphore_down (shutdown_signal, GNUNET_YES);
}

static void
run_shutdown ()
{
  GNUNET_shutdown_initiate ();
}

/**
 * Stop the application under Windows.
 * @param dwCtrlType is ignored
 */
#ifdef MINGW
BOOL WINAPI
run_shutdown_win (DWORD dwCtrlType)
{
  switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
    case CTRL_LOGOFF_EVENT:
    case SERVICE_CONTROL_STOP:
      GNUNET_shutdown_initiate ();
    }

  return TRUE;
}
#endif

/**
 * Initialize the signal handlers, etc.
 */
void __attribute__ ((constructor)) GNUNET_shutdown_handlers_ltdl_init ()
{
  GNUNET_GE_ASSERT (NULL, shutdown_signal == NULL);
  GNUNET_GE_ASSERT (NULL, shutdown_active == GNUNET_NO);
  shutdown_signal = GNUNET_semaphore_create (0);
#ifndef MINGW
  shc_int = GNUNET_signal_handler_install (SIGINT, &run_shutdown);
  shc_term = GNUNET_signal_handler_install (SIGTERM, &run_shutdown);
  shc_quit = GNUNET_signal_handler_install (SIGQUIT, &run_shutdown);
#else
  SetConsoleCtrlHandler (&run_shutdown_win, TRUE);
#endif
}

void __attribute__ ((destructor)) GNUNET_shutdown_handlers_ltdl_fini ()
{
#ifndef MINGW
  GNUNET_signal_handler_uninstall (SIGINT, &run_shutdown, shc_int);
  GNUNET_signal_handler_uninstall (SIGTERM, &run_shutdown, shc_term);
  GNUNET_signal_handler_uninstall (SIGQUIT, &run_shutdown, shc_quit);
#else
  SetConsoleCtrlHandler (&run_shutdown_win, FALSE);
#endif
  GNUNET_semaphore_destroy (shutdown_signal);
  shutdown_signal = NULL;
  shc_int = NULL;
  shc_term = NULL;
  shc_quit = NULL;
}

/* end of shutdown.c */
