/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file server/gnunetd.c
 * @brief Daemon that must run on every GNUnet peer.
 * @author Christian Grothoff
 * @author Larry Waldo
 * @author Tzvetan Horozov
 * @author Nils Durner
 */

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "core.h"
#include "connection.h"
#include "tcpserver.h"
#include "handler.h"
#include "startup.h"
#include "version.h"

void gnunet_main();

#ifdef MINGW
/**
 * Windows service information
 */
SERVICE_STATUS theServiceStatus;
SERVICE_STATUS_HANDLE hService;

/**
 * This function is called from the Windows Service Control Manager
 * when a service has to shutdown
 */
void WINAPI ServiceCtrlHandler(DWORD dwOpcode) {
  if (dwOpcode == SERVICE_CONTROL_STOP)
    win_shutdown_gnunetd(SERVICE_CONTROL_STOP);
}

/**
 * Main method of the windows service
 */
void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
  memset(&theServiceStatus, 0, sizeof(theServiceStatus));
  theServiceStatus.dwServiceType = SERVICE_WIN32;
  theServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
  theServiceStatus.dwCurrentState = SERVICE_RUNNING;

  hService = GNRegisterServiceCtrlHandler("GNUnet", ServiceCtrlHandler);
  if (! hService)
    return;

  GNSetServiceStatus(hService, &theServiceStatus);

  gnunet_main();

  theServiceStatus.dwCurrentState = SERVICE_STOPPED;
  GNSetServiceStatus(hService, &theServiceStatus);
}
#endif

/**
 * The main method of gnunetd. And here is how it works:
 * <ol>
 * <li>detach from tty, initialize all coresystems
 * <li>a) start core-services
 *     b) initialize application services and download hostlist
 * <li>wait for semaphore to signal shutdown
 * <li>shutdown all services (in roughly inverse order)
 * <li>exit
 * </ol>
 */
void gnunet_main() {
  int filedes[2]; /* pipe between client and parent */

  /* init 0: change user */
#ifndef MINGW
  char *user = getConfigurationString("GNUNETD", "USER");
  if (user && strlen(user))
    changeUser(user);
  FREENONNULL(user);
#endif

  /* init 1: version management for GNUnet core,
     essentially forces running gnunet-update
     whenever the version OR configuration changes. */
  if (OK != checkUpToDate())
    errexit(_("Configuration or GNUnet version changed.  You need to run `%s'!\n"),
	    "gnunet-update");

  /* init 2: become deamon, initialize core subsystems */
  if (NO == debug_flag())
    detachFromTerminal(filedes);

  LOG(LOG_MESSAGE,
      _("`%s' starting\n"),
      "gnunetd");

  initCore();
  initConnection();   /* requires core, starts transports! */
  loadApplicationModules(); /* still single-threaded! */

  /* initialize signal handler (CTRL-C / SIGTERM) */
  if (NO == debug_flag())
    detachFromTerminalComplete(filedes);
  writePIDFile();

  startCron();
  enableCoreProcessing();

  /* init 4: wait for shutdown */
  /* wait for SIGTERM, SIGTERM will set
     doShutdown to YES and send this thread
     a SIGUSR1 which will wake us up from the
     sleep */
  initSignalHandlers();
  LOG(LOG_MESSAGE,
      _("`%s' startup complete.\n"),
      "gnunetd");

  waitForSignalHandler();
  LOG(LOG_MESSAGE,
      _("`%s' is shutting down.\n"),
      "gnunetd");

  /* init 5: shutdown */
  disableCoreProcessing(); /* calls on applications! */
  stopCron(); /* avoid concurrency! */
  stopTCPServer(); /* calls on applications! */
  unloadApplicationModules(); /* requires connection+tcpserver+handler */

  doneConnection();  /* requires core, stops transports! */
  doneCore();

  /* init 6: goodbye */
  deletePIDFile();
  doneSignalHandlers();
  doneUtil();
}

/**
 * Initialize util (parse command line, options) and
 * call the main routine.
 */
int main(int argc, char * argv[]) {
  checkCompiler();
  umask(0);
  /* init 1: get options and basic services up */
  if (SYSERR == initUtil(argc, argv, &parseGnunetdCommandLine))
    return 0; /* parse error, --help, etc. */

#ifdef MINGW
  if (win_service()) {
    SERVICE_TABLE_ENTRY DispatchTable[] =
      {{"GNUnet", ServiceMain}, {NULL, NULL}};
    GNStartServiceCtrlDispatcher(DispatchTable);

    return 0;
  } else
#endif
    gnunet_main();

  return 0;
}

/* You have reached the end of GNUnet. You can shutdown your
   computer and get a life now. */
