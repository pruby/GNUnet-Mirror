/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"
#include "gnunet_core.h"
#include "core.h"
#include "connection.h"
#include "tcpserver.h"
#include "handler.h"
#include "startup.h"
#include "version.h"

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

  GE_LOG(ectx,
	 GE_INFO | GE_USER | GE_REQUEST,
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
  GE_LOG(ectx,
	 GE_INFO | GE_USER | GE_REQUEST,
	 _("`%s' startup complete.\n"),
	 "gnunetd");
  
  waitForSignalHandler();
  GE_LOG(ectx,
	 GE_INFO | GE_USER | GE_REQUEST,
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
}

#ifdef MINGW
/**
 * Main method of the windows service
 */
void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {
  win_service_main(gnunet_main);
}
#endif

/**
 * Initialize util (parse command line, options) and
 * call the main routine.
 */
int main(int argc, 
	 char * argv[]) {
  int ret;
  struct GC_Configuration * cfg;
  struct GE_Context * ectx;

  if ( (4 != sizeof(MESSAGE_HEADER)) ||
       (600 != sizeof(P2P_hello_MESSAGE)) ) {
    fprintf(stderr,
	    "Sorry, your C compiler did not properly align the C structs. Aborting.\n");
    return -1;
  }

  ectx = GE_create_context_stderr(NO, 
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  /* init 1: get options and basic services up */
  ret = gnunet_parse_options("gnunetd",
			     ectx,
			     cfg,
			     &gnunetdOptions,
			     (unsigned int) argc,
			     argv);
  if (ret == -1) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;  
  }
  /* now: patch up default context according to config! */

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
