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
#include "gnunet_util_boot.h"
#include "gnunet_util_cron.h"
#include "gnunet_util_error_loggers.h"
#include "gnunet_core.h"
#include "gnunet_directories.h"
#include "core.h"
#include "connection.h"
#include "tcpserver.h"
#include "handler.h"
#include "startup.h"
#include "version.h"

static struct GC_Configuration * cfg;
static struct GE_Context * ectx = NULL;

static struct CronManager * cron;

static char * cfgFilename = DEFAULT_DAEMON_CONFIG_FILE;

static int debug_flag;

static int quiet_flag;

#ifndef WINDOWS
/**
 * Cron job that triggers re-reading of the configuration.
 */
static void reread_config_helper(void * unused) {
  GE_ASSERT(NULL, cfgFilename != NULL);
  GC_parse_configuration(cfg,
			 cfgFilename);
}

/**
 * Signal handler for SIGHUP.
 * Re-reads the configuration file.
 */
static void reread_config() {
  cron_add_job(cron,
	       &reread_config_helper,
	       1 * cronSECONDS,
	       0,
	       NULL);
}
#endif

/**
 * Park main thread until shutdown has been signaled.
 */
static void waitForSignalHandler(struct GE_Context * ectx) {
  GE_LOG(ectx,
	 GE_INFO | GE_USER | GE_REQUEST,
	 _("`%s' startup complete.\n"),
	 "gnunetd");
  GNUNET_SHUTDOWN_WAITFOR();
  GE_LOG(ectx,
	 GE_INFO | GE_USER | GE_REQUEST,
	 _("`%s' is shutting down.\n"),
	 "gnunetd");
}

/**
 * The main method of gnunetd.
 */
int gnunet_main() {
  struct LoadMonitor * mon;
  struct SignalHandlerContext * shc_hup;
  int filedes[2]; /* pipe between client and parent */

  if ( (NO == debug_flag) &&
       (OK != os_terminal_detach(ectx,
				 filedes)) )
    return SYSERR;
  mon = os_network_monitor_create(ectx,
				  cfg);
  if (mon == NULL) {
   if (NO == debug_flag)
     os_terminal_detach_complete(ectx,
				filedes,
				 NO);
   return SYSERR;
  }
  cron = cron_create(ectx);
  GE_ASSERT(ectx,
	    cron != NULL);
#ifndef WINDOWS
  shc_hup = signal_handler_install(SIGHUP, &reread_config);
#endif
  if (OK != initCore(ectx,
		     cfg,
		     cron,
		     mon)) {
  	GE_LOG(ectx, GE_FATAL | GE_USER | GE_IMMEDIATE,
  		_("Core initialization failed.\n"));
  		
    cron_destroy(cron);
    os_network_monitor_destroy(mon);
#ifndef WINDOWS
    signal_handler_uninstall(SIGHUP,
			     &reread_config,
			     shc_hup);
#endif
    if (NO == debug_flag)
      os_terminal_detach_complete(ectx,
				  filedes,
				  NO);
    return SYSERR;
  }
  
  /* enforce filesystem limits */
  capFSQuotaSize(ectx, cfg);
  
  initConnection(ectx, cfg, mon, cron);
  loadApplicationModules();
  writePIDFile(ectx, cfg);
  if (NO == debug_flag)
    os_terminal_detach_complete(ectx,
				filedes,
				YES);
  cron_start(cron);
  enableCoreProcessing();
  waitForSignalHandler(ectx);
  disableCoreProcessing();
  cron_stop(cron);
  deletePIDFile(ectx, cfg);
  stopTCPServer();
  unloadApplicationModules();
  doneConnection();
  doneCore();
  os_network_monitor_destroy(mon);
#ifndef WINDOWS
  signal_handler_uninstall(SIGHUP,
			   &reread_config,
			   shc_hup);
#endif
  cron_destroy(cron);
  return OK;
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
 * All gnunetd command line options
 */
static struct CommandLineOption gnunetdOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE(&cfgFilename), /* -c */
  { '@', "win-service", NULL, "", 0,
    &gnunet_getopt_configure_set_option, "GNUNETD:WINSERVICE" },
  { 'd', "debug", NULL,
    gettext_noop("run in debug mode; gnunetd will "
		 "not daemonize and error messages will "
		 "be written to stderr instead of a logfile"),
    0, &gnunet_getopt_configure_set_one, &debug_flag },
  COMMAND_LINE_OPTION_HELP(gettext_noop("Starts the gnunetd daemon.")), /* -h */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  { 'p', "padding-disable", "YES/NO",
    gettext_noop("disable padding with random data (experimental)"), 0,
    &gnunet_getopt_configure_set_option, "GNUNETD-EXPERIMENTAL:PADDING" },
  { 'q', "quiet", NULL,
    gettext_noop("run in quiet mode"),
    0, &gnunet_getopt_configure_set_one, &quiet_flag },
#ifndef MINGW
  { 'u', "user", "USERNAME",
    gettext_noop("specify username as which gnunetd should run"), 1,
    &gnunet_getopt_configure_set_option, "GNUNETD:USERNAME" },
#endif
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_END,
};

/**
 * Initialize util (parse command line, options) and
 * call the main routine.
 */
int main(int argc,
	 char * const * argv) {
  int ret;

  if ( (4 != sizeof(MESSAGE_HEADER)) ||
       (600 != sizeof(P2P_hello_MESSAGE)) ) {
    fprintf(stderr,
	    "Sorry, your C compiler did not properly align the C structs. Aborting.\n");
    return -1;
  }
  ret = GNUNET_init(argc,
		    argv,
		    "gnunetd [OPTIONS]",
		    &cfgFilename,
		    gnunetdOptions,
		    &ectx,
		    &cfg);
  if (ret == -1) {
    GNUNET_fini(ectx, cfg);
    return 1;
  }
  if (YES == debug_flag) {
    if (quiet_flag == 0) {
      ectx = GE_create_context_multiplexer(ectx,
					   GE_create_context_stderr(NO,
								    GE_USERKIND |
								    GE_EVENTKIND |
								    GE_BULK |
								    GE_IMMEDIATE));
    }
  }
  if (OK != changeUser(ectx, cfg)) {
    GNUNET_fini(ectx, cfg);
    return 1;
  }
  setFdLimit(ectx, cfg);
  if (OK != checkUpToDate(ectx,
			  cfg)) {
    GE_LOG(ectx,
	   GE_USER | GE_FATAL | GE_IMMEDIATE,
	   _("Configuration or GNUnet version changed.  You need to run `%s'!\n"),
	   "gnunet-update");
    GNUNET_fini(ectx, cfg);
    return 1;
  }
  
#ifdef MINGW
  if (GC_get_configuration_value_yesno(cfg, "GNUNETD", "WINSERVICE", NO) == YES) {
    SERVICE_TABLE_ENTRY DispatchTable[] =
      {{"GNUnet", ServiceMain}, {NULL, NULL}};
    ret = (GNStartServiceCtrlDispatcher(DispatchTable) != 0);
  } else
#endif
  ret = gnunet_main();
  GNUNET_fini(ectx, cfg);
  if (ret != OK)
    return 1;
  return 0;
}

/* You have reached the end of GNUnet. You can shutdown your
   computer and get a life now. */
