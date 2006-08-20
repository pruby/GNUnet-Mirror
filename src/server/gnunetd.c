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
#include "gnunet_util_cron.h"
#include "gnunet_core.h"
#include "gnunet_directories.h"
#include "core.h"
#include "connection.h"
#include "tcpserver.h"
#include "handler.h"
#include "startup.h"
#include "version.h"

static struct GC_Configuration * cfg;

static struct CronManager * cron;

/**
 * Cron job that triggers re-reading of the configuration.
 */
static void reread_config_helper(void * unused) {
  char * filename;
  
  filename = NULL;
  if (-1 == GC_get_configuration_value_filename(cfg,
						"GNUNET",
						"CONFIGFILE",
						DEFAULT_DAEMON_CONFIG_FILE,
						&filename)) {
    GE_BREAK(NULL, 0); /* should never happen */
    return; 
  }
  GE_ASSERT(NULL, filename != NULL);
  GC_parse_configuration(cfg,
			 filename);
  FREE(filename);
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
int gnunet_main(struct GE_Context * ectx) {
  struct LoadMonitor * mon;
  struct SignalHandlerContext * shc_hup;
  int filedes[2]; /* pipe between client and parent */
  int debug_flag;


  debug_flag = GC_get_configuration_value_yesno(cfg,
						"GNUNETD",
						"DEBUG",
						NO);
  if ( (NO == debug_flag) &&
       (OK != os_terminal_detach(ectx,
				 filedes)) )
    return SYSERR;
  mon = os_network_monitor_create(ectx,
				  cfg);
  cron = cron_create(ectx);
  shc_hup = signal_handler_install(SIGHUP, &reread_config);
  initCore(ectx,
	   cfg,
	   cron,
	   mon);
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
  signal_handler_uninstall(SIGHUP, 
			   &reread_config,
			   shc_hup);
  cron_destroy(cron);
  return OK;
}

/**
 * All gnunetd command line options
 */
static struct CommandLineOption gnunetdOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE, /* -c */
  { '@', "win-service", NULL, gettext_noop(""), 0, 
    &gnunet_getopt_configure_set_option, "GNUNETD:WINSERVICE" },
  { 'd', "debug", NULL, 
    gettext_noop("run in debug mode; gnunetd will "
		 "not daemonize and error messages will "
		 "be written to stderr instead of a logfile"), 
    0, &gnunet_getopt_configure_set_option, "GNUNETD:DEBUG" },
  COMMAND_LINE_OPTION_HELP(gettext_noop("Starts the gnunetd daemon.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  { 'p', "padding-disable", "YES/NO", 
    gettext_noop("disable padding with random data (experimental)"), 0,
    &gnunet_getopt_configure_set_option, "GNUNETD-EXPERIMENTAL:PADDING" },
#ifndef MINGW
  { 'u', "user", "USERNAME", gettext_noop(""), 1, 
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
	 const char * argv[]) {
  int ret;
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
  os_init(ectx);
  if (-1 == gnunet_parse_options("gnunetd",
				 ectx,
				 cfg,
				 gnunetdOptions,
				 (unsigned int) argc,
				 argv)) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;  
  }
  if (OK != changeUser(ectx, cfg)) {
    GC_free(cfg);
    GE_free_context(ectx);
    return 1;
  }
  if (OK != checkUpToDate(ectx,
			  cfg)) {
    GE_LOG(ectx,
	   GE_USER | GE_FATAL | GE_IMMEDIATE,
	   _("Configuration or GNUnet version changed.  You need to run `%s'!\n"),
	   "gnunet-update");
    GC_free(cfg);
    GE_free_context(ectx);
    return 1;
  }
  ret = gnunet_main(ectx);
  GC_free(cfg);
  os_done();
  GE_free_context(ectx);
  if (ret != OK)
    return 1;
  return 0;
}

/* You have reached the end of GNUnet. You can shutdown your
   computer and get a life now. */
