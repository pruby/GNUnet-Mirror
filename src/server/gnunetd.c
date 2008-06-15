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
#include "gnunet_core.h"
#include "gnunet_directories.h"
#include "core.h"
#include "connection.h"
#include "tcpserver.h"
#include "handler.h"
#include "startup.h"
#include "version.h"

static struct GNUNET_GC_Configuration *cfg;
static struct GNUNET_GE_Context *ectx = NULL;

static struct GNUNET_CronManager *cron;
static struct GNUNET_LoadMonitor *mon;

#define PIDFILE_DATA "GNUNETD", "PIDFILE", GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY "/gnunetd/pid"

static char *cfgFilename = GNUNET_DEFAULT_DAEMON_CONFIG_FILE;

static int debug_flag;

static int loud_flag;

#ifndef WINDOWS
/**
 * Cron job that triggers re-reading of the configuration.
 */
static void
reread_config_helper (void *unused)
{
  GNUNET_GE_ASSERT (NULL, cfgFilename != NULL);
  GNUNET_GC_parse_configuration (cfg, cfgFilename);
}

/**
 * Signal handler for SIGHUP.
 * Re-reads the configuration file.
 */
static void
reread_config ()
{
  GNUNET_cron_add_job (cron, &reread_config_helper, 1 * GNUNET_CRON_SECONDS,
                       0, NULL);
}
#endif

/**
 * Park main thread until shutdown has been signaled.
 */
static void
waitForSignalHandler (struct GNUNET_GE_Context *ectx)
{
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 _("`%s' startup complete.\n"), "gnunetd");
  GNUNET_shutdown_wait_for ();
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 _("`%s' is shutting down.\n"), "gnunetd");
}

/**
 * The main method of gnunetd.
 */
int
gnunet_main ()
{
  struct GNUNET_SignalHandlerContext *shc_hup;
  int filedes[2];               /* pipe between client and parent */

  if ((GNUNET_NO == debug_flag)
      && (GNUNET_OK != GNUNET_terminal_detach (ectx, cfg, filedes,
                                               PIDFILE_DATA)))
    return GNUNET_SYSERR;
  if (GNUNET_NO != debug_flag)
    GNUNET_pid_file_write (ectx, cfg, (unsigned int) getpid (), PIDFILE_DATA);
  if (NULL == (mon = GNUNET_network_monitor_create (ectx, cfg)))
    {
      if (GNUNET_NO == debug_flag)
        GNUNET_terminal_detach_complete (ectx, filedes, GNUNET_NO);
      else
        GNUNET_pid_file_delete (ectx, cfg, PIDFILE_DATA);
      return GNUNET_SYSERR;
    }
  cron = GNUNET_cron_create (ectx);
  GNUNET_GE_ASSERT (ectx, cron != NULL);
#ifndef WINDOWS
  shc_hup = GNUNET_signal_handler_install (SIGHUP, &reread_config);
#endif
  if (GNUNET_OK != GNUNET_CORE_init (ectx, cfg, cron, mon))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_FATAL | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                     _("Core initialization failed.\n"));

      GNUNET_cron_destroy (cron);
      GNUNET_network_monitor_destroy (mon);
#ifndef WINDOWS
      GNUNET_signal_handler_uninstall (SIGHUP, &reread_config, shc_hup);
#endif
      if (GNUNET_NO == debug_flag)
        GNUNET_terminal_detach_complete (ectx, filedes, GNUNET_NO);
      return GNUNET_SYSERR;
    }

  /* enforce filesystem limits */
  GNUNET_CORE_startup_cap_fs_quota_size (ectx, cfg);

  GNUNET_CORE_connection_init (ectx, cfg, mon, cron);
  GNUNET_CORE_load_application_modules ();
  if (GNUNET_NO == debug_flag)
    GNUNET_terminal_detach_complete (ectx, filedes, GNUNET_YES);
  GNUNET_cron_start (cron);
  GNUNET_CORE_p2p_enable_processing ();
  waitForSignalHandler (ectx);
  GNUNET_CORE_p2p_disable_processing ();
  GNUNET_cron_stop (cron);
  GNUNET_CORE_stop_cs_server ();
  GNUNET_CORE_unload_application_modules ();
  GNUNET_CORE_connection_done ();
  GNUNET_CORE_done ();
  GNUNET_network_monitor_destroy (mon);
#ifndef WINDOWS
  GNUNET_signal_handler_uninstall (SIGHUP, &reread_config, shc_hup);
#endif
  GNUNET_cron_destroy (cron);
  return GNUNET_OK;
}

#ifdef MINGW
/**
 * Main method of the windows service
 */
void WINAPI
ServiceMain (DWORD argc, LPSTR * argv)
{
  GNUNET_CORE_w32_service_main (gnunet_main);
}
#endif

/**
 * All gnunetd command line options
 */
static struct GNUNET_CommandLineOption gnunetdOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  {'@', "win-service", NULL, "", 0,
   &GNUNET_getopt_configure_set_option, "GNUNETD:WINSERVICE"},
  {'d', "debug", NULL,
   gettext_noop ("run in debug mode; gnunetd will "
                 "not daemonize and error messages will "
                 "be written to stderr instead of a logfile"),
   0, &GNUNET_getopt_configure_set_one, &debug_flag},
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Starts the gnunetd daemon.")),        /* -h */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'p', "padding-disable", "YES/NO",
   gettext_noop ("disable padding with random data (experimental)"), 0,
   &GNUNET_getopt_configure_set_option, "GNUNETD-EXPERIMENTAL:PADDING"},
  {'l', "loud", NULL,
   gettext_noop
   ("print all log messages to the console (only works together with -d)"),
   0, &GNUNET_getopt_configure_set_one, &loud_flag},
#ifndef MINGW
  {'u', "user", "USERNAME",
   gettext_noop ("specify username as which gnunetd should run"), 1,
   &GNUNET_getopt_configure_set_option, "GNUNETD:USERNAME"},
#endif
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_END,
};

/**
 * Initialize util (parse command line, options) and
 * call the main routine.
 */
int
main (int argc, char *const *argv)
{
  int ret;

  if ((4 != sizeof (GNUNET_MessageHeader))
      || (600 != sizeof (GNUNET_MessageHello)))
    {
      fprintf (stderr,
               "Sorry, your C compiler did not properly align the C structs. Aborting.\n");
      return -1;
    }
  ret = GNUNET_init (argc,
                     argv,
                     "gnunetd [OPTIONS]",
                     &cfgFilename, gnunetdOptions, &ectx, &cfg);
  if (ret == -1)
    {
      GNUNET_fini (ectx, cfg);
      return 1;
    }
  GNUNET_pid_file_write (ectx, cfg, getpid (), PIDFILE_DATA);
  if (GNUNET_OK != GNUNET_CORE_startup_change_user (ectx, cfg))
    {
      GNUNET_pid_file_delete (ectx, cfg, PIDFILE_DATA);
      GNUNET_fini (ectx, cfg);
      return 1;
    }
  if (GNUNET_OK != GNUNET_CORE_startup_check_permissions (ectx, cfg))
    {
      GNUNET_pid_file_delete (ectx, cfg, PIDFILE_DATA);
      GNUNET_fini (ectx, cfg);
      return 1;
    }
  if (GNUNET_YES == debug_flag)
    {
      int dev;
      char *user_log_level;
      GNUNET_GE_KIND ull;

      GNUNET_GE_setDefaultContext (NULL);
      GNUNET_GE_free_context (ectx);
      GNUNET_GC_get_configuration_value_string (cfg,
                                                "LOGGING",
                                                "USER-LEVEL",
                                                "WARNING", &user_log_level);
      dev = GNUNET_GC_get_configuration_value_yesno (cfg,
                                                     "LOGGING", "DEVELOPER",
                                                     GNUNET_NO);
      ull = GNUNET_GE_getKIND (user_log_level);
      ull |= (ull - 1);         /* set bits for all lower log-levels */
      if (dev == GNUNET_YES)
        ull |= GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST;
      if (loud_flag == 1)
        ectx = GNUNET_GE_create_context_stderr (GNUNET_YES, GNUNET_GE_ALL);
      else
        ectx = GNUNET_GE_create_context_stderr (GNUNET_YES,
                                                GNUNET_GE_USER |
                                                GNUNET_GE_ADMIN | ull |
                                                GNUNET_GE_BULK |
                                                GNUNET_GE_IMMEDIATE);
      GNUNET_GE_setDefaultContext (ectx);
      GNUNET_free (user_log_level);
    }
  GNUNET_CORE_startup_set_fd_limit (ectx, cfg);
  if (GNUNET_OK != GNUNET_CORE_version_check_up_to_date (ectx, cfg))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_USER | GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE,
                     _
                     ("Configuration or GNUnet version changed.  You need to run `%s'!\n"),
                     "gnunet-update");
      GNUNET_pid_file_delete (ectx, cfg, PIDFILE_DATA);
      GNUNET_fini (ectx, cfg);
      return 1;
    }

#ifdef MINGW
  if (GNUNET_GC_get_configuration_value_yesno (cfg,
                                               "GNUNETD", "WINSERVICE",
                                               GNUNET_NO) == GNUNET_YES)
    {
      SERVICE_TABLE_ENTRY DispatchTable[] = { {"GNUnet", ServiceMain}
      , {NULL, NULL}
      };
      ret = (GNStartServiceCtrlDispatcher (DispatchTable) != 0);
    }
  else
#endif
    ret = gnunet_main ();
  GNUNET_pid_file_delete (ectx, cfg, PIDFILE_DATA);
  GNUNET_fini (ectx, cfg);
  if (ret != GNUNET_OK)
    return 1;
  return 0;
}

/* You have reached the end of GNUnet. You can shutdown your
   computer and get a life now. */
