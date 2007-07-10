/*
     This file is part of GNUnet.
     (C) 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file util/boot/startup.c
 * @brief standard code for GNUnet startup and shutdown
 * @author Christian Grothoff
 */

#include "gnunet_directories.h"
#include "gnunet_util_boot.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"
#include "platform.h"

static GE_KIND
convertLogLevel (const char *level)
{
  GE_KIND ret;

  ret = 0;
  if (ret || (0 == strcasecmp ("debug", level)))
    ret |= GE_DEBUG;
  if (ret || (0 == strcasecmp ("status", level)))
    ret |= GE_STATUS;
  if (ret || (0 == strcasecmp ("info", level)))
    ret |= GE_INFO;
  if (ret || (0 == strcasecmp ("warning", level)))
    ret |= GE_WARNING;
  if (ret || (0 == strcasecmp ("error", level)))
    ret |= GE_ERROR;
  if (ret || (0 == strcasecmp ("fatal", level)))
    ret = ret | GE_FATAL;
  return ret;
}

/**
 * Configure logging mechanism as specified by
 * user (and supported by system).
 *
 * @return 0 on success, 1 on error
 */
static int
configure_logging (struct GE_Context **ectx, struct GC_Configuration *cfg)
{
  char *admin_log_file;
  char *admin_log_level;
  char *user_log_level;
  GE_KIND all;
  GE_KIND ull;
  struct GE_Context *nctx;
  struct GE_Context *tetx;
  unsigned long long logrotate;
  int dev;

  nctx = NULL;
  admin_log_file = NULL;
  admin_log_level = NULL;
  user_log_level = NULL;
  logrotate = 7;
  if (-1 == GC_get_configuration_value_number (cfg,
                                               "GNUNETD",
                                               "KEEPLOG",
                                               0, 36500, 3, &logrotate))
    return 1;                   /* error! */
  GC_get_configuration_value_filename (cfg,
                                       "GNUNETD",
                                       "LOGFILE",
                                       VAR_DAEMON_DIRECTORY "/logs",
                                       &admin_log_file);
  disk_directory_create_for_file (*ectx, admin_log_file);
  GC_get_configuration_value_string (cfg,
                                     "LOGGING",
                                     "ADMIN-LEVEL",
                                     "WARNING", &admin_log_level);
  GC_get_configuration_value_string (cfg,
                                     "LOGGING",
                                     "USER-LEVEL",
                                     "WARNING", &user_log_level);
  dev = GC_get_configuration_value_yesno (cfg, "LOGGING", "DEVELOPER", NO);
  all = convertLogLevel (admin_log_level);
  ull = convertLogLevel (user_log_level);
  if (dev == YES)
    {
      all |= GE_DEVELOPER | GE_REQUEST;
      ull |= GE_DEVELOPER | GE_REQUEST;
    }
  FREE (admin_log_level);
  FREE (user_log_level);
  if (all != 0)
    {
      nctx = GE_create_context_logfile (NULL,
                                        all
                                        | GE_ADMIN
                                        | GE_BULK
                                        | GE_IMMEDIATE,
                                        admin_log_file, YES, (int) logrotate);
    }
  FREE (admin_log_file);
  if (ull != 0)
    {
      tetx = GE_create_context_stderr (YES,
                                       ull
                                       | GE_USERKIND
                                       | GE_BULK | GE_IMMEDIATE);
      if (nctx == NULL)
        nctx = tetx;
      else
        nctx = GE_create_context_multiplexer (nctx, tetx);
    }
  GE_setDefaultContext (nctx);
  GE_free_context (*ectx);
  *ectx = nctx;
  return 0;
}

/**
 * Run a standard GNUnet startup sequence
 * (initialize loggers and configuration,
 * parse options).
 *
 * @return -1 on error, position of next
 *  command-line argument to be processed in argv
 *  otherwise
 */
int
GNUNET_init (int argc,
             char *const *argv,
             const char *binaryName,
             char **cfgFileName,
             const struct CommandLineOption *options,
             struct GE_Context **ectx, struct GC_Configuration **cfg)
{
  int i;
  char *path;
  int is_daemon;
  int ret;

  os_init (NULL);

#if ENABLE_NLS
  setlocale (LC_ALL, "");
  path = os_get_installation_path (IPK_LOCALEDIR);
  BINDTEXTDOMAIN ("GNUnet", path);
  FREE (path);
  textdomain ("GNUnet");
#endif
  is_daemon = 0 == strcmp (DEFAULT_DAEMON_CONFIG_FILE, *cfgFileName);

  /* during startup, log all warnings and higher
     for anybody to stderr */
  *ectx = GE_create_context_stderr (YES,
                                    GE_WARNING | GE_ERROR | GE_FATAL |
                                    GE_USER | GE_ADMIN | GE_DEVELOPER |
                                    GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext (*ectx);
  os_init (*ectx);
  *cfg = GC_create_C_impl ();
  GE_ASSERT (*ectx, *cfg != NULL);
  i = gnunet_parse_options (binaryName,
                            *ectx, *cfg, options, (unsigned int) argc, argv);
  if (i == -1)
    return -1;
  if ((YES != disk_file_test (*ectx, *cfgFileName)) && (!is_daemon))
    {
      char *run;
      char *bindir;
      size_t max;

      bindir = os_get_installation_path (IPK_BINDIR);
      max = 128 + strlen (*cfgFileName) + strlen (bindir);
      run = MALLOC (max);
      SNPRINTF (run,
                max,
                "%sgnunet-setup -c %s generate-defaults",
                bindir, *cfgFileName);
      FREE (bindir);
      ret = system (run);
      if (0 != ret)
        GE_LOG (*ectx,
                GE_ERROR | GE_USER | GE_IMMEDIATE,
                _("Failed to run %s: %s %d\n"),
                run, strerror (errno), WEXITSTATUS (ret));
      FREE (run);
    }
  if (0 != GC_parse_configuration (*cfg, *cfgFileName))
    return -1;
  /* if PATHS/GNUNETD_HOME is not set, set it to
     the default value! */
  GC_get_configuration_value_string (*cfg,
                                     "PATHS",
                                     "GNUNETD_HOME",
                                     "/var/lib/gnunet", &path);
  FREE (path);
  GC_get_configuration_value_string (*cfg,
                                     "PATHS",
                                     "GNUNET_HOME", "~/.gnunet", &path);
  FREE (path);
  if (configure_logging (ectx, *cfg) != 0)
    return -1;
  return i;
}

/**
 * Free resources allocated during GNUnet_init.
 */
void
GNUNET_fini (struct GE_Context *ectx, struct GC_Configuration *cfg)
{
  GC_free (cfg);
  GE_setDefaultContext (NULL);
  GE_free_context (ectx);
}

/* end of startup.c */
