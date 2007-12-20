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
#include "gnunet_util_config.h"
#include "gnunet_util_error_loggers.h"
#include "platform.h"

static GNUNET_GE_KIND
convertLogLevel (const char *level)
{
  GNUNET_GE_KIND ret;

  ret = 0;
  if (ret || (0 == strcasecmp ("debug", level)))
    ret |= GNUNET_GE_DEBUG;
  if (ret || (0 == strcasecmp ("status", level)))
    ret |= GNUNET_GE_STATUS;
  if (ret || (0 == strcasecmp ("info", level)))
    ret |= GNUNET_GE_INFO;
  if (ret || (0 == strcasecmp ("warning", level)))
    ret |= GNUNET_GE_WARNING;
  if (ret || (0 == strcasecmp ("error", level)))
    ret |= GNUNET_GE_ERROR;
  if (ret || (0 == strcasecmp ("fatal", level)))
    ret = ret | GNUNET_GE_FATAL;
  return ret;
}

/**
 * Configure logging mechanism as specified by
 * user (and supported by system).
 *
 * @return 0 on success, 1 on error
 */
static int
configure_logging (struct GNUNET_GE_Context **ectx,
                   struct GNUNET_GC_Configuration *cfg)
{
  char *admin_log_file;
  char *admin_log_level;
  char *user_log_level;
  GNUNET_GE_KIND all;
  GNUNET_GE_KIND ull;
  struct GNUNET_GE_Context *nctx;
  struct GNUNET_GE_Context *tetx;
  unsigned long long logrotate;
  int dev;
  char *user;
  char *rdir;
  size_t len;
  size_t pos;

  nctx = NULL;
  admin_log_file = NULL;
  admin_log_level = NULL;
  user_log_level = NULL;
  user = NULL;
  GNUNET_GC_get_configuration_value_string (cfg, "GNUNETD", "USER", "",
                                            &user);
  if (strlen (user) == 0)
    {
      GNUNET_free (user);
      user = NULL;
    }
  logrotate = 7;
  if (-1 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      "GNUNETD",
                                                      "KEEPLOG",
                                                      0, 36500, 3,
                                                      &logrotate))
    return 1;                   /* error! */
  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "GNUNETD",
                                              "LOGFILE",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                              "/logs", &admin_log_file);
  if (user != NULL)
    {
      rdir = GNUNET_expand_file_name (NULL, admin_log_file);
      GNUNET_GE_ASSERT (NULL, rdir != NULL);
      len = strlen (rdir);
      pos = 1;
      while (pos < len)
        {
          if (rdir[pos] == DIR_SEPARATOR)
            {
              rdir[pos] = '\0';
              if (mkdir (rdir
#ifndef MINGW
                         , S_IRUSR | S_IWUSR | S_IXUSR
#endif
                  ) == 0)
                {
                  GNUNET_file_change_owner (nctx, rdir, user);
                }
              else if (errno != EEXIST)
                {
                  GNUNET_GE_LOG_STRERROR_FILE (NULL,
                                               GNUNET_GE_ERROR |
                                               GNUNET_GE_USER |
                                               GNUNET_GE_BULK, "mkdir", rdir);
                }
              rdir[pos] = DIR_SEPARATOR;
            }
          pos++;
        }
      GNUNET_free (rdir);
    }
  GNUNET_GC_get_configuration_value_string (cfg,
                                            "LOGGING",
                                            "ADMIN-LEVEL",
                                            "WARNING", &admin_log_level);
  GNUNET_GC_get_configuration_value_string (cfg,
                                            "LOGGING",
                                            "USER-LEVEL",
                                            "WARNING", &user_log_level);
  dev =
    GNUNET_GC_get_configuration_value_yesno (cfg, "LOGGING", "DEVELOPER",
                                             GNUNET_NO);
  all = convertLogLevel (admin_log_level);
  ull = convertLogLevel (user_log_level);
  if (dev == GNUNET_YES)
    {
      all |= GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST;
      ull |= GNUNET_GE_DEVELOPER | GNUNET_GE_REQUEST;
    }
  GNUNET_free (admin_log_level);
  GNUNET_free (user_log_level);
  if (all != 0)
    {
      nctx = GNUNET_GE_create_context_logfile (NULL,
                                               all
                                               | GNUNET_GE_ADMIN
                                               | GNUNET_GE_BULK
                                               | GNUNET_GE_IMMEDIATE,
                                               admin_log_file,
                                               user, GNUNET_YES,
                                               (int) logrotate);
    }
  GNUNET_free (admin_log_file);
  if (ull != 0)
    {
      tetx = GNUNET_GE_create_context_stderr (GNUNET_YES,
                                              ull
                                              | GNUNET_GE_USERKIND
                                              | GNUNET_GE_BULK |
                                              GNUNET_GE_IMMEDIATE);
      if (nctx == NULL)
        nctx = tetx;
      else
        nctx = GNUNET_GE_create_context_multiplexer (nctx, tetx);
    }
  GNUNET_free_non_null (user);
  GNUNET_GE_setDefaultContext (nctx);
  GNUNET_GE_free_context (*ectx);
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
             const struct GNUNET_CommandLineOption *options,
             struct GNUNET_GE_Context **ectx,
             struct GNUNET_GC_Configuration **cfg)
{
  int i;
  char *path;
  int is_daemon;
  int ret;

  GNUNET_os_init (NULL);

#if ENABLE_NLS
  setlocale (LC_ALL, "");
  path = GNUNET_get_installation_path (GNUNET_IPK_LOCALEDIR);
  BINDTEXTDOMAIN ("GNUnet", path);
  GNUNET_free (path);
  textdomain ("GNUnet");
#endif
  is_daemon = 0 == strcmp (GNUNET_DEFAULT_DAEMON_CONFIG_FILE, *cfgFileName);

  /* during startup, log all warnings and higher
     for anybody to stderr */
  *ectx = GNUNET_GE_create_context_stderr (GNUNET_YES,
                                           GNUNET_GE_WARNING | GNUNET_GE_ERROR
                                           | GNUNET_GE_FATAL | GNUNET_GE_USER
                                           | GNUNET_GE_ADMIN |
                                           GNUNET_GE_DEVELOPER |
                                           GNUNET_GE_IMMEDIATE |
                                           GNUNET_GE_BULK);
  GNUNET_GE_setDefaultContext (*ectx);
  GNUNET_os_init (*ectx);
  *cfg = GNUNET_GC_create ();
  GNUNET_GE_ASSERT (*ectx, *cfg != NULL);
  i = GNUNET_parse_options (binaryName,
                            *ectx, *cfg, options, (unsigned int) argc, argv);
  if (i == -1)
    return -1;
  if ((GNUNET_YES != GNUNET_disk_file_test (*ectx, *cfgFileName))
      && (!is_daemon))
    {
      char *run;
      char *bindir;
      size_t max;

      bindir = GNUNET_get_installation_path (GNUNET_IPK_BINDIR);
      max = 128 + strlen (*cfgFileName) + strlen (bindir);
      run = GNUNET_malloc (max);
      GNUNET_snprintf (run,
                       max,
                       "%sgnunet-setup -c %s generate-defaults",
                       bindir, *cfgFileName);
      GNUNET_free (bindir);
      ret = system (run);
      if (0 != ret)
        GNUNET_GE_LOG (*ectx,
                       GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                       _("Failed to run %s: %s %d\n"),
                       run, strerror (errno), WEXITSTATUS (ret));
      GNUNET_free (run);
    }
  if (0 != GNUNET_GC_parse_configuration (*cfg, *cfgFileName))
    return -1;
  /* if PATHS/GNUNETD_HOME is not set, set it to
     the default value! */
  GNUNET_GC_get_configuration_value_string (*cfg,
                                            "PATHS",
                                            "GNUNETD_HOME",
                                            "/var/lib/gnunet", &path);
  GNUNET_free (path);
  GNUNET_GC_get_configuration_value_string (*cfg,
                                            "PATHS",
                                            "GNUNET_HOME", "~/.gnunet",
                                            &path);
  GNUNET_free (path);
  if (configure_logging (ectx, *cfg) != 0)
    return -1;
  return i;
}

/**
 * Free resources allocated during GNUnet_init.
 */
void
GNUNET_fini (struct GNUNET_GE_Context *ectx,
             struct GNUNET_GC_Configuration *cfg)
{
  GNUNET_GC_free (cfg);
  GNUNET_GE_setDefaultContext (NULL);
  GNUNET_GE_free_context (ectx);
}

/* end of startup.c */
