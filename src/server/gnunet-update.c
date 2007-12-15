/*
     This file is part of GNUnet.
     (C) 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file server/gnunet-update.c
 * @brief tool to process changes due to version updates
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_core.h"
#include "core.h"
#include "startup.h"
#include "version.h"

/**
 * We may want to change this at some point into
 * something like libgnunet_update if we want to
 * separate the update code from the codebase
 * used in normal operation -- but currently I
 * see no need / use for that.
 */
#define DSO_PREFIX "libgnunet"

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_GE_Context *ectx;

static char **processed;

static unsigned int processedCount;

static GNUNET_UpdateAPI uapi;

static char *cfgFilename = GNUNET_DEFAULT_DAEMON_CONFIG_FILE;


/**
 * Allow the module named "pos" to update.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
updateModule (const char *rpos)
{
  GNUNET_UpdatePluginMainMethod mptr;
  struct GNUNET_PluginHandle *library;
  char *name;
  int i;
  char *pos;

  for (i = 0; i < processedCount; i++)
    if (0 == strcmp (rpos, processed[i]))
      {
        return GNUNET_OK;       /* already done */
      }
  GNUNET_array_grow (processed, processedCount, processedCount + 1);
  processed[processedCount - 1] = GNUNET_strdup (rpos);

  pos = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_string (cfg,
                                                      "MODULES", rpos, rpos,
                                                      &pos))
    return GNUNET_SYSERR;
  GNUNET_GE_ASSERT (ectx, pos != NULL);

  name = GNUNET_malloc (strlen (pos) + strlen ("module_") + 1);
  strcpy (name, "module_");
  strcat (name, pos);
  GNUNET_free (pos);
  library = GNUNET_plugin_load (ectx, DSO_PREFIX, name);
  if (library == NULL)
    {
      GNUNET_free (name);
      return GNUNET_SYSERR;
    }
  mptr = GNUNET_plugin_resolve_function (library, "update_", GNUNET_NO);
  if (mptr == NULL)
    {
      GNUNET_plugin_unload (library);
      GNUNET_free (name);
      return GNUNET_OK;         /* module needs no updates! */
    }
  mptr (&uapi);
  GNUNET_plugin_unload (library);
  GNUNET_free (name);
  return GNUNET_OK;
}

/**
 * Call the update module for each of the applications
 * in the current configuration.
 */
static void
updateApplicationModules ()
{
  char *dso;
  char *next;
  char *pos;

  dso = NULL;
  if (-1 == GNUNET_GC_get_configuration_value_string (cfg,
                                                      "GNUNETD",
                                                      "APPLICATIONS",
                                                      "advertising fs getoption stats traffic",
                                                      &dso))
    return;
  GNUNET_GE_ASSERT (ectx, dso != NULL);
  next = dso;
  do
    {
      pos = next;
      while ((*next != '\0') && (*next != ' '))
        next++;
      if (*next == '\0')
        {
          next = NULL;          /* terminate! */
        }
      else
        {
          *next = '\0';         /* add 0-termination for pos */
          next++;
        }
      if (strlen (pos) > 0)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Updating data for module `%s'\n"), pos);
          if (GNUNET_OK != updateModule (pos))
            GNUNET_GE_LOG (ectx,
                           GNUNET_GE_ERROR | GNUNET_GE_DEVELOPER |
                           GNUNET_GE_BULK | GNUNET_GE_USER,
                           _("Failed to update data for module `%s'\n"), pos);
        }
    }
  while (next != NULL);
  GNUNET_free (dso);
}

static void
doGet (char *get)
{
  char *sec;
  char *ent;
  char *val;

  sec = get;
  ent = get;
  while (((*ent) != ':') && ((*ent) != '\0'))
    ent++;
  if (*ent == ':')
    {
      *ent = '\0';
      ent++;
    }
  if (GNUNET_YES == GNUNET_GC_have_configuration_value (cfg, sec, ent))
    {
      GNUNET_GC_get_configuration_value_string (cfg, sec, ent, NULL, &val);
      printf ("%s\n", val);
      GNUNET_free (val);
    }
}

static void
work ()
{
  int i;
  struct GNUNET_CronManager *cron;
  char *topo;

  uapi.updateModule = &updateModule;
  uapi.request_service = &GNUNET_CORE_request_service;
  uapi.release_service = &GNUNET_CORE_release_service;
  uapi.ectx = ectx;
  uapi.cfg = cfg;

  GNUNET_GC_get_configuration_value_string (cfg,
                                            "MODULES",
                                            "topology",
                                            "topology_default", &topo);
  /* Code specific for update from 0.7.2c to 0.7.3 */
  if (0 == strcmp (topo, "topology_f2f"))
    {
      GNUNET_GC_set_configuration_value_string (cfg,
                                                ectx,
                                                "MODULES",
                                                "topology",
                                                "topology_default");
      GNUNET_GC_set_configuration_value_string (cfg,
                                                ectx,
                                                "F2F", "FRIENDS-ONLY", "YES");
      if (GNUNET_OK == GNUNET_GC_write_configuration (cfg, cfgFilename))
        fprintf (stdout, "Updated F2F configuration options successfully.\n");
      else
        fprintf (stdout,
                 "Failed to write configuration with updated F2F configuration.\n");
    }
  GNUNET_free (topo);
  cron = GNUNET_cron_create (ectx);
  if (GNUNET_CORE_init (ectx, cfg, cron, NULL) != GNUNET_OK)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_FATAL | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                     _("Core initialization failed.\n"));

      return;
    }



  /* enforce filesystem limits */
  GNUNET_CORE_startup_cap_fs_quota_size (ectx, cfg);

  /* force update of common modules (used by core) */
  updateModule ("transport");
  updateModule ("identity");
  updateModule ("session");
  updateModule ("fragmentation");
  updateModule ("topology");
  /* then update active application modules */
  updateApplicationModules ();
  /* store information about update */
  GNUNET_CORE_version_mark_as_up_to_date (ectx, cfg);

  for (i = 0; i < processedCount; i++)
    GNUNET_free (processed[i]);
  GNUNET_array_grow (processed, processedCount, 0);
  GNUNET_CORE_done ();
  GNUNET_cron_destroy (cron);
}

static int
set_client_config (GNUNET_CommandLineProcessorContext * ctx,
                   void *scls, const char *option, const char *value)
{
  cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;
  return GNUNET_OK;
}


/**
 * All gnunet-update command line options
 */
static struct GNUNET_CommandLineOption gnunetupdateOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  {'g', "get", "SECTION:ENTRY",
   gettext_noop ("print a value from the configuration file to stdout"),
   1, &GNUNET_getopt_configure_set_option, "GNUNET-UPDATE:GET"},
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Updates GNUnet datastructures after version change.")),       /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'u', "user", "LOGIN",
   gettext_noop ("run as user LOGIN"),
   1, &GNUNET_getopt_configure_set_option, "GNUNETD:USER"},
  {'U', "client", NULL,
   gettext_noop
   ("run in client mode (for getting client configuration values)"),
   0, &set_client_config, NULL},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};


int
main (int argc, char *const *argv)
{
  char *get;
  int ret;

  ret = GNUNET_init (argc,
                     argv,
                     "gnunet-update",
                     &cfgFilename, gnunetupdateOptions, &ectx, &cfg);
  if ((ret == -1)
      || (GNUNET_OK != GNUNET_CORE_startup_change_user (ectx, cfg)))
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  get = NULL;
  GNUNET_GC_get_configuration_value_string (cfg, "GNUNET-UPDATE", "GET", "",
                                            &get);
  if (strlen (get) > 0)
    doGet (get);
  else
    work ();
  GNUNET_free (get);
  GNUNET_fini (ectx, cfg);
  return 0;
}

/* end of gnunet-update */
