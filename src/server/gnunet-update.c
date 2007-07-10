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
#include "gnunet_util_boot.h"
#include "gnunet_util_cron.h"
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

static struct GC_Configuration *cfg;

static struct GE_Context *ectx;

static char **processed;

static unsigned int processedCount;

static UpdateAPI uapi;

static char *cfgFilename = DEFAULT_DAEMON_CONFIG_FILE;


/**
 * Allow the module named "pos" to update.
 * @return OK on success, SYSERR on error
 */
static int
updateModule (const char *rpos)
{
  UpdateMethod mptr;
  struct PluginHandle *library;
  char *name;
  int i;
  char *pos;

  for (i = 0; i < processedCount; i++)
    if (0 == strcmp (rpos, processed[i]))
      {
        return OK;              /* already done */
      }
  GROW (processed, processedCount, processedCount + 1);
  processed[processedCount - 1] = STRDUP (rpos);

  pos = NULL;
  if (-1 == GC_get_configuration_value_string (cfg,
                                               "MODULES", rpos, rpos, &pos))
    return SYSERR;
  GE_ASSERT (ectx, pos != NULL);

  name = MALLOC (strlen (pos) + strlen ("module_") + 1);
  strcpy (name, "module_");
  strcat (name, pos);
  FREE (pos);
  library = os_plugin_load (ectx, DSO_PREFIX, name);
  if (library == NULL)
    {
      FREE (name);
      return SYSERR;
    }
  mptr = os_plugin_resolve_function (library, "update_", NO);
  if (mptr == NULL)
    {
      os_plugin_unload (library);
      FREE (name);
      return OK;                /* module needs no updates! */
    }
  mptr (&uapi);
  os_plugin_unload (library);
  FREE (name);
  return OK;
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
  if (-1 == GC_get_configuration_value_string (cfg,
                                               "GNUNETD",
                                               "APPLICATIONS",
                                               "advertising fs getoption stats traffic",
                                               &dso))
    return;
  GE_ASSERT (ectx, dso != NULL);
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
          GE_LOG (ectx,
                  GE_INFO | GE_USER | GE_BULK,
                  _("Updating data for module `%s'\n"), pos);
          if (OK != updateModule (pos))
            GE_LOG (ectx,
                    GE_ERROR | GE_DEVELOPER | GE_BULK | GE_USER,
                    _("Failed to update data for module `%s'\n"), pos);
        }
    }
  while (next != NULL);
  FREE (dso);
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
  if (YES == GC_have_configuration_value (cfg, sec, ent))
    {
      GC_get_configuration_value_string (cfg, sec, ent, NULL, &val);
      printf ("%s\n", val);
      FREE (val);
    }
}

static void
work ()
{
  int i;
  struct CronManager *cron;

  uapi.updateModule = &updateModule;
  uapi.requestService = &requestService;
  uapi.releaseService = &releaseService;
  uapi.ectx = ectx;
  uapi.cfg = cfg;

  cron = cron_create (ectx);
  if (initCore (ectx, cfg, cron, NULL) != OK)
    {
      GE_LOG (ectx, GE_FATAL | GE_USER | GE_IMMEDIATE,
              _("Core initialization failed.\n"));

      return;
    }

  /* enforce filesystem limits */
  capFSQuotaSize (ectx, cfg);

  /* force update of common modules (used by core) */
  updateModule ("transport");
  updateModule ("identity");
  updateModule ("session");
  updateModule ("fragmentation");
  updateModule ("topology");
  /* then update active application modules */
  updateApplicationModules ();
  /* store information about update */
  upToDate (ectx, cfg);

  for (i = 0; i < processedCount; i++)
    FREE (processed[i]);
  GROW (processed, processedCount, 0);
  doneCore ();
  cron_destroy (cron);
}

static int
set_client_config (CommandLineProcessorContext * ctx,
                   void *scls, const char *option, const char *value)
{
  cfgFilename = DEFAULT_CLIENT_CONFIG_FILE;
  return OK;
}


/**
 * All gnunet-update command line options
 */
static struct CommandLineOption gnunetupdateOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),  /* -c */
  {'g', "get", "SECTION:ENTRY",
   gettext_noop ("print a value from the configuration file to stdout"),
   1, &gnunet_getopt_configure_set_option, "GNUNET-UPDATE:GET"},
  COMMAND_LINE_OPTION_HELP (gettext_noop ("Updates GNUnet datastructures after version change.")),      /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING,  /* -L */
  {'u', "user", "LOGIN",
   gettext_noop ("run as user LOGIN"),
   1, &gnunet_getopt_configure_set_option, "GNUNETD:USER"},
  {'U', "client", NULL,
   gettext_noop
   ("run in client mode (for getting client configuration values)"),
   0, &set_client_config, NULL},
  COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION),        /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
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
  if ((ret == -1) || (OK != changeUser (ectx, cfg)))
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  get = NULL;
  GC_get_configuration_value_string (cfg, "GNUNET-UPDATE", "GET", "", &get);
  if (strlen (get) > 0)
    doGet (get);
  else
    work ();
  FREE (get);
  GNUNET_fini (ectx, cfg);
  return 0;
}

/* end of gnunet-update */
