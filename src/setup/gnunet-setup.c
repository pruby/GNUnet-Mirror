/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file setup/gnunet-setup.c
 * @brief GNUnet Setup
 * @author Nils Durner
 * @author Christian Grothoff
 */
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_setup_lib.h"

#include "platform.h"

typedef int (*ConfigurationPluginMain) (int argc,
                                        char *const *argv,
                                        struct GNUNET_PluginHandle * self,
                                        struct GNUNET_GE_Context * ectx,
                                        struct GNUNET_GC_Configuration * cfg,
                                        struct GNUNET_GNS_Context * gns,
                                        const char *filename, int is_daemon);

static int config_daemon;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

#if HAVE_GUILE
static struct GNUNET_GNS_Context *gns;
#endif

static char *cfgFilename;

static int option_processing;

static char *get_option;

static char *set_option;

static int
set_option_helper (GNUNET_CommandLineProcessorContext * ctx,
                   void *unused, const char *cmdLineOption, const char *value)
{
  option_processing = GNUNET_YES;
  if (set_option != NULL)
    {
      fprintf (stderr, _("Can only set one option per invocation.\n"));
      return GNUNET_SYSERR;
    }
  if ((NULL == strstr (value, ":")) ||
      (NULL == strstr (strstr (value, ":"), "=")))
    {
      fprintf (stderr,
               _
               ("Invalid synatx, argument to 'set' must have the format SECTION:OPTION=VALUE.\n"));
      return GNUNET_SYSERR;
    }
  set_option = GNUNET_strdup (value);
  return GNUNET_OK;
}

static int
get_option_helper (GNUNET_CommandLineProcessorContext * ctx,
                   void *unused, const char *cmdLineOption, const char *value)
{
  option_processing = GNUNET_YES;
  if (get_option != NULL)
    {
      fprintf (stderr, _("Can only display one option per invocation.\n"));
      return GNUNET_SYSERR;
    }
  if (NULL == strstr (value, ":"))
    {
      fprintf (stderr,
               _
               ("Invalid synatx, argument to 'get' must have the format SECTION:OPTION.\n"));
      return GNUNET_SYSERR;
    }
  get_option = GNUNET_strdup (value);
  return GNUNET_OK;
}


/**
 * All gnunet-setup command line options
 */
static struct GNUNET_CommandLineOption gnunetsetupOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  {'d', "daemon", NULL,
   gettext_noop ("generate configuration for gnunetd, the GNUnet daemon"),
   0, &GNUNET_getopt_configure_set_one, &config_daemon},
  {'g', "get", "SECTION:ENTRY",
   gettext_noop ("print a value from the configuration file to stdout"),
   1, &get_option_helper, NULL},
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Tool to setup GNUnet.")),     /* -h */
  {'s', "set", "SECTION:ENTRY=VALUE",
   gettext_noop ("update a value in the configuration file"),
   1, &set_option_helper, NULL},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

#if HAVE_GUILE
static void
gns2cfg (struct GNUNET_GNS_TreeNode *pos)
{
  int i;
  char *val;

  if (pos == NULL)
    return;
  i = 0;
  while (pos->children[i] != NULL)
    {
      gns2cfg (pos->children[i]);
      i++;
    }
  if (i != 0)
    return;
  if ((pos->section == NULL) || (pos->option == NULL))
    return;
  if (GNUNET_NO ==
      GNUNET_GC_have_configuration_value (cfg, pos->section, pos->option))
    {
      val = GNUNET_GNS_get_default_value_as_string (pos->type, &pos->value);
      if (val != NULL)
        {
          GNUNET_GC_set_configuration_value_string (cfg,
                                                    ectx,
                                                    pos->section, pos->option,
                                                    val);
          GNUNET_free (val);
        }
    }
}
#endif

static int
dyn_config (const char *module,
            const char *mainfunc,
            int argc, char *const *argv, const char *filename)
{
  ConfigurationPluginMain mptr;
  struct GNUNET_PluginHandle *library;
  library = GNUNET_plugin_load (ectx, "libgnunet", module);
  if (!library)
    return GNUNET_SYSERR;
  mptr = GNUNET_plugin_resolve_function (library, mainfunc, GNUNET_YES);
  if (!mptr)
    {
      GNUNET_plugin_unload (library);
      return GNUNET_SYSERR;
    }
  mptr (argc, argv, library, ectx, cfg,
#if HAVE_GUILE
        gns,
#else
        NULL,
#endif
        filename, config_daemon);
  GNUNET_plugin_unload (library);
  return GNUNET_YES;
}

static const char *INFO = "gnunet-setup [OPTIONS] config|generate-defaults"
#if HAVE_DIALOG
  "|menuconfig|wizard-curses"
#endif
#if HAVE_GTK
  "|gconfig|wizard-gtk"
#endif
#if HAVE_QT
  "|wizard-qt"
#endif
  "";

/**
 * List of supported plugins.  One entry consists
 * of three strings: option name, plugin library
 * name and main method name.
 */
static const char *modules[] = {
  "gconfig", "setup_gtk", "gconf_main",
  "menuconfig", "setup_curses", "mconf_main",
  "config", "setup_text", "main_",
  "wizard-curses", "setup_curses", "wizard_curs_main",
  "wizard-gtk", "setup_gtk", "gtk_wizard_main",
  "wizard-qt", "setup_qt", "qt_wizard_main",
  "generate-defaults", "setup_text", "dump_",
  NULL,
};


int
main (int argc, char *const *argv)
{
  const char *operation;
  int done;
  char *dirname;
#if HAVE_GUILE
  char *specname;
#endif
  char *value;
  char *option;
  int i;

  ectx = GNUNET_GE_create_context_stderr (GNUNET_NO,
                                          GNUNET_GE_WARNING | GNUNET_GE_ERROR
                                          | GNUNET_GE_FATAL | GNUNET_GE_USER |
                                          GNUNET_GE_ADMIN |
                                          GNUNET_GE_DEVELOPER |
                                          GNUNET_GE_IMMEDIATE |
                                          GNUNET_GE_BULK);
  GNUNET_GE_setDefaultContext (ectx);
  GNUNET_os_init (ectx);
  cfg = GNUNET_GC_create ();
  GNUNET_GE_ASSERT (ectx, cfg != NULL);
  i = GNUNET_parse_options (INFO,
                            ectx,
                            cfg,
                            gnunetsetupOptions, (unsigned int) argc, argv);
  if (i < 0)
    {
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      return -1;
    }
  if (option_processing)
    {
      operation = "options";
    }
  else
    {
      if (i != argc - 1)
        {
          if (i < argc - 1)
            {
              fprintf (stderr, _("Too many arguments.\n"));
              return -1;
            }
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_REQUEST |
                         GNUNET_GE_USER,
                         _("No interface specified, using default\n"));
          operation = "config";
#if HAVE_DIALOG
          operation = "menuconfig";
#endif
#if HAVE_GTK
          operation = "gconfig";
#endif
        }
      else
        {
          operation = argv[i];
        }
    }
  if (NULL != strstr (operation, "wizard"))
    config_daemon = GNUNET_YES; /* wizard implies daemon! */
  if (cfgFilename == NULL)
    cfgFilename = config_daemon
      ? GNUNET_strdup (GNUNET_DEFAULT_DAEMON_CONFIG_FILE)
      : GNUNET_strdup (GNUNET_DEFAULT_CLIENT_CONFIG_FILE);
  dirname = GNUNET_expand_file_name (ectx, cfgFilename);
  GNUNET_free (cfgFilename);
  cfgFilename = GNUNET_strdup (dirname);
  i = strlen (dirname) - 1;
  while (i > -1)
    {
      char ch = dirname[i];
      if ((ch == '/') || (ch == '\\'))
        {
          dirname[i + 1] = 0;
          break;
        }
      i--;
    }
  GNUNET_disk_directory_create (ectx, dirname);
  if (((0 != ACCESS (cfgFilename, W_OK)) &&
       ((errno != ENOENT) || (0 != ACCESS (dirname, W_OK)))))
    GNUNET_GE_DIE_STRERROR_FILE (ectx,
                                 GNUNET_GE_FATAL | GNUNET_GE_USER |
                                 GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                                 "access", dirname);
  GNUNET_free (dirname);

  if (0 == ACCESS (cfgFilename, F_OK))
    GNUNET_GC_parse_configuration (cfg, cfgFilename);
  dirname = GNUNET_get_installation_path (GNUNET_IPK_DATADIR);
  GNUNET_GE_ASSERT (ectx, dirname != NULL);
#if HAVE_GUILE
  specname =
    GNUNET_malloc (strlen (dirname) + strlen ("config-daemon.scm") + 1);
  strcpy (specname, dirname);
  GNUNET_free (dirname);
  if (config_daemon)
    strcat (specname, "config-daemon.scm");
  else
    strcat (specname, "config-client.scm");
  gns = GNUNET_GNS_load_specification (ectx, cfg, specname);
  GNUNET_free (specname);
  if (gns == NULL)
    {
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      GNUNET_free (cfgFilename);
      return -1;
    }
  gns2cfg (GNUNET_GNS_get_tree_root (gns));
#endif
  if (option_processing)
    {
      done = 0;
      if (get_option != NULL)
        {
          option = strstr (get_option, ":");
          option[0] = '\0';
          option++;
          if (GNUNET_NO == GNUNET_GC_have_configuration_value (cfg,
                                                               get_option,
                                                               option))
            {
              fprintf (stderr, _("Undefined option.\n"));
              done = 1;
            }
          else
            {
              GNUNET_GC_get_configuration_value_string (cfg,
                                                        get_option,
                                                        option, NULL, &value);
              fprintf (stdout, "%s\n", value);
              GNUNET_free (value);
            }
          GNUNET_free (get_option);
        }
      if (set_option != NULL)
        {
          option = strstr (set_option, ":");
          option[0] = '\0';
          option++;
          value = strstr (option, "=");
          value[0] = '\0';
          value++;
          if ((GNUNET_OK !=
               GNUNET_GC_set_configuration_value_string (cfg, ectx,
                                                         set_option, option,
                                                         value))
              || (GNUNET_OK !=
                  GNUNET_GC_write_configuration (cfg, cfgFilename)))
            done = 1;
          GNUNET_free (set_option);
        }
#if HAVE_GUILE
      GNUNET_GNS_free_specification (gns);
#endif
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      GNUNET_free (cfgFilename);
      return done;
    }
  else
    {
      done = GNUNET_NO;
      i = 0;
      while ((done == GNUNET_NO) && (modules[i] != NULL))
        {
          if (strcmp (operation, modules[i]) == 0)
            {
              if (dyn_config (modules[i + 1],
                              modules[i + 2], argc, argv,
                              cfgFilename) != GNUNET_YES)
                {
                  GNUNET_GE_LOG (ectx,
                                 GNUNET_GE_FATAL | GNUNET_GE_USER |
                                 GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                                 _("`%s' is not available.\n"), operation);
#if HAVE_GUILE
                  GNUNET_GNS_free_specification (gns);
#endif
                  GNUNET_GC_free (cfg);
                  GNUNET_GE_free_context (ectx);
                  GNUNET_free (cfgFilename);
                  return -1;
                }
              else
                {
                  done = GNUNET_YES;
                }
            }
          i += 3;
        }
    }
  GNUNET_free (cfgFilename);
  if (done == GNUNET_NO)
    {
      fprintf (stderr, _("Unknown operation `%s'\n"), operation);
      fprintf (stderr, _("Use --help to get a list of options.\n"));
#if HAVE_GUILE
      GNUNET_GNS_free_specification (gns);
#endif
      GNUNET_GC_free (cfg);
      GNUNET_GE_free_context (ectx);
      return 1;
    }
#if HAVE_GUILE
  GNUNET_GNS_free_specification (gns);
#endif
  GNUNET_GC_free (cfg);
  GNUNET_GE_free_context (ectx);
  return 0;
}
