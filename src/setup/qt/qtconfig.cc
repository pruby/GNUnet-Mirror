#include <Qt/qapplication.h>

extern "C" {
  #include "gnunet_util.h"
  #include "platform.h"
  #include "gnunet_util.h"
  #include "gnunet_directories.h"
  #include "gnunet_setup_lib.h"
}
#include "setupWizard.h"

static struct GNUNET_GE_Context *ectx;
static struct GNUNET_GC_Configuration *cfg;
static struct GNUNET_GNS_Context *gns;
static char *cfgFilename;
static int config_daemon;

/**
 * All gnunet-setup command line options
 */
static struct GNUNET_CommandLineOption gnunetsetupOptions[] = {
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  {'d', "daemon", NULL,
   gettext_noop ("generate configuration for gnunetd, the GNUnet daemon"),
   0, &GNUNET_getopt_configure_set_one, &config_daemon},
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Tool to setup GNUnet.")),     /* -h */
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION),  /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

static const char *INFO = "gnunetsetup_qt [OPTIONS] qconfig|wizard-qt"
  "";

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

extern "C" {
int
qt_wizard_mainsetup_qt (int argc,
                          char *const *argv,
                          struct GNUNET_PluginHandle *self,
                          struct GNUNET_GE_Context *ectx,
                          struct GNUNET_GC_Configuration *cfg,
                          struct GNUNET_GNS_Context *gns,
                          const char *filename, int is_daemon)
  {
    QApplication *app;
    GSetupWizard *wiz;
    int ret;
    
    GNUNET_GE_ASSERT (ectx, is_daemon);

    app = new QApplication(argc, (char **) argv);

    wiz = new GSetupWizard();
    wiz->setErrorContext(ectx);
    wiz->setConfig(cfg);
    wiz->show();
    
    ret = app->exec();

    delete wiz;
    delete app;
  
    return ret;
  }
}

int main(int argc, char **argv)
{
  const char *operation;
  char *dirname;
  char *specname;
  int i;

  ectx = GNUNET_GE_create_context_stderr (GNUNET_NO,
                                          (GNUNET_GE_KIND) (GNUNET_GE_WARNING | GNUNET_GE_ERROR
                                          | GNUNET_GE_FATAL | GNUNET_GE_USER |
                                          GNUNET_GE_ADMIN |
                                          GNUNET_GE_DEVELOPER |
                                          GNUNET_GE_IMMEDIATE |
                                          GNUNET_GE_BULK));
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
  if (i != argc - 1)
    {
      if (i < argc - 1)
        {
          fprintf (stderr, _("Too many arguments.\n"));
          return -1;
        }
      operation = "qconfig";
    }
  else
    {
      operation = argv[i];
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
                                 (GNUNET_GE_KIND)(GNUNET_GE_FATAL | GNUNET_GE_USER |
                                 GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE),
                                 "access", dirname);
  GNUNET_free (dirname);

  if (0 == ACCESS (cfgFilename, F_OK))
    GNUNET_GC_parse_configuration (cfg, cfgFilename);
  dirname = GNUNET_get_installation_path (GNUNET_IPK_DATADIR);
  GNUNET_GE_ASSERT (ectx, dirname != NULL);
  specname = (char *)
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

  qt_wizard_mainsetup_qt(argc, argv, NULL, ectx, cfg, gns, cfgFilename, config_daemon);

  GNUNET_free (cfgFilename);
  GNUNET_GNS_free_specification (gns);
  GNUNET_GC_free (cfg);
  GNUNET_GE_free_context (ectx);
  return 0;
}
