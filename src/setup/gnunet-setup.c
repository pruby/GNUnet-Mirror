/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"

#include "platform.h"

typedef int (*ConfigurationPluginMain)(int argc,
				       char * const * argv,
				       struct PluginHandle * self,
				       struct GE_Context * ectx,
				       struct GC_Configuration * cfg,
				       struct GNS_Context * gns,
				       const char * filename,
				       int is_daemon);

static int config_daemon;

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

static struct GNS_Context * gns;

static char * cfgFilename;

/**
 * All gnunet-setup command line options
 */
static struct CommandLineOption gnunetsetupOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE(&cfgFilename), /* -c */
  { 'd', "daemon", NULL,
    gettext_noop("generate configuration for gnunetd, the GNUnet daemon"),
    0, &gnunet_getopt_configure_set_one, &config_daemon },
  COMMAND_LINE_OPTION_HELP(gettext_noop("Tool to setup GNUnet.")), /* -h */
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
};

static void gns2cfg(struct GNS_Tree * pos) {
  int i;
  char * val;

  if (pos == NULL)
    return;
  i = 0;
  while (pos->children[i] != NULL) {
    gns2cfg(pos->children[i]);
    i++;
  }
  if (i != 0)
    return;
  if ( (pos->section == NULL) ||
       (pos->option == NULL) )
    return;
  if (NO == GC_have_configuration_value(cfg,
					pos->section,
					pos->option)) {
    val = GNS_get_default_value_as_string(pos->type,
					  &pos->value);
    if (val != NULL) {
      GC_set_configuration_value_string(cfg,
					ectx,
					pos->section,
					pos->option,
					val);
      FREE(val);
    }
  }
}

static int dyn_config(const char * module,
		      const char * mainfunc,
		      int argc,
		      char * const * argv,
		      const char * filename) {
  ConfigurationPluginMain mptr;
  struct PluginHandle * library;

  library = os_plugin_load(ectx,
			   "libgnunet",
			   module);
  if (!library)
    return SYSERR;
  mptr = os_plugin_resolve_function(library,
				    mainfunc,
				    YES);
  if (! mptr) {
    os_plugin_unload(library);
    return SYSERR;
  }
  mptr(argc,
       argv,
       library,
       ectx,
       cfg,
       gns,
       filename,
       config_daemon);
  os_plugin_unload(library);
  return YES;
}

static const char * INFO =
  "gnunet-setup [OPTIONS] config"
#if HAVE_DIALOG
  "|menuconfig|wizard-curses"
#endif
#if HAVE_GTK
  "|gconfig|wizard-gtk"
#endif
  "";

/**
 * List of supported plugins.  One entry consists
 * of three strings: option name, plugin library
 * name and main method name.
 */
static const char * modules[] = {
   "gconfig", "setup_gtk", "gconf_main" ,
   "menuconfig", "setup_curses", "mconf_main" ,
   "config", "setup_text", "main_" ,
   "wizard-curses", "setup_curses", "wizard_curs_main",
   "wizard-gtk", "setup_gtk", "gtk_wizard_main",
   NULL,
};


int main(int argc,
	 char * const * argv) {
  const char * operation;
  int done;
  char * dirname;
  char * specname;
  int i;

  ectx = GE_create_context_stderr(NO,
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  os_init(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  i = gnunet_parse_options(INFO,
			   ectx,
			   cfg,
			   gnunetsetupOptions,
			   (unsigned int) argc,
			   argv);
  if (i < 0) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;
  }
  if (i != argc - 1) {
    if (i < argc - 1) {
      fprintf(stderr,
	      _("Too many arguments.\n"));
      return -1;
    }
    GE_LOG(ectx,
	   GE_WARNING | GE_REQUEST | GE_USER,
	   _("No interface specified, using default\n"));
    operation = "config";
#if HAVE_DIALOG
    operation = "menuconfig";
#endif
#if HAVE_GTK
    operation = "gconfig";
#endif
  } else {
    operation = argv[i];
  }
  if (NULL != strstr(operation, "wizard"))
    config_daemon = YES; /* wizard implies daemon! */
  if (cfgFilename == NULL)
    cfgFilename = config_daemon
      ? STRDUP(DEFAULT_DAEMON_CONFIG_FILE)
      : STRDUP(DEFAULT_CLIENT_CONFIG_FILE);
  dirname = string_expandFileName(ectx, cfgFilename);
  FREE(cfgFilename);
  cfgFilename = STRDUP(dirname);
  i = strlen(dirname) - 1;
  while (i > -1) {
    char ch = dirname[i];
    if ( (ch == '/') || (ch == '\\')) {
      dirname[i + 1] = 0;
      break;
    }
    i--;
  }
  disk_directory_create(ectx, dirname);
  if ( ( (0 != ACCESS(cfgFilename, W_OK)) &&
	 ( (errno != ENOENT) ||
	   (0 != ACCESS(dirname, W_OK))) ) )
    GE_DIE_STRERROR_FILE(ectx,
			 GE_FATAL | GE_USER | GE_ADMIN | GE_IMMEDIATE,
			 "access",
			 dirname);
  FREE(dirname);

  if (0 == ACCESS(cfgFilename, F_OK))
    GC_parse_configuration(cfg,
			   cfgFilename);
  dirname = os_get_installation_path(IPK_DATADIR);
  GE_ASSERT(ectx, dirname != NULL);
  specname = MALLOC(strlen(dirname) + strlen("config-daemon.scm") + 1);
  strcpy(specname, dirname);
  FREE(dirname);
  if (config_daemon)
    strcat(specname, "config-daemon.scm");
  else
    strcat(specname, "config-client.scm");
  gns = GNS_load_specification(ectx,
			       cfg,
			       specname);
  FREE(specname);
  if (gns == NULL) {
    GC_free(cfg);
    GE_free_context(ectx);
    FREE(cfgFilename);
    return -1;
  }
  gns2cfg(GNS_get_tree(gns));

  done = NO;
  i = 0;
  while ( (done == NO) &&
	  (modules[i] != NULL) ) {
    if (strcmp(operation, modules[i]) == 0) {
      if (dyn_config(modules[i+1],
		     modules[i+2],
		     argc,
		     argv,
		     cfgFilename) != YES) {
	GE_LOG(ectx,
	       GE_FATAL | GE_USER | GE_ADMIN | GE_IMMEDIATE,
	       _("`%s' is not available."),
	       operation);
	GNS_free_specification(gns);
	GC_free(cfg);
	GE_free_context(ectx);
	FREE(cfgFilename);
	return -1;
      } else {
	done = YES;
      }
    }
    i += 3;
  }
  FREE(cfgFilename);
  if (done == NO) {
    fprintf(stderr,
	    _("Unknown operation `%s'\n"),
	    operation);
    fprintf(stderr,
	    _("Use --help to get a list of options.\n"));
    GNS_free_specification(gns);
    GC_free(cfg);
    GE_free_context(ectx);
    return 1;
  }
  GNS_free_specification(gns);
  GC_free(cfg);
  GE_free_context(ectx);
  return 0;
}
