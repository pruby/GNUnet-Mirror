/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005 Christian Grothoff (and other contributing authors)

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
 * @file conf/gnunet-setup.c
 * @brief GNUnet Setup
 * @author Nils Durner
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "recreate.h"
#include "conf.h"
#include "zconf_tab.h"

#if HAVE_CURSES
#include "mconf.h"
#include "wizard_curs.h"
#endif

#if HAVE_GTK
#include "gconf.h"
#include "wizard.h"
#include <gtk/gtk.h>
#endif


/**
 * Perform option parsing from the command line.
 */
static int parser(int argc, char *argv[])
{
  int cont = OK;
  int c;
  int daemon = NO;
  char *filename = NULL;
  char *dirname;

  FREENONNULL(setConfigurationString("GNUNETD", "LOGFILE", NULL));
  while(1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      {"config", 1, 0, 'c'},
      {"deamon", 0, 0, 'd'},
      {"help", 0, 0, 'h'},
      {"version", 0, 0, 'v'},
      {"verbose", 0, 0, 'V'},
      {0, 0, 0, 0}
    };

    c = GNgetopt_long(argc, argv, "c:dhvV", long_options, &option_index);

    if(c == -1)
      break;                    /* No more flags to process */

    switch (c) {
    case 'c':
      filename = expandFileName(GNoptarg);
      break;
    case 'd':
      daemon = YES;
      break;
    case 'v':
      printf("gnunet-setup v%s\n", VERSION);
      cont = SYSERR;
      break;
    case 'V':
      FREENONNULL(setConfigurationString("GNUNET-SETUP", "VERBOSE", "YES"));
      break;
    case 'h':{
        static Help help[] = {
          HELP_CONFIG,
          {'d', "daemon", NULL,
           gettext_noop
           ("generate configuration for gnunetd, the GNUnet daemon")},
          HELP_HELP,
          HELP_LOGLEVEL,
          HELP_VERSION,
          HELP_VERBOSE,
          HELP_END,
        };
        formatHelp("gnunet-daemon [OPTIONS] MODE",
                   _("Tool to setup GNUnet."), help);
        printf(_("Available MODEs:\n"));
        printf(_(" config\t\ttext-based configuration\n"));
#if HAVE_CURSES
        printf(_(" menuconfig\ttext-based menu\n"));
        printf(_
               (" wizard-curses\tBasic text-based graphical configuration\n"));
#endif
#if HAVE_GTK
        printf(_(" gconfig\tGTK configuration\n"));
        printf(_(" wizard-gtk\tBasic GTK configuration\n\n"));
#endif
        cont = SYSERR;
        break;
      }
    default:
      LOG(LOG_FAILURE, _("Use --help to get a list of options.\n"));
      cont = SYSERR;
    }                           /* end of parsing commandline */
  }
  /* set the 'magic' code that indicates that
     this process is 'gnunetd' (and not any of
     the user-tools).  Needed such that we use
     the right configuration file... */
  if(daemon) {
    FREENONNULL(setConfigurationString("GNUNETD", "_MAGIC_", "YES"));
    if(filename == NULL) {
      if(0 == ACCESS(DEFAULT_DAEMON_CONFIG_FILE, W_OK) ||
	 (errno == ENOENT && 0 == ACCESS(DEFAULT_DAEMON_DIR, W_OK)))
        filename = STRDUP(DEFAULT_DAEMON_CONFIG_FILE);
      else {
        if(0 == ACCESS(VAR_DIRECTORY, W_OK))
          mkdirp(VAR_DAEMON_DIRECTORY);
        if(0 == ACCESS(VAR_DAEMON_CONFIG_FILE, W_OK) ||
            (errno == ENOENT && 0 == ACCESS(VAR_DAEMON_DIRECTORY, W_OK)))
          filename = STRDUP(VAR_DAEMON_CONFIG_FILE);
        else {
          dirname = expandFileName(GNUNET_HOME_DIRECTORY);
          mkdirp(dirname);
          FREE(dirname);
          filename = expandFileName(HOME_DAEMON_CONFIG_FILE);
        }
      }
    }
    FREENONNULL(setConfigurationString("FILES", "gnunet.conf", filename));
    conf_parse(DATADIR "/config-daemon.in");
  }
  else {
    FREENONNULL(setConfigurationString("GNUNETD", "_MAGIC_", "NO"));
    if(filename == NULL) {
      dirname = expandFileName(GNUNET_HOME_DIRECTORY);
      mkdirp(dirname);
      FREE(dirname);
      filename = expandFileName(DEFAULT_CLIENT_CONFIG_FILE);
    }
    FREENONNULL(setConfigurationString("FILES", "gnunet.conf", filename));
    conf_parse(DATADIR "/config-client.in");
  }
  dirname = STRDUP(filename);

  c = strlen(dirname) - 1;
  while(c > -1) {
    char ch = dirname[c];
    if (ch == '/' || ch == '\\') {
      dirname[c + 1] = 0;
      break;
    }
    c--;
  }

  if (c)
    mkdirp(dirname);

  if((0 != ACCESS(filename,
                  W_OK)) &&
     ((0 == ACCESS(filename, F_OK)) || (0 != ACCESS(dirname, W_OK)))) {
    errexit(_
            ("gnunet-setup must have write-access to the configuration file `%s'\n"),
            filename);
  }
  FREE(dirname);
  FREENONNULL(setConfigurationString("GNUNET-SETUP", "FILENAME", filename));
  if(GNoptind < argc)
    FREENONNULL(setConfigurationString("GNUNET-SETUP",
                                       "OPERATION", argv[GNoptind++]));
  if(GNoptind < argc) {
    LOG(LOG_WARNING, _("Invalid arguments: "));
    while(GNoptind < argc)
      LOG(LOG_WARNING, "%s ", argv[GNoptind++]);
    LOG(LOG_FATAL, _("Invalid arguments. Exiting.\n"));
    FREE(filename);
    return SYSERR;
  }

  if(0 != ACCESS(filename, F_OK))
    recreate_main();
  FREE(filename);


  return cont;
}


int main(int argc, char *argv[])
{
  char *operation;

  if(OK != initUtil(argc, argv, &parser))
    return -1;
  operation = getConfigurationString("GNUNET-SETUP", "OPERATION");
  if (operation == NULL) {
#if HAVE_GTK
    operation = STRDUP("gconfig");
#elif HAVE_CURSES
    operation = STRDUP("menuconfig");
#else
    operation = STRDUP("config");
#endif
    LOG(LOG_WARNING,
	"No interface specified, defaulting to `%s'\n",
	operation);
  }
  if(strcmp(operation, "config") == 0)
    conf_main();
  else if(strcmp(operation, "menuconfig") == 0) {
#if HAVE_CURSES
    mconf_main();
#else
    printf(_("menuconfig is not available\n"));
#endif
  }
  else if(strcmp(operation, "wizard-curses") == 0) {
    if(!testConfigurationString("GNUNETD", "_MAGIC_", "YES"))
      errexit(_("Can only run wizard to configure gnunetd.\n"
                "Did you forget the `%s' option?\n"), "-d");
#if HAVE_CURSES
    wizard_curs_main();
#else
    printf(_("wizard-curses is not available\n"));
#endif
  }
  else if(strcmp(operation, "wizard-gtk") == 0) {
    if(!testConfigurationString("GNUNETD", "_MAGIC_", "YES"))
      errexit(_("Can only run wizard to configure gnunetd.\n"
                "Did you forget the `%s' option?\n"), "-d");
#if HAVE_GTK
    gtk_init(&argc, &argv);
    wizard_main();
#else
    printf(_("wizard-gtk is not available\n"));
#endif
  }
  else if(strcmp(operation, "gconfig") == 0) {
#if HAVE_GTK
    gtk_init(&argc, &argv);
    gconf_main();
#else
    printf(_("gconfig is not available\n"));
#endif
  }
  else {
    printf(_("Unknown operation `%s'\n"), operation);
    printf(_("Use --help to get a list of options.\n"));
    FREE(operation);
    doneUtil();
    return 1;
  }

  FREE(operation);
  doneUtil();
  return 0;
}
