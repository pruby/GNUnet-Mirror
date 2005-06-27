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
 */

#include <stdio.h>
#include <string.h>
#include "gnunet_util.h"
#include "platform.h"

static void help() {
  puts(_("USAGE: gnunet-setup MODULE\n\n"
       "MODULE\n"
       " recreate\t\recreate configuration files\n"
       " config\t\ttext-based configuration\n"
       " menuconfig\ttext-based menu\n"
       " gconfig\tGTK configuration\n"
			" wizard-curses\tBasic text-based graphical configuration\n"
			" wizard-gtk\tBasic GTK configuration\n\n"));
}

#if HAVE_CURSES
int mconf_main(int ac, char **av);
int wizard_curs_main(int argc, char *argv[]);
#endif

#if HAVE_GTK
int gconf_main(int ac, char *av[]);
int wizard_main (int argc, char *argv[]);
#endif

int conf_main(int ac, char **av);
int recreate_main(int ac, char **av);

int main(int argc,
	 char *argv[]) {
  if (argc < 2) {
    help();
    return 0;
  }

  initUtil(0, NULL, NULL);

  if (strncmp(argv[1], "config", 6) == 0)
    conf_main(argc - 1, &argv[1]);
  else if (strncmp(argv[1], "menuconfig", 10) == 0) {
#if HAVE_CURSES
    mconf_main(argc - 1, &argv[1]);
#else
    puts("Menuconfig is not available\n");
#endif
  }
  else if (strncmp(argv[1], "wizard-curses", 13) == 0) {
#if HAVE_CURSES
    wizard_curs_main(argc - 1, &argv[1]);
#else
    puts("Wizard-curses is not available\n");
#endif
  }
  else if (strncmp(argv[1], "wizard-gtk", 10) == 0) {
#if HAVE_GTK
    wizard_main(argc - 1, &argv[1]);
#else
    puts("basic-gtk is not available\n");
#endif
 	}
  else if (strncmp(argv[1], "gconfig", 7) == 0) {
#if HAVE_GTK
    gconf_main(argc - 1, &argv[1]);
#else
    puts("Gconfig is not available\n");
#endif
  }
  else if (strncmp(argv[1], "recreate", 7) == 0) {
  	if (argc < 3) {
  		puts(_("Please specify a path where the configuration files will be "
  			"stored."));
  		return 1;
  	}
  	recreate_main(argc - 1, &argv[1]);
  }
	else {
    puts("Unknown configurator\n\n");
    help();
  }

  doneUtil();

  return 0;
}
