/* 
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
#include "platform.h"

static void help() {
  puts("USAGE: gnunet-setup MODULE DEFFILE\n\n"
       "MODULE\n"
       " config\t\ttext-based configuration\n"
       " menuconfig\ttext-based menu\n"
       " xconfig\tX configuration\n"
       " gconfig\tGTK configuration\n\n"
       "DEFFILE\n"
       " File which contains the configuration items\n");
}

#if HAVE_CURSES
extern int mconf_main(int ac, char **av);
#endif

extern int conf_main(int ac, char **av);
#ifdef MINGW
extern void InitWinEnv();
extern void ShutdownWinEnv();
#endif

int main(int argc, 
	 char *argv[]) {
  if (argc < 3) {
    help();    
    return 0;
  }

#ifdef MINGW
  InitWinEnv();
#endif

  if (strncmp(argv[1], "config", 6) == 0)
    conf_main(argc - 1, &argv[1]);
  else if (strncmp(argv[1], "menuconfig", 10) == 0) {
#if HAVE_CURSES
    mconf_main(argc - 1, &argv[1]);
#else
    puts("Menuconfig is not available\n");
#endif 
 } else {
    puts("Unknown configurator\n\n");
    help();
  }

#ifdef MINGW
  ShutdownWinEnv();
#endif

  return 0;
}
