/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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
 * @file conf/silent.c
 * @brief create .conf files from the .in templates
 * @author Nils Durner
 */

#include "gnunet_util.h"

#define LKC_DIRECT_LINK
#include "lkc.h"


int recreate_main(int ac, char **av) {
	struct symbol *sym;
	
	conf_parse(DATADIR"/config.in");

	/* we are setting advanced/rare settings below */
  sym = sym_find("EXPERIMENTAL", "Meta");
  sym_set_tristate_value(sym, yes);
  sym = sym_find("ADVANCED", "Meta");
  sym_set_tristate_value(sym, yes);
  sym = sym_find("RARE", "Meta");
  sym_set_tristate_value(sym, yes);

	/* save new config files to DATADIR */
  sym = sym_find("config-daemon.in_CONF_DEF_DIR", "Meta");
	sym_set_string_value(sym, DATADIR"/");

  sym = sym_find("config-daemon.in_CONF_DEF_FILE", "Meta");
	sym_set_string_value(sym, "gnunet.root");

  sym = sym_find("config-client.in_CONF_DEF_DIR", "Meta");
	sym_set_string_value(sym, DATADIR"/");

  sym = sym_find("config-client.in_CONF_DEF_FILE", "Meta");
	sym_set_string_value(sym, "gnunet.user");

	/* Write defaults */
	if (!conf_write()) {
		printf(_("Unable to save configuration files to %s.\n"), DATADIR);
		return 1;
	}
	else
		return 0;
}

/* end of silent.c */
