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
 * @file conf/recreate.c
 * @brief create .conf files from the .in templates
 * @author Nils Durner
 */

#include "gnunet_util.h"
#include "recreate.h"
#include "confdata.h"

#define LKC_DIRECT_LINK
#include "lkc.h"


/**
 * @brief Set reasonable default for GNUNETD_HOME if needed
 */
static void checkGNUNETDHome(struct symbol *sym)
{
 
  if (strcmp(sym->name, "GNUNETD_HOME") == 0)
    {
      const char *val;
      
      sym_calc_value_ext(sym, 1);
      val = sym_get_string_value(sym);
      
      /* only empty if gnunet-setup is run for the first time */
      if (!val || !strlen(val))
	{
	  /* GNUNETD_HOME isn't set yet. Let's choose a sane default */
	  struct stat buf;
	  int var = 0;
	  if (STAT("/var/lib/GNUnet", &buf) != 0)
	    {
	      /* /var/lib/GNUnet doesn't exist. Do we have write permissions to /var? */
	      if (ACCESS("/var", W_OK) == 0)
		var = 1;
	    }
	  else
	    {
	      /* /var/lib/GNUnet is there, do we have write permissions? */
	      if (ACCESS("/var/lib/GNUnet", W_OK) == 0)
		var = 1;
	    }
	  
	  sym_set_string_value(sym, var ? "/var/lib/GNUnet" : "~/.gnunet");
	}
    }
}

static void insert_nic(const char * name,
		       int defaultNIC,
		       void * cls) {
  struct symbol * sym = cls;
  if ( (NULL == sym_get_string_value(sym)) ||
       (defaultNIC) )
    sym_set_string_value(sym, name);
}

/**
 * @brief Set reasonable default for GNUNETD_HOME if needed
 */
static void checkDefaultIFC(struct symbol *sym)
{
 
  if (strncmp(sym->name, 
	      "INTERFACE",
	      strlen("INTERFACE")) == 0) /* match also for INTERFACES ! */
    {
      const char *val;
      
      sym_calc_value_ext(sym, 1);
      val = sym_get_string_value(sym);
      
      /* only empty if gnunet-setup is run for the first time */
      if (!val || !strlen(val))
	{
	  /* INTERFACE isn't set yet. Let's choose a sane default */
	  enumNetworkIfs(insert_nic, sym);
	}
    }
}


int recreate_main() {
  struct symbol *sym;
  int i = 0;
  char * filename;
  
  filename = getConfigurationString("GNUNET-SETUP",
				    "FILENAME");
  /* we are setting advanced/rare settings below */
  sym = sym_find("EXPERIMENTAL", "Meta");
  if (sym != NULL)
    sym_set_tristate_value(sym, yes);
  sym = sym_find("ADVANCED", "Meta"); 
  if (sym != NULL)
    sym_set_tristate_value(sym, yes);
  sym = sym_find("RARE", "Meta"); 
  if (sym != NULL)
    sym_set_tristate_value(sym, yes);

  /* save new config files to DATADIR */
  if (testConfigurationString("GNUNETD",
			      "_MAGIC_",
			      "YES")) {
    for_all_symbols(i, sym) {
      checkGNUNETDHome(sym);
      checkDefaultIFC(sym);
    }
  }
  /* Write defaults */
  if (conf_write(filename)) {
    printf(_("Unable to save configuration file `%s': %s.\n"), 
	   filename,
	   STRERROR(errno));
    FREE(filename);
    return 1;
  }
  FREE(filename);
  return 0;  
}

/* end of recreate.c */
