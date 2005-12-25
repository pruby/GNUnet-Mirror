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
 * @file conf/wizard_util.c
 * @brief Common helper functions
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util.h"

#define LKC_DIRECT_LINK
#include "lkc.h"


/**
 * @brief Determine whether a NIC makes a good default
 */
int wiz_is_nic_default(const char *name, int suggestion) {
	const char *nic = NULL;
	struct symbol *sym = sym_find("INTERFACE", "NETWORK");

  if (sym)
  {
  	sym_calc_value_ext(sym, 1);
  	nic = sym_get_string_value(sym);
#ifdef WINDOWS
		/* default NIC for unixes */
		if (strcmp(nic, "eth0") == 0)
			nic = NULL;
#endif
  }

  if (nic)
  {
  	/* The user has selected a NIC before */
  	int niclen = strlen(nic);
  	int inslen = strlen(name);
	suggestion = 0;
	if (inslen >= niclen)
  	{
#ifdef WINDOWS
  		if (strncmp(name + inslen - niclen - 1, nic, niclen) == 0)
#else
  		if (strcmp(name, nic) == 0)
#endif
  			suggestion = 1; /* This is the previous selection */
  	}
  }

  return suggestion;
}


/**
 * @brief Make GNUnet start automatically
 * @param doAutoStart true to enable autostart, false to disable it
 * @param username name of the user account to use
 * @param groupname name of the group to use
 * @return 1 on success, 0 on error
 */
int wiz_autostartService(int doAutoStart, char *username, char *groupname) {
  int ret = autostartService(doAutoStart,
			     username,
			     groupname);
  if (ret ) {
#ifdef MINGW
    char *err = NULL;
    switch(ret) {
    case 1:
      err = winErrorStr(_("Can't open Service Control Manager"),
			GetLastError());
      break;
    case 2:
      if (GetLastError() != ERROR_SERVICE_EXISTS) {
	err = winErrorStr(_("Can't create service"),
			  GetLastError());
      }
      break;
    case 3:
      err = winErrorStr(_("Error changing the permissions of"
			  " the GNUnet directory"),
			GetLastError());
      break;
    case 4:
      err = _("Cannot write to the regisitry");
      break;
    case 5:
      err = winErrorStr(_("Can't access the service"),
			GetLastError());
	  break;
    case 6:
      err = winErrorStr(_("Can't delete the service"),
			GetLastError());
      break;
    default:
      err = winErrorStr(_("Unknown error"), GetLastError());
    }
    if (err) {
      MessageBox(GetActiveWindow(),
  	       err,
  	       _("Error"),
  	       MB_ICONSTOP | MB_OK);
      free(err);
    }
#endif

    return 0;
  }
  return 1;
}

/**
 * @brief Add a service account for GNUnet
 * @param group the group of the new user
 * @param name the name of the new user
 * @return 1 on success
 */
int wiz_createGroupUser(char *group_name, char *user_name) {
  int ret = createGroupUser(group_name, user_name);

  if (ret) {
#ifdef MINGW
    char *err;

    switch(ret) {
    case 1:
      err = _("This version of Windows does not support "
	      "multiple users.");
      break;
    case 2:
      err = winErrorStr(_("Error creating user"), GetLastError());
      break;
    case 3:
      err = winErrorStr(_("Error accessing local security policy"), GetLastError());
      break;
    case 4:
      err = winErrorStr(_("Error granting service right to user"), GetLastError());
      break;
    default:
      err = winErrorStr(_("Unknown error while creating a new user"), GetLastError());
    }

    if (err) {
      MessageBox(0, err, _("Error"), MB_ICONSTOP | MB_OK);
      free(err);
    }
#endif
    return 0;
  }
  return 1;
}

/* end of wizard_util.c */
