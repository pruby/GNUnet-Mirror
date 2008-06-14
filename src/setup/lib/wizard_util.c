/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file setup/lib/wizard_util.c
 * @brief Common helper functions
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util.h"
#include "wizard_util.h"


/**
 * @brief Determine whether a NIC makes a good default
 */
int
GNUNET_GNS_wiz_is_nic_default (struct GNUNET_GC_Configuration *cfg,
                               const char *name, int suggestion)
{
  char *nic;

  GNUNET_GC_get_configuration_value_string (cfg, "NETWORK", "INTERFACE",
                                            GNUNET_DEFAULT_INTERFACE, &nic);

#ifdef WINDOWS
  /* default NIC for unixes */
  if (strcmp (nic, GNUNET_DEFAULT_INTERFACE) == 0)
    {
      GNUNET_free (nic);
      nic = NULL;
    }
#endif

  if (NULL != nic)
    {
      /* The user has selected a NIC before */
      int niclen, inslen;

      niclen = strlen (nic);
      inslen = strlen (name);
      suggestion = 0;

      if (inslen >= niclen)
        {
#ifdef WINDOWS
          if (strncmp (name + inslen - niclen - 1, nic, niclen) == 0)
#else
          if (strcmp (name, nic) == 0)
#endif
            suggestion = 1;     /* This is the previous selection */
        }
      GNUNET_free (nic);
    }

  return suggestion;
}


/**
 * @brief Make GNUnet start automatically
 * @param serviceType GNUNET_SERVICE_TYPE_xxx
 * @param doAutoStart true to enable autostart, false to disable it
 * @param username name of the user account to use
 * @param groupname name of the group to use
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_GNS_wiz_autostart_service (struct GNUNET_GE_Context *ectx,
                                  int serviceType, int doAutoStart,
                                  char *username, char *groupname)
{
  int ret;
  char *exe;
  char *name;

  exe = GNUNET_get_installation_path (GNUNET_IPK_BINDIR);
  exe = (char *) GNUNET_realloc (exe, strlen (exe) + 22);       /* 11 = "gnunet-auto-share.exe" */
  if (serviceType == GNUNET_SERVICE_TYPE_GNUNETD)
    {
      strcat (exe, "gnunetd");
      name = "GNUnet";
    }
  else if (serviceType == GNUNET_SERVICE_TYPE_AUTOSHARE)
    {
      strcat (exe, "gnunet-auto-share");
      name = "GNUnet Auto Share";
    }
  else
    return GNUNET_SYSERR;

#ifdef WINDOWS
  strcat (exe, ".exe");
#endif

  ret =
    GNUNET_configure_autostart (ectx, 0, doAutoStart,
                                name, exe, username, groupname);
  GNUNET_free (exe);
  if (ret != GNUNET_YES)
    {
#ifdef WINDOWS
      char *err = NULL;

      switch (ret)
        {
        case 1:
          err = winErrorStr (_("Can't open Service Control Manager"),
                             GetLastError ());
          break;
        case 2:
          if (GetLastError () != ERROR_SERVICE_EXISTS)
            {
              err = winErrorStr (_("Can't create service"), GetLastError ());
            }
          break;
        case 3:
          err = winErrorStr (_("Error changing the permissions of"
                               " the GNUnet directory"), GetLastError ());
          break;
        case 4:
          err =
            winErrorStr (_("Cannot write to the registry"), GetLastError ());
          break;
        case 5:
          err = winErrorStr (_("Can't access the service"), GetLastError ());
          break;
        case 6:
          err = winErrorStr (_("Can't delete the service"), GetLastError ());
          break;
        default:
          err = winErrorStr (_("Unknown error"), GetLastError ());
        }
      if (err)
        {
          MessageBox (GetActiveWindow (),
                      err, _("Error"), MB_ICONSTOP | MB_OK);
          free (err);
        }
#endif

      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * @brief Add a service account for GNUnet
 * @param group the group of the new user
 * @param name the name of the new user
 * @return 1 on success
 */
int
GNUNET_GNS_wiz_create_group_user (char *group_name, char *user_name)
{
  int ret;

  ret = GNUNET_configure_user_account (0, 1, user_name, group_name);

  if (ret)
    {
#ifdef MINGW
      char *err;

      switch (ret)
        {
        case 1:
          err = _("This version of Windows does not support "
                  "multiple users.");
          break;
        case 2:
          err = winErrorStr (_("Error creating user"), GetLastError ());
          break;
        case 3:
          err =
            winErrorStr (_("Error accessing local security policy"),
                         GetLastError ());
          break;
        case 4:
          err =
            winErrorStr (_("Error granting service right to user"),
                         GetLastError ());
          break;
        default:
          err =
            winErrorStr (_("Unknown error while creating a new user"),
                         GetLastError ());
        }

      if (err)
        {
          MessageBox (0, err, _("Error"), MB_ICONSTOP | MB_OK);
          free (err);
        }
#endif
      return 0;
    }
  return 1;
}

/* end of wizard_util.c */
