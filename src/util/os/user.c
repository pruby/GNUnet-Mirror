/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/user.c
 * @brief wrappers for UID functions
 * @author Christian Grothoff
 */

#include "gnunet_util_os.h"
#include "gnunet_util_string.h"
#include "platform.h"

int
GNUNET_configure_user_account (int testCapability,
                               int doAdd, const char *group_name,
                               const char *user_name)
{
  int haveGroup;

  if (testCapability)
    {
      /* TODO: actually check that group/user
         exists/does not yet exist */
#ifdef WINDOWS
      return IsWinNT ()? GNUNET_OK : GNUNET_SYSERR;
#endif
#ifdef LINUX
      if (geteuid () != 0)
        return GNUNET_SYSERR;
      if (doAdd == GNUNET_YES)
        {
          if (((ACCESS ("/usr/sbin/adduser", X_OK) == 0) ||
               (ACCESS ("/usr/sbin/useradd", X_OK) == 0)) &&
              ((ACCESS ("/usr/sbin/addgroup", X_OK) == 0) ||
               (ACCESS ("/usr/sbin/groupadd", X_OK) == 0)))
            return GNUNET_OK;
          return GNUNET_SYSERR;
        }
      else if (doAdd == GNUNET_NO)
        {
          if ((ACCESS ("/usr/sbin/deluser", X_OK) == 0) ||
              (ACCESS ("/usr/sbin/userdel", X_OK) == 0))
            return GNUNET_OK;
          return GNUNET_SYSERR;
        }
      else if (doAdd == GNUNET_SYSERR)
        {
          if (((ACCESS ("/usr/sbin/dleuser", X_OK) == 0) ||
               (ACCESS ("/usr/sbin/userdel", X_OK) == 0)) &&
              ((ACCESS ("/usr/sbin/delgroup", X_OK) == 0) ||
               (ACCESS ("/usr/sbin/groupdel", X_OK) == 0)))
            return GNUNET_OK;
          return GNUNET_SYSERR;
        }
#endif
      return GNUNET_SYSERR;
    }
  if ((user_name == NULL) || (0 == strlen (user_name)))
    return 0;

#ifdef WINDOWS
  if (IsWinNT ())
    return CreateServiceAccount (user_name, "GNUnet service account");
#elif OSX
  return GNUNET_SYSERR;         /* TODO */
#else
  if (ACCESS ("/usr/sbin/adduser", X_OK) == 0)
    {
      /* Debian */
      /* TODO: FreeBSD? http://www.freebsd.org/cgi/man.cgi?query=adduser&sektion=8 */
      char *cmd;

      haveGroup = group_name && strlen (group_name) > 0;
      cmd =
        GNUNET_malloc (256 + (haveGroup ? strlen (group_name) : 0) +
                       strlen (user_name));

      if (haveGroup)
        {
          sprintf (cmd, "/usr/sbin/addgroup --quiet --system %s", group_name);
          system (cmd);
        }

      sprintf (cmd,
               "/usr/sbin/adduser --quiet --system %s %s "
               "--no-create-home %s",
               haveGroup ? "--ingroup" : "",
               haveGroup ? group_name : "", user_name);
      system (cmd);
      GNUNET_free (cmd);
      return GNUNET_OK;
    }
  /* TODO: useradd */
  else
    return GNUNET_SYSERR;
#endif
  return GNUNET_SYSERR;
}



/**
 * @brief Change user ID
 */
int
GNUNET_change_user (struct GNUNET_GE_Context *ectx, const char *user)
{
#ifndef MINGW
  struct passwd *pws;

  errno = 0;
  pws = getpwnam (user);
  if (pws == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                     GNUNET_GE_IMMEDIATE,
                     _("Cannot obtain information about user `%s': %s\n"),
                     user, errno == 0 ? _("No such user") : STRERROR (errno));
      return GNUNET_SYSERR;
    }
  if ((0 != setgid (pws->pw_gid)) || (0 != setegid (pws->pw_gid)) ||
#if HAVE_INITGROUPS
      (0 != initgroups (user, pws->pw_gid)) ||
#endif
      (0 != setuid (pws->pw_uid)) || (0 != seteuid (pws->pw_uid)))
    {
      if ((0 != setregid (pws->pw_gid, pws->pw_gid)) ||
          (0 != setreuid (pws->pw_uid, pws->pw_uid)))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_FATAL | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                         GNUNET_GE_IMMEDIATE,
                         _("Cannot change user/group to `%s': %s\n"), user,
                         STRERROR (errno));
          return GNUNET_SYSERR;
        }
    }
#endif

  return GNUNET_OK;
}



/**
 * @brief Change owner of a file
 */
int
GNUNET_file_change_owner (struct GNUNET_GE_Context *ectx,
                          const char *filename, const char *user)
{
#ifndef MINGW
  struct passwd *pws;

  pws = getpwnam (user);
  if (pws == NULL)
    {
      if (NULL != ectx)
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                       GNUNET_GE_IMMEDIATE,
                       _("Cannot obtain information about user `%s': %s\n"),
                       user, STRERROR (errno));
      return GNUNET_SYSERR;
    }
  if ((0 != chown (filename, pws->pw_uid, pws->pw_gid)) && (NULL != ectx))
    GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                 GNUNET_GE_ERROR | GNUNET_GE_USER |
                                 GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                                 "chown", filename);
#endif
  return GNUNET_OK;
}
