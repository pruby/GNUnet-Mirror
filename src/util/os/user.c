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
 * @author Heikki Lindholm
 */

#include "platform.h"
#include "gnunet_util_os.h"
#include "gnunet_util_string.h"

#ifdef OSX
static int
parse_dscl_user_list_line (FILE * f, char *name, size_t name_len, int *id)
{
  int c;
  int state;
  int64_t tmp_id = 0LL;
  int tmp_sign = 0;
  int len = 0;
  int retval;

  retval = 2;
  state = 1;
  while ((retval == 2) && ((c = fgetc (f)) != EOF))
    {
      switch (state)
        {
        case 1:                /* skip leading ws */
          tmp_id = 0;
          tmp_sign = 1;
          len = 0;
          if (c != ' ' || c != '\t' || c != '\n')
            {
              if (len < name_len)
                name[len++] = (char) c;
              else
                retval = -1;
              state = 2;
            }
          break;
        case 2:                /* user/group name */
          if (c == ' ' || c == '\t')
            {
              name[len] = '\0';
              state = 3;
            }
          else if (c == '\n')
            state = 1;          /* error? */
          else
            {
              if (len < name_len)
                name[len++] = (char) c;
              else
                retval = -1;
            }
          break;
        case 3:                /* skip ws */
          if ((c >= '0' && c <= '9') || c == '-')
            {
              state = 4;
              if (c == '-')
                tmp_sign = -1;
              else
                tmp_id = c - '0';
            }
          else if (c == '\n')
            state = 1;
          else if (c != ' ' && c != '\t')
            retval = -1;
          break;
        case 4:                /* user/group id */
          if (c >= '0' && c <= '9')
            {
              state = 4;
              tmp_id = (tmp_id * 10) + (c - '0');
              if (tmp_id > INT32_MAX)
                retval = -1;
            }
          else if (c == '\n')
            {
              *id = tmp_sign * (int) tmp_id;
              state = 1;
              retval = 0;
            }
          else
            {
              state = 1;
              retval = -1;
            }
          break;
        }
    }
  return retval;
}

static int
run_dscl_command (const char *dir, const char *name, const char *attr_tmpl,
                  const char *attr_val)
{
  char *cmd;
  static const char *prefix = "/usr/bin/dscl .";
  size_t len;
  int ret = 0;

  if ((!dir || !name) || (attr_tmpl && !attr_val))
    return -1;

  len = strlen (prefix) + 1 + 6 + 1 + strlen (dir) + 1 + (1 + strlen (name));
  if (attr_tmpl != NULL)
    len += 1 + strlen (attr_tmpl);      /* space + len */
  else
    len += 1 + strlen ("RecordName") + 1 + strlen (name);
  if (attr_val != NULL)
    len += 1 + strlen (attr_val);       /* space + len */
  len++;                        /* terminating nil */
  cmd = GNUNET_malloc (len);
  if (attr_tmpl)
    {
      char *s;
      snprintf (cmd, len, "%s %s %s/_%s %s", prefix, "create", dir, name,
                attr_tmpl);
      s = GNUNET_strdup (cmd);
      snprintf (cmd, len, s, attr_val);
      GNUNET_free (s);
      ret = system (cmd);
    }
  else
    {
      snprintf (cmd, len, "%s %s %s/_%s", prefix, "create", dir, name);
      ret = system (cmd);
      if (ret == 0)
        {
          snprintf (cmd, len, "%s %s %s/_%s RecordName %s", prefix, "append",
                    dir, name, name);
          ret = system (cmd);
        }
    }

  if (ret == -1)
    GNUNET_GE_LOG_STRERROR (NULL,
                            GNUNET_GE_ERROR | GNUNET_GE_BULK |
                            GNUNET_GE_ADMIN, "system");
  else if (WEXITSTATUS (ret) != 0)
    GNUNET_GE_LOG (NULL,
                   GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                   _("`%s' returned with error code %u"),
                   cmd, WEXITSTATUS (ret));


  GNUNET_free (cmd);
  return ret;
}

static int
check_name (const char *name)
{
  static const char *allowed_chars =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
  int i, j;

  for (i = 0; i < strlen (name); i++)
    {
      int found = 0;
      for (j = 0; j < strlen (allowed_chars); j++)
        {
          if (name[i] == allowed_chars[j])
            found = 1;
        }
      if (!found)
        return -1;
    }
  return 0;
}
#endif /* OSX */

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
#ifdef OSX
      if (geteuid () != 0)
        return GNUNET_SYSERR;
      if (ACCESS ("/usr/bin/dscl", X_OK) == 0)
        return GNUNET_OK;
      return GNUNET_SYSERR;
#endif
      return GNUNET_SYSERR;
    }
  if ((user_name == NULL) || (0 == strlen (user_name)))
    return 0;

#ifdef WINDOWS
  if (IsWinNT ())
    return CreateServiceAccount (user_name, "GNUnet service account");
#elif defined(OSX)
  if (ACCESS ("/usr/bin/dscl", X_OK) == 0)
    {
      const char *real_user_name = "\"GNUnet daemon\"";
      const char *real_group_name = "\"GNUnet administrators\"";
      int id, uid, gid;
      int user_found, group_found;
      char *s;
      FILE *f;
      int ret;

      haveGroup = group_name && strlen (group_name) > 0;

      if (check_name (user_name) != 0)
        return GNUNET_SYSERR;
      if (haveGroup && check_name (group_name) != 0)
        return GNUNET_SYSERR;

      s = GNUNET_malloc (256);

      if (!haveGroup)
        group_name = "nogroup";

      f = popen ("/usr/bin/dscl . -list /Groups PrimaryGroupID 2> /dev/null",
                 "r");
      if (f == NULL)
        {
          GNUNET_GE_LOG_STRERROR_FILE (NULL,
                                       GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                       GNUNET_GE_ADMIN, "popen", "dscl");
          GNUNET_free (s);
          return GNUNET_SYSERR;
        }
      gid = -100;
      group_found = 0;
      while (!feof (f))
        {
          ret = parse_dscl_user_list_line (f, s, 256, &id);
          if (ret < 0)
            {
              GNUNET_GE_LOG (NULL,
                             GNUNET_GE_ERROR | GNUNET_GE_BULK |
                             GNUNET_GE_ADMIN,
                             _("Error while parsing dscl output.\n"));
              pclose (f);
              GNUNET_free (s);
              return GNUNET_SYSERR;
            }
          if (ret == 2)
            break;
          if (!group_found && id > gid && id < 500)
            gid = id;
          if (strcmp (s, group_name) == 0 ||
              (s[0] == '_' && strcmp (s + 1, group_name) == 0))
            {
              gid = id;
              group_found = 1;
            }
        }
      pclose (f);
      if (!haveGroup && !group_found)
        {
          GNUNET_GE_LOG (NULL,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                         _
                         ("Couldn't find a group (`%s') for the new user and none was specified.\n"),
                         group_name);
          GNUNET_free (s);
          return GNUNET_SYSERR;
        }

      f = popen ("/usr/bin/dscl . -list /Users UniqueID 2> /dev/null", "r");
      if (f == NULL)
        {
          GNUNET_GE_LOG_STRERROR_FILE (NULL,
                                       GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                       GNUNET_GE_ADMIN, "popen", "dscl");
          GNUNET_free (s);
          return GNUNET_SYSERR;
        }
      uid = -100;
      user_found = 0;
      while (!feof (f))
        {
          ret = parse_dscl_user_list_line (f, s, 256, &id);
          if (ret < 0)
            {
              GNUNET_GE_LOG (NULL,
                             GNUNET_GE_ERROR | GNUNET_GE_BULK |
                             GNUNET_GE_ADMIN,
                             _("Error while parsing dscl output.\n"));
              pclose (f);
              GNUNET_free (s);
              return GNUNET_SYSERR;
            }
          if (ret == 2)
            break;
          if (!user_found && id > uid && id < 500)
            uid = id;
          if (strcmp (s, user_name) == 0 ||
              (s[0] == '_' && strcmp (s + 1, user_name) == 0))
            {
              uid = id;
              user_found = 1;
            }
        }
      pclose (f);

      if (haveGroup && !group_found)
        {
          if (gid > 400)
            gid++;
          else
            gid = 400;
          if (gid >= 500)
            {
              GNUNET_GE_LOG (NULL,
                             GNUNET_GE_ERROR | GNUNET_GE_BULK |
                             GNUNET_GE_ADMIN,
                             _
                             ("Failed to find a free system id for the new group.\n"));
              GNUNET_free (s);
              return GNUNET_SYSERR;
            }
        }
      if (!user_found)
        {
          if (uid > 400)
            uid++;
          else
            uid = 400;
          if (uid >= 500)
            {
              GNUNET_GE_LOG (NULL,
                             GNUNET_GE_ERROR | GNUNET_GE_BULK |
                             GNUNET_GE_ADMIN,
                             _
                             ("Failed to find a free system id for the new user.\n"));
              GNUNET_free (s);
              return GNUNET_SYSERR;
            }
        }

      ret = 0;
      if (haveGroup && !group_found)
        {
          ret = run_dscl_command ("/Groups", group_name, NULL, NULL);

          if (ret == 0)
            ret =
              run_dscl_command ("/Groups", group_name, "Password %s",
                                "\"*\"");
          if (ret == 0)
            {
              snprintf (s, 12, "%d", gid);
              ret =
                run_dscl_command ("/Groups", group_name, "PrimaryGroupID %s",
                                  s);
            }
          if (ret == 0)
            ret =
              run_dscl_command ("/Groups", group_name, "RealName %s",
                                real_group_name);
        }

      if (!user_found)
        {
          if (ret == 0)
            ret = run_dscl_command ("/Users", user_name, NULL, NULL);
          if (ret == 0)
            ret =
              run_dscl_command ("/Users", user_name, "UserShell %s",
                                "/usr/bin/false");
          if (ret == 0)
            ret =
              run_dscl_command ("/Users", user_name, "RealName %s",
                                real_user_name);
          if (ret == 0)
            {
              snprintf (s, 12, "%d", uid);
              ret = run_dscl_command ("/Users", user_name, "UniqueID %s", s);
            }
          if (ret == 0)
            {
              snprintf (s, 12, "%d", gid);
              ret =
                run_dscl_command ("/Users", user_name, "PrimaryGroupID %s",
                                  s);
            }
          if (ret == 0)
            ret =
              run_dscl_command ("/Users", user_name, "NFSHomeDirectory %s",
                                "/var/empty");
          if (ret == 0)
            ret =
              run_dscl_command ("/Users", user_name, "passwd %s", "\"*\"");
        }

      GNUNET_free (s);
      return ret == 0 ? GNUNET_OK : GNUNET_SYSERR;
    }
  else
    return GNUNET_SYSERR;
#else
  if (ACCESS ("/usr/sbin/adduser", X_OK) == 0)
    {
      /* Debian */
      /* TODO: FreeBSD? http://www.freebsd.org/cgi/man.cgi?query=adduser&sektion=8 */
      char *cmd;
      int ret;

      haveGroup = group_name && strlen (group_name) > 0;
      cmd =
        GNUNET_malloc (256 + (haveGroup ? strlen (group_name) : 0) +
                       strlen (user_name));

      if (haveGroup)
        {
          sprintf (cmd, "/usr/sbin/addgroup --quiet --system %s", group_name);
          ret = system (cmd);
          if (ret == -1)
            GNUNET_GE_LOG_STRERROR (NULL,
                                    GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                    GNUNET_GE_ADMIN, "system");
          else if (WEXITSTATUS (ret) != 0)
            GNUNET_GE_LOG (NULL,
                           GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                           _("`%s' returned with error code %u"),
                           "addgroup", WEXITSTATUS (ret));
        }

      sprintf (cmd,
               "/usr/sbin/adduser --quiet --system %s %s "
               "--no-create-home %s",
               haveGroup ? "--ingroup" : "",
               haveGroup ? group_name : "", user_name);
      ret = system (cmd);
      if (ret == -1)
        GNUNET_GE_LOG_STRERROR (NULL,
                                GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                GNUNET_GE_ADMIN, "system");
      else if (WEXITSTATUS (ret) != 0)
        GNUNET_GE_LOG (NULL,
                       GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                       _("`%s' returned with error code %u"),
                       "adduser", WEXITSTATUS (ret));
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
