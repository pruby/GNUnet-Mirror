/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/osconfig.c
 * @brief functions to read or change the OS configuration
 * @author Nils Durner
 * @author Heikki Lindholm
 * @author Jake Dust
 */

#include "platform.h"
#include "gnunet_util_os.h"
#include "gnunet_util_string.h"

/**
 * @brief Enumerate all network interfaces
 * @param callback the callback function
 */
void
GNUNET_list_network_interfaces (struct GNUNET_GE_Context *ectx,
                                GNUNET_NetworkInterfaceProcessor proc,
                                void *cls)
{
#ifdef MINGW
  ListNICs (proc, cls);
#else
  char entry[11], *dst;
  FILE *f;

  if (system ("ifconfig > /dev/null 2> /dev/null"))
    if (system ("/sbin/ifconfig > /dev/null 2> /dev/null") == 0)
      f = popen ("/sbin/ifconfig 2> /dev/null", "r");
    else
      f = NULL;
  else
    f = popen ("ifconfig 2> /dev/null", "r");
  if (!f)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_USER | GNUNET_GE_ADMIN |
                                   GNUNET_GE_BULK | GNUNET_GE_WARNING,
                                   "popen", "ifconfig");
      return;
    }

  while (1)
    {
      int i = 0;
      int c = fgetc (f);

      if (c == EOF)
        break;

      dst = entry;

      /* Read interface name until the first space (or colon under OS X) */
      while (c != EOF && c != '\n' &&
#ifdef OSX
             c != ':'
#else
             c != ' '
#endif
             && i < 10)
        {
          *dst++ = c;
          i++;
          c = fgetc (f);
        }
      *dst = 0;

      if ((entry[0] != '\0') &&
          (GNUNET_OK !=
           proc (entry, strcmp (entry, GNUNET_DEFAULT_INTERFACE) == 0, cls)))
        break;

      while ((c != '\n') && (c != EOF))
        c = fgetc (f);
    }
  pclose (f);
#endif
}

/**
 * @brief Set maximum number of open file descriptors
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_set_fd_limit (struct GNUNET_GE_Context *ectx, int n)
{
  if (n == 0)
    return GNUNET_OK;
#if HAVE_SETRLIMIT
  struct rlimit rlim;
  int ret;

  rlim.rlim_cur = n;
  rlim.rlim_max = n;
  ret = setrlimit (RLIMIT_NOFILE, &rlim);
  if (ret != 0)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_INFO | GNUNET_GE_USER |
                              GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                              "setrlimit");
      return GNUNET_SYSERR;
    }
#else
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_ADMIN,
                 _("Setting open descriptor limit not supported.\n"));
#endif
  return GNUNET_OK;
}

/**
 * @brief Checks if we can start GNUnet automatically
 * @return GNUNET_YES if yes, GNUNET_NO otherwise
 */
static int
isOSAutostartCapable ()
{
#ifdef LINUX
  if (ACCESS ("/usr/sbin/update-rc.d", X_OK) == 0)
    {
      /* Debian */
      if (ACCESS ("/etc/init.d/", W_OK) == 0)
        return GNUNET_YES;
    }
  /* Gentoo */
  else if (ACCESS ("/sbin/rc-update", X_OK) == 0)
    {
      if (ACCESS ("/etc/init.d/", W_OK) == 0)
        return GNUNET_YES;
    }
  return GNUNET_NO;
#else
#ifdef WINDOWS
  return IsWinNT ()? GNUNET_YES : GNUNET_NO;
#else
  return GNUNET_NO;
#endif
#endif
}

/**
 * @brief Make "application" start automatically
 *
 * @param testCapability GNUNET_YES to merely probe if the OS has this
 *        functionality (in that case, no actual operation is
 *        performed).  GNUNET_SYSERR is returned if
 *        a) autostart is not supported,
 *        b) the application does not seem to exist
 *        c) the user or group do not exist
 *        d) the user has insufficient permissions for
 *           changing autostart
 *        e) doAutoStart is GNUNET_NO, but autostart is already
 *           disabled
 *        f) doAutoStart is GNUNET_YES, but autostart is already
 *           enabled
 * @param doAutoStart GNUNET_YES to enable autostart of the
 *        application, GNUNET_NO to disable it
 * @param servicename name of the service as displayed by the OS
 * @param application path to service binary
 * @param username name of the user account to use
 * @param groupname name of the group to use
 * @returns GNUNET_YES on success, GNUNET_NO if unsupported, GNUNET_SYSERR on failure or one of
 *          these error codes:
 *  Windows
 *    2 SCM could not be opened
 *    3 service could not be created/deleted
 *    4 permissions could not be granted
 *    5 registry could not be accessed
 *    6 service could not be accessed
 *  Unix
 *    2 startup script could not be opened
 */
int
GNUNET_configure_autostart (struct GNUNET_GE_Context *ectx,
                            int testCapability,
                            int doAutoStart,
                            const char *servicename,
                            const char *application,
                            const char *username, const char *groupname)
{
  if (testCapability)
    {
      /* TODO: check that user/group/application
         exist! */
      return isOSAutostartCapable ();
    }
#ifdef WINDOWS
  if (doAutoStart)
    {
      if (IsWinNT ())
        {
          char *err = NULL;
          DWORD dwErr = 0;

          if (username && !strlen (username))
            username = NULL;

          /* Install service */
          switch (InstallAsService (servicename, application, username))
            {
            case 0:
              break;
            case 1:
              return GNUNET_NO;
            case 2:
              return 2;
            case 3:
              if (GetLastError () != ERROR_SERVICE_EXISTS)
                return 3;
              break;
            default:
              return GNUNET_SYSERR;
            }

          /* Grant permissions to the GNUnet directory */
          if ((!err || dwErr == ERROR_SERVICE_EXISTS) && username)
            {
              char szHome[_MAX_PATH + 1];

              plibc_conv_to_win_path ("/", szHome);

              if (!AddPathAccessRights (szHome, username, GENERIC_ALL))
                return 4;
            }
        }
      else
        {
          char szPath[_MAX_PATH + 1];
          HKEY hKey;

          plibc_conv_to_win_path (application, szPath);

          if (RegOpenKeyEx (HKEY_LOCAL_MACHINE,
                            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            0, KEY_EXECUTE, &hKey) == ERROR_SUCCESS)
            {
              if (RegSetValueEx (hKey,
                                 servicename,
                                 0, REG_SZ, szPath,
                                 strlen (szPath)) != ERROR_SUCCESS)
                return 5;

              RegCloseKey (hKey);
            }
          else
            return 5;
        }
    }
  else
    {
      if (IsWinNT ())
        {
          switch (UninstallService (servicename))
            {
            case 0:
              break;
            case 1:
              return GNUNET_NO;
            case 2:
              return 2;
            case 3:
              return 6;
            case 4:
              return 3;
            default:
              return GNUNET_SYSERR;
            }
        }
      else
        {
          HKEY hKey;

          if (RegOpenKeyEx (HKEY_LOCAL_MACHINE,
                            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
            {
              RegDeleteValue (hKey, servicename);
              RegCloseKey (hKey);
            }
          else
            return 5;
        }
    }

  return GNUNET_YES;
#else
  struct stat buf;
  int ret;
  int i;
  char *initscript;

  i = strlen (application) - 1;
  if (i <= 0)
    return GNUNET_SYSERR;
  while ((i > 0) && (application[i] != DIR_SEPARATOR))
    i--;

  initscript = GNUNET_malloc (strlen (&application[i]) + 13);
  strcpy (initscript, "/etc/init.d/");
  strcat (initscript, &application[i]);

  /* Unix */
  if ((ACCESS ("/usr/sbin/update-rc.d", X_OK) != 0))
    {
      if ((ACCESS ("/sbin/rc-update", X_OK) != 0))
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_USER |
                                       GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                                       "access", "/usr/sbin/update-rc.d");
          GNUNET_free (initscript);
          return GNUNET_SYSERR;
        }
    }

  /* Debian */
  if (doAutoStart)
    {
      if (ACCESS (application, X_OK) != 0)
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_USER |
                                       GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                                       "access", application);
        }

      if (STAT (initscript, &buf) == -1)
        {
          /* create init file */
          FILE *f = FOPEN (initscript, "w");
          if (f == NULL)
            {
              GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                           GNUNET_GE_ERROR | GNUNET_GE_USER |
                                           GNUNET_GE_ADMIN |
                                           GNUNET_GE_IMMEDIATE, "fopen",
                                           "/etc/init.d/gnunetd");
              GNUNET_free (initscript);
              return 2;
            }

          fprintf (f,
                   "#!/bin/sh\n"
                   "#\n"
                   "# Automatically created by %s\n"
                   "#\n"
                   "\n"
                   "PIDFILE=/var/run/gnunetd/%s.pid\n"
                   "APPNAME=%s\n"
                   "\n"
                   "case \"$1\" in\n"
                   "  start)\n"
                   "  	echo -n \"Starting $APPNAME: \"\n"
                   "  	%s\n && echo ok || echo failed\n"
                   "  	;;\n"
                   "  stop)\n"
                   "  	echo -n \"Stopping $APPNAME: \"\n"
                   "  	kill `cat $PIDFILE`\n && echo ok || echo failed\n"
                   "  	;;\n"
                   "  reload)\n"
                   "  	echo -n \"Reloading $APPNAME: \"\n"
                   "  	kill -HUP `cat $PIDFILE`\n && echo ok || echo failed\n"
                   "  	;;\n"
                   "  restart|force-reload)\n"
                   "  	echo \"Restarting $APPNAME...\"\n"
                   "  	$0 stop\n"
                   "  	sleep 1\n"
                   "  	$0 start\n"
                   "  	;;\n"
                   "  *)\n"
                   "  	echo \"Usage: %s {start|stop|reload|restart|force-reload}\" >&2\n"
                   "  	exit 1\n"
                   "  	;;\n"
                   "\n"
                   "esac\n"
                   "exit 0\n",
                   "gnunet-setup",
                   application, servicename, application, initscript);
          fclose (f);
          if (0 != CHMOD (initscript,
                          S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH))
            {
              GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                           GNUNET_GE_WARNING | GNUNET_GE_USER
                                           | GNUNET_GE_ADMIN |
                                           GNUNET_GE_IMMEDIATE, "chmod",
                                           initscript);
              GNUNET_free (initscript);
              return GNUNET_SYSERR;
            }
        }
      if (STAT (initscript, &buf) != -1)
        {
          errno = 0;
          if (ACCESS ("/usr/sbin/update-rc.d", W_OK) == 0)
            {
              ret = system ("/usr/sbin/update-rc.d gnunetd defaults");
              if (ret != 0)
                {
                  if (errno != 0)
                    {
                      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                                   GNUNET_GE_WARNING |
                                                   GNUNET_GE_USER |
                                                   GNUNET_GE_ADMIN |
                                                   GNUNET_GE_IMMEDIATE,
                                                   "system",
                                                   "/usr/sbin/update-rc.d");
                    }
                  else
                    {
                      GNUNET_GE_LOG (ectx,
                                     GNUNET_GE_WARNING | GNUNET_GE_USER |
                                     GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                                     _
                                     ("Command `%s' failed with error code %u\n"),
                                     "/usr/sbin/update-rc.d gnunetd defaults",
                                     WEXITSTATUS (ret));
                    }
                  GNUNET_free (initscript);
                  return GNUNET_SYSERR;
                }
            }
          else if (ACCESS ("/sbin/rc-update", W_OK) == 0)
            {
              ret = system ("/sbin/rc-update add gnunetd default");
              if (ret != 0)
                {
                  if (errno != 0)
                    {
                      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                                   GNUNET_GE_WARNING |
                                                   GNUNET_GE_USER |
                                                   GNUNET_GE_ADMIN |
                                                   GNUNET_GE_IMMEDIATE,
                                                   "system",
                                                   "/sbin/rc-update");
                    }
                  else
                    {
                      GNUNET_GE_LOG (ectx,
                                     GNUNET_GE_WARNING | GNUNET_GE_USER |
                                     GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                                     _
                                     ("Command `%s' failed with error code %u\n"),
                                     "/sbin/rc-update add gnunetd default",
                                     WEXITSTATUS (ret));
                    }
                  GNUNET_free (initscript);
                  return GNUNET_SYSERR;
                }
            }
        }
      GNUNET_free (initscript);
      return GNUNET_YES;
    }
  else
    {                           /* REMOVE autostart */
      if ((UNLINK (initscript) == -1) && (errno != ENOENT))
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_WARNING | GNUNET_GE_USER |
                                       GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE,
                                       "unlink", initscript);
          GNUNET_free (initscript);
          return GNUNET_SYSERR;
        }
      errno = 0;
      if (ACCESS ("/usr/sbin/update-rc.d", W_OK) == 0)
        {
          ret = system ("/usr/sbin/update-rc.d gnunetd remove");
          if (ret != 0)
            {
              GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                           GNUNET_GE_WARNING | GNUNET_GE_USER
                                           | GNUNET_GE_ADMIN |
                                           GNUNET_GE_IMMEDIATE, "system",
                                           "/usr/sbin/update-rc.d");
              GNUNET_free (initscript);
              return GNUNET_SYSERR;
            }
        }
      else if (ACCESS ("/sbin/rc-update", W_OK) == 0)
        {
          ret = system ("/sbin/rc-update del gnunetd");
          if (ret != 0)
            {
              GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                           GNUNET_GE_WARNING | GNUNET_GE_USER
                                           | GNUNET_GE_ADMIN |
                                           GNUNET_GE_IMMEDIATE, "system",
                                           "/sbin/rc-update");
              GNUNET_free (initscript);
              return GNUNET_SYSERR;
            }
        }
      GNUNET_free (initscript);
      return GNUNET_YES;
    }
  GNUNET_free (initscript);
#endif
  return GNUNET_SYSERR;
}


/* end of osconfig.c */
