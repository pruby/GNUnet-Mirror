/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file server/startup.c
 * @brief insignificant gnunetd helper methods
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"

#include "tcpserver.h"
#include "core.h"
#include "startup.h"

#ifdef MINGW
/**
 * Windows service information
 */
static SERVICE_STATUS theServiceStatus;
static SERVICE_STATUS_HANDLE hService;
#endif

/**
 * Shutdown gnunetd
 * @param cfg configuration, may be NULL if in service mode
 * @param sig signal code that causes shutdown, optional
 */
void
GNUNET_CORE_shutdown (struct GNUNET_GC_Configuration *cfg, int sig)
{
#ifdef MINGW
  if (!cfg || GNUNET_GC_get_configuration_value_yesno (cfg,
                                                       "GNUNETD",
                                                       "WINSERVICE",
                                                       GNUNET_NO) ==
      GNUNET_YES)
    {
      /* If GNUnet runs as service, only the
         Service Control Manager is allowed
         to kill us. */
      if (sig != SERVICE_CONTROL_STOP)
        {
          SERVICE_STATUS theStat;

          /* Init proper shutdown through the SCM */
          if (GNControlService (hService, SERVICE_CONTROL_STOP, &theStat))
            {
              /* Success */

              /* The Service Control Manager will call
                 gnunetd.c::ServiceCtrlHandler(), which calls
                 this function again. We then stop the gnunetd. */
              return;
            }
          /* We weren't able to tell the SCM to stop the service,
             but we don't care.
             Just shut the gnunetd process down. */
        }

      /* Acknowledge the shutdown request */
      theServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
      GNSetServiceStatus (hService, &theServiceStatus);
    }
#endif

  GNUNET_shutdown_initiate ();
}

#ifdef MINGW
/**
 * This function is called from the Windows Service Control Manager
 * when a service has to shutdown
 */
static void WINAPI
ServiceCtrlHandler (DWORD dwOpcode)
{
  if (dwOpcode == SERVICE_CONTROL_STOP)
    GNUNET_CORE_shutdown (NULL, dwOpcode);
}

/**
 * called by gnunetd.c::ServiceMain()
 */
void
GNUNET_CORE_w32_service_main (void (*gnunet_main) ())
{
  memset (&theServiceStatus, 0, sizeof (theServiceStatus));
  theServiceStatus.dwServiceType = SERVICE_WIN32;
  theServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
  theServiceStatus.dwCurrentState = SERVICE_RUNNING;

  hService = GNRegisterServiceCtrlHandler ("GNUnet", ServiceCtrlHandler);
  if (!hService)
    return;

  GNSetServiceStatus (hService, &theServiceStatus);

  gnunet_main ();

  theServiceStatus.dwCurrentState = SERVICE_STOPPED;
  GNSetServiceStatus (hService, &theServiceStatus);
}
#endif


int
GNUNET_CORE_startup_change_user (struct GNUNET_GE_Context *ectx,
                                 struct GNUNET_GC_Configuration *cfg)
{
  char *user;
  char *prio;

  if (0 == GNUNET_GC_get_configuration_value_string (cfg,
                                                     "LOAD",
                                                     "PRIORITY",
                                                     "IDLE", &prio)
      && strlen (prio))
    GNUNET_set_process_priority (ectx, prio);
  GNUNET_free (prio);
  user = NULL;
  if (0 == GNUNET_GC_get_configuration_value_string (cfg,
                                                     "GNUNETD",
                                                     "USER",
                                                     "", &user)
      && strlen (user))
    {
      if (GNUNET_OK != GNUNET_change_user (ectx, user))
        {
          GNUNET_free (user);
          return GNUNET_SYSERR;
        }
    }
  GNUNET_free (user);
  return GNUNET_OK;
}

int
GNUNET_CORE_startup_set_fd_limit (struct GNUNET_GE_Context *ectx,
                                  struct GNUNET_GC_Configuration *cfg)
{
  unsigned long long limit;

  limit = 0;
  if (0 == GNUNET_GC_get_configuration_value_number (cfg,
                                                     "GNUNETD",
                                                     "FDLIMIT",
                                                     0, 65536, 1024, &limit))
    {
      if (GNUNET_OK != GNUNET_set_fd_limit (ectx, (int) limit))
        {
          return GNUNET_SYSERR;
        }
    }
  return GNUNET_OK;
}

/**
 * @brief Cap datastore limit to the filesystem's capabilities
 * @notice FAT does not support files larger than 2/4 GB
 * @param ectx error handler
 * @param cfg configuration manager
 */
void
GNUNET_CORE_startup_cap_fs_quota_size (struct GNUNET_GE_Context *ectx,
                                       struct GNUNET_GC_Configuration *cfg)
{
#ifdef WINDOWS
  unsigned long long quota, cap;
  char *afsdir, fs[MAX_PATH + 1];
  DWORD flags;

  if (-1 == GNUNET_GC_get_configuration_value_number (cfg,
                                                      "FS",
                                                      "QUOTA",
                                                      0,
                                                      ((unsigned long long)
                                                       -1) / 1024 / 1024,
                                                      1024, &quota))
    return;

  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "FS",
                                              "DIR",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY
                                              "/data/fs/", &afsdir);
  GNUNET_GE_ASSERT (ectx, strlen (afsdir) > 2);

  /* get root directory */
  afsdir[3] = '\0';

  if (!GetVolumeInformation (afsdir,
                             NULL, 0, NULL, NULL, &flags, fs, _MAX_PATH + 1))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_IMMEDIATE,
                     _
                     ("Unable to obtain filesystem information for `%s': %u\n"),
                     afsdir, GetLastError ());

      return;
    }

  if (strncasecmp (fs, "NTFS", 4) == 0)
    cap = 0;
  else if (strcasecmp (fs, "FAT32") == 0)
    cap = 3000;
  else if (strcasecmp (fs, "FAT16") == 0)
    cap = 1500;
  else
    {
      /* unknown FS */
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_IMMEDIATE,
                     _("Filesystem `%s' of partition `%s' is unknown. Please "
                       "contact gnunet-developers@gnu.org!"), fs, afsdir);

      if (!(flags & FILE_PERSISTENT_ACLS))
        cap = 1500;
      else
        cap = 0;
    }

  if ((cap != 0) && (cap < quota))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_IMMEDIATE,
                     _
                     ("Limiting datastore size to %llu GB, because the `%s' filesystem does "
                      "not support larger files. Please consider storing the database on "
                      "a NTFS partition!\n"), cap / 1000, fs);

      GNUNET_GC_set_configuration_value_number (cfg, ectx, "FS", "QUOTA",
                                                cap);
    }
#endif
}

static int
checkPermission (struct GNUNET_GE_Context *ectx,
                 struct GNUNET_GC_Configuration *cfg,
                 const char *section,
                 const char *option,
                 const char *def, int is_directory, int mode)
{
  char *fn;
  int i;

  GNUNET_GC_get_configuration_value_filename (cfg, section, option, def, &fn);
  if (is_directory)
    GNUNET_disk_directory_create (ectx, fn);
  else
    GNUNET_disk_directory_create_for_file (ectx, fn);
  if ((0 != ACCESS (fn, F_OK)) && (mode == W_OK))
    {
      /* adjust check to see if directory is writable */
      i = strlen (fn);
      while ((i > 1) && (fn[i] != DIR_SEPARATOR))
        i--;
      fn[i] = '\0';
      mode = X_OK | W_OK;
    }
  if (0 != ACCESS (fn, mode))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_FATAL | GNUNET_GE_USER | GNUNET_GE_ADMIN |
                     GNUNET_GE_IMMEDIATE,
                     _("Insufficient access permissions for `%s': %s\n"), fn,
                     STRERROR (errno));
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fn);
  return GNUNET_OK;
}

#define CHECK(a,b,c,d,e) if (GNUNET_OK != checkPermission(ectx, cfg, a, b, c, d, e)) return GNUNET_SYSERR;

int
GNUNET_CORE_startup_check_permissions (struct GNUNET_GE_Context *ectx,
                                       struct GNUNET_GC_Configuration *cfg)
{
  CHECK ("PATHS", "GNUNETD_HOME", "/var/lib/gnunet", GNUNET_YES, W_OK | X_OK);
  CHECK ("GNUNETD", "LOGFILE", "$GNUNETD_HOME/daemon-logs", GNUNET_NO, W_OK);
  /* these should only be checked if "fs" is actually
     loaded; we clearly should not check everything here
     that just might be used (MYSQL-CONFIG, F2F-FRIENDS),
     OTOH, late messages in the startup sequence are also
     not great.  Would be nice if we could find a way to
     keep things decentralized and still do a nice job
     with reporting errors... */
  CHECK ("FS", "DIR", "$GNUNETD_HOME/data/fs", GNUNET_YES, W_OK | X_OK);
  CHECK ("FS",
         "INDEX-DIRECTORY", "$GNUNETD_HOME/data/shared", GNUNET_YES,
         W_OK | X_OK);
  return GNUNET_OK;
}

/* end of startup.c */
