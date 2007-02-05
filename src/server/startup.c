/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 *
 * Helper methods for the startup of gnunetd:
 * - PID file handling
 *
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
void shutdown_gnunetd(struct GC_Configuration * cfg, 
		      int sig) {
#ifdef MINGW
  if (!cfg || GC_get_configuration_value_yesno(cfg, 
					       "GNUNETD", 
					       "WINSERVICE", 
					       NO) == YES) {
    /* If GNUnet runs as service, only the
       Service Control Manager is allowed
       to kill us. */
    if (sig != SERVICE_CONTROL_STOP)
      {
	SERVICE_STATUS theStat;
	
	/* Init proper shutdown through the SCM */
	if (GNControlService(hService, SERVICE_CONTROL_STOP, &theStat))
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
    GNSetServiceStatus(hService, &theServiceStatus);
  }
#endif

  GNUNET_SHUTDOWN_INITIATE();
}

#ifdef MINGW
/**
 * This function is called from the Windows Service Control Manager
 * when a service has to shutdown
 */
static void WINAPI ServiceCtrlHandler(DWORD dwOpcode) {
  if (dwOpcode == SERVICE_CONTROL_STOP)
    shutdown_gnunetd(NULL, dwOpcode);
}

/**
 * called by gnunetd.c::ServiceMain()
 */
void win_service_main(void (*gnunet_main)()) {
  memset(&theServiceStatus, 0, sizeof(theServiceStatus));
  theServiceStatus.dwServiceType = SERVICE_WIN32;
  theServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
  theServiceStatus.dwCurrentState = SERVICE_RUNNING;

  hService = GNRegisterServiceCtrlHandler("GNUnet", ServiceCtrlHandler);
  if (! hService)
    return;

  GNSetServiceStatus(hService, &theServiceStatus);

  gnunet_main();

  theServiceStatus.dwCurrentState = SERVICE_STOPPED;
  GNSetServiceStatus(hService, &theServiceStatus);
}
#endif


int changeUser(struct GE_Context * ectx,
	       struct GC_Configuration * cfg) {
  char * user;

  user = NULL;
  if (0 == GC_get_configuration_value_string(cfg,
					     "GNUNETD",
					     "USER",
					     "",
					     &user) && strlen(user)) {
    if (OK != os_change_user(ectx,
			     user)) {
      FREE(user);
      return SYSERR;
    }
  }
  FREE(user);
  return OK;
}

int setFdLimit(struct GE_Context * ectx,
               struct GC_Configuration * cfg) {
  unsigned long long limit;

  limit = 0;
  if (0 == GC_get_configuration_value_number(cfg,
					     "GNUNETD",
					     "FDLIMIT",
					     0,
					     65536,
					     1024,
					     &limit)) {
    if (OK != os_set_fd_limit(ectx,
			      (int)limit)) {
      return SYSERR;
    }
  }
  return OK;
}

/**
 * @brief Cap datastore limit to the filesystem's capabilities
 * @notice FAT does not support files larger than 2/4 GB
 * @param ectx error handler
 * @param cfg configuration manager
 */
void capFSQuotaSize(struct GE_Context * ectx,
               struct GC_Configuration * cfg)
{
#ifdef WINDOWS
  unsigned long long quota, cap;
  char *afsdir, fs[MAX_PATH + 1];
  DWORD flags;
  
  if (-1 == GC_get_configuration_value_number(cfg,
                 "FS",
                 "QUOTA",
                 0,
                 ((unsigned long long)-1)/1024/1024,
                 1024,
                 &quota))
    return;

  GC_get_configuration_value_filename(cfg,
              "FS",
              "DIR",
              VAR_DAEMON_DIRECTORY "/data/fs/",
              &afsdir);
  GE_ASSERT(ectx, strlen(afsdir) > 2);
  
  /* get root directory */
  afsdir[3] = '\0';

  if (!GetVolumeInformation(afsdir,
               NULL,
               0,
               NULL,
               NULL,
               &flags,
               fs,
               _MAX_PATH + 1)) {
    GE_LOG(ectx,
      GE_ERROR | GE_ADMIN | GE_USER | GE_IMMEDIATE,
      _("Unable to obtain filesystem information for `%s': %u\n"),
      afsdir,
      GetLastError());
      
    return;
  }
  
  if (strncasecmp(fs, "NTFS", 4) == 0)
    cap = 0;
  else if (strcasecmp(fs, "FAT32") == 0)
    cap = 3000;
  else if (strcasecmp(fs, "FAT16") == 0)
    cap = 1500;
  else {
    /* unknown FS */
    GE_LOG(ectx,
      GE_ERROR | GE_ADMIN | GE_USER | GE_IMMEDIATE,
      _("Filesystem `%s' of partition `%s' is unknown. Please "
        "contact gnunet-developers@gnu.org!"),
      fs,
      afsdir);
    
    if (!(flags & FILE_PERSISTENT_ACLS))
      cap = 1500;
    else
      cap = 0;
  }
  
  if ((cap != 0) && (cap < quota)) {
    GE_LOG(ectx,
      GE_WARNING | GE_ADMIN | GE_USER | GE_IMMEDIATE,
      _("Limiting datastore size to %llu GB, because the `%s' filesystem does "
        "not support larger files. Please consider storing the database on "
        "a NTFS partition!\n"),
      cap / 1000,
      fs);
    
    GC_set_configuration_value_number(cfg,
               ectx,
               "FS",
               "QUOTA",
               cap);
  }
#endif
}

static char * getPIDFile(struct GC_Configuration * cfg) {
  char * pif;

  if (0 != GC_get_configuration_value_filename(cfg,
					       "GNUNETD",
					       "PIDFILE",
					       VAR_DAEMON_DIRECTORY "/gnunetd.pid",
					       &pif))
    return NULL;
  return pif;
}

/**
 * Write our process ID to the pid file.
 */
void writePIDFile(struct GE_Context * ectx,
		  struct GC_Configuration * cfg) {
  FILE * pidfd;
  char * pif;

  pif = getPIDFile(cfg);
  if (pif == NULL)
    return; /* no PID file */
  pidfd = FOPEN(pif, "w");
  if (pidfd == NULL) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_ADMIN | GE_BULK,
			 "fopen",
			 pif);
    FREE(pif);
    return;
  }
  if (0 > FPRINTF(pidfd,
		  "%u",
		  (unsigned int) getpid()))
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_ADMIN | GE_BULK,
			 "fprintf",
			 pif);
  if (0 != fclose(pidfd))
    GE_LOG_STRERROR_FILE(ectx,
			 GE_WARNING | GE_ADMIN | GE_BULK,
			 "fclose",
			 pif);
  FREE(pif);
}

void deletePIDFile(struct GE_Context * ectx,
		   struct GC_Configuration * cfg) {
  char * pif = getPIDFile(cfg);
  if (pif == NULL)
    return; /* no PID file */
  if (YES == disk_file_test(ectx,
			    pif)) {
    if (0 != UNLINK(pif))
      GE_LOG_STRERROR_FILE(ectx,
			   GE_WARNING | GE_ADMIN | GE_BULK,
			   "unlink",
			   pif);
  }
  FREE(pif);
}

/* end of startup.c */
