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
 * @file src/util/daemon.c
 * @brief code for client-gnunetd interaction (start, stop, waitpid, check running)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"


/**
 * Checks if gnunetd is running
 *
 * Uses CS_PROTO_traffic_COUNT query to determine if gnunetd is
 * running.
 *
 * @return OK if gnunetd is running, SYSERR if not
 */
int checkGNUnetDaemonRunning() {
  GNUNET_TCP_SOCKET * sock;
  CS_MESSAGE_HEADER csHdr;
  int ret;

  sock = getClientSocket();
  if(sock == NULL) {
    BREAK();
    return SYSERR;
  }

  csHdr.size
    = htons(sizeof(CS_MESSAGE_HEADER));
  csHdr.type
    = htons(CS_PROTO_traffic_COUNT);
  if (SYSERR == writeToSocket(sock,
                              &csHdr)) {
    releaseClientSocket(sock);
    return SYSERR;
  }
  if (SYSERR == readTCPResult(sock,
  			      &ret)) {
    releaseClientSocket(sock);
    return SYSERR;
  }
  releaseClientSocket(sock);

  return OK;
}


#if LINUX || OSX || SOLARIS || SOMEBSD
/**
 * Fork a gnunetd process
 *
 * @param daemonize YES if gnunetd should be daemonized
 * @return pid_t of gnunetd if NOT daemonized, 0 if
 *  daemonized sucessfully, -1 on error
 */
static pid_t launchWithExec(int daemonize) {
  pid_t pid;

  pid = fork();
  if (pid == 0) {
    char * args[5];
    char * path;
    char * cp;

    path = NULL;
    cp = getConfigurationString("MAIN",
				"ARGV[0]");
    if (cp != NULL) {
      int i = strlen(cp);
      while ( (i >= 0) &&
	      (cp[i] != DIR_SEPARATOR) )
	i--;
      if ( i != -1 ) {
	cp[i+1] = '\0';
	path = MALLOC(i+2+strlen("gnunetd"));
	strcpy(path, cp);
	strcat(path, "gnunetd");
	if (ACCESS(path, X_OK) == 0) {
	  args[0] = path;
	} else {
	  FREE(path);
	  path = NULL;
	  args[0] = "gnunetd";
	}
	FREE(cp);
      } else {
	args[0] = "gnunetd";
      }
    }
    cp = getConfigurationString("GNUNET",
				"GNUNETD-CONFIG");
    if (cp != NULL) {
      args[1] = "-c";
      args[2] = cp;
      if (NO == daemonize) {
	args[3] = "-d";
	args[4] = NULL;
      } else
	args[3] = NULL;
    } else {
      if (NO == daemonize) {
	args[1] = "-d";
	args[2] = NULL;
      } else
	args[1] = NULL;
    }
    errno = 0;
    nice(10); /* return value is not well-defined */
    if (errno != 0)
      LOG_STRERROR(LOG_WARNING, "nice");
    if (path != NULL)
      execv(path,
	    args);
    else
      execvp("gnunetd",
	     args);
    LOG_STRERROR(LOG_FAILURE, "exec");
    LOG(LOG_FAILURE,
	_("Attempted path to `%s' was `%s'.\n"),
	"gnunetd",
	(path == NULL) ? "gnunetd" : path);
    FREENONNULL(path); /* yeah, right, like we're likely to get
			  here... */
    FREENONNULL(args[1]);
    _exit(-1);
  } else if (daemonize) {
    pid_t ret;
    int status;

    ret = waitpid(pid, &status, 0);
    if (ret == -1) {
      LOG_STRERROR(LOG_ERROR, "waitpid");
      return SYSERR;
    }
    if ( (WIFEXITED(status) &&
	  (0 != WEXITSTATUS(status)) ) ) {
      return SYSERR;
    }
#ifdef WCOREDUMP
    if (WCOREDUMP(status)) {
      return SYSERR;
    }
#endif
    if (WIFSIGNALED(status) ||
	WTERMSIG(status) ) {
      return SYSERR;
    }
    return 0;
  }
  return pid;
}
#endif

/**
 * Start gnunetd process
 *
 * @param daemonize YES if gnunetd should be daemonized
 * @return pid_t of gnunetd if NOT daemonized, 0 if
 *  daemonized sucessfully, -1 on error
 */
int startGNUnetDaemon(int daemonize) {
#if LINUX || OSX || SOLARIS || SOMEBSD
  return launchWithExec(daemonize);
#elif MINGW
  char szCall[_MAX_PATH + 1], szWd[_MAX_PATH + 1], szCWd[_MAX_PATH + 1];
  char *args[1], *cp = NULL;
  int pid;
  int idx = 0;

  plibc_conv_to_win_path("/bin/gnunetd.exe", szCall);
  plibc_conv_to_win_path("/bin", szWd);
  _getcwd(szCWd, _MAX_PATH);

  chdir(szWd);

  if (daemonize == NO) {
  	args[0] = "-d";
 		idx = 1;

    cp = getConfigurationString("GNUNET",
				"GNUNETD-CONFIG");
		if (cp) {
			args[1] = "-c";
			args[2] = cp;
			idx=3;
		}		
  }

  args[idx] = NULL;
  pid = spawnvp(_P_NOWAIT, szCall, (const char *const *) args);
  chdir(szCWd);

  FREENONNULL(cp);

  return (daemonize == NO) ? pid : 0;
#else
  /* any system out there that does not support THIS!? */
  system("gnunetd"); /* we may not have nice,
			so let's be minimalistic here. */
  return 0;
#endif
}


/**
 * Stop gnunetd
 *
 * Note that returning an error does NOT mean that
 * gnunetd will continue to run (it may have been
 * shutdown by something else in the meantime or
 * crashed).  Call checkDaemonRunning() frequently
 * to check the status of gnunetd.
 *
 * Furthermore, note that this WILL potentially kill
 * gnunetd processes on remote machines that cannot
 * be restarted with startGNUnetDaemon!
 *
 * This function does NOT need the PID and will also
 * kill daemonized gnunetd's.
 *
 * @return OK successfully stopped, SYSERR: error
 */
int stopGNUnetDaemon() {
  GNUNET_TCP_SOCKET * sock;
  CS_MESSAGE_HEADER csHdr;
  int ret;

  sock = getClientSocket();
  if (sock == NULL)
    return SYSERR;
  csHdr.size
    = htons(sizeof(CS_MESSAGE_HEADER));
  csHdr.type
    = htons(CS_PROTO_SHUTDOWN_REQUEST);
  if (SYSERR == writeToSocket(sock,
			      &csHdr)) {
    releaseClientSocket(sock);
    return SYSERR;
  }
  if (SYSERR == readTCPResult(sock,
			      &ret)) {
    releaseClientSocket(sock);
    return SYSERR;
  }
  releaseClientSocket(sock);
  return ret;
}

/**
 * Wait until the gnunet daemon is
 * running.
 *
 * @param timeout how long to wait at most
 * @return OK if gnunetd is now running
 */
int waitForGNUnetDaemonRunning(cron_t timeout) {
  timeout += cronTime(NULL);
  while (OK != checkGNUnetDaemonRunning()) {
    gnunet_util_sleep(100 * cronMILLIS);
    if (timeout < cronTime(NULL))
      return checkGNUnetDaemonRunning();
  }
  return OK;
}

/**
 * Wait until the gnunet daemon (or any other CHILD process for that
 * matter) with the given PID has terminated.  Assumes that
 * the daemon was started with startGNUnetDaemon in no-daemonize mode.
 * On arbitrary PIDs, this function may fail unexpectedly.
 *
 * @return YES if gnunetd shutdown with
 *  return value 0, SYSERR if waitpid
 *  failed, NO if gnunetd shutdown with
 *  some error
 */
int waitForGNUnetDaemonTermination(int pid) {
  pid_t p;
  int status;

  p = pid;
  if (p != WAITPID(p, &status, 0)) {
    LOG_STRERROR(LOG_ERROR, "waitpid");
    return SYSERR;
  }
  if (WEXITSTATUS(status) == 0)
    return YES;
  else
    return NO;
}

int termProcess(int pid) {
#ifndef MINGW
	return kill(pid, SIGTERM) == 0;
#else
	int ret;
	DWORD dwExitCode = 0;
	
	HANDLE hProc = OpenProcess(1, 0, pid);
	GenerateConsoleCtrlEvent(CTRL_C_EVENT, pid);
	
	WaitForSingleObject(hProc, 3000);
	
	GetExitCodeProcess(hProc, &dwExitCode);
	if(dwExitCode == STILL_ACTIVE) {
		ret = TerminateProcess(hProc, 0);
	}
	else
		ret = 1;

	CloseHandle(hProc);
		
	return ret;
#endif
}

/* end of daemon.c */
