/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * - install signal handling
 * - system checks on startup
 * - PID file handling
 * - detaching from terminal
 * - command line parsing
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"

#include "tcpserver.h"
#include "core.h"

extern int debug_flag, win_service;
#ifdef MINGW
extern SERVICE_STATUS theServiceStatus;
extern SERVICE_STATUS_HANDLE hService;
#endif

/**
 * This flag is set if gnunetd is shutting down.
 */
static Semaphore * doShutdown;

/* ************* SIGNAL HANDLING *********** */

/**
 * Cron job that triggers re-reading of the configuration.
 */
static void reread_config_helper(void * unused) {
  LOG(LOG_DEBUG,
      "Re-reading configuration file.\n");
  readConfiguration();
  triggerGlobalConfigurationRefresh();
  LOG(LOG_DEBUG,
      "New configuration active.\n");
}

/**
 * Signal handler for SIGHUP.
 * Re-reads the configuration file.
 */
static void reread_config(int signum) {
  addCronJob(&reread_config_helper,
	     1 * cronSECONDS,
	     0,
	     NULL);
}

/**
 * Try a propper shutdown of gnunetd.
 */
static void shutdown_gnunetd(int signum) {

#ifdef MINGW
if (win_service)
{
  /* If GNUnet runs as service, only the
     Service Control Manager is allowed
     to kill us. */
  if (signum != SERVICE_CONTROL_STOP)
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

  SEMAPHORE_UP(doShutdown);
}

static int shutdownHandler(ClientHandle client,
                           const CS_MESSAGE_HEADER * msg) {
  int ret;

  if (ntohs(msg->size) != sizeof(CS_MESSAGE_HEADER)) {
    LOG(LOG_WARNING,
        _("The `%s' request received from client is malformed.\n"),
	"shutdown");
    return SYSERR;
  }
  LOG(LOG_INFO,
      "shutdown request accepted from client\n");

  if (SYSERR == unregisterCSHandler(CS_PROTO_SHUTDOWN_REQUEST,
                                    &shutdownHandler))
    GNUNET_ASSERT(0);
  ret = sendTCPResultToClient(client,
			      OK);
  shutdown_gnunetd(0);
  return ret;
}

#ifdef MINGW
BOOL WINAPI win_shutdown_gnunetd(DWORD dwCtrlType)
{
  switch(dwCtrlType)
  {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
    case CTRL_LOGOFF_EVENT:
    case SERVICE_CONTROL_STOP:
      shutdown_gnunetd(dwCtrlType);
  }

  return TRUE;
}
#endif

/**
 * Initialize signal handlers
 */
void initSignalHandlers() {
#ifndef MINGW
  struct sigaction sig;
  struct sigaction oldsig;
#endif

  doShutdown = SEMAPHORE_NEW(0);

#ifndef MINGW
  sig.sa_handler = &shutdown_gnunetd;
  sigemptyset(&sig.sa_mask);
#ifdef SA_INTERRUPT
  sig.sa_flags = SA_INTERRUPT; /* SunOS */
#else
  sig.sa_flags = SA_RESTART;
#endif
  sigaction(SIGINT,  &sig, &oldsig);
  sigaction(SIGTERM, &sig, &oldsig);
  sigaction(SIGQUIT, &sig, &oldsig);

  sig.sa_handler = &reread_config;
  sigaction(SIGHUP, &sig, &oldsig);
#else
  SetConsoleCtrlHandler(&win_shutdown_gnunetd, TRUE);
#endif

  if (SYSERR == registerCSHandler(CS_PROTO_SHUTDOWN_REQUEST,
                                  &shutdownHandler))
    GNUNET_ASSERT(0);
}

void doneSignalHandlers() {
#ifndef MINGW
  struct sigaction sig;
  struct sigaction oldsig;

  sig.sa_handler = SIG_DFL;
  sigemptyset(&sig.sa_mask);
#ifdef SA_INTERRUPT
  sig.sa_flags = SA_INTERRUPT; /* SunOS */
#else
  sig.sa_flags = SA_RESTART;
#endif
  sigaction(SIGINT,  &sig, &oldsig);
  sigaction(SIGTERM, &sig, &oldsig);
  sigaction(SIGQUIT, &sig, &oldsig);
#else
  SetConsoleCtrlHandler(&win_shutdown_gnunetd, TRUE);
#endif
  SEMAPHORE_FREE(doShutdown);
}

/**
 * Cron job to timeout gnunetd.
 */
static void semaphore_up(void * sem) {
  SEMAPHORE_UP((Semaphore*)sem);
}

void waitForSignalHandler() {
  int valgrind;

  /* mechanism to stop gnunetd after a certain
     time without a signal -- to debug with valgrind*/
  valgrind = getConfigurationInt("GNUNETD",
				 "VALGRIND");
  if (valgrind > 0)
    addCronJob(&semaphore_up,
	       valgrind * cronSECONDS,
	       0,
	       doShutdown);
#if 0
  /* If Valgrind is used to debug memory leaks, some sort of mechanism
     is needed to make gnunetd exit without using any signal -IW*/
  FILE *fp;

  while(1) {
    fp=FOPEN("/tmp/quitgn", "r");
    if(fp) {
      fprintf(stderr, "QUITTING...\n");
      fclose(fp);
      return;
    }
    sleep(1);
  }
#endif
  SEMAPHORE_DOWN(doShutdown);
  if (valgrind > 0)
    delCronJob(&semaphore_up,
	       0,
	       doShutdown);

}

/* *********** SYSTEM CHECKS ON STARTUP ************ */

/**
 * Check if the compiler did a decent job aligning the structs...
 */
void checkCompiler() {
  GNUNET_ASSERT(sizeof(P2P_hello_MESSAGE) == 600);
  GNUNET_ASSERT(sizeof(P2P_MESSAGE_HEADER) == 4);
}

/* *********** PID file handling *************** */

static char * getPIDFile() {
  return getFileName("GNUNETD",
		     "PIDFILE",
		     _("You must specify a name for the PID file in section"
		       " `%s' under `%s'.\n"));
}

/**
 * Write our process ID to the pid file.
 */
void writePIDFile() {
  FILE * pidfd;
  char * pif;

  pif = getPIDFile();
  pidfd = FOPEN(pif, "w");
  if (pidfd == NULL) {
    LOG(LOG_WARNING,
	_("Could not write PID to file `%s': %s.\n"),
	pif,
	STRERROR(errno));
  } else {
    fprintf(pidfd, "%u", (unsigned int) getpid());
    fclose(pidfd);
  }
  FREE(pif);
}

void deletePIDFile() {
  char * pif = getPIDFile();
  UNLINK(pif);
  FREE(pif);
}

/* ************** DETACHING FROM TERMAINAL ************** */

/**
 * Fork and start a new session to go into the background
 * in the way a good deamon should.
 *
 * @param filedes pointer to an array of 2 file descriptors
 *        to complete the detachment protocol (handshake)
 */
void detachFromTerminal(int * filedes) {
#ifndef MINGW
  pid_t pid;
  int nullfd;
#endif

  /* Don't hold the wrong FS mounted */
  if (CHDIR("/") < 0) {
    perror("chdir");
    exit(1);
  }

#ifndef MINGW
  PIPE(filedes);
  pid = fork();
  if (pid < 0) {
    perror("fork");
    exit(1);
  }
  if (pid) {  /* Parent */
    int ok;
    char c;

    closefile(filedes[1]); /* we only read */
    ok = SYSERR;
    while (0 < READ(filedes[0], &c, sizeof(char))) {
      if (c == '.')
	ok = OK;
    }
    fflush(stdout);
    if (ok == OK)
      exit(0);
    else
      exit(1); /* child reported error */
  }
  closefile(filedes[0]); /* we only write */
  nullfd = fileopen("/dev/null",
		O_CREAT | O_RDWR | O_APPEND);
  if (nullfd < 0) {
    perror("/dev/null");
    exit(1);
  }
  /* child - close fds linking to invoking terminal, but
   * close usual incoming fds, but redirect them somewhere
   * useful so the fds don't get reallocated elsewhere.
   */
  if (dup2(nullfd,0) < 0 ||
      dup2(nullfd,1) < 0 ||
      dup2(nullfd,2) < 0) {
    perror("dup2"); /* Should never happen */
    exit(1);
  }
  pid = setsid(); /* Detach from controlling terminal */
#else
 FreeConsole();
#endif
}

void detachFromTerminalComplete(int * filedes) {
#ifndef MINGW
  char c = '.';
  WRITE(filedes[1], &c, sizeof(char)); /* signal success */
  closefile(filedes[1]);
#endif
}

/* ****************** COMMAND LINE PARSING ********************* */

static void printDot(void * unused) {
  LOG(LOG_DEBUG, ".");
}

/**
 * Print a list of the options we offer.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    { 'd', "debug", NULL,
      gettext_noop("run in debug mode; gnunetd will "
		   "not daemonize and error messages will "
		   "be written to stderr instead of a logfile") },
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'u', "user", "LOGIN",
      gettext_noop("run as user LOGIN") },
    HELP_VERSION,
    HELP_END,
  };
  formatHelp("gnunetd [OPTIONS]",
	     _("Starts the gnunetd daemon."),
	     help);
}

#ifndef MINGW
/**
 * @brief Change user ID
 */
void changeUser(const char *user) {
  struct passwd * pws;

  pws = getpwnam(user);
  if(pws == NULL) {
    LOG(LOG_WARNING,
        _("User `%s' not known, cannot change UID to it.\n"), user);
    return;
  }
  if((0 != setgid(pws->pw_gid)) ||
     (0 != setegid(pws->pw_gid)) ||
     (0 != setuid(pws->pw_uid)) || (0 != seteuid(pws->pw_uid))) {
    if((0 != setregid(pws->pw_gid, pws->pw_gid)) ||
       (0 != setreuid(pws->pw_uid, pws->pw_uid)))
      LOG(LOG_WARNING,
          _("Cannot change user/group to `%s': %s\n"),
          user, STRERROR(errno));
  }
}
#endif

/**
 * Perform option parsing from the command line.
 */
int parseCommandLine(int argc,
		     char * argv[]) {
  int cont = OK;
  int c;

  /* set the 'magic' code that indicates that
     this process is 'gnunetd' (and not any of
     the tools).  This can be used by code
     that runs in both the tools and in gnunetd
     to distinguish between the two cases. */
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      { "loglevel",1, 0, 'L' },
      { "config",  1, 0, 'c' },
      { "version", 0, 0, 'v' },
      { "help",    0, 0, 'h' },
      { "user",    1, 0, 'u' },
      { "debug",   0, 0, 'd' },
      { "livedot", 0, 0, 'l' },
      { "padding", 1, 0, 'p' },
      { "win-service", 0, 0, '@' },
      { 0,0,0,0 }
    };

    c = GNgetopt_long(argc,
		      argv,
		      "vhdc:u:L:lp:@",
		      long_options,
		      &option_index);

    if (c == -1)
      break;  /* No more flags to process */

    switch(c) {
    case 'p':
      FREENONNULL(setConfigurationString("GNUNETD-EXPERIMENTAL",
					 "PADDING",
					 GNoptarg));
      break;
    case 'l':
      addCronJob(&printDot,
		 1 * cronSECONDS,
		 1 * cronSECONDS,
		 NULL);
      break;
    case 'c':
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    case 'v':
      printf("GNUnet v%s\n",
	     VERSION);
      cont = SYSERR;
      break;
    case 'h':
      printhelp();
      cont = SYSERR;
      break;
    case 'L':
      FREENONNULL(setConfigurationString("GNUNETD",
					 "LOGLEVEL",
					 GNoptarg));
      break;
    case 'd':
      debug_flag = YES;
      FREENONNULL(setConfigurationString("GNUNETD",
					 "LOGFILE",
					 NULL));
      break;
#ifndef MINGW	/* not supported */
    case 'u':
      changeUser(GNoptarg);
      break;
#endif
#ifdef MINGW
    case '@':
      win_service = YES;
      break;
#endif
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      cont = SYSERR;
    } /* end of parsing commandline */
  }
  if (GNoptind < argc) {
    LOG(LOG_WARNING,
	_("Invalid command-line arguments:\n"));
    while (GNoptind < argc) {
      LOG(LOG_WARNING,
	  _("Argument %d: `%s'\n"),
	  GNoptind+1,
	  argv[GNoptind]);
      GNoptind++;
    }
    LOG(LOG_FATAL,
	_("Invalid command-line arguments.\n"));
    return SYSERR;
  }
  return cont;
}

/* end of startup.c */
