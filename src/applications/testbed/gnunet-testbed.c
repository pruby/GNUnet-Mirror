/*
     This file is part of GNUnet.
     (C) 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/testbed/gnunet-testbed.c 
 * @brief A Testbed tool for performing distributed experiments
 * @author Ronaldo Alves Ferreira
 * @author Christian Grothoff
 * @author Murali Krishan Ramanathan
 *
 * Todo:
 * - test secure sign-on (and test testbed setup script!)
 * - allow removing of peers (explicitly AND when peer shuts down!)
 *   Problem: what happens to the peer-IDs in that case?
 * - general problem: the way we use tcpio means that any rouge
 *   testbed-gnunetd can stall gnunet-testbed indefinitely!
 * - security: limit "exec" to certain processes
 */

#include "gnunet_util.h"
#include "platform.h"
#include "testbed.h"
#include "socket.h"
#include "commands.h"
#include <signal.h>

#ifndef sighandler_t
typedef void (*sighandler_t)(int);
#endif

#define TESTBED_VERSION		"0.0.5"
#define HELPER                  "==HELPER=="

/* we may want to change SHELL and PORT into values
   obtained from the configuration... */

#define SHELL	(NULL == getenv("BASH") ? "/bin/bash" : getenv("BASH"))

#define PORT getConfigurationInt("GNUNET-TESTBED","PORT")

/* TB_ALIASES should probably be forced to live somewhere
   under ~/.gnunet */
#define TB_ALIASES "/tmp/gnunet-testbed-aliasdefinitions"


/**
 * Name of gnunet-testbed binary.
 */
static char * testbedArg0;


/* ****************** scriptability *************** */

#ifndef MINGW /* FIXME MINGW */



/**
 * Parse the options, set the timeout.
 *
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return OK on error, SYSERR if we should exit 
 */
static int helperParseOptions(int argc, char *argv[]) {
  int c, option_index;
  
  FREENONNULL(setConfigurationString("GNUNETD", 
				     "LOGFILE", 
				     NULL));
  while (1) {
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { 0,0,0,0 }
    };    
    
    option_index = 0;
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:L:", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'v': 
      printf("GNUnet v%s, gnunet-testbed v%s\n",
	     VERSION,
	     TESTBED_VERSION);
      return SYSERR;     
    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	HELP_HELP,
	HELP_LOGLEVEL,	
	HELP_VERSION,
	HELP_END,
      };
      formatHelp("gnunet-testbed ==HELPER== [OPTIONS] [COMMAND]",
		 _("Start GNUnet-testbed helper."),
		 help);
      return SYSERR;
    }      
    default: 
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return -1;
    } /* end of parsing commandline */
  } /* while (1) */
  setConfigurationStringList(&argv[GNoptind],
			     argc - GNoptind);
  return OK;
}


/**
 * This is the main method of the helper-process that
 * is invoked from the bash-process.  Helper encapsulates
 * the command from the shell in a stream, sends it
 * over the socket to the main gnunet-testbed process,
 * retrieves there result and outputs he result back
 * to bash.
 */
static int helper_main(int argc,
		       char * argv[]) {
  int    i, retVal, len, res;
  char  *buf;
  struct sockaddr_in soaddr;
  
  if (SYSERR == initUtil(argc,
			 argv,
			 &helperParseOptions))
    return -1;

  argc = getConfigurationStringList(&argv);  
  
  if (argc == 0) {
    fprintf(stderr,
	    " must have at least one argument!\n");
    return -1;
  }  
  sock = SOCKET(PF_INET, 
		SOCK_STREAM,
		6); /* 6: TCP */
  if (sock == -1) {
    LOG_STRERROR(LOG_FAILURE, "socket");
    return SYSERR;
  }
  soaddr.sin_family
    = AF_INET;
  soaddr.sin_addr.s_addr
    = htonl(INADDR_LOOPBACK);
  soaddr.sin_port 
    = htons(PORT);
  res = CONNECT(sock,
		(struct sockaddr*)&soaddr, 
		sizeof(soaddr));
  if ( (res < 0) && 
       (errno != EINPROGRESS) ) {
    LOG(LOG_INFO,
	_("Cannot connect to LOOPBACK port %d: %s\n"),
	PORT,
	STRERROR(errno));
    CLOSE(sock);
    sock = -1;
    return SYSERR;
  }
  
  /* write command to socket */
  socketSend(strlen(argv[0]),
	     SOCKET_BEGIN_COMMAND, 
	     argv[0]);
  FREE(argv[0]);
  /* write args to socket */
  for (i=1;i<argc;i++) {
    socketSend(strlen(argv[i]), 
	       SOCKET_ADD_ARGUMENT, 
	       argv[i]);
    FREE(argv[i]);
  }
  FREE(argv);
  socketSend(0,
	     SOCKET_END_COMMAND, 
	     NULL);
  
  /* read result from socket, print to stderr,  obtain retVal */
  i = SOCKET_PRINTF;
  buf = NULL;
  while (i == SOCKET_PRINTF) {
    FREENONNULL(buf);
    buf = NULL;
    i = readSocket(&buf, &len);
    if (i == SOCKET_PRINTF)
      fprintf(stdout, 
	      "%.*s", 
	      (int) len, 
	      buf);
  }  
  retVal = *(int*)buf;
  FREE(buf);  
  CLOSE(sock);
  return retVal;
}

/**
 * A child (the shell) has quit.  So we exit,
 * too.
 */
static void sigChildHandler(int signal,
			    siginfo_t * info,
			    void * extra) {
  do_quit = YES;
}

/**
 * This is the "bash" process.  Execs bash.
 * @returns never
 */
static void bash_main() {
  int   i;
  FILE *aliases;
  char * configFile;
  char *argv[] = {
    NULL,		/* replaced by SHELL */
    "--init-file",
    TB_ALIASES,
    "-i",
    NULL,
  };
  
  configFile = getConfigurationString("FILES",
				      "gnunet.conf");
  GNUNET_ASSERT(configFile != NULL);
  argv[0] = SHELL;
  aliases = FOPEN(TB_ALIASES, "w+");
  fprintf(aliases, 
	  "export PS1=\"[GTB]%% \"\n");
  i=0;
  while (commands[i].command != NULL) {
    if (0 == strcmp("exit", commands[i].command)) {
      fprintf(aliases,
	      "alias exit=\"%s ==HELPER== -c %s exit ; exit\"\n",
	      testbedArg0,
	      configFile);
    } else {
      fprintf(aliases,
	      "alias %s=\"%s ==HELPER== -c %s %s\"\n",
	      commands[i].command,
	      testbedArg0,
	      configFile,
	      commands[i].command);
    }
    i++;
  }
  FREE(configFile);
  fclose(aliases);
  doneUtil(); 
  execvp(SHELL, argv);       
  fprintf(stderr,
	  _("Could not execute '%s': %s\n"),
	  SHELL,
	  STRERROR(errno));
}

/**
 * Configuration...
 */
static CIDRNetwork * trustedNetworks_ = NULL;

/**
 * Is this IP labeled as trusted for CS connections?
 */
static int isWhitelisted(IPaddr ip) {   
  return checkIPListed(trustedNetworks_,
		       ip);
}

/**
 * This is the main method of the server.  It reads
 * commands from the socket that are created by helper process.
 * It is the main process that also keeps the state
 * throughout the session.
 *
 * @param bash_pid the process ID of the child that is bash
 */
static int server_main(pid_t bash_pid) {
  int   i, status, ssock, lenOfIncomingAddr;
  int   secs = 5;
  const int on = 1;
  struct sockaddr_in serverAddr, clientAddr;
  struct sigaction oldAct;
  struct sigaction newAct;
  sigset_t set;
  sigset_t oset;

  
  /* create the socket */
 CREATE_SOCKET:
  while ( (ssock = SOCKET(PF_INET, SOCK_STREAM, 0)) < 0) {
    LOG_STRERROR(LOG_ERROR, "socket");
    LOG(LOG_ERROR, 
	_("No client service started. Trying again in 30 seconds.\n"));
    sleep(30);
  }
  
  serverAddr.sin_family
    = AF_INET;
  serverAddr.sin_addr.s_addr 
    = htonl(INADDR_ANY);
  serverAddr.sin_port
    = htons(PORT);
  
  if (SETSOCKOPT(ssock, 
		 SOL_SOCKET,
		 SO_REUSEADDR,
		 &on,
		 sizeof(on)) < 0)
    LOG_STRERROR(LOG_ERROR, "setsockopt");
  
  /* bind the socket */
  if (BIND(ssock,
	   (struct sockaddr*)&serverAddr,
	   sizeof(serverAddr)) < 0) {
    LOG(LOG_ERROR, 
	_("Error (%s) binding the TCP listener to "
	  "port %d. No proxy service started.\nTrying "
	  "again in %d seconds...\n"),
	STRERROR(errno),
	PORT, 
	secs);
    sleep(secs);
    secs += 5; /* slow progression... */
    CLOSE(ssock);
    goto CREATE_SOCKET;
  }
  
  do_quit = NO;
  /* signal handler is needed if the child did exit 
     (e.g. with CTRL-D and not with the command 'exit') */
  newAct.sa_sigaction = &sigChildHandler;
  sigfillset(&newAct.sa_mask);
  newAct.sa_flags = SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
  if (0 != sigaction(SIGCHLD,
		     &newAct,
		     &oldAct)) 
    DIE_STRERROR("sigaction");
  sigemptyset(&set);
  sigaddset(&set, SIGCHLD);
  if (0 != sigprocmask(SIG_UNBLOCK,
		       &set,
		       &oset))
    DIE_STRERROR("sigprocmask");
  LISTEN(ssock, 5);
  while ( (do_quit == NO) &&
	  (0 == waitpid(bash_pid, 
			&status, 
			WNOHANG)) ) {
    int   argc;
    char *command;
    char **args;
    char *buf;
    unsigned int len;
    fd_set rset;
    fd_set wset;
    fd_set eset;
    IPaddr ipaddr;
    
    lenOfIncomingAddr = sizeof(clientAddr); 
    /* accept is not interrupted by SIGCHLD,
       so we must do a select first; yuck. */
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    FD_ZERO(&eset);
    FD_SET(ssock, &rset);
    sock = select(ssock+1, &rset, &wset, &eset, NULL);
    if (sock == -1)
      continue;
    sock = ACCEPT(ssock,
		  (struct sockaddr *)&clientAddr,
		  &lenOfIncomingAddr);
    if (sock < 0) {
      LOG_STRERROR(LOG_ERROR, "accept");
      continue;
    }
    /* access control! */
    GNUNET_ASSERT(sizeof(struct in_addr) == sizeof(IPaddr));
    memcpy(&ipaddr,
	   &clientAddr.sin_addr,
	   sizeof(struct in_addr));   
    if (NO == isWhitelisted(ipaddr)) {
      LOG(LOG_WARNING,
	  _("Rejected unauthorized connection from %u.%u.%u.%u.\n"),
	  PRIP(ntohl(*(int*)&clientAddr.sin_addr)));
      CLOSE(sock);
      continue;
    }


    /* read from socket, run reaction,
       return result value and stdout value;
       possibly set doExit to 1 to exit */    
    buf = NULL;
    if (SOCKET_BEGIN_COMMAND != readSocket(&buf, &len)) {
      fprintf(stderr,
	      _("Protocol violation on socket. "
		"Expected command.\n"));
      return -1;
    }
    command = MALLOC(len+1);
    memcpy(command, buf, len);
    command[len] = '\0';    
    argc = 0;
    args = NULL;
    FREE(buf);
    buf = NULL;
    while (SOCKET_ADD_ARGUMENT == readSocket(&buf, &len)) {
      GROW(args, argc, argc+1);
      args[argc-1] = MALLOC(len+1);
      memcpy(args[argc-1], buf, len);	     
      args[argc-1][len] = '\0';
      FREE(buf);
      buf = NULL;
    }
    FREENONNULL(buf);
    i = 0;
    while (commands[i].command != NULL) {
      if (0 == strcmp(commands[i].command, command)) {
	int ret;
	ret = commands[i].handler(argc, args);
	socketSend(sizeof(unsigned int), 
		   SOCKET_RETVAL,
		   &ret);
	break;
      }
      i++;
    }
    for (i=0;i<argc;i++)
      FREE(args[i]);
    GROW(args, argc, 0);
    if (commands[i].command == NULL) {
      /* should never happen unless the user
	 plays by hand with the aliases... */
      i = -1;
      PRINTF(_("Command '%s' not found!\n"),
	     command);
      socketSend(sizeof(unsigned int), 
		 SOCKET_RETVAL, 
		 &i);
    }
    FREE(command);    
    CLOSE(sock);
    sock = -1;
  }
  /* just to be certain, we could have
     left the main loop due to doExit... */
  waitpid(bash_pid, 
	  &status, 
	  WNOHANG);
  /* restore... */
  if (0 != sigaction(SIGCHLD,
		     &oldAct,
		     &newAct)) 
    LOG_STRERROR(LOG_WARNING, "sigaction");
  return status;
}

#endif

/* *************** command line options *********** */


/**
 * Parse the options, set the timeout.
 *
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return OK on error, SYSERR if we should exit 
 */
static int parseOptions(int argc, char *argv[]) {
  int c, option_index;
  
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  while (1) {
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { 0,0,0,0 }
    };    
    
    option_index = 0;
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:L:", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'v': 
      printf("GNUnet v%s, gnunet-testbed v%s\n",
	     VERSION,
	     TESTBED_VERSION);
      return SYSERR;
      
    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	HELP_HELP,
	HELP_LOGLEVEL,	
	HELP_VERSION,
	HELP_END,
      };
      formatHelp("gnunet-testbed [OPTIONS]",
		 _("Start GNUnet testbed controller."),
		 help);
      return SYSERR;
    }      
    default: 
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return -1;
    } /* end of parsing commandline */
  } /* while (1) */
  return OK;
}

/* **************** main **************** */

/**
 * Create a testbed environment with multiple peers to collect 
 * GNUnet statistics.  Note that the same binary is used for
 * two distinct purposes.  One is the stateful master process
 * that maintains the testbed.  A second type of process is
 * created if HELPER is the first argument.  These processes
 * are created by the user from the SHELL and they merely serve
 * to communicate back the user-commands to the master-process.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 on success, -1 on error
 */   
int main(int argc, char *argv[]) {
#ifndef MINGW /* FIXME MINGW */
  pid_t pid;
  char * ch;
  
  testbedArg0 = expandFileName(argv[0]);
  /* first, evaluate if we are the special
     helper process.  If so, eat HELPER
     argument and run helper_main */
  if (argc > 1) {
    if (strcmp(argv[1], HELPER) == 0) {
      argv[1] = argv[0];
      return helper_main(argc -1, &argv[1]);
    }
  }
  
  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return -1; 

  ch = getConfigurationString("GNUNET-TESTBED",
			      "TRUSTED");
  if (ch == NULL) {
    trustedNetworks_ = parseRoutes("127.0.0.0/8;"); /* by default, trust localhost only */
  } else {
    trustedNetworks_ = parseRoutes(ch);    
    if (trustedNetworks_ == NULL) 
      errexit(_("Malformed entry in the configuration in section %s under %s: %s\n"),
	      "GNUNET-TESTBED",
	      "TRUSTED", 
	      ch); 
    FREE(ch);
  }
  
  /* we are the main testbed process.  Fork of
     a shell and start processing from the socket */
  
  pid = fork();
  if (pid < 0)
    DIE_STRERROR("fork");
  if (pid == 0) {
    FREE(trustedNetworks_);
    bash_main();
    return 0; /* unreached */
  } else {
    int ret;
    /* run actual main loop */
    ret = server_main(pid);
    /* just to be certain */
    kill(pid, SIGHUP);
    /* proper shutdown... */
    doneUtil();
    FREE(trustedNetworks_);
    UNLINK(TB_ALIASES);
    FREE(testbedArg0);
    return ret;
  } 
#endif
}

/* end of gnunet-testbed.c */ 
