/** 
 * @file applications/fs/ecrs/ecrstest.c
 * @brief testcase for ecrs (upload-download)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include <sys/wait.h>

#define CHECK(a) if (!(a)) { ok = NO; BREAK(); goto FAILURE; }

static int parseCommandLine(int argc, 
			    char * argv[]) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "NO"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNET",
				     "LOGLEVEL",
				     "WARNING"));
  return OK;
}


int main(int argc, char * argv[]){
  pid_t daemon;
  int status;
  int ok;
  Mutex lock;
  GNUNET_TCP_SOCKET * sock;
  int i;

  daemon = fork();
  if (daemon == 0) {
    /* FIXME: would be nice to be able to tell
       gnunetd to use the check/debug DB and not
       any real DB! */
    if (0 != execlp("gnunetd", /* what binary to execute, must be in $PATH! */
		    "gnunetd", /* arg0, path to gnunet binary */
		    "-d",  /* do not daemonize so we can easily kill you */
		    "-L", 
		    "DEBUG",  /* gnunetd loglevel */
		    NULL)) {
      fprintf(stderr,
	      _("'%s' failed: %s\n"),
	      "execlp",
	      STRERROR(errno));
      return -1;
    }
  }
  ok = YES;
  initUtil(argc, argv, &parseCommandLine);
  startCron();
  MUTEX_CREATE(&lock);
  gnunet_util_sleep(5 * cronSECONDS); /* give gnunetd time to start */
  sock = getClientSocket();
  CHECK(sock != NULL);
  
  /* ACTUAL TEST CODE */
  /* TO BE ADDED */

  /* END OF TEST CODE */
 FAILURE:
  if (sock != NULL)
    releaseClientSocket(sock);
  MUTEX_DESTROY(&lock);
  stopCron();
  doneUtil();
  if (0 != kill(daemon, SIGTERM))
    DIE_STRERROR("kill");
  if (daemon != waitpid(daemon, &status, 0)) 
    DIE_STRERROR("waitpid");
  
  if ( (WEXITSTATUS(status) == 0) && 
       (ok == YES) )
    return 0;
  else
    return 1;    
}

/* end of ecrstest.c */
