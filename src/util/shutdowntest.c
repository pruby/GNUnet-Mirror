/** 
 * @file test/shutdowntest.c
 * @brief testcase for util/shutdown.c
 */

#include "gnunet_util.h"
#include "platform.h"

static pid_t myPID;

static int check() {
  /* first, test / SIGINT (simulated) */
  initializeShutdownHandlers();
  if (testShutdown() != NO)
    return 1;
#ifndef MINGW
  kill(myPID, SIGINT);
#else
  GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
#endif
  if (testShutdown() != YES)
    return 2;
  wait_for_shutdown(); 
  doneShutdownHandlers();
  
  /* now, test "run_shutdown" */
  initializeShutdownHandlers();
  if (testShutdown() != NO)
    return 3;
  run_shutdown(42);
  if (testShutdown() != YES)
    return 4;
  wait_for_shutdown(); 
  doneShutdownHandlers();  

  return 0;
}


/**
 * Perform option parsing from the command line. 
 */
static int parseCommandLine(int argc, 
			    char * argv[]) {
  char c;

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      { "config",  1, 0, 'c' },
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "c:", 
		      long_options, 
		      &option_index);
    
    if (c == -1) 
      break;  /* No more flags to process */
    
    switch(c) {
    case 'c': 
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    } /* end of parsing commandline */
  }
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGLEVEL",
				     "WARNING"));
  return OK;
}

int main(int argc,
	 char * argv[]){
  int ret;

  myPID = getpid();
  initUtil(argc, argv, &parseCommandLine);

  ret = check();
  if (ret != 0)
    fprintf(stderr,
	    "ERROR %d\n", ret);
  doneUtil();
  return ret;
}

/* end of shutdowntest.c */
