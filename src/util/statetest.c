/**
 * @file test/storagetest.c
 * @brief testcase for the state module
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

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
				     "LOGLEVEL",
				     "NOTHING"));
  return OK;
}

#define TH "TestHandle"

int testState() {
  char * testString = "Hello World";  
  char * ret;

  stateUnlinkFromDB(TH); /* go to defined state */
  if (SYSERR == stateWriteContent(TH,
				  5,
				  testString))
    return 1;
  if (SYSERR == stateAppendContent(TH,
				   6,
				   &testString[5]))
    return 2;
  ret = NULL;
  if (SYSERR == stateReadContent(TH,
				 (void**)&ret))
    return 3;
  if (0 != strncmp(ret, testString, 11))
    return 4;
  FREE(ret);
  if (OK != stateUnlinkFromDB(TH))
    return 5;
  return 0;
}

int main(int argc, char * argv[]) {
  int ret = 0;
  initUtil(argc, argv, &parseCommandLine);
  ret = testState();

  doneUtil();
  return ret;
} /* end of main */
