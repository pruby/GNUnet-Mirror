/**
 * @file test/configtest.c
 * @brief Test that the configuration module works.
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

static int testConfig() {
  char * c;
  if (NO == testConfigurationString("test",
				    "a",
				    "a")) {
    printf("[test]-a not mapped to a");
    return 1;
  }
  c = getConfigurationString("test",
			     "b");
  if (0 != strcmp("b",
		  c)) {		    
    printf("[test]-b not mapped to b");
    return 1;
  }
  FREENONNULL(c);
  if (5 != getConfigurationInt("test",
			       "five")) {
    printf("[test]-five not mapped to 5");
    return 1;
  }
  FREENONNULL(setConfigurationString("more",
		  	             "c",
			             "d"));
  if (NO == testConfigurationString("more",
				    "c",
				    "d")) {
    printf("[more]-c not re-mapped to d");
    return 1;
  }  
  if (42 != getConfigurationInt("more",
				"five")) {
    printf("[more]-five not mapped to 42");
    return 1;
  }
  if (NO == testConfigurationString("last",
				    "test",
				    "hello/world")) {
    printf("string substitution did not work: >>%s<<\n",
	   getConfigurationString("last",
				  "test"));
    return 1;
  }
  if (NO == testConfigurationString("last",
				    "boom",
				    "1 2 3 testing")) {
    printf("string enclosing with \"'s did not work: >>%s<<\n",
	   getConfigurationString("last",
				  "boom"));
    return 1;
  }
  if (NO == testConfigurationString("last",
				    "trailing",
				    "YES")) {
    printf("confused with trailing spaces: >>%s<<\n",
	   getConfigurationString("last",
		   		  "trailing"));
  }
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
				     "LOGLEVEL",
				     "NOTHING"));
  return OK;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;
  char * args[] = {
    "main",
    "-c",
    "testconfig.conf",
  };

  initUtil(3, args, &parseCommandLine);
  failureCount += testConfig();
  doneUtil();

  if (failureCount == 0) 
    return 0;
  else {
    printf("\n\n%d TESTS FAILED!\n\n",failureCount);
    return -1;
  } 
}
