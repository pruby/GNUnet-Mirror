/** 
 * @file test/identitytest.c
 * @brief testcase for util/identity.c
 */

#include "gnunet_util.h"

int initAddress(); /* in identity.c */

static int check() {
  if (initAddress() != OK)
    return 1;
  else
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
  initUtil(argc, argv, &parseCommandLine);

  ret = check();
  if (ret != 0)
    fprintf(stderr,
	    "ERROR %d.  Did you configure GNUnet properly?\n", 
	    ret);
  doneUtil();
  return ret;
}

/* end of identitytest.c */
