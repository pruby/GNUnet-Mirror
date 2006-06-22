/**
 * @file util/statuscallstest.c
 * @brief testcase for util/statuscalls.c
 */

#include "gnunet_util.h"
#include "platform.h"

/**
 * Perform option parsing from the command line.
 */
static int parseCommandLine(int argc,
			    char * argv[]) {
  char c;

  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "GNUNETD_HOME",
				     "/tmp/gnunet_test/"));
  FREENONNULL(setConfigurationString("FILES",
				     "gnunet.conf",
				     "check.conf"));
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
      break;  /* No more flags to process*/

    switch(c) {
    case 'c':
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    } /* end of parsing commandline */
  }
  return OK;
}

int main(int argc, char * argv[]){
  int ret;
  cron_t start;

  if (OK != initUtil(argc, argv, &parseCommandLine))
    errexit("Error during initialization!\n");
  startCron();
  /* need to run each phase for more than 10s since
     statuscalls only refreshes that often... */
  cronTime(&start);
  while (start + 12 * cronSECONDS > cronTime(NULL))
    sleep(1);
  cronTime(&start);
  ret = getCPULoad();
  while (start + 12 * cronSECONDS > cronTime(NULL))
    sqrt(245.2523); /* do some processing to drive load up */
  if (ret > getCPULoad())
    printf("busy loop decreased CPU load: %d < %d.\n",
	   ret,
	   getCPULoad());
  stopCron();
  doneUtil();

  return 0;
}
