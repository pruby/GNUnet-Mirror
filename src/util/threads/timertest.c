/**
 * @file test/timertest.c
 * @brief testcase for util/timer.c; also measures how
 *  precise the timers are.  Expect values between 10 and 20 ms on
 *  modern machines.
 */

#include "gnunet_util.h"
#include "platform.h"

#define VERBOSE NO

static void semaphore_up(Semaphore * sem) {
  SEMAPHORE_UP(sem);
}

static int check() {
  cron_t now;
  cron_t last;
  TIME_T tnow;
  TIME_T tlast;
  int i;
  unsigned long long cumDelta;
  Semaphore * sem;

  /* test that time/cronTime are monotonically
     increasing;
     measure precision of sleep and report;
     test that sleep is interrupted by signals; */
  last = cronTime(&now);
  if (last != now)
    return 1;
  tlast = TIME(&tnow);
  if (tlast != tnow)
    return 2;
  while (now == last)
    now = cronTime(NULL);
  while (tnow == tlast)
    tnow = TIME(NULL);
  if (now < last)
    return 3;
  if (tnow < tlast)
    return 4;
  cumDelta = 0;
#define INCR 47
#define MAXV 1500
  for (i=0;i<MAXV;i+=INCR) {
    cronTime(&last);
    if (0 != gnunet_util_sleep(cronMILLIS * i))
      return 5;
    cronTime(&now);
#if VERBOSE
    fprintf(stderr,
	    "%4u ms requested, got: %4lld ms\n",
	    i / cronMILLIS,
	    (now - last) / cronMILLIS);
#endif
    if (last + cronMILLIS * i < now)
      cumDelta += (now - (last+cronMILLIS*i));
    else
      cumDelta += ((last+cronMILLIS*i) - now);
  }
  FPRINTF(stdout,
	  "Sleep precision: %llu ms.  ",
	  cumDelta / cronMILLIS / (MAXV/INCR));
  if (cumDelta <= 10 * cronMILLIS * MAXV / INCR)
    fprintf(stdout,
	    "Timer precision is excellent.\n");
  else if (cumDelta <= 50 * cronMILLIS * MAXV / INCR) /* 50 ms average deviation */
    fprintf(stdout,
	    "Timer precision is good.\n");
  else if (cumDelta > 250 * cronMILLIS * MAXV / INCR)
    fprintf(stdout,
	    "Timer precision is awful.\n");
  else
    fprintf(stdout,
	    "Timer precision is acceptable.\n");

  sem = SEMAPHORE_NEW(0);

  startCron();
  cumDelta = 0;

#define MAXV2 1500
#define INCR2 113
  for (i=50;i<MAXV2+50;i+=INCR2) {
    cronTime(&last);
    addCronJob((CronJob) &semaphore_up,
	       i * cronMILLIS,
	       0,
	       sem);
    SEMAPHORE_DOWN(sem);
    cronTime(&now);
    if (now < last + i)
      now = last + i - now;
    else
      now = now - (last + i);
    cumDelta += now;
#if VERBOSE
    FPRINTF(stderr,
	    "Sleep interrupted by signal within %llu ms of deadline (intended delay: %d ms).\n",
	    now,
	    i);
#endif
  }
  FPRINTF(stdout,
	  "Sleep interrupt precision is %llums. ",
	  cumDelta / (MAXV2/INCR2) );
  if (cumDelta <= 10 * cronMILLIS * MAXV2 / INCR2)
    fprintf(stdout,
	    "Timer precision is excellent.\n");
  else if (cumDelta <= 50 * cronMILLIS * MAXV2 / INCR2) /* 50ms average deviation */
    fprintf(stdout,
	    "Timer precision is good.\n");
  else if (cumDelta > 250 * cronMILLIS * MAXV2 / INCR2)
    fprintf(stdout,
	    "Timer precision is awful.\n");
  else
    fprintf(stdout,
	    "Timer precision is acceptable.\n");

  stopCron();
  SEMAPHORE_FREE(sem);

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
	    "ERROR %d\n", ret);
  doneUtil();
  return ret;
}

/* end of timertest.c */
