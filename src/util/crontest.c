/**
 * @file test/crontest.c
 * @brief Testcase for cron.
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

static int global;
static int global2;
static int global3;

/**
 * Initialize controlThread.
 */
void initCron();

/**
 * Make sure to call stopCron before calling this method!
 */
void doneCron();

/**
 * Process the cron-job at the beginning of the waiting
 * queue, that is, remove, invoke, and re-insert if
 * it is a periodical job. Make sure the sync is down
 * while the job is running (it may add other jobs!)
 */
void runJob();

static void cronJob(void * unused) {
  global++;
}
static void cronJob2(void * unused) {
  global2++;
}
static void cronJob3(void * unused) {
  global3++;
}

int testCron() {
  int i;

  global = -1;
  global2 = -1;
  global3 = -1;
  addCronJob(&cronJob, cronSECONDS*1, cronSECONDS*1, NULL);
  addCronJob(&cronJob2, cronSECONDS*4, cronSECONDS*4, NULL);
  addCronJob(&cronJob3, cronSECONDS*16, cronSECONDS*16, NULL);
  for (i=0;i<10;i++) {
    /*    fprintf(stderr,"."); */
    sleep(1);
    if (((global-i) * (global-i)) > 9) {
      fprintf(stderr,"1: Expected %d got %d\n", i, global);
      return 1;
    }
    if (((global2-(i>>2)) * (global2-(i>>2))) > 9) {
      fprintf(stderr,"2: Expected %d got %d\n", i>>2, global2);
      return 1;
    }
    if (((global3-(i>>4)) * (global3-(i>>4))) > 9) {
      fprintf(stderr,"3: Expected %d got %d\n", i>>4, global3);
      return 1;
    }
  }
  delCronJob(&cronJob, cronSECONDS*1, NULL);
  delCronJob(&cronJob2, cronSECONDS*4, NULL);
  delCronJob(&cronJob3, cronSECONDS*16, NULL);
  return 0;
}

static void delJob() {
  delCronJob(&cronJob, 42, NULL);
}

static int testDelCron() {
  global = 0;
  addCronJob(&cronJob, cronSECONDS*1, 42, NULL);
  addCronJob(&delJob, 500 * cronMILLIS, 0, NULL);
  sleep(1);
  if (global != 0) {
    fprintf(stderr,
	    "cron job was supposed to be deleted, but ran anyway!\n");
    return 1;
  } else
    return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;

  initCron();
  startCron();
  failureCount += testCron();
  failureCount += testDelCron();
  stopCron();
  doneCron();
  if (failureCount == 0)
    return 0;
  else {
    printf("\n\n%d TESTS FAILED!\n\n",failureCount);
    return -1;
  }
} /* end of main */
