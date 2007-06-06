/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/cron/crontest.c
 * @brief Testcase for cron.
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_util_cron.h"
#include "platform.h"

static int global;
static int global2;
static int global3;

static struct CronManager * cron;

static void cronJob(void * unused) {
  global++;
}

static void cronJob2(void * unused) {
  global2++;
}

static void cronJob3(void * unused) {
  global3++;
}

static int testCron() {
  int i;

  global = -1;
  global2 = -1;
  global3 = -1;
  cron_add_job(cron,
	       &cronJob, cronSECONDS*1, cronSECONDS*1, NULL);
  cron_add_job(cron,
	       &cronJob2, cronSECONDS*4, cronSECONDS*4, NULL);
  cron_add_job(cron,
	       &cronJob3, cronSECONDS*16, cronSECONDS*16, NULL);
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
  cron_del_job(cron,
	       &cronJob, cronSECONDS*1, NULL);
  cron_del_job(cron,
	       &cronJob2, cronSECONDS*4, NULL);
  cron_del_job(cron,
	       &cronJob3, cronSECONDS*16, NULL);
  return 0;
}

static void delJob(void * unused) {
  cron_del_job(cron,
	       &cronJob, 42, NULL);
}

static int testDelCron() {
  global = 0;
  cron_add_job(cron,
	       &cronJob, cronSECONDS*1, 42, NULL);
  cron_add_job(cron,
	       &delJob, 500 * cronMILLIS, 0, NULL);
  PTHREAD_SLEEP(1 * cronSECONDS);
  if (global != 0) {
    fprintf(stderr,
	    "cron job was supposed to be deleted, but ran anyway!\n");
    return 1;
  }
  return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;

  cron = cron_create(NULL);
  cron_start(cron);
  failureCount += testCron();
  failureCount += testDelCron();
  cron_stop(cron);
  cron_destroy(cron);
  if (failureCount != 0)
    return 1;
  return 0;
} /* end of main */
