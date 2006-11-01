/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
/*
 * @file applications/sqstore_sqlite/sqlitetest2.c
 * @brief Test for the sqstore implementations.
 * @author Christian Grothoff
 *
 * This testcase inserts a bunch of (variable size) data and then deletes
 * data until the (reported) database size drops below a given threshold.
 * This is iterated 10 times, with the actual size of the content stored,
 * the database size reported and the file size on disk being printed for
 * each iteration.  The code also prints a "I" for every 40 blocks
 * inserted and a "D" for every 40 blocks deleted.  The deletion 
 * strategy alternates between "lowest priority" and "earliest expiration".
 * Priorities and expiration dates are set using a pseudo-random value 
 * within a realistic range.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_cron.h"
#include "gnunet_util_crypto.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_protocols.h"
#include "gnunet_sqstore_service.h"
#include "core.h"

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

/**
 * Target datastore size.
 */
#define MAX_SIZE 1024 * 1024 * 32

static unsigned long long stored_bytes;

static int putValue(SQstore_ServiceAPI * api,
		    int i) {
  Datastore_Value * value;
  static HashCode512 key;
  static int ic;

  hash(&key,
       sizeof(HashCode512),
       &key);
  value = MALLOC(sizeof(Datastore_Value) + 8 * i);
  value->size = htonl(sizeof(Datastore_Value) + 8 * i);
  value->type = htonl(i);
  value->prio = htonl(weak_randomi(100));
  value->anonymityLevel = htonl(i);
  value->expirationTime = htonll(get_time() + weak_randomi(1000));
  memset(&value[1], i, i*8);
  if (OK != api->put(&key, value))
    return SYSERR;
  ic++;
  if (ic % 40 == 0)
    fprintf(stderr, "I");
  stored_bytes += ntohl(value->size);
  FREE(value);
  return OK;
}

static int 
iterateDelete(const HashCode512 * key,
	      const Datastore_Value * val,
	      void * cls) {
  SQstore_ServiceAPI * api = cls;
  static int dc;

  if (api->getSize() < MAX_SIZE)
    return SYSERR;
  dc++;
  if (dc % 40 == 0)
    fprintf(stderr, "D");
  GE_ASSERT(NULL, 1 == api->del(key, val));
  stored_bytes -= ntohl(val->size);
  return OK;
}

/**
 * Add testcode here!
 */
static int test(SQstore_ServiceAPI * api) {
  int i;
  int j;
  unsigned long long size;

  for (i=0;i<100;i++) {
    fprintf(stderr, ".");
    for (j=0;j<4000;j+=10)
      ASSERT(OK == putValue(api, j));
    if ((i % 2) == 0)
      api->iterateLowPriority(0, &iterateDelete, api);
    else
      api->iterateExpirationTime(0, &iterateDelete, api);    
    if ((i % 10) == 9) {
      disk_file_size(NULL,
		     "/tmp/gnunet-sqlite-sqstore-test/data/fs/content/gnunet.dat",
		     &size,
		     NO);
      printf("\nStored %llu - reported size %llu - actual size %llu\n",
	     stored_bytes, 
	     api->getSize(),
	     size);
    }
  }
  api->drop();
  return OK;

 FAILURE:
  api->drop();
  return SYSERR;
}

int main(int argc, char *argv[]) {
  SQstore_ServiceAPI * api;
  int ok;
  struct GC_Configuration * cfg;
  struct CronManager * cron;

  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;
  }
  cron = cron_create(NULL);
  initCore(NULL,
	   cfg,
	   cron,
	   NULL);
  api = requestService("sqstore");
  if (api != NULL) {
    ok = test(api);
    releaseService(api);
  } else
    ok = SYSERR;
  doneCore();
  cron_destroy(cron);
  GC_free(cfg);
  if (ok == SYSERR)
    return 1;
  return 0;
}

/* end of sqlitetest2.c */
