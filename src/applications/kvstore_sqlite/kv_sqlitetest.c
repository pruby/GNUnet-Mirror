/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/kvstore_sqlite/kv_sqlitetest.c
 * @brief Test for the kvstore implementations.
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_kvstore_service.h"
#include "core.h"

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)


/**
 * Add testcode here!
 */
static int test(KVstore_ServiceAPI * api) {
  KVHandle *kv;
  HashCode512 k, v;
  HashCode512 *r;

  cron_t timeStmp;

  kv = api->getTable("TEST", "KV");
  ASSERT(kv != NULL);
  
  cronTime(&timeStmp);
  ASSERT(api->put(kv, (void *) &k, sizeof(k), (void *) &v, sizeof(v),
    timeStmp) == OK);
  
  r = api->get(kv, (void *) &k, sizeof(k), 0, 0, NULL, NULL);
  ASSERT(r != NULL);
  ASSERT(memcmp(&v, r, sizeof(v)) == 0);
  FREE(r);
  
  ASSERT(api->del(kv, (void *) &k, sizeof(k), 0) == OK);
  
  ASSERT(api->get(kv, (void *) &k, sizeof(k), 0, 0, NULL, NULL) == NULL);
  
  ASSERT(api->dropTable(kv) == OK);
  
  api->dropDatabase("TEST");

  return OK;
  
 FAILURE:
  api->dropDatabase("TEST");
  return SYSERR;
}

#define TEST_DB "/tmp/GNUnet_sqstore_test/"

/**
 * Perform option parsing from the command line.
 */
static int parser(int argc,
		  char * argv[]) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "GNUNETD_HOME",
				     "/tmp/gnunet_test/"));
  FREENONNULL(setConfigurationString("FILES",
				     "gnunet.conf",
				     "check.conf"));
  FREENONNULL(setConfigurationString("FS",
				     "DIR",
				     TEST_DB));
  return OK;
}

int main(int argc, char *argv[]) {
  KVstore_ServiceAPI * api;
  int ok;

  if (OK != initUtil(argc, argv, &parser))
    errexit(_("Could not initialize libgnunetutil!\n"));
  fprintf(stderr, "init\n");
  initCore();
  api = requestService("kvstore_sqlite");
  if (api != NULL) {
    ok = test(api);
    releaseService(api);
  } else
    ok = SYSERR;
  doneCore();
  doneUtil();
  if (ok == SYSERR)
    return 1;
  else
    return 0;
}

/* end of kv_sqlitetest.c */
