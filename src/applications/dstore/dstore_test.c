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
 * @file applications/dstore/dstore_test.c
 * @brief Test for the dstore implementations.
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_cron.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_protocols.h"
#include "gnunet_dstore_service.h"
#include "core.h"

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

static int error;

static void checkIt(const HashCode512 * key,
		    unsigned int type,
		    unsigned int size,
		    const char * data,
		    void * cls) {
  if (size != sizeof(HashCode512)) {
    printf("ERROR: Invalid size\n");
    error = 2;
  }
  if (0 != memcmp(data, cls, size)) {
    printf("ERROR: Invalid data\n");
    error = 3;
  }
}

/**
 * Add testcode here!
 */
static int test(Dstore_ServiceAPI * api) {
  HashCode512 k;
  HashCode512 n;
  cron_t exp;
  unsigned int i;

  exp = get_time() + 5 * cronMINUTES;
  memset(&k,
	 0,
	 sizeof(HashCode512));
  for (i=0;i<100;i++) {
    hash(&k,
	 sizeof(HashCode512),
	 &n);
    ASSERT(OK == api->put(&k,
			  i % 2,
			  exp,
			  sizeof(HashCode512),
			  (const char*) &n));
    k = n;
  }
  memset(&k,
	 0,
	 sizeof(HashCode512));
  for (i=0;i<100;i++) {
    hash(&k,
	 sizeof(HashCode512),
	 &n);
    ASSERT(1 == api->get(&k,
			 i % 2,
			 &checkIt,
			 &n));
    k = n;
  }
  return OK;
 FAILURE:
  return SYSERR;
}

#define TEST_DB "/tmp/GNUnet_dstore_test/"

int main(int argc, char *argv[]) {
  Dstore_ServiceAPI * api;
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
  api = requestService("dstore");
  if (api != NULL) {
    ok = test(api);
    releaseService(api);
  } else
    ok = SYSERR;
  doneCore();
  if (ok == SYSERR)
    return 1;
  return error;
}

/* end of dstore_test.c */
