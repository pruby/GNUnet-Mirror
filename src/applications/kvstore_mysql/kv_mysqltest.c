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
static int
test (GNUNET_KVstore_ServiceAPI * api)
{
  GNUNET_KeyValueRecord *kv;
  GNUNET_HashCode k, v;
  GNUNET_HashCode *r;

  GNUNET_CronTime timeStmp;

  kv = api->getTable ("TEST", "KV");
  ASSERT (kv != NULL);

  timeStmp = GNUNET_get_time ();
  ASSERT (api->put (kv, (void *) &k, sizeof (k), (void *) &v, sizeof (v),
                    timeStmp) == GNUNET_OK);

  r = api->get (kv, (void *) &k, sizeof (k), 0, 0, NULL, NULL);
  ASSERT (r != NULL);
  ASSERT (memcmp (&v, r, sizeof (v)) == 0);
  GNUNET_free (r);

  ASSERT (api->del (kv, (void *) &k, sizeof (k), 0) == GNUNET_OK);

  ASSERT (api->get (kv, (void *) &k, sizeof (k), 0, 0, NULL, NULL) == NULL);

  ASSERT (api->dropTable (kv) == GNUNET_OK);

  api->dropDatabase ("TEST");

  return GNUNET_OK;

FAILURE:
  api->dropDatabase ("TEST");
  return GNUNET_SYSERR;
}

#define TEST_DB "/tmp/GNUnet_sqstore_test/"

int
main (int argc, char *argv[])
{
  GNUNET_KVstore_ServiceAPI *api;
  int ok;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_CronManager *cron;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  cron = GNUNET_cron_create (NULL);
  GNUNET_CORE_init (NULL, cfg, cron, NULL);
  api = GNUNET_CORE_request_service ("kvstore_sqlite");
  if (api != NULL)
    {
      ok = test (api);
      GNUNET_CORE_release_service (api);
    }
  else
    ok = GNUNET_SYSERR;
  GNUNET_CORE_done ();
  if (ok == GNUNET_SYSERR)
    return 1;
  return 0;
}

/* end of kv_sqlitetest.c */
