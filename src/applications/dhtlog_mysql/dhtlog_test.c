/*
     This file is part of GNUnet.
     (C) 2006 - 2009 Christian Grothoff (and other contributing authors)

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
 * @file applications/dhtlog/dhtlog_test.c
 * @brief Test of the dhtlog service
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_dhtlog_service.h"
#include "core.h"


/**
 * Actual test of the service operations
 */
static int
test (GNUNET_dhtlog_ServiceAPI * api)
{
  GNUNET_PeerIdentity p;
  GNUNET_HashCode k;
  GNUNET_HashCode n;
  GNUNET_CronTime exp;
  int ret;
  unsigned int i = 42;
  unsigned long long trialuid;
  unsigned long long sqlqueryuid;
  unsigned long long sqlrouteuid = 0;
  unsigned long long nodeuid = 0;
  unsigned long long internaluid = 1010223344;

  memset (&k, 1, sizeof (GNUNET_HashCode));
  memset (&n, 4, sizeof (GNUNET_HashCode));
  memcpy (&p.hashPubKey, &n, sizeof (GNUNET_HashCode));

  ret = api->insert_trial (&trialuid, i, "trialtest");
  fprintf (stderr, "Trial uid is %llu\n", trialuid);

  if (ret != GNUNET_OK)
    {
      return ret;
    }
  ret = api->get_trial (&trialuid);
  if (ret != GNUNET_OK)
    {
      return ret;
    }
  fprintf (stderr, "Trial uid is %llu\n", trialuid);

  ret =
    api->insert_query (&sqlqueryuid, internaluid, trialuid, 2, 4, 0, &p, &k);
  fprintf (stderr, "Sql uid for dht query is %llu\n", sqlqueryuid);

  ret =
    api->insert_route (&sqlrouteuid, sqlqueryuid, trialuid, 1, 3, 1, &p, &k,
                       NULL, &p);
  fprintf (stderr, "Sql uid for dht route is %llu\n", sqlrouteuid);
  ret =
    api->insert_route (&sqlrouteuid, sqlqueryuid, trialuid, 2, 7, 0, &p, &k,
                       &p, &p);
  fprintf (stderr, "Sql uid for dht route is %llu\n", sqlrouteuid);
  ret =
    api->insert_route (&sqlrouteuid, sqlqueryuid, trialuid, 3, 9, 1, &p, &k,
                       &p, NULL);
  fprintf (stderr, "Sql uid for dht route is %llu\n", sqlrouteuid);

  ret = api->insert_node (&nodeuid, trialuid, &p);
  if (ret != GNUNET_OK)
    {
      fprintf (stderr, "received ret value of %d\n", ret);
      return ret;
    }
  sleep (1);
  fprintf (stderr, "Updating trial %llu with endtime of now\n", trialuid);
  ret = api->update_trial (trialuid);

  if (ret != GNUNET_OK)
    {
      return ret;
    }

  return ret;
}

int
main (int argc, char *argv[])
{
  GNUNET_dhtlog_ServiceAPI *api;

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

  api = GNUNET_CORE_request_service ("dhtlog_mysql");
  if (api != NULL)
    {
      printf ("Successfully got service\n");
      ok = test (api);
      GNUNET_CORE_release_service (api);
    }
  else
    {
      printf ("Problem getting service...\n");
      ok = GNUNET_SYSERR;
    }
  GNUNET_CORE_done ();
  if (ok == GNUNET_SYSERR)
    {
      fprintf (stderr, "Ending with error!\n");
      return 1;
    }
  else
    {
      fprintf (stderr, "Ending without errors (:\n");
    }

  return GNUNET_OK;
}

/* end of dhtlog_test.c */
