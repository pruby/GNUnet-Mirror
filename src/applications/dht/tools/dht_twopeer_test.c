/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/dht/tools/dht_twopeer_test.c
 * @brief DHT testcase
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"


#define START_PEERS 1


static int ok;

static int
waitForConnect (const char *name, unsigned long long value, void *cls)
{
  if ((value > 0) && (0 == strcmp (_("# dht connections"), name)))
    {
      ok = 1;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

#define CHECK(a) do { if (!(a)) { ret = 1; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; } } while(0)

/**
 * Testcase to test DHT routing (2 peers only).
 * @return 0: ok, -1: error
 */
int
main (int argc, const char **argv)
{
#if START_PEERS
  struct GNUNET_TESTING_DaemonContext *peers;
#endif
  int ret = 0;
  GNUNET_HashCode key;
  char *value;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_ClientServerConnection *sock;
  int left;

  ectx = NULL;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_PEERS
  peers = GNUNET_TESTING_start_daemons ("tcp",
                                        "advertising dht stats",
                                        "/tmp/gnunet-dht-test",
                                        2087, 10000, 2);
  if (peers == NULL)
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  if (GNUNET_OK != GNUNET_TESTING_connect_daemons (2087, 12087))
    {
      GNUNET_TESTING_stop_daemons (peers);
      fprintf (stderr, "Failed to connect the peers!\n");
      GNUNET_GC_free (cfg);
      return -1;
    }

  /* wait for DHT's to find each other! */
  sock = GNUNET_client_connection_create (NULL, cfg);
  left = 10;                    /* how many iterations should we wait? */
  printf ("Waiting for peers to DHT-connect (1->2)");
  while (GNUNET_OK ==
         GNUNET_STATS_get_statistics (NULL, sock, &waitForConnect, NULL))
    {
      printf (".");
      fflush (stdout);
      sleep (2);
      left--;
      if (left == 0)
        break;
    }
  printf (left > 0 ? " OK!\n" : "?\n");
  GNUNET_client_connection_destroy (sock);
  if (ok == 0)
    {
      GNUNET_TESTING_stop_daemons (peers);
      fprintf (stderr, "Peers' DHTs failed to DHT-connect!\n");
      GNUNET_GC_free (cfg);
      return -1;
    }

  /* switch to peer2 */
  GNUNET_GC_set_configuration_value_string (cfg,
                                            ectx,
                                            "NETWORK", "HOST",
                                            "localhost:12087");
  /* verify that peer2 also sees the other DHT! */
  ok = 0;
  sock = GNUNET_client_connection_create (NULL, cfg);
  left = 10;                    /* how many iterations should we wait? */
  printf ("Waiting for peers to DHT-connect (2->1)");
  while (GNUNET_OK ==
         GNUNET_STATS_get_statistics (NULL, sock, &waitForConnect, NULL))
    {
      printf (".");
      fflush (stdout);
      sleep (2);
      left--;
      if (left == 0)
        break;
    }
  printf (left > 0 ? " OK!\n" : "?\n");
  GNUNET_client_connection_destroy (sock);
  if (ok == 0)
    {
      GNUNET_TESTING_stop_daemons (peers);
      fprintf (stderr, "Peers' DHTs failed to DHT-connect!\n");
      GNUNET_GC_free (cfg);
      return -1;
    }


  /* actual test code */
  /* switch to peer1 */
  GNUNET_GC_set_configuration_value_string (cfg,
                                            ectx,
                                            "NETWORK", "HOST",
                                            "localhost:2087");
  GNUNET_hash ("key2", 4, &key);
  value = GNUNET_malloc (8);
  memset (value, 'A', 8);
  CHECK (GNUNET_OK == GNUNET_DHT_put (cfg,
                                      ectx,
                                      &key,
                                      GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                      8, value));
  /* switch to peer2 */
  GNUNET_GC_set_configuration_value_string (cfg,
                                            ectx,
                                            "NETWORK", "HOST",
                                            "localhost:12087");
  GNUNET_hash ("key", 3, &key);
  value = GNUNET_malloc (8);
  memset (value, 'B', 8);
  CHECK (GNUNET_OK == GNUNET_DHT_put (cfg,
                                      ectx,
                                      &key,
                                      GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                      8, value));
  GNUNET_hash ("key2", 4, &key);
  left = 10;
  printf ("Getting key 2 from peer 2 (stored at peer 1)");
  do
    {
      printf (".");
      fflush (stdout);
      if (1 == GNUNET_DHT_get (cfg,
                               ectx,
                               GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                               &key, 2 * GNUNET_CRON_SECONDS, NULL, NULL))
        break;
      left--;
    }
  while (left > 0);
  printf (left > 0 ? " OK!\n" : "?\n");

  CHECK (left > 0);
  /* switch to peer1 */
  GNUNET_GC_set_configuration_value_string (cfg,
                                            ectx,
                                            "NETWORK", "HOST",
                                            "localhost:2087");
  printf ("Getting key 1 from peer 1 (stored at peer 2)");
  left = 10;
  do
    {
      printf (".");
      fflush (stdout);
      if (1 == GNUNET_DHT_get (cfg,
                               ectx,
                               GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                               &key, 2 * GNUNET_CRON_SECONDS, NULL, NULL))
        break;
      left--;
    }
  while (left > 0);
  printf (left > 0 ? " OK!\n" : "?\n");
  CHECK (left > 0);
  /* end of actual test code */

FAILURE:
#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif
  GNUNET_GC_free (cfg);
  return ret;
}

/* end of dht_twopeer_test.c */
