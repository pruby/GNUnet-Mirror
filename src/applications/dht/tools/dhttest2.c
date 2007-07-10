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
 * @file applications/dht/tools/dhttest2.c
 * @brief DHT testcase
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_util_cron.h"


#define START_PEERS 1


static int ok;

static int
waitForConnect (const char *name, unsigned long long value, void *cls)
{
  if ((value > 0) && (0 == strcmp (_("# dht connections"), name)))
    {
      ok = 1;
      return SYSERR;
    }
  return OK;
}

#define CHECK(a) do { if (!(a)) { ret = 1; GE_BREAK(ectx, 0); goto FAILURE; } } while(0)

/**
 * Testcase to test DHT routing (2 peers only).
 * @return 0: ok, -1: error
 */
int
main (int argc, const char **argv)
{
#if START_PEERS
  struct DaemonContext *peers;
#endif
  int ret = 0;
  HashCode512 key;
  DataContainer *value;
  struct GE_Context *ectx;
  struct GC_Configuration *cfg;
  struct ClientServerConnection *sock;
  int left;

  ectx = NULL;
  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
#if START_PEERS
  peers = gnunet_testing_start_daemons ("tcp",
                                        "advertising dht stats",
                                        "/tmp/gnunet-dht-test",
                                        2087, 10000, 2);
  if (peers == NULL)
    {
      GC_free (cfg);
      return -1;
    }
#endif
  if (OK != gnunet_testing_connect_daemons (2087, 12087))
    {
      gnunet_testing_stop_daemons (peers);
      fprintf (stderr, "Failed to connect the peers!\n");
      GC_free (cfg);
      return -1;
    }

  /* wait for DHT's to find each other! */
  sock = client_connection_create (NULL, cfg);
  left = 30;                    /* how many iterations should we wait? */
  while (OK == STATS_getStatistics (NULL, sock, &waitForConnect, NULL))
    {
      printf ("Waiting for peers to DHT-connect (%u iterations left)...\n",
              left);
      sleep (5);
      left--;
      if (left == 0)
        break;
    }
  connection_destroy (sock);
  if (ok == 0)
    {
      gnunet_testing_stop_daemons (peers);
      fprintf (stderr, "Peers' DHTs failed to DHT-connect!\n");
      GC_free (cfg);
      return -1;
    }

  /* switch to peer2 */
  GC_set_configuration_value_string (cfg,
                                     ectx,
                                     "NETWORK", "HOST", "localhost:12087");
  /* verify that peer2 also sees the other DHT! */
  ok = 0;
  sock = client_connection_create (NULL, cfg);
  left = 30;                    /* how many iterations should we wait? */
  while (OK == STATS_getStatistics (NULL, sock, &waitForConnect, NULL))
    {
      printf ("Waiting for peers to DHT-connect (%u iterations left)...\n",
              left);
      sleep (5);
      left--;
      if (left == 0)
        break;
    }
  connection_destroy (sock);
  if (ok == 0)
    {
      gnunet_testing_stop_daemons (peers);
      fprintf (stderr, "Peers' DHTs failed to DHT-connect!\n");
      GC_free (cfg);
      return -1;
    }


  /* switch to peer1 */
  GC_set_configuration_value_string (cfg,
                                     ectx,
                                     "NETWORK", "HOST", "localhost:2087");

  /* actual test code */
  hash ("key2", 4, &key);
  value = MALLOC (8);
  value->size = ntohl (8);
  memset (&value[1], 'A', 4);
  printf ("Peer1 stores key2\n");
  CHECK (OK == DHT_LIB_put (cfg,
                            ectx,
                            &key,
                            DHT_STRING2STRING_BLOCK,
                            get_time () + 5 * cronMINUTES, value));
  printf ("Peer1 gets key2\n");
  CHECK (1 == DHT_LIB_get (cfg,
                           ectx,
                           DHT_STRING2STRING_BLOCK,
                           &key, 2 * cronSECONDS, NULL, NULL));
  /* switch to peer2 */
  GC_set_configuration_value_string (cfg,
                                     ectx,
                                     "NETWORK", "HOST", "localhost:12087");
  hash ("key", 3, &key);
  value = MALLOC (8);
  value->size = ntohl (8);
  memset (&value[1], 'B', 4);
  printf ("Peer2 stores key.\n");
  CHECK (OK == DHT_LIB_put (cfg,
                            ectx,
                            &key,
                            DHT_STRING2STRING_BLOCK,
                            get_time () + 5 * cronMINUTES, value));
  printf ("Peer2 gets key.\n");
  CHECK (1 == DHT_LIB_get (cfg,
                           ectx,
                           DHT_STRING2STRING_BLOCK,
                           &key, 2 * cronSECONDS, NULL, NULL));

  hash ("key2", 4, &key);
  printf ("Peer2 gets key2.\n");
  CHECK (1 == DHT_LIB_get (cfg,
                           ectx,
                           DHT_STRING2STRING_BLOCK,
                           &key, 30 * cronSECONDS, NULL, NULL));
  /* switch to peer1 */
  GC_set_configuration_value_string (cfg,
                                     ectx,
                                     "NETWORK", "HOST", "localhost:2087");
  printf ("Peer1 gets key\n");
  CHECK (1 == DHT_LIB_get (cfg,
                           ectx,
                           DHT_STRING2STRING_BLOCK,
                           &key, 30 * cronSECONDS, NULL, NULL));
  /* end of actual test code */

FAILURE:
#if START_PEERS
  gnunet_testing_stop_daemons (peers);
#endif
  GC_free (cfg);
  return ret;
}

/* end of dhttest2.c */
