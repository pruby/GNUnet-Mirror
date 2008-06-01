/*
     This file is part of GNUnet.
     (C) 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/dht/tools/dht_multipeer_test.c
 * @brief DHT testcase
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"
#include "dht_api.h"

/**
 * How many peers should the testcase run?  Note that
 * we create a clique topology so the cost is quadratic!
 */
#define NUM_PEERS 8

/**
 * How many times will we try the DHT-GET operation before
 * giving up for good?
 */
#define NUM_ROUNDS 10

static int ok;
static int found;

static int
result_callback (const GNUNET_HashCode * key,
                 unsigned int type,
                 unsigned int size, const char *data, void *cls)
{
  int *i = cls;
  char expect[8];

#if 0
  fprintf (stderr, "Got %u %u `%.*s'\n", type, size, size, data);
#endif
  memset (expect, (*i), sizeof (expect));
  if ((8 != size) ||
      (0 != memcmp (expect, data, size)) ||
      (type != GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING))
    {
      return GNUNET_SYSERR;
    }
  found++;
  return GNUNET_OK;
}


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
 * Testcase to test DHT routing (many peers).
 * @return 0: ok, -1: error
 */
int
main (int argc, const char **argv)
{
  struct GNUNET_TESTING_DaemonContext *peers;
  int ret = 0;
  GNUNET_HashCode key;
  char *value;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_ClientServerConnection *sock;
  struct GNUNET_DHT_Context *ctx_array[NUM_PEERS];
  int left;
  int i;
  int j;
  int k;

  char buf[128];

  ectx = NULL;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  peers = GNUNET_TESTING_start_daemons ("tcp",
                                        "advertising dht stats",
                                        "/tmp/gnunet-dht-test",
                                        2087, 10, NUM_PEERS);
  if (peers == NULL)
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  for (i = 0; i < NUM_PEERS; i++)
    {
      for (j = 0; j < i; j++)
        {
          if (GNUNET_OK != GNUNET_TESTING_connect_daemons (2087 + 10 * i,
                                                           2087 + 10 * j))
            {
              GNUNET_TESTING_stop_daemons (peers);
              fprintf (stderr, "Failed to connect the peers!\n");
              GNUNET_GC_free (cfg);
              return -1;
            }
        }
    }

  /* put loop */
  for (i = 0; i < NUM_PEERS; i++)
    {
      GNUNET_snprintf (buf, 128, "localhost:%u", 2087 + i * 10);
      GNUNET_GC_set_configuration_value_string (cfg, ectx, "NETWORK", "HOST",
                                                buf);
      /* wait for some DHT's to find each other! */
      sock = GNUNET_client_connection_create (NULL, cfg);
      left = 30;                /* how many iterations should we wait? */
      printf ("Waiting for peer %u to DHT-connect", i);
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
      GNUNET_hash (buf, 4, &key);
      value = GNUNET_malloc (8);
      memset (value, 'A' + i, 8);
      CHECK (GNUNET_OK == GNUNET_DHT_put (cfg,
                                          ectx,
                                          &key,
                                          GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                          8, value));
      GNUNET_free (value);
    }

  /* get loop */
  found = 0;
  for (i = 0; i < NUM_PEERS; i++)
    {
      GNUNET_snprintf (buf, 128, "localhost:%u", 2087 + i * 10);
      GNUNET_GC_set_configuration_value_string (cfg,
                                                ectx, "NETWORK", "HOST", buf);
      ctx_array[i] =
        GNUNET_DHT_context_create (cfg, ectx, &result_callback, NULL);
      for (j = 0; j < NUM_PEERS; j++)
        {
          GNUNET_snprintf (buf, 128, "localhost:%u", 2087 + j * 10);
          GNUNET_hash (buf, 4, &key);
          printf ("Peer %d gets key %d", i, j);
          for (k = 0; k < NUM_ROUNDS; k++)
            {
              printf (".");
              fflush (stdout);
              if (0 < GNUNET_DHT_get_start (ctx_array[i],
                                            GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                            &key))
                break;
            }
          if (k < NUM_ROUNDS)
            {
              printf (" OK!\n");
            }
          else
            {
              printf ("?\n");
            }
        }
    }

  for (i = 0; i < NUM_PEERS; i++)
    {
      GNUNET_DHT_context_destroy (ctx_array[i]);
    }
  /* end of actual test code */
  printf ("Found %u out of %u attempts.\n", found, NUM_PEERS * NUM_PEERS);
FAILURE:
  GNUNET_TESTING_stop_daemons (peers);
  GNUNET_GC_free (cfg);
  return ret;
}

/* end of dht_multipeer_test.c */
