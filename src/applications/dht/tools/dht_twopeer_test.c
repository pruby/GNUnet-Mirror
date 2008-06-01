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
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"
#include "dht_api.h"


#define START_PEERS 1


static int ok;
static int peer1count;
static int peer2count;

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

static int
result_callback_peer1 (const GNUNET_HashCode * key,
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
  peer1count--;
  return GNUNET_OK;
}

static int
result_callback_peer2 (const GNUNET_HashCode * key,
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
  peer2count--;
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
  struct GNUNET_DHT_Context *ctx_peer1;
  struct GNUNET_DHT_Context *ctx_peer2;
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
  ctx_peer1 =
    GNUNET_DHT_context_create (cfg, ectx, &result_callback_peer1, NULL);
  left = 50;                    /* how many iterations should we wait? */
  printf ("Waiting for peers to DHT-connect (1->2)");
  while (GNUNET_OK ==
         GNUNET_STATS_get_statistics (NULL, ctx_peer1->sock, &waitForConnect,
                                      NULL))
    {
      printf (".");
      fflush (stdout);
      sleep (2);
      left--;
      if (left == 0)
        break;
    }
  printf (left > 0 ? " OK!\n" : "?\n");
  if (ok == 0)
    {
      GNUNET_TESTING_stop_daemons (peers);
      fprintf (stderr, "Peers' DHTs failed to DHT-connect!\n");
      GNUNET_GC_free (cfg);
      GNUNET_DHT_context_destroy (ctx_peer1);
      return -1;
    }

  /* switch to peer2 */
  GNUNET_GC_set_configuration_value_string (cfg,
                                            ectx,
                                            "NETWORK", "HOST",
                                            "localhost:12087");
  /* verify that peer2 also sees the other DHT! */
  ok = 0;
  ctx_peer2 =
    GNUNET_DHT_context_create (cfg, ectx, &result_callback_peer2, NULL);
  left = 50;                    /* how many iterations should we wait? */
  printf ("Waiting for peers to DHT-connect (2->1)");
  while (GNUNET_OK ==
         GNUNET_STATS_get_statistics (NULL, ctx_peer2->sock, &waitForConnect,
                                      NULL))
    {
      printf (".");
      fflush (stdout);
      sleep (2);
      left--;
      if (left == 0)
        break;
    }
  printf (left > 0 ? " OK!\n" : "?\n");
  if (ok == 0)
    {
      GNUNET_TESTING_stop_daemons (peers);
      fprintf (stderr, "Peers' DHTs failed to DHT-connect!\n");
      GNUNET_GC_free (cfg);
      GNUNET_DHT_context_destroy (ctx_peer1);
      GNUNET_DHT_context_destroy (ctx_peer2);
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
  GNUNET_hash ("key", 3, &key);
  value = GNUNET_malloc (8);
  memset (value, 'B', 8);
  CHECK (GNUNET_OK == GNUNET_DHT_put (cfg,
                                      ectx,
                                      &key,
                                      GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                      8, value));
  GNUNET_hash ("key2", 4, &key);
  peer2count = 10;
  printf ("Getting key 2 from peer 2 (stored at peer 1)");
  do
    {
      printf (".");
      fflush (stdout);
      if (GNUNET_OK == GNUNET_DHT_get_start (ctx_peer2,
                                             GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                             &key))
        break;
    }
  while (peer2count > 0);
  printf (peer2count > 0 ? " OK!\n" : "?\n");

  CHECK (peer2count > 0);

  printf ("Getting key 1 from peer 1 (stored at peer 2)");
  peer1count = 10;
  do
    {
      printf (".");
      fflush (stdout);
      if (GNUNET_OK == GNUNET_DHT_get_start (ctx_peer1,
                                             GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                             &key))
        break;
    }
  while (peer1count > 0);
  printf (peer1count > 0 ? " OK!\n" : "?\n");
  CHECK (peer1count > 0);
  /* end of actual test code */

FAILURE:
#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif
  GNUNET_GC_free (cfg);
  GNUNET_DHT_context_destroy (ctx_peer1);
  GNUNET_DHT_context_destroy (ctx_peer2);
  return ret;
}

/* end of dht_twopeer_test.c */
