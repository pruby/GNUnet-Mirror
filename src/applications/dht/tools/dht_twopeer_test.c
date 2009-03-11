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


#define START_PEERS 1

#define NUM_ROUNDS 100

#define CHECK(a) do { if (!(a)) { ret = 1; GNUNET_GE_BREAK(NULL, 0); goto FAILURE; } } while(0)

struct PeerData 
{
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_DHT_Context *ctx_peer;
  struct GNUNET_ClientServerConnection *sock;
  int peercount;  
  int expect_i;
};

static int
test_connected(struct GNUNET_ClientServerConnection *sock)
{
  int left = 50;
  unsigned long long have;
  while (0 == (have = GNUNET_DHT_test_connected(sock)))
    {
      printf ("."); fflush (stdout);
      sleep (2);
      left--;
      if (left == 0)
        break;
    }
  printf ((have > 0) ? " OK!\n" : "?\n");
  return have > 0;
}

static int
result_callback (const GNUNET_HashCode * key,
		 unsigned int type,
		 unsigned int size, const char *data, void *cls)
{
  struct PeerData * pd = cls;
  char expect[8];

#if 0
  fprintf (stderr, "Got %u %u `%.*s'\n", type, size, size, data);
#endif
  memset (expect, pd->expect_i, sizeof (expect));
  if ((8 != size) ||
      (0 != memcmp (expect, data, size)) ||
      (type != GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING))
    return GNUNET_SYSERR;
  pd->peercount--;
  return GNUNET_OK;
}

static int
setup_peer(struct PeerData * pd,
	   const char * pstr)
{
  int ret = 0;
  pd->cfg = GNUNET_GC_create ();
  CHECK (-1 != GNUNET_GC_parse_configuration (pd->cfg, "check.conf"));
  GNUNET_GC_set_configuration_value_string (pd->cfg,
                                            NULL,
                                            "NETWORK", "HOST",
                                            "localhost:22087");
  pd->sock = GNUNET_client_connection_create (NULL, pd->cfg);
  pd->ctx_peer =
    GNUNET_DHT_context_create (pd->cfg, NULL, &result_callback, pd);
 FAILURE:
  return ret;
}

static void
free_peer (struct PeerData * pd)
{
  if (NULL != pd->ctx_peer)
    GNUNET_DHT_context_destroy (pd->ctx_peer);
  if (NULL != pd->sock)
    GNUNET_client_connection_destroy (pd->sock);
  if (NULL != pd->cfg)
    GNUNET_GC_free (pd->cfg);
}

static int
put_at_peer(struct PeerData * pd,
	    const char * keys,
	    int val)
{
  int ret = 0;
  char value[8];
  GNUNET_HashCode key;

  GNUNET_hash (keys, 5, &key);
  memset (value, val, sizeof (value));
  CHECK (GNUNET_OK == GNUNET_DHT_put (pd->cfg,
                                      NULL,
                                      &key,
                                      GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
                                      sizeof (value), value));
 FAILURE:
  return ret;
}

static int
get_at_peer(struct PeerData * pd,
	    const char * keys,
	    int want)
{
  int ret = 0;
  GNUNET_HashCode key;
  struct GNUNET_DHT_GetRequest *get;
  int k;

  GNUNET_hash (keys, 5, &key);
  pd->peercount = 10;
  pd->expect_i = want;
  CHECK (NULL != (get = GNUNET_DHT_get_start (pd->ctx_peer,
					      GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING,
					      &key)));
  for (k = 0; k < NUM_ROUNDS; k++)
    {
      if (0 == (k % 10))
        printf (".");
      fflush (stdout);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (pd->peercount < 10)
        break;
    }
  CHECK (GNUNET_OK == GNUNET_DHT_get_stop (pd->ctx_peer, get));
  printf (pd->peercount < 10 ? " OK!\n" : "?\n");
  CHECK (pd->peercount < 10);
 FAILURE:
  return ret;
}


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
  struct PeerData p1;
  struct PeerData p2;

  memset(&p1, 0, sizeof(struct PeerData));
  memset(&p2, 0, sizeof(struct PeerData));
#if START_PEERS
  fprintf (stderr, "Starting peers...\n");
  peers = GNUNET_TESTING_start_daemons ("tcp",
                                        "advertising dht stats",
                                        "/tmp/gnunet-dht-two-test",
                                        22087, 10, 2);
  CHECK (peers != NULL);
#endif 
  CHECK(0 == setup_peer(&p1, "localhost:22087"));
  CHECK(0 == setup_peer(&p2, "localhost:22097"));
  fprintf (stderr, "Connecting peers...\n");
  CHECK (GNUNET_OK == GNUNET_TESTING_connect_daemons (22087, 22097));


  /* wait for DHT's to find each other! */
  /* verify that peer2 also sees the other DHT! */
  printf ("Waiting for peers to DHT-connect (1->2)");
  CHECK (test_connected(p1.sock));
  printf ("Waiting for peers to DHT-connect (2->1)");
  CHECK (test_connected(p2.sock));

  /* actual test code */
  CHECK (0 == put_at_peer (&p1, "key 1", 'A'));
  CHECK (0 == put_at_peer (&p2, "key 2", 'B'));
  printf ("DHT get (1->1)");
  CHECK (0 == get_at_peer (&p1, "key 1", 'A'));
  printf ("DHT get (2->2");
  CHECK (0 == get_at_peer (&p2, "key 2", 'B'));
  printf ("DHT get (1->2)");
  CHECK (0 == get_at_peer (&p1, "key 2", 'B'));
  printf ("DHT get (2->1)");
  CHECK (0 == get_at_peer (&p2, "key 1", 'A'));
  /* end of actual test code */

FAILURE:
#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif
  free_peer(&p1);
  free_peer(&p2);
  return ret;
}

/* end of dht_twopeer_test.c */
