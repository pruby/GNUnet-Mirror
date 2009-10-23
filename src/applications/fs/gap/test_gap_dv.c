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
 * @file applications/fs/gap/test_gap_dv.c
 * @brief DV_DHT testcase
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"
#include "gnunet_remote_lib.h"

/**
 * How many peers should the testcase run?  Note that
 * we create a clique topology so the cost is quadratic!
 */
#define NUM_PEERS 15

/**
 * How many times will we try the DV_DHT-GET operation before
 * giving up for good?
 */
#define NUM_ROUNDS 20

/**
 * How often do we iterate the put-get loop?
 */
#define NUM_REPEAT 20

static int ok;

static int
waitForConnect (const char *name, unsigned long long value, void *cls)
{
  if ((value > 0) && (0 == strcmp (_("# dv_dht connections"), name)))
    {
      ok = 1;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

static int
getPeers (const char *name, unsigned long long value, void *cls)
{
  if ((value > 0) && (strstr (name, _("# dv")) != NULL))
    {
      fprintf (stderr, "%s : %llu\n", name, value);
    }

  if ((value > 0) && (0 == strcmp (_("# dv_dht connections"), name)))
    {
      ok = 1;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

#define CHECK(a) do { if (!(a)) { ret = 1; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; } } while(0)

/**
 * Testcase to test DV_DHT routing (many peers).
 * @return 0: ok, -1: error
 */
int
main (int argc, const char **argv)
{
  struct GNUNET_REMOTE_TESTING_DaemonContext *peers;
  struct GNUNET_REMOTE_TESTING_DaemonContext *peer_array[NUM_PEERS];
  struct GNUNET_REMOTE_TESTING_DaemonContext *pos;
  int ret = 0;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_ClientServerConnection *sock;
  int left;
  int i;
  int r;
  char buf[128];

  ectx = NULL;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "gap_test.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  GNUNET_GC_set_configuration_value_string (cfg, NULL,
                                            "MULTIPLE_SERVER_TESTING",
                                            "DOT_OUTPUT", "topology.dot");
  printf ("Starting %u peers...\n", NUM_PEERS);
  GNUNET_REMOTE_start_daemons (&peers, cfg, NUM_PEERS);
  if (peers == NULL)
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  pos = peers;
  for (i = 0; i < NUM_PEERS; i++)
    {
      peer_array[i] = pos;
      pos = pos->next;
    }
  sleep (30);
  fprintf (stdout, "Will run for %d minues\n", NUM_REPEAT);
  for (r = 0; r < NUM_REPEAT; r++)
    {
      fprintf (stderr, "After %d minutes\n", r);
      for (i = 0; i < NUM_PEERS; i++)
        {
          if (GNUNET_shutdown_test () == GNUNET_YES)
            break;
          fprintf (stderr, "Peer %d: ", i);
          sock =
            GNUNET_client_connection_create (NULL, peer_array[i]->config);
          GNUNET_STATS_get_statistics (NULL, sock, &getPeers, NULL);
          GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
          GNUNET_client_connection_destroy (sock);

        }
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
      sleep (60);
    }

  for (r = 0; r < NUM_REPEAT; r++)
    {
      for (i = 0; i < NUM_PEERS; i++)
        {
          if (GNUNET_shutdown_test () == GNUNET_YES)
            break;
          fprintf (stderr, "Peer %d: ", i);
          sock =
            GNUNET_client_connection_create (NULL, peer_array[i]->config);
          GNUNET_STATS_get_statistics (NULL, sock, &getPeers, NULL);
          GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
          GNUNET_client_connection_destroy (sock);

        }
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;

      printf ("Waiting for DV_DHT connections of peer");
      for (i = 0; i < NUM_PEERS; i++)
        {
          if (GNUNET_shutdown_test () == GNUNET_YES)
            break;
          ok = 0;
          printf (" %d", i);
          fflush (stdout);
          GNUNET_snprintf (buf, sizeof (buf), "localhost:%u", 2087 + i * 10);
          /* wait for some DV_DHT's to find each other! */
          sock =
            GNUNET_client_connection_create (NULL, peer_array[i]->config);
          left = 30;            /* how many iterations should we wait? */
          while (GNUNET_OK ==
                 GNUNET_STATS_get_statistics (NULL, sock, &waitForConnect,
                                              NULL))
            {
              if (GNUNET_shutdown_test () == GNUNET_YES)
                break;
              if (9 == left % 10)
                printf (".");
              fflush (stdout);
              GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
              left--;
              if (left == 0)
                break;
            }
          GNUNET_client_connection_destroy (sock);
          if (ok == 0)
            {
              printf ("ERROR!\n");
              fflush (stdout);
              pos = peers;
              while (pos != NULL)
                {
                  GNUNET_REMOTE_kill_daemon (pos);
                  pos = pos->next;
                }
              fprintf (stderr, "Peers' DV_DHTs failed to DV_DHT-connect!\n");
              GNUNET_GC_free (cfg);
              return -1;
            }

        }
    }
  /* end of actual test code */

  pos = peers;
  while (pos != NULL)
    {
      GNUNET_REMOTE_kill_daemon (pos);
      pos = pos->next;
    }
  GNUNET_GC_free (cfg);
  return ret;
}

/* end of test_gap_dv.c */
