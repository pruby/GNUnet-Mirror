/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/advertising/advertising_test.c
 * @brief testcase to show advertising works; mostly,
 *        the test should display a roughly increasing
 *        number of overall connections; given enough
 *        time (more than what is given by default),
 *        the number should approach 100.
 *
 *        Note that data in /tmp (esp. data/hosts/ *)
 *        will mess with the results...
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"

#define NUM_PEERS 6

#define NUM_ROUNDS 5

static int
countConnections (const char *name, unsigned long long value, void *cls)
{
  int *num = cls;
  if (0 == strcmp (_("# of connected peers"), name))
    {
      *num = value;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * Testcase to test advertising
 * @return 0: ok, -1: error
 */
int
main (int argc, const char **argv)
{
  struct GNUNET_TESTING_DaemonContext *peers;
  int ret = 0;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_ClientServerConnection *sock;
  int i;
  int k;
  int have;
  int found;
  char buf[128];
  int min;

  ectx = NULL;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  peers =
    GNUNET_TESTING_start_daemons (strstr (argv[0], "_") + 1,
                                  "advertising stats",
                                  "/tmp/gnunet-advertising-test", 12087, 10,
                                  NUM_PEERS);
  if (peers == NULL)
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  /* do circular connect */
  for (i = 0; i < NUM_PEERS; i++)
    {
      if (GNUNET_OK != GNUNET_TESTING_connect_daemons (12087 + 10 * i,
                                                       12087 +
                                                       10 * ((i + 1) %
                                                             NUM_PEERS)))
        {
          GNUNET_TESTING_stop_daemons (peers);
          fprintf (stderr,
                   "Failed to connect peers %d and %d!\n",
                   i, (i + 1) % NUM_PEERS);
          GNUNET_GC_free (cfg);
          return -1;
        }
    }
  GNUNET_thread_sleep (15 * GNUNET_CRON_SECONDS);

  /* check loops */
  for (k = 0; k < NUM_ROUNDS; k++)
    {
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
      found = 0;
      min = NUM_PEERS;
      for (i = 0; i < NUM_PEERS; i++)
        {
          GNUNET_snprintf (buf, 128, "localhost:%u", 12087 + i * 10);
          GNUNET_GC_set_configuration_value_string (cfg,
                                                    ectx, "NETWORK", "HOST",
                                                    buf);
          sock = GNUNET_client_connection_create (NULL, cfg);
          have = -1;
          GNUNET_STATS_get_statistics (NULL, sock, &countConnections, &have);
          GNUNET_client_connection_destroy (sock);
          if (have == -1)
            {
              fprintf (stderr, "Trouble getting statistics!\n");
            }
          else
            {
              found += have;
              if (have < min)
                min = have;
            }
        }
      fprintf (stderr,
               "Have %d connections total in round %d, minimum number was %d\n",
               found, k, min);
      if (k < NUM_ROUNDS - 1)
        GNUNET_thread_sleep (45 * GNUNET_CRON_SECONDS); /* one hello-forward round is 45s! */
    }
  GNUNET_TESTING_stop_daemons (peers);
  GNUNET_GC_free (cfg);
  return ret;
}

/* end of advertising_test.c */
