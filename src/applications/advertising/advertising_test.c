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
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"

#define NUM_PEERS 12

#define NUM_ROUNDS 10

static int
countConnections (const char *name, unsigned long long value, void *cls)
{
  int *num = cls;
  if (0 == strcmp (_("# of connected peers"), name))
    {
      *num = value;
      return SYSERR;
    }
  return OK;
}

/**
 * Testcase to test advertising
 * @return 0: ok, -1: error
 */
int
main (int argc, const char **argv)
{
  struct DaemonContext *peers;
  int ret = 0;
  struct GE_Context *ectx;
  struct GC_Configuration *cfg;
  struct ClientServerConnection *sock;
  int i;
  int k;
  int have;
  int found;
  char buf[128];
  int min;

  ectx = NULL;
  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
  peers =
    gnunet_testing_start_daemons (NULL ==
                                  strstr (argv[0], "_udp") ? "tcp" : "udp",
                                  "advertising stats",
                                  "/tmp/gnunet-advertising-test", 2087, 10,
                                  NUM_PEERS);
  if (peers == NULL)
    {
      GC_free (cfg);
      return -1;
    }
  /* do circular connect */
  for (i = 0; i < NUM_PEERS; i++)
    {
      if (OK != gnunet_testing_connect_daemons (2087 + 10 * i,
                                                2087 +
                                                10 * ((i + 1) % NUM_PEERS)))
        {
          gnunet_testing_stop_daemons (peers);
          fprintf (stderr,
                   "Failed to connect peers %d and %d!\n",
                   i, (i + 1) % NUM_PEERS);
          GC_free (cfg);
          return -1;
        }
    }
  PTHREAD_SLEEP (15 * cronSECONDS);

  /* check loops */
  for (k = 0; k < NUM_ROUNDS; k++)
    {
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
      found = 0;
      min = NUM_PEERS;
      for (i = 0; i < NUM_PEERS; i++)
        {
          SNPRINTF (buf, 128, "localhost:%u", 2087 + i * 10);
          GC_set_configuration_value_string (cfg,
                                             ectx, "NETWORK", "HOST", buf);
          sock = client_connection_create (NULL, cfg);
          STATS_getStatistics (NULL, sock, &countConnections, &have);
          connection_destroy (sock);
          found += have;
          if (have < min)
            min = have;
        }
      fprintf (stderr,
               "Have %d connections total in round %d, minimum number was %d\n",
               found, k, min);
      if (k < NUM_ROUNDS - 1)
        PTHREAD_SLEEP (45 * cronSECONDS);       /* one hello-forward round is 45s! */
    }
  gnunet_testing_stop_daemons (peers);
  GC_free (cfg);
  return ret;
}

/* end of dhttest.c */
