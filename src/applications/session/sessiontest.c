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
 * @file applications/session/sessiontest.c
 * @brief Session establishment testcase
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"

#define START_PEERS YES

static int ok;

static int
waitForConnect (const char *name, unsigned long long value, void *cls)
{
  if ((value > 0) && (0 == strcmp (_("# of connected peers"), name)))
    {
      ok = 1;
      return SYSERR;
    }
  return OK;
}

/**
 * Testcase to test p2p session key exchange.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0: ok, -1: error
 */
int
main (int argc, char **argv)
{
#if START_PEERS
  struct DaemonContext *peers;
#endif
  int ret;
  struct ClientServerConnection *sock1;
  struct ClientServerConnection *sock2;
  int left;
  struct GC_Configuration *cfg;

  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
#if START_PEERS
  peers =
    gnunet_testing_start_daemons (NULL ==
                                  strstr (argv[0], "_udp") ? "tcp" : "udp",
                                  "advertising stats",
                                  "/tmp/gnunet-session-test", 2087, 10000, 2);
  if (peers == NULL)
    {
      GC_free (cfg);
      return -1;
    }
#endif
  gnunet_testing_connect_daemons (2087, 12087);
  if (OK == connection_wait_for_running (NULL, cfg, 30 * cronSECONDS))
    {
      sock1 = client_connection_create (NULL, cfg);
      GC_set_configuration_value_string (cfg,
                                         NULL,
                                         "NETWORK",
                                         "HOST", "localhost:12087");
      sock2 = client_connection_create (NULL, cfg);
      left = 30;                /* how many iterations should we wait? */
      while (OK == STATS_getStatistics (NULL, sock1, &waitForConnect, NULL))
        {
          printf ("Waiting for peers to connect (%u iterations left)...\n",
                  left);
          sleep (5);
          left--;
          if (left == 0)
            {
              ret = 1;
              break;
            }
        }
#if 0
      if (ok == 1)
        {
          for (left = 0; left < 10; left++)
            {
              ok = 0;
              while (GNUNET_SHUTDOWN_TEST () == NO)
                {
                  printf ("Checking that peers are staying connected 1...\n");
                  STATS_getStatistics (NULL, sock1, &waitForConnect, NULL);
                  sleep (1);
                  if (ok == 0)
                    {
                      printf ("Peers disconnected!\n");
                      break;
                    }
                  printf ("Checking that peers are staying connected 2...\n");
                  STATS_getStatistics (NULL, sock2, &waitForConnect, NULL);
                  sleep (1);
                  if (ok == 0)
                    {
                      printf ("Peers disconnected!\n");
                      break;
                    }
                }
            }
        }
      else
        {
          printf ("Peers failed to connect!\n");
        }
#endif

      connection_destroy (sock1);
      connection_destroy (sock2);
    }
  else
    {
      printf ("Could not establish connection with peer.\n");
      ret = 1;
    }
#if START_PEERS
  gnunet_testing_stop_daemons (peers);
#endif
  GC_free (cfg);
  return (ok == 0) ? 1 : 0;
}

/* end of sessiontest.c */
