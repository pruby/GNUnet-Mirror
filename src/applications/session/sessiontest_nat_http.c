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
 * @file applications/session/sessiontest_nat_http.c
 * @brief Session establishment testcase for NAT over HTTP
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_identity_lib.h"
#include "gnunet_stats_lib.h"

#define START_PEERS 1

static int ok;

static int
waitForConnect (const char *name, unsigned long long value, void *cls)
{
  if ((value > 0) && (0 == strcmp (_("# of connected peers"), name)))
    {
      ok = 1;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


/**
 * Notify NATed peer about other peer.
 *
 * @param port1 client port of the first daemon
 * @param port2 client port of the second daemon
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
connect_daemons (unsigned short port1, unsigned short port2)
{
  char host[128];
  struct GNUNET_GC_Configuration *cfg1 = GNUNET_GC_create ();
  struct GNUNET_GC_Configuration *cfg2 = GNUNET_GC_create ();
  struct GNUNET_ClientServerConnection *sock1;
  struct GNUNET_ClientServerConnection *sock2;
  int ret;
  GNUNET_MessageHello *h1;

  ret = GNUNET_SYSERR;
  GNUNET_snprintf (host, 128, "localhost:%u", port1);
  GNUNET_GC_set_configuration_value_string (cfg1, NULL, "NETWORK", "HOST",
                                            host);
  GNUNET_snprintf (host, 128, "localhost:%u", port2);
  GNUNET_GC_set_configuration_value_string (cfg2, NULL, "NETWORK", "HOST",
                                            host);
  if ((GNUNET_OK ==
       GNUNET_wait_for_daemon_running (NULL, cfg1, 300 * GNUNET_CRON_SECONDS))
      && (GNUNET_OK ==
          GNUNET_wait_for_daemon_running (NULL, cfg2,
                                          300 * GNUNET_CRON_SECONDS)))
    {
      sock1 = GNUNET_client_connection_create (NULL, cfg1);
      sock2 = GNUNET_client_connection_create (NULL, cfg2);
      if ((sock1 != NULL) && (sock2 != NULL))
        {
          h1 = NULL;
          fprintf (stderr, "Notifying NATed peer about other peer");
          if ((GNUNET_OK == GNUNET_IDENTITY_get_self (sock1,
                                                      &h1)) &&
              (GNUNET_OK == GNUNET_IDENTITY_peer_add (sock2, h1)))
            {
              fprintf (stderr, "!\n");
              ret = GNUNET_OK;
            }
          else
            fprintf (stderr, "?\n");
          GNUNET_free_non_null (h1);
        }
      if (sock1 != NULL)
        GNUNET_client_connection_destroy (sock1);
      if (sock2 != NULL)
        GNUNET_client_connection_destroy (sock2);
    }
  else
    {
      fprintf (stderr, "Failed to establish connection with peers.\n");
    }
  GNUNET_GC_free (cfg1);
  GNUNET_GC_free (cfg2);
  return ret;
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
  pid_t peer1;
  pid_t peer2;
#endif
  int ret;
  struct GNUNET_ClientServerConnection *sock;
  int left;
  struct GNUNET_GC_Configuration *cfg;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_PEERS
  peer1 = GNUNET_daemon_start (NULL, cfg, "http-peer.conf", GNUNET_NO);
  if (peer1 == -1)
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  peer2 = GNUNET_daemon_start (NULL, cfg, "nat-http-peer.conf", GNUNET_NO);
  if (peer2 == -1)
    {
      GNUNET_daemon_stop (NULL, peer1);
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  connect_daemons (2087, 12087);
  if (GNUNET_OK ==
      GNUNET_wait_for_daemon_running (NULL, cfg, 30 * GNUNET_CRON_SECONDS))
    {
      sock = GNUNET_client_connection_create (NULL, cfg);
      left = 30;                /* how many iterations should we wait? */
      while (GNUNET_OK ==
             GNUNET_STATS_get_statistics (NULL, sock, &waitForConnect, NULL))
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
      GNUNET_client_connection_destroy (sock);
    }
  else
    {
      printf ("Could not establish connection with peer.\n");
      ret = 1;
    }
#if START_PEERS
  GNUNET_daemon_stop (NULL, peer1);
  GNUNET_daemon_stop (NULL, peer2);
#endif
  GNUNET_GC_free (cfg);
  return (ok == 0) ? 1 : 0;
}

/* end of sessiontest_nat_http.c */
