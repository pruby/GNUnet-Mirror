/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/hostlist/hostlisttest.c
 * @brief testcase for hostlist server
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"

#define START_PEERS GNUNET_YES

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
 * Testcase to test hostlist.
 */
int
main (int argc, char **argv)
{
#if START_PEERS
  pid_t peer1;
  pid_t peer2;
#endif
  int ret;
  struct GNUNET_ClientServerConnection *sock1;
  int left;
  struct GNUNET_GC_Configuration *cfg;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_PEERS
  GNUNET_disk_directory_remove (NULL, "/tmp/gnunet-hostlist-test-server");
  GNUNET_disk_directory_remove (NULL, "/tmp/gnunet-hostlist-test-client");
  peer1 = GNUNET_daemon_start (NULL, cfg, "tcp-peer.conf", GNUNET_NO);
  if (peer1 == -1)
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  peer2 = GNUNET_daemon_start (NULL, cfg, "nat-peer.conf", GNUNET_NO);
  if (peer2 == -1)
    {
      GNUNET_daemon_stop (NULL, peer1);
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  if (GNUNET_OK ==
      GNUNET_wait_for_daemon_running (NULL, cfg, 30 * GNUNET_CRON_SECONDS))
    {
      GNUNET_thread_sleep (GNUNET_CRON_SECONDS);        /* give stats time to load! */
      sock1 = GNUNET_client_connection_create (NULL, cfg);
      left = 30;                /* how many iterations should we wait? */
      while (GNUNET_OK ==
             GNUNET_STATS_get_statistics (NULL, sock1, &waitForConnect, NULL))
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
      GNUNET_client_connection_destroy (sock1);
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

/* end of hostlisttest.c */
