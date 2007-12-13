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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file applications/tracekit/tracekittest.c
 * @brief tracekit testcase, linear topology
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_tracekit_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"

#define START_PEERS 1

#define PEER_COUNT 4

#define TEST_DEPTH PEER_COUNT

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static int
report (void *unused,
	const GNUNET_PeerIdentity * reporter,
	const GNUNET_PeerIdentity * link)
{
  GNUNET_EncName src;
  GNUNET_EncName dst;

  GNUNET_hash_to_enc (&reporter->hashPubKey, &src);
  if (link != NULL)
    {
      GNUNET_hash_to_enc (&link->hashPubKey, &dst);
      fprintf (stdout,
               _("`%s' connected to `%s'.\n"),
               (const char *) &src, (const char *) &dst);
    }
  else
    {
      fprintf (stdout,
               _("`%s' is not connected to any peer.\n"),
               (const char *) &src);
    }
  return GNUNET_OK;
}

/**
 * Testcase to test tracekit
 * @return 0: ok, -1: error
 */
int
main (int argc, char **argv)
{
  struct GNUNET_TESTING_DaemonContext *peers;
  struct GNUNET_ClientServerConnection *sock;
  int ret;
  int i;

  ret = 0;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_PEERS
  peers = GNUNET_TESTING_start_daemons ("tcp",
                                        "advertising topology tracekit stats",
                                        "/tmp/gnunet-tracekit-test",
                                        2087, 10, PEER_COUNT);
  if (peers == NULL)
    {
      fprintf (stderr, "Failed to start the gnunetd daemons!\n");
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  for (i = 1; i < PEER_COUNT; i++)
    {
      if (GNUNET_OK != GNUNET_TESTING_connect_daemons (2077 + (10 * i),
                                                       2087 + (10 * i)))
        {
          GNUNET_TESTING_stop_daemons (peers);
          fprintf (stderr, "Failed to connect the peers!\n");
          GNUNET_GC_free (cfg);
          return -1;
        }
    }
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
      GNUNET_fini (ectx, cfg);
      return 1;
    }
  ret = 0; /* FIXME: set to 1 here, to 0 in report! */
  GNUNET_TRACEKIT_run (sock, TEST_DEPTH, 0, &report, &ret);
  GNUNET_client_connection_destroy (sock);

#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif

  GNUNET_GC_free (cfg);
  return ret;
}

/* end of tracekittest.c */
