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
 * @file applications/testing/testingtest_loop.c
 * @brief GAP economy testcase, download from star topology
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_testing_lib.h"
#include "gnunet_identity_lib.h"
#include "gnunet_util.h"

#define LOOP_COUNT 10

#define PEER_COUNT 10

/**
 * Testcase to test testing's connection establishment
 * @return 0: ok, -1: error
 */
int
main (int argc, char **argv)
{
  struct GNUNET_TESTING_DaemonContext *peers;
  int j;
  int i;

  for (j = 0; j < LOOP_COUNT; j++)
    {
      peers = GNUNET_TESTING_start_daemons ("tcp",
                                            "advertising topology stats",
                                            "/tmp/gnunet-testing-test-loop",
                                            2087, 10, PEER_COUNT);
      if (peers == NULL)
        {
          fprintf (stderr, "Failed to start the gnunetd daemons!\n");
          return -1;
        }
      /* connect as star-topology */
      for (i = 1; i < PEER_COUNT; i++)
        {
          if (GNUNET_OK !=
              GNUNET_TESTING_connect_daemons (2087, 2087 + 10 * i))
            {
              GNUNET_TESTING_stop_daemons (peers);
              fprintf (stderr, "Failed to connect the peers!\n");
              return -1;
            }
        }
      GNUNET_TESTING_stop_daemons (peers);
    }
  return 0;
}

/* end of testingtest_loop.c */
