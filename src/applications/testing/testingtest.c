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
 * @file applications/testing/testingtest.c
 * @brief testcase for testing library
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_testing_lib.h"

/**
 * Testcase
 * @return 0: ok, -1: error
 */
int
main (int argc, const char **argv)
{
  pid_t daemon1;
  pid_t daemon2;
  PeerIdentity p1;
  PeerIdentity p2;
  char *c1 = NULL;
  char *c2 = NULL;
  int ret = 0;

  if (OK != gnunet_testing_start_daemon (12087,
                                         10000,
                                         "/tmp/gnunet-testing-1",
                                         "tcp",
                                         "advertising stats",
                                         &daemon1, &p1, &c1))
    ret |= 1;
  if (OK != gnunet_testing_start_daemon (22087,
                                         20000,
                                         "/tmp/gnunet-testing-2",
                                         "tcp",
                                         "advertising stats",
                                         &daemon2, &p2, &c2))
    ret |= 2;
  if (OK != gnunet_testing_connect_daemons (12087, 22087))
    ret |= 4;
  if (OK != gnunet_testing_stop_daemon (12087, daemon1))
    ret |= 8;
  if (OK != gnunet_testing_stop_daemon (22087, daemon2))
    ret |= 16;
  if (c1 != NULL)
    {
      UNLINK (c1);
      FREE (c1);
    }
  if (c2 != NULL)
    {
      UNLINK (c2);
      FREE (c2);
    }
  return ret;
}

/* end of testingtest.c */
