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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file applications/chat/chattest.c
 * @brief chat testcase, loopback only
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_chat_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"

#define START_PEERS 1

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_ClientServerConnection *sock;



/**
 * Testcase to test chat.
 * @return 0: ok, -1: error
 */
int
main (int argc, char **argv)
{
  struct GNUNET_TESTING_DaemonContext *peers;
  int ret;
  struct GNUNET_CHAT_Room *r1;
  struct GNUNET_CHAT_Room *r2;

  ret = 0;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_PEERS
  peers = GNUNET_TESTING_start_daemons ("",
                                        "chat stats",
                                        "/tmp/gnunet-chat-test", 2087, 10, 1);
  if (peers == NULL)
    {
      fprintf (stderr, "Failed to start the gnunetd daemon!\n");
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  r1 = GNUNET_CHAT_join_room (...);

  GNUNET_CHAT_leave_room (r1);

  GNUNET_shutdown_wait_for ();

#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif

  GNUNET_GC_free (cfg);
  return 0;
}

/* end of chattest.c */
