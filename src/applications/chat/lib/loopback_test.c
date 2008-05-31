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
 * @file applications/chat/lib/loopback_test.c
 * @brief chat testcase, loopback only
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_chat_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"
#include "gnunet_core.h"

#define START_PEERS 1

static struct GNUNET_GC_Configuration *cfg;

static int
receive_callback1 (void *cls,
                   struct GNUNET_CHAT_Room *room,
                   const char *senderNick,
                   const char *message,
                   GNUNET_CronTime timestamp, GNUNET_CHAT_MSG_OPTIONS options)
{
  fprintf (stdout, _("`%s' said: %s\n"), senderNick, message);
  return GNUNET_OK;
}

static int
member_list_callback1 (void *cls, const char *senderNick,
                       int is_joining, GNUNET_CronTime timestamp)
{
  fprintf (stdout, is_joining
           ? _("`%s' entered the room\n")
           : _("`%s' left the room\n"), senderNick);
  return GNUNET_OK;
}

static int
receive_callback2 (void *cls,
                   struct GNUNET_CHAT_Room *room,
                   const char *senderNick,
                   const char *message,
                   GNUNET_CronTime timestamp, GNUNET_CHAT_MSG_OPTIONS options)
{
  fprintf (stdout, _("`%s' said: %s\n"), senderNick, message);
  return GNUNET_OK;
}

static int
member_list_callback2 (void *cls, const char *senderNick,
                       int is_joining, GNUNET_CronTime timestamp)
{
  fprintf (stdout, is_joining
           ? _("`%s' entered the room\n")
           : _("`%s' left the room\n"), senderNick);
  return GNUNET_OK;
}



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
  GNUNET_RSA_PublicKey me;
  struct GNUNET_RSA_PrivateKey *key = NULL;

  ret = 0;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  GNUNET_disable_entropy_gathering ();
  key = GNUNET_RSA_create_key ();
  GNUNET_RSA_get_public_key (key, &me);
#if START_PEERS
  peers = GNUNET_TESTING_start_daemons ("tcp",
                                        "chat stats",
                                        "/tmp/gnunet-chat-test/",
                                        2087, 10, 1);
  if (peers == NULL)
    {
      fprintf (stderr, "Failed to start the gnunetd daemons!\n");
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  r1 =
    GNUNET_CHAT_join_room (NULL, cfg, "nicktest1", "testroom", &me, key, "",
                           &receive_callback1, NULL, &member_list_callback1,
                           NULL);
  if (r1 == NULL)
    {
      ret = 1;
      goto CLEANUP;
    }
  r2 =
    GNUNET_CHAT_join_room (NULL, cfg, "nicktest2", "testroom", &me, key, "",
                           &receive_callback2, NULL, &member_list_callback2,
                           NULL);
  if (r2 == NULL)
    {
      ret = 1;
      goto CLEANUP;
    }

  GNUNET_CHAT_send_message (r1, "test message 1", NULL, NULL,
                            GNUNET_CHAT_MSG_OPTION_NONE, NULL);

  GNUNET_CHAT_send_message (r2, "test message 2", NULL, NULL,
                            GNUNET_CHAT_MSG_OPTION_NONE, NULL);

CLEANUP:
  if (r1 != NULL)
    GNUNET_CHAT_leave_room (r1);
  if (r2 != NULL)
    GNUNET_CHAT_leave_room (r2);

#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif
  GNUNET_GC_free (cfg);
  return ret;
}

/* end of chattest.c */
