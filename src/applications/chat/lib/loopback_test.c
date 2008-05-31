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
#include "gnunet_ecrs_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"
#include "gnunet_core.h"

#define START_PEERS 1

static struct GNUNET_GC_Configuration *cfg;

static int
receive_callback1 (void *cls,
                   struct GNUNET_CHAT_Room *room,
                   const GNUNET_HashCode * sender,
		   const struct GNUNET_ECRS_MetaData * member_info,
                   const char *message,
		   GNUNET_CHAT_MSG_OPTIONS options)
{

  return GNUNET_OK;
}

static int
member_list_callback1 (void *cls,
		       const struct GNUNET_ECRS_MetaData * member_info,
		       const GNUNET_RSA_PublicKey * member_id) 
{
  return GNUNET_OK;
}

static int
receive_callback2 (void *cls,
                   struct GNUNET_CHAT_Room *room,
                   const GNUNET_HashCode * sender,
		   const struct GNUNET_ECRS_MetaData * member_info,
                   const char *message,
		   GNUNET_CHAT_MSG_OPTIONS options)
{
  return GNUNET_OK;
}

static int
member_list_callback2 (void *cls,
		       const struct GNUNET_ECRS_MetaData * member_info,
		       const GNUNET_RSA_PublicKey * member_id) 
{
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
  unsigned int seq;
  struct GNUNET_ECRS_MetaData * meta1;
  struct GNUNET_ECRS_MetaData * meta2;

  ret = 0;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  GNUNET_disable_entropy_gathering ();
#if START_PEERS
  peers = GNUNET_TESTING_start_daemons ("tcp",
                                        "chat stats",
                                        "/tmp/gnunet-chat-test/",
                                        2087, 10, 1);
  if (peers == NULL)
    {
      fprintf (stderr, "Failed to start the gnunetd daemon!\n");
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  meta1 = GNUNET_ECRS_meta_data_create();
  GNUNET_ECRS_meta_data_insert(meta1,
			       EXTRACTOR_TITLE,
			       "Alice");
  meta2 = GNUNET_ECRS_meta_data_create();
  GNUNET_ECRS_meta_data_insert(meta2,
			       EXTRACTOR_TITLE,
			       "Bob");
  r1 =
    GNUNET_CHAT_join_room (NULL, cfg, "nick1", 
			   meta1, "test", -1,
                           &receive_callback1, NULL, 
			   &member_list_callback1, NULL,
			   NULL, NULL);
  if (r1 == NULL)
    {
      ret = 1;
      goto CLEANUP;
    }
  r2 =
    GNUNET_CHAT_join_room (NULL, cfg, "nick2",
			   meta2, "test", -1, 
                           &receive_callback2, NULL, 
			   &member_list_callback2, NULL,
			   NULL, NULL);
  if (r2 == NULL)
    {
      ret = 1;
      goto CLEANUP;
    }

  GNUNET_CHAT_send_message (r1, "test message 1",
                            GNUNET_CHAT_MSG_OPTION_NONE, NULL, &seq);

  GNUNET_CHAT_send_message (r2, "test message 2", 
                            GNUNET_CHAT_MSG_OPTION_NONE, NULL, &seq);

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

/* end of loopback_test.c */
