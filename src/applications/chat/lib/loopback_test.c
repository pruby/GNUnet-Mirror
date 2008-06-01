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
 *
 * TODO:
 * - test private messages (need more than 2 users!)
 * - test anonymous messages
 * - test acknowledgements (verify sig!)
 * - test authenticated message (flags only)
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

#define DEBUG 0

static unsigned int error;

struct Wanted
{
  struct GNUNET_ECRS_MetaData *meta;

  GNUNET_HashCode *sender;

  char *msg;

  const char *me;

  struct GNUNET_Semaphore *recv;

  struct GNUNET_Semaphore *pre;

  GNUNET_CHAT_MSG_OPTIONS opt;

};

static int
receive_callback (void *cls,
                  struct GNUNET_CHAT_Room *room,
                  const GNUNET_HashCode * sender,
                  const struct GNUNET_ECRS_MetaData *member_info,
                  const char *message, GNUNET_CHAT_MSG_OPTIONS options)
{
  struct Wanted *want = cls;

#if DEBUG
  fprintf (stderr, "%s - told that %s says %s\n",
           want->me,
           member_info == NULL ? NULL
           : GNUNET_ECRS_meta_data_get_by_type (member_info, EXTRACTOR_TITLE),
           message);
#endif
  GNUNET_semaphore_down (want->pre, GNUNET_YES);
  if (!((0 == strcmp (message, want->msg)) &&
        (((sender == NULL) && (want->sender == NULL)) ||
         ((sender != NULL) &&
          (want->sender != NULL) &&
          (0 == memcmp (sender, want->sender, sizeof (GNUNET_HashCode))))) &&
        (GNUNET_ECRS_meta_data_test_equal (member_info,
                                           want->meta)) &&
        (options == want->opt)))
    {
      abort ();
      error++;
    }
  GNUNET_semaphore_up (want->recv);
  return GNUNET_OK;
}

static int
member_list_callback (void *cls,
                      const struct GNUNET_ECRS_MetaData *member_info,
                      const GNUNET_RSA_PublicKey * member_id,
                      GNUNET_CHAT_MSG_OPTIONS options)
{
  struct Wanted *want = cls;
  GNUNET_HashCode sender;

#if DEBUG
  fprintf (stderr, "%s - told that %s joins\n",
           want->me,
           member_info == NULL ? NULL
           : GNUNET_ECRS_meta_data_get_by_type (member_info,
                                                EXTRACTOR_TITLE));
#endif
  GNUNET_semaphore_down (want->pre, GNUNET_YES);
  GNUNET_hash (member_id, sizeof (GNUNET_RSA_PublicKey), &sender);
  if (!((0 == memcmp (&sender, want->sender, sizeof (GNUNET_HashCode))) &&
        (((member_info == NULL) &&
          (want->meta == NULL)) ||
         ((member_info != NULL) &&
          (want->meta != NULL) &&
          (GNUNET_ECRS_meta_data_test_equal (member_info,
                                             want->meta)))) &&
        (options == want->opt)))
    {
      abort ();
      error++;
    }
  GNUNET_semaphore_up (want->recv);
  return GNUNET_OK;
}

static void
check_down (struct Wanted *want)
{
  int tries;
  tries = 10;
  while (tries > 0)
    {
      if (GNUNET_SYSERR != GNUNET_semaphore_down (want->recv, GNUNET_YES))
        break;
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      tries--;
    }
  if (tries == 0)
    error++;
}

/**
 * Testcase to test chat.
 * @return 0: ok, -1: error
 */
int
main (int argc, char **argv)
{
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_TESTING_DaemonContext *peers;
  int ret;
  struct GNUNET_CHAT_Room *r1;
  struct GNUNET_CHAT_Room *r2;
  unsigned int seq;
  struct GNUNET_ECRS_MetaData *meta1;
  struct GNUNET_ECRS_MetaData *meta2;
  GNUNET_HashCode alice;
  GNUNET_HashCode bob;
  struct Wanted alice_wanted;
  struct Wanted bob_wanted;

  memset (&alice_wanted, 0, sizeof (struct Wanted));
  memset (&bob_wanted, 0, sizeof (struct Wanted));
  alice_wanted.me = "Alice";
  bob_wanted.me = "Bob";
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
  meta1 = GNUNET_ECRS_meta_data_create ();
  GNUNET_ECRS_meta_data_insert (meta1, EXTRACTOR_TITLE, "Alice");
  meta2 = GNUNET_ECRS_meta_data_create ();
  GNUNET_ECRS_meta_data_insert (meta2, EXTRACTOR_TITLE, "Bob");

  /* alice joining */
#if DEBUG
  fprintf (stderr, "Alice joining\n");
#endif
  alice_wanted.recv = GNUNET_semaphore_create (0);
  alice_wanted.pre = GNUNET_semaphore_create (1);
  alice_wanted.meta = meta1;
  alice_wanted.sender = &alice;
  alice_wanted.msg = NULL;
  alice_wanted.opt = -1;
  r1 =
    GNUNET_CHAT_join_room (NULL, cfg, "alice",
                           meta1, "test", -1,
                           &receive_callback, &alice_wanted,
                           &member_list_callback, &alice_wanted,
                           NULL, NULL, &alice);
  if (r1 == NULL)
    {
      ret = 1;
      goto CLEANUP;
    }
  check_down (&alice_wanted);

  /* bob joining */
#if DEBUG
  fprintf (stderr, "Bob joining\n");
#endif
  alice_wanted.meta = meta2;
  alice_wanted.sender = &bob;
  alice_wanted.msg = NULL;
  alice_wanted.opt = -1;
  GNUNET_semaphore_up (alice_wanted.pre);

  bob_wanted.recv = GNUNET_semaphore_create (0);
  bob_wanted.pre = GNUNET_semaphore_create (1);
  bob_wanted.meta = meta2;
  bob_wanted.sender = &bob;
  bob_wanted.msg = NULL;
  bob_wanted.opt = -1;
  r2 =
    GNUNET_CHAT_join_room (NULL, cfg, "bob",
                           meta2, "test", -1,
                           &receive_callback, &bob_wanted,
                           &member_list_callback, &bob_wanted,
                           NULL, NULL, &bob);
  if (r2 == NULL)
    {
      ret = 1;
      goto CLEANUP;
    }
  check_down (&alice_wanted);
  check_down (&bob_wanted);
  bob_wanted.meta = meta1;
  bob_wanted.sender = &alice;
  bob_wanted.msg = NULL;
  bob_wanted.opt = -1;
  GNUNET_semaphore_up (bob_wanted.pre);
  check_down (&bob_wanted);
  /* end of Bob joining */

  /* alice to bob */
#if DEBUG
  fprintf (stderr, "Alice says 'Hi!'\n");
#endif
  GNUNET_CHAT_send_message (r1, "Hi!",
                            GNUNET_CHAT_MSG_OPTION_NONE, NULL, &seq);
  alice_wanted.meta = meta1;
  alice_wanted.sender = &alice;
  alice_wanted.msg = "Hi!";
  alice_wanted.opt = 0;
  GNUNET_semaphore_up (alice_wanted.pre);
  bob_wanted.meta = meta1;
  bob_wanted.sender = &alice;
  bob_wanted.msg = "Hi!";
  bob_wanted.opt = 0;
  GNUNET_semaphore_up (bob_wanted.pre);
  check_down (&alice_wanted);
  check_down (&bob_wanted);


  /* bob to alice */
#if DEBUG
  fprintf (stderr, "Bob says 'Rehi!'\n");
#endif
  GNUNET_CHAT_send_message (r2, "Rehi!",
                            GNUNET_CHAT_MSG_OPTION_NONE, NULL, &seq);
  alice_wanted.meta = meta2;
  alice_wanted.sender = &bob;
  alice_wanted.msg = "Rehi!";
  alice_wanted.opt = 0;
  GNUNET_semaphore_up (alice_wanted.pre);
  bob_wanted.meta = meta2;
  bob_wanted.sender = &bob;
  bob_wanted.msg = "Rehi!";
  bob_wanted.opt = 0;
  GNUNET_semaphore_up (bob_wanted.pre);
  check_down (&alice_wanted);
  check_down (&bob_wanted);

  /* alice leaving */
#if DEBUG
  fprintf (stderr, "Alice is leaving.\n");
#endif
  GNUNET_CHAT_leave_room (r1);
  r1 = NULL;
  bob_wanted.meta = NULL;
  bob_wanted.sender = &alice;
  bob_wanted.msg = NULL;
  bob_wanted.opt = 0;
  GNUNET_semaphore_up (bob_wanted.pre);
  check_down (&bob_wanted);

  /* bob leaving */
#if DEBUG
  fprintf (stderr, "Bob is leaving.\n");
#endif
  GNUNET_CHAT_leave_room (r2);
  r2 = NULL;

CLEANUP:
  if (r1 != NULL)
    GNUNET_CHAT_leave_room (r1);
  if (r2 != NULL)
    GNUNET_CHAT_leave_room (r2);
  if (bob_wanted.pre != NULL)
    GNUNET_semaphore_destroy (bob_wanted.pre);
  if (bob_wanted.recv != NULL)
    GNUNET_semaphore_destroy (bob_wanted.recv);
  if (alice_wanted.pre != NULL)
    GNUNET_semaphore_destroy (alice_wanted.pre);
  if (alice_wanted.recv != NULL)
    GNUNET_semaphore_destroy (alice_wanted.recv);

#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif
  GNUNET_GC_free (cfg);
  if (error != 0)
    ret = 1;
  return ret;
}

/* end of loopback_test.c */
