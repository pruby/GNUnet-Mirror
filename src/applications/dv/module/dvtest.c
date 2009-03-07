/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/dv/dvtest.c
 * @brief DV Transport testing tool
 * @author Nathan EVans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_stats_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_util.h"
#include "dv_tbench.h"
#include "gnunet_remote_lib.h"
#include "gnunet_directories.h"

#define START_PEERS 1

static struct GNUNET_REMOTE_TESTING_DaemonContext *peer1;
static struct GNUNET_REMOTE_TESTING_DaemonContext *peer2;
static struct GNUNET_REMOTE_TESTING_DaemonContext *peer3;
static struct GNUNET_REMOTE_TESTING_DaemonContext *peer4;
static struct GNUNET_REMOTE_TESTING_DaemonContext *peer5;
static struct GNUNET_REMOTE_TESTING_DaemonContext *peer6;
static struct GNUNET_REMOTE_TESTING_DaemonContext *peer7;
static struct GNUNET_REMOTE_TESTING_DaemonContext *peer8;

GNUNET_EncName peer1enc;
GNUNET_EncName peer2enc;
GNUNET_EncName peer3enc;
GNUNET_EncName peer4enc;
GNUNET_EncName peer5enc;
GNUNET_EncName peer6enc;
GNUNET_EncName peer7enc;
GNUNET_EncName peer8enc;

static int
test (struct GNUNET_ClientServerConnection *sock,
      unsigned int messageSize,
      unsigned int messageCnt,
      unsigned int messageIterations,
      GNUNET_CronTime messageSpacing,
      unsigned int messageTrainSize,
      GNUNET_CronTime messageTimeOut,
      GNUNET_PeerIdentity receiver /* in milli-seconds */ )
{
  int ret;
  CS_tbench_request_MESSAGE msg;
  CS_tbench_reply_MESSAGE *buffer;
  float messagesPercentLoss;

  printf (_("Using %u messages of size %u for %u times.\n"),
          messageCnt, messageSize, messageIterations);
  msg.header.size = htons (sizeof (CS_tbench_request_MESSAGE));
  msg.header.type = htons (GNUNET_CS_PROTO_TBENCH_REQUEST);
  msg.msgSize = htonl (messageSize);
  msg.msgCnt = htonl (messageCnt);
  msg.iterations = htonl (messageIterations);
  msg.intPktSpace = GNUNET_htonll (messageSpacing);
  msg.trainSize = htonl (messageTrainSize);
  msg.timeOut = GNUNET_htonll (messageTimeOut);
  msg.priority = htonl (5);
  msg.receiverId = receiver;

  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &msg.header))
    return -1;
  ret = 0;

  buffer = NULL;
  if (GNUNET_OK ==
      GNUNET_client_connection_read (sock,
                                     (GNUNET_MessageHeader **) & buffer))
    {
      if ((float) buffer->mean_loss <= 0)
        {
          messagesPercentLoss = 0.0;
        }
      else
        {
          messagesPercentLoss =
            (buffer->mean_loss / ((float) htons (msg.msgCnt)));
        }
      printf (_
              ("Times: max %16llu  min %16llu  mean %12.3f  variance %12.3f\n"),
              GNUNET_ntohll (buffer->max_time),
              GNUNET_ntohll (buffer->min_time), buffer->mean_time,
              buffer->variance_time);
      printf (_("Loss:  max %16u  min %16u  mean %12.3f  variance %12.3f\n"),
              ntohl (buffer->max_loss), ntohl (buffer->min_loss),
              buffer->mean_loss, buffer->variance_loss);
    }
  else
    {
      printf (_("\nFailed to receive reply from gnunetd.\n"));
      ret = -1;
    }
  GNUNET_free_non_null (buffer);

  return ret;
}

/**
 * Testcase to test DV communications.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0: ok, -1: error
 */
int
main (int argc, char **argv)
{
#if START_PEERS
  struct GNUNET_REMOTE_TESTING_DaemonContext *peers;
  struct GNUNET_REMOTE_TESTING_DaemonContext *pos;
#endif
  int i;
  int ret;
  struct GNUNET_ClientServerConnection *sock;
  struct GNUNET_GC_Configuration *cfg;

  ret = 0;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "dv_test.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_PEERS
  GNUNET_GC_set_configuration_value_string (cfg, NULL,
                                            "MULTIPLE_SERVER_TESTING",
                                            "DOT_OUTPUT", "topology.dot");
  peers = GNUNET_REMOTE_start_daemons (cfg, 8);
  if (peers == NULL)
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  peer1 = peers;
  peer2 = peer1->next;
  peer3 = peer2->next;
  peer4 = peer3->next;
  peer5 = peer4->next;
  peer6 = peer5->next;
  peer7 = peer6->next;
  peer8 = peer7->next;

  GNUNET_hash_to_enc (&peer1->peer->hashPubKey, &peer1enc);
  GNUNET_hash_to_enc (&peer2->peer->hashPubKey, &peer2enc);
  GNUNET_hash_to_enc (&peer3->peer->hashPubKey, &peer3enc);
  GNUNET_hash_to_enc (&peer4->peer->hashPubKey, &peer4enc);
  GNUNET_hash_to_enc (&peer5->peer->hashPubKey, &peer5enc);
  GNUNET_hash_to_enc (&peer6->peer->hashPubKey, &peer6enc);
  GNUNET_hash_to_enc (&peer7->peer->hashPubKey, &peer7enc);
  GNUNET_hash_to_enc (&peer8->peer->hashPubKey, &peer8enc);

  ((char *) &peer1enc)[5] = '\0';
  ((char *) &peer2enc)[5] = '\0';
  ((char *) &peer3enc)[5] = '\0';
  ((char *) &peer4enc)[5] = '\0';
  ((char *) &peer5enc)[5] = '\0';
  ((char *) &peer6enc)[5] = '\0';
  ((char *) &peer7enc)[5] = '\0';
  ((char *) &peer8enc)[5] = '\0';

  sock = GNUNET_client_connection_create (NULL, peers->config);

  /* 'slow' pass: wait for bandwidth negotiation! */
  printf (_("Sleeping 55 seconds to let topology stabilize...\n"));
  sleep (55);
  printf (_("Running benchmark...\n"));
  printf (_("Sending from %s to %s...\n"), (char *) &peer1enc,
          (char *) &peer2enc);

  if (ret == 0)
    ret =
      test (sock, 64, 1, 1, 500 * GNUNET_CRON_MILLISECONDS, 1,
            15 * GNUNET_CRON_SECONDS, *peer2->peer);

  printf (_("Sending from %s to %s...\n"), (char *) &peer1enc,
          (char *) &peer3enc);
  if (ret == 0)
    ret =
      test (sock, 64, 1, 1, 50 * GNUNET_CRON_MILLISECONDS, 1,
            5 * GNUNET_CRON_SECONDS, *peer3->peer);

  printf (_("Sending from %s to %s...\n"), (char *) &peer1enc,
          (char *) &peer4enc);
  if (ret == 0)
    ret =
      test (sock, 64, 1, 1, 50 * GNUNET_CRON_MILLISECONDS, 1,
            5 * GNUNET_CRON_SECONDS, *peer4->peer);

  printf (_("Sending from %s to %s...\n"), (char *) &peer1enc,
          (char *) &peer5enc);
  if (ret == 0)
    ret =
      test (sock, 64, 1, 1, 50 * GNUNET_CRON_MILLISECONDS, 1,
            5 * GNUNET_CRON_SECONDS, *peer5->peer);

  printf (_("Sending from %s to %s...\n"), (char *) &peer1enc,
          (char *) &peer6enc);
  if (ret == 0)
    ret =
      test (sock, 64, 1, 1, 50 * GNUNET_CRON_MILLISECONDS, 1,
            5 * GNUNET_CRON_SECONDS, *peer6->peer);

  printf (_("Sending from %s to %s...\n"), (char *) &peer1enc,
          (char *) &peer7enc);
  if (ret == 0)
    ret =
      test (sock, 64, 1, 1, 50 * GNUNET_CRON_MILLISECONDS, 1,
            5 * GNUNET_CRON_SECONDS, *peer7->peer);

  GNUNET_client_connection_destroy (sock);
#if START_PEERS
  /*FIXME: Have GNUNET_REMOTE_TESTING_stop_daemons... GNUNET_TESTING_stop_daemons (peers); */
  pos = peers;
  while (pos != NULL)
    {
      GNUNET_REMOTE_kill_daemon (pos);
      pos = pos->next;
    }
#endif

  GNUNET_GC_free (cfg);
  return ret;
}

/* end of dvtest.c */
