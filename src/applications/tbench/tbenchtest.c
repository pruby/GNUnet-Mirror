/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/tbench/tbenchtest.c
 * @brief Transport mechanism testing tool
 * @author Paul Ruth, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_stats_lib.h"
#include "tbench.h"

static int parseOptions(int argc,
			char ** argv) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  return OK;
}

/**
 * Identity of peer 2.
 */
static PeerIdentity peer2;

static int test(GNUNET_TCP_SOCKET * sock,
		unsigned int messageSize,
		unsigned int messageCnt,
		unsigned int messageIterations,
		cron_t messageSpacing,
		unsigned int messageTrainSize,
		cron_t messageTimeOut /* in milli-seconds */) {
  int ret;
  CS_tbench_request_MESSAGE msg;
  CS_tbench_reply_MESSAGE * buffer;
  float messagesPercentLoss;

  printf(_("Using %u messages of size %u for %u times.\n"),
	 messageCnt,
	 messageSize,
	 messageIterations);
  msg.header.size = htons(sizeof(CS_tbench_request_MESSAGE));
  msg.header.type = htons(CS_PROTO_tbench_REQUEST);
  msg.msgSize     = htonl(messageSize);
  msg.msgCnt      = htonl(messageCnt);
  msg.iterations  = htonl(messageIterations);
  msg.intPktSpace = htonll(messageSpacing);
  msg.trainSize   = htonl(messageTrainSize);
  msg.timeOut     = htonll(messageTimeOut);
  msg.priority    = htonl(5);
  msg.receiverId  = peer2;

  if (SYSERR == writeToSocket(sock,
			      &msg.header))
    return -1;
  ret = 0;

  buffer = NULL;
  if (OK == readFromSocket(sock, (CS_MESSAGE_HEADER**)&buffer)) {
    if ((float)buffer->mean_loss <= 0){
      messagesPercentLoss = 0.0;
    } else {
      messagesPercentLoss = (buffer->mean_loss/((float)htons(msg.msgCnt)));
    }
    printf(_("Times: max %16llu  min %16llu  mean %12.3f  variance %12.3f\n"),
	   ntohll(buffer->max_time),
	   ntohll(buffer->min_time),
	   buffer->mean_time,
	   buffer->variance_time);
    printf(_("Loss:  max %16u  min %16u  mean %12.3f  variance %12.3f\n"),
	   ntohl(buffer->max_loss),
	   ntohl(buffer->min_loss),
	   buffer->mean_loss,
	   buffer->variance_loss);
  } else {
    printf(_("\nFailed to receive reply from gnunetd.\n"));
    ret = -1;
  }
  FREENONNULL(buffer);

  return ret;
}

static int waitForConnect(const char * name,
			  unsigned long long value,
			  void * cls) {
  if ( (value > 0) &&
       (0 == strcmp(_("# of connected peers"),
		    name)) )
    return SYSERR;
  return OK;
}

static int checkConnected(GNUNET_TCP_SOCKET * sock) {
  int left;
  int ret;

  ret = 0;
  left = 30; /* how many iterations should we wait? */
  while (OK == requestStatistics(sock,
				 &waitForConnect,
				 NULL)) {
    printf(_("Waiting for peers to connect (%u iterations left)...\n"),
	   left);
    sleep(5);
    left--;
    if (left == 0) {
      ret = 1;
      break;
    }
  }
  return ret;
}

/**
 * Testcase to test p2p communications.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0: ok, -1: error
 */
int main(int argc, char ** argv) {
  pid_t daemon1;
  pid_t daemon2;
  int ret;
  int left;
  GNUNET_TCP_SOCKET * sock;
  int i;

  GNUNET_ASSERT(OK ==
		enc2hash("BV3AS3KMIIBVIFCGEG907N6NTDTH26B7T6FODUSLSGK"
			 "5B2Q58IEU1VF5FTR838449CSHVBOAHLDVQAOA33O77F"
			 "OPDA8F1VIKESLSNBO",
			 &peer2.hashPubKey));
  if (OK != initUtil(argc,
		     argv,
		     &parseOptions))
    return -1;
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer1.conf"));
  daemon1 = startGNUnetDaemon(NO);
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer2.conf"));
  daemon2 = startGNUnetDaemon(NO);
  /* in case existing hellos have expired */
  sleep(5);
  system("cp peer1/data/hosts/* peer2/data/hosts/");
  system("cp peer2/data/hosts/* peer1/data/hosts/");
  if (daemon1 != -1) {
    if (! termProcess(daemon1))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon1));
  }
  if (daemon2 != -1) {
    if (! termProcess(daemon2))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon2));
  }

  /* re-start, this time we're sure up-to-date hellos are available */
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer1.conf"));
  daemon1 = startGNUnetDaemon(NO);
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer2.conf"));
  daemon2 = startGNUnetDaemon(NO);
  gnunet_util_sleep(5 * cronSECONDS);
  sleep(5);

  ret = 0;
  left = 5;
  /* wait for connection or abort with error */
  do {
    sock = getClientSocket();
    if (sock == NULL) {
      printf(_("Waiting for gnunetd to start (%u iterations left)...\n"),
	     left);
      sleep(1);
      left--;
      if (left == 0) {
	ret = 1;
	break;
      }
    }
  } while (sock == NULL);

  ret = checkConnected(sock);
  printf(_("Running benchmark...\n"));
  /* 'slow' pass: wait for bandwidth negotiation! */
  if (ret == 0)
    ret = test(sock, 64, 100, 4, 50 * cronMILLIS, 1, 30 * cronSECONDS);
  checkConnected(sock);
  /* 'blast' pass: hit bandwidth limits! */
  for (i=8;i<60000;i*=2) {
    if (ret == 0)
      ret = test(sock, i, 1+1024/i, 4, 10 * cronMILLIS, 2, 2 * cronSECONDS);
    checkConnected(sock);
  }
  ret = test(sock, 32768, 10, 10, 500 * cronMILLIS, 1, 10 * cronSECONDS);
  releaseClientSocket(sock);
  if (daemon1 != -1) {
    if (! termProcess(daemon1))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon1));
  }
  if (daemon2 != -1) {
    if (! termProcess(daemon2))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon2));
  }
  doneUtil();
  return ret;
}

/* end of tbenchtest.c */
