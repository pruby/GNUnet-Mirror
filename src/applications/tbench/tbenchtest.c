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
#include <sys/wait.h>

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
		unsigned short messageSize,
		unsigned short messageCnt,
		unsigned short messageIterations,
		unsigned short messageSpacing,
		unsigned short messageTrainSize,
		unsigned int messageTimeOut /* in milli-seconds */) {
  int ret;
  TBENCH_CS_MESSAGE msg;
  TBENCH_CS_REPLY * buffer;
  float messagesPercentLoss;

  memset(&msg,
	 0,
	 sizeof(TBENCH_CS_MESSAGE));
  msg.header.size = htons(sizeof(TBENCH_CS_MESSAGE));
  msg.header.type = htons(TBENCH_CS_PROTO_REQUEST);
  msg.msgSize     = htons(messageSize);
  msg.msgCnt      = htons(messageCnt);
  msg.iterations  = htons(messageIterations);
  msg.intPktSpace = htons(messageSpacing);
  msg.trainSize   = htons(messageTrainSize);
  msg.timeOut     = htonl(messageTimeOut);
  msg.receiverId  = peer2;
  
  if (SYSERR == writeToSocket(sock,
			      &msg.header))
    return -1;
  ret = 0;
  
  buffer = NULL;
  if (OK == readFromSocket(sock, (CS_HEADER**)&buffer)) {
    if ((float)buffer->mean_loss <= 0){
      messagesPercentLoss = 0.0;
    } else {
      messagesPercentLoss = (buffer->mean_loss/((float)htons(msg.msgCnt)));
    }
    printf(_("Times: max %8d  min %8d  mean %8.4f  variance %8.4f\n"),
	   htons(buffer->max_time),
	   htons(buffer->min_time),
	   buffer->mean_time,
	   buffer->variance_time);
    printf(_("Loss:  max %8d  min %8d  mean %8.4f  variance %8.4f\n"),
	   htons(buffer->max_loss),
	   htons(buffer->min_loss),
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
  int status;
  GNUNET_TCP_SOCKET * sock;

  GNUNET_ASSERT(OK ==
		enc2hash("BV3AS3KMIIBVIFCGEG907N6NTDTH26B7T6FODUSLSGK"
			 "5B2Q58IEU1VF5FTR838449CSHVBOAHLDVQAOA33O77F"
			 "OPDA8F1VIKESLSNBO",
			 &peer2.hashPubKey));

  daemon1 = fork();
  if (daemon1 == 0) {
    if (0 != execlp("gnunetd", /* what binary to execute, must be in $PATH! */
		    "gnunetd", /* arg0, path to gnunet binary */
		    "-d",  /* do not daemonize so we can easily kill you */
		    "-c",
		    "peer1.conf", /* configuration file */
		    NULL)) {
      fprintf(stderr,
	      _("'%s' failed: %s\n"),
	      "execlp",
	      STRERROR(errno));
      return -1;
    }
  }
  daemon2 = fork();
  if (daemon2 == 0) {
    if (0 != execlp("gnunetd", /* what binary to execute, must be in $PATH! */
		    "gnunetd", /* arg0, path to gnunet binary */
		    "-d",  /* do not daemonize so we can easily kill you */
		    "-c",
		    "peer2.conf", /* configuration file */
		    NULL)) {
      fprintf(stderr,
	      _("'%s' failed: %s\n"),
	      "execlp",
	      STRERROR(errno));
      return -1;
    }
  }
  /* in case existing HELOs have expired */
  sleep(5);
  system("cp peer1/data/hosts/* peer2/data/hosts/");
  system("cp peer2/data/hosts/* peer1/data/hosts/");
  if (daemon1 != -1) {
    if (0 != kill(daemon1, SIGTERM))
      DIE_STRERROR("kill");
    if (daemon1 != waitpid(daemon1, &status, 0)) 
      DIE_STRERROR("waitpid");
  }
  if (daemon2 != -1) {
    if (0 != kill(daemon2, SIGTERM))
      DIE_STRERROR("kill");
    if (daemon2 != waitpid(daemon2, &status, 0)) 
      DIE_STRERROR("waitpid");
  }

  /* re-start, this time we're sure up-to-date HELOs are available */
  daemon1 = fork(); 
  if (daemon1 == 0) {
    if (0 != execlp("gnunetd", /* what binary to execute, must be in $PATH! */
		    "gnunetd", /* arg0, path to gnunet binary */
		    "-d",  /* do not daemonize so we can easily kill you */
		    "-c",
		    "peer1.conf", /* configuration file */
		    NULL)) {
      fprintf(stderr,
	      _("'%s' failed: %s\n"),
	      "execlp",
	      STRERROR(errno));
      return -1;
    }
  }
  daemon2 = fork();
  if (daemon2 == 0) {
    if (0 != execlp("gnunetd", /* what binary to execute, must be in $PATH! */
		    "gnunetd", /* arg0, path to gnunet binary */
		    "-d",  /* do not daemonize so we can easily kill you */
		    "-c",
		    "peer2.conf", /* configuration file */
		    NULL)) {
      fprintf(stderr,
	      _("'%s' failed: %s\n"),
	      "execlp",
	      STRERROR(errno));
      return -1;
    }
  }
  sleep(5);
  
  ret = 0;
  left = 5;
  /* wait for connection or abort with error */
  initUtil(argc, argv, &parseOptions);
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

  if (ret == 0)
    ret = test(sock, 4, 1, 1, 1, 1, 5000);
  if (ret == 0)
    ret = test(sock, 50, 64, 40, 50, 10, 10000);
  if (ret == 0)
    ret = test(sock, 1024, 64, 4, 0, 1, 10000);
  if (ret == 0)
    ret = test(sock, 32*1024, 8, 4, 0, 1, 30000);
  
  releaseClientSocket(sock);
  doneUtil();

  if (daemon1 != -1) {
    if (0 != kill(daemon1, SIGTERM))
      DIE_STRERROR("kill");
    if (daemon1 != waitpid(daemon1, &status, 0)) 
      DIE_STRERROR("waitpid");
  }
  if (daemon2 != -1) {
    if (0 != kill(daemon2, SIGTERM))
      DIE_STRERROR("kill");
    if (daemon2 != waitpid(daemon2, &status, 0)) 
      DIE_STRERROR("waitpid");
  }
  return ret;
}

/* end of tbenchtest.c */ 
