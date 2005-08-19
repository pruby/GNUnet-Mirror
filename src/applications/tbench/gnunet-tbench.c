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
 * @file applications/tbench/gnunet-tbench.c
 * @brief Transport mechanism benchmarking tool
 * @author Paul Ruth, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "tbench.h"

#define TBENCH_VERSION "0.1.1"

#define DEFAULT_MESSAGE_SIZE	10
#define DEFAULT_TIMEOUT		(2 * cronSECONDS)
#define DEFAULT_SPACING		0

#define OF_HUMAN_READABLE 0
#define OF_GNUPLOT_INPUT 1

static unsigned int messageSize = DEFAULT_MESSAGE_SIZE;
static unsigned int messageCnt  = 1;
static char * messageReceiver;
static unsigned int messageIterations = 1;
static unsigned int messageTrainSize  = 1;
static cron_t messageTimeOut          = DEFAULT_TIMEOUT;
static cron_t messageSpacing          = DEFAULT_SPACING;
static unsigned int outputFormat      = OF_HUMAN_READABLE;

/**
 * Parse the options, set the timeout.
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return OK on error, SYSERR if we should exit
 */
static int parseOptions(int argc,
			char ** argv) {
  int option_index;
  int c;

  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  while (1) {
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "gnuplot", 0, 0, 'g' },
      { "iterations", 1, 0, 'i'},
      { "msg", 1, 0, 'n'},
      { "rec", 1, 0, 'r'},
      { "size", 1, 0, 's' },
      { "space", 1, 0, 'S' },
      { "timeout", 1, 0, 't' },
      { "xspace", 1, 0, 'X' },
      { 0,0,0,0 }
    };
    option_index=0;
    c = GNgetopt_long(argc,
		      argv,
		      "vhdc:L:H:n:s:r:i:t:S:X:g",
		      long_options,
		      &option_index);
    if (c == -1)
      break;  /* No more flags to process*/
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'g':
      outputFormat = OF_GNUPLOT_INPUT;
      break;
    case 'h': {
      static Help help[] = {
	HELP_CONFIG,
	HELP_HELP,
	{ 'g', "gnuplot", NULL,
	  gettext_noop("output in gnuplot format") },
	HELP_LOGLEVEL,	
	{ 'i', "iterations", "ITER",
	  gettext_noop("number of iterations") },
	{ 'n', "msg", "MESSAGES",
	  gettext_noop("number of messages to use per iteration") },
	{ 'r', "rec", "RECEIVER",
	  gettext_noop("receiver host identifier (ENC file name)") },
	{ 's', "size", "SIZE",
	  gettext_noop("message size") },
	{ 'S', "space", "SPACE",
	  gettext_noop("sleep for SPACE ms after each a message block") },
	{ 't', "timeout", "TIMEOUT",
	  gettext_noop("time to wait for the completion of an iteration (in ms)") },
	HELP_VERSION,
	{ 'X', "xspace", "COUNT",
	  gettext_noop("number of messages in a message block") },
	HELP_END,
      };
      formatHelp("gnunet-tbench [OPTIONS]",
		 _("Start GNUnet transport benchmarking tool."),
		 help);
      return SYSERR;
    }
    case 'i':
      if(1 != sscanf(GNoptarg,
		     "%ud",
		     &messageIterations)){
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-i");
	return SYSERR;
      }
      break;
    case 'n':
      if(1 != sscanf(GNoptarg,
		     "%ud",
		     &messageCnt)){
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-n");
	return SYSERR;
      }
      break;
    case 'r':
      messageReceiver = STRDUP(GNoptarg);
      break;
    case 's':
      if(1 != sscanf(GNoptarg,
		     "%ud",
		     &messageSize)){
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-s");
	return SYSERR;
      }
      break;
    case 'S':
      if(1 != sscanf(GNoptarg,
		     "%ud",
		     &messageTrainSize)){
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-S");
	return SYSERR;
      }
      break;
    case 't':
      if(1 != SSCANF(GNoptarg,
		     "%llud",
		     &messageTimeOut)){
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-t");
	return SYSERR;
      }
      break;
    case 'v':
      printf("GNUnet v%s, gnunet-tbench v%s\n",
	     VERSION,
	     TBENCH_VERSION);
      return SYSERR;
    case 'X':
      if(1 != SSCANF(GNoptarg,
		     "%llud",
		     &messageSpacing)){
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-X");
	return SYSERR;
      }
      break;
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return -1;
    } /* end of parsing commandline */
  } /* while (1) */
  return OK;
}

/**
 * Tool to benchmark the performance of the P2P transports.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunetsearch: 0: ok, -1: error
 */
int main(int argc, char ** argv) {
  GNUNET_TCP_SOCKET * sock;
  CS_tbench_request_MESSAGE msg;
  CS_tbench_reply_MESSAGE * buffer;
  float messagesPercentLoss;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0; /* parse error, --help, etc. */
  sock = getClientSocket();
  if (sock == NULL)
    errexit(_("Could not connect to gnunetd.\n"));

  msg.header.size = htons(sizeof(CS_tbench_request_MESSAGE));
  msg.header.type = htons(CS_PROTO_tbench_REQUEST);
  msg.msgSize     = htonl(messageSize);
  msg.msgCnt      = htonl(messageCnt);
  msg.iterations  = htonl(messageIterations);
  msg.intPktSpace = htonll(messageSpacing);
  msg.trainSize   = htonl(messageTrainSize);
  msg.timeOut     = htonll(messageTimeOut);
  msg.priority    = htonl(5);
  if (messageReceiver == NULL)
    errexit(_("You must specify a receiver!\n"));
  if (OK != enc2hash(messageReceiver,
		     &msg.receiverId.hashPubKey))		
    errexit(_("Invalid receiver peer ID specified (`%s' is not valid name).\n"),
	    messageReceiver);
  FREE(messageReceiver);

  if (SYSERR == writeToSocket(sock,
			      &msg.header))
    return -1;

  buffer = NULL;
  if (OK == readFromSocket(sock,
			   (CS_MESSAGE_HEADER**)&buffer)) {
    GNUNET_ASSERT(ntohs(buffer->header.size) ==
		  sizeof(CS_tbench_reply_MESSAGE));
    if ((float)buffer->mean_loss <= 0){
      BREAK();
      messagesPercentLoss = 0.0;
    } else {
      messagesPercentLoss = (buffer->mean_loss/((float)htons(msg.msgCnt)));
    }
    switch (outputFormat) {
    case OF_HUMAN_READABLE:
      printf(_("Time:\n"));
      PRINTF(_("\tmax      %llums\n"),
	     ntohll(buffer->max_time));
      PRINTF(_("\tmin      %llums\n"),
	     ntohll(buffer->min_time));
      printf(_("\tmean     %8.4fms\n"),
	     buffer->mean_time);
      printf(_("\tvariance %8.4fms\n"),
	     buffer->variance_time);

      printf(_("Loss:\n"));
      printf(_("\tmax      %u\n"),
	     ntohl(buffer->max_loss));
      printf(_("\tmin      %u\n"),
	     ntohl(buffer->min_loss));
      printf(_("\tmean     %8.4f\n"),
	     buffer->mean_loss);
      printf(_("\tvariance %8.4f\n"),
	     buffer->variance_loss);
      break;
    case OF_GNUPLOT_INPUT:
      printf("%f %f\n",
	     buffer->mean_time,
	     1.0-messagesPercentLoss);
      break;
    default:
      printf(_("Output format not known, this should not happen.\n"));
    }
    FREE(buffer);
  } else
    printf(_("\nDid not receive the message from gnunetd. Is gnunetd running?\n"));

  releaseClientSocket(sock);
  doneUtil();
  return 0;
}

/* end of gnunet-tbench.c */
