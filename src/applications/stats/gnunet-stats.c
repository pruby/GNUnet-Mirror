/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/stats/gnunet-stats.c 
 * @brief tool to obtain statistics from gnunetd.
 * @author Christian Grothoff
 * @author Igor Wronsky
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "statistics.h"

#define STATS_VERSION "3.0.0"

static int printProtocols;

/**
 * Return a descriptive name for a p2p message type
 */
static const char *p2pMessageName( unsigned short type ) {
  const char *name = NULL;

  switch( type ) {
  case p2p_PROTO_HELO : 
    name = "p2p_PROTO_HELO";
    break;
  case p2p_PROTO_SKEY : 
    name = "p2p_PROTO_SKEY";
    break;
  case p2p_PROTO_PING : 
    name = "p2p_PROTO_PING";
    break;
  case p2p_PROTO_PONG : 
    name = "p2p_PROTO_PONG";
    break;
  case p2p_PROTO_NOISE : 
    name = "p2p_PROTO_NOISE";
    break;
  case p2p_PROTO_HANGUP : 
    name = "p2p_PROTO_HANGUP";
    break;
  case CHAT_p2p_PROTO_MSG : 
    name = "CHAT_p2p_PROTO_MSG";
    break;
  case TRACEKIT_p2p_PROTO_PROBE : 
    name = "TRACEKIT_p2p_PROTO_PROBE";
    break;
  case TRACEKIT_p2p_PROTO_REPLY : 
    name = "TRACEKIT_p2p_PROTO_REPLY";
    break;
  case TBENCH_p2p_PROTO_REQUEST	: 
    name = "TBENCH_p2p_PROTO_REQUEST";
    break;
  case TBENCH_p2p_PROTO_REPLY	: 
    name = "TBENCH_p2p_PROTO_REPLY";
    break;
  default:
    name = NULL;
    break;
  }
  return name;

}

/**
 * Return a descriptive name for a client server message type
 */
static const char *csMessageName( unsigned short type ) {
  const char *name = NULL;

  switch( type ) {
  case CS_PROTO_RETURN_VALUE : 
    name = "CS_PROTO_RETURN_VALUE";
    break;
  case CS_PROTO_CLIENT_COUNT : 
    name = "CS_PROTO_CLIENT_COUNT";
    break;
  case CS_PROTO_TRAFFIC_QUERY : 
    name = "CS_PROTO_TRAFFIC_QUERY";
    break;
  case CS_PROTO_TRAFFIC_INFO : 
    name = "CS_PROTO_TRAFFIC_INFO";
    break;
  case STATS_CS_PROTO_GET_STATISTICS : 
    name = "STATS_CS_PROTO_GET_STATISTICS";
    break;
  case STATS_CS_PROTO_STATISTICS : 
    name = "STATS_CS_PROTO_STATISTICS";
    break;
  case STATS_CS_PROTO_GET_CS_MESSAGE_SUPPORTED : 
    name = "STATS_CS_PROTO_GET_CS_MESSAGE_SUPPORTED";
    break;
  case STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED : 
    name = "STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED";
    break;
  case CHAT_CS_PROTO_MSG : 
    name = "CHAT_CS_PROTO_MSG";
    break;
  case TRACEKIT_CS_PROTO_PROBE : 
    name = "TRACEKIT_CS_PROTO_PROBE";
    break;
  case TRACEKIT_CS_PROTO_REPLY : 
    name = "TRACEKIT_CS_PROTO_REPLY";
    break;
  case TBENCH_CS_PROTO_REQUEST : 
    name = "TBENCH_CS_PROTO_REQUEST";
    break;
  case TBENCH_CS_PROTO_REPLY : 
    name = "TBENCH_CS_PROTO_REPLY";
    break;
  default:
    name = NULL;
    break;    
  }
  return name;
}

/**
 * Print statistics received from TCP socket.
 * @param stream where to print the statistics
 * @param sock the socket to use 
 * @return OK on success, SYSERR on error
 */
static int requestAndPrintStatistics(FILE * stream,
				     GNUNET_TCP_SOCKET * sock) {
  STATS_CS_MESSAGE * statMsg;
  CS_HEADER csHdr;
  unsigned int count;
  unsigned int i;
  int mpos;
  
  csHdr.size 
    = htons(sizeof(CS_HEADER));
  csHdr.type
    = htons(STATS_CS_PROTO_GET_STATISTICS);
  if (SYSERR == writeToSocket(sock,
			      &csHdr)) {
    fprintf(stream,
	    _("Error sending request for statistics to gnunetd.\n"));
    return SYSERR;
  }
  statMsg 
    = MALLOC(MAX_BUFFER_SIZE);
  statMsg->totalCounters 
    = htonl(1); /* to ensure we enter the loop */
  count = 0;
  while ( count < ntohl(statMsg->totalCounters) ) {
    /* printf("reading from socket starting %u of %d\n",
       count, ntohl(statMsg->totalCounters) );*/
    if (SYSERR == readFromSocket(sock,
				 (CS_HEADER**)&statMsg)) {
      fprintf(stream,
	      _("Error receiving reply for statistics from gnunetd.\n"));
      FREE(statMsg);
      return SYSERR;    
    }
    if (ntohs(statMsg->header.size) < sizeof(STATS_CS_MESSAGE)) {
      BREAK();
      break;
    }
    mpos = sizeof(unsigned long long) * ntohl(statMsg->statCounters);
    if (count == 0) {
      fprintf(stream,
	      "%-60s: %16u\n",
	      _("Uptime (seconds)"),
	      (unsigned int) 
	      ((cronTime(NULL) - ntohll(statMsg->startTime))/cronSECONDS));
    }
    for (i=0;i<ntohl(statMsg->statCounters);i++) {
      if (mpos+strlen(&((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos])+1 > 
	  ntohs(statMsg->header.size) - sizeof(STATS_CS_MESSAGE)) {
	BREAK();
	break; /* out of bounds! */      
      }
      fprintf(stream,
	      "%-60s: %16llu\n",
	      &((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos],
	      ntohll(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values[i]));
      mpos += strlen(&((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos])+1;
    }    
    count += ntohl(statMsg->statCounters);
  } /* end while */
  FREE(statMsg);
  return OK;
}

/**
 * Queries the server for what protocol messages are
 * supported and prints a list of them
 * @param stream where to print the statistics
 * @param sock the socket to use 
 * @return OK on success, SYSERR on error
 */
static int requestAndPrintProtocols(FILE * stream,
				     GNUNET_TCP_SOCKET * sock) {
  STATS_CS_GET_MESSAGE_SUPPORTED csStatMsg;
  int i = 0;
  int supported = NO;
  const char *name = NULL;

  csStatMsg.header.size 
    = htons(sizeof(STATS_CS_GET_MESSAGE_SUPPORTED));


  fprintf(stream, 
	  _("Supported Peer to Peer messages:\n"));
  csStatMsg.header.type
    = htons(STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED);
  for (i = 0; i < 500; ++ i)
  {
    csStatMsg.type = htons(i);

    if (SYSERR == writeToSocket(sock, &csStatMsg.header)) {
      fprintf(stream,
	      _("Error sending request for p2p protocol status to gnunetd.\n"));
      return SYSERR;
    }
    if (SYSERR == readTCPResult(sock, &supported)) {
      fprintf(stream,
	      _("Error reading p2p protocol status from gnunetd.\n"));
      return SYSERR;
    }

    if (supported == YES)
    {
      fprintf(stream, "\t%d", i);
      name = p2pMessageName( i );
      if (name != NULL) {
        fprintf(stream, "\t(%s)", name);
      }
      fprintf(stream, "\n");
    }
  }
  fprintf(stream, 
	  _("Supported client-server messages:\n"));
  csStatMsg.header.type
    = htons(STATS_CS_PROTO_GET_CS_MESSAGE_SUPPORTED);
  for (i = 0; i < 500; ++ i)
  {
    csStatMsg.type = htons(i);

    if (SYSERR == writeToSocket(sock, &csStatMsg.header)) {
      fprintf(stream,
	      _("Error sending request for client-server protocol status to gnunetd.\n"));
      return SYSERR;
    }
    if (SYSERR == readTCPResult(sock, &supported)) {
      fprintf(stream,
	      _("Error reading client-server protocol status from gnunetd.\n"));
      return SYSERR;
    }

    if (supported == YES)
    {
      fprintf(stream, "\t%d", i);
      name = csMessageName( i );
      if (name != NULL) {
        fprintf(stream, "\t(%s)", name);
      }
      fprintf(stream, "\n");
    }
  }

  return OK;
}

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'p', "protocols", NULL,
      gettext_noop("prints supported protocol messages") },
    HELP_VERSION,
    HELP_END,
  };
  formatHelp("gnunet-stats [OPTIONS]",
	     _("Print statistics about GNUnet operations."),
	     help);
}

/**
 * Parse the options.
 *
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return SYSERR if we should abort, OK to continue
 */
static int parseOptions(int argc,
			char ** argv) {
  int option_index;
  int c;  

  while (1) {
    static struct GNoption long_options[] = {
      { "protocols",          0, 0, 'p' }, 
      LONG_DEFAULT_OPTIONS,
      { 0,0,0,0 }
    };    
    option_index = 0;
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:L:H:", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'v': 
      printf("GNUnet v%s, gnunet-stats v%s\n",
	     VERSION, STATS_VERSION);
      return SYSERR;
    case 'h': 
      printhelp(); 
      return SYSERR;
    case 'p':
      printProtocols = YES;
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
 * The main function to obtain statistics from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */   
int main(int argc, char ** argv) {
  int res;
  GNUNET_TCP_SOCKET * sock;

  printProtocols = NO;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;
  sock = getClientSocket();
  res = requestAndPrintStatistics(stdout,
				  sock);
  if ((printProtocols == YES) && (res == OK)) {
    res = requestAndPrintProtocols(stdout,
				   sock);
  }
  if (sock != NULL)
    releaseClientSocket(sock);
  doneUtil();

  return (res == OK) ? 0 : 1;
}

/* end of gnunet-stats.c */
