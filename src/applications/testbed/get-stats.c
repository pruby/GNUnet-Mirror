/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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

#include "gnunet_util.h"
#include "platform.h"
#include "socket.h"

/**
 * Return a descriptive name for a p2p message type
 */
static const char *p2pMessageName(unsigned short type) {
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
  case p2p_PROTO_TIMESTAMP : 
    name = "p2p_PROTO_TIMESTAMP";
    break;
  case p2p_PROTO_SEQUENCE : 
    name = "p2p_PROTO_SEQUENCE";
    break;
  case p2p_PROTO_NOISE : 
    name = "p2p_PROTO_NOISE";
    break;
  case p2p_PROTO_HANGUP : 
    name = "p2p_PROTO_HANGUP";
    break;
  case AFS_p2p_PROTO_QUERY : 
    name = "AFS_p2p_PROTO_QUERY";
    break;
  case AFS_p2p_PROTO_3HASH_RESULT : 
    name = "AFS_p2p_PROTO_3HASH_RESULT";
    break;
  case AFS_p2p_PROTO_CHK_RESULT : 
    name = "AFS_p2p_PROTO_CHK_RESULT";
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
  case AFS_CS_PROTO_QUERY: 
    name = "AFS_CS_PROTO_QUERY";
    break;
  case AFS_CS_PROTO_RESULT_3HASH: 
    name = "AFS_CS_PROTO_RESULT_3HASH";
    break;
  case AFS_CS_PROTO_RESULT_CHK: 
    name = "AFS_CS_PROTO_RESULT_CHK";
    break;
  case AFS_CS_PROTO_INSERT_CHK: 
    name = "AFS_CS_PROTO_INSERT_CHK";
    break;
  case AFS_CS_PROTO_INSERT_3HASH : 
    name = "AFS_CS_PROTO_INSERT_3HASH";
    break;
  case AFS_CS_PROTO_INDEX_BLOCK : 
    name = "AFS_CS_PROTO_INDEX_BLOCK";
    break;
  case AFS_CS_PROTO_INDEX_FILE : 
    name = "AFS_CS_PROTO_INDEX_FILE";
    break;
  case AFS_CS_PROTO_INDEX_SUPER : 
    name = "AFS_CS_PROTO_INDEX_SUPER";
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
int requestAndPrintStatistics(GNUNET_TCP_SOCKET * sock) {
  STATS_CS_MESSAGE * statMsg;
  CS_HEADER csHdr;
  unsigned int count;
  unsigned int i;
  int mpos;
  
  csHdr.size = htons(sizeof(CS_HEADER));
  csHdr.type = htons(STATS_CS_PROTO_GET_STATISTICS);
  if (SYSERR == writeToSocket(sock, &csHdr)) {
    PRINTF(_("Error sending request for statistics to peer.\n"));
    return SYSERR;
  }
  statMsg = MALLOC(MAX_BUFFER_SIZE);
  statMsg->totalCounters = htonl(1); /* to ensure we enter the loop */
  count = 0;
  while ( count < ntohl(statMsg->totalCounters) ) {
    /* printf("reading from socket starting %u of %d\n",
       count, ntohl(statMsg->totalCounters) );*/
    if (SYSERR == readFromSocket(sock,
				 (CS_HEADER**)&statMsg)) {
      PRINTF(_("Error receiving reply for statistics from peer.\n"));
      FREE(statMsg);
      return SYSERR;    
    }
    if (ntohs(statMsg->header.size) < sizeof(STATS_CS_MESSAGE)) {
      LOG(LOG_WARNING,
	  _("Received malformed stats message (%d < %d)\n"),
	  ntohs(statMsg->header.size), 
	  sizeof(STATS_CS_MESSAGE) );
      break;
    }
    mpos = sizeof(unsigned long long) * ntohl(statMsg->statCounters);
    if (count == 0) {
      PRINTF("%-60s: %16u\n",
	     _("Uptime (seconds)"),
	     (unsigned int) 
	     ((cronTime(NULL) - ntohll(statMsg->startTime))/
	      cronSECONDS));
    }
    for (i=0; i < ntohl(statMsg->statCounters); i++) {
      if (mpos+strlen(&((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos])+1 > 
	  ntohs(statMsg->header.size) - sizeof(STATS_CS_MESSAGE)) {
	LOG(LOG_WARNING,
	    _("Received malformed stats message (%d > %d)\n"),
	    mpos+strlen(&((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos])+1,
	    ntohs(statMsg->header.size)-sizeof(STATS_CS_MESSAGE));
	break; /* out of bounds! */      
      }
      PRINTF("%-60s: %16llu\n",
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
 * Print statistics received from TCP socket.
 * @param stream where to print the statistics
 * @param sock the socket to use 
 * @return OK on success, SYSERR on error
 */
int requestAndPrintStatistic(GNUNET_TCP_SOCKET * sock,
			     char * name) {
  STATS_CS_MESSAGE * statMsg;
  CS_HEADER csHdr;
  unsigned int count;
  unsigned int i;
  int mpos;
  
  csHdr.size = htons(sizeof(CS_HEADER));
  csHdr.type = htons(STATS_CS_PROTO_GET_STATISTICS);
  if (SYSERR == writeToSocket(sock, &csHdr)) {
    PRINTF(_("Error sending request for statistics to peer.\n"));
    return SYSERR;
  }
  statMsg = MALLOC(MAX_BUFFER_SIZE);
  statMsg->totalCounters = htonl(1); /* to ensure we enter the loop */
  count = 0;
  while ( count < ntohl(statMsg->totalCounters) ) {
    /* printf("reading from socket starting %u of %d\n",
       count, ntohl(statMsg->totalCounters) );*/
    if (SYSERR == readFromSocket(sock,
				 (CS_HEADER**)&statMsg)) {
      PRINTF(_("Error receiving reply for statistics from peer.\n"));
      FREE(statMsg);
      return SYSERR;    
    }
    if (ntohs(statMsg->header.size) < sizeof(STATS_CS_MESSAGE)) {
      PRINTF(_("Error receiving reply for statistics from peer.\n"));
      LOG(LOG_WARNING,
	  _("received malformed stats message (%d < %d)\n"),
	  ntohs(statMsg->header.size), 
	  sizeof(STATS_CS_MESSAGE) );
      break;
    }
    mpos = sizeof(unsigned long long) * ntohl(statMsg->statCounters);
    if (count == 0) {
      if (0 == strcmp(name,
		      _("Uptime (seconds)")))
	PRINTF("%u\n",
	       (unsigned int) 
	       ((cronTime(NULL) - ntohll(statMsg->startTime))/
		cronSECONDS));
    }
    for (i=0; i<ntohl(statMsg->statCounters); i++) {
      if (mpos+strlen(&((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos])+1 > 
	  ntohs(statMsg->header.size) - sizeof(STATS_CS_MESSAGE)) {
	LOG(LOG_WARNING,
	    _("Received malformed stats message (%d > %d)\n"),
	    mpos+strlen(&((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos])+1,
	    ntohs(statMsg->header.size)-sizeof(STATS_CS_MESSAGE));
	break; /* out of bounds! */      
      }
      if (0 == strcmp(name,
		      &((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos]))
	PRINTF("%llu\n",
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
int requestAndPrintProtocols(GNUNET_TCP_SOCKET * sock) {
  STATS_CS_GET_MESSAGE_SUPPORTED csStatMsg;
  int i = 0;
  int supported = NO;
  const char *name = NULL;
  
  csStatMsg.header.size 
    = htons(sizeof(STATS_CS_GET_MESSAGE_SUPPORTED));  
  PRINTF(_("Supported Peer to Peer messages:\n"));
  csStatMsg.header.type
    = htons(STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED);
  for (i=0;i<65536;i++) {
    csStatMsg.type = htons(i);
    
    if (SYSERR == writeToSocket(sock, &csStatMsg.header)) {
      PRINTF(_("Error sending request for p2p protocol "
	       "status to gnunetd.\n"));
      return SYSERR;
    }
    if (SYSERR == readTCPResult(sock, &supported)) {
      PRINTF(_("Error reading p2p protocol status from gnunetd.\n"));
      return SYSERR;
    }
    
    if (supported == YES) {
      PRINTF("\t%d", i);
      name = p2pMessageName( i );
      if (name != NULL) {
	PRINTF("\t(%s)", name);
      }
      PRINTF("\n");
    }
  }
  PRINTF(_("Supported Client Server messages:\n"));
  csStatMsg.header.type
    = htons(STATS_CS_PROTO_GET_CS_MESSAGE_SUPPORTED);
  for (i=0;i<65536;i++) {
    csStatMsg.type = htons(i);   
    if (SYSERR == writeToSocket(sock, &csStatMsg.header)) {
      PRINTF(_("Error sending request for client-server "
	       "protocol status to gnunetd.\n"));
      return SYSERR;
    }
    if (SYSERR == readTCPResult(sock, &supported)) {
      PRINTF(_("Error reading client-server protocol "
	       "status from gnunetd.\n"));
      return SYSERR;
    }    
    if (supported == YES) {
      PRINTF("\t%d", i);
      name = csMessageName( i );
      if (name != NULL) {
	PRINTF("\t(%s)", name);
      }
      PRINTF("\n");
    }
  }
  return OK;
}


/* end of get-stats.c */
