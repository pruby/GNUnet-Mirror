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
 * @file applications/stats/clientapi.c 
 * @brief convenience API to the stats service
 * @author Christian Grothoff
 * @author Igor Wronsky
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_stats_lib.h"
#include "statistics.h"

/**
 * Return a descriptive name for a p2p message type
 */
const char * p2pMessageName(unsigned short type) {
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
const char *csMessageName(unsigned short type) {
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
 * Request statistics from TCP socket.
 * @param sock the socket to use 
 * @param processor function to call on each value
 * @return OK on success, SYSERR on error
 */
int requestStatistics(GNUNET_TCP_SOCKET * sock,
		      StatisticsProcessor processor,
		      void * cls) {
  STATS_CS_MESSAGE * statMsg;
  CS_HEADER csHdr;
  unsigned int count;
  unsigned int i;
  int mpos;
  int ret;
  
  ret = OK;
  csHdr.size 
    = htons(sizeof(CS_HEADER));
  csHdr.type
    = htons(STATS_CS_PROTO_GET_STATISTICS);
  if (SYSERR == writeToSocket(sock,
			      &csHdr)) 
    return SYSERR;  
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
      FREE(statMsg);
      return SYSERR;    
    }
    if (ntohs(statMsg->header.size) < sizeof(STATS_CS_MESSAGE)) {
      BREAK();
      ret = SYSERR;
      break;
    }
    mpos = sizeof(unsigned long long) * ntohl(statMsg->statCounters);
    if (count == 0) {
      ret = processor(_("Uptime (seconds)"),
		      (unsigned long long) 
		      ((cronTime(NULL) - ntohll(statMsg->startTime))/cronSECONDS),
		      cls);
    }
    for (i=0;i<ntohl(statMsg->statCounters);i++) {
      if (mpos+strlen(&((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos])+1 > 
	  ntohs(statMsg->header.size) - sizeof(STATS_CS_MESSAGE)) {
	BREAK();
	ret = SYSERR;
	break; /* out of bounds! */      
      }
      if (ret != SYSERR) {
	char desc[61];
	SNPRINTF(desc, 
		 61, 
		 "%60s", 
		 &((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos]);
	ret = processor(desc,
			ntohll(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values[i]),
			cls);
      }
      mpos += strlen(&((char*)(((STATS_CS_MESSAGE_GENERIC*)statMsg)->values))[mpos])+1;
    }    
    count += ntohl(statMsg->statCounters);
  } /* end while */
  FREE(statMsg);
  return ret;
}


/**
 * Request available protocols from TCP socket.
 * @param sock the socket to use 
 * @param processor function to call on each value
 * @return OK on success, SYSERR on error
 */
int requestAvailableProtocols(GNUNET_TCP_SOCKET * sock,
			      ProtocolProcessor processor,
			      void * cls) {
  STATS_CS_GET_MESSAGE_SUPPORTED csStatMsg;
  unsigned short i;
  int supported;
  int ret;

  ret = OK;
  csStatMsg.header.size 
    = htons(sizeof(STATS_CS_GET_MESSAGE_SUPPORTED));
  csStatMsg.header.type
    = htons(STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED);
  for (i=0;i<65535;i++) {
    csStatMsg.type = htons(i);
    if (SYSERR == writeToSocket(sock, 
				&csStatMsg.header)) 
      return SYSERR;
    if (SYSERR == readTCPResult(sock,
				&supported)) 
      return SYSERR;
    if (supported == YES) {
      ret = processor(i, YES, cls);
      if (ret != OK)
	break;
    }
  }
  csStatMsg.header.type
    = htons(STATS_CS_PROTO_GET_CS_MESSAGE_SUPPORTED);
  for (i=0;i<65535;i++) {
    csStatMsg.type = htons(i);
    if (SYSERR == writeToSocket(sock, 
				&csStatMsg.header)) 
      return SYSERR;   
    if (SYSERR == readTCPResult(sock, &supported)) 
      return SYSERR;
    if (supported == YES) {
      ret = processor(i, NO, cls);
      if (ret != OK)
	break;
    }
  }
  return OK;
}

/* end of clientapi.c */
