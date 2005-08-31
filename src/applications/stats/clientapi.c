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
  case p2p_PROTO_hello :
    name = "p2p_PROTO_hello";
    break;
  case P2P_PROTO_setkey :
    name = "P2P_PROTO_setkey";
    break;
  case p2p_PROTO_PING :
    name = "p2p_PROTO_PING";
    break;
  case p2p_PROTO_PONG :
    name = "p2p_PROTO_PONG";
    break;
  case P2P_PROTO_noise :
    name = "P2P_PROTO_noise";
    break;
  case P2P_PROTO_hangup :
    name = "P2P_PROTO_hangup";
    break;
  case P2P_PROTO_chat_MSG :
    name = "P2P_PROTO_chat_MSG";
    break;
  case P2P_PROTO_tracekit_PROBE :
    name = "P2P_PROTO_tracekit_PROBE";
    break;
  case P2P_PROTO_tracekit_REPLY :
    name = "P2P_PROTO_tracekit_REPLY";
    break;
  case P2P_PROTO_tbench_REQUEST	:
    name = "P2P_PROTO_tbench_REQUEST";
    break;
  case P2P_PROTO_tbench_REPLY	:
    name = "P2P_PROTO_tbench_REPLY";
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
  case CS_PROTO_traffic_COUNT :
    name = "CS_PROTO_traffic_COUNT";
    break;
  case CS_PROTO_traffic_QUERY :
    name = "CS_PROTO_traffic_QUERY";
    break;
  case CS_PROTO_traffic_INFO :
    name = "CS_PROTO_traffic_INFO";
    break;
  case CS_PROTO_stats_GET_STATISTICS :
    name = "CS_PROTO_stats_GET_STATISTICS";
    break;
  case CS_PROTO_stats_STATISTICS :
    name = "CS_PROTO_stats_STATISTICS";
    break;
  case CS_PROTO_stats_GET_CS_MESSAGE_SUPPORTED :
    name = "CS_PROTO_stats_GET_CS_MESSAGE_SUPPORTED";
    break;
  case CS_PROTO_stats_GET_P2P_MESSAGE_SUPPORTED :
    name = "CS_PROTO_stats_GET_P2P_MESSAGE_SUPPORTED";
    break;
  case CS_PROTO_chat_MSG :
    name = "CS_PROTO_chat_MSG";
    break;
  case CS_PROTO_tracekit_PROBE :
    name = "CS_PROTO_tracekit_PROBE";
    break;
  case CS_PROTO_tracekit_REPLY :
    name = "CS_PROTO_tracekit_REPLY";
    break;
  case CS_PROTO_tbench_REQUEST :
    name = "CS_PROTO_tbench_REQUEST";
    break;
  case CS_PROTO_tbench_REPLY :
    name = "CS_PROTO_tbench_REPLY";
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
  CS_stats_reply_MESSAGE * statMsg;
  CS_MESSAGE_HEADER csHdr;
  unsigned int count;
  unsigned int i;
  int mpos;
  int ret;

  ret = OK;
  csHdr.size
    = htons(sizeof(CS_MESSAGE_HEADER));
  csHdr.type
    = htons(CS_PROTO_stats_GET_STATISTICS);
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
				 (CS_MESSAGE_HEADER**)&statMsg)) {
      FREE(statMsg);
      return SYSERR;
    }
    if (ntohs(statMsg->header.size) < sizeof(CS_stats_reply_MESSAGE)) {
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
      if (mpos+strlen(&((char*)(((CS_stats_reply_MESSAGE_GENERIC*)statMsg)->values))[mpos])+1 >
	  ntohs(statMsg->header.size) - sizeof(CS_stats_reply_MESSAGE)) {
	BREAK();
	ret = SYSERR;
	break; /* out of bounds! */
      }
      if (ret != SYSERR) {
	ret = processor(&((char*)(((CS_stats_reply_MESSAGE_GENERIC*)statMsg)->values))[mpos],
			ntohll(((CS_stats_reply_MESSAGE_GENERIC*)statMsg)->values[i]),
			cls);
      }
      mpos += strlen(&((char*)(((CS_stats_reply_MESSAGE_GENERIC*)statMsg)->values))[mpos])+1;
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
  CS_stats_get_supported_MESSAGE csStatMsg;
  unsigned short i;
  unsigned short j;
  int supported;
  int ret;

  ret = OK;
  csStatMsg.header.size
    = htons(sizeof(CS_stats_get_supported_MESSAGE));
  csStatMsg.header.type
    = htons(CS_PROTO_stats_GET_P2P_MESSAGE_SUPPORTED);
  for (j=2;j<4;j++) {
    csStatMsg.handlerType = htons(j);
    for (i=0;i<65535;i++) {
      csStatMsg.type = htons(i);
      if (SYSERR == writeToSocket(sock,
				  &csStatMsg.header))
	return SYSERR;
      if (SYSERR == readTCPResult(sock,
				  &supported))
	return SYSERR;
      if (supported == YES) {	
	ret = processor(i,
			(j == 2) ? YES : NO,
			cls);
	if (ret != OK)
	  break;
      }
    }
  }
  csStatMsg.header.type
    = htons(CS_PROTO_stats_GET_CS_MESSAGE_SUPPORTED);
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
