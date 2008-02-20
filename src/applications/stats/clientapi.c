/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
const char *
GNUNET_STATS_p2p_message_type_to_string (unsigned short type)
{
  const char *name = NULL;

  switch (type)
    {
    case GNUNET_P2P_PROTO_HELLO:
      name = "p2p_PROTO_hello";
      break;
    case GNUNET_P2P_PROTO_SET_KEY:
      name = "P2P_PROTO_setkey";
      break;
    case GNUNET_P2P_PROTO_PING:
      name = "p2p_PROTO_PING";
      break;
    case GNUNET_P2P_PROTO_PONG:
      name = "p2p_PROTO_PONG";
      break;
    case GNUNET_P2P_PROTO_HANG_UP:
      name = "P2P_PROTO_hangup";
      break;
    case GNUNET_P2P_PROTO_MESSAGE_FRAGMENT:
      name = "P2P_PROTO_fragment";
      break;
    case GNUNET_P2P_PROTO_NOISE:
      name = "P2P_PROTO_noise";
      break;

    case GNUNET_P2P_PROTO_GAP_QUERY:
      name = "P2P_PROTO_gap_QUERY";
      break;
    case GNUNET_P2P_PROTO_GAP_RESULT:
      name = "P2P_PROTO_gap_RESULT";
      break;

    case GNUNET_P2P_PROTO_CHAT_MSG:
      name = "P2P_PROTO_chat_MSG";
      break;

    case GNUNET_P2P_PROTO_TRACEKIT_PROBE:
      name = "P2P_PROTO_tracekit_PROBE";
      break;
    case GNUNET_P2P_PROTO_TRACEKIT_REPLY:
      name = "P2P_PROTO_tracekit_REPLY";
      break;

    case GNUNET_P2P_PROTO_TBENCH_REQUEST:
      name = "P2P_PROTO_tbench_REQUEST";
      break;
    case GNUNET_P2P_PROTO_TBENCH_REPLY:
      name = "P2P_PROTO_tbench_REPLY";
      break;

    case GNUNET_P2P_PROTO_RPC_REQ:
      name = "GNUNET_P2P_PROTO_RPC_REQ";
      break;
    case GNUNET_P2P_PROTO_RPC_RES:
      name = "GNUNET_P2P_PROTO_RPC_RES";
      break;
    case GNUNET_P2P_PROTO_RPC_ACK:
      name = "GNUNET_P2P_PROTO_RPC_ACK";
      break;

    case GNUNET_P2P_PROTO_DHT_DISCOVERY:
      name = "GNUNET_P2P_PROTO_DHT_DISCOVERY";
      break;
    case GNUNET_P2P_PROTO_DHT_ASK_HELLO:
      name = "GNUNET_P2P_PROTO_DHT_ASK_HELLO";
      break;
    case GNUNET_P2P_PROTO_DHT_GET:
      name = "GNUNET_P2P_PROTO_DHT_GET";
      break;
    case GNUNET_P2P_PROTO_DHT_PUT:
      name = "GNUNET_P2P_PROTO_DHT_PUT";
      break;
    case GNUNET_P2P_PROTO_DHT_RESULT:
      name = "GNUNET_P2P_PROTO_DHT_RESULT";
      break;

    case GNUNET_P2P_PROTO_AIP_IP:
      name = "GNUNET_P2P_PROTO_AIP_IP";
      break;
    case GNUNET_P2P_PROTO_AIP_ROUTE:
      name = "GNUNET_P2P_PROTO_AIP_ROUTE";
      break;
    case GNUNET_P2P_PROTO_AIP_ROUTES:
      name = "GNUNET_P2P_PROTO_AIP_ROUTES";
      break;
    case GNUNET_P2P_PROTO_AIP_GETROUTE:
      name = "GNUNET_P2P_PROTO_AIP_GETROUTE";
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
const char *
GNUNET_STATS_cs_message_type_to_string (unsigned short type)
{
  const char *name = NULL;

  switch (type)
    {
    case GNUNET_CS_PROTO_RETURN_VALUE:
      name = "CS_PROTO_RETURN_VALUE";
      break;
    case GNUNET_CS_PROTO_SHUTDOWN_REQUEST:
      name = "CS_PROTO_SHUTDOWN_REQUEST";
      break;
    case GNUNET_CS_PROTO_GET_OPTION_REQUEST:
      name = "CS_PROTO_GET_OPTION_REQUEST";
      break;
    case GNUNET_CS_PROTO_GET_OPTION_REPLY:
      name = "CS_PROTO_GET_OPTION_REPLY";
      break;
    case GNUNET_CS_PROTO_RETURN_ERROR:
      name = "CS_PROTO_RETURN_ERROR";
      break;

    case GNUNET_CS_PROTO_GAP_QUERY_START:
      name = "CS_PROTO_gap_QUERY_START";
      break;
    case GNUNET_CS_PROTO_GAP_RESULT:
      name = "CS_PROTO_gap_RESULT";
      break;
    case GNUNET_CS_PROTO_GAP_INSERT:
      name = "CS_PROTO_gap_INSERT";
      break;
    case GNUNET_CS_PROTO_GAP_INDEX:
      name = "CS_PROTO_gap_INDEX";
      break;
    case GNUNET_CS_PROTO_GAP_DELETE:
      name = "CS_PROTO_gap_DELETE";
      break;
    case GNUNET_CS_PROTO_GAP_UNINDEX:
      name = "CS_PROTO_gap_UNINDEX";
      break;
    case GNUNET_CS_PROTO_GAP_TESTINDEX:
      name = "CS_PROTO_gap_TESTINDEX";
      break;
    case GNUNET_CS_PROTO_GAP_INIT_INDEX:
      name = "CS_PROTO_gap_INIT_INDEX";
      break;

    case GNUNET_CS_PROTO_TRAFFIC_COUNT:
      name = "GNUNET_CS_PROTO_TRAFFIC_COUNT";
      break;
    case GNUNET_CS_PROTO_TRAFFIC_QUERY:
      name = "GNUNET_CS_PROTO_TRAFFIC_QUERY";
      break;
    case GNUNET_CS_PROTO_TRAFFIC_INFO:
      name = "GNUNET_CS_PROTO_TRAFFIC_INFO";
      break;

    case GNUNET_CS_PROTO_STATS_GET_STATISTICS:
      name = "GNUNET_CS_PROTO_STATS_GET_STATISTICS";
      break;
    case GNUNET_CS_PROTO_STATS_STATISTICS:
      name = "GNUNET_CS_PROTO_STATS_STATISTICS";
      break;
    case GNUNET_CS_PROTO_STATS_GET_CS_MESSAGE_SUPPORTED:
      name = "GNUNET_CS_PROTO_STATS_GET_CS_MESSAGE_SUPPORTED";
      break;
    case GNUNET_CS_PROTO_STATS_GET_P2P_MESSAGE_SUPPORTED:
      name = "GNUNET_CS_PROTO_STATS_GET_P2P_MESSAGE_SUPPORTED";
      break;

    case GNUNET_CS_PROTO_TBENCH_REQUEST:
      name = "GNUNET_CS_PROTO_TBENCH_REQUEST";
      break;
    case GNUNET_CS_PROTO_TBENCH_REPLY:
      name = "GNUNET_CS_PROTO_TBENCH_REPLY";
      break;

    case GNUNET_CS_PROTO_TRACEKIT_PROBE:
      name = "GNUNET_CS_PROTO_TRACEKIT_PROBE";
      break;
    case GNUNET_CS_PROTO_TRACEKIT_REPLY:
      name = "GNUNET_CS_PROTO_TRACEKIT_REPLY";
      break;

    case GNUNET_CS_PROTO_CHAT_MSG:
      name = "GNUNET_CS_PROTO_CHAT_MSG";
      break;

    case GNUNET_CS_PROTO_DHT_REQUEST_GET:
      name = "GNUNET_CS_PROTO_DHT_REQUEST_GET";
      break;
    case GNUNET_CS_PROTO_DHT_REQUEST_PUT:
      name = "GNUNET_CS_PROTO_DHT_REQUEST_PUT";
      break;

    case GNUNET_CS_PROTO_TESTBED_REQUEST:
      name = "GNUNET_CS_PROTO_TESTBED_REQUEST";
      break;
    case GNUNET_CS_PROTO_TESTBED_REPLY:
      name = "GNUNET_CS_PROTO_TESTBED_REPLY";
      break;

    case GNUNET_CS_PROTO_VPN_MSG:
      name = "GNUNET_CS_PROTO_VPN_MSG";
      break;
    case GNUNET_CS_PROTO_VPN_REPLY:
      name = "GNUNET_CS_PROTO_VPN_REPLY";
      break;
    case GNUNET_CS_PROTO_VPN_TUNNELS:
      name = "GNUNET_CS_PROTO_VPN_TUNNELS";
      break;
    case GNUNET_CS_PROTO_VPN_ROUTES:
      name = "GNUNET_CS_PROTO_VPN_ROUTES";
      break;
    case GNUNET_CS_PROTO_VPN_REALISED:
      name = "GNUNET_CS_PROTO_VPN_REALISED";
      break;
    case GNUNET_CS_PROTO_VPN_RESET:
      name = "GNUNET_CS_PROTO_VPN_RESET";
      break;
    case GNUNET_CS_PROTO_VPN_ADD:
      name = "GNUNET_CS_PROTO_VPN_ADD";
      break;
    case GNUNET_CS_PROTO_VPN_TRUST:
      name = "GNUNET_CS_PROTO_VPN_TRUST";
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
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_STATS_get_statistics (struct GNUNET_GE_Context *ectx,
                             struct GNUNET_ClientServerConnection *sock,
                             GNUNET_STATS_StatisticsProcessor processor,
                             void *cls)
{
  CS_stats_reply_MESSAGE *statMsg;
  GNUNET_MessageHeader csHdr;
  unsigned int count;
  unsigned int i;
  int mpos;
  int ret;

  ret = GNUNET_OK;
  csHdr.size = htons (sizeof (GNUNET_MessageHeader));
  csHdr.type = htons (GNUNET_CS_PROTO_STATS_GET_STATISTICS);
  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &csHdr))
    return GNUNET_SYSERR;
  statMsg = GNUNET_malloc (sizeof (CS_stats_reply_MESSAGE));
  statMsg->totalCounters = htonl (1);   /* to ensure we enter the loop */
  count = 0;
  while (count < ntohl (statMsg->totalCounters))
    {
      GNUNET_free (statMsg);
      statMsg = NULL;
      /* printf("reading from socket starting %u of %d\n",
         count, ntohl(statMsg->totalCounters) ); */
      if (GNUNET_SYSERR ==
          GNUNET_client_connection_read (sock,
                                         (GNUNET_MessageHeader **) & statMsg))
        return GNUNET_SYSERR;
      if ((ntohs (statMsg->header.size) < sizeof (CS_stats_reply_MESSAGE)) ||
          (((char *) statMsg)[ntohs (statMsg->header.size) - 1] != '\0'))
        {
          GNUNET_GE_BREAK (ectx, 0);
          ret = GNUNET_SYSERR;
          break;
        }
      mpos = sizeof (unsigned long long) * ntohl (statMsg->statCounters);
      if (count == 0)
        {
          ret = processor (_("Uptime (seconds)"),
                           (unsigned long long)
                           ((GNUNET_get_time () -
                             GNUNET_ntohll (statMsg->startTime)) /
                            GNUNET_CRON_SECONDS), cls);
        }
      for (i = 0; i < ntohl (statMsg->statCounters); i++)
        {
          if (mpos +
              strlen (&
                      ((char
                        *) (((CS_stats_reply_MESSAGE_GENERIC *)
                             statMsg)->values))[mpos]) + 1 >
              ntohs (statMsg->header.size) - sizeof (CS_stats_reply_MESSAGE))
            {
              GNUNET_GE_BREAK (ectx, 0);
              ret = GNUNET_SYSERR;
              break;            /* out of bounds! */
            }
          if (ret != GNUNET_SYSERR)
            {
              ret =
                processor (&
                           ((char
                             *) (((CS_stats_reply_MESSAGE_GENERIC *)
                                  statMsg)->values))[mpos],
                           GNUNET_ntohll (((CS_stats_reply_MESSAGE_GENERIC *)
                                           statMsg)->values[i]), cls);
            }
          mpos +=
            strlen (&
                    ((char
                      *) (((CS_stats_reply_MESSAGE_GENERIC *)
                           statMsg)->values))[mpos]) + 1;
        }
      count += ntohl (statMsg->statCounters);
    }                           /* end while */
  GNUNET_free (statMsg);
  return ret;
}


/**
 * Request available protocols from TCP socket.
 * @param sock the socket to use
 * @param processor function to call on each value
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_STATS_get_available_protocols (struct GNUNET_GE_Context *ectx,
                                      struct GNUNET_ClientServerConnection
                                      *sock,
                                      GNUNET_STATS_ProtocolProcessor
                                      processor, void *cls)
{
  CS_stats_get_supported_MESSAGE csStatMsg;
  unsigned short i;
  unsigned short j;
  int supported;
  int ret;

  ret = GNUNET_OK;
  csStatMsg.header.size = htons (sizeof (CS_stats_get_supported_MESSAGE));
  csStatMsg.header.type =
    htons (GNUNET_CS_PROTO_STATS_GET_P2P_MESSAGE_SUPPORTED);
  for (j = 2; j < 4; j++)
    {
      csStatMsg.handlerType = htons (j);
      for (i = 0; i < 65535; i++)
        {
          csStatMsg.type = htons (i);
          if (GNUNET_SYSERR ==
              GNUNET_client_connection_write (sock, &csStatMsg.header))
            return GNUNET_SYSERR;
          if (GNUNET_SYSERR ==
              GNUNET_client_connection_read_result (sock, &supported))
            return GNUNET_SYSERR;
          if (supported == GNUNET_YES)
            {
              ret = processor (i, (j == 2) ? GNUNET_YES : GNUNET_NO, cls);
              if (ret != GNUNET_OK)
                break;
            }
        }
    }
  return GNUNET_OK;
}

/* end of clientapi.c */
