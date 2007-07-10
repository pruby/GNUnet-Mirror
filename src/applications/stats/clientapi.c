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
STATS_p2pMessageName (unsigned short type)
{
  const char *name = NULL;

  switch (type)
    {
    case p2p_PROTO_hello:
      name = "p2p_PROTO_hello";
      break;
    case P2P_PROTO_setkey:
      name = "P2P_PROTO_setkey";
      break;
    case p2p_PROTO_PING:
      name = "p2p_PROTO_PING";
      break;
    case p2p_PROTO_PONG:
      name = "p2p_PROTO_PONG";
      break;
    case P2P_PROTO_hangup:
      name = "P2P_PROTO_hangup";
      break;
    case P2P_PROTO_fragment:
      name = "P2P_PROTO_fragment";
      break;
    case P2P_PROTO_noise:
      name = "P2P_PROTO_noise";
      break;

    case P2P_PROTO_gap_QUERY:
      name = "P2P_PROTO_gap_QUERY";
      break;
    case P2P_PROTO_gap_RESULT:
      name = "P2P_PROTO_gap_RESULT";
      break;

    case P2P_PROTO_chat_MSG:
      name = "P2P_PROTO_chat_MSG";
      break;

    case P2P_PROTO_tracekit_PROBE:
      name = "P2P_PROTO_tracekit_PROBE";
      break;
    case P2P_PROTO_tracekit_REPLY:
      name = "P2P_PROTO_tracekit_REPLY";
      break;

    case P2P_PROTO_tbench_REQUEST:
      name = "P2P_PROTO_tbench_REQUEST";
      break;
    case P2P_PROTO_tbench_REPLY:
      name = "P2P_PROTO_tbench_REPLY";
      break;

    case P2P_PROTO_rpc_REQ:
      name = "P2P_PROTO_rpc_REQ";
      break;
    case P2P_PROTO_rpc_RES:
      name = "P2P_PROTO_rpc_RES";
      break;
    case P2P_PROTO_rpc_ACK:
      name = "P2P_PROTO_rpc_ACK";
      break;

    case P2P_PROTO_DHT_DISCOVERY:
      name = "P2P_PROTO_DHT_DISCOVERY";
      break;
    case P2P_PROTO_DHT_ASK_HELLO:
      name = "P2P_PROTO_DHT_ASK_HELLO";
      break;
    case P2P_PROTO_DHT_GET:
      name = "P2P_PROTO_DHT_GET";
      break;
    case P2P_PROTO_DHT_PUT:
      name = "P2P_PROTO_DHT_PUT";
      break;
    case P2P_PROTO_DHT_RESULT:
      name = "P2P_PROTO_DHT_RESULT";
      break;

    case P2P_PROTO_aip_IP:
      name = "P2P_PROTO_aip_IP";
      break;
    case P2P_PROTO_aip_ROUTE:
      name = "P2P_PROTO_aip_ROUTE";
      break;
    case P2P_PROTO_aip_ROUTES:
      name = "P2P_PROTO_aip_ROUTES";
      break;
    case P2P_PROTO_aip_GETROUTE:
      name = "P2P_PROTO_aip_GETROUTE";
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
STATS_csMessageName (unsigned short type)
{
  const char *name = NULL;

  switch (type)
    {
    case CS_PROTO_RETURN_VALUE:
      name = "CS_PROTO_RETURN_VALUE";
      break;
    case CS_PROTO_SHUTDOWN_REQUEST:
      name = "CS_PROTO_SHUTDOWN_REQUEST";
      break;
    case CS_PROTO_GET_OPTION_REQUEST:
      name = "CS_PROTO_GET_OPTION_REQUEST";
      break;
    case CS_PROTO_GET_OPTION_REPLY:
      name = "CS_PROTO_GET_OPTION_REPLY";
      break;
    case CS_PROTO_RETURN_ERROR:
      name = "CS_PROTO_RETURN_ERROR";
      break;

    case CS_PROTO_gap_QUERY_START:
      name = "CS_PROTO_gap_QUERY_START";
      break;
    case CS_PROTO_gap_QUERY_STOP:
      /* case CS_PROTO_gap_RESULT : */
      name = "CS_PROTO_gap_QUERY_STOP or CS_PROTO_gap_RESULT";
      break;
    case CS_PROTO_gap_INSERT:
      name = "CS_PROTO_gap_INSERT";
      break;
    case CS_PROTO_gap_INDEX:
      name = "CS_PROTO_gap_INDEX";
      break;
    case CS_PROTO_gap_DELETE:
      name = "CS_PROTO_gap_DELETE";
      break;
    case CS_PROTO_gap_UNINDEX:
      name = "CS_PROTO_gap_UNINDEX";
      break;
    case CS_PROTO_gap_TESTINDEX:
      name = "CS_PROTO_gap_TESTINDEX";
      break;
    case CS_PROTO_gap_GET_AVG_PRIORITY:
      name = "CS_PROTO_gap_GET_AVG_PRIORITY";
      break;
    case CS_PROTO_gap_INIT_INDEX:
      name = "CS_PROTO_gap_INIT_INDEX";
      break;

    case CS_PROTO_traffic_COUNT:
      name = "CS_PROTO_traffic_COUNT";
      break;
    case CS_PROTO_traffic_QUERY:
      name = "CS_PROTO_traffic_QUERY";
      break;
    case CS_PROTO_traffic_INFO:
      name = "CS_PROTO_traffic_INFO";
      break;

    case CS_PROTO_stats_GET_STATISTICS:
      name = "CS_PROTO_stats_GET_STATISTICS";
      break;
    case CS_PROTO_stats_STATISTICS:
      name = "CS_PROTO_stats_STATISTICS";
      break;
    case CS_PROTO_stats_GET_CS_MESSAGE_SUPPORTED:
      name = "CS_PROTO_stats_GET_CS_MESSAGE_SUPPORTED";
      break;
    case CS_PROTO_stats_GET_P2P_MESSAGE_SUPPORTED:
      name = "CS_PROTO_stats_GET_P2P_MESSAGE_SUPPORTED";
      break;

    case CS_PROTO_tbench_REQUEST:
      name = "CS_PROTO_tbench_REQUEST";
      break;
    case CS_PROTO_tbench_REPLY:
      name = "CS_PROTO_tbench_REPLY";
      break;

    case CS_PROTO_tracekit_PROBE:
      name = "CS_PROTO_tracekit_PROBE";
      break;
    case CS_PROTO_tracekit_REPLY:
      name = "CS_PROTO_tracekit_REPLY";
      break;

    case CS_PROTO_chat_MSG:
      name = "CS_PROTO_chat_MSG";
      break;

    case CS_PROTO_dht_REQUEST_GET:
      name = "CS_PROTO_dht_REQUEST_GET";
      break;
    case CS_PROTO_dht_REQUEST_PUT:
      name = "CS_PROTO_dht_REQUEST_PUT";
      break;

    case CS_PROTO_testbed_REQUEST:
      name = "CS_PROTO_testbed_REQUEST";
      break;
    case CS_PROTO_testbed_REPLY:
      name = "CS_PROTO_testbed_REPLY";
      break;

    case CS_PROTO_VPN_MSG:
      name = "CS_PROTO_VPN_MSG";
      break;
    case CS_PROTO_VPN_REPLY:
      name = "CS_PROTO_VPN_REPLY";
      break;
    case CS_PROTO_VPN_DEBUGOFF:
      name = "CS_PROTO_VPN_DEBUGOFF";
      break;
    case CS_PROTO_VPN_TUNNELS:
      name = "CS_PROTO_VPN_TUNNELS";
      break;
    case CS_PROTO_VPN_ROUTES:
      name = "CS_PROTO_VPN_ROUTES";
      break;
    case CS_PROTO_VPN_REALISED:
      name = "CS_PROTO_VPN_REALISED";
      break;
    case CS_PROTO_VPN_RESET:
      name = "CS_PROTO_VPN_RESET";
      break;
    case CS_PROTO_VPN_REALISE:
      name = "CS_PROTO_VPN_REALISE";
      break;
    case CS_PROTO_VPN_ADD:
      name = "CS_PROTO_VPN_ADD";
      break;
    case CS_PROTO_VPN_TRUST:
      name = "CS_PROTO_VPN_TRUST";
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
int
STATS_getStatistics (struct GE_Context *ectx,
                     struct ClientServerConnection *sock,
                     STATS_StatProcessor processor, void *cls)
{
  CS_stats_reply_MESSAGE *statMsg;
  MESSAGE_HEADER csHdr;
  unsigned int count;
  unsigned int i;
  int mpos;
  int ret;

  ret = OK;
  csHdr.size = htons (sizeof (MESSAGE_HEADER));
  csHdr.type = htons (CS_PROTO_stats_GET_STATISTICS);
  if (SYSERR == connection_write (sock, &csHdr))
    return SYSERR;
  statMsg = MALLOC (sizeof (CS_stats_reply_MESSAGE));
  statMsg->totalCounters = htonl (1);   /* to ensure we enter the loop */
  count = 0;
  while (count < ntohl (statMsg->totalCounters))
    {
      FREE (statMsg);
      statMsg = NULL;
      /* printf("reading from socket starting %u of %d\n",
         count, ntohl(statMsg->totalCounters) ); */
      if (SYSERR == connection_read (sock, (MESSAGE_HEADER **) & statMsg))
        return SYSERR;
      if ((ntohs (statMsg->header.size) < sizeof (CS_stats_reply_MESSAGE)) ||
          (((char *) statMsg)[ntohs (statMsg->header.size) - 1] != '\0'))
        {
          GE_BREAK (ectx, 0);
          ret = SYSERR;
          break;
        }
      mpos = sizeof (unsigned long long) * ntohl (statMsg->statCounters);
      if (count == 0)
        {
          ret = processor (_("Uptime (seconds)"),
                           (unsigned long long)
                           ((get_time () -
                             ntohll (statMsg->startTime)) / cronSECONDS),
                           cls);
        }
      for (i = 0; i < ntohl (statMsg->statCounters); i++)
        {
          if (mpos +
              strlen (&
                      ((char
                        *) (((CS_stats_reply_MESSAGE_GENERIC *) statMsg)->
                            values))[mpos]) + 1 >
              ntohs (statMsg->header.size) - sizeof (CS_stats_reply_MESSAGE))
            {
              GE_BREAK (ectx, 0);
              ret = SYSERR;
              break;            /* out of bounds! */
            }
          if (ret != SYSERR)
            {
              ret =
                processor (&
                           ((char
                             *) (((CS_stats_reply_MESSAGE_GENERIC *)
                                  statMsg)->values))[mpos],
                           ntohll (((CS_stats_reply_MESSAGE_GENERIC *)
                                    statMsg)->values[i]), cls);
            }
          mpos +=
            strlen (&
                    ((char *) (((CS_stats_reply_MESSAGE_GENERIC *) statMsg)->
                               values))[mpos]) + 1;
        }
      count += ntohl (statMsg->statCounters);
    }                           /* end while */
  FREE (statMsg);
  return ret;
}


/**
 * Request available protocols from TCP socket.
 * @param sock the socket to use
 * @param processor function to call on each value
 * @return OK on success, SYSERR on error
 */
int
STATS_getAvailableProtocols (struct GE_Context *ectx,
                             struct ClientServerConnection *sock,
                             STATS_ProtocolProcessor processor, void *cls)
{
  CS_stats_get_supported_MESSAGE csStatMsg;
  unsigned short i;
  unsigned short j;
  int supported;
  int ret;

  ret = OK;
  csStatMsg.header.size = htons (sizeof (CS_stats_get_supported_MESSAGE));
  csStatMsg.header.type = htons (CS_PROTO_stats_GET_P2P_MESSAGE_SUPPORTED);
  for (j = 2; j < 4; j++)
    {
      csStatMsg.handlerType = htons (j);
      for (i = 0; i < 65535; i++)
        {
          csStatMsg.type = htons (i);
          if (SYSERR == connection_write (sock, &csStatMsg.header))
            return SYSERR;
          if (SYSERR == connection_read_result (sock, &supported))
            return SYSERR;
          if (supported == YES)
            {
              ret = processor (i, (j == 2) ? YES : NO, cls);
              if (ret != OK)
                break;
            }
        }
    }
  return OK;
}

/* end of clientapi.c */
