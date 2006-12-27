/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_protocols.h
 * @brief definition for GNUnet protocol numbers.
 *   This file is used whenever GNUnet components
 *   use integers to uniquely identify some type and
 *   where independent code may also use the same
 *   namespace.  By putting all of these constants
 *   into one header file it is easy to ensure that
 *   there are no conflicts between different
 *   parts of the code.
 * @author Christian Grothoff
 */

#ifndef GNUNET_PROTOCOLS_H
#define GNUNET_PROTOCOLS_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/* ********* transport protocol numbers ************* */

/**
 * These are the protocol numbers for the underlying GNUnet
 * protocols. They are typically taken to hint at a well-known
 * protocol, but they are not used in the same way. They just indicate
 * _internally_ to GNUnet which protocol from the TCP/IP suite to use
 * to run GNUnet over.
 */

/**
 * protocol number for "unspecified"
 */
#define ANY_PROTOCOL_NUMBER 0

/**
 * protocol number for 'NAT'.  Used as the advertisements for peers behind
 * a NAT box.
 */
#define NAT_PROTOCOL_NUMBER 1

/**
 * protocol number of TCP.
 */
#define TCP_PROTOCOL_NUMBER 2

/**
 * protocol number of UDP.
 */
#define UDP_PROTOCOL_NUMBER 3

/**
 * Protocol number for TCP on IPv6 (TCP+6)
 */
#define TCP6_PROTOCOL_NUMBER 4

/**
 * Protocol number for UDP on IPv6 (UDP+6)
 */
#define UDP6_PROTOCOL_NUMBER 5

/**
 * protocol number of TCP.
 */
#define TCP_OLD_PROTOCOL_NUMBER 6

/**
 * protocol number for HTTP (80 is too big, so 8 will have to do)
 */
#define HTTP_PROTOCOL_NUMBER 8

/**
 * protocol number of UDP. Do NEVER change, also used in other context!
 */
#define UDP_OLD_PROTOCOL_NUMBER 17

/**
 * protocol number for SMTP
 */
#define SMTP_PROTOCOL_NUMBER 25

/**
 * Largest protocol number.
 */
#define MAX_PROTOCOL_NUMBER 26

/* ********* client-server protocol (over TCP) ********** */
/* ********* CS CORE messages ********** */

/**
 * return value for remote calls (generic message)
 */
#define CS_PROTO_RETURN_VALUE 0

/**
 * client to gnunetd: shutdown
 */
#define CS_PROTO_SHUTDOWN_REQUEST 1

/**
 * client to gnunetd: get configuration option
 */
#define CS_PROTO_GET_OPTION_REQUEST 2

/**
 * gnunetd to client: option value
 */
#define CS_PROTO_GET_OPTION_REPLY 3

/**
 * gnunetd to client: error message
 */
#define CS_PROTO_RETURN_ERROR 4


/* ********** CS AFS application messages ********** */

/**
 * client to gnunetd: send queries
 */
#define CS_PROTO_gap_QUERY_START 8

/**
 * client to gnunetd: stop query
 */
#define CS_PROTO_gap_QUERY_STOP 9

/**
 * gnunetd to client: here is your answer
 */
#define CS_PROTO_gap_RESULT 9

/**
 * client to gnunetd: insert CHK content (no index)
 */
#define CS_PROTO_gap_INSERT 10

/**
 * client to gnunetd: index content
 */
#define CS_PROTO_gap_INDEX 11

/**
 * client to gnunetd: delete content
 */
#define CS_PROTO_gap_DELETE 12

/**
 * client to gnunetd: unindex content
 */
#define CS_PROTO_gap_UNINDEX 13

/**
 * client to gnunetd: test if content is indexed
 */
#define CS_PROTO_gap_TESTINDEX 14

/**
 * Client to gnunetd: what is the average priority of entries in the
 * routing table?
 */
#define CS_PROTO_gap_GET_AVG_PRIORITY 15

/**
 * client to gnunetd: initialize to index file
 */
#define CS_PROTO_gap_INIT_INDEX 16

/* *********** messages for traffic module ************* */

/**
 * client to traffic module: to how many nodes are we connected?
 * reply is a CS_returnvalue_MESSAGE message.
 */
#define CS_PROTO_traffic_COUNT 32

/**
 * Client to traffic module: how much traffic do we have at the moment?
 */
#define CS_PROTO_traffic_QUERY 33

/**
 * traffic module to client: traffic statistics
 */
#define CS_PROTO_traffic_INFO 34


/* *********** messages for stats module ************* */

/**
 * client to stats module: request statistics
 */
#define CS_PROTO_stats_GET_STATISTICS 36

/**
 * stats module to client: statistics
 */
#define CS_PROTO_stats_STATISTICS 37

/**
 * client to stats module: is client server message supported
 */
#define CS_PROTO_stats_GET_CS_MESSAGE_SUPPORTED 38

/**
 * client to stats module: is p2p message supported
 */
#define CS_PROTO_stats_GET_P2P_MESSAGE_SUPPORTED 39


/* ********** CS TBENCH application messages ********** */

#define CS_PROTO_tbench_REQUEST	40
#define CS_PROTO_tbench_REPLY	41


/* ********** CS TRACEKIT application messages ********* */

#define CS_PROTO_tracekit_PROBE 42
#define CS_PROTO_tracekit_REPLY 43


/* ********** CS CHAT application messages ********** */

#define CS_PROTO_chat_MSG 44


/* ********** CS DHT application messages ********** */

/**
 * Client to CS or CS to client: get from table
 */
#define CS_PROTO_dht_REQUEST_GET      48

/**
 * Client to CS or CS to client: put into table
 */
#define CS_PROTO_dht_REQUEST_PUT      49


/* ********** CS TESTBED application messages ********** */

#define CS_PROTO_testbed_REQUEST 50

#define CS_PROTO_testbed_REPLY   51



/* ************* CS VPN messages ************* */

/**
 * Most are commands available to clients
 * except VPN_MSG (general loggable output) and
 * VPN_REPLY = output from a command.
 * The commands output their last using their own code
 * instead of the VPN_REPLY so the UI knows it has
 * seen all the output.
 */
#define CS_PROTO_VPN_MSG 92
#define CS_PROTO_VPN_REPLY 93
#define CS_PROTO_VPN_DEBUGOFF 94
#define CS_PROTO_VPN_DEBUGON 95
#define CS_PROTO_VPN_TUNNELS 96
#define CS_PROTO_VPN_ROUTES 97
#define CS_PROTO_VPN_REALISED 98
#define CS_PROTO_VPN_RESET 99
#define CS_PROTO_VPN_REALISE 100
#define CS_PROTO_VPN_ADD 101
#define CS_PROTO_VPN_TRUST 102


#define CS_PROTO_MAX_USED 80

/* ******** node-to-node (p2p) messages (over anything) ********* */

/* ********* p2p infrastructure messages *********** */

/**
 * announcement of public key
 */
#define p2p_PROTO_hello 0

/**
 * session key exchange, session key is encrypted with hostkey
 */
#define P2P_PROTO_setkey 1

/**
 * PING
 */
#define p2p_PROTO_PING 2

/**
 * PONG (response to PING)
 */
#define p2p_PROTO_PONG 3

/**
 * termination of connection (other host is nice
 * and tells us, there is NO requirement to do so!)
 */
#define P2P_PROTO_hangup 4

/**
 * Fragmented message.
 */
#define P2P_PROTO_fragment 5

/**
 * noise, used to fill packets to sizes >1k.
 */
#define P2P_PROTO_noise 6


/* ************* p2p GAP application messages *********** */

/**
 * Query for content.
 */
#define P2P_PROTO_gap_QUERY 16

/**
 * receive content
 */
#define P2P_PROTO_gap_RESULT 17

/* ************** p2p CHAT application messages *********** */

/**
 * chat message
 */
#define P2P_PROTO_chat_MSG 32

/* *************** p2p TRACEKIT application messages ******** */

#define P2P_PROTO_tracekit_PROBE 36

#define P2P_PROTO_tracekit_REPLY 37

/* ********** p2p TBENCH application messages ********** */

/**
 * benchmark message: send back reply asap
 */
#define P2P_PROTO_tbench_REQUEST 40
#define P2P_PROTO_tbench_REPLY 	 41

/************** p2p RPC application messages ************/

#define P2P_PROTO_rpc_REQ 42
#define P2P_PROTO_rpc_RES 43
#define P2P_PROTO_rpc_ACK 44

/************** p2p DHT application messages ************/

#define P2P_PROTO_DHT_DISCOVERY 45
#define P2P_PROTO_DHT_ASK_HELLO 46
#define P2P_PROTO_DHT_GET       47
#define P2P_PROTO_DHT_PUT       48
#define P2P_PROTO_DHT_RESULT    49


/* ************* p2p VPN messages ************* */

#define P2P_PROTO_aip_IP 64	/* contains IPv6 frame */

#define P2P_PROTO_aip_ROUTE 65 /* a route to a node */

#define P2P_PROTO_aip_ROUTES 66 /* no more routes in my table */

#define P2P_PROTO_aip_GETROUTE 67 /* request for a table entry from a peer */


#define P2P_PROTO_MAX_USED 68



/* ************** Block types (libecrs) ************************ */

/**
 * Reserved number for "any type".
 */
#define ANY_BLOCK 0

/**
 * Data block (leaf or inner block).
 */
#define D_BLOCK 1

/**
 * Namespace binding (subspace entry)
 */
#define S_BLOCK 2

/**
 * Keyword binding (entry in keyword space)
 */
#define K_BLOCK 3

/**
 * Namespace advertisement.
 */
#define N_BLOCK 4

/**
 * Namespace advertisement in keyword space.
 */
#define KN_BLOCK 5

/**
 * DHT String2String (for dht-query/dht-join).
 */
#define DHT_STRING2STRING_BLOCK 7

/**
 * Reserved for internal usage
 */
#define RESERVED_BLOCK 0xFFFFFFFE

/**
 * Type of OnDemand encoded blocks.
 */
#define ONDEMAND_BLOCK 0xFFFFFFFF



#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif
#endif
