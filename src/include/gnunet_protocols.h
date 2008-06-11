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
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
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
#define GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY 0

/**
 * protocol number for 'NAT'.  Used as the advertisements for peers behind
 * a NAT box.
 */
#define GNUNET_TRANSPORT_PROTOCOL_NUMBER_NAT 1

/**
 * protocol number of TCP.
 */
#define GNUNET_TRANSPORT_PROTOCOL_NUMBER_TCP 6

/**
 * protocol number of UDP.
 */
#define GNUNET_TRANSPORT_PROTOCOL_NUMBER_UDP 7

/**
 * protocol number for HTTP (80 is too big, so 8 will have to do)
 */
#define GNUNET_TRANSPORT_PROTOCOL_NUMBER_HTTP 8

/**
 * protocol number for SMTP
 */
#define GNUNET_TRANSPORT_PROTOCOL_NUMBER_SMTP 25

/**
 * Largest protocol number.
 */
#define GNUNET_TRANSPORT_PROTOCOL_NUMBER_MAX 26

/* ********* client-server protocol (over TCP) ********** */
/* ********* CS CORE messages ********** */

/**
 * return value for remote calls (generic message)
 */
#define GNUNET_CS_PROTO_RETURN_VALUE 0

/**
 * client to gnunetd: shutdown
 */
#define GNUNET_CS_PROTO_SHUTDOWN_REQUEST 1

/**
 * client to gnunetd: get configuration option
 */
#define GNUNET_CS_PROTO_GET_OPTION_REQUEST 2

/**
 * gnunetd to client: option value
 */
#define GNUNET_CS_PROTO_GET_OPTION_REPLY 3

/**
 * gnunetd to client: error message
 */
#define GNUNET_CS_PROTO_RETURN_ERROR 4


/* ********** CS FS application messages ********** */

/**
 * client to gnunetd: send queries
 */
#define GNUNET_CS_PROTO_GAP_QUERY_START 8

/**
 * client to gnunetd: stop query
 */
#define GNUNET_CS_PROTO_GAP_QUERY_STOP 9

/**
 * gnunetd to client: here is your answer
 * (yes, same number as stop query!)
 */
#define GNUNET_CS_PROTO_GAP_RESULT 9

/**
 * client to gnunetd: insert GNUNET_EC_ContentHashKey content (no index)
 */
#define GNUNET_CS_PROTO_GAP_INSERT 10

/**
 * client to gnunetd: index content
 */
#define GNUNET_CS_PROTO_GAP_INDEX 11

/**
 * client to gnunetd: delete content
 */
#define GNUNET_CS_PROTO_GAP_DELETE 12

/**
 * client to gnunetd: unindex content
 */
#define GNUNET_CS_PROTO_GAP_UNINDEX 13

/**
 * client to gnunetd: test if content is indexed
 */
#define GNUNET_CS_PROTO_GAP_TESTINDEX 14

/**
 * client to gnunetd: initialize to index file
 */
#define GNUNET_CS_PROTO_GAP_INIT_INDEX 15


/* *********** messages for identity module ************* */

/**
 * Client asks daemon for information about
 * all known peers
 */
#define GNUNET_CS_PROTO_IDENTITY_REQUEST_INFO 25

/**
 * Deamon responds with information about a peer.
 */
#define GNUNET_CS_PROTO_IDENTITY_INFO 26

/**
 * Client asks the Daemon about how to contact
 * it.
 */
#define GNUNET_CS_PROTO_IDENTITY_REQUEST_HELLO 27

/**
 * Client informs the Daemon about how to contact
 * a particular peer -- or daemon informs client
 * about how other peers should contact it.
 */
#define GNUNET_CS_PROTO_IDENTITY_HELLO 28

/**
 * Client asks the Daemon to GNUNET_RSA_sign a message.
 */
#define GNUNET_CS_PROTO_IDENTITY_REQUEST_SIGNATURE 29

/**
 * Daemon sends client a signature
 */
#define GNUNET_CS_PROTO_IDENTITY_SIGNATURE 30

/**
 * Client asks the daemon to try to connect to
 * a particular peer.
 */
#define GNUNET_CS_PROTO_IDENTITY_CONNECT 31


/* *********** messages for traffic module ************* */

/**
 * client to traffic module: to how many nodes are we connected?
 * reply is a CS_returnvalue_MESSAGE message.
 */
#define GNUNET_CS_PROTO_TRAFFIC_COUNT 32

/**
 * Client to traffic module: how much traffic do we have at the moment?
 */
#define GNUNET_CS_PROTO_TRAFFIC_QUERY 33

/**
 * traffic module to client: traffic statistics
 */
#define GNUNET_CS_PROTO_TRAFFIC_INFO 34


/* *********** messages for stats module ************* */

/**
 * client to stats module: request statistics
 */
#define GNUNET_CS_PROTO_STATS_GET_STATISTICS 36

/**
 * stats module to client: statistics
 */
#define GNUNET_CS_PROTO_STATS_STATISTICS 37

/**
 * client to stats module: is client server message supported
 */
#define GNUNET_CS_PROTO_STATS_GET_CS_MESSAGE_SUPPORTED 38

/**
 * client to stats module: is p2p message supported
 */
#define GNUNET_CS_PROTO_STATS_GET_P2P_MESSAGE_SUPPORTED 39


/* ********** CS TBENCH application messages ********** */

#define GNUNET_CS_PROTO_TBENCH_REQUEST	40
#define GNUNET_CS_PROTO_TBENCH_REPLY	41


/* ********** CS TRACEKIT application messages ********* */

#define GNUNET_CS_PROTO_TRACEKIT_PROBE 42
#define GNUNET_CS_PROTO_TRACEKIT_REPLY 43


/* ********** CS CHAT application messages ********** */

#define GNUNET_CS_PROTO_CHAT_JOIN_REQUEST 44
#define GNUNET_CS_PROTO_CHAT_JOIN_NOTIFICATION 45
#define GNUNET_CS_PROTO_CHAT_LEAVE_NOTIFICATION 46
#define GNUNET_CS_PROTO_CHAT_MESSAGE_NOTIFICATION 47
#define GNUNET_CS_PROTO_CHAT_TRANSMIT_REQUEST 48
#define GNUNET_CS_PROTO_CHAT_CONFIRMATION_RECEIPT 49

/* ********** CS DHT application messages ********** */

/**
 * Client to CS or CS to client: get from table (starts request)
 */
#define GNUNET_CS_PROTO_DHT_REQUEST_GET      60

/**
 * Client to CS or CS to client: put into table
 */
#define GNUNET_CS_PROTO_DHT_REQUEST_PUT      61
/**
 * Client to CS: end get from table (ends request)
 */
#define GNUNET_CS_PROTO_DHT_REQUEST_GET_END      62
/* ************* CS VPN messages ************* */

/**
 * Most are commands available to clients
 * except VPN_MSG (general loggable output) and
 * VPN_REPLY = output from a command.
 * The commands output their last using their own code
 * instead of the VPN_REPLY so the UI knows it has
 * seen all the output.
 */
#define GNUNET_CS_PROTO_VPN_MSG 64
#define GNUNET_CS_PROTO_VPN_REPLY 65
#define GNUNET_CS_PROTO_VPN_TUNNELS 66
#define GNUNET_CS_PROTO_VPN_ROUTES 67
#define GNUNET_CS_PROTO_VPN_REALISED 68
#define GNUNET_CS_PROTO_VPN_RESET 69
#define GNUNET_CS_PROTO_VPN_ADD 70
#define GNUNET_CS_PROTO_VPN_TRUST 71


#define GNUNET_CS_PROTO_MAX_USED 80

/* ******** node-to-node (p2p) messages (over anything) ********* */

/* ********* p2p infrastructure messages *********** */

/**
 * announcement of public key
 */
#define GNUNET_P2P_PROTO_HELLO 0

/**
 * session key exchange, session key is encrypted with hostkey
 */
#define GNUNET_P2P_PROTO_SET_KEY 1

/**
 * PING
 */
#define GNUNET_P2P_PROTO_PING 2

/**
 * PONG (response to PING)
 */
#define GNUNET_P2P_PROTO_PONG 3

/**
 * termination of connection (other host is nice
 * and tells us, there is GNUNET_NO requirement to do so!)
 */
#define GNUNET_P2P_PROTO_HANG_UP 4

/**
 * Fragmented message.
 */
#define GNUNET_P2P_PROTO_MESSAGE_FRAGMENT 5

/**
 * noise, used to fill packets to sizes >1k.
 */
#define GNUNET_P2P_PROTO_NOISE 6


/* ************* p2p GAP application messages *********** */

/**
 * Query for content.
 */
#define GNUNET_P2P_PROTO_GAP_QUERY 8

/**
 * receive content
 */
#define GNUNET_P2P_PROTO_GAP_RESULT 9

/************** p2p DHT application messages ************/

#define GNUNET_P2P_PROTO_DHT_DISCOVERY 18
#define GNUNET_P2P_PROTO_DHT_ASK_HELLO 19
#define GNUNET_P2P_PROTO_DHT_GET       20
#define GNUNET_P2P_PROTO_DHT_PUT       21
#define GNUNET_P2P_PROTO_DHT_RESULT    22

/* ************** p2p CHAT application messages *********** */

/**
 * chat message
 */
#define GNUNET_P2P_PROTO_CHAT_MSG 32

/* *************** p2p TRACEKIT application messages ******** */

#define GNUNET_P2P_PROTO_TRACEKIT_PROBE 36

#define GNUNET_P2P_PROTO_TRACEKIT_REPLY 37

/* ********** p2p TBENCH application messages ********** */

/**
 * benchmark message: send back reply asap
 */
#define GNUNET_P2P_PROTO_TBENCH_REQUEST 40
#define GNUNET_P2P_PROTO_TBENCH_REPLY 	 41

/************** p2p RPC application messages ************/

#define GNUNET_P2P_PROTO_RPC_REQ 42
#define GNUNET_P2P_PROTO_RPC_RES 43
#define GNUNET_P2P_PROTO_RPC_ACK 44

/* ************* p2p VPN messages ************* */

#define GNUNET_P2P_PROTO_AIP_IP 64      /* contains IPv6 frame */

#define GNUNET_P2P_PROTO_AIP_ROUTE 65   /* a route to a node */

#define GNUNET_P2P_PROTO_AIP_ROUTES 66  /* no more routes in my table */

#define GNUNET_P2P_PROTO_AIP_GETROUTE 67        /* request for a table entry from a peer */


#define GNUNET_P2P_PROTO_MAX_USED 68



/* ************** Block types (libecrs) ************************ */

/**
 * Reserved number for "any type".
 */
#define GNUNET_ECRS_BLOCKTYPE_ANY 0

/**
 * Data block (leaf or inner block).
 */
#define GNUNET_ECRS_BLOCKTYPE_DATA 1

/**
 * Namespace binding (subspace entry)
 */
#define GNUNET_ECRS_BLOCKTYPE_SIGNED 2

/**
 * Keyword binding (entry in keyword space)
 */
#define GNUNET_ECRS_BLOCKTYPE_KEYWORD 3

/**
 * Namespace advertisement in keyword space.
 */
#define GNUNET_ECRS_BLOCKTYPE_KEYWORD_SIGNED 4

/**
 * Type of OnDemand encoded blocks.
 */
#define GNUNET_ECRS_BLOCKTYPE_ONDEMAND 6

/**
 * DHT String2String (for dht-testing)
 */
#define GNUNET_ECRS_BLOCKTYPE_DHT_STRING2STRING 7

/**
 * Reserved for internal usage
 */
#define GNUNET_ECRS_BLOCKTYPE_RESERVED 0xFFFFFFFE


/* ************* priorities for poll-content ************ */

/* note that the absolute values do not matter;
   highest priority first is the rule!
   The naming-prefix used is after the name of
   the module using the respective constant.  */

#define GNUNET_FS_GAP_QUERY_POLL_PRIORITY 100

#define GNUNET_DHT_QUERY_POLL_PRIORITY 2

#define GNUNET_FS_GAP_CONTENT_MIGRATION_PRIORITY 1



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif
#endif
