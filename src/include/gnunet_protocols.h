/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * protocol number of TCP. Do NEVER change, also used in other context! 
 */
#define TCP_PROTOCOL_NUMBER 6

/**
 * protocol number for HTTP (80 is too big, so 8 will have to do)
 */
#define HTTP_PROTOCOL_NUMBER 8

/**
 * Protocol number for TCP on IPv6 (TCP+6)
 */
#define TCP6_PROTOCOL_NUMBER 12

/**
 * protocol number of UDP. Do NEVER change, also used in other context! 
 */
#define UDP_PROTOCOL_NUMBER 17

/**
 * Protocol number for UDP on IPv6 (UDP+6)
 */
#define UDP6_PROTOCOL_NUMBER 23

/**
 * protocol number for SMTP 
 */
#define SMTP_PROTOCOL_NUMBER 25



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


/* ********** CS AFS application messages ********** */

/**
 * client to gnunetd: send queries
 */
#define AFS_CS_PROTO_QUERY_START 8

/**
 * client to gnunetd: stop query
 */
#define AFS_CS_PROTO_QUERY_STOP 9

/**
 * gnunetd to client: here is your answer
 */
#define AFS_CS_PROTO_RESULT 9

/**
 * client to gnunetd: insert CHK content (no index) 
 */
#define AFS_CS_PROTO_INSERT 10

/**
 * client to gnunetd: index content
 */
#define AFS_CS_PROTO_INDEX 11

/**
 * client to gnunetd: delete content 
 */
#define AFS_CS_PROTO_DELETE 12

/**
 * client to gnunetd: unindex content
 */
#define AFS_CS_PROTO_UNINDEX 13

/**
 * client to gnunetd: test if content is indexed
 */
#define AFS_CS_PROTO_TESTINDEX 14

/**
 * Client to gnunetd: what is the average priority of entries in the
 * routing table?
 */
#define AFS_CS_PROTO_GET_AVG_PRIORITY 15

/**
 * client to gnunetd: initialize to index file
 */
#define AFS_CS_PROTO_INIT_INDEX 16

/* *********** messages for traffic module ************* */

/**
 * client to traffic module: to how many nodes are we connected? 
 * reply is a CS_RETURN_VALUE message. 
 */
#define CS_PROTO_CLIENT_COUNT 32

/**
 * Client to traffic module: how much traffic do we have at the moment?
 */
#define CS_PROTO_TRAFFIC_QUERY 33

/**
 * traffic module to client: traffic statistics 
 */
#define CS_PROTO_TRAFFIC_INFO 34


/* *********** messages for stats module ************* */

/**
 * client to stats module: request statistics 
 */
#define STATS_CS_PROTO_GET_STATISTICS 36

/**
 * stats module to client: statistics 
 */
#define STATS_CS_PROTO_STATISTICS 37

/**
 * client to stats module: is client server message supported
 */
#define STATS_CS_PROTO_GET_CS_MESSAGE_SUPPORTED 38

/**
 * client to stats module: is p2p message supported
 */
#define STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED 39


/* ********** CS TBENCH application messages ********** */

#define TBENCH_CS_PROTO_REQUEST	40
#define TBENCH_CS_PROTO_REPLY	41


/* ********** CS TRACEKIT application messages ********* */

#define TRACEKIT_CS_PROTO_PROBE 42
#define TRACEKIT_CS_PROTO_REPLY 43


/* ********** CS CHAT application messages ********** */

#define CHAT_CS_PROTO_MSG 44


/* ********** CS TESTBED application messages ********** */

#define TESTBED_CS_PROTO_REQUEST 50
#define TESTBED_CS_PROTO_REPLY   51


/* ********** CS DHT application messages ********** */
                                        
/**
 * client to CS: join table        
 */
#define DHT_CS_PROTO_REQUEST_JOIN     72

/**
 * client to CS: leave table       
 */
#define DHT_CS_PROTO_REQUEST_LEAVE    73

/**
 * Client to CS or CS to client: get from table   
 */
#define DHT_CS_PROTO_REQUEST_GET      74

/**
 * Client to CS or CS to client: put into table    
 */
#define DHT_CS_PROTO_REQUEST_PUT      75 

/**
 * Client to CS or CS to client: remove from table
 */
#define DHT_CS_PROTO_REQUEST_REMOVE   76 

/**
 * Client to CS or CS to client: results from get
 */
#define DHT_CS_PROTO_REPLY_GET        77

/**
 * Client to CS or CS to client: confirmed
 */
#define DHT_CS_PROTO_REPLY_ACK        78

/**
 * Client to CS: iterate over table
 */
#define DHT_CS_PROTO_REQUEST_ITERATE   79


#define MAX_CS_PROTO_USED 80

/* ******** node-to-node (p2p) messages (over anything) ********* */

/* ********* p2p infrastructure messages *********** */

/**
 * announcement of public key 
 */
#define p2p_PROTO_HELO 0

/**
 * session key exchange, session key is encrypted with hostkey 
 */
#define p2p_PROTO_SKEY 1

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
#define p2p_PROTO_HANGUP 4

/**
 * Fragmented message.
 */
#define p2p_PROTO_FRAGMENT 5

/**
 * noise, used to fill packets to sizes >1k.
 */
#define p2p_PROTO_NOISE 6

/* ************* p2p GAP application messages *********** */

/**
 * Query for content. 
 */
#define GAP_p2p_PROTO_QUERY 16

/**
 * receive content 
 */
#define GAP_p2p_PROTO_RESULT 17

/* ************** p2p CHAT application messages *********** */

/**
 * chat message 
 */
#define CHAT_p2p_PROTO_MSG 32

/* *************** p2p TRACEKIT application messages ******** */

#define TRACEKIT_p2p_PROTO_PROBE 36

#define TRACEKIT_p2p_PROTO_REPLY 37

/* ********** p2p TBENCH application messages ********** */

/**
 * benchmark message: send back reply asap 
 */
#define TBENCH_p2p_PROTO_REQUEST 40
#define TBENCH_p2p_PROTO_REPLY 	 41

/************** p2p RPC application messages ************/

#define RPC_p2p_PROTO_REQ 42
#define RPC_p2p_PROTO_RES 43
#define RPC_p2p_PROTO_ACK 44

#define MAX_p2p_PROTO_USED 45



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


#endif
