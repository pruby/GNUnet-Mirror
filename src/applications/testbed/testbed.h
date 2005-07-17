/*
     This file is part of GNUnet.
     (C) 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @author Ronaldo Alves Ferreira
 * @author Christian Grothoff
 * @author Murali Krishna Ramanathan
 * @file applications/testbed/testbed.h
 **/
#ifndef TESTBED_TESTBED_H
#define TESTBED_TESTBED_H

#include "platform.h"

#include "gnunet_core.h"

/* */
#define TESTBED_hello_RESPONSE   0       /* peer responds with a hello */
#define TESTBED_ADD_PEER	1	/* Add a peer to a peer connection pool			*/
#define TESTBED_DEL_PEER	2	/* Delete a peer from a peer connection pool		*/
#define TESTBED_DEL_ALL_PEERS	3	/* Delete all peers from a peer connection pool		*/
#define TESTBED_GET_hello	4	/* Get the complete host information (ID, IP, ...)	*/
#define TESTBED_SET_TVALUE	5	/* Set trust value for a peer				*/
#define TESTBED_GET_TVALUE	6	/* Get trust value of a peer				*/
#define TESTBED_OUTPUT_RESPONSE	7	/* Reply to GET_OUTPUT					*/
#define TESTBED_SET_BW		8	/* Set in/outbound bandwidth				*/
#define TESTBED_SET_LOSS_RATE	9	/* Set the drop probability of a connection		*/
#define TESTBED_LOAD_MODULE     10      /* load a module                                        */
#define TESTBED_UNLOAD_MODULE   11      /* unload a module                                      */
#define TESTBED_UPLOAD_FILE	12	/* Upload a file to a peer				*/
#define TESTBED_DISABLE_hello    13      /* stop sending hellos */
#define TESTBED_ENABLE_hello     14      /* start sending hellos */
#define TESTBED_DISABLE_AUTOCONNECT    15      /* stop automatically connecting to other peers */
#define TESTBED_ENABLE_AUTOCONNECT     16      /* start trying to automatically connect to other peers */
#define TESTBED_ALLOW_CONNECT   17      /* only allow connections from a certain group of peers */
#define TESTBED_DENY_CONNECT    18      /* deny connections from a certain group of peers */
#define TESTBED_EXEC            19      /* execute process */
#define TESTBED_SIGNAL          20      /* send signal to process */
#define TESTBED_GET_OUTPUT      21      /* get output from process */
#define TESTBED_undefined       22

/**
 * Number of entries in handlers array.  Checked automatically when the
 * module is initialized.
 */
#define TESTBED_MAX_MSG 22

/*
  TODO LIST:
  Make loss rate to work. (CG: DONE)
  Upload a file to a specific machine.  (RF: DONE)
  Revisit statistics (don't re-invent that wheel!)
  AFS download a file on a specific machine.
  AFS insert a file on a specific machine.
 */

typedef struct {
  CS_MESSAGE_HEADER header;
  unsigned int msgType;	/* The message types listed above	*/
} TESTBED_CS_MESSAGE;

typedef struct {
  TESTBED_CS_MESSAGE testbed_cs_message;
  char data[1];		/* Value is dependent on the type field */
} TESTBED_CS_MESSAGE_GENERIC;

typedef struct {
  TESTBED_CS_MESSAGE header;
} TESTBED_undefined_MESSAGE;

typedef struct {
  TESTBED_CS_MESSAGE header;
  unsigned short proto;
  unsigned short reserved; /* for alignment */
} TESTBED_GET_hello_MESSAGE;

typedef struct {
  TESTBED_CS_MESSAGE header;
  unsigned int in_bw;		/* Inbound bandwidth		*/
  unsigned int out_bw;	/* Outbound bandwidth		*/
} TESTBED_SET_BW_MESSAGE;

typedef struct {
  TESTBED_CS_MESSAGE header;
  P2P_hello_MESSAGE helo;
} TESTBED_hello_MESSAGE;

typedef struct {
  TESTBED_CS_MESSAGE header;
  P2P_hello_MESSAGE helo;
} TESTBED_ADD_PEER_MESSAGE;

typedef struct {
    TESTBED_CS_MESSAGE header;
    PeerIdentity host;
} TESTBED_DEL_PEER_MESSAGE;

typedef struct {
    TESTBED_CS_MESSAGE header;
} TESTBED_DEL_ALL_PEERS_MESSAGE;

typedef struct {
    TESTBED_CS_MESSAGE header;
    PeerIdentity otherPeer;
} TESTBED_GET_TVALUE_MESSAGE;

typedef struct {
    TESTBED_CS_MESSAGE header;
    PeerIdentity otherPeer;
    unsigned int trust;
} TESTBED_SET_TVALUE_MESSAGE;

typedef struct {
    TESTBED_CS_MESSAGE header;
    PeerIdentity otherPeer;
} TESTBED_BLACKLIST_MESSAGE;

typedef struct {
  TESTBED_CS_MESSAGE header;
  unsigned int percentageLossInbound;
  unsigned int percentageLossOutbound;
} TESTBED_SET_LOSS_RATE_MESSAGE;

typedef struct {
    TESTBED_CS_MESSAGE header;
} TESTBED_LOAD_MODULE_MESSAGE;

typedef struct {
    TESTBED_LOAD_MODULE_MESSAGE load_module_message;
    char modulename[1];
} TESTBED_LOAD_MODULE_MESSAGE_GENERIC;

typedef struct {
  TESTBED_CS_MESSAGE header;
} TESTBED_UNLOAD_MODULE_MESSAGE;

typedef struct {
  TESTBED_UNLOAD_MODULE_MESSAGE unload_module_message;
  char modulename[1];
} TESTBED_UNLOAD_MODULE_MESSAGE_GENERIC;

#define TESTBED_FILE_APPEND	1
#define TESTBED_FILE_DELETE	2

#define TESTBED_FILE_BLK_SIZE	1400

typedef struct {
  TESTBED_CS_MESSAGE header;
  unsigned int type;
} TESTBED_UPLOAD_FILE_MESSAGE;

typedef struct {
  TESTBED_UPLOAD_FILE_MESSAGE upload_file_message;
  char buf[1];
} TESTBED_UPLOAD_FILE_MESSAGE_GENERIC;

typedef struct {
    TESTBED_CS_MESSAGE header;
} TESTBED_DISABLE_hello_MESSAGE;

typedef struct {
    TESTBED_CS_MESSAGE header;
} TESTBED_ENABLE_hello_MESSAGE;

typedef struct {
    TESTBED_CS_MESSAGE header;
} TESTBED_ENABLE_AUTOCONNECT_MESSAGE;

typedef struct {
    TESTBED_CS_MESSAGE header;
} TESTBED_DISABLE_AUTOCONNECT_MESSAGE;

typedef struct {
  TESTBED_CS_MESSAGE header;
} TESTBED_ALLOW_CONNECT_MESSAGE;

typedef struct {
  TESTBED_ALLOW_CONNECT_MESSAGE allow_connect_message;
  PeerIdentity peers[1];
} TESTBED_ALLOW_CONNECT_MESSAGE_GENERIC;

typedef struct {
  TESTBED_CS_MESSAGE header;
} TESTBED_DENY_CONNECT_MESSAGE;

typedef struct {
  TESTBED_DENY_CONNECT_MESSAGE deny_connect_message;
  PeerIdentity peers[1];
} TESTBED_DENY_CONNECT_MESSAGE_GENERIC;

typedef struct {
  TESTBED_CS_MESSAGE header;
} TESTBED_EXEC_MESSAGE;

typedef struct {
  TESTBED_EXEC_MESSAGE exec_message;
  char commandLine[1];
} TESTBED_EXEC_MESSAGE_GENERIC;

typedef struct {
  TESTBED_CS_MESSAGE header;
  unsigned int pid;
  int signal;
} TESTBED_SIGNAL_MESSAGE;

typedef struct {
  TESTBED_CS_MESSAGE header;
  int pid;
} TESTBED_GET_OUTPUT_MESSAGE;

typedef struct {
  TESTBED_CS_MESSAGE header;
} TESTBED_OUTPUT_REPLY_MESSAGE;

typedef struct {
  TESTBED_OUTPUT_REPLY_MESSAGE output_reply_message;
  char data[1];
} TESTBED_OUTPUT_REPLY_MESSAGE_GENERIC;

#endif
