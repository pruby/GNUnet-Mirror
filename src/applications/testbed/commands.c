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
 * @file applications/testbed/commands.c
 * @brief the commands available in the testbed
 * @author Ronaldo Alves Ferreira
 * @author Christian Grothoff
 * @author Murali Krishan Ramanathan
 *
 * Todo:
 * - test add-ssh-node
 * - implement shutdown (in particular, kill ssh connections / processes!)
 * - design and implement better topology management
 * - test
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_getoption_lib.h"
#include "gnunet_stats_lib.h"
#include "testbed.h"
#include "commands.h"
#include "socket.h"

/**
 * @brief struct keeping per-peer information for the testbed
 */
typedef struct {
  /** IP address of the peer */
  IPaddr	     ip;
  /** CS port of the peer */
  unsigned short     port;
  /** string describing the peer address */
  char	* ips;
  /** socket to communicate with the peer */
  GNUNET_TCP_SOCKET sock;
  /** hello message identifying the peer in the network */
  P2P_hello_MESSAGE * helo;
  /** if we're using ssh, what is the PID of the
      ssh process? (-1 for unencrypted direct connections) */
  pid_t ssh;
} NODE_INFO;

/**
 * List of nodes known to the testbed.
 */
static NODE_INFO * nodes = NULL;

/**
 * Number of known nodes, size of the nodes array.
 */
static unsigned int nnodes = 0;

/**
 * Should the driver exit?
 */
int do_quit = NO;

/**
 * Convert the strings ss and ds to peer-identifiers (ints) s and d
 * respectively.  Aborts the method containing the macro with an error
 * message if the peer-IDs are not within range.
 */
#define CHECK_SRC_DST(s, d, ss, ds)	\
  s = atoi(ss);			\
  d = atoi(ds);				    \
  if (s < 0 || s >= nnodes || d < 0 || d >= nnodes) {  \
    XPRINTF("Invalid src (%s) or dst (%s)\n", ss, ds);  \
    return -1;					       \
  }

/**
 * Convert the string ps to a peer-id p and abort the current method
 * with an error message if ps is not a valid peer-id.
 */
#define CHECK_PEER(p, ps)	\
  p = atoi(ps);				\
  if (p < 0 || p >= nnodes) {			\
    XPRINTF("Invalid peer value %s\n", ps);	\
    return -1;					\
  }

/**
 * Send a message to peer 'peer' of type 'msgType'
 * the given size and data.
 */
static int sendMessage(unsigned msgType,
		       int peer,
		       unsigned short argSize,
		       void *arg) {
  TESTBED_CS_MESSAGE * msg;
  int msgsz;

  /* Assume peer value is valid. */
  if (argSize + sizeof(TESTBED_CS_MESSAGE) > 65535)
    errexit("Message body too big for sendMessage: %s\n",
	    argSize);

  msgsz = sizeof(TESTBED_CS_MESSAGE)+argSize;
  msg = MALLOC(msgsz);
  msg->header.size
    = htons(msgsz);
  msg->header.type
    = htons(CS_PROTO_testbed_REQUEST);
  msg->msgType
    = htonl(msgType);
  memcpy(&((TESTBED_CS_MESSAGE_GENERIC*)msg)->data[0],
	 arg,
	 argSize);
  msgsz = writeToSocket(&nodes[peer].sock,
			&msg->header);
  FREE(msg);
  if (msgsz == SYSERR) {
    XPRINTF(" Could not send message to peer %s.\n",
	   nodes[peer].ips);
    return SYSERR;
  }
  return OK;
}

/**
 * Read a result from the given peer.  Print
 * an error message if the peer fails to respond.
 *
 * @return OK on success, SYSERR on error
 */
static int readResult(int peer,
		      int * result) {
  if (OK != readTCPResult(&nodes[peer].sock,
			  result)) {
    XPRINTF(" peer %s is not responding.\n",
	   nodes[peer].ips);
    return SYSERR;
  }
  return OK;
}

/* ****************** individual commands ********** */


/**
 * Add a node to the configuration.
 * Arguments must be IP PORT of the peer.
 */
static int addNode(int argc, char * argv[]) {
  int currindex;
  TESTBED_hello_MESSAGE * hdr;
  TESTBED_GET_hello_MESSAGE req;
  int port;
  int i;

  if (argc != 2) {
    XPRINTF("Syntax: add-node IP PORT.\n");
    return -1;
  }
  port = atoi(argv[1]);
  for (i=0;i<nnodes;i++) {
    if ( (0 == strcmp(argv[0],
		      nodes[i].ips)) &&
	 (port == nodes[i].port) ) {
      XPRINTF("Node already in use!\n");
      return -1;
    }
  }


  req.proto = 0;
  req.reserved = 0;
  /* connect */
  currindex = nnodes;
  GROW(nodes, nnodes, nnodes+1);
  nodes[currindex].ips = STRDUP(argv[0]);
  nodes[currindex].port = atoi(argv[1]);
  nodes[currindex].ssh = -1;
#ifndef MINGW
  inet_aton(argv[0], (struct in_addr*) &nodes[currindex].ip);
#else
  nodes[currindex].ip.addr.S_un.S_addr = inet_addr(argv[0]);
#endif

  if (SYSERR == initGNUnetClientSocket(nodes[currindex].port,
				       nodes[currindex].ips,
				       &nodes[currindex].sock)) {
    XPRINTF(" could not connect to %s:%d.\n",
	   nodes[currindex].ips,
	   nodes[currindex].port);
    return -1;
  }

  /* request hello */
  if (OK != sendMessage(TESTBED_GET_hello,
			currindex,
			sizeof(TESTBED_GET_hello_MESSAGE)-sizeof(TESTBED_CS_MESSAGE),
			&req.proto)) {
    /* send message already printed an error message */
    destroySocket(&nodes[currindex].sock);
    FREE(nodes[currindex].ips);
    GROW(nodes,
	 nnodes,
	 nnodes-1);
    return -1;
  }

  hdr = NULL;
  if (SYSERR == readFromSocket(&nodes[currindex].sock,
			       (CS_MESSAGE_HEADER**)&hdr)) {
    XPRINTF(" peer %s is not responding.\n",
	   nodes[currindex].ips);
    destroySocket(&nodes[currindex].sock);
    FREE(nodes[currindex].ips);
    GROW(nodes, nnodes, nnodes-1);
    return -1;
  }
  if ( (ntohs(hdr->header.header.type) == CS_PROTO_testbed_REPLY) &&
       (ntohs(hdr->header.header.size) >= sizeof(TESTBED_hello_MESSAGE)) &&
       (ntohl(hdr->header.msgType) == TESTBED_hello_RESPONSE) &&
       (ntohs(hdr->header.header.size) - sizeof(TESTBED_CS_MESSAGE) >= sizeof(P2P_hello_MESSAGE)) &&
       (ntohs(hdr->header.header.size) - sizeof(TESTBED_CS_MESSAGE) == P2P_hello_MESSAGE_size(&hdr->helo)) ) {
    nodes[currindex].helo
      = MALLOC(P2P_hello_MESSAGE_size(&hdr->helo));
    memcpy(nodes[currindex].helo,
	   &hdr->helo,
	   P2P_hello_MESSAGE_size(&hdr->helo));
  } else {
    FREE(hdr);
    destroySocket(&nodes[currindex].sock);
    XPRINTF(" peer %s did not respond with proper hello.\n",
	   nodes[currindex].ips);
    FREE(nodes[currindex].ips);
    GROW(nodes, nnodes, nnodes-1);
    return -1;
  }
  FREE(hdr);
  XPRINTF("%d\n",
	 currindex);
  return 0;
}



/**
 * Add an node reachable via ssh-tunnel to the configuration.
 * Arguments must be LOGIN, IP PORT of the peer.  Sshd must
 * be running on the default port.
 */
static int addSshNode(int argc, char * argv[]) {
  int currindex;
  TESTBED_hello_MESSAGE * hdr;
  TESTBED_GET_hello_MESSAGE req;
  int port;
  int i;
  pid_t pid;
  unsigned short lport;
  int rtc;
  int ret;
  int status;

  if (argc != 3) {
    XPRINTF("Syntax: add-ssh-node LOGIN IP PORT.\n");
    return -1;
  }
  port = atoi(argv[2]);
  for (i=0;i<nnodes;i++) {
    if ( (0 == strcmp(argv[1],
		      nodes[i].ips)) &&
	 (port == nodes[i].port) ) {
      XPRINTF("Node already in use!\n");
      return -1;
    }
  }

  /* find available local port to bind to */
  for (lport=10000;lport<65535;lport++) {
    struct sockaddr_in addr;
    int s;
    const int on = 1;

    s = SOCKET(PF_INET, SOCK_STREAM, 0);
    if (s == -1) {
      XPRINTF("Cannot open socket: %s\n",
	     STRERROR(errno));
      return -1;
    }
    if ( SETSOCKOPT(s,
		    SOL_SOCKET,
		    SO_REUSEADDR,
		    &on, sizeof(on)) < 0 )
      perror("setsockopt");
    memset(&addr,
	   0,
	   sizeof(addr));
    addr.sin_family
      = AF_INET;
    addr.sin_addr.s_addr
      = htonl(INADDR_ANY);
    addr.sin_port
      = htons(lport);
    if (0 == BIND(s,
		  (const struct sockaddr *) &addr,
		  sizeof(struct sockaddr_in))) {
      closefile(s);
      break; /* found port! */
    } else {
      closefile(s); /* not available, try another one... */
    }
  }
  if (lport == 65535) {
    XPRINTF(" Cannot find available local port!\n");
    return -1;
  }

  pid = fork();
  if (pid == 0) {
    char * sargv[7];
    char pohopo[64];
    sargv[0] = "ssh";
    sargv[1] = "-l";
    sargv[2] = argv[0]; /* login */
    sargv[3] = "-L";
    SNPRINTF(pohopo,
	     64,
	     "%d:%s:%d",
	     lport, /* local port */
	     "localhost", /* loopback on remote host */
	     port /* remote port */);
    sargv[4] = pohopo;
    sargv[5] = argv[1]; /* remote hostname */
    sargv[6] = NULL; /* last argument */
    execvp("ssh",
	   sargv);
    LOG(LOG_ERROR,
	" execvp failed: %s\n",
	STRERROR(errno));
    exit(-1);
  }
  if (pid == -1) {
    XPRINTF("Failed to fork: %s\n",
	   STRERROR(errno));
    return -1;
  }


  req.proto = 0;
  req.reserved = 0;
  /* connect */
  currindex = nnodes;
  GROW(nodes, nnodes, nnodes+1);
  nodes[currindex].ips = STRDUP("localhost");
  nodes[currindex].port = lport;
  nodes[currindex].ssh = pid;
#ifndef MINGW
  inet_aton(argv[0], (struct in_addr*) &nodes[currindex].ip);
#else
  nodes[currindex].ip.addr.S_un.S_addr = inet_addr(argv[0]);
#endif

  /* FIXME: wait a bit to give ssh a chance to connect... */
  rtc = 0; /* number of retries */
  while (rtc < 5) {
    ret = initGNUnetClientSocket(nodes[currindex].port,
				 nodes[currindex].ips,
				 &nodes[currindex].sock);
    if (ret == OK)
      break;
    rtc++;
    gnunet_util_sleep(cronSECONDS);
  }
  if (ret == SYSERR) {
    XPRINTF(" could not connect to %s:%d.\n",
	   nodes[currindex].ips,
	   nodes[currindex].port);
    kill(nodes[currindex].ssh,
	 SIGTERM);
    waitpid(nodes[currindex].ssh,
	    &status,
	    0);
    GROW(nodes, nnodes, nnodes-1);
    return -1;
  }

  /* request hello */
  if (OK != sendMessage(TESTBED_GET_hello,
			currindex,
			sizeof(TESTBED_GET_hello_MESSAGE)-sizeof(TESTBED_CS_MESSAGE),
			&req.proto)) {
    /* send message already printed an error message */
    destroySocket(&nodes[currindex].sock);
    FREE(nodes[currindex].ips);
    /* fixme: check error conditions on kill/waidpid! */
    kill(nodes[currindex].ssh,
	 SIGTERM);
    waitpid(nodes[currindex].ssh,
	    &status,
	    0);
    GROW(nodes,
	 nnodes,
	 nnodes-1);
    return -1;
  }

  hdr = NULL;
  if (SYSERR == readFromSocket(&nodes[currindex].sock,
			       (CS_MESSAGE_HEADER**)&hdr)) {
    XPRINTF(" peer %s is not responding.\n",
	   nodes[currindex].ips);
    destroySocket(&nodes[currindex].sock);
    FREE(nodes[currindex].ips);
    /* fixme: check error conditions on kill/waidpid! */
    kill(nodes[currindex].ssh,
	 SIGTERM);
    waitpid(nodes[currindex].ssh,
	    &status,
	    0);
    GROW(nodes, nnodes, nnodes-1);
    return -1;
  }
  if ( (ntohs(hdr->header.header.type) == CS_PROTO_testbed_REPLY) &&
       (ntohs(hdr->header.header.size) >= sizeof(TESTBED_hello_MESSAGE)) &&
       (ntohl(hdr->header.msgType) == TESTBED_hello_RESPONSE) &&
       (ntohs(hdr->header.header.size) - sizeof(TESTBED_CS_MESSAGE) >= sizeof(P2P_hello_MESSAGE)) &&
       (ntohs(hdr->header.header.size) - sizeof(TESTBED_CS_MESSAGE) == P2P_hello_MESSAGE_size(&hdr->helo)) ) {
    nodes[currindex].helo
      = MALLOC(P2P_hello_MESSAGE_size(&hdr->helo));
    memcpy(nodes[currindex].helo,
	   &hdr->helo,
	   P2P_hello_MESSAGE_size(&hdr->helo));
  } else {
    FREE(hdr);
    destroySocket(&nodes[currindex].sock);
    XPRINTF(" peer %s did not respond with proper hello.\n",
	   nodes[currindex].ips);
    FREE(nodes[currindex].ips);
    /* fixme: check error conditions on kill/waidpid! */
    kill(nodes[currindex].ssh,
	 SIGTERM);
    waitpid(nodes[currindex].ssh,
	    &status,
	    0);
    GROW(nodes, nnodes, nnodes-1);
    return -1;
  }
  FREE(hdr);
  XPRINTF("%d\n",
	 currindex);
  return 0;
}


/**
 * Tear down the connection between two peers.
 */
static int delConnection(int argc,
			 char * argv[]) {
  int src, dst, ack;

  if (argc != 2) {
    XPRINTF("Syntax: disconnect PEERID PEERID\n");
    return -1;
  }
  CHECK_SRC_DST(src, dst, argv[0], argv[1]);
  if (OK != sendMessage(TESTBED_DEL_PEER,
			src,
			sizeof(PeerIdentity),
			&nodes[dst].helo->senderIdentity))
    return -1;
  if (OK != readResult(src,
		       &ack))
    return -1;
  if (ack == OK) {
    XPRINTF("OK.\n");
    return 0;
  } else {
    XPRINTF(" Connection NOT deleted.\n");
    return -1;
  }
}

/**
 * Tear down all connections of a peer.
 */
static int delAllConnections(int argc,
			     char * argv[]) {
  int dst, ack;

  if (argc != 1) {
    XPRINTF("Syntax: disconnect-all PEERID\n");
    return -1;
  }
  CHECK_PEER(dst, argv[0]);
  if (OK != sendMessage(TESTBED_DEL_ALL_PEERS,
			dst,
			0,
			NULL))
    return -1;
  if (OK != readResult(dst,
		       &ack))
    return -1;
  if (ack == OK) {
    XPRINTF("OK.\n");
    return 0;
  } else {
    XPRINTF(" Connections NOT deleted.\n");
    return -1;
  }
}

/**
 * Add a connection between two peers.
 */
static int addConnection(int argc,
			 char * argv[]) {
  int src, dst, ack;

  if (argc != 2) {
    XPRINTF("Syntax: connect PEERID PEERID\n");
    return -1;
  }
  CHECK_SRC_DST(src, dst, argv[0], argv[1]);
  if (SYSERR == sendMessage(TESTBED_ADD_PEER,
			    src,
			    P2P_hello_MESSAGE_size(nodes[dst].helo),
			    nodes[dst].helo))
    return -1;
  if (OK != readResult(src,
		       &ack))
    return -1;
  if (ack == OK) {
    XPRINTF("OK.\n");
    return 0;
  } else {
    XPRINTF(" peer cannot connect.\n");
    return -1;
  }
}

/**
 * Set the level of trust that one peer has in
 * another.
 */
static int setTrust(int argc, char * argv[]) {
  int src, dst, value, ack;
  TESTBED_SET_TVALUE_MESSAGE msg;

  if (argc != 3) {
    XPRINTF("Syntax: set-trust PEERID PEERID TRUST\n");
    return -1;
  }
  CHECK_SRC_DST(src, dst, argv[0], argv[1]);
  value = atoi(argv[2]);
  msg.trust = htonl(value);
  memcpy(&msg.otherPeer,
	 &nodes[dst].helo->senderIdentity,
	 sizeof(PeerIdentity));
  if (SYSERR == sendMessage(TESTBED_SET_TVALUE,
			    src,
			    sizeof(PeerIdentity)+sizeof(unsigned int),
			    &msg.otherPeer))
    return -1;
  if (OK != readResult(src,
		       &ack))
    return -1;
  if (htonl(ack) != OK) {
    XPRINTF(" peer could not set trust value.\n");
    return -1;
  } else {
    XPRINTF("OK.\n");
    return 0;
  }
}

/**
 * Get the amount of trust that A has in B.
 */
static int getTrust(int argc, char *argv[]) {
  int src, dst, value;

  if (argc != 2) {
    XPRINTF("Syntax: get-trust PEERID PEERID\n");
    return -1;
  }
  CHECK_SRC_DST(src, dst, argv[0], argv[1]);
  if (SYSERR == sendMessage(TESTBED_GET_TVALUE,
			    src,
			    sizeof(PeerIdentity),
			    &nodes[dst].helo->senderIdentity))
    return -1;
  if (SYSERR == readResult(src, &value))
    return -1;
  if (value < 0) {
    XPRINTF(" could not get trust value.\n");
    return -1;
  } else {
    XPRINTF("%d\n",
	   value);
    return 0;
  }
}

/**
 * Disable hello at a peer.
 */
static int disablehello(int argc, char *argv[]) {
  int dst, value;

  if (argc != 1) {
    XPRINTF("Syntax: helo-disable PEERID\n");
    return -1;
  }
  CHECK_PEER(dst, argv[0]);
  if (SYSERR == sendMessage(TESTBED_DISABLE_hello,
			    dst,
			    0,
			    NULL))
    return -1;
  if (SYSERR == readResult(dst, &value))
    return -1;
  if (value != OK) {
    XPRINTF(" could disable hello\n");
    return -1;
  } else {
    XPRINTF("OK.\n");
    return 0;
  }
}

/**
 * Enable hello at a peer.
 */
static int enablehello(int argc, char *argv[]) {
  int dst, value;

  if (argc != 1) {
    XPRINTF("Syntax: helo-enable PEERID\n");
    return -1;
  }
  CHECK_PEER(dst, argv[0]);
  if (SYSERR == sendMessage(TESTBED_ENABLE_hello,
			    dst,
			    0,
			    NULL))
    return -1;
  if (SYSERR == readResult(dst, &value))
    return -1;
  if (value != OK) {
    XPRINTF(" could enable hello\n");
    return -1;
  } else {
    XPRINTF("OK.\n");
    return 0;
  }
}

/**
 * Disable AUTOCONNECT at a peer.
 */
static int disableAUTOCONNECT(int argc, char *argv[]) {
  int dst, value;

  if (argc != 1) {
    XPRINTF("Syntax: autoconnect-disable PEERID\n");
    return -1;
  }
  CHECK_PEER(dst, argv[0]);
  if (SYSERR == sendMessage(TESTBED_DISABLE_AUTOCONNECT,
			    dst,
			    0,
			    NULL))
    return -1;
  if (SYSERR == readResult(dst, &value))
    return -1;
  if (value != OK) {
    XPRINTF(" could disable AUTOCONNECT\n");
    return -1;
  } else {
    XPRINTF("OK.\n");
    return 0;
  }
}

/**
 * Enable AUTOCONNECT at a peer.
 */
static int enableAUTOCONNECT(int argc, char *argv[]) {
  int dst, value;

  if (argc != 1) {
    XPRINTF("Syntax: autoconnect-enable PEERID\n");
    return -1;
  }
  CHECK_PEER(dst, argv[0]);
  if (SYSERR == sendMessage(TESTBED_ENABLE_AUTOCONNECT,
			    dst,
			    0,
			    NULL))
    return -1;
  if (SYSERR == readResult(dst, &value))
    return -1;
  if (value != OK) {
    XPRINTF(" could enable AUTOCONNECT\n");
    return -1;
  } else {
    XPRINTF("OK.\n");
    return 0;
  }
}


static int allowDenyConnectHelper(unsigned int argc,
				  char * argv[],
				  int type) {
  int dst, value;
  PeerIdentity * list;
  int i;
  int idx = 0;

  CHECK_PEER(dst, argv[0]);
  if (argc > (65532 - sizeof(TESTBED_CS_MESSAGE)) / sizeof(PeerIdentity)) {
    XPRINTF("Too many peers specified.  Ask a wizard to enlarge limit.\n");
    return -1;
  }

  list = NULL;
  for (i=1;i<argc;i++)
    CHECK_PEER(idx, argv[i]); /* may return, do before MALLOC! */
  if (argc > 1)
    list = MALLOC(sizeof(PeerIdentity)*(argc-1));
  for (i=1;i<argc;i++) {
    CHECK_PEER(idx, argv[i]);
    memcpy(&list[i-1],
	   &nodes[idx].helo->senderIdentity,
	   sizeof(PeerIdentity));
  }
  if (SYSERR == sendMessage(type,
			    dst,
			    sizeof(PeerIdentity)*(argc-1),
			    list)) {
    FREENONNULL(list);
    return -1;
  }
  FREENONNULL(list);
  if (SYSERR == readResult(dst, &value))
    return -1;
  if (value != OK) {
    XPRINTF(" could change setting.\n");
    return -1;
  } else {
    XPRINTF("OK.\n");
    return 0;
  }
}

/**
 * Deny connections to certain peers at a peer.
 */
static int denyConnect(int argc, char *argv[]) {
  if (argc < 1) {
    XPRINTF("Syntax: connect-deny PEERID [PEERID]*\n");
    return -1;
  }
  return allowDenyConnectHelper(argc, argv,
				TESTBED_DENY_CONNECT);
}

/**
 * Allow connections to certain peers at a peer.
 */
static int allowConnect(int argc, char *argv[]) {
  if (argc < 1) {
    XPRINTF("Syntax: connect-allow PEERID [PEERID]*\n");
    return -1;
  }
  return allowDenyConnectHelper(argc, argv,
				TESTBED_ALLOW_CONNECT);
}

/**
 * Helper function for (un)loadModule.
 * @param type load or unload requested?
 */
static int loadModuleHelper(unsigned short type,
			    char * peerId,
			    char * modulename) {
  int ok, dst;

  CHECK_PEER(dst, peerId);
  if (OK != sendMessage(type,
			dst,
			strlen(modulename),
			modulename))
    return -1;
  if (OK != readResult(dst,
		       &ok))
    return -1;
  if (ok != OK) {
    XPRINTF(" peer %s refused.\n",
	   nodes[dst].ips);
    return -1;
  }
  XPRINTF("OK.\n");
  return 0;
}

/**
 * Load an application module at the given peer.
 */
static int loadModule(int argc, char *argv[]) {
  if (argc != 2) {
    XPRINTF("Syntax: load-module PEERID MODULENAME\n");
    return -1;
  }
  return loadModuleHelper(TESTBED_LOAD_MODULE,
			  argv[0],
			  argv[1]);
}

/**
 * Unload an application module.
 */
static int unloadModule(int argc, char *argv[]) {
  if (argc != 2) {
    XPRINTF("Syntax: unload-module PEERID MODULENAME\n");
    return -1;
  }
  return loadModuleHelper(TESTBED_UNLOAD_MODULE,
			  argv[0],
			  argv[1]);
}

/**
 * Fork a client process.  Captures the output and makes it
 * available via process-output.  The client can be killed
 * using process-signal.  The process identifier is printed.
 */
static int startProcess(int argc,
			char *argv[]) {
  char * cmdLine;
  int size;
  int i;
  int dst;
  int ack;
  int pos;

  if (argc < 2) {
    XPRINTF("Syntax: process-start PEERID COMMAND [ARGUMENTS]\n");
    return -1;
  }
  CHECK_PEER(dst, argv[0]);
  size = 0;
  for (i=1;i<argc;i++)
    size += 1 + strlen(argv[i]);
  cmdLine = MALLOC(size);
  pos = 0;
  for (i=1;i<argc;i++) {
    memcpy(&cmdLine[pos],
	   argv[i],
	   strlen(argv[i])+1);
    pos += strlen(argv[i])+1;
  }

  if (OK != sendMessage(TESTBED_EXEC,
			dst,
			size,
			cmdLine)) {
    FREE(cmdLine);
    return -1;
  }
  FREE(cmdLine);
  if (OK != readResult(dst,
		       &ack))
    return -1;
  if (ack != SYSERR) {
    XPRINTF("%d\n",
	   ack);
    return 0;
  } else {
    XPRINTF(" Peer could not fork process.\n");
    return -1;
  }
}

/**
 * Send a signal to a client process.  Use signal
 * 0 to test if the process is still live.  Use
 * -1 to obtain the return value from a dead
 * process and to free all associated resources.
 * For -1 the return value is printed, otherwise OK.
 * Note that if the signal is -1 and the process
 * is still running, -1 is returned (which can then
 * NOT be distinguished from the process returning -1)
 */
static int signalProcess(int argc, char *argv[]) {
  int dst;
  int ack;
  TESTBED_SIGNAL_MESSAGE msg;

  if (argc != 3) {
    XPRINTF("Syntax: process-signal PEERID PROCESSID SIGNAL\n");
    return -1;
  }
  CHECK_PEER(dst, argv[0]);
  msg.pid = htonl(atoi(argv[1]));
  msg.signal = htonl(atoi(argv[2]));
  if (OK != sendMessage(TESTBED_SIGNAL,
			dst,
			sizeof(TESTBED_SIGNAL_MESSAGE) - sizeof(TESTBED_CS_MESSAGE),
			&msg.pid))
    return -1;
  if (OK != readResult(dst,
		       &ack))
    return -1;
  if (ntohl(msg.signal) == -1) {
    XPRINTF("%d\n", ack);
    return 0;
  }
  if (ack == OK) {
    XPRINTF("OK.\n");
    return 0;
  } else {
    XPRINTF(" Peer could not signal process.\n");
    return -1;
  }
}

/**
 * Get the recorded output of a process.
 */
static int dumpProcessOutput(int argc,
			     char * argv[]) {
  int dst;
  int pid;
  unsigned int ack;

  if (argc != 2) {
    XPRINTF("Syntax: process-output PEERID PROCESSID\n");
    return -1;
  }
  CHECK_PEER(dst, argv[0]);
  pid = htonl(atoi(argv[1]));
  if (OK != sendMessage(TESTBED_GET_OUTPUT,
			dst,
			sizeof(int),
			&pid))
    return -1;
  if (OK != readResult(dst,
		       &ack))
    return -1;
  if (ack != SYSERR) {
    char * tmp;
    unsigned int pos = 0;
    while (pos < ack) {
      unsigned short size;
      TESTBED_OUTPUT_REPLY_MESSAGE * reply;

      reply = NULL;
      if (SYSERR == readFromSocket(&nodes[dst].sock,
				   (CS_MESSAGE_HEADER**)&reply)) {
	XPRINTF(" peer %s is not responding after %d of %d bytes.\n",
	       nodes[dst].ips,
	       pos,
	       ack);
	return -1;
      }
      /* FIXME: check that this is the correct reply format */
      size = ntohs(reply->header.header.size) - sizeof(TESTBED_OUTPUT_REPLY_MESSAGE);
      tmp = MALLOC(size+1);
      memcpy(tmp,
	     &((TESTBED_OUTPUT_REPLY_MESSAGE_GENERIC*)reply)->data[0],
	     size);
      tmp[size] = '\0';
      XPRINTF("%s",
	     tmp);	
      FREE(tmp);
      FREE(reply);
      pos += size;
    }
    return 0;
  } else {
    XPRINTF(" Peer could not return process output.\n");
    return -1;
  }
}

/**
 * Set bandwidth limitations for a peer.
 */
static int setBW(int argc, char * argv[]) {
  TESTBED_SET_BW_MESSAGE msg;
  int dst, in, out, ack;

  if (argc != 3) {
    XPRINTF("Syntax: set-bw PEERID DOWN-BPS UP-BPS\n");
    return -1;
  }
  CHECK_PEER(dst, argv[0]);
  in  = atoi(argv[1]);
  out = atoi(argv[2]);
  if ((in < 0) || (out < 0)) {
    XPRINTF(" Invalid bandwidth specification.\n");
    return -1;
  }
  msg.in_bw  = htonl(in);
  msg.out_bw = htonl(out);
  if (SYSERR == sendMessage(TESTBED_SET_BW,
			    dst,
			    sizeof(TESTBED_SET_BW_MESSAGE) - sizeof(TESTBED_CS_MESSAGE),
			    &msg.in_bw))
    return -1;
  if (OK != readResult(dst, &ack))
    return -1;
  if (ack != OK) {
    XPRINTF(" peer could not set the specified bandwith.\n");
    return -1;
  } else {
    XPRINTF("OK.\n");
    return 0;
  }
}

/**
 * Set artifical message loss rates for a peer.
 */
static int setLoss(int argc, char * argv[]) {
  int dst;
  int ack;
  TESTBED_SET_LOSS_RATE_MESSAGE msg;

  if (argc != 3) {
    XPRINTF("Syntax: set-loss PEERID DOWN-LOSS UP-LOSS\n");
    return -1;
  }
  CHECK_PEER(dst, argv[0]);
  msg.percentageLossInbound
    = htonl(atoi(argv[1]));
  msg.percentageLossOutbound
    = htonl(atoi(argv[2]));

  if (SYSERR == sendMessage(TESTBED_SET_LOSS_RATE,
			    dst,
			    sizeof(TESTBED_SET_LOSS_RATE_MESSAGE) - sizeof(TESTBED_CS_MESSAGE),
			    &msg.percentageLossInbound))
    return -1;
  if (OK != readResult(dst, &ack))
    return -1;
  if (ack != OK) {
    XPRINTF(" peer could not set the specified loss rates.\n");
    return -1;
  } else {
    XPRINTF("OK.\n");
    return 0;
  }
}

static int printStatistic(const char * name,
			  unsigned long long value,
			  const char * arg) {
  if (0 == strcmp(name,
		  arg))
    XPRINTF("%llu\n",
	   value);
  return OK;
}

/**
 * Obtain statistics from a peer.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
static int getStat(int argc, char ** argv) {
  int res, peer, printProtocols;

  printProtocols = NO;
  if (argc != 2) {
    XPRINTF("Syntax: get-stat PEERID STATID\n");
    return -1;
  }
  CHECK_PEER(peer, argv[0]);
  res = requestStatistics(&nodes[peer].sock,
			  (StatisticsProcessor) &printStatistic,
			  argv[1]);
  if (res == OK)
    return 0;
  else
    return -1;
}

/**
 * Print statistics received.
 *
 * @param stream where to print the statistics
 * @return OK on success, SYSERR on error
 */
static int printStatistics(const char * name,
			   unsigned long long value,
			   void * unused) {
  XPRINTF("%-60s: %16llu\n",
	 name,
	 value);
  return OK;
}

static int lastIp2p;

static int printProtocols(unsigned short type,
			  int isP2P,
			  void * unused) {
  const char *name = NULL;

  if (isP2P != lastIp2p) {
    if (isP2P)
      XPRINTF(_("Supported peer-to-peer messages:\n"));
    else
      XPRINTF(_("Supported client-server messages:\n"));
    lastIp2p = isP2P;
  }
  if (isP2P)
    name = p2pMessageName(type);
  else
    name = csMessageName(type);
  if (name == NULL)
    XPRINTF("\t%d\n",
	   type);
  else
    XPRINTF("\t%d\t(%s)\n",
	   type,
	   name);
  return OK;
}

/**
 * Obtain statistics from a peer.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
static int getStats(int argc, char ** argv) {
  int res, peer, printProtocolsOpt;

  printProtocolsOpt = NO;
  if (argc == 2) {
    if (strcmp(argv[0], "-P")) {
      XPRINTF("Syntax: get-stats [-P] PEERID\n");
      return -1;
    }
    printProtocolsOpt = YES;
    CHECK_PEER(peer, argv[1]);
  } else if (argc != 1) {
    XPRINTF("Syntax: get-stats [-P] PEERID\n");
    return -1;
  } else
    CHECK_PEER(peer, argv[0]);
  res = requestStatistics(&nodes[peer].sock,
			  (StatisticsProcessor) &printStatistics,
			  NULL);
  if ( (printProtocolsOpt == YES) &&
       (res == OK)) {
 lastIp2p = 42; /* not YES or NO */
    res = requestAvailableProtocols(&nodes[peer].sock,
				    (ProtocolProcessor) &printProtocols,
				    NULL);
  }
  if (res == OK)
    return 0;
  else
    return -1;
}


/**
 * Obtain option from a peer.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
static int getOption(int argc, char ** argv) {
  int peer;
  char * opt;

  if (argc != 3) {
    XPRINTF("Syntax: get-option PEERID SECTION OPTION\n");
    return -1;
  }
  CHECK_PEER(peer, argv[0]);
  opt = getConfigurationOptionValue(&nodes[peer].sock,
				    argv[1],
				    argv[2]);
  if (opt == NULL) {
    XPRINTF("Error sending request to peer %d\n",
	   peer);
    return -1;
  }
  XPRINTF("%s\n",
	 opt);
  FREE(opt);
  return 0;
}


/**
 * Upload a file to a peer.
 */
static int uploadFile(int argc,
		      char *argv[]) {
  int peer, nbytes, flen, ack;
  char * buf;
  FILE * infile;
  TESTBED_UPLOAD_FILE_MESSAGE * msg;

  if (argc != 3) {
    XPRINTF("Syntax: load-file PEERID LOCAL_FILENAME DEST_FILENAME\n");
    return -1;
  }
  CHECK_PEER(peer, argv[0]);
  infile = FOPEN(argv[1], "r");
  if (infile == NULL) {
    XPRINTF(" Could not open file %s\n",
	   argv[1]);
    return -1;
  }
  flen = strlen(argv[2]) + 1; /* '\0' added in the flen */
  if (flen > TESTBED_FILE_BLK_SIZE) {
    XPRINTF(" destination file name too long (%d characters, limit %d).\n",
	   flen-1,
	   TESTBED_FILE_BLK_SIZE);
    return -1;
  }

  msg = MALLOC(sizeof(TESTBED_UPLOAD_FILE_MESSAGE) + TESTBED_FILE_BLK_SIZE);
  msg->header.header.size
    = htons(sizeof(TESTBED_UPLOAD_FILE_MESSAGE)+flen);
  msg->header.header.type
    = htons(CS_PROTO_testbed_REQUEST);
  msg->header.msgType
    = htonl(TESTBED_UPLOAD_FILE);
  msg->type
    = htonl(TESTBED_FILE_DELETE);
  memcpy(((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC*)msg)->buf, argv[2], flen);

  if (SYSERR == writeToSocket(&nodes[peer].sock,
			      &msg->header.header)) {
    fclose(infile);
    FREE(msg);
    XPRINTF(" Could not send message to peer %s.\n",
	   nodes[peer].ips);
    return -1;
  }
  /* Read ack from the peer */
  if (OK != readTCPResult(&nodes[peer].sock, &ack)) {
    fclose(infile);
    FREE(msg);
    XPRINTF("Peer is not responding\n");
    return -1;
  }
  if (ack != OK) {
    fclose(infile);
    FREE(msg);
    XPRINTF(" Peer returned error (delete existing file).\n");
    return -1;
  }
  msg->type = htonl(TESTBED_FILE_APPEND);
  buf = ((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC*)msg)->buf + flen;
  while ((nbytes = GN_FREAD(buf, 1,
			    (TESTBED_FILE_BLK_SIZE -
			     sizeof(TESTBED_UPLOAD_FILE_MESSAGE) - flen),
			    infile)) > 0) {
    if (ferror(infile))
      break;
    msg->header.header.size = htons(sizeof(TESTBED_UPLOAD_FILE_MESSAGE) +
				    nbytes + flen);
    if (SYSERR == writeToSocket(&nodes[peer].sock, &msg->header.header)) {
      fclose(infile);
      FREE(msg);
      XPRINTF(" could not send file to node %s.\n",
	     nodes[peer].ips);
      return -1;
    }
    if (OK != readResult(peer, &ack)) {
      fclose(infile);
      FREE(msg);
      return -1;
    }
    if (ack != OK) {
      fclose(infile);
      FREE(msg);
      XPRINTF(" peer returned error.\n");
      return -1;
    }
  }
  if (ferror(infile)) {
    fclose(infile);
    FREE(msg);
    XPRINTF(" could not read source file. Transmission aborted.\n");
    return -1;
  }
  fclose(infile);
  FREE(msg);
  XPRINTF("OK.\n");
  return 0;
}

/**
 * Print the list of commands.
 */
static int printOnlineHelp(int argc,
			   char * argv[]) {
  int i;
  i = 0;
  while (commands[i].command != NULL) {
    XPRINTF("%-30s%s\n",
	   commands[i].command,
	   commands[i].help);
    i++;
  }
  return 0;
}

static int processCommands(char * buffer,
			   unsigned int * available) {
  int ip[4];
  int port;
  unsigned int end;
  unsigned int start;
  char * up;
  int err;

  err = 0;
  end = 0;
  start = 0;
  while (end < *available) {
    while ( (buffer[end] != '\n') &&
	    (end < *available) )
      end++;
    if (buffer[end] != '\n') {
      if (start == 0) {
	XPRINTF("Received invalid response from HTTP server!\n");
	return -1;
      } else {
	memmove(buffer,
		&buffer[start],
		*available - start);
	*available -= start;
	return 0;
      }
    }
    up = MALLOC(end-start+1);
    memcpy(up,
	   &buffer[start],
	   end - start);
    up[end-start] = '\0';
    port = 2087; /* default port */
    if (4 <= sscanf(up,
		    "add-node %d %d %d %d %d",
		    &ip[0],
		    &ip[1],
		    &ip[2],
		    &ip[3],
		    &port)) {
      char ports[12];
      char ips[128];
      char * argv[2];
      SNPRINTF(ports,
	       12,
	       "%d",
	       port);
      SNPRINTF(ips,
	       128,
	       "%u.%u.%u.%u",
	       ip[0],
	       ip[1],
	       ip[2],
	       ip[3]);
      argv[0] = ips;
      argv[1] = ports;
      if (0 != addNode(2, argv))
	err = 2;
    } else {
      char * login;
      login = MALLOC(64);
      if (5 <= sscanf(up,
		      "add-node %63s %d %d %d %d %d",
		      login,
		      &ip[0],
		      &ip[1],
		      &ip[2],
		      &ip[3],
		      &port)) {
	char ports[12];
	char ips[128];
	char * argv[3];
	SNPRINTF(ports,
		 12,
		 "%d",
		 port);
	SNPRINTF(ips,
		 128,
		 "%u.%u.%u.%u",
		 ip[0],
		 ip[1],
		 ip[2],
		 ip[3]);
	argv[0] = login;
	argv[1] = ips;
	argv[2] = ports;
	if (0 != addSshNode(3, argv))
	  err = 2;
      }
      FREE(login);
    }
    FREE(up);
    end++;
    start = end;
  }
  return err;
}


#define GET_COMMAND "GET %s/display.php3 HTTP/1.0\r\n\r\n"
#define HTTP_URL "http://"

/**
 * add-nodes that are listed as available at the
 * TESTBED-HTTP registry.  Optional argument:
 * URL of the registry (by default we use the
 * value from the configuration file value).
 */
static int addAvailable(int argc,
			char * argv[]) {
  char * reg = NULL;
  long int port;
  char * hostname;
  unsigned int curpos;
  struct hostent *ip_info;
  struct sockaddr_in soaddr;
  int sock;
  size_t ret;
  char * command;
  cron_t start;
  char c;
  char * buffer;
  int i;
  int j;
  int k;
  struct sockaddr_in theProxy;
  char *proxy, *proxyPort;
  struct hostent *ip;
  size_t n;

  if (argc == 0) {
    reg = getConfigurationString("GNUNET-TESTBED",
				 "REGISTERURL");
    if (reg == NULL) {
      XPRINTF(" no testbed registration URL given.\n");
      return -1;
    }
  } else
    reg = STRDUP(argv[0]);



  proxy = getConfigurationString("GNUNETD",
				 "HTTP-PROXY");
  if (proxy != NULL) {
    ip = GETHOSTBYNAME(proxy);
    if (ip == NULL) {
      XPRINTF(" Couldn't resolve name of HTTP proxy %s\n",
	     proxy);
      theProxy.sin_addr.s_addr = 0;
    } else {
      theProxy.sin_addr.s_addr
	= ((struct in_addr *)ip->h_addr)->s_addr;
      proxyPort = getConfigurationString("GNUNETD",
					 "HTTP-PROXY-PORT");
      if (proxyPort == NULL) {
	theProxy.sin_port = htons(8080);
      } else {
	theProxy.sin_port = htons(atoi(proxyPort));
	FREE(proxyPort);
      }
    }
    FREE(proxy);
  } else {
    theProxy.sin_addr.s_addr = 0;
  }

  if (0 != strncmp(HTTP_URL,
		   reg,
		   strlen(HTTP_URL)) ) {
    XPRINTF(" invalid URL %s (must begin with %s)\n",
	   reg,
	   HTTP_URL);
    return -1;
  }
  port = 80; /* default http port */

  hostname = STRDUP(&reg[strlen(HTTP_URL)]);
  buffer = NULL;
  j = -1;
  k = -1;
  for (i=0;i<strlen(hostname);i++) {
    if (hostname[i] == ':')
      j = i;
    if (hostname[i] == '/') {
      k = i;
      if (j == -1)
	j = i;
      break;
    }
  }
  if ( (j != -1) && (j < k) ) {
    char * pstring;
    if (k == -1) {
      pstring = MALLOC(strlen(hostname)-j+1);
      memcpy(pstring,
	     &hostname[j],
	     strlen(hostname)-j+1);
      pstring[strlen(hostname)-j] = '\0';
    } else {
      pstring = MALLOC(k-j+1);
      memcpy(pstring,
	     &hostname[j],
	     k-j);
      pstring[k-j] = '\0';
    }
    port = strtol(pstring, &buffer, 10);
    if ( (port < 0) || (port > 65536) ) {
      XPRINTF(" malformed http URL: %s at %s.\n",
	     reg,
	     buffer);
      FREE(hostname);
      FREE(reg);
      FREE(pstring);
      return -1;
    }
    FREE(pstring);
  }
  hostname[k] = '\0';

#if DEBUG_TESTBED
  LOG(LOG_INFO,
      " Trying to download a hostlist from %s\n",
      reg);
#endif



  sock = SOCKET(PF_INET,
		SOCK_STREAM,
		0);
  if (sock < 0) {
    XPRINTF(" could not open socket for hostlist download (%s).\n",
	   STRERROR(errno));
    FREE(hostname);
    FREE(reg);
    return -1;
  }

  /* Do we need to connect through a proxy? */
  if (theProxy.sin_addr.s_addr == 0) {
    /* no proxy */
    ip_info = GETHOSTBYNAME(hostname);
    if (ip_info == NULL) {
      XPRINTF(" could not download hostlist, host %s unknown\n",
	     hostname);
      FREE(reg);
      FREE(hostname);
      return -1;
    }
    soaddr.sin_addr.s_addr
      = ((struct in_addr*)(ip_info->h_addr))->s_addr;
    soaddr.sin_port
      = htons((unsigned short)port);
  } else {
    /* proxy */
    soaddr.sin_addr.s_addr
      = theProxy.sin_addr.s_addr;
    soaddr.sin_port
      = theProxy.sin_port;
  }
  soaddr.sin_family = AF_INET;
  if (CONNECT(sock,
	      (struct sockaddr*)&soaddr,
	      sizeof(soaddr)) < 0) {
    XPRINTF(" failed to send HTTP request to host %s: %s\n",
	   hostname,
	   STRERROR(errno));
    FREE(reg);
    FREE(hostname);
    closefile(sock);
    return -1;
  }

  n = strlen(GET_COMMAND) + strlen(reg);
  command = MALLOC(n);
  SNPRINTF(command,
	   n,
	   GET_COMMAND,
	   reg);
  FREE(reg);
  curpos = strlen(command)+1;
  curpos = SEND_BLOCKING_ALL(sock,
			     command,
			     curpos);
  if (SYSERR == (int)curpos) {
    XPRINTF(" failed so send HTTP request %s to host %s (%u - %d) - %s\n",
	   command,
	   hostname,
	   curpos,
	   sock,
	   STRERROR(errno));
    FREE(command);
    FREE(hostname);
    closefile(sock);
    return -1;
  }
  FREE(command);
  FREE(hostname);
  cronTime(&start);

  /* we first have to read out the http_response*/
  /* it ends with four line delimiters: "\r\n\r\n" */
  curpos = 0;
  while (curpos < 4) {
    int success;

    if (start + 5 * cronMINUTES < cronTime(NULL))
      break; /* exit after 5m */
    success = RECV_NONBLOCKING(sock,
			       &c,
			       sizeof(c),
			       &ret);
    if ( success == NO ) {
      gnunet_util_sleep(100 * cronMILLIS);
      continue;
    }
    if ( (ret == 0) || (ret == (size_t)-1) )
      break; /* end of transmission or error */
    if ((c=='\r') || (c=='\n'))
      curpos += ret;
    else
      curpos=0;
  }
  if (curpos < 4) { /* invalid response */
    XPRINTF(" exit register (error: no http response read)\n");
    closefile(sock);
    return -1;
  }

  /* now read peer list */
  buffer = MALLOC(65536);


  while (1) {
    int success;

    if (start + 300 * cronSECONDS < cronTime(NULL))
      break; /* exit after 300s */
    curpos = 0;
    while (curpos < 65536) {
      if (start + 300 * cronSECONDS < cronTime(NULL))
	break; /* exit after 300s */
      success = RECV_NONBLOCKING(sock,
			     &buffer[curpos],
			     65536-curpos,
			     &ret);
      if ( success == NO ) {
        gnunet_util_sleep(20);
	continue;
      }
      if ( (ret == 0) || (ret == (size_t)-1) )
	break; /* end of file or error*/
      curpos += ret;

      if (0 != processCommands(buffer, &curpos)) {
	FREE(buffer);
	closefile(sock);
	return -1;
      }
    }
  }
  if (0 != processCommands(buffer, &curpos)) {
    FREE(buffer);
    closefile(sock);
    return -1;
  }
  FREE(buffer);
  closefile(sock);
  return 0;
}

/**
 * Print the list of available peers.
 */
static int listPeers(int argc, char * argv[]) {
  int i;
  for (i=0;i<nnodes;i++)
    XPRINTF("%4d - %s:%d\n",
	   i,
	   nodes[i].ips,
	   nodes[i].port);
  return 0;
}

/**
 * Exit gnunet-testbed shell.
 */
static int doExit(int argc, char * argv[]) {
  do_quit = YES;
  return 0;
}

/* ****************** command set ****************** */

CMD_ENTRY commands[] = {
  { "help",
    "print this help text",
    &printOnlineHelp },
  { "get-trust",
    "",
    &getTrust },
  { "set-bw",
    "",
    &setBW },
  { "set-trust",
    "",
    &setTrust },
  { "add-node",
    "add node to testbed, arguments: IP PORT",
    &addNode },
  { "add-ssh-node",
    "add node to testbed, arguments: LOGIN IP PORT",
    &addSshNode },
  { "connect",
    "connect two peers",
    &addConnection },
  { "disconnect",
    "disconnect two peers",
    &delConnection },
  { "disconnect-all",
    "destroy all connections between peers",
    &delAllConnections },
  { "helo-disable",
    "disable hello advertisements",
    &disablehello },
  { "helo-enable",
    "enable hello advertisements",
    &enablehello },
  { "autoconnect-disable", "", &disableAUTOCONNECT },
  { "autoconnect-enable", "", &enableAUTOCONNECT },
  { "process-start",
    "Start a process on a given peer.  Prints the process-ID on success.",
    &startProcess },
  { "process-signal",
    "Send a signal to a process running at a peer.  Use signal 0 to test if the process is still running.  Use -1 to obtain the exit code of a process that terminated.",
    &signalProcess },
  { "process-output",
    "Obtain the process output from a process at a peer.",
    &dumpProcessOutput },
  { "exit",
    "exit the testbed shell",
    &doExit },
  { "list-peers", "", &listPeers},
  { "set-loss", "", &setLoss} ,
  { "get-stats",
    "get all stats values from peer",
    &getStats },
  { "get-stat",
    "get one specific stats value from peer",
    &getStat },
  { "get-option",
    "Get configuration value from peer.",
    &getOption },
  { "load-module", "", &loadModule },
  { "unload-module", "", &unloadModule },
  { "add-available",
    "Check http server for available testbed peers and add"
    " all available nodes.  An optional argument can be"
    " passed to specify the URL of the http server.",
    &addAvailable },
  { "upload",
    "",
    &uploadFile },
  { "connect-deny", "", &denyConnect },
  { "connect-allow", "", &allowConnect },
  { NULL, NULL }, /* termination */
};


/* end of commands.c */
