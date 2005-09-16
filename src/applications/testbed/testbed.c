/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/testbed/testbed.c
 * @author Ronaldo Alves Ferreira
 * @author Christian Grothoff
 * @author Murali Khrisna Ramanathan
 * @brief Testbed CORE.  This is the code that is plugged
 * into the GNUnet core to enable transport profiling.
 */


#include "platform.h"
#include "testbed.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"

#define DEBUG_TESTBED YES

#define GET_COMMAND "GET %s/%s.php3?trusted=%s&port=%s&secure=%s HTTP/1.0\r\n\r\n"
#define HTTP_URL "http://"

/* */
static CoreAPIForApplication * coreAPI;

static Identity_ServiceAPI * identity;

static void sendAcknowledgement(ClientHandle client,
				int ack) {
  if (OK != coreAPI->sendValueToClient(client, ack)) {
    LOG(LOG_WARNING,
	_("Could not send acknowledgement back to client.\n"));
  }
}

/**
 * Handler that is called for "message not understood" cases.
 */
static void tb_undefined(ClientHandle client,
			 TESTBED_CS_MESSAGE * msg) {
  LOG(LOG_WARNING,
      _("Received unknown testbed message of type %u.\n"),
      ntohl(msg->msgType));
}

/**
 * Connect to another peer.
 */
static void tb_ADD_PEER(ClientHandle client,
			TESTBED_CS_MESSAGE * msg) {
  P2P_MESSAGE_HEADER noise;
  TESTBED_ADD_PEER_MESSAGE * hm
    = (TESTBED_ADD_PEER_MESSAGE*) msg;

  LOG(LOG_DEBUG,
      " tb_ADD_PEER\n");
  if (sizeof(TESTBED_ADD_PEER_MESSAGE) >
      ntohs(msg->header.size) ) {
    LOG(LOG_ERROR,
	_("size of `%s' message is too short. Ignoring.\n"),
	"ADD_PEER");
    return;
  }
  if (P2P_hello_MESSAGE_size(&hm->helo) !=
      ntohs(msg->header.size) - sizeof(TESTBED_CS_MESSAGE) ) {
    LOG(LOG_ERROR,
	_("size of `%s' message is wrong. Ignoring.\n"),
	"_ADD_PEER");
    return;
  }

  identity->addHost(&hm->helo);
  noise.size = htons(sizeof(P2P_MESSAGE_HEADER));
  noise.type = htons(P2P_PROTO_noise);
  coreAPI->unicast(&hm->helo.senderIdentity,
		   &noise,
		   EXTREME_PRIORITY,
		   0);
  sendAcknowledgement(client, OK);
}

/**
 * Disconnect from another peer.
 */
static void tb_DEL_PEER(ClientHandle client,
			TESTBED_DEL_PEER_MESSAGE * msg) {
  coreAPI->disconnectFromPeer(&msg->host);
  sendAcknowledgement(client, OK);
}

static void doDisconnect(const PeerIdentity * id,
			 void * unused) {
  coreAPI->disconnectFromPeer(id);
}

/**
 * Disconnect from all other peers.
 */
static void tb_DEL_ALL_PEERS(ClientHandle client,
			     TESTBED_DEL_ALL_PEERS_MESSAGE * msg) {
  coreAPI->forAllConnectedNodes(&doDisconnect,
				NULL);
  sendAcknowledgement(client, OK);
}

/**
 * Get a hello message for this peer.
 */
static void tb_GET_hello(ClientHandle client,
			TESTBED_GET_hello_MESSAGE * msg) {
  P2P_hello_MESSAGE * helo;
  unsigned int proto = ntohs(msg->proto);

  helo = identity->identity2Helo(coreAPI->myIdentity,
				 proto,
				 NO);
  if (NULL == helo) {
    LOG(LOG_WARNING,
	_("TESTBED could not generate hello message for protocol %u\n"),
	proto);
    sendAcknowledgement(client, SYSERR);
  } else {
    TESTBED_hello_MESSAGE * reply
      = MALLOC(ntohs(helo->header.size) + sizeof(TESTBED_CS_MESSAGE));
    reply->header.header.size
      = htons(ntohs(helo->header.size) + sizeof(TESTBED_CS_MESSAGE));
    reply->header.header.type
      = htons(CS_PROTO_testbed_REPLY);
    reply->header.msgType
      = htonl(TESTBED_hello_RESPONSE);
    memcpy(&reply->helo,
	   helo,
	   ntohs(helo->header.size));
    coreAPI->sendToClient(client,
			  &reply->header.header);
    LOG(LOG_DEBUG,
	"%s: returning from sendToClient\n",
	__FUNCTION__);
    FREE(helo);
    FREE(reply);
  }
}

/**
 * Set a trust value.
 */
static void tb_SET_TVALUE(ClientHandle client,
			  TESTBED_SET_TVALUE_MESSAGE * msg) {
  int trust;

  trust = ntohl(msg->trust);
  identity->changeHostTrust(&msg->otherPeer,
			    trust);
  sendAcknowledgement(client, OK);
}	
		
/**
 * Get a trust value.
 */
static void tb_GET_TVALUE(ClientHandle client,
			  TESTBED_GET_TVALUE_MESSAGE * msg) {
  unsigned int trust;

  trust = identity->getHostTrust(&msg->otherPeer);
  sendAcknowledgement(client, trust);
}	

/**
 * Change the bandwidth limitations.
 */
static void tb_SET_BW(ClientHandle client,
		      TESTBED_SET_BW_MESSAGE * msg) {
  LOG(LOG_DEBUG,
      "gnunet-testbed: tb_SET_BW\n");
  setConfigurationInt("LOAD",
		      "MAXNETDOWNBPSTOTAL",
		      ntohl(msg->in_bw));
  setConfigurationInt("LOAD",
		      "MAXNETUPBPSTOTAL",
		      ntohl(msg->out_bw));
  triggerGlobalConfigurationRefresh();
  sendAcknowledgement(client, OK);
}		

/**
 * Load an application module.
 */
static void tb_LOAD_MODULE(ClientHandle client,
			   TESTBED_CS_MESSAGE * msg) {
  unsigned short size;
  char * name;
  int ok;

  size = ntohs(msg->header.size);
  if (size <= sizeof(TESTBED_CS_MESSAGE) ) {
    LOG(LOG_WARNING,
	_("received invalid `%s' message\n"),
	"LOAD_MODULE");
    return;
  }

  if (! testConfigurationString("TESTBED",
				"ALLOW_MODULE_LOADING",
				"YES")) {
    sendAcknowledgement(client, SYSERR);
    return;
  }

  name = STRNDUP(&((TESTBED_LOAD_MODULE_MESSAGE_GENERIC*)msg)->modulename[0],
		 size - sizeof(TESTBED_CS_MESSAGE));
  if (strlen(name) == 0) {
    LOG(LOG_WARNING,
	_("received invalid `%s' message (empty module name)\n"),
	"LOAD_MODULE");
    return;
  }
  ok = coreAPI->loadApplicationModule(name);
  if (ok != OK)
    LOG(LOG_WARNING,
	_("loading module `%s' failed.  Notifying client.\n"),
	name);
  FREE(name);
  sendAcknowledgement(client, ok);
}

/**
 * Unload an application module.
 */
static void tb_UNLOAD_MODULE(ClientHandle client,
			     TESTBED_CS_MESSAGE * msg) {
  unsigned short size;
  char * name;
  int ok;

  size = ntohs(msg->header.size);
  if (size <= sizeof(TESTBED_CS_MESSAGE) ) {
    LOG(LOG_WARNING,
	_("received invalid `%s' message\n"),
	"UNLOAD_MODULE");
    return;
  }
  if (! testConfigurationString("TESTBED",
				"ALLOW_MODULE_LOADING",
				"YES")) {
    sendAcknowledgement(client, SYSERR);
    return;
  }

  name = STRNDUP(&((TESTBED_UNLOAD_MODULE_MESSAGE_GENERIC*)msg)->modulename[0],
		 size - sizeof(TESTBED_CS_MESSAGE));
  if (strlen(name) == 0) {
    LOG(LOG_WARNING,
	_("received invalid `%s' message (empty module name)\n"),
	"UNLOAD_MODULE");
    return;
  }
  ok = coreAPI->unloadApplicationModule(name);
  if (ok != OK)
    LOG(LOG_WARNING,
	_("unloading module failed.  Notifying client.\n"));
  FREE(name);
  sendAcknowledgement(client, ok);
}

/**
 * Set the reliability of the inbound and outbound transfers for this
 * peer (by making it drop a certain percentage of the messages at
 * random).
 */
static void tb_DISABLE_AUTOCONNECT(ClientHandle client,
				   TESTBED_DISABLE_AUTOCONNECT_MESSAGE * msg) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "DISABLE-AUTOCONNECT",
				     "YES"));
  triggerGlobalConfigurationRefresh();
  sendAcknowledgement(client, OK);
}

/**
 * Set the reliability of the inbound and outbound transfers for this
 * peer (by making it drop a certain percentage of the messages at
 * random).
 */
static void tb_ENABLE_AUTOCONNECT(ClientHandle client,
				  TESTBED_ENABLE_AUTOCONNECT_MESSAGE * msg) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "DISABLE-AUTOCONNECT",
				     "NO"));
  triggerGlobalConfigurationRefresh();
  sendAcknowledgement(client, OK);
}

/**
 * Set the reliability of the inbound and outbound transfers for this
 * peer (by making it drop a certain percentage of the messages at
 * random).
 */
static void tb_DISABLE_hello(ClientHandle client,
			    TESTBED_DISABLE_hello_MESSAGE * msg) {
  FREENONNULL(setConfigurationString("NETWORK",
				     "DISABLE-ADVERTISEMENTS",
				     "YES"));
  FREENONNULL(setConfigurationString("NETWORK",
				     "HELLOEXCHANGE",
				     "NO"));
  triggerGlobalConfigurationRefresh();
  sendAcknowledgement(client, OK);
}

/**
 * Set the reliability of the inbound and outbound transfers for this
 * peer (by making it drop a certain percentage of the messages at
 * random).
 */
static void tb_ENABLE_hello(ClientHandle client,
			   TESTBED_ENABLE_hello_MESSAGE * msg) {
  FREENONNULL(setConfigurationString("NETWORK",
				     "DISABLE-ADVERTISEMENTS",
				     "NO"));
  FREENONNULL(setConfigurationString("NETWORK",
				     "HELLOEXCHANGE",
				     "YES"));
  triggerGlobalConfigurationRefresh();
  sendAcknowledgement(client, OK);
}

/**
 * Allow only certain peers to connect.
 */
static void tb_ALLOW_CONNECT(ClientHandle client,
			     TESTBED_ALLOW_CONNECT_MESSAGE * msg) {
  char * value;
  unsigned short size;
  unsigned int count;
  unsigned int i;
  EncName enc;

  size = ntohs(msg->header.header.size);
  if (size <= sizeof(TESTBED_CS_MESSAGE) ) {
    LOG(LOG_WARNING,
	_("received invalid `%s' message\n"),
	"ALLOW_CONNECT");
    return;
  }
  count = (size - sizeof(TESTBED_CS_MESSAGE)) / sizeof(PeerIdentity);
  if (count * sizeof(PeerIdentity) + sizeof(TESTBED_CS_MESSAGE) != size) {
    LOG(LOG_WARNING,
	_("received invalid `%s' message\n"),
	"ALLOW_CONNECT");
    return;
  }
  if (count == 0) {
    value = NULL;
  } else {
    value = MALLOC(count * sizeof(EncName) + 1);
    value[0] = '\0';
    for (i=0;i<count;i++) {
      hash2enc(&((TESTBED_ALLOW_CONNECT_MESSAGE_GENERIC*)msg)->peers[i].hashPubKey,
	       &enc);
      strcat(value, (char*)&enc);
    }
  }
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LIMIT-ALLOW",
				     value));
  FREENONNULL(value);
  triggerGlobalConfigurationRefresh();
  sendAcknowledgement(client, OK);
}

/**
 * Deny certain peers the right to connect.
 */
static void tb_DENY_CONNECT(ClientHandle client,
			    TESTBED_DENY_CONNECT_MESSAGE * msg) {
  char * value;
  unsigned short size;
  unsigned int count;
  unsigned int i;
  EncName enc;

  size = ntohs(msg->header.header.size);
  if (size <= sizeof(TESTBED_CS_MESSAGE) ) {
    LOG(LOG_WARNING,
	_("received invalid `%s' message\n"),
	"DENY_CONNECT");
    return;
  }
  count = (size - sizeof(TESTBED_CS_MESSAGE)) / sizeof(PeerIdentity);
  if (count * sizeof(PeerIdentity) + sizeof(TESTBED_CS_MESSAGE) != size) {
    LOG(LOG_WARNING,
	_("received invalid `%s' message\n"),
	"DENY_CONNECT");
    return;
  }
  if (count == 0) {
    value = NULL;
  } else {
    value = MALLOC(count * sizeof(EncName) + 1);
    value[0] = '\0';
    for (i=0;i<count;i++) {
      hash2enc(&((TESTBED_DENY_CONNECT_MESSAGE_GENERIC*)msg)->peers[i].hashPubKey,
	       &enc);
      strcat(value, (char*)&enc);
    }
  }
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LIMIT-DENY",
				     value));
  FREENONNULL(value);
  triggerGlobalConfigurationRefresh();
  sendAcknowledgement(client, OK);
}

/**
 * Information about processes that we have forked off.
 */
typedef struct {
  /** the unique identifier of the PI */
  unsigned int uid;
  /** errno after fork */
  int errno_;
  /** the PID of the process */
  pid_t pid;
  /** stdout and stderr of the process */
  int outputPipe;
  /** thread that reads the output of the process */
  PTHREAD_T reader;
  /** how many bytes of output did the process produce? */
  unsigned int outputSize;
  /** the output of the process */
  char * output;
  /** did the process exit? (YES/NO) */
  int hasExited;
  /** if the process did exit, what was the status? (or errno of execve) */
  int exitStatus;
  /** semaphore used to communicate thread-start */
  Semaphore * sem;
  /** Client responsible for this process
      (if that client disconnects, the process
      will be killed!) */
  ClientHandle client;
  /** arguments for exec */
  char ** argv;
  int argc;
} ProcessInfo;

static unsigned int uidCounter = 0;

/**
 * The process table.
 */
static ProcessInfo ** pt = NULL;

/**
 * Number of entries in the process table.
 */
static unsigned int ptSize = 0;

/**
 * Lock for accessing the PT
 */
static Mutex lock;

/**
 * Thread that captures the output from a child-process
 * and stores it in the process info.
 */
static int pipeReaderThread(ProcessInfo * pi) {
  int ret = 1;
  char * buffer;
  int pos;
  int fd[2];
  int i;
  char * dir;
  char * tmp;

  if (0 != PIPE(fd)) {
    LOG_STRERROR(LOG_WARNING, "pipe");
    pi->pid = SYSERR;
    SEMAPHORE_UP(pi->sem);
    MUTEX_UNLOCK(&lock);
    return -1;
  }
  LOG(LOG_DEBUG,
      "exec'ing: %s with %d arguments\n",
      pi->argv[0],
      pi->argc-1);
  for (i=1;i<pi->argc;i++)
    LOG(LOG_DEBUG,
	"exec argument %d is %s\n",
	i, pi->argv[i]);
  tmp = getConfigurationString("TESTBED",
			       "UPLOAD-DIR");
  if (tmp == NULL)
    tmp = STRDUP("/");
  dir = expandFileName(tmp);
  mkdirp(dir);
  FREE(tmp);

  MUTEX_LOCK(&lock);
  pi->pid = fork();
  pi->errno_ = errno;
  if (pi->pid == 0) {
    /* make pipe stdout/stderr */

    closefile(fd[0]);
    closefile(1);
    closefile(2);
    if (-1 == dup2(fd[1], 1))
      LOG_STRERROR(LOG_ERROR, "dup2");
    if (-1 == dup2(fd[1], 2))
      LOG_STRERROR(LOG_ERROR, "dup2");
    closefile(fd[1]);
    CHDIR(dir);
    FREE(dir);
    execvp(pi->argv[0],
	   &pi->argv[0]);
    LOG_FILE_STRERROR(LOG_ERROR, "execvp", pi->argv[0]);
    fprintf(stderr,
	    _("`%s' %s failed: %s\n"),
	    "execvp",
	    pi->argv[0],
	    STRERROR(errno));
    exit(errno);
  } /* end pi->pid == 0 */
  FREE(dir);
  closefile(fd[1]);
  for (pos=0;pos<pi->argc;pos++)
    FREE(pi->argv[pos]);
  FREE(pi->argv);
  if (pi->pid == -1) {
    closefile(fd[0]);
    SEMAPHORE_UP(pi->sem);
    MUTEX_UNLOCK(&lock);
    return -1;
  }
  pi->uid = uidCounter++;
  pi->outputPipe = fd[0];
  pi->outputSize = 0;
  pi->output = NULL;
  pi->hasExited = NO;
  pi->exitStatus = 0;

  GROW(pt,
       ptSize,
       ptSize+1);
  pt[ptSize-1] = pi;
  SEMAPHORE_UP(pi->sem);
  MUTEX_UNLOCK(&lock);

#define PRT_BUFSIZE 65536
  buffer = MALLOC(PRT_BUFSIZE);
  while (ret > 0) {
    ret = READ(pi->outputPipe,
	       buffer,
	       PRT_BUFSIZE);
    if (ret <= 0)
      break;
    MUTEX_LOCK(&lock);
    if (pi->outputSize == -1) {
      MUTEX_UNLOCK(&lock);
      break;
    }
    GROW(pi->output,
	 pi->outputSize,
	 pi->outputSize + ret);
    memcpy(&pi->output[pi->outputSize-ret],
	   buffer,
	   ret);
    MUTEX_UNLOCK(&lock);
  }
  closefile(pi->outputPipe);
  MUTEX_LOCK(&lock);

  ret = waitpid(pi->pid,
		&pi->exitStatus,
		0);
  if (ret != pi->pid) {
    LOG_STRERROR(LOG_WARNING, "waitpid");
    pi->exitStatus = errno;
  }
  pi->hasExited = YES;
  MUTEX_UNLOCK(&lock);
  return 0;
}

/**
 * Execute a command.
 */
static void tb_EXEC(ClientHandle client,
		    TESTBED_CS_MESSAGE * msg) {
  int argc2;
  unsigned short size;
  unsigned int uid;
  int pos;
  TESTBED_EXEC_MESSAGE * emsg;
  ProcessInfo * pi;
  char * clientConfig;
  char * mainName;

  emsg = (TESTBED_EXEC_MESSAGE*)msg;
  size = htons(msg->header.size);
  if ( (size <= sizeof(TESTBED_CS_MESSAGE)) ||
       (((TESTBED_EXEC_MESSAGE_GENERIC*)emsg)->commandLine[size-sizeof(TESTBED_CS_MESSAGE)-1] != '\0') ) {
    LOG(LOG_WARNING,
	_("received invalid `%s' message: %s.\n"),
	"EXEC",
	(size <= sizeof(TESTBED_CS_MESSAGE))
	? "size smaller or equal than TESTBED_CS_MESSAGE"
	: "last character in command line is not zero-terminator");
    sendAcknowledgement(client, SYSERR);
    return;
  }
  size -= sizeof(TESTBED_CS_MESSAGE);
  pi = MALLOC(sizeof(ProcessInfo));
  pi->argc = 0;
  for (pos=0;pos<size;pos++)
    if (((TESTBED_EXEC_MESSAGE_GENERIC*)emsg)->commandLine[pos] == '\0')
      pi->argc++;
  mainName = STRDUP(&((TESTBED_EXEC_MESSAGE_GENERIC*)emsg)->commandLine[0]);
  clientConfig = NULL;
  if (0 == strncmp("gnunet",
		   mainName,
		   strlen("gnunet")))
    clientConfig = getConfigurationString("TESTBED",
					  "CLIENTCONFIG");
  if (clientConfig != NULL)
    pi->argc +=2;
  argc2 = pi->argc;
  pi->argv = MALLOC(sizeof(char*)*(pi->argc+1));
  pi->argv[0] = mainName;
  pi->argv[pi->argc] = NULL; /* termination! */
  for (pos=size-2;pos>=0;pos--)
    if (((TESTBED_EXEC_MESSAGE_GENERIC*)emsg)->commandLine[pos] == '\0')
      pi->argv[--argc2] = STRDUP(&((TESTBED_EXEC_MESSAGE_GENERIC*)emsg)->commandLine[pos+1]);
  if (clientConfig != NULL) {
    pi->argv[--argc2] = clientConfig;
    pi->argv[--argc2] = STRDUP("-c");
  }
  MUTEX_LOCK(&lock);

  pi->sem = SEMAPHORE_NEW(0);
  if (0 != PTHREAD_CREATE(&pi->reader,
			  (PThreadMain) &pipeReaderThread,
			  pi,
			  8*1024)) {
    LOG_STRERROR(LOG_WARNING, "pthread_create");
    SEMAPHORE_FREE(pi->sem);
    MUTEX_UNLOCK(&lock);
    FREE(pi);
    sendAcknowledgement(client, SYSERR);
    return;
  }
  MUTEX_UNLOCK(&lock);
  SEMAPHORE_DOWN(pi->sem);
  SEMAPHORE_FREE(pi->sem);
  uid = pi->uid;
  if (uid == -1) {
    errno = pi->errno_;
    LOG_STRERROR(LOG_WARNING, "fork");
    FREE(pi);
    uid = SYSERR;
  }
  sendAcknowledgement(client, uid);
}

/**
 * Send a signal to a process or obtain the status of the
 * process on exit.
 */
static void tb_SIGNAL(ClientHandle client,
		      TESTBED_SIGNAL_MESSAGE * msg) {
  int ret;
  int i;
  unsigned int uid;
  int sig;
  void * unused;
  ProcessInfo * pi;

  ret = SYSERR;
  uid = ntohl(msg->pid);
  sig = ntohl(msg->signal);
  MUTEX_LOCK(&lock);
  for (i=0;i<ptSize;i++) {
    pi = pt[i];
    if (pi->uid != uid)
      continue;
    if (sig == -1) {	
      if (pi->hasExited == NO) {
	ret = SYSERR;
      } else {	
	ret = WEXITSTATUS(pi->exitStatus);
	/* free resources... */
	GROW(pi->output,
	     pi->outputSize,
	     0);
	PTHREAD_JOIN(&pi->reader,
		     &unused);
	FREE(pi);
	pt[i] = pt[ptSize-1];
	GROW(pt,
	     ptSize,
	     ptSize-1);
      }
    } else {
      if (pi->hasExited == NO) {
	if (0 == kill(pi->pid,
		      ntohl(msg->signal)))
	  ret = OK;
	else
	  LOG_STRERROR(LOG_WARNING, "kill");
      }
    }
    break;
  }
  MUTEX_UNLOCK(&lock);
  sendAcknowledgement(client, ret);
}

/**
 * Get the output of a process.
 */
static void tb_GET_OUTPUT(ClientHandle client,
			  TESTBED_GET_OUTPUT_MESSAGE * msg) {
  int i;
  unsigned int uid;

  uid = ntohl(msg->pid);
  MUTEX_LOCK(&lock);
  for (i=0;i<ptSize;i++) {
    ProcessInfo * pi;

    pi = pt[i];
    if (pi->uid == uid) {
      unsigned int pos;
      TESTBED_OUTPUT_REPLY_MESSAGE * msg;

      msg = MALLOC(65532);
      msg->header.header.type
	= htons(CS_PROTO_testbed_REPLY);
      msg->header.msgType
	= htonl(TESTBED_OUTPUT_RESPONSE);

      sendAcknowledgement(client, pi->outputSize);
      pos = 0;
      while (pos < pi->outputSize) {	
	unsigned int run = pi->outputSize - pos;
	if (run > 65532 - sizeof(TESTBED_OUTPUT_REPLY_MESSAGE))
	  run = 65532 - sizeof(TESTBED_OUTPUT_REPLY_MESSAGE);
	msg->header.header.size
	  = htons(run+sizeof(TESTBED_OUTPUT_REPLY_MESSAGE));
	memcpy(&((TESTBED_OUTPUT_REPLY_MESSAGE_GENERIC*)msg)->data[0],
	       &pi->output[pos],
	       run);
	coreAPI->sendToClient(client,
			      &msg->header.header);
	pos += run;
      }
      FREE(msg);
      /* reset output buffer */
      GROW(pi->output,
	   pi->outputSize,
	   0);
      MUTEX_UNLOCK(&lock);
      return;
    }
  }
  MUTEX_UNLOCK(&lock);
  sendAcknowledgement(client, SYSERR);
}

/**
 * The client is uploading a file to this peer.
 */
static void tb_UPLOAD_FILE(ClientHandle client,
			   TESTBED_UPLOAD_FILE_MESSAGE * msg) {
  int ack;
  unsigned int size;
  char * filename, *gnHome, *s;
  char * end;
  char * tmp;
  FILE *outfile;

  LOG(LOG_DEBUG,
      "tb_UPLOAD_FILE\n");
  if (sizeof(TESTBED_UPLOAD_FILE_MESSAGE) > ntohs(msg->header.header.size)) {
    LOG(LOG_ERROR,
	_("size of `%s' message is too short. Ignoring.\n"),
	"UPLOAD_FILE");
    sendAcknowledgement(client, SYSERR);
    return;
  }
  end = &((char*)msg)[ntohs(msg->header.header.size)];
  s = filename = ((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC*)msg)->buf;
  while ( (*s) && (s != end) ) {
    if (*s == '.' && *(s+1) == '.') {
      LOG(LOG_ERROR,
	  _("\'..\' is not allowed in file name (%s).\n"),
	  filename);
      return;
    }
    s++;
  }
  if (s == filename) {
    /* filename empty, not allowed! */
    LOG(LOG_ERROR,
	_("Empty filename for UPLOAD_FILE message is invalid!\n"));
    sendAcknowledgement(client, SYSERR);
    return;
  }
  if (s == end) {
    /* filename empty, not allowed! */
    LOG(LOG_ERROR,
	_("Filename for UPLOAD_FILE message is not null-terminated (invalid!)\n"));
    sendAcknowledgement(client, SYSERR);
    return;
  }
  tmp = getConfigurationString("TESTBED",
			       "UPLOAD-DIR");
  if (tmp == NULL) {
    LOG(LOG_ERROR,
	_("Upload refused!"));
    sendAcknowledgement(client, SYSERR);
    return;
  }
  gnHome = expandFileName(tmp);
  FREE(tmp);
  mkdirp(gnHome);

  filename = MALLOC(strlen(filename) + strlen(gnHome) + 2); /*2: /, \0 */
  strcpy(filename, gnHome);
  strcat(filename, "/");
  strncat(filename,
	  ((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC*)msg)->buf,
	  end - ((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC*)msg)->buf);
  if (htonl(msg->type) == TESTBED_FILE_DELETE) {
    if (REMOVE(filename) && errno != ENOENT) {
      LOG_FILE_STRERROR(LOG_WARNING, "remove", filename);
      ack = SYSERR;
    } else
      ack = OK;
    FREE(filename);
    sendAcknowledgement(client, ack);
    return;
  }
  if (htonl(msg->type) != TESTBED_FILE_APPEND) {
    LOG(LOG_ERROR,
	_("Invalid message received at %s:%d."),
	__FILE__,
	__LINE__);
    FREE(filename);
    return;
  }
  outfile = FOPEN(filename, "ab");
  if (outfile == NULL) {
    /* Send nack back to control point. */
    LOG_FILE_STRERROR(LOG_ERROR, "fopen", filename);
    sendAcknowledgement(client, SYSERR);
    FREE(filename);
    return;
  }
  FREE(filename);
  s    = ((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC*)msg)->buf
    + strlen(((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC*)msg)->buf) + 1; /* \0 added */
  size = ntohs(msg->header.header.size) -
    sizeof(TESTBED_UPLOAD_FILE_MESSAGE) -
    (strlen(((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC*)msg)->buf)+1);
  if (GN_FWRITE(s, 1, size, outfile) != size)
    ack = SYSERR;
  else
    ack = OK;
  fclose(outfile);
  sendAcknowledgement(client, ack);
}

/**
 * General type of a message handler.
 */			
typedef void (*THandler)(ClientHandle client,
			 TESTBED_CS_MESSAGE * msg);

/**
 * @brief Entry in the handlers array that describes a testbed message handler.
 */
typedef struct HD_ {
    /**
     * function that handles these types of messages
     */
    THandler handler;

    /**
     * Expected size of messages for this handler.  Checked by caller.  Use
     * 0 for variable size, in that case, the handler must check.
     */
    unsigned short expectedSize;

    /**
     * Textual description of the handler for debugging
     */
    char * description;

    /**
     * The message-ID of the handler.  Used only for checking that
     * the handler array matches the message IDs defined in testbed.h.
     * Must be equal to the index in the handler array that yields
     * this entry.
     */
    unsigned int msgId;
} HD;

/* some macros to make initializing the handlers array extremely brief. */

#define TBDENTRY(a)  {(THandler)&tb_##a, 0, "##a##", TESTBED_##a }
#define TBSENTRY(a)  {(THandler)&tb_##a, sizeof(TESTBED_##a##_MESSAGE),\
		      "##a##", TESTBED_##a}

/**
 * The array of message handlers.  Add new handlers here.
 */
static HD handlers[] = {
  TBSENTRY(undefined),	/* For IDs that should never be received */
  TBDENTRY(ADD_PEER),	/* RF: Why was this as TBDENTRY? Because hello is variable size! */
  TBSENTRY(DEL_PEER),
  TBSENTRY(DEL_ALL_PEERS),
  TBSENTRY(GET_hello),
  TBSENTRY(SET_TVALUE),
  TBSENTRY(GET_TVALUE),
  TBSENTRY(undefined),
  TBSENTRY(SET_BW),
  TBDENTRY(LOAD_MODULE),
  TBDENTRY(UNLOAD_MODULE),
  TBDENTRY(UPLOAD_FILE),
  TBSENTRY(DISABLE_hello),
  TBSENTRY(ENABLE_hello),
  TBSENTRY(DISABLE_AUTOCONNECT),
  TBSENTRY(ENABLE_AUTOCONNECT),
  TBDENTRY(ALLOW_CONNECT),
  TBDENTRY(DENY_CONNECT),
  TBDENTRY(EXEC),
  TBSENTRY(SIGNAL),
  TBSENTRY(GET_OUTPUT),
  { NULL, 0, NULL, 0 },	/* this entry is used to ensure that
			   a wrong TESTBED_MAX_MSG will abort
			   insted of possibly segfaulting.
			   This must always be the LAST entry. */
};


/**
 * Global handler called by the GNUnet core.  Does the demultiplexing
 * on the testbed-message type.
 */
static void csHandleTestbedRequest(ClientHandle client,
				   CS_MESSAGE_HEADER * message) {
  TESTBED_CS_MESSAGE * msg;
  unsigned short size;
  unsigned int id;

#if DEBUG_TESTBED
  LOG(LOG_DEBUG,
      "TESTBED handleTestbedRequest\n");
#endif
  size = ntohs(message->size);
  if (size < sizeof(TESTBED_CS_MESSAGE)) {
    LOG(LOG_WARNING,
	_("received invalid testbed message of size %u\n"),
	size);
    return;
  }
  msg = (TESTBED_CS_MESSAGE *)message;
  id = ntohl(msg->msgType);
  if (id < TESTBED_MAX_MSG) {
    if ( (handlers[id].expectedSize == 0) ||
	 (handlers[id].expectedSize == size) ) {
      LOG(LOG_DEBUG,
	  "TESTBED received message of type %u.\n",
	  id);

      handlers[id].handler(client, msg);

    } else {
      LOG(LOG_ERROR,
	  _("Received testbed message of type %u but unexpected size %u, expected %u\n"),
	  id,
	  size,
	  handlers[id].expectedSize);
    }
  } else {
    tb_undefined(client, msg);
  }
}

/**
 * Register this testbed peer with the central testbed server.
 * Yes, the testbed has a central server.  There's nothing wrong
 * with that.  It's a testbed.
 */
static void httpRegister(char * cmd) {
  char * reg;
  long int port;
  char * hostname;
  unsigned int curpos;
  struct hostent *ip_info;
  struct sockaddr_in soaddr;
  int sock;
  size_t ret;
  char * command;
  char * secure;
  char * trusted;
  unsigned short tport;
  char sport[6];
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

  reg = getConfigurationString("TESTBED",
			       "REGISTERURL");
  if (reg == NULL) {
    LOG(LOG_DEBUG,
	_("No testbed URL given, not registered.\n"));
    return;
  }

  proxy = getConfigurationString("GNUNETD",
				 "HTTP-PROXY");
  if (proxy != NULL) {
    ip = GETHOSTBYNAME(proxy);
    if (ip == NULL) {
      LOG(LOG_ERROR,
	  _("Could not resolve name of HTTP proxy `%s'.\n"),
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
    LOG(LOG_WARNING,
	_("Invalid URL `%s' (must begin with `%s')\n"),
	reg,
	HTTP_URL);
    return;
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
      LOG(LOG_ERROR,
	  _("Malformed http URL: `%s' at `%s'.  Testbed-client not registered.\n"),
	  reg,
	  buffer);
      FREE(hostname);
      FREE(reg);
      FREE(pstring);
      return;
    }
    FREE(pstring);
  }
  hostname[k] = '\0';

#if DEBUG_TESTBED
  LOG(LOG_INFO,
      "Trying to (un)register testbed client at %s\n",
      reg);
#endif



  sock = SOCKET(PF_INET,
		SOCK_STREAM,
		0);
  if (sock < 0) {
    LOG_STRERROR(LOG_ERROR, "socket");
    FREE(hostname);
    FREE(reg);
    return;
  }

  /* Do we need to connect through a proxy? */
  if (theProxy.sin_addr.s_addr == 0) {
    /* no proxy */
    ip_info = GETHOSTBYNAME(hostname);
    if (ip_info == NULL) {
      LOG(LOG_WARNING,
	  _("Could not register testbed, host `%s' unknown\n"),
	  hostname);
      FREE(reg);
      FREE(hostname);
      return;
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
    LOG(LOG_WARNING,
	_("Failed to send HTTP request to host `%s': %s\n"),
	hostname,
	STRERROR(errno));
    FREE(reg);
    FREE(hostname);
    closefile(sock);
    return;
  }


  trusted = getConfigurationString("NETWORK",
				   "TRUSTED");
  if (trusted == NULL)
    trusted = STRDUP("127.0.0.0/8;");
  i = 0;
  while (trusted[i] != '\0') {
    if (trusted[i] == ';')
      trusted[i] = '@';
    i++;
  }
  tport = getGNUnetPort();
  SNPRINTF(sport,
	   6,
	   "%u",
	   tport);
  secure = getConfigurationString("TESTBED",
				  "LOGIN");
  if (secure == NULL)
    secure = STRDUP("");
  n = strlen(GET_COMMAND)
    + strlen(cmd)
    + strlen(reg)
    + strlen(trusted)
    + strlen(sport)
    + strlen(secure) + 1;
  command = MALLOC(n);
  SNPRINTF(command,
	   n,
	   GET_COMMAND,
	   reg,
	   cmd,
	   trusted,
	   sport,
	   secure);
  FREE(trusted);
  FREE(secure);
  FREE(reg);
  curpos = strlen(command)+1;
  curpos = SEND_BLOCKING_ALL(sock,
			     command,
			     curpos);
  if (SYSERR == (int)curpos) {
    LOG(LOG_WARNING,
	_("Failed so send HTTP request `%s' to host `%s': %s\n"),
	command,
	hostname,
	STRERROR(errno));
    FREE(command);
    FREE(hostname);
    closefile(sock);
    return;
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
    if ( (ret == 0) || (ret == (size_t) -1) )
      break; /* end of transmission or error */
    if ((c=='\r') || (c=='\n'))
      curpos += ret;
    else
      curpos=0;
  }
  closefile(sock);
  if (curpos < 4) { /* invalid response */
    LOG(LOG_WARNING,
	_("Exit register (error: no http response read).\n"));
  }
#if DEBUG_TESTBED
  LOG(LOG_INFO,
      "Exit register (%d seconds before timeout)\n",
      (int)(start + 300 * cronSECONDS - cronTime(NULL))/cronSECONDS);
#endif
}

/**
 * When a client exits, kill all associated processes.
 */
static void testbedClientExitHandler(ClientHandle client) {
  int i;
  int pding;
  void * unused;

  pding = 0;
  /* kill all processes */
  MUTEX_LOCK(&lock);
  for (i=ptSize-1;i>=0;i--) {
    if (pt[i]->client == client) {
      pding++;
      if (pt[i]->hasExited == NO)
	kill(pt[i]->pid, SIGKILL); /* die NOW */
    }
  }
  MUTEX_UNLOCK(&lock);
  /* join on all pthreads, but since they may be
     blocking on the same lock, unlock from time
     to time for a while to let them leave...
     FIXME: not really elegant, better use
     semaphores... */
  while (pding > 0) {
    pding = 0;
    gnunet_util_sleep(50);
    MUTEX_LOCK(&lock);
    for (i=ptSize-1;i>=0;i--) {
      if (pt[i]->client == client) {
	if (pt[i]->hasExited == YES) {
	  PTHREAD_JOIN(&pt[i]->reader,
		       &unused);
	  GROW(pt[i]->output,
	       pt[i]->outputSize,
	       0);
	  FREE(pt[i]);
	  pt[i] = pt[ptSize-1];
	  GROW(pt,
	       ptSize,
	       ptSize-1);
	} else {
	  pding++;
	}
      }
    }
    MUTEX_UNLOCK(&lock);
  }
}

/**
 * Initialize the TESTBED module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 * @return SYSERR on errors
 */
int initialize_module_testbed(CoreAPIForApplication * capi) {
  unsigned int i;

  /* some checks */
  for (i=0;i<TESTBED_MAX_MSG;i++)
    if ( (handlers[i].msgId != i) &&
	 (handlers[i].handler != &tb_undefined) )
      GNUNET_ASSERT(0);
  GNUNET_ASSERT(handlers[TESTBED_MAX_MSG].handler == NULL);
  identity = capi->requestService("identity");
  if (identity == NULL)
    return SYSERR;

  MUTEX_CREATE(&lock);
  LOG(LOG_DEBUG,
      "TESTBED registering handler %d!\n",
      CS_PROTO_testbed_REQUEST);
  coreAPI = capi;
  GNUNET_ASSERT(SYSERR != capi->registerClientExitHandler(&testbedClientExitHandler));
  GNUNET_ASSERT(SYSERR != capi->registerClientHandler(CS_PROTO_testbed_REQUEST,
						      (CSHandler)&csHandleTestbedRequest));
  httpRegister("startup");
  setConfigurationString("ABOUT",
			 "testbed",
			 gettext_noop("allows construction of a P2P-testbed"
			   " (incomplete)"));
  return OK;
}

/**
 * Shutdown the testbed module.
 */
void done_module_testbed() {
  int i;

  /* kill all child-processes */
  for (i=0;i<ptSize;i++) {
    ProcessInfo * pi;
    void * unused;

    pi = pt[i];
    if (pi->hasExited != NO)
      kill(pi->pid, SIGKILL);
    PTHREAD_JOIN(&pi->reader,
		 &unused);
    FREENONNULL(pi->output);
    FREE(pi);
  }
  GROW(pt,
       ptSize,
       0);

  httpRegister("shutdown");
  MUTEX_DESTROY(&lock);
  LOG(LOG_DEBUG,
      "TESTBED unregistering handler %d\n",
      CS_PROTO_testbed_REQUEST);
  coreAPI->unregisterClientHandler(CS_PROTO_testbed_REQUEST,
				   (CSHandler)&csHandleTestbedRequest);
  coreAPI->unregisterClientExitHandler(&testbedClientExitHandler);
  coreAPI->releaseService(identity);
  identity = NULL;
  coreAPI = NULL;
}

/* end of testbed.c */
