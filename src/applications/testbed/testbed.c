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

#define DEBUG_TESTBED GNUNET_YES

#define GET_COMMAND "GET %s/%s.php3?trusted=%s&port=%s&secure=%s HTTP/1.0\r\n\r\n"
#define HTTP_URL "http://"

/* */
static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Identity_ServiceAPI *identity;

static void
sendAcknowledgement (GNUNET_ClientHandle client, int ack)
{
  if (GNUNET_OK != coreAPI->sendValueToClient (client, ack))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Could not send acknowledgement back to client.\n"));
    }
}

/**
 * Handler that is called for "message not understood" cases.
 */
static void
tb_undefined (GNUNET_ClientHandle client, TESTBED_CS_MESSAGE * msg)
{
  GNUNET_GE_LOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                 _("Received unknown testbed message of type %u.\n"),
                 ntohl (msg->msgType));
}

/**
 * Connect to another peer.
 */
static void
tb_ADD_PEER (GNUNET_ClientHandle client, TESTBED_CS_MESSAGE * msg)
{
  GNUNET_MessageHeader noise;
  TESTBED_ADD_PEER_MESSAGE *hm = (TESTBED_ADD_PEER_MESSAGE *) msg;

  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 " tb_ADD_PEER\n");
  if (sizeof (TESTBED_ADD_PEER_MESSAGE) > ntohs (msg->header.size))
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("size of `%s' message is too short. Ignoring.\n"),
                     "ADD_PEER");
      return;
    }
  if (GNUNET_sizeof_hello (&hm->helo) !=
      ntohs (msg->header.size) - sizeof (TESTBED_CS_MESSAGE))
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("size of `%s' message is wrong. Ignoring.\n"),
                     "_ADD_PEER");
      return;
    }

  identity->addHost (&hm->helo);
  noise.size = htons (sizeof (GNUNET_MessageHeader));
  noise.type = htons (GNUNET_P2P_PROTO_NOISE);
  coreAPI->unicast (&hm->helo.senderIdentity, &noise, GNUNET_EXTREME_PRIORITY,
                    0);
  sendAcknowledgement (client, GNUNET_OK);
}

/**
 * Disconnect from another peer.
 */
static void
tb_DEL_PEER (GNUNET_ClientHandle client, TESTBED_DEL_PEER_MESSAGE * msg)
{
  coreAPI->connection_disconnect_from_peer (&msg->host);
  sendAcknowledgement (client, GNUNET_OK);
}

static void
doDisconnect (const GNUNET_PeerIdentity * id, void *unused)
{
  coreAPI->connection_disconnect_from_peer (id);
}

/**
 * Disconnect from all other peers.
 */
static void
tb_DEL_ALL_PEERS (GNUNET_ClientHandle client,
                  TESTBED_DEL_ALL_PEERS_MESSAGE * msg)
{
  coreAPI->forAllConnectedNodes (&doDisconnect, NULL);
  sendAcknowledgement (client, GNUNET_OK);
}

/**
 * Get a hello message for this peer.
 */
static void
tb_GET_hello (GNUNET_ClientHandle client, TESTBED_GET_hello_MESSAGE * msg)
{
  GNUNET_MessageHello *helo;
  unsigned int proto = ntohs (msg->proto);

  helo = identity->identity2Helo (coreAPI->myIdentity, proto, GNUNET_NO);
  if (NULL == helo)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("TESTBED could not generate hello message for protocol %u\n"),
                     proto);
      sendAcknowledgement (client, GNUNET_SYSERR);
    }
  else
    {
      TESTBED_hello_MESSAGE *reply
        =
        GNUNET_malloc (ntohs (helo->header.size) +
                       sizeof (TESTBED_CS_MESSAGE));
      reply->header.header.size =
        htons (ntohs (helo->header.size) + sizeof (TESTBED_CS_MESSAGE));
      reply->header.header.type = htons (GNUNET_CS_PROTO_TESTBED_REPLY);
      reply->header.msgType = htonl (TESTBED_hello_RESPONSE);
      memcpy (&reply->helo, helo, ntohs (helo->header.size));
      coreAPI->cs_send_to_client (client, &reply->header.header);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "%s: returning from GNUNET_CORE_cs_send_to_client\n",
                     __FUNCTION__);
      GNUNET_free (helo);
      GNUNET_free (reply);
    }
}

/**
 * Set a trust value.
 */
static void
tb_SET_TVALUE (GNUNET_ClientHandle client, TESTBED_SET_TVALUE_MESSAGE * msg)
{
  int trust;

  trust = ntohl (msg->trust);
  identity->changeHostTrust (&msg->otherPeer, trust);
  sendAcknowledgement (client, GNUNET_OK);
}

/**
 * Get a trust value.
 */
static void
tb_GET_TVALUE (GNUNET_ClientHandle client, TESTBED_GET_TVALUE_MESSAGE * msg)
{
  unsigned int trust;

  trust = identity->getHostTrust (&msg->otherPeer);
  sendAcknowledgement (client, trust);
}

/**
 * Change the bandwidth limitations.
 */
static void
tb_SET_BW (GNUNET_ClientHandle client, TESTBED_SET_BW_MESSAGE * msg)
{
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "gnunet-testbed: tb_SET_BW\n");
  setConfigurationInt ("LOAD", "MAXNETDOWNBPSTOTAL", ntohl (msg->in_bw));
  setConfigurationInt ("LOAD", "MAXNETUPBPSTOTAL", ntohl (msg->out_bw));
  triggerGlobalConfigurationRefresh ();
  sendAcknowledgement (client, GNUNET_OK);
}

/**
 * Load an application module.
 */
static void
tb_LOAD_MODULE (GNUNET_ClientHandle client, TESTBED_CS_MESSAGE * msg)
{
  unsigned short size;
  char *name;
  int ok;

  size = ntohs (msg->header.size);
  if (size <= sizeof (TESTBED_CS_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("received invalid `%s' message\n"), "LOAD_MODULE");
      return;
    }

  if (!testConfigurationString ("TESTBED", "ALLOW_MODULE_LOADING", "YES"))
    {
      sendAcknowledgement (client, GNUNET_SYSERR);
      return;
    }

  name =
    STRNDUP (&((TESTBED_LOAD_MODULE_MESSAGE_GENERIC *) msg)->
             modulename[0], size - sizeof (TESTBED_CS_MESSAGE));
  if (strlen (name) == 0)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("received invalid `%s' message (empty module name)\n"),
                     "LOAD_MODULE");
      return;
    }
  ok = coreAPI->loadApplicationModule (name);
  if (ok != GNUNET_OK)
    GNUNET_GE_LOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                   _("loading module `%s' failed.  Notifying client.\n"),
                   name);
  GNUNET_free (name);
  sendAcknowledgement (client, ok);
}

/**
 * Unload an application module.
 */
static void
tb_UNLOAD_MODULE (GNUNET_ClientHandle client, TESTBED_CS_MESSAGE * msg)
{
  unsigned short size;
  char *name;
  int ok;

  size = ntohs (msg->header.size);
  if (size <= sizeof (TESTBED_CS_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("received invalid `%s' message\n"), "UNLOAD_MODULE");
      return;
    }
  if (!testConfigurationString ("TESTBED", "ALLOW_MODULE_LOADING", "YES"))
    {
      sendAcknowledgement (client, GNUNET_SYSERR);
      return;
    }

  name =
    STRNDUP (&((TESTBED_UNLOAD_MODULE_MESSAGE_GENERIC *) msg)->
             modulename[0], size - sizeof (TESTBED_CS_MESSAGE));
  if (strlen (name) == 0)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("received invalid `%s' message (empty module name)\n"),
                     "UNLOAD_MODULE");
      return;
    }
  ok = coreAPI->unloadApplicationModule (name);
  if (ok != GNUNET_OK)
    GNUNET_GE_LOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                   _("unloading module failed.  Notifying client.\n"));
  GNUNET_free (name);
  sendAcknowledgement (client, ok);
}

/**
 * Set the reliability of the inbound and outbound transfers for this
 * peer (by making it drop a certain percentage of the messages at
 * random).
 */
static void
tb_DISABLE_AUTOCONNECT (GNUNET_ClientHandle client,
                        TESTBED_DISABLE_AUTOCONNECT_MESSAGE * msg)
{
  GNUNET_free_non_null (setConfigurationString ("GNUNETD",
                                                "DISABLE-AUTOCONNECT",
                                                "YES"));
  triggerGlobalConfigurationRefresh ();
  sendAcknowledgement (client, GNUNET_OK);
}

/**
 * Set the reliability of the inbound and outbound transfers for this
 * peer (by making it drop a certain percentage of the messages at
 * random).
 */
static void
tb_ENABLE_AUTOCONNECT (GNUNET_ClientHandle client,
                       TESTBED_ENABLE_AUTOCONNECT_MESSAGE * msg)
{
  GNUNET_free_non_null (setConfigurationString ("GNUNETD",
                                                "DISABLE-AUTOCONNECT", "NO"));
  triggerGlobalConfigurationRefresh ();
  sendAcknowledgement (client, GNUNET_OK);
}

/**
 * Set the reliability of the inbound and outbound transfers for this
 * peer (by making it drop a certain percentage of the messages at
 * random).
 */
static void
tb_DISABLE_hello (GNUNET_ClientHandle client,
                  TESTBED_DISABLE_hello_MESSAGE * msg)
{
  GNUNET_free_non_null (setConfigurationString ("NETWORK",
                                                "DISABLE-ADVERTISEMENTS",
                                                "YES"));
  GNUNET_free_non_null (setConfigurationString
                        ("NETWORK", "HELLOEXCHANGE", "NO"));
  triggerGlobalConfigurationRefresh ();
  sendAcknowledgement (client, GNUNET_OK);
}

/**
 * Set the reliability of the inbound and outbound transfers for this
 * peer (by making it drop a certain percentage of the messages at
 * random).
 */
static void
tb_ENABLE_hello (GNUNET_ClientHandle client,
                 TESTBED_ENABLE_hello_MESSAGE * msg)
{
  GNUNET_free_non_null (setConfigurationString ("NETWORK",
                                                "DISABLE-ADVERTISEMENTS",
                                                "NO"));
  GNUNET_free_non_null (setConfigurationString
                        ("NETWORK", "HELLOEXCHANGE", "YES"));
  triggerGlobalConfigurationRefresh ();
  sendAcknowledgement (client, GNUNET_OK);
}

/**
 * Allow only certain peers to connect.
 */
static void
tb_ALLOW_CONNECT (GNUNET_ClientHandle client,
                  TESTBED_ALLOW_CONNECT_MESSAGE * msg)
{
  char *value;
  unsigned short size;
  unsigned int count;
  unsigned int i;
  GNUNET_EncName enc;

  size = ntohs (msg->header.header.size);
  if (size <= sizeof (TESTBED_CS_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("received invalid `%s' message\n"), "ALLOW_CONNECT");
      return;
    }
  count = (size - sizeof (TESTBED_CS_MESSAGE)) / sizeof (GNUNET_PeerIdentity);
  if (count * sizeof (GNUNET_PeerIdentity) + sizeof (TESTBED_CS_MESSAGE) !=
      size)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("received invalid `%s' message\n"), "ALLOW_CONNECT");
      return;
    }
  if (count == 0)
    {
      value = NULL;
    }
  else
    {
      value = GNUNET_malloc (count * sizeof (GNUNET_EncName) + 1);
      value[0] = '\0';
      for (i = 0; i < count; i++)
        {
          GNUNET_hash_to_enc (&
                              ((TESTBED_ALLOW_CONNECT_MESSAGE_GENERIC
                                *) msg)->peers[i].hashPubKey, &enc);
          strcat (value, (char *) &enc);
        }
    }
  GNUNET_free_non_null (setConfigurationString
                        ("GNUNETD", "LIMIT-ALLOW", value));
  GNUNET_free_non_null (value);
  triggerGlobalConfigurationRefresh ();
  sendAcknowledgement (client, GNUNET_OK);
}

/**
 * Deny certain peers the right to connect.
 */
static void
tb_DENY_CONNECT (GNUNET_ClientHandle client,
                 TESTBED_DENY_CONNECT_MESSAGE * msg)
{
  char *value;
  unsigned short size;
  unsigned int count;
  unsigned int i;
  GNUNET_EncName enc;

  size = ntohs (msg->header.header.size);
  if (size <= sizeof (TESTBED_CS_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("received invalid `%s' message\n"), "DENY_CONNECT");
      return;
    }
  count = (size - sizeof (TESTBED_CS_MESSAGE)) / sizeof (GNUNET_PeerIdentity);
  if (count * sizeof (GNUNET_PeerIdentity) + sizeof (TESTBED_CS_MESSAGE) !=
      size)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("received invalid `%s' message\n"), "DENY_CONNECT");
      return;
    }
  if (count == 0)
    {
      value = NULL;
    }
  else
    {
      value = GNUNET_malloc (count * sizeof (GNUNET_EncName) + 1);
      value[0] = '\0';
      for (i = 0; i < count; i++)
        {
          GNUNET_hash_to_enc (&
                              ((TESTBED_DENY_CONNECT_MESSAGE_GENERIC *)
                               msg)->peers[i].hashPubKey, &enc);
          strcat (value, (char *) &enc);
        }
    }
  GNUNET_free_non_null (setConfigurationString
                        ("GNUNETD", "LIMIT-DENY", value));
  GNUNET_free_non_null (value);
  triggerGlobalConfigurationRefresh ();
  sendAcknowledgement (client, GNUNET_OK);
}

/**
 * Information about processes that we have forked off.
 */
typedef struct
{
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
  char *output;
  /** did the process exit? (GNUNET_YES/GNUNET_NO) */
  int hasExited;
  /** if the process did exit, what was the status? (or errno of execve) */
  int exitStatus;
  /** semaphore used to communicate thread-start */
  Semaphore *sem;
  /** Client responsible for this process
      (if that client disconnects, the process
      will be killed!) */
  GNUNET_ClientHandle client;
  /** arguments for exec */
  char **argv;
  int argc;
} ProcessInfo;

static unsigned int uidCounter = 0;

/**
 * The process table.
 */
static ProcessInfo **pt = NULL;

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
static int
pipeReaderThread (ProcessInfo * pi)
{
  int ret = 1;
  char *buffer;
  int pos;
  int fd[2];
  int i;
  char *dir;
  char *tmp;

  if (0 != PIPE (fd))
    {
      LOG_STRERROR (LOG_WARNING, "pipe");
      pi->pid = GNUNET_SYSERR;
      GNUNET_semaphore_up (pi->sem);
      GNUNET_mutex_unlock (&lock);
      return -1;
    }
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "exec'ing: %s with %d arguments\n", pi->argv[0],
                 pi->argc - 1);
  for (i = 1; i < pi->argc; i++)
    GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                   "exec argument %d is %s\n", i, pi->argv[i]);
  tmp = getConfigurationString ("TESTBED", "UPLOAD-DIR");
  if (tmp == NULL)
    tmp = GNUNET_strdup (DIR_SEPARATOR_STR);
  dir = expandFileName (tmp);
  GNUNET_disk_directory_create (ectx, dir);
  GNUNET_free (tmp);

  GNUNET_mutex_lock (&lock);
  pi->pid = fork ();
  pi->errno_ = errno;
  if (pi->pid == 0)
    {
      /* make pipe stdout/stderr */

      closefile (fd[0]);
      closefile (1);
      closefile (2);
      if (-1 == dup2 (fd[1], 1))
        LOG_STRERROR (LOG_ERROR, "dup2");
      if (-1 == dup2 (fd[1], 2))
        LOG_STRERROR (LOG_ERROR, "dup2");
      closefile (fd[1]);
      CHDIR (dir);
      GNUNET_free (dir);
      execvp (pi->argv[0], &pi->argv[0]);
      GNUNET_GE_LOG_STRERROR_FILE (ectx, LOG_ERROR, "execvp", pi->argv[0]);
      fprintf (stderr,
               _("`%s' %s failed: %s\n"),
               "execvp", pi->argv[0], STRERROR (errno));
      exit (errno);
    }                           /* end pi->pid == 0 */
  GNUNET_free (dir);
  closefile (fd[1]);
  for (pos = 0; pos < pi->argc; pos++)
    GNUNET_free (pi->argv[pos]);
  GNUNET_free (pi->argv);
  if (pi->pid == -1)
    {
      closefile (fd[0]);
      GNUNET_semaphore_up (pi->sem);
      GNUNET_mutex_unlock (&lock);
      return -1;
    }
  pi->uid = uidCounter++;
  pi->outputPipe = fd[0];
  pi->outputSize = 0;
  pi->output = NULL;
  pi->hasExited = GNUNET_NO;
  pi->exitStatus = 0;

  GNUNET_array_grow (pt, ptSize, ptSize + 1);
  pt[ptSize - 1] = pi;
  GNUNET_semaphore_up (pi->sem);
  GNUNET_mutex_unlock (&lock);

#define PRT_BUFSIZE 65536
  buffer = GNUNET_malloc (PRT_BUFSIZE);
  while (ret > 0)
    {
      ret = READ (pi->outputPipe, buffer, PRT_BUFSIZE);
      if (ret <= 0)
        break;
      GNUNET_mutex_lock (&lock);
      if (pi->outputSize == -1)
        {
          GNUNET_mutex_unlock (&lock);
          break;
        }
      GNUNET_array_grow (pi->output, pi->outputSize, pi->outputSize + ret);
      memcpy (&pi->output[pi->outputSize - ret], buffer, ret);
      GNUNET_mutex_unlock (&lock);
    }
  closefile (pi->outputPipe);
  GNUNET_mutex_lock (&lock);

  ret = waitpid (pi->pid, &pi->exitStatus, 0);
  if (ret != pi->pid)
    {
      LOG_STRERROR (LOG_WARNING, "waitpid");
      pi->exitStatus = errno;
    }
  pi->hasExited = GNUNET_YES;
  GNUNET_mutex_unlock (&lock);
  return 0;
}

/**
 * Execute a command.
 */
static void
tb_EXEC (GNUNET_ClientHandle client, TESTBED_CS_MESSAGE * msg)
{
  int argc2;
  unsigned short size;
  unsigned int uid;
  int pos;
  TESTBED_EXEC_MESSAGE *emsg;
  ProcessInfo *pi;
  char *clientConfig;
  char *mainName;

  emsg = (TESTBED_EXEC_MESSAGE *) msg;
  size = htons (msg->header.size);
  if ((size <= sizeof (TESTBED_CS_MESSAGE)) ||
      (((TESTBED_EXEC_MESSAGE_GENERIC *) emsg)->
       commandLine[size - sizeof (TESTBED_CS_MESSAGE) - 1] != '\0'))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("received invalid `%s' message: %s.\n"), "EXEC",
                     (size <=
                      sizeof (TESTBED_CS_MESSAGE)) ?
                     "size smaller or equal than TESTBED_CS_MESSAGE" :
                     "last character in command line is not zero-terminator");
      sendAcknowledgement (client, GNUNET_SYSERR);
      return;
    }
  size -= sizeof (TESTBED_CS_MESSAGE);
  pi = GNUNET_malloc (sizeof (ProcessInfo));
  pi->argc = 0;
  for (pos = 0; pos < size; pos++)
    if (((TESTBED_EXEC_MESSAGE_GENERIC *) emsg)->commandLine[pos] == '\0')
      pi->argc++;
  mainName =
    GNUNET_strdup (&((TESTBED_EXEC_MESSAGE_GENERIC *) emsg)->commandLine[0]);
  clientConfig = NULL;
  if (0 == strncmp ("gnunet", mainName, strlen ("gnunet")))
    clientConfig = getConfigurationString ("TESTBED", "CLIENTCONFIG");
  if (clientConfig != NULL)
    pi->argc += 2;
  argc2 = pi->argc;
  pi->argv = GNUNET_malloc (sizeof (char *) * (pi->argc + 1));
  pi->argv[0] = mainName;
  pi->argv[pi->argc] = NULL;    /* termination! */
  for (pos = size - 2; pos >= 0; pos--)
    if (((TESTBED_EXEC_MESSAGE_GENERIC *) emsg)->commandLine[pos] == '\0')
      pi->argv[--argc2] =
        GNUNET_strdup (&((TESTBED_EXEC_MESSAGE_GENERIC *) emsg)->
                       commandLine[pos + 1]);
  if (clientConfig != NULL)
    {
      pi->argv[--argc2] = clientConfig;
      pi->argv[--argc2] = GNUNET_strdup ("-c");
    }
  GNUNET_mutex_lock (&lock);

  pi->sem = GNUNET_semaphore_create (0);
  if (0 != GNUNET_thread_create (&pi->reader,
                                 (GNUNET_ThreadMainFunction) &
                                 pipeReaderThread, pi, 8 * 1024))
    {
      LOG_STRERROR (LOG_WARNING, "pthread_create");
      GNUNET_semaphore_destroy (pi->sem);
      GNUNET_mutex_unlock (&lock);
      GNUNET_free (pi);
      sendAcknowledgement (client, GNUNET_SYSERR);
      return;
    }
  GNUNET_mutex_unlock (&lock);
  GNUNET_semaphore_down (pi->sem);
  GNUNET_semaphore_destroy (pi->sem);
  uid = pi->uid;
  if (uid == -1)
    {
      errno = pi->errno_;
      LOG_STRERROR (LOG_WARNING, "fork");
      GNUNET_free (pi);
      uid = GNUNET_SYSERR;
    }
  sendAcknowledgement (client, uid);
}

/**
 * Send a signal to a process or obtain the status of the
 * process on exit.
 */
static void
tb_SIGNAL (GNUNET_ClientHandle client, TESTBED_SIGNAL_MESSAGE * msg)
{
  int ret;
  int i;
  unsigned int uid;
  int sig;
  void *unused;
  ProcessInfo *pi;

  ret = GNUNET_SYSERR;
  uid = ntohl (msg->pid);
  sig = ntohl (msg->signal);
  GNUNET_mutex_lock (&lock);
  for (i = 0; i < ptSize; i++)
    {
      pi = pt[i];
      if (pi->uid != uid)
        continue;
      if (sig == -1)
        {
          if (pi->hasExited == GNUNET_NO)
            {
              ret = GNUNET_SYSERR;
            }
          else
            {
              ret = WEXITSTATUS (pi->exitStatus);
              /* free resources... */
              GNUNET_array_grow (pi->output, pi->outputSize, 0);
              GNUNET_thread_join (&pi->reader, &unused);
              GNUNET_free (pi);
              pt[i] = pt[ptSize - 1];
              GNUNET_array_grow (pt, ptSize, ptSize - 1);
            }
        }
      else
        {
          if (pi->hasExited == GNUNET_NO)
            {
              if (0 == kill (pi->pid, ntohl (msg->signal)))
                ret = GNUNET_OK;
              else
                LOG_STRERROR (LOG_WARNING, "kill");
            }
        }
      break;
    }
  GNUNET_mutex_unlock (&lock);
  sendAcknowledgement (client, ret);
}

/**
 * Get the output of a process.
 */
static void
tb_GET_OUTPUT (GNUNET_ClientHandle client, TESTBED_GET_OUTPUT_MESSAGE * msg)
{
  int i;
  unsigned int uid;

  uid = ntohl (msg->pid);
  GNUNET_mutex_lock (&lock);
  for (i = 0; i < ptSize; i++)
    {
      ProcessInfo *pi;

      pi = pt[i];
      if (pi->uid == uid)
        {
          unsigned int pos;
          TESTBED_OUTPUT_REPLY_MESSAGE *msg;

          msg = GNUNET_malloc (65532);
          msg->header.header.type = htons (GNUNET_CS_PROTO_TESTBED_REPLY);
          msg->header.msgType = htonl (TESTBED_OUTPUT_RESPONSE);

          sendAcknowledgement (client, pi->outputSize);
          pos = 0;
          while (pos < pi->outputSize)
            {
              unsigned int run = pi->outputSize - pos;
              if (run > 65532 - sizeof (TESTBED_OUTPUT_REPLY_MESSAGE))
                run = 65532 - sizeof (TESTBED_OUTPUT_REPLY_MESSAGE);
              msg->header.header.size
                = htons (run + sizeof (TESTBED_OUTPUT_REPLY_MESSAGE));
              memcpy (&((TESTBED_OUTPUT_REPLY_MESSAGE_GENERIC *) msg)->
                      data[0], &pi->output[pos], run);
              coreAPI->cs_send_to_client (client, &msg->header.header);
              pos += run;
            }
          GNUNET_free (msg);
          /* reset output buffer */
          GNUNET_array_grow (pi->output, pi->outputSize, 0);
          GNUNET_mutex_unlock (&lock);
          return;
        }
    }
  GNUNET_mutex_unlock (&lock);
  sendAcknowledgement (client, GNUNET_SYSERR);
}

/**
 * The client is uploading a file to this peer.
 */
static void
tb_UPLOAD_FILE (GNUNET_ClientHandle client, TESTBED_UPLOAD_FILE_MESSAGE * msg)
{
  int ack;
  unsigned int size;
  char *filename, *gnHome, *s;
  char *end;
  char *tmp;
  FILE *outfile;

  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "tb_UPLOAD_FILE\n");
  if (sizeof (TESTBED_UPLOAD_FILE_MESSAGE) > ntohs (msg->header.header.size))
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("size of `%s' message is too short. Ignoring.\n"),
                     "UPLOAD_FILE");
      sendAcknowledgement (client, GNUNET_SYSERR);
      return;
    }
  end = &((char *) msg)[ntohs (msg->header.header.size)];
  s = filename = ((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC *) msg)->buf;
  while ((*s) && (s != end))
    {
      if (*s == '.' && *(s + 1) == '.')
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("\'..\' is not allowed in file name (%s).\n"),
                         filename);
          return;
        }
      s++;
    }
  if (s == filename)
    {
      /* filename empty, not allowed! */
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Empty filename for UPLOAD_FILE message is invalid!\n"));
      sendAcknowledgement (client, GNUNET_SYSERR);
      return;
    }
  if (s == end)
    {
      /* filename empty, not allowed! */
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Filename for UPLOAD_FILE message is not null-terminated (invalid!)\n"));
      sendAcknowledgement (client, GNUNET_SYSERR);
      return;
    }
  tmp = getConfigurationString ("TESTBED", "UPLOAD-DIR");
  if (tmp == NULL)
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Upload refused!"));
      sendAcknowledgement (client, GNUNET_SYSERR);
      return;
    }
  gnHome = expandFileName (tmp);
  GNUNET_free (tmp);
  GNUNET_disk_directory_create (ectx, gnHome);

  filename = GNUNET_malloc (strlen (filename) + strlen (gnHome) + 2);   /*2: /, \0 */
  strcpy (filename, gnHome);
  strcat (filename, DIR_SEPARATOR_STR);
  strncat (filename,
           ((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC *) msg)->buf,
           end - ((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC *) msg)->buf);
  if (htonl (msg->type) == TESTBED_FILE_DELETE)
    {
      if (REMOVE (filename) && errno != ENOENT)
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx, LOG_WARNING, "remove", filename);
          ack = GNUNET_SYSERR;
        }
      else
        ack = GNUNET_OK;
      GNUNET_free (filename);
      sendAcknowledgement (client, ack);
      return;
    }
  if (htonl (msg->type) != TESTBED_FILE_GNUNET_array_append)
    {
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Invalid message received at %s:%d."), __FILE__,
                     __LINE__);
      GNUNET_free (filename);
      return;
    }
  outfile = FOPEN (filename, "ab");
  if (outfile == NULL)
    {
      /* Send nack back to control point. */
      GNUNET_GE_LOG_STRERROR_FILE (ectx, LOG_ERROR, "fopen", filename);
      sendAcknowledgement (client, GNUNET_SYSERR);
      GNUNET_free (filename);
      return;
    }
  GNUNET_free (filename);
  s = ((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC *) msg)->buf + strlen (((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC *) msg)->buf) + 1;     /* \0 added */
  size = ntohs (msg->header.header.size) -
    sizeof (TESTBED_UPLOAD_FILE_MESSAGE) -
    (strlen (((TESTBED_UPLOAD_FILE_MESSAGE_GENERIC *) msg)->buf) + 1);
  if (GN_FWRITE (s, 1, size, outfile) != size)
    ack = GNUNET_SYSERR;
  else
    ack = GNUNET_OK;
  fclose (outfile);
  sendAcknowledgement (client, ack);
}

/**
 * General type of a message handler.
 */
typedef void (*THandler) (GNUNET_ClientHandle client,
                          TESTBED_CS_MESSAGE * msg);

/**
 * @brief Entry in the handlers array that describes a testbed message handler.
 */
typedef struct HD_
{
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
  char *description;

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
  TBSENTRY (undefined),         /* For IDs that should never be received */
  TBDENTRY (ADD_PEER),          /* RF: Why was this as TBDENTRY? Because hello is variable size! */
  TBSENTRY (DEL_PEER),
  TBSENTRY (DEL_ALL_PEERS),
  TBSENTRY (GET_hello),
  TBSENTRY (SET_TVALUE),
  TBSENTRY (GET_TVALUE),
  TBSENTRY (undefined),
  TBSENTRY (SET_BW),
  TBDENTRY (LOAD_MODULE),
  TBDENTRY (UNLOAD_MODULE),
  TBDENTRY (UPLOAD_FILE),
  TBSENTRY (DISABLE_hello),
  TBSENTRY (ENABLE_hello),
  TBSENTRY (DISABLE_AUTOCONNECT),
  TBSENTRY (ENABLE_AUTOCONNECT),
  TBDENTRY (ALLOW_CONNECT),
  TBDENTRY (DENY_CONNECT),
  TBDENTRY (EXEC),
  TBSENTRY (SIGNAL),
  TBSENTRY (GET_OUTPUT),
  {NULL, 0, NULL, 0},           /* this entry is used to ensure that
                                   a wrong TESTBED_MAX_MSG will abort
                                   insted of possibly segfaulting.
                                   This must always be the LAST entry. */
};


/**
 * Global handler called by the GNUnet core.  Does the demultiplexing
 * on the testbed-message type.
 */
static void
csHandleTestbedRequest (GNUNET_ClientHandle client,
                        CS_MESSAGE_HEADER * message)
{
  TESTBED_CS_MESSAGE *msg;
  unsigned short size;
  unsigned int id;

#if DEBUG_TESTBED
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TESTBED handleTestbedRequest\n");
#endif
  size = ntohs (message->size);
  if (size < sizeof (TESTBED_CS_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("received invalid testbed message of size %u\n"),
                     size);
      return;
    }
  msg = (TESTBED_CS_MESSAGE *) message;
  id = ntohl (msg->msgType);
  if (id < TESTBED_MAX_MSG)
    {
      if ((handlers[id].expectedSize == 0) ||
          (handlers[id].expectedSize == size))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "TESTBED received message of type %u.\n", id);

          handlers[id].handler (client, msg);

        }
      else
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Received testbed message of type %u but unexpected size %u, expected %u\n"),
                         id, size, handlers[id].expectedSize);
        }
    }
  else
    {
      tb_undefined (client, msg);
    }
}

/**
 * Register this testbed peer with the central testbed server.
 * Yes, the testbed has a central server.  There's nothing wrong
 * with that.  It's a testbed.
 */
static void
httpRegister (char *cmd)
{
  char *reg;
  long int port;
  char *hostname;
  unsigned int curpos;
  GNUNET_IPv4Address ip_info;
  struct sockaddr_in soaddr;
  int sock;
  size_t ret;
  char *command;
  char *secure;
  char *trusted;
  unsigned short tport;
  char sport[6];
  GNUNET_CronTime start;
  char c;
  char *buffer;
  int i;
  int j;
  int k;
  struct sockaddr_in theProxy;
  char *proxy, *proxyPort;
  size_t n;

  reg = getConfigurationString ("TESTBED", "REGISTERURL");
  if (reg == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     _("No testbed URL given, not registered.\n"));
      return;
    }

  proxy = getConfigurationString ("GNUNETD", "HTTP-PROXY");
  if (proxy != NULL)
    {
      if (GNUNET_OK != GNUNET_get_host_by_name (ectx, proxy, &ip_info))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("Could not resolve name of HTTP proxy `%s'.\n"),
                         proxy);
          theProxy.sin_addr.s_addr = 0;
        }
      else
        {
          memcpy (&theProxy.sin_addr.s_addr, &ip_info,
                  sizeof (GNUNET_IPv4Address));
          proxyPort = getConfigurationString ("GNUNETD", "HTTP-PROXY-PORT");
          if (proxyPort == NULL)
            {
              theProxy.sin_port = htons (8080);
            }
          else
            {
              theProxy.sin_port = htons (atoi (proxyPort));
              GNUNET_free (proxyPort);
            }
        }
      GNUNET_free (proxy);
    }
  else
    {
      theProxy.sin_addr.s_addr = 0;
    }

  if (0 != strncmp (HTTP_URL, reg, strlen (HTTP_URL)))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Invalid URL `%s' (must begin with `%s')\n"), reg,
                     HTTP_URL);
      return;
    }
  port = 80;                    /* default http port */

  hostname = GNUNET_strdup (&reg[strlen (HTTP_URL)]);
  buffer = NULL;
  j = -1;
  k = -1;
  for (i = 0; i < strlen (hostname); i++)
    {
      if (hostname[i] == ':')
        j = i;
      if (hostname[i] == '/')
        {
          k = i;
          if (j == -1)
            j = i;
          break;
        }
    }
  if ((j != -1) && (j < k))
    {
      char *pstring;
      if (k == -1)
        {
          pstring = GNUNET_malloc (strlen (hostname) - j + 1);
          memcpy (pstring, &hostname[j], strlen (hostname) - j + 1);
          pstring[strlen (hostname) - j] = '\0';
        }
      else
        {
          pstring = GNUNET_malloc (k - j + 1);
          memcpy (pstring, &hostname[j], k - j);
          pstring[k - j] = '\0';
        }
      port = strtol (pstring, &buffer, 10);
      if ((port < 0) || (port > 65536))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Malformed http URL: `%s' at `%s'.  Testbed-client not registered.\n"),
                         reg, buffer);
          GNUNET_free (hostname);
          GNUNET_free (reg);
          GNUNET_free (pstring);
          return;
        }
      GNUNET_free (pstring);
    }
  hostname[k] = '\0';

#if DEBUG_TESTBED
  GNUNET_GE_LOG (ectx, GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Trying to (un)register testbed client at %s\n", reg);
#endif



  sock = SOCKET (PF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      LOG_STRERROR (LOG_ERROR, "socket");
      GNUNET_free (hostname);
      GNUNET_free (reg);
      return;
    }

  /* Do we need to connect through a proxy? */
  if (theProxy.sin_addr.s_addr == 0)
    {
      /* no proxy */
      if (GNUNET_OK != GNUNET_get_host_by_name (ectx, hostname, &ip_info))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("Could not register testbed, host `%s' unknown\n"),
                         hostname);
          GNUNET_free (reg);
          GNUNET_free (hostname);
          return;
        }
      memcpy (&soaddr.sin_addr.s_addr, &ip_info, sizeof (GNUNET_IPv4Address));
      soaddr.sin_port = htons ((unsigned short) port);
    }
  else
    {
      /* proxy */
      soaddr.sin_addr.s_addr = theProxy.sin_addr.s_addr;
      soaddr.sin_port = theProxy.sin_port;
    }
  soaddr.sin_family = AF_INET;
  if (CONNECT (sock,
               (struct sockaddr *) &soaddr,
               sizeof (soaddr)) < 0 && errno != EWOULDBLOCK)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Failed to send HTTP request to host `%s': %s\n"),
                     hostname, STRERROR (errno));
      GNUNET_free (reg);
      GNUNET_free (hostname);
      closefile (sock);
      return;
    }


  trusted = getConfigurationString ("NETWORK", "TRUSTED");
  if (trusted == NULL)
    trusted = GNUNET_strdup ("127.0.0.0/8;");
  i = 0;
  while (trusted[i] != '\0')
    {
      if (trusted[i] == ';')
        trusted[i] = '@';
      i++;
    }
  tport = getGNUnetPort ();
  GNUNET_snprintf (sport, 6, "%u", tport);
  secure = getConfigurationString ("TESTBED", "LOGIN");
  if (secure == NULL)
    secure = GNUNET_strdup ("");
  n = strlen (GET_COMMAND)
    + strlen (cmd)
    + strlen (reg) + strlen (trusted) + strlen (sport) + strlen (secure) + 1;
  command = GNUNET_malloc (n);
  GNUNET_snprintf (command, n, GET_COMMAND, reg, cmd, trusted, sport, secure);
  GNUNET_free (trusted);
  GNUNET_free (secure);
  GNUNET_free (reg);
  curpos = strlen (command) + 1;
  curpos = SEND_BLOCKING_ALL (sock, command, curpos);
  if (GNUNET_SYSERR == (int) curpos)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Failed so send HTTP request `%s' to host `%s': %s\n"),
                     command, hostname, STRERROR (errno));
      GNUNET_free (command);
      GNUNET_free (hostname);
      closefile (sock);
      return;
    }
  GNUNET_free (command);
  GNUNET_free (hostname);
  cronTime (&start);

  /* we first have to read out the http_response */
  /* it ends with four line delimiters: "\r\n\r\n" */
  curpos = 0;
  while (curpos < 4)
    {
      int success;

      if (start + 5 * GNUNET_CRON_MINUTES < GNUNET_get_time ())
        break;                  /* exit after 5m */
      success = RECV_NONBLOCKING (sock, &c, sizeof (c), &ret);
      if (success == GNUNET_NO)
        {
          GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
          continue;
        }
      if ((ret == 0) || (ret == (size_t) - 1))
        break;                  /* end of transmission or error */
      if ((c == '\r') || (c == '\n'))
        curpos += ret;
      else
        curpos = 0;
    }
  closefile (sock);
  if (curpos < 4)
    {                           /* invalid response */
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Exit register (error: no http response read).\n"));
    }
#if DEBUG_TESTBED
  GNUNET_GE_LOG (ectx, GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Exit register (%d seconds before timeout)\n",
                 (int) (start + 300 * GNUNET_CRON_SECONDS -
                        GNUNET_get_time ()) / GNUNET_CRON_SECONDS);
#endif
}

/**
 * When a client exits, kill all associated processes.
 */
static void
testbedClientExitHandler (GNUNET_ClientHandle client)
{
  int i;
  int pding;
  void *unused;

  pding = 0;
  /* kill all processes */
  GNUNET_mutex_lock (&lock);
  for (i = ptSize - 1; i >= 0; i--)
    {
      if (pt[i]->client == client)
        {
          pding++;
          if (pt[i]->hasExited == GNUNET_NO)
            kill (pt[i]->pid, SIGKILL); /* die NOW */
        }
    }
  GNUNET_mutex_unlock (&lock);
  /* join on all pthreads, but since they may be
     blocking on the same lock, unlock from time
     to time for a while to let them leave...
     FIXME: not really elegant, better use
     semaphores... */
  while (pding > 0)
    {
      pding = 0;
      GNUNET_thread_sleep (50);
      GNUNET_mutex_lock (&lock);
      for (i = ptSize - 1; i >= 0; i--)
        {
          if (pt[i]->client == client)
            {
              if (pt[i]->hasExited == GNUNET_YES)
                {
                  GNUNET_thread_join (&pt[i]->reader, &unused);
                  GNUNET_array_grow (pt[i]->output, pt[i]->outputSize, 0);
                  GNUNET_free (pt[i]);
                  pt[i] = pt[ptSize - 1];
                  GNUNET_array_grow (pt, ptSize, ptSize - 1);
                }
              else
                {
                  pding++;
                }
            }
        }
      GNUNET_mutex_unlock (&lock);
    }
}

/**
 * Initialize the TESTBED module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 * @return GNUNET_SYSERR on errors
 */
int
initialize_module_testbed (GNUNET_CoreAPIForPlugins * capi)
{
  unsigned int i;

  /* some checks */
  for (i = 0; i < TESTBED_MAX_MSG; i++)
    if ((handlers[i].msgId != i) && (handlers[i].handler != &tb_undefined))
      GNUNET_GE_ASSERT (ectx, 0);
  GNUNET_GE_ASSERT (ectx, handlers[TESTBED_MAX_MSG].handler == NULL);
  identity = capi->request_service ("identity");
  if (identity == NULL)
    return GNUNET_SYSERR;

  GNUNET_mutex_create (&lock);
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TESTBED registering handler %d!\n",
                 GNUNET_CS_PROTO_TESTBED_REQUEST);
  coreAPI = capi;
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->
                    GNUNET_CORE_cs_register_exit_handler
                    (&testbedClientExitHandler));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->
                    registerClientHandler (GNUNET_CS_PROTO_TESTBED_REQUEST,
                                           (GNUNET_ClientRequestHandler) &
                                           csHandleTestbedRequest));
  httpRegister ("startup");

  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "testbed",
                                                                   gettext_noop
                                                                   ("allows construction of a P2P-testbed"
                                                                    " (incomplete)")));
  return GNUNET_OK;
}

/**
 * Shutdown the testbed module.
 */
void
done_module_testbed ()
{
  int i;

  /* kill all child-processes */
  for (i = 0; i < ptSize; i++)
    {
      ProcessInfo *pi;
      void *unused;

      pi = pt[i];
      if (pi->hasExited != GNUNET_NO)
        kill (pi->pid, SIGKILL);
      GNUNET_thread_join (&pi->reader, &unused);
      GNUNET_free_non_null (pi->output);
      GNUNET_free (pi);
    }
  GNUNET_array_grow (pt, ptSize, 0);

  httpRegister ("shutdown");
  GNUNET_mutex_destroy (&lock);
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TESTBED unregistering handler %d\n",
                 GNUNET_CS_PROTO_TESTBED_REQUEST);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_TESTBED_REQUEST,
                                    (GNUNET_ClientRequestHandler) &
                                    csHandleTestbedRequest);
  coreAPI->cs_exit_handler_unregister (&testbedClientExitHandler);
  coreAPI->release_service (identity);
  identity = NULL;
  coreAPI = NULL;
}

/* end of testbed.c */
