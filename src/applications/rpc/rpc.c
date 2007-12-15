/*
      This file is part of GNUnet

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
 * @file module/dht_rpc.c
 * @brief Implementation of RPC's
 * @author Antti Salonen, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_rpc_service.h"
#include "gnunet_rpc_lib.h"

/**
 * Flag that determines if the RPC test will be build as
 * an application module.
 */
#define PROVIDE_RPC_TEST GNUNET_YES

/**
 * Print messages helpful for debugging the RPC code.
 */
#define DEBUG_RPC GNUNET_NO

/**
 * Print messages helpful for debugging RPC clients.
 */
#define DEBUG_RPC_CLIENT GNUNET_NO

/**
 * Minimum delay between retry attempts for RPC messages.
 */
#define MIN_RPC_FREQUENCY (50 * GNUNET_CRON_MILLISECONDS)

/**
 * Initial minimum delay between retry attempts for RPC messages
 * (before we figure out how fast the connection really is).
 */
#define INITIAL_RPC_FREQUENCY (15 * GNUNET_CRON_SECONDS)

/**
 * After what time do we time-out every request (if it is not
 * repeated)?
 */
#define MAX_RPC_TIMEOUT (2 * GNUNET_CRON_MINUTES)


#if DEBUG_RPC_CLIENT
#define RPC_STATUS(a,b,c) GNUNET_GE_LOG(ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER, "RPC: `%s' (%p) %s at %s\n", a, c, b, __FUNCTION__);
#else
#define RPC_STATUS(a,b,c)
#endif


/**
 * Access to GNUnet core API.
 */
static GNUNET_CoreAPIForPlugins *coreAPI = NULL;

/**
 * A mutex for synchronous access to all module-wide data structures. This
 * lock must be held by the thread that accesses any module-wide accessable
 * data structures.
 */
static struct GNUNET_Mutex *rpcLock;

static struct GNUNET_GE_Context *ectx;

/* *************** RPC registration ****************** */

/**
 * An RPC registered by the local node.
 */
typedef struct
{
  char *name;
  /**
   * Callback for a synchronous RPC.  NULL for async RPCs.
   */
  GNUNET_RPC_SynchronousFunction callback;

  /**
   * Callback for an asynchronous RPC.  NULL for sync RPCs.
   */
  GNUNET_RPC_AsynchronousFunction async_callback;
} RegisteredRPC;

/**
 * A set of RegisteredRPC structures, one for each RPC registered by the
 * local node.
 */
static struct GNUNET_Vector *list_of_callbacks;


/**
 * Registers an RPC callback under the given name.
 * @param name the name of the callback, must not be NULL
 * @param callback the function to call
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 *   (typically if a callback of that name is already in use).
 */
static int
RPC_register (const char *name, GNUNET_RPC_SynchronousFunction callback)
{
  RegisteredRPC *rrpc;

  GNUNET_GE_ASSERT (ectx, name != NULL);
  GNUNET_GE_ASSERT (ectx, callback != NULL);
  GNUNET_mutex_lock (rpcLock);
  rrpc = GNUNET_vector_get_first (list_of_callbacks);
  while (rrpc != NULL)
    {
      if (0 == strcmp (rrpc->name, name))
        {
          GNUNET_mutex_unlock (rpcLock);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("%s::%s - RPC %s:%p could not be registered:"
                           " another callback is already using this name (%p)\n"),
                         __FILE__, __FUNCTION__, name, callback,
                         rrpc->callback);
          return GNUNET_SYSERR;
        }
      rrpc = GNUNET_vector_get_next (list_of_callbacks);
    }
  rrpc = GNUNET_malloc (sizeof (RegisteredRPC));
  rrpc->name = GNUNET_strdup (name);
  rrpc->callback = callback;
  rrpc->async_callback = NULL;
  GNUNET_vector_insert_last (list_of_callbacks, rrpc);
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "%s::%s - Registered RPC %d: %s\n",
                 __FILE__, __FUNCTION__,
                 GNUNET_vector_get_size (list_of_callbacks), name);
  GNUNET_mutex_unlock (rpcLock);
  return GNUNET_OK;
}

/**
 * Registers an async RPC callback under the given name.
 * @param name the name of the callback, must not be NULL
 * @param callback the function to call
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 *   (typically if a callback of that name is already in use).
 */
static int
RPC_register_async (const char *name,
                    GNUNET_RPC_AsynchronousFunction callback)
{
  RegisteredRPC *rrpc;

  GNUNET_GE_ASSERT (ectx, name != NULL);
  GNUNET_GE_ASSERT (ectx, callback != NULL);
  GNUNET_mutex_lock (rpcLock);
  rrpc = GNUNET_vector_get_first (list_of_callbacks);
  while (rrpc != NULL)
    {
      if (0 == strcmp (rrpc->name, name))
        {
          GNUNET_mutex_unlock (rpcLock);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("%s::%s - RPC %s:%p could not be registered:"
                           " another callback is already using this name (%p)\n"),
                         __FILE__, __FUNCTION__, name, callback,
                         rrpc->callback);
          return GNUNET_SYSERR;
        }
      rrpc = GNUNET_vector_get_next (list_of_callbacks);
    }
  rrpc = GNUNET_malloc (sizeof (RegisteredRPC));
  rrpc->name = GNUNET_strdup (name);
  rrpc->callback = NULL;
  rrpc->async_callback = callback;
  GNUNET_vector_insert_last (list_of_callbacks, rrpc);
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "%s::%s - Registered asynchronous RPC %d: %s\n",
                 __FILE__, __FUNCTION__,
                 GNUNET_vector_get_size (list_of_callbacks), name);
  GNUNET_mutex_unlock (rpcLock);
  return GNUNET_OK;
}


/**
 * Unregisters an RPC callback of the given name.
 * @param name the name of the callback, must not be NULL
 * @param callback the function to unregister, NULL for any function
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 *   (typically if a callback of that name does not exist or is
 *    bound to a different function).
 */
static int
RPC_unregister (const char *name, GNUNET_RPC_SynchronousFunction callback)
{
  RegisteredRPC *rrpc;

  GNUNET_GE_ASSERT (ectx, name != NULL);
  GNUNET_mutex_lock (rpcLock);
  rrpc = GNUNET_vector_get_first (list_of_callbacks);
  while (rrpc != NULL)
    {
      if (0 == strcmp (rrpc->name, name))
        {
          if ((rrpc->callback != callback) && (callback != NULL))
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _("%s::%s - RPC %s:%p could not be unregistered:"
                               " another callback registered under that name: %p\n"),
                             __FILE__, __FUNCTION__, name, callback,
                             rrpc->callback);
              GNUNET_mutex_unlock (rpcLock);
              return GNUNET_SYSERR;
            }
          GNUNET_vector_delete (list_of_callbacks, rrpc);
          GNUNET_free (rrpc->name);
          GNUNET_free (rrpc);
          GNUNET_mutex_unlock (rpcLock);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "%s::%s - Unregistered RPC %s\n", __FILE__,
                         __FUNCTION__, name);
          return GNUNET_OK;
        }
      rrpc = GNUNET_vector_get_next (list_of_callbacks);
    }
  GNUNET_mutex_unlock (rpcLock);
  GNUNET_GE_LOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                 _
                 ("%s::%s - RPC %s:%p could not be unregistered: not found\n"),
                 __FILE__, __FUNCTION__, name, callback);
  return GNUNET_SYSERR;
}

/**
 * Unregisters an asynchronous RPC callback of the given name.
 * @param name the name of the callback, must not be NULL
 * @param callback the function to unregister, NULL for any function
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 *   (typically if a callback of that name does not exist or is
 *    bound to a different function).
 */
static int
RPC_unregister_async (const char *name,
                      GNUNET_RPC_AsynchronousFunction callback)
{
  RegisteredRPC *rrpc;

  GNUNET_GE_ASSERT (ectx, name != NULL);
  GNUNET_mutex_lock (rpcLock);
  rrpc = GNUNET_vector_get_first (list_of_callbacks);
  while (rrpc != NULL)
    {
      if (0 == strcmp (rrpc->name, name))
        {
          if ((rrpc->async_callback != callback) && (callback != NULL))
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _("%s::%s - RPC %s:%p could not be unregistered:"
                               " another callback registered under that name: %p\n"),
                             __FILE__, __FUNCTION__, name, callback,
                             rrpc->callback);
              GNUNET_mutex_unlock (rpcLock);
              return GNUNET_SYSERR;
            }
          GNUNET_vector_delete (list_of_callbacks, rrpc);
          GNUNET_free (rrpc->name);
          GNUNET_free (rrpc);
          GNUNET_mutex_unlock (rpcLock);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "%s::%s - Unregistered asynchronous RPC %s\n",
                         __FILE__, __FUNCTION__, name);
          return GNUNET_OK;
        }
      rrpc = GNUNET_vector_get_next (list_of_callbacks);
    }
  GNUNET_mutex_unlock (rpcLock);
  GNUNET_GE_LOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                 _
                 ("%s::%s - async RPC %s:%p could not be unregistered: not found\n"),
                 __FILE__, __FUNCTION__, name, callback);
  return GNUNET_SYSERR;
}


/* ******** tracking per peer stats to estimate turnaround ***** */

/**
 * What is the time-interval for which we keep activity stats?
 */
#define PEER_TRACKING_TIME_INTERVAL (30 * GNUNET_CRON_SECONDS)

/**
 * Of how many messages do we keep track per peer (for statistics).
 */
#define MTRACK_COUNT 64

/**
 * A per-peer structure to store TCP-like data.
 */
typedef struct
{
  GNUNET_PeerIdentity identity;

  /**
   * What is the expected response time for this peer? (0 for unknown)
   */
  GNUNET_CronTime averageResponseTime;

  /**
   * In which of the last 32 time intervals did we send a message?
   * (highest bit corresponds to last time interval; if zero,
   * the record is to be freed).
   */
  unsigned int agedActivitySend;

  /**
   * In which of the last 32 time intervals did we receive a message?
   * (highest bit corresponds to last time interval; if zero,
   * the record is to be freed).
   */
  unsigned int agedActivityRecv;

  /**
   * What were the last times when requests were send to the peer?
   * 0 for no request send *or* last request was repeated.
   */
  GNUNET_CronTime lastRequestTimes[MTRACK_COUNT];

  /**
   * Message ID of the last requests.
   */
  unsigned int lastRequestId[MTRACK_COUNT];

  /**
   * Index to the smallest value in lastRequestTimes.
   */
  unsigned int oldestRTIndex;

} PeerInfo;

/**
 * A set of Peer structures, one for each GNUnet peer (as identified by
 * GNUNET_PeerIdentity) known to the RPC module. Peers are added as either RPC's
 * are made to them from the local node, or an RPC call is received from them.
 */
static struct GNUNET_Vector *peerInformation;

static PeerInfo *
getPeerInfo (const GNUNET_PeerIdentity * id)
{
  PeerInfo *pi;

  pi = (PeerInfo *) GNUNET_vector_get_first (peerInformation);
  while (pi != NULL)
    {
      if (0 == memcmp (id, &pi->identity, sizeof (GNUNET_PeerIdentity)))
        return pi;
      pi = (PeerInfo *) GNUNET_vector_get_next (peerInformation);
    }
  return NULL;
}

/**
 * What is the expected response time for this peer?
 * @return 0 for unknown
 */
static GNUNET_CronTime
getExpectedResponseTime (const GNUNET_PeerIdentity * peer)
{
  GNUNET_CronTime result;
  PeerInfo *pi;

  GNUNET_mutex_lock (rpcLock);
  pi = getPeerInfo (peer);
  if (pi == NULL)
    result = 0;
  else
    result = pi->averageResponseTime;
  GNUNET_mutex_unlock (rpcLock);
  return result;
}

/**
 * Cron-job used to age the peer statistics.
 */
static void
agePeerStats (void *unused)
{
  PeerInfo *pi;

  GNUNET_mutex_lock (rpcLock);
  pi = GNUNET_vector_get_first (peerInformation);
  while (pi != NULL)
    {
      pi->agedActivitySend = pi->agedActivitySend / 2;
      pi->agedActivityRecv = pi->agedActivityRecv / 2;
      if ((pi->agedActivitySend == 0) && (pi->agedActivityRecv == 0))
        {
          GNUNET_vector_delete (peerInformation, pi);
          GNUNET_free (pi);
        }

      pi = GNUNET_vector_get_next (peerInformation);
    }
  GNUNET_mutex_unlock (rpcLock);
}

/**
 * Ensure replies and requests have different IDs when dealing
 * with the same peer.
 */
#define MINGLE(a,b) (((b) == GNUNET_P2P_PROTO_RPC_RES) ? (a) : (a) ^ 0x12345678)

/**
 * Notification: we sent a message to the peer.
 * @param messageID pseudo-unique ID of the request
 */
static void
notifyPeerRequest (GNUNET_PeerIdentity * peer, unsigned int messageID)
{
  int i;
  PeerInfo *pi;

  GNUNET_mutex_lock (rpcLock);
  pi = getPeerInfo (peer);
  if (pi != NULL)
    {
      for (i = 0; i < MTRACK_COUNT; i++)
        {
          if (pi->lastRequestId[i] == messageID)
            {
              pi->lastRequestTimes[i] = 0;      /* re-send! */
              GNUNET_mutex_unlock (rpcLock);
              return;
            }
        }
      pi->agedActivitySend |= 0x80000000;
      pi->lastRequestTimes[pi->oldestRTIndex] = GNUNET_get_time ();
      pi->lastRequestId[pi->oldestRTIndex] = messageID;
      pi->oldestRTIndex = (pi->oldestRTIndex + 1) % MTRACK_COUNT;
      GNUNET_mutex_unlock (rpcLock);
      return;
    }
  pi = GNUNET_malloc (sizeof (PeerInfo));
  memset (pi, 0, sizeof (PeerInfo));
  pi->identity = *peer;
  pi->agedActivitySend = 0x80000000;
  pi->lastRequestTimes[0] = GNUNET_get_time ();
  pi->lastRequestId[0] = messageID;
  pi->oldestRTIndex = 1;
  GNUNET_vector_insert_last (peerInformation, pi);
  GNUNET_mutex_unlock (rpcLock);
}

/**
 * Notification: we received a (valid) response from the peer.
 * @param messageID the ID of the message that a reply was received
 *        for
 */
static void
notifyPeerReply (const GNUNET_PeerIdentity * peer, unsigned int messageID)
{
  int i;
  PeerInfo *pi;

  GNUNET_mutex_lock (rpcLock);
  pi = GNUNET_vector_get_first (peerInformation);
  while (pi != NULL)
    {
      if (0 == memcmp (peer, &pi->identity, sizeof (GNUNET_PeerIdentity)))
        {
          for (i = 0; i < MTRACK_COUNT; i++)
            {
              if (pi->lastRequestId[i] == messageID)
                {
                  if (pi->lastRequestTimes[i] != 0)
                    {           /* resend */
                      pi->averageResponseTime
                        = (pi->averageResponseTime * (MTRACK_COUNT - 1) +
                           GNUNET_get_time () -
                           pi->lastRequestTimes[i]) / MTRACK_COUNT;
                      pi->agedActivityRecv |= 0x80000000;
                      pi->lastRequestTimes[i] = 0;
                    }
                  GNUNET_mutex_unlock (rpcLock);
                  return;
                }
            }
          break;
        }
      pi = GNUNET_vector_get_next (peerInformation);
    }
  GNUNET_mutex_unlock (rpcLock);
}

/* ***************** RPC datastructures ****************** */


/**
 * @brief Request to execute an function call on the remote peer.  The
 * message is of variable size to pass arguments.  Requests and reply
 * messages use the same struct, the only difference is in the value
 * of the header.type field.  For the reply, the
 * functionNameLength indicates the status (0 for GNUNET_OK, otherwise an
 * error code).  argumentCount must be 0 for errors and otherwise
 * indicate the number of return values.
 */
typedef struct
{
  GNUNET_MessageHeader header;
  GNUNET_Int32Time timestamp;
  unsigned int sequenceNumber;
  unsigned int importance;
  unsigned short argumentCount;
  unsigned short functionNameLength;
} P2P_rpc_MESSAGE;


typedef struct
{
  P2P_rpc_MESSAGE rpc_message;
  /**
   * functionNameLength characters describing the function name
   * followed by a serialization of argumentCount arguments.
   */
  char data[1];
} P2P_rpc_MESSAGE_GENERIC;


/**
 * An ACK message.  An ACK acknowledges the receiving a reply to an
 * RPC call (three-way handshake).  Without an ACK, the receiver of an
 * RPC request is supposed to repeatedly send the RPC reply (until it
 * times out).
 */
typedef struct
{
  GNUNET_MessageHeader header;
  /**
   * The number of the original request for which this is the
   * ACK.
   */
  unsigned int sequenceNumber;
} RPC_ACK_Message;

/**
 * GNUNET_RSA_Signature of a function called on completion of
 * the RPC.
 * @param context closure
 * @param sequenceNumber ID of the callback
 * @param errorCode 0 on success
 * @param result the return values, NULL on error
 */
typedef void (*RPCFinishedCallback) (void *context,
                                     unsigned int sequenceNumber,
                                     unsigned short errorCode,
                                     GNUNET_RPC_CallParameters * result);

/**
 * A per-RPC structure.
 */
typedef struct GNUNET_RPC_CallHandle
{
  /**
   * The sequence number of this RPC.
   */
  unsigned int sequenceNumber;

  /**
   * For which peer is this message?
   */
  GNUNET_PeerIdentity receiver;

  /**
   * The message we are transmitting (either the request or the
   * reply).
   */
  P2P_rpc_MESSAGE *msg;

  /**
   * Time where this record times out (timeout value for original
   * request, fixed timeout for reply if no further requests are
   * received; once we send the ACK the record of the sender is
   * discarded; we always send additional ACKs even if we don't have a
   * matching record anymore).
   */
  GNUNET_CronTime expirationTime;

  /**
   * Frequency at which we currently repeat the message.  Initially
   * set to the round-trip estimate, with exponential back-off.
   */
  GNUNET_CronTime repetitionFrequency;

  /**
   * Last time the message was sent.
   */
  GNUNET_CronTime lastAttempt;

  /**
   * Number of times we have attempted to transmit.
   */
  unsigned int attempts;

  /**
   * If this was a request initiated by this node we'll have to pass
   * the result back to the original caller.  This gives the method
   * and some context args that needs to be invoked.
   */
  RPCFinishedCallback finishedCallback;

  /**
   * Arguments to the callback.
   */
  void *rpcCallbackArgs;

   /**
    * How important is this RPC?
    */
  unsigned int importance;
} CallInstance;

/**
 * A set of GNUNET_RPC_CallHandle structures for active incoming rpc calls.
 * (requests without a reply).
 */
static struct GNUNET_Vector *incomingCalls;

/**
 * A set of GNUNET_RPC_CallHandle structures for active outgoing rpc calls.
 * (reply messages without an ACK).
 */
static struct GNUNET_Vector *outgoingCalls;

/**
 * A counter whose value is used for identifying the RPC's originating
 * from the local node. The value of the counter is incremented after each
 * RPC and thus its value also tells the number of RPC's originated from the
 * local node (modulo integer overflow).
 */
static unsigned int rpcIdentifier = 0;

/**
 * Cron-job that processes the RPC queues.  Created for
 * each GNUNET_RPC_CallHandle.  Not renewed if the call times out,
 * deleted if the appropriate response is received.
 */
static void
retryRPCJob (void *ctx)
{
  CallInstance *call = ctx;
  GNUNET_CronTime now;

  now = GNUNET_get_time ();
  GNUNET_GE_ASSERT (ectx,
                    (GNUNET_get_time () + 1 * GNUNET_CRON_MINUTES >
                     call->expirationTime)
                    || (call->expirationTime - GNUNET_get_time () <
                        1 * GNUNET_CRON_HOURS));
  GNUNET_mutex_lock (rpcLock);
  if (now > call->expirationTime)
    {
#if DEBUG_RPC
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Completed RPC %p (timeout).\n", call);
#endif
      if (call->finishedCallback != NULL)
        {
          call->finishedCallback (call->rpcCallbackArgs,
                                  call->sequenceNumber,
                                  GNUNET_RPC_ERROR_TIMEOUT, NULL);
          GNUNET_vector_delete (outgoingCalls, call);
        }
      else
        {
          GNUNET_vector_delete (incomingCalls, call);
        }
      GNUNET_free (call->msg);
      GNUNET_free (call);
    }
  else
    {
      if ((coreAPI != NULL)
          && (call->expirationTime - now > 50 * GNUNET_CRON_MILLISECONDS))
        {
          unsigned int maxdelay;

          if (call->repetitionFrequency == 0)
            {
              call->repetitionFrequency
                = getExpectedResponseTime (&call->receiver) * 2;
              if (call->repetitionFrequency == 0)
                call->repetitionFrequency = INITIAL_RPC_FREQUENCY;
              if (call->repetitionFrequency < MIN_RPC_FREQUENCY)
                call->repetitionFrequency = MIN_RPC_FREQUENCY;
            }
          else
            call->repetitionFrequency = 2 * call->repetitionFrequency;
          maxdelay = (now - call->expirationTime) / 2;
          if (maxdelay > call->repetitionFrequency / 2)
            maxdelay = call->repetitionFrequency / 2;
          notifyPeerRequest (&call->receiver,
                             MINGLE (call->sequenceNumber,
                                     ntohs (call->msg->header.type)));
#if DEBUG_RPC
          if (ntohs (call->msg->header.type) == GNUNET_P2P_PROTO_RPC_REQ)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "Sending RPC request %p: '%.*s' (expires in %llums, last attempt %llums ago; attempt %u).\n",
                             call, ntohs (call->msg->functionNameLength),
                             &((P2P_rpc_MESSAGE_GENERIC *) call->msg)->
                             data[0], call->expirationTime - now,
                             now - call->lastAttempt, call->attempts);
            }
          else
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "Sending RPC reply %p (expires in %llums, last attempt %llums ago, attempt %u).\n",
                             call, call->expirationTime - now,
                             now - call->lastAttempt, call->attempts);
            }
#endif
          call->lastAttempt = now;
          call->attempts++;
          coreAPI->unicast (&call->receiver,
                            &call->msg->header,
                            ntohl (call->msg->importance), maxdelay);
        }
      GNUNET_GE_ASSERT (ectx,
                        (GNUNET_get_time () + 1 * GNUNET_CRON_MINUTES >
                         call->expirationTime)
                        || (call->expirationTime - GNUNET_get_time () <
                            1 * GNUNET_CRON_HOURS));
      GNUNET_cron_add_job (coreAPI->cron, &retryRPCJob,
                           call->repetitionFrequency, 0, call);
    }
  GNUNET_mutex_unlock (rpcLock);
}

/**
 * Send an ACK message.
 */
static void
sendAck (const GNUNET_PeerIdentity * receiver,
         unsigned int sequenceNumber,
         unsigned int importance, unsigned int maxDelay)
{
  RPC_ACK_Message msg;

  msg.header.size = htons (sizeof (RPC_ACK_Message));
  msg.header.type = htons (GNUNET_P2P_PROTO_RPC_ACK);
  msg.sequenceNumber = htonl (sequenceNumber);
  coreAPI->unicast (receiver, &msg.header, importance, maxDelay);
}

static char *
getFunctionName (P2P_rpc_MESSAGE * req)
{
  char *ret;
  unsigned short slen;

  slen = ntohs (req->functionNameLength);
  if (ntohs (req->header.size) < sizeof (P2P_rpc_MESSAGE) + slen)
    return NULL;                /* invalid! */
  ret = GNUNET_malloc (slen + 1);
  memcpy (ret, &((P2P_rpc_MESSAGE_GENERIC *) req)->data[0], slen);
  ret[slen] = '\0';
  return ret;
}

static GNUNET_RPC_CallParameters *
deserializeArguments (P2P_rpc_MESSAGE * req)
{
  unsigned short slen;
  GNUNET_RPC_CallParameters *ret;

  if (ntohs (req->header.type) == GNUNET_P2P_PROTO_RPC_REQ)
    slen = ntohs (req->functionNameLength);
  else
    slen = 0;
  if (ntohs (req->header.size) < sizeof (P2P_rpc_MESSAGE) + slen)
    return NULL;                /* invalid! */
  ret =
    GNUNET_RPC_parameters_deserialize (&
                                       ((P2P_rpc_MESSAGE_GENERIC *)
                                        req)->data[slen],
                                       ntohs (req->header.size) -
                                       sizeof (P2P_rpc_MESSAGE) - slen);
  if (GNUNET_RPC_parameters_count (ret) != ntohs (req->argumentCount))
    {
      GNUNET_RPC_parameters_destroy (ret);
      return NULL;              /* invalid! */
    }
  return ret;
}

/**
 * Build an RPC message serializing the name and values
 * properly.
 * @param errorCode the status code for the message, if non-NULL
 *   values will be NULL
 * @param name the name of the target method, NULL for a reply.
 * @param sequenceNumber the unique ID of the message
 * @param values the arguments or return values, maybe NULL
 * @return the RPC message to transmit, caller must free
 */
static P2P_rpc_MESSAGE *
buildMessage (unsigned short errorCode,
              const char *name,
              unsigned int sequenceNumber,
              unsigned int importance, GNUNET_RPC_CallParameters * values)
{
  P2P_rpc_MESSAGE *ret;
  size_t size = sizeof (P2P_rpc_MESSAGE);
  int slen;

  if (name != NULL)
    {
      slen = strlen (name);
      size += slen;
    }
  else
    slen = 0;
  if (values != NULL)
    size += GNUNET_RPC_parameters_get_serialized_size (values);
  if (size >= GNUNET_MAX_BUFFER_SIZE)
    return NULL;                /* message to big! */
  ret = GNUNET_malloc (size);
  ret->header.size = htons (size);
  ret->timestamp = htonl (GNUNET_get_time_int32 (NULL));
  ret->sequenceNumber = htonl (sequenceNumber);
  ret->importance = htonl (importance);
  if (name == NULL)
    ret->functionNameLength = htons (errorCode);
  else
    ret->functionNameLength = htons (slen);
  ret->argumentCount = htons (GNUNET_RPC_parameters_count (values));
  if (name != NULL)
    {
      memcpy (&((P2P_rpc_MESSAGE_GENERIC *) ret)->data[0], name, slen);
    }
  GNUNET_RPC_parameters_serialize (values,
                                   &((P2P_rpc_MESSAGE_GENERIC *) ret)->
                                   data[slen]);

  if (name == NULL)
    ret->header.type = htons (GNUNET_P2P_PROTO_RPC_RES);
  else
    ret->header.type = htons (GNUNET_P2P_PROTO_RPC_REQ);

  return ret;
}


/* ***************** RPC P2P message handlers **************** */


/**
 * GNUNET_RSA_Signature of the callback function for the ASYNC_RPC to
 * be called upon completion of the ASYNC function.  Initiates
 * sending back the reply.  Also called in the synchronous RPC
 * case o complete the reply (since it's the same code).
 */
static void
async_rpc_complete_callback (GNUNET_RPC_CallParameters * results,
                             int errorCode, CallInstance * calls)
{
  GNUNET_mutex_lock (rpcLock);
  /* build reply message */
  calls->msg = buildMessage (errorCode,
                             NULL,
                             calls->sequenceNumber,
                             calls->importance, results);
  if (calls->msg == NULL)
    calls->msg = buildMessage (GNUNET_RPC_ERROR_RETURN_VALUE_TOO_LARGE,
                               NULL,
                               calls->sequenceNumber,
                               calls->importance, results);
  GNUNET_vector_insert_last (incomingCalls, calls);

  GNUNET_GE_ASSERT (ectx,
                    (GNUNET_get_time () + 1 * GNUNET_CRON_MINUTES >
                     calls->expirationTime)
                    || (calls->expirationTime - GNUNET_get_time () <
                        1 * GNUNET_CRON_HOURS));
  /* for right now: schedule cron job to send reply! */
  GNUNET_cron_add_job (coreAPI->cron, &retryRPCJob, 0, 0, calls);
  GNUNET_mutex_unlock (rpcLock);
}


/**
 * Handle request for remote function call.  Checks if message
 * has been seen before, if not performs the call and sends
 * reply.
 */
static int
handleRPCMessageReq (const GNUNET_PeerIdentity * sender,
                     const GNUNET_MessageHeader * message)
{
  P2P_rpc_MESSAGE *req;
  CallInstance *calls;
  unsigned int sq;
  unsigned short errorCode;
  char *functionName;
  GNUNET_RPC_CallParameters *argumentValues;
  GNUNET_RPC_CallParameters *returnValues;
  RegisteredRPC *rpc;
  unsigned int minSQ;

  if ((ntohs (message->type) != GNUNET_P2P_PROTO_RPC_REQ) ||
      (ntohs (message->size) < sizeof (P2P_rpc_MESSAGE)))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_REQUEST | GNUNET_GE_ADMIN,
                     _("Invalid message of type %u received.  Dropping.\n"),
                     ntohs (message->type));
      return GNUNET_SYSERR;
    }
  req = (P2P_rpc_MESSAGE *) message;
  sq = ntohl (req->sequenceNumber);
#if DEBUG_RPC
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received RPC request with id %u.\n", sq);
#endif
  GNUNET_mutex_lock (rpcLock);

  /* check if message is already in incomingCalls,
     if so, update expiration, otherwise deserialize,
     perform call, add reply and create cron job */

  calls = GNUNET_vector_get_first (incomingCalls);
  if (calls == NULL)
    minSQ = 0;
  else
    minSQ = 0xFFFFFFFF;
  while (calls != NULL)
    {
      if (calls->sequenceNumber < minSQ)
        minSQ = calls->sequenceNumber;
      if ((calls->sequenceNumber == sq) &&
          (0 ==
           memcmp (&calls->receiver, sender, sizeof (GNUNET_PeerIdentity))))
        break;
      calls = GNUNET_vector_get_next (incomingCalls);
    }
  if (calls != NULL)
    {
      PeerInfo *pi = getPeerInfo (sender);

      if (pi != NULL)
        {
          if (pi->averageResponseTime < MAX_RPC_TIMEOUT / 2)
            pi->averageResponseTime *= 2;
        }
      RPC_STATUS ("", "received duplicate request", calls);
      calls->expirationTime = GNUNET_get_time () + MAX_RPC_TIMEOUT;
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Dropping RPC request %u, duplicate.\n", sq);
      GNUNET_mutex_unlock (rpcLock);
      return GNUNET_OK;         /* seen before */
    }
  if (minSQ > sq)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Dropping RPC request %u, sequence number too old (current minimum is %u).\n",
                     sq, minSQ);
      GNUNET_mutex_unlock (rpcLock);
      return GNUNET_OK;         /* seen before */
    }

  /* deserialize */
  functionName = getFunctionName (req);
  argumentValues = deserializeArguments (req);
  if ((functionName == NULL) || (argumentValues == NULL))
    {
      GNUNET_free_non_null (functionName);
      if (argumentValues != NULL)
        GNUNET_RPC_parameters_destroy (argumentValues);
      GNUNET_mutex_unlock (rpcLock);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Dropping RPC request %u: message malformed.\n"));
      return GNUNET_SYSERR;     /* message malformed */
    }

  /* find matching RPC function */
  rpc = (RegisteredRPC *) GNUNET_vector_get_first (list_of_callbacks);
  while (rpc != NULL)
    {
      if (0 == strcmp (functionName, rpc->name))
        break;
      rpc = (RegisteredRPC *) GNUNET_vector_get_next (list_of_callbacks);
    }
  calls = GNUNET_malloc (sizeof (CallInstance));
  RPC_STATUS (functionName, "received request", calls);
  GNUNET_free (functionName);
  calls->sequenceNumber = sq;
  calls->receiver = *sender;
  calls->expirationTime = GNUNET_get_time () + MAX_RPC_TIMEOUT;
  calls->lastAttempt = 0;
  calls->attempts = 0;
  calls->finishedCallback = NULL;
  calls->rpcCallbackArgs = NULL;
  calls->importance = ntohl (req->importance);

  /* if possible, perform RPC call */
  if (rpc == NULL)
    {
      GNUNET_RPC_parameters_destroy (argumentValues);
      returnValues = NULL;
      errorCode = GNUNET_RPC_ERROR_UNKNOWN_FUNCTION;
    }
  else
    {
      if (rpc->callback == NULL)
        {
          /* asynchronous RPC */
          rpc->async_callback (sender,
                               argumentValues,
                               &async_rpc_complete_callback, calls);
          GNUNET_mutex_unlock (rpcLock);
          return GNUNET_OK;
        }
      returnValues = GNUNET_RPC_parameters_create ();
      rpc->callback (sender, argumentValues, returnValues);
      GNUNET_RPC_parameters_destroy (argumentValues);
      errorCode = GNUNET_RPC_ERROR_OK;
    }
  GNUNET_mutex_unlock (rpcLock);
  async_rpc_complete_callback (returnValues, errorCode, calls);
  return GNUNET_OK;
}

/**
 * Handle reply for request for remote function call.  Checks
 * if we are waiting for a reply, if so triggers the reply.
 * Also always sends an ACK.
 */
static int
handleRPCMessageRes (const GNUNET_PeerIdentity * sender,
                     const GNUNET_MessageHeader * message)
{
  P2P_rpc_MESSAGE *res;
  CallInstance *call;

  if ((ntohs (message->type) != GNUNET_P2P_PROTO_RPC_RES) ||
      (ntohs (message->size) < sizeof (P2P_rpc_MESSAGE)))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Invalid message of type %u received.  Dropping.\n"),
                     ntohs (message->type));
      return GNUNET_SYSERR;
    }
  res = (P2P_rpc_MESSAGE *) message;
#if DEBUG_RPC
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received RPC reply with id %u.\n",
                 ntohl (res->sequenceNumber));
#endif

  GNUNET_cron_suspend_jobs (coreAPI->cron, GNUNET_NO);
  GNUNET_mutex_lock (rpcLock);

  /* Locate the GNUNET_RPC_CallHandle structure. */
  call = GNUNET_vector_get_first (outgoingCalls);
  while (call != NULL)
    {
      if ((0 == memcmp (&call->receiver,
                        sender,
                        sizeof (GNUNET_PeerIdentity))) &&
          (call->sequenceNumber == ntohl (res->sequenceNumber)))
        break;
      call = GNUNET_vector_get_next (outgoingCalls);
    }
  if (NULL != call)
    {
      GNUNET_RPC_CallParameters *reply;
      P2P_rpc_MESSAGE_GENERIC *gen;
      unsigned short error;

      RPC_STATUS ("", "received reply", call);
      gen = (P2P_rpc_MESSAGE_GENERIC *) res;
      reply = NULL;
      error = ntohs (res->functionNameLength);

      if (error == GNUNET_RPC_ERROR_OK)
        {
          reply = GNUNET_RPC_parameters_deserialize (&gen->data[0],
                                                     ntohs (message->size) -
                                                     sizeof
                                                     (P2P_rpc_MESSAGE));
          if (ntohs (res->argumentCount) !=
              GNUNET_RPC_parameters_count (reply))
            {
              GNUNET_RPC_parameters_destroy (reply);
              reply = NULL;
              error = GNUNET_RPC_ERROR_REPLY_MALFORMED;
            }
        }
      if (call->finishedCallback != NULL)
        {
          call->finishedCallback (call->rpcCallbackArgs,
                                  call->sequenceNumber, error, reply);
          call->finishedCallback = NULL;
        }
      GNUNET_vector_delete (outgoingCalls, call);
      notifyPeerReply (sender,
                       MINGLE (call->sequenceNumber,
                               GNUNET_P2P_PROTO_RPC_REQ));
      GNUNET_cron_del_job (coreAPI->cron, &retryRPCJob, 0, call);
      GNUNET_free (call->msg);
      GNUNET_free (call);
      if (reply != NULL)
        GNUNET_RPC_parameters_destroy (reply);
    }
  sendAck (sender, ntohl (res->sequenceNumber), 0,      /* not important, ACK should be tiny enough to go through anyway */
           0 /* right away */ );
  GNUNET_mutex_unlock (rpcLock);
  GNUNET_cron_resume_jobs (coreAPI->cron, GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Handle a peer-to-peer message of type GNUNET_P2P_PROTO_RPC_ACK.
 */
static int
handleRPCMessageAck (const GNUNET_PeerIdentity * sender,
                     const GNUNET_MessageHeader * message)
{
  RPC_ACK_Message *ack;
  CallInstance *call;

  if ((ntohs (message->type) != GNUNET_P2P_PROTO_RPC_ACK) ||
      (ntohs (message->size) != sizeof (RPC_ACK_Message)))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_REQUEST | GNUNET_GE_ADMIN,
                     _("Invalid message of type %u received.  Dropping.\n"),
                     ntohs (message->type));
      return GNUNET_SYSERR;
    }

  ack = (RPC_ACK_Message *) message;
#if DEBUG_RPC
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received RPC ACK with id %u.\n",
                 ntohl (ack->sequenceNumber));
#endif
  GNUNET_cron_suspend_jobs (coreAPI->cron, GNUNET_NO);
  GNUNET_mutex_lock (rpcLock);

  /* Locate the GNUNET_RPC_CallHandle structure. */
  call = (CallInstance *) GNUNET_vector_get_first (incomingCalls);
  while (call != NULL)
    {
      if ((0 == memcmp (&call->receiver,
                        sender,
                        sizeof (GNUNET_PeerIdentity))) &&
          (call->sequenceNumber == ntohl (ack->sequenceNumber)))
        break;
      call = (CallInstance *) GNUNET_vector_get_next (incomingCalls);
    }

  /* check if we're waiting for an ACK, if so remove job */
  if (NULL != call)
    {
      RPC_STATUS ("", "acknowledged reply", call);
      notifyPeerReply (sender,
                       MINGLE (ntohl (ack->sequenceNumber),
                               GNUNET_P2P_PROTO_RPC_RES));
      GNUNET_cron_del_job (coreAPI->cron, &retryRPCJob, 0, call);
      GNUNET_vector_delete (incomingCalls, call);
      GNUNET_free (call->msg);
      GNUNET_free (call);
    }
  else
    {
      PeerInfo *pi = getPeerInfo (sender);
      if (pi != NULL)
        {
          if (pi->averageResponseTime < MAX_RPC_TIMEOUT / 2)
            pi->averageResponseTime *= 2;
        }
#if DEBUG_RPC
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "ACK is a duplicate (or invalid).\n");
#endif
    }

  GNUNET_mutex_unlock (rpcLock);
  GNUNET_cron_resume_jobs (coreAPI->cron, GNUNET_NO);
  return GNUNET_OK;
}

/* ********************* RPC service functions ******************** */

typedef struct
{
  struct GNUNET_Semaphore *sem;
  GNUNET_RPC_CallParameters *result;
  unsigned short ec;
} RPC_EXEC_CLS;

/**
 * Callback function invoked whenever the RPC is complete
 * (timeout, error or success).
 */
static void
RPC_execute_callback (RPC_EXEC_CLS * context,
                      unsigned int sq, unsigned short ec,
                      GNUNET_RPC_CallParameters * res)
{
  int i;
  unsigned int dl;
  void *data;

  for (i = GNUNET_RPC_parameters_count (res) - 1; i >= 0; i--)
    {
      data = NULL;
      GNUNET_RPC_parameters_get_value_by_index (res, i, &dl, &data);
      GNUNET_RPC_parameters_add (context->result,
                                 GNUNET_RPC_parameters_get_name (res, i), dl,
                                 data);
    }
  context->ec = ec;
  GNUNET_semaphore_up (context->sem);
}

/**
 * Executes a blocking RPC on a node, which may be the local node. The
 * function performs the following steps:
 *
 * - Constructs a request packet from the request parameters
 * - Waits on a signaling semaphore until the result is ready or timeout
 * - passes the results back to the caller
 *
 * @return the error code of the operation (0 for success).
 */
static int
RPC_execute (const GNUNET_PeerIdentity * receiver,
             const char *name,
             GNUNET_RPC_CallParameters * requestParam,
             GNUNET_RPC_CallParameters * returnParam, unsigned int importance,
             GNUNET_CronTime timeout)
{
  RPC_EXEC_CLS cls;
  CallInstance *call;

  GNUNET_mutex_lock (rpcLock);
  cls.sem = GNUNET_semaphore_create (0);
  cls.result = returnParam;
  call = GNUNET_malloc (sizeof (CallInstance));
  RPC_STATUS (name, "started synchronously", call);
  call->lastAttempt = 0;
  call->attempts = 0;
  call->repetitionFrequency = getExpectedResponseTime (receiver);
  call->expirationTime = GNUNET_get_time () + timeout;
  call->receiver = *receiver;
  call->sequenceNumber = rpcIdentifier++;
  call->msg = buildMessage (GNUNET_RPC_ERROR_OK,
                            name,
                            call->sequenceNumber, importance, requestParam);
  call->finishedCallback = (RPCFinishedCallback) & RPC_execute_callback;
  call->rpcCallbackArgs = &cls;
  GNUNET_vector_insert_last (outgoingCalls, call);
  GNUNET_GE_ASSERT (ectx,
                    (GNUNET_get_time () + 1 * GNUNET_CRON_MINUTES >
                     call->expirationTime)
                    || (call->expirationTime - GNUNET_get_time () <
                        1 * GNUNET_CRON_HOURS));
  GNUNET_cron_add_job (coreAPI->cron, &retryRPCJob, 0, 0, call);
  GNUNET_mutex_unlock (rpcLock);
  GNUNET_semaphore_down (cls.sem, GNUNET_YES);
  GNUNET_semaphore_destroy (cls.sem);
  RPC_STATUS (name, "completed synchronously", call);
  return cls.ec;
}

typedef struct GNUNET_RPC_RequestHandle
{
  GNUNET_PeerIdentity peer;
  CallInstance *call;
  GNUNET_RPC_AsynchronousCompletionCallback callback;
  void *closure;
  unsigned short errorCode;
} RPC_Record;

static void
RPC_async_callback (RPC_Record * rec,
                    unsigned int sequenceNumber,
                    unsigned short errorCode,
                    GNUNET_RPC_CallParameters * result)
{
  if ((errorCode == GNUNET_RPC_ERROR_OK) && (rec->callback != NULL))
    {
      rec->callback (&rec->peer, result, rec->closure);
      rec->callback = NULL;     /* never call callback twice */
    }
  rec->errorCode = errorCode;
}

/**
 * Start an asynchronous RPC.
 *
 * @param timeout when should we stop trying the RPC
 * @param callback function to call with the return value from
 *        the RPC
 * @param closure extra argument to callback
 * @return value required to stop the RPC (and the RPC must
 *  be explicitly stopped to free resources!)
 */
static RPC_Record *
RPC_start (const GNUNET_PeerIdentity * receiver,
           const char *name,
           GNUNET_RPC_CallParameters * request_param,
           unsigned int importance,
           GNUNET_CronTime timeout,
           GNUNET_RPC_AsynchronousCompletionCallback callback, void *closure)
{
  RPC_Record *ret;

  if (timeout > 1 * GNUNET_CRON_HOURS)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("`%s' called with timeout above 1 hour (bug?)\n"),
                     __FUNCTION__);
      timeout = 1 * GNUNET_CRON_HOURS;
    }
  ret = GNUNET_malloc (sizeof (RPC_Record));
  RPC_STATUS (name, "started asynchronously", ret);
  ret->peer = *receiver;
  ret->callback = callback;
  ret->closure = closure;
  ret->errorCode = GNUNET_RPC_ERROR_TIMEOUT;
  GNUNET_mutex_lock (rpcLock);
  ret->call = GNUNET_malloc (sizeof (CallInstance));
  ret->call->lastAttempt = 0;
  ret->call->attempts = 0;
  ret->call->repetitionFrequency = getExpectedResponseTime (receiver);
  ret->call->expirationTime = GNUNET_get_time () + timeout;
  ret->call->receiver = *receiver;
  ret->call->sequenceNumber = rpcIdentifier++;
  ret->call->msg = buildMessage (GNUNET_RPC_ERROR_OK,
                                 name,
                                 ret->call->sequenceNumber,
                                 importance, request_param);
  ret->call->finishedCallback = (RPCFinishedCallback) & RPC_async_callback;
  ret->call->rpcCallbackArgs = ret;
  GNUNET_vector_insert_last (outgoingCalls, ret->call);
  GNUNET_GE_ASSERT (ectx,
                    (GNUNET_get_time () + 1 * GNUNET_CRON_MINUTES >
                     ret->call->expirationTime)
                    || (ret->call->expirationTime - GNUNET_get_time () <
                        1 * GNUNET_CRON_HOURS));
  GNUNET_cron_add_job (coreAPI->cron, &retryRPCJob, 0, 0, ret->call);
  GNUNET_mutex_unlock (rpcLock);
  return ret;
}

/**
 * Stop an asynchronous RPC (and free associated resources)
 *
 * @param record the return value from RPC_start
 * @return GNUNET_RPC_ERROR_OK if the RPC was successful,
 *  another RPC_ERROR code if it was aborted
 */
static int
RPC_stop (RPC_Record * record)
{
  int ret;

  RPC_STATUS ("", "stopped", record);
  GNUNET_cron_suspend_jobs (coreAPI->cron, GNUNET_YES);
  GNUNET_cron_del_job (coreAPI->cron, &retryRPCJob, 0, record->call);
  GNUNET_cron_resume_jobs (coreAPI->cron, GNUNET_YES);
  GNUNET_mutex_lock (rpcLock);
  if (NULL != GNUNET_vector_delete (outgoingCalls, record->call))
    {
      GNUNET_free (record->call->msg);
      GNUNET_free (record->call);
    }
  GNUNET_mutex_unlock (rpcLock);
  ret = record->errorCode;
  GNUNET_free (record);

  return ret;
}

/* ******************* Exported functions ******************* */

/**
 * Shutdown RPC service.
 */
void
release_module_rpc ()
{
  CallInstance *call;

  GNUNET_cron_del_job (coreAPI->cron,
                       &agePeerStats, PEER_TRACKING_TIME_INTERVAL, NULL);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_RPC_REQ, &handleRPCMessageReq);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_RPC_RES, &handleRPCMessageRes);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_RPC_ACK, &handleRPCMessageAck);
  if (NULL != peerInformation)
    {
      while (GNUNET_vector_get_size (peerInformation) > 0)
        GNUNET_free (GNUNET_vector_delete_last (peerInformation));
      GNUNET_vector_destroy (peerInformation);
      peerInformation = NULL;
    }
  if (NULL != incomingCalls)
    {
      while (GNUNET_vector_get_size (incomingCalls) > 0)
        {
          call = (CallInstance *) GNUNET_vector_delete_last (incomingCalls);
          GNUNET_cron_del_job (coreAPI->cron, &retryRPCJob, 0, call);
          GNUNET_free (call->msg);
          GNUNET_free (call);
        }
      GNUNET_vector_destroy (incomingCalls);
      incomingCalls = NULL;
    }
  if (NULL != outgoingCalls)
    {
      while (GNUNET_vector_get_size (outgoingCalls) > 0)
        {
          call = (CallInstance *) GNUNET_vector_delete_last (outgoingCalls);
          GNUNET_cron_del_job (coreAPI->cron, &retryRPCJob, 0, call);
          GNUNET_free (call->msg);
          GNUNET_free (call);
        }
      GNUNET_vector_destroy (outgoingCalls);
      outgoingCalls = NULL;
    }
  if (NULL != list_of_callbacks)
    {
      while (GNUNET_vector_get_size (list_of_callbacks) > 0)
        {
          RegisteredRPC *rpc;
          rpc =
            (RegisteredRPC *) GNUNET_vector_delete_last (list_of_callbacks);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("RPC not unregistered: %s:%p\n"), rpc->name,
                         rpc->callback);
          GNUNET_free (rpc->name);
          GNUNET_free (rpc);
        }
      GNUNET_vector_destroy (list_of_callbacks);
      list_of_callbacks = NULL;
    }
  coreAPI = NULL;
  rpcLock = NULL;
}

/**
 * Initialize the RPC service.
 */
GNUNET_RPC_ServiceAPI *
provide_module_rpc (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_RPC_ServiceAPI rpcAPI;
  int rvalue;

  ectx = capi->ectx;
  rpcLock = capi->connection_get_lock ();
  coreAPI = capi;
  peerInformation = GNUNET_vector_create (16);
  incomingCalls = GNUNET_vector_create (16);
  outgoingCalls = GNUNET_vector_create (16);
  list_of_callbacks = GNUNET_vector_create (16);
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering handlers %d %d %d\n"),
                 "rpc", GNUNET_P2P_PROTO_RPC_REQ, GNUNET_P2P_PROTO_RPC_RES,
                 GNUNET_P2P_PROTO_RPC_ACK);
  rvalue = GNUNET_OK;
  if (capi->registerHandler (GNUNET_P2P_PROTO_RPC_REQ,
                             &handleRPCMessageReq) == GNUNET_SYSERR)
    rvalue = GNUNET_SYSERR;
  if (capi->registerHandler (GNUNET_P2P_PROTO_RPC_RES,
                             &handleRPCMessageRes) == GNUNET_SYSERR)
    rvalue = GNUNET_SYSERR;
  if (capi->registerHandler (GNUNET_P2P_PROTO_RPC_ACK,
                             &handleRPCMessageAck) == GNUNET_SYSERR)
    rvalue = GNUNET_SYSERR;
  if (rvalue == GNUNET_SYSERR)
    {
      release_module_rpc ();
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Failed to initialize `%s' service.\n"), "rpc");
      return NULL;
    }
  else
    {
      rpcAPI.RPC_execute = &RPC_execute;
      rpcAPI.RPC_register = &RPC_register;
      rpcAPI.RPC_unregister = &RPC_unregister;
      rpcAPI.RPC_register_async = &RPC_register_async;
      rpcAPI.RPC_unregister_async = &RPC_unregister_async;
      rpcAPI.RPC_start = &RPC_start;
      rpcAPI.RPC_stop = &RPC_stop;
      GNUNET_cron_add_job (coreAPI->cron,
                           &agePeerStats,
                           PEER_TRACKING_TIME_INTERVAL,
                           PEER_TRACKING_TIME_INTERVAL, NULL);
      return &rpcAPI;
    }
}

#if PROVIDE_RPC_TEST

static void
testCallback (const GNUNET_PeerIdentity * sender,
              GNUNET_RPC_CallParameters * arguments,
              GNUNET_RPC_CallParameters * results)
{
  unsigned int dl;
  char *data;

  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "RPC callback invoked!\n");
  if ((GNUNET_OK ==
       GNUNET_RPC_parameters_get_value_by_name (arguments, "command", &dl,
                                                (void **) &data))
      && (strncmp ("Hello", data, dl) == 0))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "RPC callback received Hello command!\n");
      GNUNET_RPC_parameters_add (results, "response",
                                 strlen ("Hello RPC World") + 1,
                                 "Hello RPC World");
    }
}

static void
async_RPC_Complete_callback (GNUNET_RPC_CallParameters * results,
                             struct GNUNET_Semaphore *GNUNET_RSA_sign)
{
  unsigned int dl;
  char *reply;

  GNUNET_semaphore_down (GNUNET_RSA_sign, GNUNET_YES);
  if ((GNUNET_OK != GNUNET_RPC_parameters_get_value_by_name (results,
                                                             "response",
                                                             &dl,
                                                             (void **)
                                                             &reply))
      || (strncmp ("Hello RPC World", reply, dl) != 0))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("RPC async reply invalid.\n"));
    }
  else
    GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                   "RPC async reply received.\n");
}

int
initialize_module_rpc (GNUNET_CoreAPIForPlugins * capi)
{
  GNUNET_RPC_ServiceAPI *rpcAPI;
  int ret;
  GNUNET_RPC_CallParameters *args;
  GNUNET_RPC_CallParameters *rets;
  unsigned int dl;
  char *reply;
  int code;
  struct GNUNET_RPC_RequestHandle *record;
  struct GNUNET_Semaphore *GNUNET_RSA_sign;

  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "RPC testcase starting\n");
  rpcAPI = capi->request_service ("rpc");
  if (rpcAPI == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  ret = GNUNET_OK;

  if (GNUNET_OK != rpcAPI->RPC_register ("testFunction", &testCallback))
    {
      GNUNET_GE_BREAK (ectx, 0);
      ret = GNUNET_SYSERR;
    }

  args = GNUNET_RPC_parameters_create ();
  GNUNET_RPC_parameters_add (args, "command", strlen ("Hello") + 1, "Hello");
  GNUNET_RSA_sign = GNUNET_semaphore_create (0);
  record = rpcAPI->RPC_start (coreAPI->myIdentity,
                              "testFunction",
                              args,
                              0,
                              5 * GNUNET_CRON_SECONDS,
                              (GNUNET_RPC_AsynchronousCompletionCallback) &
                              async_RPC_Complete_callback, GNUNET_RSA_sign);
  GNUNET_semaphore_up (GNUNET_RSA_sign);        /* allow callback now - forces async! */
  rets = GNUNET_RPC_parameters_create ();
  code = rpcAPI->RPC_execute (coreAPI->myIdentity,
                              "testFunction", args, rets, 0,
                              5 * GNUNET_CRON_SECONDS);
  if (code != GNUNET_RPC_ERROR_OK)
    {
      GNUNET_GE_BREAK (ectx, 0);
      ret = GNUNET_SYSERR;
    }
  GNUNET_RPC_parameters_destroy (args);
  if ((GNUNET_OK != GNUNET_RPC_parameters_get_value_by_name (rets,
                                                             "response",
                                                             &dl,
                                                             (void **)
                                                             &reply))
      || (strncmp ("Hello RPC World", reply, dl) != 0))
    {
      GNUNET_GE_BREAK (ectx, 0);
      ret = GNUNET_SYSERR;
    }
  GNUNET_RPC_parameters_destroy (rets);
  GNUNET_thread_sleep (1 * GNUNET_CRON_SECONDS);
  if (GNUNET_RPC_ERROR_OK != rpcAPI->RPC_stop (record))
    GNUNET_GE_LOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                   _("async RPC reply not received.\n"));

  if (GNUNET_OK != rpcAPI->RPC_unregister ("testFunction", &testCallback))
    {
      GNUNET_GE_BREAK (ectx, 0);
      ret = GNUNET_SYSERR;
    }
  if (GNUNET_OK != capi->release_service (rpcAPI))
    {
      GNUNET_GE_BREAK (ectx, 0);
      ret = GNUNET_SYSERR;
    }
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "RPC testcase completed with status %s\n",
                 ret == GNUNET_OK ? "SUCCESS" : "FAILURE");
  return ret;
}

/**
 * Does nothing (but must be present for clean unload of the
 * testcase!).
 */
int
done_module_rpc ()
{
  return GNUNET_OK;
}

#endif

/* end of rpc.c */
