/*
      This file is part of GNUnet
      (C) 2003, 2005, 2008 Christian Grothoff (and other contributing authors)

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
 * @file rpc/module/rpc.c
 * @brief Implementation of RPCs
 * @author Antti Salonen, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_rpc_service.h"
#include "gnunet_rpc_lib.h"

/**
 * Maximum number of concurrent RPCs that we support per peer.
 */
#define RPC_MAX_REQUESTS_PER_PEER 16

/**
 * Maximum number of retries done for sending of responses.
 */
#define RPC_MAX_REPLY_ATTEMPTS 3

/**
 * Granularity for the RPC cron job.
 */
#define RPC_CRON_FREQUENCY (500 * GNUNET_CRON_MILLISECONDS)

/**
 * Initial minimum delay between retry attempts for RPC messages
 * (before we figure out how fast the connection really is).
 */
#define RPC_INITIAL_ROUND_TRIP_TIME (15 * GNUNET_CRON_SECONDS)

/**
 * After what time do we time-out every request (if it is not
 * repeated)?
 */
#define RPC_INTERNAL_PROCESSING_TIMEOUT (2 * GNUNET_CRON_MINUTES)


/**
 * @brief Request to execute an function call on the remote peer.  The
 * message is of variable size to pass arguments.  Requests and reply
 * messages use the same struct, the only difference is in the value
 * of the header.type field.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Timestamp (of the sender of this message).
   */
  GNUNET_Int32Time timestamp;

  /**
   * Sequence number (of the initiator).
   */
  unsigned int sequenceNumber;

  /**
   * How important is this message?
   */
  unsigned int importance;

  /**
   * Number of arguments or return values.  Must be 0
   * if this message communicates an error.
   */
  unsigned int argumentCount;

  /**
   * For the request, this is the length of the
   * name of the function.  For a response,
   * this is the status.
   */
  unsigned int functionNameLength;
} P2P_rpc_MESSAGE;

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
 * These structures are allocated while a peer
 * is handling an RPC request.
 */
struct GNUNET_RPC_CallHandle
{
  struct GNUNET_RPC_CallHandle *next;

  struct GNUNET_RPC_CallHandle *prev;

  /**
   * The message we are transmitting.  NULL
   * if our local RPC invocation has not
   * yet completed.  NON-NULL if we are
   * waiting for the ACK.
   */
  P2P_rpc_MESSAGE *msg;

  /**
   * Name of the local RPC function that we
   * have been calling.
   */
  char *function_name;

  /**
   * For which peer is this response?
   */
  GNUNET_PeerIdentity initiator;

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
   * Error code for the response.
   */
  unsigned int errorCode;

  /**
   * The sequence number of this RPC.
   */
  unsigned int sequenceNumber;

   /**
    * How important is this RPC?
    */
  unsigned int importance;
};

/**
 * These structures are allocated while a peer
 * is waiting for a remote RPC to return a result.
 */
struct GNUNET_RPC_RequestHandle
{
  struct GNUNET_RPC_RequestHandle *next;

  struct GNUNET_RPC_RequestHandle *prev;

  /**
   * The message we are transmitting.
   */
  P2P_rpc_MESSAGE *msg;

  /**
   * Function to call once we get a reply.
   */
  GNUNET_RPC_AsynchronousCompletionCallback callback;

  void *cls;

  /**
   * To which peer are we sending the request?
   */
  GNUNET_PeerIdentity receiver;

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
   * The sequence number of this RPC.
   */
  unsigned int sequenceNumber;

   /**
   * Number of times we have attempted to transmit.
   */
  unsigned int attempts;

   /**
    * How important is this RPC?
    */
  unsigned int importance;

  /**
   * Error code for the response.
   */
  unsigned int errorCode;
};

/**
 * List of RPC handlers registered by the local node.
 */
struct RegisteredRPC
{
  struct RegisteredRPC *next;

  /**
   * Name of the RPC.
   */
  char *name;

  /**
   * Callback for an asynchronous RPC.
   */
  GNUNET_RPC_AsynchronousFunction async_callback;

  /**
   * Extra argument to async_callback.
   */
  void *cls;
};

/**
 * A set of RegisteredRPC structures, one for each RPC registered by the
 * local node.
 */
static struct RegisteredRPC *list_of_callbacks;

/**
 * A set of GNUNET_RPC_CallHandle structures for active incoming rpc calls.
 * (requests without a reply).
 */
static struct GNUNET_RPC_CallHandle *incomingCalls;

/**
 * Linked list active outgoing rpc calls.
 * (waiting for function and reply messages without an ACK).
 */
static struct GNUNET_RPC_RequestHandle *outgoingCalls;

/**
 * A counter whose value is used for identifying the RPC's originating
 * from the local node. The value of the counter is incremented after each
 * RPC and thus its value also tells the number of RPC's originated from the
 * local node (modulo integer overflow).
 */
static unsigned int rpcIdentifier;

/**
 * Access to GNUnet core API.
 */
static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * A mutex for synchronous access to all module-wide data structures. This
 * lock must be held by the thread that accesses any module-wide accessable
 * data structures.
 */
static struct GNUNET_Mutex *lock;

/**
 * Registers an async RPC callback under the given name.
 * @param name the name of the callback, must not be NULL
 * @param callback the function to call
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 *   (typically if a callback of that name is already in use).
 */
static int
RPC_register (const char *name,
              GNUNET_RPC_AsynchronousFunction callback, void *cls)
{
  struct RegisteredRPC *rrpc;

  GNUNET_GE_ASSERT (coreAPI->ectx, name != NULL);
  GNUNET_GE_ASSERT (coreAPI->ectx, callback != NULL);
  GNUNET_mutex_lock (lock);
  rrpc = list_of_callbacks;
  while (rrpc != NULL)
    {
      if (0 == strcmp (rrpc->name, name))
        {
          GNUNET_mutex_unlock (lock);
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("%s::%s - RPC %s:%p could not be registered:"
                           " another callback is already using this name (%p)\n"),
                         __FILE__, __FUNCTION__, name, callback,
                         rrpc->async_callback);
          return GNUNET_SYSERR;
        }
      rrpc = rrpc->next;
    }
  rrpc = GNUNET_malloc (sizeof (struct RegisteredRPC));
  rrpc->name = GNUNET_strdup (name);
  rrpc->async_callback = callback;
  rrpc->cls = cls;
  rrpc->next = list_of_callbacks;
  list_of_callbacks = rrpc;
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
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
RPC_unregister (const char *name,
                GNUNET_RPC_AsynchronousFunction callback, void *cls)
{
  struct RegisteredRPC *pos;
  struct RegisteredRPC *prev;

  GNUNET_GE_ASSERT (NULL, NULL == incomingCalls);
  GNUNET_GE_ASSERT (coreAPI->ectx, name != NULL);
  GNUNET_mutex_lock (lock);
  prev = NULL;
  pos = list_of_callbacks;
  while (pos != NULL)
    {
      if ((0 == strcmp (pos->name, name)) &&
          (pos->async_callback == callback) && (pos->cls == cls))
        {
          if (prev == NULL)
            list_of_callbacks = pos->next;
          else
            prev->next = pos->next;
          GNUNET_free (pos->name);
          GNUNET_free (pos);
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
      prev = pos;
      pos = pos->next;
    }
  GNUNET_mutex_unlock (lock);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                 _
                 ("%s::%s - async RPC %s:%p could not be unregistered: not found\n"),
                 __FILE__, __FUNCTION__, name, callback);
  return GNUNET_SYSERR;
}

/**
 * Get the name of the RPC function.
 */
static char *
RPC_get_function_name (const P2P_rpc_MESSAGE * req)
{
  char *ret;
  unsigned int slen;

  slen = ntohl (req->functionNameLength);
  if ((ntohs (req->header.size) < sizeof (P2P_rpc_MESSAGE) + slen) ||
      (sizeof (P2P_rpc_MESSAGE) + slen < sizeof (P2P_rpc_MESSAGE)))
    return NULL;                /* invalid! */
  ret = GNUNET_malloc (slen + 1);
  memcpy (ret, &req[1], slen);
  ret[slen] = '\0';
  return ret;
}

/**
 * Get the arguments (or return value) from
 * the request.
 */
static struct GNUNET_RPC_CallParameters *
RPC_deserialize_arguments (const P2P_rpc_MESSAGE * req)
{
  unsigned int slen;
  struct GNUNET_RPC_CallParameters *ret;

  if (ntohs (req->header.type) == GNUNET_P2P_PROTO_RPC_REQ)
    slen = ntohl (req->functionNameLength);
  else
    slen = 0;
  if ((ntohs (req->header.size) < sizeof (P2P_rpc_MESSAGE) + slen) ||
      (sizeof (P2P_rpc_MESSAGE) + slen < sizeof (P2P_rpc_MESSAGE)))
    return NULL;                /* invalid! */
  ret =
    GNUNET_RPC_parameters_deserialize (&((char *) &req[1])[slen],
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
 * Send an ACK message.
 */
static void
RPC_send_ack (const GNUNET_PeerIdentity * receiver,
              unsigned int sequenceNumber,
              unsigned int importance, unsigned int maxDelay)
{
  RPC_ACK_Message msg;

  msg.header.size = htons (sizeof (RPC_ACK_Message));
  msg.header.type = htons (GNUNET_P2P_PROTO_RPC_ACK);
  msg.sequenceNumber = htonl (sequenceNumber);
  coreAPI->ciphertext_send (receiver, &msg.header, importance, maxDelay);
}

/**
 * Build an RPC message serializing the name and values
 * properly.
 *
 * @param errorCode the status code for the message, if non-NULL
 *   values will be NULL
 * @param name the name of the target method, NULL for a reply.
 * @param sequenceNumber the unique ID of the message
 * @param values the arguments or return values, maybe NULL
 * @return the RPC message to transmit, caller must free
 */
static P2P_rpc_MESSAGE *
RPC_build_message (unsigned short errorCode,
                   const char *name,
                   unsigned int sequenceNumber,
                   unsigned int importance,
                   const struct GNUNET_RPC_CallParameters *values)
{
  P2P_rpc_MESSAGE *ret;
  size_t size = sizeof (P2P_rpc_MESSAGE);
  int slen;

  if (name != NULL)
    slen = strlen (name);
  else
    slen = 0;
  size += slen;
  if (values != NULL)
    size += GNUNET_RPC_parameters_get_serialized_size (values);
  if (size >= GNUNET_MAX_BUFFER_SIZE)
    return NULL;                /* message to big! */
  ret = GNUNET_malloc (size);
  ret->header.size = htons (size);
  ret->header.type =
    htons ((name ==
            NULL) ? GNUNET_P2P_PROTO_RPC_RES : GNUNET_P2P_PROTO_RPC_REQ);
  ret->timestamp = htonl (GNUNET_get_time_int32 (NULL));
  ret->sequenceNumber = htonl (sequenceNumber);
  ret->importance = htonl (importance);
  if (name == NULL)
    ret->functionNameLength = htonl (errorCode);
  else
    ret->functionNameLength = htonl (slen);
  ret->argumentCount =
    htonl ((values == NULL) ? 0 : GNUNET_RPC_parameters_count (values));
  if (name != NULL)
    memcpy (&ret[1], name, slen);
  GNUNET_RPC_parameters_serialize (values, &((char *) &ret[1])[slen]);
  return ret;
}



/* ***************** RPC P2P message handlers **************** */

/**
 * Function called to communicate the return value of
 * an RPC to the peer that initiated it.
 */
static void
RPC_complete (const struct GNUNET_RPC_CallParameters *results,
              int errorCode, struct GNUNET_RPC_CallHandle *call)
{
  GNUNET_mutex_lock (lock);
  GNUNET_GE_ASSERT (NULL, call->msg == NULL);
  call->msg = RPC_build_message (errorCode,
                                 NULL,
                                 call->sequenceNumber,
                                 call->importance, results);
  if (call->msg == NULL)
    call->msg = RPC_build_message (GNUNET_RPC_ERROR_RETURN_VALUE_TOO_LARGE,
                                   NULL,
                                   call->sequenceNumber,
                                   call->importance, results);
  call->lastAttempt = GNUNET_get_time ();
  call->repetitionFrequency = RPC_INITIAL_ROUND_TRIP_TIME;
  call->attempts = 1;
  call->errorCode = errorCode;
  coreAPI->ciphertext_send (&call->initiator,
                            &call->msg->header,
                            call->importance,
                            RPC_INITIAL_ROUND_TRIP_TIME / 2);
  GNUNET_mutex_unlock (lock);
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
  const P2P_rpc_MESSAGE *req;
  struct GNUNET_RPC_CallHandle *pos;
  struct GNUNET_RPC_CallParameters *argumentValues;
  const struct RegisteredRPC *rpc;
  unsigned int sq;
  unsigned int total;
  char *functionName;

  if (ntohs (message->size) < sizeof (P2P_rpc_MESSAGE))
    {
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_SYSERR;
    }
  req = (const P2P_rpc_MESSAGE *) message;
  functionName = RPC_get_function_name (req);
  if (functionName == NULL)
    {
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_SYSERR;
    }
  argumentValues = RPC_deserialize_arguments (req);
  if (argumentValues == NULL)
    {
      GNUNET_free (functionName);
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_SYSERR;     /* message malformed */
    }
  sq = ntohl (req->sequenceNumber);

  /* check if message is already in incomingCalls! */
  GNUNET_mutex_lock (lock);
  pos = incomingCalls;
  total = 0;
  while ((pos != NULL) &&
         ((pos->sequenceNumber != sq) ||
          (0 != memcmp (&pos->initiator,
                        sender, sizeof (GNUNET_PeerIdentity)))))
    {
      if (0 == memcmp (&pos->initiator, sender, sizeof (GNUNET_PeerIdentity)))
        total++;
      pos = pos->next;
    }
  if ((pos != NULL) || (total > RPC_MAX_REQUESTS_PER_PEER))
    {
      /* already pending or too many pending */
      GNUNET_free (functionName);
      GNUNET_RPC_parameters_destroy (argumentValues);
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }

  /* find matching RPC function */
  rpc = list_of_callbacks;
  while (rpc != NULL)
    {
      if (0 == strcmp (functionName, rpc->name))
        break;
      rpc = rpc->next;
    }
  /* create call handle */
  pos = GNUNET_malloc (sizeof (struct GNUNET_RPC_CallHandle));
  memset (pos, 0, sizeof (struct GNUNET_RPC_CallHandle));
  pos->function_name = functionName;
  pos->sequenceNumber = sq;
  pos->initiator = *sender;
  pos->expirationTime = GNUNET_get_time () + RPC_INTERNAL_PROCESSING_TIMEOUT;
  pos->importance = ntohl (req->importance);
  pos->next = incomingCalls;
  if (incomingCalls != NULL)
    incomingCalls->prev = pos;
  incomingCalls = pos;
  if (rpc == NULL)
    RPC_complete (NULL, GNUNET_RPC_ERROR_UNKNOWN_FUNCTION, pos);
  else
    rpc->async_callback (rpc->cls, sender, argumentValues, pos);
  GNUNET_RPC_parameters_destroy (argumentValues);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Handle reply for request for remote function call.  Checks
 * if we are waiting for a reply, if so triggers the callback.
 * Also always sends an ACK.
 */
static int
handleRPCMessageRes (const GNUNET_PeerIdentity * sender,
                     const GNUNET_MessageHeader * message)
{
  const P2P_rpc_MESSAGE *res;
  struct GNUNET_RPC_RequestHandle *pos;
  struct GNUNET_RPC_CallParameters *reply;
  unsigned int error;

  if (ntohs (message->size) < sizeof (P2P_rpc_MESSAGE))
    {
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_SYSERR;
    }
  res = (const P2P_rpc_MESSAGE *) message;
  RPC_send_ack (sender,
                ntohl (res->sequenceNumber), ntohl (res->importance), 0);
  /* Locate the GNUNET_RPC_CallHandle structure. */
  GNUNET_mutex_lock (lock);
  pos = outgoingCalls;
  while (pos != NULL)
    {
      if ((0 == memcmp (&pos->receiver,
                        sender,
                        sizeof (GNUNET_PeerIdentity))) &&
          (pos->sequenceNumber == ntohl (res->sequenceNumber)))
        break;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      /* duplicate reply */
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }
  /* remove pos from linked list */
  GNUNET_mutex_unlock (lock);

  /* call callback */
  reply = NULL;
  error = ntohl (res->functionNameLength);
  if (error == GNUNET_RPC_ERROR_OK)
    reply = GNUNET_RPC_parameters_deserialize ((char *) &res[1],
                                               ntohs (message->size) -
                                               sizeof (P2P_rpc_MESSAGE));
  if (ntohl (res->argumentCount) != GNUNET_RPC_parameters_count (reply))
    {
      GNUNET_RPC_parameters_destroy (reply);
      reply = NULL;
      error = GNUNET_RPC_ERROR_REPLY_MALFORMED;
    }
  if (pos->callback != NULL)
    {
      pos->callback (sender, reply, error, pos->cls);
      pos->callback = NULL;
      pos->errorCode = error;
    }
  if (reply != NULL)
    GNUNET_RPC_parameters_destroy (reply);
  return GNUNET_OK;
}

/**
 * Handle a peer-to-peer message of type GNUNET_P2P_PROTO_RPC_ACK.
 */
static int
handleRPCMessageAck (const GNUNET_PeerIdentity * sender,
                     const GNUNET_MessageHeader * message)
{
  const RPC_ACK_Message *ack;
  struct GNUNET_RPC_CallHandle *pos;

  if (ntohs (message->size) != sizeof (RPC_ACK_Message))
    {
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_SYSERR;
    }
  ack = (const RPC_ACK_Message *) message;
  GNUNET_mutex_lock (lock);

  /* Locate the GNUNET_RPC_CallHandle structure. */
  pos = incomingCalls;
  while (pos != NULL)
    {
      if ((0 == memcmp (&pos->initiator,
                        sender,
                        sizeof (GNUNET_PeerIdentity))) &&
          (pos->sequenceNumber == ntohl (ack->sequenceNumber)))
        break;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      /* duplicate ACK, ignore */
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }
  /* remove from list */
  if (pos->prev == NULL)
    incomingCalls = pos->next;
  else
    pos->prev->next = pos->next;
  if (pos->next != NULL)
    pos->next->prev = pos->prev;
  GNUNET_free (pos->msg);
  GNUNET_free (pos->function_name);
  GNUNET_free (pos);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
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
static struct GNUNET_RPC_RequestHandle *
RPC_start (const GNUNET_PeerIdentity * receiver,
           const char *name,
           const struct GNUNET_RPC_CallParameters *request_param,
           unsigned int importance,
           GNUNET_CronTime timeout,
           GNUNET_RPC_AsynchronousCompletionCallback callback, void *closure)
{
  struct GNUNET_RPC_RequestHandle *ret;

  if (timeout > 1 * GNUNET_CRON_HOURS)
    timeout = 1 * GNUNET_CRON_HOURS;
  ret = GNUNET_malloc (sizeof (struct GNUNET_RPC_RequestHandle));
  memset (ret, 0, sizeof (struct GNUNET_RPC_RequestHandle));
  ret->receiver = *receiver;
  ret->callback = callback;
  ret->cls = closure;
  ret->expirationTime = GNUNET_get_time () + timeout;
  ret->lastAttempt = 0;
  ret->attempts = 0;
  ret->sequenceNumber = rpcIdentifier++;
  ret->msg = RPC_build_message (GNUNET_RPC_ERROR_OK,
                                name,
                                ret->sequenceNumber,
                                importance, request_param);
  ret->repetitionFrequency = RPC_INITIAL_ROUND_TRIP_TIME;
  GNUNET_mutex_lock (lock);
  ret->next = outgoingCalls;
  outgoingCalls = ret;
  if (ret->next != NULL)
    ret->next->prev = ret;
  GNUNET_mutex_unlock (lock);
  coreAPI->ciphertext_send (receiver,
                            &ret->msg->header,
                            importance, RPC_INITIAL_ROUND_TRIP_TIME / 2);
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
RPC_stop (struct GNUNET_RPC_RequestHandle *record)
{
  int ret;

  GNUNET_mutex_lock (lock);
  if (record->prev == NULL)
    outgoingCalls = record->next;
  else
    record->prev->next = record->next;
  if (record->next != NULL)
    record->next->prev = record->prev;
  GNUNET_free (record->msg);
  GNUNET_mutex_unlock (lock);
  ret =
    (record->callback == NULL) ? record->errorCode : GNUNET_RPC_ERROR_ABORTED;
  GNUNET_free (record);
  return ret;
}


/**
 * Cron-job that processes the RPC queues.  This job is responsible
 * for retransmission of requests and un-ACKed responses.  It is also
 * there to trigger timeouts.
 */
static void
RPC_retry_job (void *unused)
{
  GNUNET_CronTime now;
  struct GNUNET_RPC_CallHandle *ipos;
  struct GNUNET_RPC_RequestHandle *opos;

  GNUNET_mutex_lock (lock);
  now = GNUNET_get_time ();
  ipos = incomingCalls;
  while (ipos != NULL)
    {
      if ((ipos->expirationTime < now) ||
          (ipos->attempts >= RPC_MAX_REPLY_ATTEMPTS))
        {
          GNUNET_free_non_null (ipos->msg);
          GNUNET_free (ipos->function_name);
          if (ipos->prev == NULL)
            incomingCalls = ipos->next;
          else
            ipos->prev->next = ipos->next;
          if (ipos->next != NULL)
            ipos->next = ipos->prev;
          GNUNET_free (ipos);
          ipos = incomingCalls;
          continue;
        }
      if ((ipos->msg != NULL) &&
          (ipos->lastAttempt + ipos->repetitionFrequency < now))
        {
          ipos->lastAttempt = now;
          ipos->attempts++;
          ipos->repetitionFrequency *= 2;
          coreAPI->ciphertext_send (&ipos->initiator,
                                    &ipos->msg->header,
                                    ipos->repetitionFrequency / 2,
                                    ipos->importance);
        }
      ipos = ipos->next;
    }
  opos = outgoingCalls;
  while (opos != NULL)
    {
      if (opos->expirationTime < now)
        {
          if (opos->callback != NULL)
            {
              opos->callback (&opos->receiver,
                              NULL, GNUNET_RPC_ERROR_TIMEOUT, opos->cls);
              opos->callback = NULL;
            }
          GNUNET_free_non_null (opos->msg);
          if (opos->prev == NULL)
            outgoingCalls = opos->next;
          else
            opos->prev->next = opos->next;
          if (opos->next != NULL)
            opos->next = opos->prev;
          GNUNET_free (opos);
          opos = outgoingCalls;
          continue;
        }
      if (opos->lastAttempt + opos->repetitionFrequency < now)
        {
          opos->lastAttempt = now;
          opos->attempts++;
          opos->repetitionFrequency *= 2;
          coreAPI->ciphertext_send (&opos->receiver,
                                    &opos->msg->header,
                                    opos->repetitionFrequency / 2,
                                    opos->importance);
        }
      opos = opos->next;
    }
  GNUNET_mutex_unlock (lock);
}

/* ******************* Exported functions ******************* */

/**
 * Shutdown RPC service.
 */
void
release_module_rpc ()
{
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_RPC_REQ,
                                              &handleRPCMessageReq);
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_RPC_RES,
                                              &handleRPCMessageRes);
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_RPC_ACK,
                                              &handleRPCMessageAck);
  GNUNET_GE_ASSERT (NULL, NULL == incomingCalls);
  GNUNET_GE_ASSERT (NULL, NULL == outgoingCalls);
  GNUNET_GE_ASSERT (NULL, NULL == list_of_callbacks);
  GNUNET_cron_del_job (coreAPI->cron,
                       &RPC_retry_job, RPC_CRON_FREQUENCY, NULL);
  coreAPI = NULL;
  lock = NULL;
}

/**
 * Initialize the RPC service.
 */
GNUNET_RPC_ServiceAPI *
provide_module_rpc (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_RPC_ServiceAPI rpcAPI;
  int rvalue;

  lock = capi->global_lock_get ();
  coreAPI = capi;
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering handlers %d %d %d\n"), "rpc",
                 GNUNET_P2P_PROTO_RPC_REQ, GNUNET_P2P_PROTO_RPC_RES,
                 GNUNET_P2P_PROTO_RPC_ACK);
  rvalue = GNUNET_OK;
  if (capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_RPC_REQ,
                                             &handleRPCMessageReq) ==
      GNUNET_SYSERR)
    rvalue = GNUNET_SYSERR;
  if (capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_RPC_RES,
                                             &handleRPCMessageRes) ==
      GNUNET_SYSERR)
    rvalue = GNUNET_SYSERR;
  if (capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_RPC_ACK,
                                             &handleRPCMessageAck) ==
      GNUNET_SYSERR)
    rvalue = GNUNET_SYSERR;
  if (rvalue == GNUNET_SYSERR)
    {
      release_module_rpc ();
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Failed to initialize `%s' service.\n"), "rpc");
      return NULL;
    }
  GNUNET_cron_add_job (coreAPI->cron,
                       &RPC_retry_job,
                       RPC_CRON_FREQUENCY, RPC_CRON_FREQUENCY, NULL);
  rpcAPI.RPC_register = &RPC_register;
  rpcAPI.RPC_unregister = &RPC_unregister;
  rpcAPI.RPC_complete = &RPC_complete;
  rpcAPI.RPC_start = &RPC_start;
  rpcAPI.RPC_stop = &RPC_stop;
  return &rpcAPI;
}

/* end of rpc.c */
