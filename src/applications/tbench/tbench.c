/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/tbench/tbench.c
 * @author Paul Ruth
 * @brief module to enable transport profiling.
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "tbench.h"

#define DEBUG_TBENCH GNUNET_NO

typedef struct
{
  GNUNET_CronTime totalTime;
  unsigned char *packetsReceived;
  unsigned int maxPacketNumber;
  unsigned int lossCount;
  unsigned int duplicateCount;
} IterationData;

/**
 * Message exchanged between peers for profiling
 * transport performance.
 */
typedef struct
{
  GNUNET_MessageHeader header;
  unsigned int iterationNum;
  unsigned int packetNum;
  unsigned int priority;
  unsigned int nounce;
  unsigned int crc;
} P2P_tbench_MESSAGE;

/**
 * Lock for access to semaphores.
 */
static struct GNUNET_Mutex *lock;

static struct GNUNET_Semaphore *postsem;

/**
 * What is the current iteration counter? (Used to verify
 * that replies match the current request series).
 */
static unsigned int currIteration;

static unsigned int currNounce;

/**
 * Did the current iteration time-out? (GNUNET_YES/GNUNET_NO)
 */
static int timeoutOccured;

static struct GNUNET_GE_Context *ectx;

static GNUNET_CoreAPIForPlugins *coreAPI;

static IterationData *results;

/**
 * Did we receive the last response for the current iteration
 * before the timeout? If so, when?
 */
static GNUNET_CronTime earlyEnd;


/**
 * Another peer send us a tbench request.  Just turn
 * around and send it back.
 */
static int
handleTBenchReq (const GNUNET_PeerIdentity * sender,
                 const GNUNET_MessageHeader * message)
{
  GNUNET_MessageHeader *reply;
  const P2P_tbench_MESSAGE *msg;

#if DEBUG_TBENCH
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                 "Received tbench request\n");
#endif
  if (ntohs (message->size) < sizeof (P2P_tbench_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  msg = (const P2P_tbench_MESSAGE *) message;
  if (GNUNET_crc32_n (&msg[1],
                      ntohs (message->size) - sizeof (P2P_tbench_MESSAGE))
      != ntohl (msg->crc))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }

#if DEBUG_TBENCH
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                 "Received request %u from iteration %u/%u\n",
                 htonl (msg->packetNum),
                 htonl (msg->iterationNum), htonl (msg->nounce));
#endif
  reply = GNUNET_malloc (ntohs (message->size));
  memcpy (reply, message, ntohs (message->size));
  reply->type = htons (GNUNET_P2P_PROTO_TBENCH_REPLY);
  coreAPI->ciphertext_send (sender, reply, ntohl (msg->priority), 0);   /* no delay */
  GNUNET_free (reply);
  return GNUNET_OK;
}

/**
 * We received a tbench-reply.  Check and count stats.
 */
static int
handleTBenchReply (const GNUNET_PeerIdentity * sender,
                   const GNUNET_MessageHeader * message)
{
  const P2P_tbench_MESSAGE *pmsg;
  unsigned int lastPacketNumber;
  IterationData *res;

  if (ntohs (message->size) < sizeof (P2P_tbench_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  pmsg = (const P2P_tbench_MESSAGE *) message;
  if (GNUNET_crc32_n (&pmsg[1],
                      ntohs (message->size) - sizeof (P2P_tbench_MESSAGE))
      != ntohl (pmsg->crc))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_lock (lock);
  if ((timeoutOccured == GNUNET_NO) &&
      (postsem != NULL) &&
      (htonl (pmsg->iterationNum) == currIteration) &&
      (htonl (pmsg->nounce) == currNounce))
    {
      res = &results[currIteration];
      lastPacketNumber = ntohl (pmsg->packetNum);
      if (lastPacketNumber <= res->maxPacketNumber)
        {
          if (0 == res->packetsReceived[lastPacketNumber]++)
            {
              res->lossCount--;
              if (res->lossCount == 0)
                earlyEnd = GNUNET_get_time ();
            }
          else
            {
              res->duplicateCount++;
            }
        }
#if DEBUG_TBENCH
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "Received response %u from iteration %u/%u on time!\n",
                     htonl (pmsg->packetNum),
                     htonl (pmsg->iterationNum), htonl (pmsg->nounce));
#endif
    }
  else
    {
#if DEBUG_TBENCH
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "Received message %u from iteration %u too late (now at iteration %u)\n",
                     ntohl (pmsg->packetNum),
                     ntohl (pmsg->iterationNum), currIteration);
#endif
    }
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Cron-job helper function to signal timeout.
 */
static void
semaUp (void *cls)
{
  struct GNUNET_Semaphore *sem = cls;
  timeoutOccured = GNUNET_YES;
  GNUNET_semaphore_up (sem);
}

/**
 * Handle client request (main function)
 */
static int
csHandleTBenchRequest (struct GNUNET_ClientHandle *client,
                       const GNUNET_MessageHeader * message)
{
  CS_tbench_request_MESSAGE *msg;
  CS_tbench_reply_MESSAGE reply;
  P2P_tbench_MESSAGE *p2p;
  unsigned short size;
  unsigned int iteration;
  unsigned int packetNum;
  GNUNET_CronTime startTime;
  GNUNET_CronTime endTime;
  GNUNET_CronTime now;
  GNUNET_CronTime delay;
  unsigned long long sum_loss;
  unsigned int max_loss;
  unsigned int min_loss;
  GNUNET_CronTime sum_time;
  GNUNET_CronTime min_time;
  GNUNET_CronTime max_time;
  double sum_variance_time;
  double sum_variance_loss;
  unsigned int msgCnt;
  unsigned int iterations;

#if DEBUG_TBENCH
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                 "Tbench received request from client.\n", msgCnt, size,
                 iterations);
#endif
  if (ntohs (message->size) != sizeof (CS_tbench_request_MESSAGE))
    return GNUNET_SYSERR;

  msg = (CS_tbench_request_MESSAGE *) message;
  size = sizeof (P2P_tbench_MESSAGE) + ntohl (msg->msgSize);
  if (size < sizeof (P2P_tbench_MESSAGE))
    return GNUNET_SYSERR;
  delay = GNUNET_ntohll (msg->intPktSpace);
  iterations = ntohl (msg->iterations);
  msgCnt = ntohl (msg->msgCnt);
#if DEBUG_TBENCH
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                 "Tbench runs %u test messages of size %u in %u iterations.\n",
                 msgCnt, size, iterations);
#endif
  GNUNET_mutex_lock (lock);
  if (results != NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                     "Cannot run multiple tbench sessions at the same time!\n");
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  results = GNUNET_malloc (sizeof (IterationData) * iterations);

  p2p = GNUNET_malloc (size);
  memset (p2p, 0, size);
  p2p->header.size = htons (size);
  p2p->header.type = htons (GNUNET_P2P_PROTO_TBENCH_REQUEST);
  p2p->priority = msg->priority;

  for (iteration = 0; iteration < iterations; iteration++)
    {
      results[iteration].maxPacketNumber = msgCnt;
      results[iteration].packetsReceived = GNUNET_malloc (msgCnt);
      memset (results[iteration].packetsReceived, 0, msgCnt);
      results[iteration].lossCount = msgCnt;
      results[iteration].duplicateCount = 0;

      earlyEnd = 0;
      postsem = GNUNET_semaphore_create (0);
      currNounce = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 0xFFFFFF);
      p2p->nounce = htonl (currNounce);
      currIteration = iteration;
      p2p->iterationNum = htonl (currIteration);
      memset (&p2p[1],
              GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 256),
              size - sizeof (P2P_tbench_MESSAGE));
      p2p->crc =
        htonl (GNUNET_crc32_n (&p2p[1], size - sizeof (P2P_tbench_MESSAGE)));
      GNUNET_mutex_unlock (lock);       /* allow receiving */

      startTime = GNUNET_get_time ();
      endTime = startTime + GNUNET_ntohll (msg->timeOut);

      timeoutOccured = GNUNET_NO;
      GNUNET_cron_add_job (coreAPI->cron,
                           &semaUp,
                           GNUNET_ntohll (msg->timeOut) *
                           GNUNET_CRON_MILLISECONDS, 0, postsem);
      for (packetNum = 0; packetNum < msgCnt; packetNum++)
        {
          now = GNUNET_get_time ();
          p2p->packetNum = htonl (packetNum);
#if DEBUG_TBENCH
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                         "Sending message %u of size %u in iteration %u\n",
                         packetNum, size, iteration);
#endif
          coreAPI->ciphertext_send (&msg->receiverId, &p2p->header, ntohl (msg->priority), 0);  /* no delay */
          if ((delay != 0) &&
              (htonl (msg->trainSize) != 0) &&
              (packetNum % htonl (msg->trainSize)) == 0)
            GNUNET_thread_sleep (delay);
        }
      GNUNET_semaphore_down (postsem, GNUNET_YES);
      GNUNET_mutex_lock (lock);
      if (earlyEnd == 0)
        earlyEnd = GNUNET_get_time ();
      results[iteration].totalTime = earlyEnd - startTime;
      GNUNET_free (results[iteration].packetsReceived);
      GNUNET_semaphore_destroy (postsem);
      postsem = NULL;
    }
  GNUNET_mutex_unlock (lock);
  GNUNET_free (p2p);
#if DEBUG_TBENCH
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                 "Done waiting for response.\n", packetNum, size, iteration);
#endif

  sum_loss = 0;
  sum_time = 0;
  max_loss = 0;
  min_loss = msgCnt;
  min_time = 1 * GNUNET_CRON_YEARS;
  max_time = 0;
  /* data post-processing */
  for (iteration = 0; iteration < iterations; iteration++)
    {
      sum_loss += results[iteration].lossCount;
      sum_time += results[iteration].totalTime;

      if (results[iteration].lossCount > max_loss)
        max_loss = results[iteration].lossCount;
      if (results[iteration].lossCount < min_loss)
        min_loss = results[iteration].lossCount;
      if (results[iteration].totalTime > max_time)
        max_time = results[iteration].totalTime;
      if (results[iteration].totalTime < min_time)
        min_time = results[iteration].totalTime;
    }

  sum_variance_time = 0.0;
  sum_variance_loss = 0.0;
  for (iteration = 0; iteration < iterations; iteration++)
    {
      sum_variance_time +=
        (results[iteration].totalTime - sum_time / iterations) *
        (results[iteration].totalTime - sum_time / iterations);
      sum_variance_loss +=
        (results[iteration].lossCount - sum_loss / iterations) *
        (results[iteration].lossCount - sum_loss / iterations);
    }

  /* send collected stats back to client */
  reply.header.size = htons (sizeof (CS_tbench_reply_MESSAGE));
  reply.header.type = htons (GNUNET_CS_PROTO_TBENCH_REPLY);
  reply.max_loss = htonl (max_loss);
  reply.min_loss = htonl (min_loss);
  reply.mean_loss = ((float) sum_loss / (float) iterations);
  reply.mean_time = ((float) sum_time / (float) iterations);
  reply.max_time = GNUNET_htonll (max_time);
  reply.min_time = GNUNET_htonll (min_time);
  reply.variance_time = sum_variance_time / (iterations - 1);
  reply.variance_loss = sum_variance_loss / (iterations - 1);
  GNUNET_free (results);
  results = NULL;
  return coreAPI->cs_send_message (client, &reply.header, GNUNET_YES);
}

/**
 * Initialize the AFS module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 * @return GNUNET_SYSERR on errors
 */
int
initialize_module_tbench (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;

  ectx = capi->ectx;
  lock = GNUNET_mutex_create (GNUNET_NO);
  coreAPI = capi;
  if (GNUNET_SYSERR ==
      capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_TBENCH_REPLY,
                                             &handleTBenchReply))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_TBENCH_REQUEST,
                                             &handleTBenchReq))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->cs_handler_register (GNUNET_CS_PROTO_TBENCH_REQUEST,
                                 &csHandleTBenchRequest))
    ok = GNUNET_SYSERR;

  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "tbench",
                                                                   gettext_noop
                                                                   ("allows profiling of direct "
                                                                    "peer-to-peer connections")));
  return ok;
}

void
done_module_tbench ()
{
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_TBENCH_REQUEST,
                                              &handleTBenchReq);
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_TBENCH_REPLY,
                                              &handleTBenchReply);
  coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_TBENCH_REQUEST,
                                  &csHandleTBenchRequest);
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  coreAPI = NULL;
}

/* end of tbench.c */
