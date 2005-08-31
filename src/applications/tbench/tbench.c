/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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

#define DEBUG_TBENCH NO

typedef struct {
  cron_t totalTime;
  unsigned char * packetsReceived;
  unsigned int maxPacketNumber;
  unsigned int lossCount;
  unsigned int duplicateCount;
} IterationData;

/**
 * Message exchanged between peers for profiling
 * transport performance.
 */
typedef struct {
  P2P_MESSAGE_HEADER header;
  unsigned int iterationNum;
  unsigned int packetNum;
  unsigned int priority;
  unsigned int nounce;
  unsigned int crc;
} P2P_tbench_MESSAGE;

/**
 * Lock for access to semaphores.
 */
static Mutex lock;

static Semaphore * presem;

static Semaphore * postsem;

/**
 * What was the packet number we received?
 */
static unsigned int lastPacketNumber;

/**
 * What is the current iteration counter? (Used to verify
 * that replies match the current request series).
 */
static unsigned int currIteration;
static unsigned int currNounce;

/**
 * Did the current iteration time-out? (YES/NO)
 */
static int timeoutOccured;


static CoreAPIForApplication * coreAPI;

/**
 * Check if we have received a p2p reply,
 * update result counters accordingly.
 *
 * @return 0 if we have received all results, >0 otherwise
 */
static int pollResults(IterationData * results,
		       int blocking) {
  if (results->lossCount == 0)
    return 0;
  if (blocking == YES) {
    if (timeoutOccured == YES)
      return results->lossCount;
    SEMAPHORE_DOWN(postsem);
  } else {
    if (OK != SEMAPHORE_DOWN_NONBLOCKING(postsem))
      return results->lossCount;
  }
  do {
    if (timeoutOccured == YES) {
      SEMAPHORE_UP(presem);
      return results->lossCount;
    }
    if (lastPacketNumber > results->maxPacketNumber) {
      SEMAPHORE_UP(presem);
      return results->lossCount;
    }
    if (0 == results->packetsReceived[lastPacketNumber]++) {
      results->lossCount--;
    } else {
      results->duplicateCount++;
#if DEBUG_TBENCH
      LOG(LOG_DEBUG,
	  "Received duplicate message %u from iteration %u\n",
	  lastPacketNumber,
	  currIteration);
#endif
    }
    SEMAPHORE_UP(presem);
  } while (OK == SEMAPHORE_DOWN_NONBLOCKING(postsem));
  return results->lossCount;
}

/**
 * Another peer send us a tbench request.  Just turn
 * around and send it back.
 */
static int handleTBenchReq(const PeerIdentity * sender,
			   const P2P_MESSAGE_HEADER * message) {
  P2P_MESSAGE_HEADER * reply;
  const P2P_tbench_MESSAGE * msg;

  if ( ntohs(message->size) < sizeof(P2P_tbench_MESSAGE)) {
    BREAK();
    return SYSERR;
  }
  msg = (const P2P_tbench_MESSAGE*) message;
  if (crc32N(&msg[1],
	     ntohs(message->size) - sizeof(P2P_tbench_MESSAGE))
      != ntohl(msg->crc)) {
    BREAK();
    return SYSERR;
  }

#if DEBUG_TBENCH
  LOG(LOG_DEBUG,
      "Received request %u from iteration %u/%u\n",
      htonl(msg->packetNum),
      htonl(msg->iterationNum),
      htonl(msg->nounce));
#endif
  reply = MALLOC(ntohs(message->size));
  memcpy(reply,
	 message,
	 ntohs(message->size));
  reply->type = htons(P2P_PROTO_tbench_REPLY);
  coreAPI->unicast(sender,
		   reply,
		   ntohl(msg->priority), /* medium importance */
		   0); /* no delay */
  FREE(reply);
  return OK;
}

/**
 * We received a tbench-reply.  Check and count stats.
 */
static int handleTBenchReply(const PeerIdentity * sender,
			     const P2P_MESSAGE_HEADER * message) {
  const P2P_tbench_MESSAGE * pmsg;

  if (ntohs(message->size) < sizeof(P2P_tbench_MESSAGE)) {
    BREAK();
    return SYSERR;
  }
  pmsg = (const P2P_tbench_MESSAGE*) message;
  if (crc32N(&pmsg[1],
	     ntohs(message->size) - sizeof(P2P_tbench_MESSAGE))
      != ntohl(pmsg->crc)) {
    BREAK();
    return SYSERR;
  }
#if DEBUG_TBENCH
  LOG(LOG_DEBUG,
      "Received response %u from iteration %u/%u\n",
      htonl(pmsg->packetNum),
      htonl(pmsg->iterationNum),
      htonl(pmsg->nounce));
#endif
  MUTEX_LOCK(&lock);
  if ( (timeoutOccured == NO) &&
       (presem != NULL) &&
       (postsem != NULL) &&
       (htonl(pmsg->iterationNum) == currIteration) &&
       (htonl(pmsg->nounce) == currNounce) ) {
    SEMAPHORE_DOWN(presem);
    lastPacketNumber = ntohl(pmsg->packetNum);
    SEMAPHORE_UP(postsem);
  } else {
#if DEBUG_TBENCH
    LOG(LOG_DEBUG,
	"Received message %u from iteration %u too late (now at iteration %u)\n",
	ntohl(pmsg->packetNum),
	ntohl(pmsg->iterationNum),
	currIteration);
#endif
  }
  MUTEX_UNLOCK(&lock);
  return OK;
}

/**
 * Cron-job helper function to signal timeout.
 */
static void semaUp(Semaphore * sem) {
  timeoutOccured = YES;
  SEMAPHORE_UP(sem);
}

/**
 * Handle client request (main function)
 */
static int csHandleTBenchRequest(ClientHandle client,
				 const CS_MESSAGE_HEADER * message) {
  CS_tbench_request_MESSAGE * msg;
  CS_tbench_reply_MESSAGE reply;
  P2P_tbench_MESSAGE * p2p;
  unsigned short size;
  unsigned int iteration;
  unsigned int packetNum;
  cron_t startTime;
  cron_t endTime;
  cron_t now;
  cron_t delay;
  cron_t delayStart;
  IterationData * results;
  unsigned long long sum_loss;
  unsigned int max_loss;
  unsigned int min_loss;
  cron_t sum_time;
  cron_t min_time;
  cron_t max_time;
  cron_t earlyEnd;
  double sum_variance_time;
  double sum_variance_loss;
  unsigned int msgCnt;
  unsigned int iterations;

  if ( ntohs(message->size) != sizeof(CS_tbench_request_MESSAGE) )
    return SYSERR;

  msg = (CS_tbench_request_MESSAGE*) message;
  size = sizeof(P2P_tbench_MESSAGE) + ntohl(msg->msgSize);
  if (size < sizeof(P2P_tbench_MESSAGE))
    return SYSERR;
  delay = ntohll(msg->intPktSpace);
  iterations = ntohl(msg->iterations);
  msgCnt = ntohl(msg->msgCnt);
#if DEBUG_TBENCH
  LOG(LOG_MESSAGE,
      "Tbench runs %u test messages of size %u in %u iterations.\n",
      msgCnt,
      size,
      iterations);
#endif
  results = MALLOC(sizeof(IterationData) * iterations);

  p2p = MALLOC(size);
  memset(p2p,
	 0,
	 size);
  p2p->header.size = htons(size);
  p2p->header.type = htons(P2P_PROTO_tbench_REQUEST);
  p2p->priority = msg->priority;

  MUTEX_LOCK(&lock);
  for (iteration=0;iteration<iterations;iteration++) {
    results[iteration].maxPacketNumber = msgCnt;
    results[iteration].packetsReceived = MALLOC(msgCnt);
    memset(results[iteration].packetsReceived,
	   0,
	   msgCnt);
    results[iteration].lossCount = msgCnt;
    results[iteration].duplicateCount = 0;

    earlyEnd = 0;
    presem = SEMAPHORE_NEW(1);
    postsem = SEMAPHORE_NEW(0);
    currNounce = randomi(0xFFFFFF);
    p2p->nounce
      = htonl(currNounce);
    currIteration = iteration;
    p2p->iterationNum
      = htonl(currIteration);
    memset(&p2p[1],
	   randomi(256),
	   size - sizeof(P2P_tbench_MESSAGE));
    p2p->crc
      = htonl(crc32N(&p2p[1],
		     size - sizeof(P2P_tbench_MESSAGE)));
    MUTEX_UNLOCK(&lock); /* allow receiving */

    cronTime(&startTime);
    endTime = startTime + ntohll(msg->timeOut);

    timeoutOccured = NO;
    addCronJob((CronJob)&semaUp,
	       ntohll(msg->timeOut) * cronMILLIS,
	       0,
	       postsem);
    for (packetNum=0;packetNum<msgCnt;packetNum++){
      cronTime(&now);
      if (now > endTime)
	break; /* timeout */

      p2p->packetNum = htonl(packetNum);
#if DEBUG_TBENCH
      LOG(LOG_DEBUG,
	  "Sending message %u of size %u in iteration %u\n",
	  packetNum,
	  size,
	  iteration);
#endif
      coreAPI->unicast(&msg->receiverId,
		       &p2p->header,
		       ntohl(msg->priority),
		       0); /* no delay */
      pollResults(&results[iteration], NO);
      if ( (delay != 0) &&
	   (htonl(msg->trainSize) != 0) &&
	   (packetNum % htonl(msg->trainSize)) == 0) {
	delayStart = now;
	while ( (cronTime(&now) < (delayStart+delay)) &&
		(timeoutOccured == NO) ) {
	  if (delayStart + delay - now  > 5 * cronMILLIS) {
	    pollResults(&results[iteration], NO);
	    gnunet_util_sleep(5 * cronMILLIS);
	  } else
	    gnunet_util_sleep(delayStart + delay - now);
	}
      }	
      if ( (0 == pollResults(&results[iteration], NO)) &&
	   (earlyEnd == 0) )
	earlyEnd = cronTime(NULL);
    }
    while ( (timeoutOccured == NO) &&
	    (cronTime(&now) < endTime) ) {
      if ( (0 == pollResults(&results[iteration], YES) ) &&
	   (earlyEnd == 0) )
	earlyEnd = now;
      gnunet_util_sleep(5 * cronMILLIS);
    }

    /* make sure to unblock waiting jobs */
    timeoutOccured = YES;
    SEMAPHORE_UP(presem);

    MUTEX_LOCK(&lock);
    if (earlyEnd == 0)
      earlyEnd = now;
    results[iteration].totalTime
      = earlyEnd - startTime;
    FREE(results[iteration].packetsReceived);
    suspendCron();
    delCronJob((CronJob)&semaUp,
	       0,
	       postsem);
    resumeCron();
    SEMAPHORE_FREE(presem);
    SEMAPHORE_FREE(postsem);
    presem = NULL;
    postsem = NULL;

  }
  MUTEX_UNLOCK(&lock);

  sum_loss = 0;
  sum_time = 0;
  max_loss = 0;
  min_loss = msgCnt;
  min_time = 1 * cronYEARS;
  max_time = 0;
  /* data post-processing */
  for (iteration=0;iteration<iterations;iteration++) {
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
  for(iteration = 0; iteration <iterations; iteration++){
    sum_variance_time +=
      (results[iteration].totalTime - sum_time/iterations) *
      (results[iteration].totalTime - sum_time/iterations);
    sum_variance_loss +=
      (results[iteration].lossCount - sum_loss/iterations) *
      (results[iteration].lossCount - sum_loss/iterations);
  }

  /* send collected stats back to client */
  reply.header.size = htons(sizeof(CS_tbench_reply_MESSAGE));
  reply.header.type = htons(CS_PROTO_tbench_REPLY);
  reply.max_loss = htonl(max_loss);
  reply.min_loss = htonl(min_loss);
  reply.mean_loss = ((float)sum_loss/(float)iterations);
  reply.mean_time = ((float)sum_time/(float)iterations);
  reply.max_time = htonll(max_time);
  reply.min_time = htonll(min_time);
  reply.variance_time = sum_variance_time/(iterations-1);
  reply.variance_loss = sum_variance_loss/(iterations-1);
  FREE(results);
  return coreAPI->sendToClient(client,
			       &reply.header);
}

/**
 * Initialize the AFS module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 * @return SYSERR on errors
 */
int initialize_module_tbench(CoreAPIForApplication * capi) {
  int ok = OK;

  MUTEX_CREATE(&lock);
  coreAPI = capi;
  if (SYSERR == capi->registerHandler(P2P_PROTO_tbench_REPLY,
				      &handleTBenchReply))
    ok = SYSERR;
  if (SYSERR == capi->registerHandler(P2P_PROTO_tbench_REQUEST,
				      &handleTBenchReq))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(CS_PROTO_tbench_REQUEST,
					    &csHandleTBenchRequest))
    ok = SYSERR;
  setConfigurationString("ABOUT",
			 "tbench",
			 gettext_noop("allows profiling of direct "
     			              "peer-to-peer connections"));
  return ok;
}

void done_module_tbench() {
  coreAPI->unregisterHandler(P2P_PROTO_tbench_REQUEST,
			     &handleTBenchReq);
  coreAPI->unregisterHandler(P2P_PROTO_tbench_REPLY,
			     &handleTBenchReply);
  coreAPI->unregisterClientHandler(CS_PROTO_tbench_REQUEST,
				   &csHandleTBenchRequest);
  MUTEX_DESTROY(&lock);
  coreAPI = NULL;
}

/* end of tbench.c */
