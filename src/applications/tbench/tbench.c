/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

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
 * TBench CORE. This is the code that is plugged
 * into the GNUnet core to enable transport profiling.
 *
 * @author Paul Ruth
 * @file applications/tbench/tbench.c
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "tbench.h"

struct Result {
  cron_t   time;
  unsigned int packets;
};

static CoreAPIForApplication * coreAPI = NULL;
static Mutex lock;
static Mutex lockCnt;
static PeerIdentity receiverIdent;
static Semaphore * sem;
static cron_t startTime = 0;
static cron_t endTime = 0;

static int msgCnt = 1;
static int msgIter = 1;
static int receiveCnt;
static int currIteration;

/* */
static int handleTBenchReq(const PeerIdentity * sender,
			   const p2p_HEADER * message) {
  TBENCH_p2p_MESSAGE *pmsg = (TBENCH_p2p_MESSAGE*)message;
  
  LOG(LOG_DEBUG, 
      "%s received iteration %d, message %d",
      __FUNCTION__,
      htons(pmsg->iterationNum), 
      htons(pmsg->packetNum));
  pmsg->header.type = htons(TBENCH_p2p_PROTO_REPLY);
  coreAPI->unicast(sender, message, 5, 0);    
  return OK;
}

/* */
static int handleTBenchReply(const PeerIdentity * sender,
			     const p2p_HEADER * message) {
  TBENCH_p2p_MESSAGE *pmsg = (TBENCH_p2p_MESSAGE*)message;
  
  LOG(LOG_DEBUG, 
      "%s",
      __FUNCTION__);
  MUTEX_LOCK(&lockCnt); 
  if(htons(pmsg->iterationNum) == currIteration) {
    cronTime(&endTime);
    receiveCnt++;
    LOG(LOG_DEBUG,
	"iteration %d, received reply, %d",
	currIteration, receiveCnt);
    if(receiveCnt >= msgCnt)
      SEMAPHORE_UP(sem);
  } else {
    LOG(LOG_DEBUG,
	"Old Reply: iteration %d, received reply, %d",
	currIteration, receiveCnt);
  }
  MUTEX_UNLOCK(&lockCnt);
  return OK;
}

static void semaUp(Semaphore * sem) {
  SEMAPHORE_UP(sem);
}

/* */
static void csHandleTBenchRequest(ClientHandle client,
 				  const CS_HEADER * message) {
  int i,j;
  int sum_loss,sum_time;
  double sum_variance_time, sum_variance_loss;
  TBENCH_p2p_MESSAGE *opmsg;
  TBENCH_CS_MESSAGE *icmsg;
  TBENCH_CS_REPLY *ocmsg;
  struct Result *results;

  LOG(LOG_DEBUG, 
      "%s",
      __FUNCTION__);
  icmsg   = (TBENCH_CS_MESSAGE*)message;
 
  opmsg = MALLOC(sizeof(TBENCH_p2p_MESSAGE)+ntohs(icmsg->msgSize)+1);
  ocmsg = MALLOC(sizeof(TBENCH_CS_REPLY));
  MUTEX_LOCK(&lock); /* only one benchmark run
			at a time */
  
  msgCnt  = htons(icmsg->msgCnt);
  msgIter = htons(icmsg->iterations);
  results = MALLOC(msgIter * sizeof(struct Result));

  LOG(LOG_DEBUG,
      "TBENCH: msgCnt %d msgIter %d",
      msgCnt, msgIter);
  sem = SEMAPHORE_NEW(0);

  receiveCnt = 0;

  memcpy(&receiverIdent,
	 &icmsg->receiverId,
	 sizeof(PeerIdentity));
  
  /* set up opmsg */
  memset(opmsg, 0, sizeof(TBENCH_p2p_MESSAGE));
  opmsg->header.size = htons(sizeof(TBENCH_p2p_MESSAGE)+ntohs(icmsg->msgSize));
  opmsg->header.type = htons(TBENCH_p2p_PROTO_REQUEST);
  opmsg->iterationNum = opmsg->packetNum = htons(0);
 
  for(currIteration = 0; currIteration < msgIter; currIteration++){
    opmsg->iterationNum = htons(currIteration);
    receiveCnt = 0;
    LOG(LOG_DEBUG,
	"Timeout after %u ms",
	ntohl(icmsg->timeOut));
    addCronJob((CronJob)&semaUp,
	       ntohl(icmsg->timeOut) * cronMILLIS,
	       0,
	       sem);
    cronTime(&startTime);
    endTime = startTime;
    for(j = 0; j < msgCnt; j++){
      if (cronTime(NULL) > startTime + ntohl(icmsg->timeOut)*cronMILLIS)
	break;
      opmsg->packetNum = htons(j);
      coreAPI->unicast(&receiverIdent, &opmsg->header, 5, 0); 
      if (htons(icmsg->intPktSpace)!=0 && (j % htons(icmsg->trainSize)) == 0) {
	struct timespec del;
	struct timespec rem;
	del.tv_sec = htons(icmsg->intPktSpace) / cronSECONDS;
	del.tv_nsec = (htons(icmsg->intPktSpace) - (del.tv_sec * cronSECONDS)) * 1000 * 1000;
#ifndef WINDOWS
	nanosleep(&del, &rem);
#else
    SleepEx(del.tv_sec * 1000 + del.tv_nsec / 1000000, TRUE);
#endif
      }	
    }
    SEMAPHORE_DOWN(sem);    
    suspendCron();
    delCronJob((CronJob)&semaUp,
	       0,
	       sem);
    resumeCron();
    results[currIteration].time = endTime-startTime;
    results[currIteration].packets = receiveCnt;
  }
  SEMAPHORE_FREE(sem);
  MUTEX_UNLOCK(&lock);

  /* Lets see what the raw results are */
  for(i = 0; i <  msgIter; i++){
    LOG(LOG_EVERYTHING, 
	"iter[%d], packets %d/%d, time %d ms",
	i,
	results[i].packets,
	msgCnt,
	results[i].time); 
  }

  sum_loss = msgCnt - results[0].packets;
  ocmsg->max_loss = htons(msgCnt - results[0].packets);
  ocmsg->min_loss = htons(msgCnt - results[0].packets);
  sum_time = results[0].time;
  ocmsg->max_time = htons(results[0].time);
  ocmsg->min_time = htons(results[0].time);
  for(i = 1; i < msgIter; i++) {
    LOG(LOG_EVERYTHING, 
	" iteration=%d", 
	i);
    sum_loss += msgCnt - results[i].packets;
    if(msgCnt-results[i].packets > htons(ocmsg->max_loss))
      ocmsg->max_loss = htons(msgCnt - results[i].packets);

    if(msgCnt-results[i].packets < htons(ocmsg->min_loss))
      ocmsg->min_loss = htons(msgCnt - results[i].packets);

    sum_time += results[i].time;
    if(results[i].time > htons(ocmsg->max_time))
      ocmsg->max_time = htons(results[i].time);

    if(results[i].time < htons(ocmsg->min_time))
      ocmsg->min_time = htons(results[i].time); 
  } 
  ocmsg->mean_loss = ((float)sum_loss/(float)msgIter);
  ocmsg->mean_time = ((float)sum_time/(float)msgIter);
  
  sum_variance_time = 0.0;
  sum_variance_loss = 0.0;
  for(i = 0; i < msgIter; i++){
    LOG(LOG_DEBUG,
	"TBENCH: iteration=%d msgIter=%d", 
	i,
	msgIter);
    sum_variance_time += (results[i].time - ocmsg->mean_time)*
      (results[i].time - ocmsg->mean_time); 

    sum_variance_loss += ((msgCnt - results[i].packets) - ocmsg->mean_loss)*
      ((msgCnt - results[i].packets) - ocmsg->mean_loss); 
  }
  ocmsg->variance_time = sum_variance_time/(msgIter-1);
  ocmsg->variance_loss = sum_variance_loss/(msgIter-1);

  ocmsg->header.size = htons(sizeof(TBENCH_CS_MESSAGE));
  ocmsg->header.type = htons(TBENCH_CS_PROTO_REPLY);

  LOG(LOG_DEBUG, 
      "calling writeToSocket");
  if (SYSERR == coreAPI->sendToClient(client,
				      &ocmsg->header))
    return;
  FREE(opmsg);
  FREE(ocmsg);
  FREE(results);
  LOG(LOG_DEBUG,
      "finishing benchmark");
}

/**
 * Initialize the AFS module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 * @return SYSERR on errors
 */
int initialize_module_tbench(CoreAPIForApplication * capi) {
  int ok = OK;

  MUTEX_CREATE(&lock);
  MUTEX_CREATE(&lockCnt);
  coreAPI = capi;
  if (SYSERR == capi->registerHandler(TBENCH_p2p_PROTO_REPLY,
				      &handleTBenchReply))
    ok = SYSERR;
  if (SYSERR == capi->registerHandler(TBENCH_p2p_PROTO_REQUEST,
				      &handleTBenchReq))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(TBENCH_CS_PROTO_REQUEST,
					    (CSHandler)&csHandleTBenchRequest))
    ok = SYSERR;
  return ok;
}

void done_module_tbench() {
  coreAPI->unregisterHandler(TBENCH_p2p_PROTO_REQUEST,
			   &handleTBenchReq);
  coreAPI->unregisterHandler(TBENCH_p2p_PROTO_REPLY,
			   &handleTBenchReply);
  coreAPI->unregisterClientHandler(TBENCH_CS_PROTO_REQUEST,
				   (CSHandler)&csHandleTBenchRequest);
  MUTEX_DESTROY(&lock);
  MUTEX_DESTROY(&lockCnt);
  coreAPI = NULL;
}

/* end of tbench.c */
