/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/esed2/policy.c
 * @author Christian Grothoff
 *
 * The code in this module is responsible for enforcing
 * the anonymity policy set by the user.
 */ 

#include "gnunet_afs_esed2.h"
#include "platform.h"

/**
 * Socket to communicate with gnunetd.
 */
static GNUNET_TCP_SOCKET * sock = NULL;

/**
 * CoreAPI, null if we are using the socket!
 */
static CoreAPIForApplication * coreAPI;

/**
 * Which value did the user specify for the sendPolicy?
 */
static int sendPolicy;

/**
 * Which value did the user specify for the receivePolicy?
 */
static int receivePolicy;

/* ************* traffic information from the core ********* */

/**
 * Last time traffic information was obtained.
 */ 
static cron_t lastPoll = 0;

/**
 * Mutex for synchronizing access.
 */
static Mutex lock;

/**
 * Number of peers that were active at the last poll (since this is
 * always type sensitive, not totals).
 */
static unsigned int chkPeers = 0;
static unsigned int hashPeers = 0;
static unsigned int queryPeers = 0;

/**
 * Number of bytes of unmatched bytes of traffic at the last poll
 * (totals and separate for the 3 message types).
 */
static unsigned int totalReceiveBytes = 0;
static unsigned int totalCHKBytes = 0;
static unsigned int total3HASHBytes = 0;
static unsigned int totalQueryBytes = 0;

/**
 * Poll gnunetd via TCP about traffic information.
 * Note that we only send the request if we would
 * otherwise potentially have to refuse messages.
 */
static void pollSocket() {
  cron_t now;
  CS_TRAFFIC_INFO * info;
  CS_TRAFFIC_REQUEST req;
  int i;

  cronTime(&now);
  MUTEX_LOCK(&lock);
  if (now - lastPoll < TTL_DECREMENT) {
    MUTEX_UNLOCK(&lock);
    return; /* poll at most every ttl-decrement time units */
  }
  lastPoll = now;
  req.header.size 
    = htons(sizeof(CS_TRAFFIC_REQUEST));
  req.header.type
    = htons(CS_PROTO_TRAFFIC_QUERY);
  req.timePeriod 
    = htonl(TTL_DECREMENT);
  if (SYSERR == writeToSocket(sock,
			      &req.header)) {
    MUTEX_UNLOCK(&lock);
    LOG(LOG_WARNING,
	_("Failed to query gnunetd about traffic conditions.\n"));
    return; 
  }
  info = NULL;
  if (SYSERR == readFromSocket(sock,
			       (CS_HEADER**)&info)) {
    MUTEX_UNLOCK(&lock); 
    LOG(LOG_WARNING,
	_("Did not receive reply from gnunetd about traffic conditions.\n"));
    return; 
  }
  if ( (ntohs(info->header.type) != 
	CS_PROTO_TRAFFIC_INFO) ||
       (ntohs(info->header.size) != 
	sizeof(CS_TRAFFIC_INFO) + ntohl(info->count)*sizeof(TRAFFIC_COUNTER)) ) {
    MUTEX_UNLOCK(&lock); 
    BREAK();
    return;
  }

  for (i=ntohl(info->count)-1;i>=0;i--) {
    TRAFFIC_COUNTER * tc = &((CS_TRAFFIC_INFO_GENERIC*)info)->counters[i];
    if ((tc->flags & TC_TYPE_MASK) == TC_RECEIVED) {
      totalReceiveBytes += tc->count * tc->avrg_size;
      switch (ntohs(tc->type)) {
      case AFS_p2p_PROTO_QUERY:
	totalQueryBytes += tc->count * tc->avrg_size;
	queryPeers += (ntohs(tc->flags) & TC_DIVERSITY_MASK);
	break;
      case AFS_p2p_PROTO_3HASH_RESULT:
	total3HASHBytes += tc->count * tc->avrg_size;
	hashPeers += (ntohs(tc->flags) & TC_DIVERSITY_MASK);
	break;
      case AFS_p2p_PROTO_CHK_RESULT:
	totalCHKBytes += tc->count * tc->avrg_size;
	chkPeers += (ntohs(tc->flags) & TC_DIVERSITY_MASK);
	break;
      default:
	break;
      } /* end switch */
    } /* end if received */
  } /* end for all counters */

  FREE(info);
  MUTEX_UNLOCK(&lock);
}

/**
 * Poll gnunet core via coreapi about traffic information.
 */
static void pollCAPI() {
  cron_t now;
  unsigned short avgMessageSize;
  unsigned short messageCount;
  unsigned int peerCount;
  unsigned int timeDistribution;
  unsigned short messageType;

  cronTime(&now);
  MUTEX_LOCK(&lock);
  if (now - lastPoll < TTL_DECREMENT) {
    MUTEX_UNLOCK(&lock);
    return; /* don't bother */
  }
  lastPoll = now;

  for (messageType=0;messageType<MAX_p2p_PROTO_USED;messageType++) {
    coreAPI->getTrafficStats(messageType,
			     TC_RECEIVED,
			     TTL_DECREMENT,
			     &avgMessageSize,
			     &messageCount,
			     &peerCount,
			     &timeDistribution);
    totalReceiveBytes += messageCount * avgMessageSize;
    switch (messageType) {
    case AFS_p2p_PROTO_QUERY:
      totalQueryBytes += messageCount * avgMessageSize;
      queryPeers += peerCount;
      break;
    case AFS_p2p_PROTO_3HASH_RESULT:
      total3HASHBytes += messageCount * avgMessageSize;
      hashPeers += peerCount;
      break;
    case AFS_p2p_PROTO_CHK_RESULT:
      totalCHKBytes += messageCount * avgMessageSize;
      chkPeers += peerCount;
      break;
    default:
      break;
    } /* end switch */
  }
  MUTEX_UNLOCK(&lock);
}

/**
 * Test if the required number of peers were active.
 *
 * @param port which protocol are we interested in
 * @param peerCount how many peers are required
 * @return YES if we had sufficient amounts of traffic, NO if not
 */
static int checkPeerPolicy(unsigned short port,
			   unsigned int peerCount) {
  switch (port) {
  case AFS_p2p_PROTO_QUERY:
    if (queryPeers >= peerCount)
      return YES;
    else
      return NO;
  case AFS_p2p_PROTO_CHK_RESULT:
    if (chkPeers >= peerCount)
      return YES;
    else
      return NO;
  case AFS_p2p_PROTO_3HASH_RESULT:
    if (hashPeers >= peerCount)
      return YES;
    else
      return NO;
  default: 
    return NO;
  }
}

/**
 * Test if the required amount of traffic is available.
 *
 * @param port what type of traffic are we interested in?
 * @param size how much traffic do we intend to produce?
 * @param byteRatio how much cover traffic do we need (byteRatio*size)
 * @param strictMatch does only traffic of exactly the same
 *        type (port) count?
 * @return YES if enough cover traffic was be found, NO if not.
 */
static int checkRatioPolicy(unsigned short port,
			    unsigned short size,
			    unsigned int byteRatio,
			    int strictMatch) {
  unsigned int cost;

  cost = byteRatio * size;
  if (strictMatch) {
    switch (port) {
    case AFS_p2p_PROTO_QUERY:
      if (totalQueryBytes < cost)
	return NO;
      totalQueryBytes -= cost;
      return YES;
    case AFS_p2p_PROTO_CHK_RESULT:
      if (totalCHKBytes < cost)
	return NO;
      totalCHKBytes -= cost;
      return YES;
    case AFS_p2p_PROTO_3HASH_RESULT:
      if (total3HASHBytes < cost)
	return NO;
      total3HASHBytes -= cost;
      return YES;
    default: 
      return NO;
    }
  } else {
    if (totalReceiveBytes < cost)
      return NO;
    totalReceiveBytes -= cost;
    return YES;
  }
}

/**
 * Initialize the module.
 *
 * @param capi the GNUnet core API (NULL if we are a client)
 */
void initAnonymityPolicy(CoreAPIForApplication * capi) {
  receivePolicy = getConfigurationInt("AFS",
				   "ANONYMITY-RECEIVE");
  sendPolicy = getConfigurationInt("AFS",
		 	           "ANONYMITY-SEND");
  if ( (0 >= sendPolicy) &&
       (0 >= receivePolicy) )
    return;

  coreAPI = capi;
  if (capi == NULL) {
    sock = getClientSocket();
    if (sock == NULL)
      errexit(" could not connect to gnunetd\n");
  }
  MUTEX_CREATE(&lock);
}

/**
 * Shutdown the module.
 */
void doneAnonymityPolicy() {
  if (sock != NULL) {
    MUTEX_DESTROY(&lock);
    releaseClientSocket(sock);
  }
  if (coreAPI != NULL) {
    MUTEX_DESTROY(&lock);		  
    coreAPI = NULL;
  }
}

/**
 * Test if the policy requirements are fullfilled.
 *
 * @param policyValue the anonymity degree required by the user
 * @param type the message type
 * @param size the size of the message
 * @return YES if this isok for the policy, NO if not.
 */
static int checkPolicy(int policyValue,
		       unsigned short type,
		       unsigned short size) {
  unsigned int peerCount;
  unsigned int byteRatio;

  if (policyValue <= 0)
    return YES; /* no policy */
  if (policyValue >= 1000) {
    byteRatio = policyValue / 1000;
    peerCount = policyValue % 1000;
  } else {
    byteRatio = policyValue;
    peerCount = 0;
  }
  if (peerCount > 0)
    if (NO == checkPeerPolicy(type, 
			      peerCount))
      return NO;
  if (byteRatio > 0)
    if (NO == checkRatioPolicy(type, 
			       size,
			       byteRatio,
			       policyValue >= 1000))
      return NO;
  return YES;
}

/**
 * Check if the anonymity policy would be violated if
 * a message of the given type is sent.
 * @param type the request type of the message that will be
 *        transmitted
 * @param size the size of the message that will be
 *        transmitted
 * @return YES if this is ok for the policy, NO if not
 */
int checkAnonymityPolicy(unsigned short type,
			 unsigned short size) {
  if ( (sock == NULL) &&
       (coreAPI == NULL) )
    return YES;
  if (sock == NULL)
    pollCAPI();
  else
    pollSocket();
  switch (type) {
  case AFS_CS_PROTO_QUERY:
    return checkPolicy(receivePolicy, type, size);
  case AFS_CS_PROTO_RESULT_3HASH:
  case AFS_CS_PROTO_RESULT_CHK:
    return checkPolicy(sendPolicy, type, size);
  default:
    return YES;
  }
}
			 
/* end of policy.c */
