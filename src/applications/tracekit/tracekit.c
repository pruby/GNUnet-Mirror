/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/tracekit/tracekit.c
 * @brief implementation of the tracekit protocol
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "tracekit.h"

static CoreAPIForApplication * coreAPI = NULL;
static Mutex lock;
static unsigned int clientCount = 0;
static ClientHandle * clients = NULL;

#if VERBOSE_STATS
static int stat_cs_requests;
static int stat_cs_replies;
static int stat_p2p_requests;
static int stat_p2p_replies;
#endif

typedef struct {
  PeerIdentity initiator;
  PeerIdentity replyTo;
  TIME_T timestamp;  
  unsigned int priority;
} RTE;

#define MAXROUTE 64

static RTE * routeTable[MAXROUTE];

static int handlep2pReply(const PeerIdentity * sender,
			  const p2p_HEADER * message) {
  unsigned int i;
  unsigned int hostCount;
  TRACEKIT_p2p_REPLY * reply;
  EncName initiator;
  EncName sen;

  hash2enc(&sender->hashPubKey,
	   &sen);
  hostCount = (ntohs(message->size)-sizeof(TRACEKIT_p2p_REPLY))/sizeof(PeerIdentity);
  if (ntohs(message->size) !=
      sizeof(TRACEKIT_p2p_REPLY)+hostCount*sizeof(PeerIdentity)) {
    LOG(LOG_WARNING,
	_("Received invalid '%s' message from '%s'.\n"),
	"TRACEKIT_p2p_PROBE",
	&sen);
    return SYSERR;
  }
  reply = (TRACEKIT_p2p_REPLY*)message;
#if VERBOSE_STATS
  statChange(stat_p2p_replies, 1);
#endif
  hash2enc(&reply->initiatorId.hashPubKey,
	   &initiator);
  LOG(LOG_DEBUG,
      "TRACEKIT: Sending reply back to initiator '%s'.\n",
      &initiator);
  MUTEX_LOCK(&lock);
  for (i=0;i<MAXROUTE;i++) {
    if (routeTable[i] == NULL)
      continue;
    if ( (routeTable[i]->timestamp == (TIME_T)ntohl(reply->initiatorTimestamp)) &&
	 (equalsHashCode160(&routeTable[i]->initiator.hashPubKey,
			    &reply->initiatorId.hashPubKey) ) ) {
      LOG(LOG_DEBUG,
	  "TRACEKIT: found matching entry in routing table\n");
      if (equalsHashCode160(&coreAPI->myIdentity->hashPubKey,
			    &routeTable[i]->replyTo.hashPubKey) ) {
	unsigned int idx;
	TRACEKIT_CS_REPLY * csReply;

	idx = ntohl(reply->clientId);
	LOG(LOG_DEBUG,
	    "TRACEKIT: I am initiator, sending to client.\n");
	if (idx >= clientCount) {
	  BREAK();
	  continue; /* discard */
	}
	if (clients[idx] == NULL) {
	  LOG(LOG_DEBUG,
	      "TRACEKIT: received response on slot %u, but client already exited.\n",
	      idx);
	  continue; /* discard */
	}
	
	csReply = MALLOC(sizeof(TRACEKIT_CS_REPLY)+hostCount*sizeof(PeerIdentity));
	/* build msg */
	csReply->header.size 
	  = htons(sizeof(TRACEKIT_CS_REPLY)+hostCount*sizeof(PeerIdentity));
	csReply->header.type 
	  = htons(TRACEKIT_CS_PROTO_REPLY);
	csReply->responderId 
	  = reply->responderId;
	memcpy(&((TRACEKIT_CS_REPLY_GENERIC*)csReply)->peerList[0],
	       &((TRACEKIT_p2p_REPLY_GENERIC*)reply)->peerList[0],
	       hostCount * sizeof(PeerIdentity));
#if VERBOSE_STATS
	statChange(stat_cs_replies, 1);
#endif
	coreAPI->sendToClient(clients[idx],
			      &csReply->header);
	FREE(csReply);
      } else {
	EncName hop;

	hash2enc(&routeTable[i]->replyTo.hashPubKey,
		 &hop);
	LOG(LOG_DEBUG,
	    "TRACEKIT: forwarding to next hop '%s'\n",
	    &hop);
#if VERBOSE_STATS
	statChange(stat_p2p_replies, 1);
#endif
	coreAPI->unicast(&routeTable[i]->replyTo,
			 message,
			 routeTable[i]->priority,
			 0);
      }
    }
  }
  MUTEX_UNLOCK(&lock);
  return OK;
}


typedef struct {
  TRACEKIT_p2p_REPLY_GENERIC * reply;
  int max;
  int pos;
} Closure;

static void getPeerCallback(const PeerIdentity * id,
			    Closure * closure) {
  if (closure->pos < closure->max) {
    /* check needed since #connections may change anytime! */
    closure->reply->peerList[closure->pos++] = *id;
  }
}

static void transmit(const PeerIdentity * id,
		     TRACEKIT_p2p_PROBE * pro) {
  if (! hostIdentityEquals(id,
			   &pro->initiatorId))
    coreAPI->unicast(id,
		     &pro->header,
		     ntohl(pro->priority),
		     0);
}

static int handlep2pProbe(const PeerIdentity * sender,
			  const p2p_HEADER * message) {
  TRACEKIT_p2p_REPLY * reply;
  TRACEKIT_p2p_PROBE * msg;
  Closure closure;
  int i;
  int sel;
  int hops;
  TIME_T oldest;
  int count;
  unsigned int size;
  EncName init;
  EncName sen;
  TIME_T now;

  hash2enc(&sender->hashPubKey,
	   &sen);
  if (ntohs(message->size) != 
      sizeof(TRACEKIT_p2p_PROBE)) {
    LOG(LOG_WARNING,
	_("Received invalid '%s' message from '%s'.\n"),
	"TRACEKIT_p2p_PROBE",
	&sen);
    return SYSERR;
  }
  LOG(LOG_DEBUG,
      "TRACEKIT: received probe\n");
#if VERBOSE_STATS
  statChange(stat_p2p_requests, 1);
#endif
  TIME(&now);
  msg = (TRACEKIT_p2p_PROBE*) message;
  if ((TIME_T)ntohl(msg->timestamp) > 3600 + now) {
    LOG(LOG_DEBUG,
	"TRACEKIT: probe has timestamp in the far future (%d > %d), dropping\n",
	ntohl(msg->timestamp), 
	3600 + now);
    return SYSERR; /* Timestamp is more than 1h in the future. Invalid! */
  }
  hash2enc(&msg->initiatorId.hashPubKey,
	   &init);
  MUTEX_LOCK(&lock);
  /* test if already processed */
  for (i=0;i<MAXROUTE;i++) {
    if (routeTable[i] == NULL)
      continue;
    if ( (routeTable[i]->timestamp == (TIME_T)ntohl(msg->timestamp)) &&
	 equalsHashCode160(&routeTable[i]->initiator.hashPubKey,
			   &msg->initiatorId.hashPubKey) ) {
      LOG(LOG_DEBUG,
	  "TRACEKIT-PROBE %d from '%s' received twice (slot %d), ignored\n",
	  ntohl(msg->timestamp),
	  &init,
	  i);
      MUTEX_UNLOCK(&lock);
      return OK;
    }
  }
  /* no, find and kill oldest entry */
  oldest = ntohl(msg->timestamp);
  sel = -1;
  for (i=0;i<MAXROUTE;i++) {
    if (routeTable[i] == NULL) {
      sel = i;
      oldest = 0;
      continue;
    }
    if (oldest > routeTable[i]->timestamp) {
      oldest = routeTable[i]->timestamp;
      sel = i;
    }
    if (routeTable[i]->timestamp < now - 3600) {
      /* side-effect: drop very old entries */
      FREE(routeTable[i]);
      routeTable[i] = NULL;
    }
  }
  if (sel == -1) {
    MUTEX_UNLOCK(&lock);
    LOG(LOG_INFO,
	_("TRACEKIT: routing table full, trace request dropped\n"));
    return OK;
  }
  if (routeTable[sel] == NULL)
    routeTable[sel] = MALLOC(sizeof(RTE));
  routeTable[sel]->timestamp 
    = ntohl(msg->timestamp);
  routeTable[sel]->priority
    = ntohl(msg->priority);
  routeTable[sel]->initiator 
    = msg->initiatorId;
  routeTable[sel]->replyTo
    = *sender;  
  MUTEX_UNLOCK(&lock);
  LOG(LOG_DEBUG,
      "TRACEKIT-PROBE started at %d by peer '%s' received, processing in slot %d with %u hops\n",
      ntohl(msg->timestamp),
      &init,
      sel,
      ntohl(msg->hopsToGo));
  count = coreAPI->forAllConnectedNodes(NULL, NULL);
  hops = ntohl(msg->hopsToGo);
  /* forward? */
  if (hops > 0) {
    msg->hopsToGo = htonl(hops-1);
    coreAPI->forAllConnectedNodes((PerNodeCallback) & transmit,
				  msg);
#if VERBOSE_STATS
    statChange(stat_p2p_requests, 
	       count);
#endif
  }
  /* build local reply */
  size = sizeof(TRACEKIT_p2p_REPLY) + count*sizeof(PeerIdentity);
  reply = MALLOC(size);
  closure.reply = (TRACEKIT_p2p_REPLY_GENERIC*) reply;
  closure.max = count;
  closure.pos = 0;
  coreAPI->forAllConnectedNodes((PerNodeCallback)&getPeerCallback,
				&closure);
  reply->header.type 
    = htons(TRACEKIT_p2p_PROTO_REPLY);
  reply->initiatorId 
    = msg->initiatorId;
  reply->responderId
    = *(coreAPI->myIdentity);
  reply->initiatorTimestamp 
    = msg->timestamp;
  reply->clientId
    = msg->clientId;
  /* break up into chunks of MTU size! */
  while (size >= sizeof(TRACEKIT_p2p_REPLY)) {
    int rest;
    int maxBytes;
    int batchSize;

    if (size > 1024) {     
      batchSize = (1024 - sizeof(TRACEKIT_p2p_REPLY) / sizeof(PeerIdentity));
      maxBytes = sizeof(TRACEKIT_p2p_REPLY) + sizeof(PeerIdentity) * batchSize;
    } else {
      batchSize = (size - sizeof(TRACEKIT_p2p_REPLY)) / sizeof(PeerIdentity); 
      maxBytes = size;
    }
    reply->header.size
      = htons(maxBytes);
    if (equalsHashCode160(&coreAPI->myIdentity->hashPubKey,
			  &sender->hashPubKey)) {
      handlep2pReply(coreAPI->myIdentity,
		     &reply->header);
    } else {
      coreAPI->unicast(sender,
		       &reply->header,
		       ntohl(msg->priority),
		       0);
#if VERBOSE_STATS
      statChange(stat_p2p_replies, 1);
#endif
    }
    rest = size - maxBytes;
    memcpy(&((TRACEKIT_p2p_REPLY_GENERIC*)reply)->peerList[0],
	   &((TRACEKIT_p2p_REPLY_GENERIC*)reply)->peerList[maxBytes - sizeof(TRACEKIT_p2p_REPLY)],
	   rest);
    size -= maxBytes;
    if (rest == 0)
      break;
  }
  FREE(reply);
  return OK;
}

static int csHandle(ClientHandle client,
		    const CS_HEADER * message) {
  int i;
  int idx;
  TRACEKIT_CS_PROBE * csProbe;
  TRACEKIT_p2p_PROBE p2pProbe;

#if VERBOSE_STATS
  statChange(stat_cs_requests, 1);
#endif
  LOG(LOG_DEBUG,
      "TRACEKIT: client sends probe request\n");

  /* build probe, broadcast */
  csProbe = (TRACEKIT_CS_PROBE*) message;
  if (ntohs(csProbe->header.size) != 
      sizeof(TRACEKIT_CS_PROBE) ) {
    LOG(LOG_WARNING,
	_("TRACEKIT: received invalid '%s' message\n"),
	"TRACEKIT_CS_PROBE");
    return SYSERR;
  }

  MUTEX_LOCK(&lock);
  idx = -1;
  for (i=0;i<clientCount;i++) {
    if (clients[i] == client) {
      idx = i;
      break;
    }    
    if ( (clients[i] == NULL) &&
	 (idx == -1) ) {
      idx = i;
      break;
    }
  }
  if (idx == -1) {
    GROW(clients,
	 clientCount,
	 clientCount+1);
    idx = clientCount-1;
  }  
  clients[idx] = client;
  MUTEX_UNLOCK(&lock);
  LOG(LOG_DEBUG,
      "TRACEKIT: client joins in slot %u.\n",
      idx);

  p2pProbe.header.size
    = htons(sizeof(TRACEKIT_p2p_PROBE));
  p2pProbe.header.type
    = htons(TRACEKIT_p2p_PROTO_PROBE);
  p2pProbe.clientId
    = htonl(idx);
  p2pProbe.hopsToGo
    = csProbe->hops;
  p2pProbe.timestamp
    = htonl(TIME(NULL));
  p2pProbe.priority
    = csProbe->priority;
  memcpy(&p2pProbe.initiatorId,
	 coreAPI->myIdentity,
	 sizeof(PeerIdentity));
  handlep2pProbe(coreAPI->myIdentity,
		 &p2pProbe.header); /* FIRST send to myself! */
#if VERBOSE_STATS
  statChange(stat_p2p_requests,
	     coreAPI->forAllConnectedNodes(NULL, NULL));
#endif
  return OK;
}

static void clientExitHandler(ClientHandle c) {
  int i;

  MUTEX_LOCK(&lock);
  for (i=0;i<clientCount;i++)
    if (clients[i] == c) {
      LOG(LOG_DEBUG,
	  "TRACEKIT: client in slot %u exits.\n",
	  i);
      clients[i] = NULL;
      break;
    }
  i=clientCount-1;
  while ( (i >= 0) &&
	  (clients[i] == NULL) )
    i--;
  i++;
  if (i != clientCount)
    GROW(clients, 
	 clientCount,
	 i);
  MUTEX_UNLOCK(&lock);
}

int initialize_module_tracekit(CoreAPIForApplication * capi) {
  int ok = OK;

  MUTEX_CREATE(&lock);
  coreAPI = capi;
#if VERBOSE_STATS
  stat_cs_requests 
    = statHandle(_("# client trace requests received"));
  stat_cs_replies
    = statHandle(_("# client trace replies sent"));
  stat_p2p_requests
    = statHandle(_("# p2p trace requests received"));
  stat_p2p_replies
    = statHandle(_("# p2p trace replies sent"));
#endif
  LOG(LOG_DEBUG,
      "TRACEKIT registering handlers %d %d and %d\n",
      TRACEKIT_p2p_PROTO_PROBE,
      TRACEKIT_p2p_PROTO_REPLY,
      TRACEKIT_CS_PROTO_PROBE);
  memset(routeTable, 
	 0, 
	 MAXROUTE*sizeof(RTE*));
  if (SYSERR == capi->registerHandler(TRACEKIT_p2p_PROTO_PROBE,
				      &handlep2pProbe))
    ok = SYSERR;
  if (SYSERR == capi->registerHandler(TRACEKIT_p2p_PROTO_REPLY,
				      &handlep2pReply))
    ok = SYSERR;
  if (SYSERR == capi->registerClientExitHandler(&clientExitHandler))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(TRACEKIT_CS_PROTO_PROBE,
					    (CSHandler)&csHandle))
    ok = SYSERR;
  return ok;
}

void done_module_tracekit() {
  int i;

  coreAPI->unregisterHandler(TRACEKIT_p2p_PROTO_PROBE,
			     &handlep2pProbe);
  coreAPI->unregisterHandler(TRACEKIT_p2p_PROTO_REPLY,
			     &handlep2pReply);
  coreAPI->unregisterClientExitHandler(&clientExitHandler);
  coreAPI->unregisterClientHandler(TRACEKIT_CS_PROTO_PROBE,
				   (CSHandler)&csHandle);
  for (i=0;i<MAXROUTE;i++) {
    FREENONNULL(routeTable[i]);
    routeTable[i] = NULL;
  }  
  GROW(clients,
       clientCount,
       0);
  MUTEX_DESTROY(&lock);
  coreAPI = NULL;
}

/* end of tracekit.c */
