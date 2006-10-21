/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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

static CoreAPIForApplication * coreAPI;

static struct MUTEX * lock;

static unsigned int clientCount;

static struct ClientHandle ** clients;

static struct GE_Context * ectx;

typedef struct {
  PeerIdentity initiator;
  PeerIdentity replyTo;
  TIME_T timestamp;
  unsigned int priority;
} RTE;

#define MAXROUTE 64

static RTE * routeTable[MAXROUTE];

static int handlep2pReply(const PeerIdentity * sender,
			  const MESSAGE_HEADER * message) {
  unsigned int i;
  unsigned int hostCount;
  P2P_tracekit_reply_MESSAGE * reply;
  EncName initiator;
  EncName sen;

  hash2enc(&sender->hashPubKey,
	   &sen);
  hostCount = (ntohs(message->size)-sizeof(P2P_tracekit_reply_MESSAGE))/sizeof(PeerIdentity);
  if (ntohs(message->size) !=
      sizeof(P2P_tracekit_reply_MESSAGE)+hostCount*sizeof(PeerIdentity)) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Received invalid `%s' message from `%s'.\n"),
	   "P2P_tracekit_probe_MESSAGE",
	   &sen);
    return SYSERR;
  }
  reply = (P2P_tracekit_reply_MESSAGE*)message;
  hash2enc(&reply->initiatorId.hashPubKey,
	   &initiator);
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "TRACEKIT: Sending reply back to initiator `%s'.\n",
	 &initiator);
  MUTEX_LOCK(lock);
  for (i=0;i<MAXROUTE;i++) {
    if (routeTable[i] == NULL)
      continue;
    if ( (routeTable[i]->timestamp == (TIME_T)ntohl(reply->initiatorTimestamp)) &&
	 (0 == memcmp(&routeTable[i]->initiator.hashPubKey,
		      &reply->initiatorId.hashPubKey,
		      sizeof(HashCode512)) ) ) {
      GE_LOG(ectx,
	     GE_DEBUG | GE_REQUEST | GE_USER,
	     "TRACEKIT: found matching entry in routing table\n");
      if (0 == memcmp(&coreAPI->myIdentity->hashPubKey,
		      &routeTable[i]->replyTo.hashPubKey,
		      sizeof(HashCode512)) ) {
	unsigned int idx;
	CS_tracekit_reply_MESSAGE * csReply;

	idx = ntohl(reply->clientId);
	GE_LOG(ectx,
	       GE_DEBUG | GE_REQUEST | GE_USER,
	       "TRACEKIT: I am initiator, sending to client.\n");
	if (idx >= clientCount) {
	  GE_BREAK(ectx, 0);
	  continue; /* discard */
	}
	if (clients[idx] == NULL) {
	  GE_LOG(ectx,
		 GE_DEBUG | GE_REQUEST | GE_USER,
		 "TRACEKIT: received response on slot %u, but client already exited.\n",
		 idx);
	  continue; /* discard */
	}
	
	csReply = MALLOC(sizeof(CS_tracekit_reply_MESSAGE)+hostCount*sizeof(PeerIdentity));
	/* build msg */
	csReply->header.size
	  = htons(sizeof(CS_tracekit_reply_MESSAGE)+hostCount*sizeof(PeerIdentity));
	csReply->header.type
	  = htons(CS_PROTO_tracekit_REPLY);
	csReply->responderId
	  = reply->responderId;
	memcpy(&((CS_tracekit_reply_MESSAGE_GENERIC*)csReply)->peerList[0],
	       &((P2P_tracekit_reply_MESSAGE_GENERIC*)reply)->peerList[0],
	       hostCount * sizeof(PeerIdentity));
	coreAPI->sendToClient(clients[idx],
			      &csReply->header);
	FREE(csReply);
      } else {
	EncName hop;

	hash2enc(&routeTable[i]->replyTo.hashPubKey,
		 &hop);
	GE_LOG(ectx,
	       GE_DEBUG | GE_REQUEST | GE_USER,
	       "TRACEKIT: forwarding to next hop `%s'\n",
	       &hop);
	coreAPI->unicast(&routeTable[i]->replyTo,
			 message,
			 routeTable[i]->priority,
			 0);
      }
    }
  }
  MUTEX_UNLOCK(lock);
  return OK;
}


typedef struct {
  PeerIdentity * peers;
  unsigned int max;
  int pos;
} Tracekit_Collect_Trace_Closure;

static void getPeerCallback(const PeerIdentity * id,
			    void * cls) {
  Tracekit_Collect_Trace_Closure * closure = cls;
  if (closure->pos == closure->max) {
    GROW(closure->peers,
	 closure->max,
	 closure->max + 32);
  }
  if (closure->pos < closure->max) {
    /* check needed since #connections may change anytime! */
    closure->peers[closure->pos++] = *id;
  }
}

static void transmit(const PeerIdentity * id,
		     void * cls) {
  P2P_tracekit_probe_MESSAGE * pro = cls;
  if (0 != memcmp(id,
		  &pro->initiatorId,
		  sizeof(PeerIdentity)))
    coreAPI->unicast(id,
		     &pro->header,
		     ntohl(pro->priority),
		     0);
}

static int handlep2pProbe(const PeerIdentity * sender,
			  const MESSAGE_HEADER * message) {
  P2P_tracekit_reply_MESSAGE * reply;
  P2P_tracekit_probe_MESSAGE * msg;
  Tracekit_Collect_Trace_Closure closure;
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
      sizeof(P2P_tracekit_probe_MESSAGE)) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Received invalid `%s' message from `%s'.\n"),
	   "P2P_tracekit_probe_MESSAGE",
	   &sen);
    return SYSERR;
  }
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "TRACEKIT: received probe\n");
  TIME(&now);
  msg = (P2P_tracekit_probe_MESSAGE*) message;
  if ((TIME_T)ntohl(msg->timestamp) > 3600 + now) {
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "TRACEKIT: probe has timestamp in the far future (%d > %d), dropping\n",
	   ntohl(msg->timestamp),
	   3600 + now);
    return SYSERR; /* Timestamp is more than 1h in the future. Invalid! */
  }
  hash2enc(&msg->initiatorId.hashPubKey,
	   &init);
  MUTEX_LOCK(lock);
  /* test if already processed */
  for (i=0;i<MAXROUTE;i++) {
    if (routeTable[i] == NULL)
      continue;
    if ( (routeTable[i]->timestamp == (TIME_T)ntohl(msg->timestamp)) &&
	 0 == memcmp(&routeTable[i]->initiator.hashPubKey,
		     &msg->initiatorId.hashPubKey,
		     sizeof(HashCode512)) ) {
      GE_LOG(ectx,
	     GE_DEBUG | GE_REQUEST | GE_USER,
	     "TRACEKIT-PROBE %d from `%s' received twice (slot %d), ignored\n",
	     ntohl(msg->timestamp),
	     &init,
	     i);
      MUTEX_UNLOCK(lock);
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
    MUTEX_UNLOCK(lock);
    GE_LOG(ectx,
	   GE_INFO | GE_REQUEST | GE_USER,
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
  MUTEX_UNLOCK(lock);
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "TRACEKIT-PROBE started at %d by peer `%s' received, processing in slot %d with %u hops\n",
	 ntohl(msg->timestamp),
	 &init,
	 sel,
	 ntohl(msg->hopsToGo));
  hops = ntohl(msg->hopsToGo);
  /* forward? */
  if (hops > 0) {
    msg->hopsToGo = htonl(hops-1);
    coreAPI->forAllConnectedNodes(&transmit,
				  msg);
  }
  closure.peers = NULL;
  closure.max = 0;
  closure.pos = 0;
  coreAPI->forAllConnectedNodes(&getPeerCallback,
				&closure);
  /* build local reply */
  while (closure.pos > 0) {
    count = closure.pos;
    if (count > 60000 / sizeof(PeerIdentity))
      count = 60000 / sizeof(PeerIdentity);
    size = sizeof(P2P_tracekit_reply_MESSAGE) + count*sizeof(PeerIdentity);
    reply = MALLOC(size);
    reply->header.size
      = htons(size);
    reply->header.type
      = htons(P2P_PROTO_tracekit_REPLY);
    reply->initiatorId
      = msg->initiatorId;
    reply->responderId
      = *(coreAPI->myIdentity);
    reply->initiatorTimestamp
      = msg->timestamp;
    reply->clientId
      = msg->clientId;
    memcpy(&reply[1],
	   &closure.peers[closure.pos - count],
	   count * sizeof(PeerIdentity));
    if (equalsHashCode512(&coreAPI->myIdentity->hashPubKey,
			  &sender->hashPubKey)) {
      handlep2pReply(coreAPI->myIdentity,
		     &reply->header);
    } else {
      coreAPI->unicast(sender,
		       &reply->header,
		       ntohl(msg->priority),
		       0);
    }
    closure.pos -= count;
    FREE(reply);
  }
  GROW(closure.peers,
       closure.max,
       0);
  return OK;
}

static int csHandle(struct ClientHandle * client,
		    const MESSAGE_HEADER * message) {
  int i;
  int idx;
  CS_tracekit_probe_MESSAGE * csProbe;
  P2P_tracekit_probe_MESSAGE p2pProbe;

  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "TRACEKIT: client sends probe request\n");

  /* build probe, broadcast */
  csProbe = (CS_tracekit_probe_MESSAGE*) message;
  if (ntohs(csProbe->header.size) !=
      sizeof(CS_tracekit_probe_MESSAGE) ) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("TRACEKIT: received invalid `%s' message\n"),
	   "CS_tracekit_probe_MESSAGE");
    return SYSERR;
  }

  MUTEX_LOCK(lock);
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
  MUTEX_UNLOCK(lock);
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "TRACEKIT: client joins in slot %u.\n",
	 idx);

  p2pProbe.header.size
    = htons(sizeof(P2P_tracekit_probe_MESSAGE));
  p2pProbe.header.type
    = htons(P2P_PROTO_tracekit_PROBE);
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
  return OK;
}

static void clientExitHandler(struct ClientHandle * c) {
  int i;

  MUTEX_LOCK(lock);
  for (i=0;i<clientCount;i++)
    if (clients[i] == c) {
      GE_LOG(ectx,
	     GE_DEBUG | GE_REQUEST | GE_USER,
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
  MUTEX_UNLOCK(lock);
}

int initialize_module_tracekit(CoreAPIForApplication * capi) {
  int ok = OK;

  ectx = capi->ectx;
  lock = MUTEX_CREATE(NO);
  coreAPI = capi;
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "TRACEKIT registering handlers %d %d and %d\n",
	 P2P_PROTO_tracekit_PROBE,
	 P2P_PROTO_tracekit_REPLY,
	 CS_PROTO_tracekit_PROBE);
  memset(routeTable,
	 0,
	 MAXROUTE*sizeof(RTE*));
  if (SYSERR == capi->registerHandler(P2P_PROTO_tracekit_PROBE,
				      &handlep2pProbe))
    ok = SYSERR;
  if (SYSERR == capi->registerHandler(P2P_PROTO_tracekit_REPLY,
				      &handlep2pReply))
    ok = SYSERR;
  if (SYSERR == capi->registerClientExitHandler(&clientExitHandler))
    ok = SYSERR;
  if (SYSERR == capi->registerClientHandler(CS_PROTO_tracekit_PROBE,
					    (CSHandler)&csHandle))
    ok = SYSERR;
  GE_ASSERT(capi->ectx,
	    0 == GC_set_configuration_value_string(capi->cfg,
						   capi->ectx,
						   "ABOUT",
						   "tracekit",
						   gettext_noop("allows mapping of the network topology")));
  return ok;
}

void done_module_tracekit() {
  int i;

  coreAPI->unregisterHandler(P2P_PROTO_tracekit_PROBE,
			     &handlep2pProbe);
  coreAPI->unregisterHandler(P2P_PROTO_tracekit_REPLY,
			     &handlep2pReply);
  coreAPI->unregisterClientExitHandler(&clientExitHandler);
  coreAPI->unregisterClientHandler(CS_PROTO_tracekit_PROBE,
				   &csHandle);
  for (i=0;i<MAXROUTE;i++) {
    FREENONNULL(routeTable[i]);
    routeTable[i] = NULL;
  }
  GROW(clients,
       clientCount,
       0);
  MUTEX_DESTROY(lock);
  lock = NULL;
  coreAPI = NULL;
}

/* end of tracekit.c */
