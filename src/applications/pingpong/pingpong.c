/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file server/pingpong.c
 * @brief Pings a host and triggers an action if a reply is received.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_pingpong_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_transport_service.h"

/**
 * Ping message (test if address actually corresponds to
 * the advertised GNUnet host. The receiver responds with
 * exactly the same message, except that it is now a pong.
 * This message can be send in plaintext and without padding
 * and typically does make little sense (except keepalive)
 * for an encrypted (authenticated) tunnel.
 * <br>
 * There is also no proof that the other side actually
 * has the acclaimed identity, the only thing that is
 * proved is that the other side can be reached via
 * the underlying protocol and that it is a GNUnet node.
 * <br>
 * The challenge prevents an inept adversary from sending
 * us a hello and then an arbitrary PONG reply (adversary
 * must at least be able to sniff our outbound traffic).
 */
typedef struct {
  MESSAGE_HEADER header;

  /**
   * Which peer is the target of the ping? This is important since for
   * plaintext-pings, we need to catch faulty advertisements that
   * advertise a correct address but with the wrong public key.
   */
  PeerIdentity receiver;

  /**
   * The challenge is a (pseudo) random number that an adversary that
   * wants to fake a pong message would have to guess. Since even if
   * the number is guessed, the security impact is at most some wasted
   * resources, 32 bit are more than enough.
   */
  int challenge;

} P2P_pingpong_MESSAGE;

#define DEBUG_PINGPONG NO

#define MAX_PING_PONG 256

typedef struct {
  PeerIdentity receiverIdentity;
  int challenge;
  int plaintext;
  CronJob method;
  void * data;
  TIME_T sendTime;
} PingPongEntry;

static PingPongEntry * pingPongs;

static struct MUTEX * pingPongLock;

static CoreAPIForApplication * coreAPI;

static Transport_ServiceAPI * transport;

static Identity_ServiceAPI * identity;

static Stats_ServiceAPI * stats;

static struct GE_Context * ectx;

static int stat_encryptedPongReceived;

static int stat_plaintextPongReceived;

static int stat_pingReceived;

static int stat_pingCreated;

static int stat_pongSent;

static int stat_plaintextPingSent;

static int stat_ciphertextPingSent;

/**
 * We received a PING message, send the PONG reply.
 */	
static int pingReceived(const PeerIdentity * sender,
			const MESSAGE_HEADER * msg) {
  P2P_pingpong_MESSAGE * pmsg;

  if (ntohs(msg->size) != sizeof(P2P_pingpong_MESSAGE) ) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER | GE_DEVELOPER,
	   _("Received malformed `%s' message. Dropping.\n"),
	   "ping");
    return SYSERR;
  }
  if (stats != NULL)
    stats->change(stat_pingReceived, 1);
  pmsg = (P2P_pingpong_MESSAGE *) msg;
  if (0 != memcmp(coreAPI->myIdentity,
		  &pmsg->receiver,
		  sizeof(PeerIdentity))) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_ADMIN,
	   _("Received ping for another peer. Dropping.\n"));
    return SYSERR; /* not for us */
  }

#if DEBUG_PINGPONG
  EncName enc;

  hash2enc(&sender->hashPubKey, &enc);
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Received ping from peer %s.\n",
	 &enc);
#endif

  pmsg->header.type = htons(p2p_PROTO_PONG);
  if (stats != NULL)
    stats->change(stat_pingReceived, 1);
  coreAPI->unicast(sender,
		   &pmsg->header,
		   EXTREME_PRIORITY,
		   0); /* send now! */
  if (stats != NULL)
    stats->change(stat_pongSent, 1);
  return OK;
}

static int sendPlaintext(const PeerIdentity * peer,
			 const P2P_pingpong_MESSAGE * msg) {
  TSession * mytsession;
  int ret;

  mytsession = transport->connectFreely(peer, YES);
  if (mytsession == NULL)
    return SYSERR;
  ret = coreAPI->sendPlaintext(mytsession,
			       (char*)msg,
			       sizeof(P2P_pingpong_MESSAGE));
  transport->disconnect(mytsession);
  return ret;
}

/**
 * We received a PING message, send the PONG reply and notify the
 * connection module that the session is still life.
 */	
static int plaintextPingReceived(const PeerIdentity * sender,
				 const MESSAGE_HEADER * hmsg,
				 TSession * tsession) {
#if DEBUG_PINGPONG
  EncName enc;
#endif
  P2P_pingpong_MESSAGE * pmsg;

  if (ntohs(hmsg->size) != sizeof(P2P_pingpong_MESSAGE) ) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER | GE_DEVELOPER,
	   _("Received malformed `%s' message. Dropping.\n"),
	   "ping");
    return SYSERR;
  }
  pmsg = (P2P_pingpong_MESSAGE *) hmsg;
  if (0 != memcmp(coreAPI->myIdentity,
		  &pmsg->receiver,
		  sizeof(PeerIdentity))) {
    GE_LOG(ectx,
	   GE_INFO | GE_REQUEST | GE_ADMIN,
	   _("Received PING not destined for us!\n"));
    return SYSERR; /* not for us */
  }

#if DEBUG_PINGPONG
  hash2enc(&sender->hashPubKey, &enc);
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Received plaintext ping from peer %s.\n",
	 &enc);
#endif

  pmsg->header.type = htons(p2p_PROTO_PONG);
  /* allow using a different transport for sending the reply, the
     transport may have been uni-directional! */
  if ( (tsession != NULL) &&
       (OK == coreAPI->sendPlaintext(tsession,
				     (char*) pmsg,
				     sizeof(P2P_pingpong_MESSAGE))) )
    return OK;
  return sendPlaintext(sender, pmsg);
}

/**
 * Handler for a pong.
 */ 	
static int pongReceived(const PeerIdentity * sender,
			const MESSAGE_HEADER * msg) {
  int i;
  P2P_pingpong_MESSAGE * pmsg;
  PingPongEntry * entry;
  int matched;
#if DEBUG_PINGPONG
  EncName enc;
#endif

  pmsg = (P2P_pingpong_MESSAGE *) msg;
  if ( (ntohs(msg->size) != sizeof(P2P_pingpong_MESSAGE)) ||
       (0 != memcmp(sender,
		    &pmsg->receiver,
		    sizeof(PeerIdentity))) ) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER | GE_DEVELOPER,
	   _("Received malformed `%s' message. Dropping.\n"),
	   "pong");
    return SYSERR; /* bad pong */
  }
#if DEBUG_PINGPONG
  hash2enc(&sender->hashPubKey,
	   &enc);
  GE_LOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
      "Received PONG from `%s'.\n",
      &enc);
#endif
  matched = 0;
  if (stats != NULL)
    stats->change(stat_encryptedPongReceived, 1);
  MUTEX_LOCK(pingPongLock);
  for (i=0;i<MAX_PING_PONG;i++) {
    entry = &pingPongs[i];
    if ( ((int)ntohl(pmsg->challenge) == entry->challenge) &&
	 (0 == memcmp(sender,
		      &entry->receiverIdentity,
		      sizeof(PeerIdentity))) &&
	 (entry->plaintext == NO) ) {
      entry->method(entry->data);
      /* entry was valid for one time only */
      memset(entry,
      	     0,
	     sizeof(PingPongEntry));
      matched++;
    }
  }
  MUTEX_UNLOCK(pingPongLock);
#if DEBUG_PINGPONG
  hash2enc(&sender->hashPubKey,
	   &enc);
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Received PONG from `%s' matched %u peers.\n",
	 &enc,
	 matched);
#endif
  if (matched == 0) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_ADMIN,
	   _("Could not match PONG against any PING. "
	     "Try increasing MAX_PING_PONG constant.\n"));
  }
  return OK;
}

/**
 * Handler for a pong.
 */ 	
static int plaintextPongReceived(const PeerIdentity * sender,
				 const MESSAGE_HEADER * msg,
				 TSession * session) {
  int i;
  P2P_pingpong_MESSAGE * pmsg;
  PingPongEntry * entry;
  int matched;
#if DEBUG_PINGPONG
  EncName enc;
#endif

  pmsg = (P2P_pingpong_MESSAGE *) msg;
  if ( (ntohs(msg->size) != sizeof(P2P_pingpong_MESSAGE)) ||
       (0 != memcmp(sender,
		    &pmsg->receiver,
		    sizeof(PeerIdentity)))) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER | GE_DEVELOPER,
	   _("Received malformed `%s' message. Dropping.\n"),
	   "pong");
    return SYSERR; /* bad pong */
  }
  if (stats != NULL)
    stats->change(stat_plaintextPongReceived, 1);
  matched = 0;
  MUTEX_LOCK(pingPongLock);
  for (i=0;i<MAX_PING_PONG;i++) {
    entry = &pingPongs[i];
    if ( ((int)ntohl(pmsg->challenge) == entry->challenge) &&
	 (0 == memcmp(sender,
		      &entry->receiverIdentity,
		      sizeof(PeerIdentity))) &&
	 (entry->plaintext == YES) ) {
      entry->method(entry->data);
      /* entry was valid for one time only */
      memset(entry,
      	     0,
	     sizeof(PingPongEntry));
      matched++;
    }
  }
  MUTEX_UNLOCK(pingPongLock);
#if DEBUG_PINGPONG
  hash2enc(&sender->hashPubKey,
	   &enc);
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Received plaintext PONG from `%s' matched %u peers.\n",
	 &enc,
	 matched);
#endif
  if (matched == 0) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_ADMIN,
	   _("Could not match PONG against any PING. "
	     "Try increasing MAX_PING_PONG constant.\n"));
  }
  return OK;
}

/**
 * Create a ping a host an call a method if a reply comes back.
 * Does  NOT send the ping message but rather returns it
 * to the caller.  The caller is responsible for both sending
 * and freeing the message.
 *
 * @param receiver the peer that should be PINGed
 * @param method the method to call if a PONG comes back
 * @param data an argument to pass to the method.
 * @param plaintext is the PONG expected to be in plaintext (YES/NO)
 * @returns NULL on error, otherwise the PING message
 */
static MESSAGE_HEADER *
createPing(const PeerIdentity * receiver,
	   CronJob method,	
	   void * data,
	   int plaintext,
	   int challenge) {
  int i;
  int j;
  TIME_T min;
  PingPongEntry * entry;
  TIME_T now;
  P2P_pingpong_MESSAGE * pmsg;

  MUTEX_LOCK(pingPongLock);
  now = TIME(&min); /* set both, tricky... */

  j = -1;
  for (i=0;i<MAX_PING_PONG;i++)
    if (min > pingPongs[i].sendTime) {
      min = pingPongs[i].sendTime;
      j = i;
    }
  if (j == -1) { /* all send this second!? */
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_ADMIN,
	   _("Cannot create PING, table full. "
	     "Try increasing MAX_PING_PONG.\n"));
    MUTEX_UNLOCK(pingPongLock);
    return NULL;
  }
  entry = &pingPongs[j];
  entry->sendTime = now;
  entry->method = method;
  entry->plaintext = plaintext;
  FREENONNULL(entry->data);
  entry->data = data;
  entry->receiverIdentity = *receiver;
  pmsg = MALLOC(sizeof(P2P_pingpong_MESSAGE));
  pmsg->header.size = htons(sizeof(P2P_pingpong_MESSAGE));
  pmsg->header.type = htons(p2p_PROTO_PING);
  memcpy(&pmsg->receiver,
	 receiver,
	 sizeof(PeerIdentity));
  entry->challenge = challenge;
  pmsg->challenge = htonl(challenge);
  MUTEX_UNLOCK(pingPongLock);
  if (stats != NULL)
    stats->change(stat_pingCreated, 1);
  return &pmsg->header;
}

/**
 * Ping a host an call a method if a reply comes back.
 *
 * @param receiver the peer that should be PINGed
 * @param usePlaintext send the PING in plaintext (YES/NO)
 * @param method the method to call if a PONG comes back
 * @param data an argument to pass to the method.
 * @returns OK on success, SYSERR on error
 */
static int initiatePing(const PeerIdentity * receiver,
			CronJob method,
			void * data,
			int usePlaintext,
			int challenge) {
  P2P_pingpong_MESSAGE * pmsg;

  pmsg = (P2P_pingpong_MESSAGE*) createPing(receiver,
					    method,
					    data,
					    usePlaintext,
					    challenge);
  if (pmsg == NULL)
    return SYSERR;
  if (usePlaintext == YES) {
    sendPlaintext(receiver, pmsg);
    if (stats != NULL)
      stats->change(stat_plaintextPingSent, 1);
  } else {
    coreAPI->unicast(receiver,
		     &pmsg->header,
		     EXTREME_PRIORITY,
		     0);
    if (stats != NULL)
      stats->change(stat_ciphertextPingSent, 1);
  }
  FREE(pmsg);
  return OK;
}

/**
 * Initialize the pingpong module.
 */
Pingpong_ServiceAPI *
provide_module_pingpong(CoreAPIForApplication * capi) {
  static Pingpong_ServiceAPI ret;

  ectx = capi->ectx;
  GE_ASSERT(ectx,
	    sizeof(P2P_pingpong_MESSAGE) == 72);
  coreAPI = capi;
  identity = capi->requestService("identity");
  if (identity == NULL) {
    GE_BREAK(capi->ectx, 0);
    return NULL;
  }
  transport = capi->requestService("transport");
  if (transport == NULL) {
    GE_BREAK(capi->ectx, 0);
    capi->releaseService(identity);
    return NULL;
  }
  stats = capi->requestService("stats");
  if (stats != NULL) {
    stat_encryptedPongReceived
      = stats->create(gettext_noop("# encrypted PONG messages received"));
    stat_plaintextPongReceived
      = stats->create(gettext_noop("# plaintext PONG messages received"));
    stat_pingReceived
      = stats->create(gettext_noop("# encrypted PING messages received"));
    stat_pingCreated
      = stats->create(gettext_noop("# PING messages created"));
    stat_pongSent
      = stats->create(gettext_noop("# encrypted PONG messages sent"));
    stat_plaintextPingSent
      = stats->create(gettext_noop("# plaintext PING messages sent"));
    stat_ciphertextPingSent
      = stats->create(gettext_noop("# encrypted PING messages sent"));

  }
  pingPongLock = capi->getConnectionModuleLock();
  pingPongs = (PingPongEntry*) MALLOC(sizeof(PingPongEntry)*MAX_PING_PONG);
  memset(pingPongs,
  	 0,
	 sizeof(PingPongEntry)*MAX_PING_PONG);
  GE_LOG(ectx,
	 GE_DEBUG | GE_USER | GE_REQUEST,
	 _("`%s' registering handlers %d %d (plaintext and ciphertext)\n"),
	 "pingpong",
	 p2p_PROTO_PING,
	 p2p_PROTO_PONG);
  capi->registerHandler(p2p_PROTO_PING,
			&pingReceived);
  capi->registerHandler(p2p_PROTO_PONG,
			&pongReceived);
  capi->registerPlaintextHandler(p2p_PROTO_PING,
				 &plaintextPingReceived);
  capi->registerPlaintextHandler(p2p_PROTO_PONG,
				 &plaintextPongReceived);
  ret.ping = &initiatePing;
  ret.pingUser = &createPing;
  ret.ping_size = sizeof(P2P_pingpong_MESSAGE);
  return &ret;
}

/**
 * Shutdown the pingpong module.
 */
int release_module_pingpong() {
  int i;

  coreAPI->releaseService(stats);
  stats = NULL;
  coreAPI->releaseService(transport);
  transport = NULL;
  coreAPI->releaseService(identity);
  identity = NULL;
  for (i=0;i<MAX_PING_PONG;i++)
    FREENONNULL(pingPongs[i].data);
  FREE(pingPongs);
  coreAPI->unregisterHandler(p2p_PROTO_PING,
			     &pingReceived);
  coreAPI->unregisterHandler(p2p_PROTO_PONG,
			     &pongReceived);
  coreAPI->unregisterPlaintextHandler(p2p_PROTO_PING,
				      &plaintextPingReceived);
  coreAPI->unregisterPlaintextHandler(p2p_PROTO_PONG,
				      &plaintextPongReceived);
  coreAPI = NULL;
  return OK;
}

/* end of pingpong.c */
