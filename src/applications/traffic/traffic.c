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
 * @file applications/traffic/traffic.c
 * @brief tracks current traffic patterns
 * @author Christian Grothoff
 *
 * Module to keep track of recent amounts of p2p traffic on the local
 * GNUnet node. Uses roughly 6 kb of memory given the current
 * settings. The current settings allow the minimal anonymity
 * requirements that can be confirmed to reach 15 peers in the last 32
 * minutes (for any given message type). If significantly higher
 * levels are required, the current code would need to be recompiled
 * with different values. I currently do not belive we should make
 * better traffic tracking even an option.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_traffic_service.h"
#include "gnunet_stats_service.h"
#include "traffic.h"

#define DEBUG 0

/**
 * How many time-units back do we keep the history of?  (must really
 * be <=32 since we use the 32 bit in an unsigned int). The memory
 * impact of this value n is 4 * 3 * MAX_MESSAGE_ID * n, which is for
 * the default of n=32 with the current MAX_MESSAGE_ID being roughly a
 * dozen less than 2k.
 */
#define HISTORY_SIZE 32

#define KEEP_TRANSMITTED_STATS YES

#define KEEP_RECEIVE_STATS YES

#if KEEP_RECEIVE_STATS || KEEP_TRANSMITTED_STATS
static Stats_ServiceAPI * stats;
#endif

#if KEEP_RECEIVE_STATS
static int stat_traffic_received_by_type[P2P_PROTO_MAX_USED];
#endif

#if KEEP_TRANSMITTED_STATS
static int stat_traffic_transmitted_by_type[P2P_PROTO_MAX_USED];
#endif

/**
 * Macro to access the slot at time "t" in the history.
 */
#define HS_SLOT(a) ((a) % HISTORY_SIZE)

/**
 * Of how many peers do we keep track per message type
 * about "recent" interactions? The memory impact of
 * this value n is 8 * 3 * MAX_MESSAGE_ID * n. The current
 * number of messages is roughly a dozen, so the memory
 * impact is about 200 bytes * n, or for the default
 * of n=15 it is 3kb.
 */
#define MAX_PEER_IDs 15

/**
 * Information about when a peer was last involved
 * in a message of the given type.
 */
typedef struct {

  /**
   * The ".a" member of the Host identity of the peer.
   */
  int peerIdentity_a;

  /**
   * The time of the interaction.
   */
  unsigned int time;

} PeerDate;

/**
 * Numbers for one receive/send/self-send type.
 */
typedef struct {

  /**
   * When was this record last updated?
   */
  cron_t lastUpdate;

  /**
   * Time slots for processing (shifted bitvector)
   */
  unsigned int slots;

  /**
   * "peerCount" identities of the peers that we interacted with
   * most recently (abreviated identities plus timestamps)
   */
  PeerDate peers[MAX_PEER_IDs];

  /**
   * How many messages were processed? (rotating buffer)
   */
  unsigned int count[HISTORY_SIZE];

  /**
   * Average sizes (rotating buffer)
   */
  double avgSize[HISTORY_SIZE];

} DirectedTrafficCounter;

/**
 * Type of the internal traffic counters.
 */
typedef struct {

  /**
   * Statistics for sending
   */
  DirectedTrafficCounter send;

  /**
   * Statistics for receiving
   */
  DirectedTrafficCounter receive;

} TrafficCounter;

/**
 * Lock to synchronize access.
 */
static struct MUTEX * lock;

/**
 * Highest message type seen so far.
 */
static unsigned int max_message_type = 0;

/**
 * The actual counters.
 */
static TrafficCounter ** counters = NULL;

#if DEBUG
static unsigned long long server_port;
#endif

static CoreAPIForApplication * coreAPI;

/**
 * Update the use table dtc. A message of the given
 * size was processed interacting with a peer with
 * the given peerId.
 */
static void updateUse(DirectedTrafficCounter * dtc,
		      unsigned short size,
		      int peerId,
		      int expireOnly) {
  cron_t now;
  cron_t delta;
  unsigned int unitNow;
  unsigned int deltaUnits;
  unsigned int minPeerId;
  unsigned int minPeerTime;
  unsigned int i;
  unsigned int slot;

  now = get_time();
  unitNow = now / TRAFFIC_TIME_UNIT;
  delta = now - dtc->lastUpdate;
  dtc->lastUpdate = now;
  deltaUnits = delta / TRAFFIC_TIME_UNIT;

  if (NO == expireOnly) {
    /* update peer identities */
    minPeerTime = 0;
    minPeerId = 0;
    for (i=0;i<MAX_PEER_IDs;i++) {
      if (dtc->peers[i].time < minPeerTime)
	minPeerId = i;
      if (dtc->peers[i].peerIdentity_a == peerId) {
	minPeerId = i;
	break; /* if the peer is already listed, re-use
		  that slot & update the time! */
      }
    }
    dtc->peers[minPeerId].time = unitNow;
    dtc->peers[minPeerId].peerIdentity_a = peerId;
  }

  /* update expired slots: set appropriate slots to 0 */
  if (deltaUnits > HISTORY_SIZE)
    deltaUnits = HISTORY_SIZE;
  for (i=0;i<deltaUnits;i++) {
    dtc->count[HS_SLOT(unitNow - HISTORY_SIZE - i)] = 0;
    dtc->avgSize[HS_SLOT(unitNow - HISTORY_SIZE - i)] = 0.0;
  }

  if (NO == expireOnly) {
    int devideBy;

    /* update slots */
    dtc->slots = 0x80000000 | (dtc->slots >> deltaUnits);

    /* recompute average, increment count */
    slot = HS_SLOT(unitNow);
    dtc->count[slot]++;
    devideBy = dtc->count[slot];
    if (devideBy <= 0)
      dtc->avgSize[slot] = 0; /* how can this happen? */
    else
      dtc->avgSize[slot]
        = ((dtc->avgSize[slot] * (dtc->count[slot]-1)) + size) / devideBy;
  }
}

/**
 * Build the traffic counter summary to send it over
 * the network.
 * @param res where to write the summary to
 * @param dtc the internal traffic counter to convert
 * @param tcType the type of the counter (for the flags)
 * @param countTimeUnits for how long ago should we take
 *    the history into consideration (max is HISTORY_SIZE).
 * @param msgType what is the type of the message that the dtc is for?
 */
static void buildSummary(TRAFFIC_COUNTER * res,
			 DirectedTrafficCounter * dtc,
			 unsigned int tcType,
			 unsigned int countTimeUnits,
			 unsigned short msgType) {
  unsigned int i;
  unsigned short peerCount;
  cron_t now;
  unsigned int unitNow;
  unsigned int msgCount;
  unsigned long long totalMsgSize;

  updateUse(dtc, 0, 0, YES); /* expire old entries */
  now = get_time();
  unitNow = now / TRAFFIC_TIME_UNIT;

  /* count number of peers that we interacted with in
     the last countTimeUnits */
  peerCount = 0;
  for (i=0;i<MAX_PEER_IDs;i++)
    if (dtc->peers[i].time > now - countTimeUnits)
      peerCount++;
  res->flags = htons(tcType|peerCount);

  /* determine number of messages and average size */
  msgCount = 0;
  totalMsgSize = 0;
  for (i=0;i<countTimeUnits;i++) {
    unsigned int slot = HS_SLOT(unitNow - i);
    totalMsgSize += dtc->count[slot] * dtc->avgSize[slot];
    msgCount += dtc->count[slot];
  }

  res->count = htonl(msgCount);
  res->type = htons(msgType);
  if (msgCount > 0)
    res->avrg_size = htonl(totalMsgSize / msgCount);
  else
    res->avrg_size = 0;
  res->time_slots = htonl(dtc->slots);
}

/**
 * Build a reply message for the client.
 */
static CS_traffic_info_MESSAGE * buildReply(unsigned int countTimeUnits) {
  CS_traffic_info_MESSAGE * reply;
  unsigned int count;
  unsigned int i;

  MUTEX_LOCK(lock);
  count = 0;
  for (i=0;i<max_message_type;i++)
    if (counters[i] != NULL) {
      if (counters[i]->send.slots != 0)
	count++;
      if (counters[i]->receive.slots != 0)
	count++;
    }
  reply = MALLOC(sizeof(CS_traffic_info_MESSAGE)+
		 count * sizeof(TRAFFIC_COUNTER));
  reply->header.type = htons(CS_PROTO_traffic_INFO);
  reply->header.size = htons(sizeof(CS_traffic_info_MESSAGE)+
			    count * sizeof(TRAFFIC_COUNTER));
  reply->count = htonl(count);
  count = 0;
  for (i=0;i<max_message_type;i++)
    if (counters[i] != NULL) {
      if (counters[i]->send.slots != 0)
	buildSummary(&((CS_traffic_info_MESSAGE_GENERIC*)reply)->counters[count++],
		     &counters[i]->send,
		     TC_SENT,
		     countTimeUnits,
		     i);
      if (counters[i]->receive.slots != 0)
	buildSummary(&((CS_traffic_info_MESSAGE_GENERIC*)reply)->counters[count++],
		     &counters[i]->receive,
		     TC_RECEIVED,
		     countTimeUnits,
		     i);
    }

  MUTEX_UNLOCK(lock);
  return reply;
}

static int trafficQueryHandler(struct ClientHandle * sock,
			       const MESSAGE_HEADER * message) {
  const CS_traffic_request_MESSAGE * msg;
  CS_traffic_info_MESSAGE * reply;
  int ret;

  if (sizeof(CS_traffic_request_MESSAGE) != ntohs(message->size))
    return SYSERR;
  msg = (const CS_traffic_request_MESSAGE*) message;
  reply = buildReply(ntohl(msg->timePeriod));
  ret = coreAPI->sendToClient(sock, &reply->header);
  FREE(reply);
  return ret;
}


/**
 * Get statistics over the number of messages that
 * were received or send of a given type.
 *
 * @param messageType the type of the message
 * @param sendReceive TC_SENT for sending, TC_RECEIVED for receiving
 * @param timePeriod how many TRAFFIC_TIME_UNITs to take
 *        into consideration (limited by HISTORY_SIZE)
 * @param avgMessageSize average size of the messages (set)
 * @param messageCount number of messages (set)
 * @param peerCount number of peers engaged (set)
 * @param timeDistribution bit-vector giving times of interactions,
 *        highest bit is current time-unit, bit 1 is 32 time-units ago (set)
 * @return OK on success, SYSERR on error
 */
static int getTrafficStats(unsigned int timePeriod,
			   unsigned short messageType,
			   unsigned short sendReceive,
			   unsigned int * messageCount,
			   unsigned int * peerCount,
			   unsigned int * avgMessageSize,
			   unsigned int * timeDistribution) {
  DirectedTrafficCounter * dtc;
  unsigned int i;
  unsigned int nowUnit;
  double totSize;

  if (timePeriod > HISTORY_SIZE)
    timePeriod = HISTORY_SIZE;
  MUTEX_LOCK(lock);
  if ( (messageType >= max_message_type) ||
       (counters[messageType] == NULL) ) {
    *avgMessageSize = 0;
    *messageCount = 0;
    *peerCount = 0;
    *timeDistribution = 0;
    MUTEX_UNLOCK(lock);
    return OK;
  }

  if (sendReceive == TC_SENT)
    dtc = &counters[messageType]->send;
  else
    dtc = &counters[messageType]->receive;
  updateUse(dtc, 0, 0, YES);

  nowUnit = get_time() / TRAFFIC_TIME_UNIT;
  *peerCount = 0;
  *messageCount = 0;
  totSize = 0;
  for (i=0;i<MAX_PEER_IDs;i++)
    if (dtc->peers[i].time > nowUnit - timePeriod)
      (*peerCount)++;
  for (i=0;i<timePeriod;i++) {
    unsigned int slot;

    slot = HS_SLOT(nowUnit-i);
    (*messageCount) += dtc->count[slot];
    totSize += dtc->count[slot] * dtc->avgSize[slot];
  }
  if (*messageCount>0)
    *avgMessageSize = (unsigned short) (totSize / (*messageCount));
  else
    *avgMessageSize = 0;
  *timeDistribution = dtc->slots;
  MUTEX_UNLOCK(lock);
  return OK;
}


/**
 * Ensure that the counters array has the appropriate
 * size and a valid traffic counter allocated for the
 * given port.
 */
static void checkPort(unsigned short port) {
  if (port >= max_message_type)
    GROW(counters,
	 max_message_type,
	 port + 1);
  if (counters[port] == NULL) {
    counters[port] = MALLOC(sizeof(TrafficCounter));
    memset(counters[port],
	   0,
	   sizeof(TrafficCounter));
  }
}

static void updateTrafficSendCounter(unsigned short ptyp,
				     unsigned short plen) {
#if KEEP_TRANSMITTED_STATS
  if (ptyp >= P2P_PROTO_MAX_USED)
    return; /* not tracked */
  if (0 == stat_traffic_transmitted_by_type[ptyp]) {
    char * s;
    s = MALLOC(256);
    SNPRINTF(s,
	     256,
	     _("# bytes transmitted of type %d"),
	     ptyp);
    stat_traffic_transmitted_by_type[ptyp]
      = stats->create(s);
    FREE(s);
  }
  stats->change(stat_traffic_transmitted_by_type[ptyp],
		plen);
#endif
}

static void updateTrafficReceiveCounter(unsigned short ptyp,
					unsigned short plen) {
#if KEEP_RECEIVE_STATS
  if (ptyp < P2P_PROTO_MAX_USED) {
    if (0 == stat_traffic_received_by_type[ptyp]) {
      char * s;
      s = MALLOC(256);
      SNPRINTF(s,
	       256,
	       _("# bytes received of type %d"),
	       ptyp);
      stat_traffic_received_by_type[ptyp]
	= stats->create(s);
      FREE(s);
    }
    stats->change(stat_traffic_received_by_type[ptyp],
		  plen);
  }
#endif
}


/**
 * A message was received.  Update traffic stats.
 *
 * @param header the header of the message
 * @param sender the identity of the sender
 */
static int trafficReceive(const PeerIdentity * sender,
			  const MESSAGE_HEADER * header) {
  unsigned short port;

  port = ntohs(header->type);
  updateTrafficReceiveCounter(port,
			      ntohs(header->size));
  MUTEX_LOCK(lock);
  checkPort(port);
  updateUse(&counters[port]->receive,
	    ntohs(header->size),
	    sender->hashPubKey.bits[0],
	    NO);
  MUTEX_UNLOCK(lock);
  return OK;
}

/**
 * A message is send.  Update traffic stats.
 *
 * @param header the header of the message
 * @param receiver the identity of the receiver
 */
static int trafficSend(const PeerIdentity * receiver,
		       const MESSAGE_HEADER * header) {
  unsigned short port;

  port = ntohs(MAKE_UNALIGNED(header->type));
  updateTrafficSendCounter(port,
			   ntohs(MAKE_UNALIGNED(header->size)));
  MUTEX_LOCK(lock);
  checkPort(port);
  updateUse(&counters[port]->send,
	    ntohs(MAKE_UNALIGNED(header->size)),
	    receiver->hashPubKey.bits[0],
	    NO);
  MUTEX_UNLOCK(lock);
  return OK;
}


/**
 * Initialize the traffic module.
 */
Traffic_ServiceAPI *
provide_module_traffic(CoreAPIForApplication * capi) {
  static Traffic_ServiceAPI api;
#if KEEP_RECEIVE_STATS || KEEP_TRANSMITTED_STATS
  int i;
#endif

  coreAPI = capi;
#if DEBUG
  GC_get_configuration_value_number(capi->cfg,
				    "NETWORK",
				    "PORT",
				    0,
				    65536,
				    2087,
				    &server_port);
#endif
  api.get = &getTrafficStats;
#if KEEP_TRANSMITTED_STATS
  for (i=0;i<P2P_PROTO_MAX_USED;i++)
    stat_traffic_transmitted_by_type[i] = 0;
  coreAPI->registerSendNotify(&trafficSend);
#endif
#if KEEP_RECEIVE_STATS
  for (i=0;i<P2P_PROTO_MAX_USED;i++) {
    stat_traffic_received_by_type[i] = 0;
    coreAPI->registerHandler(i,
			     &trafficReceive);
  }
#endif

  GE_ASSERT(coreAPI->ectx, counters == NULL);
  lock = MUTEX_CREATE(NO);
#if KEEP_RECEIVE_STATS || KEEP_TRANSMITTED_STATS
  stats = capi->requestService("stats");
#endif
 return &api;
}

/**
 * Shutdown the traffic module.
 */
void release_module_traffic() {
  unsigned int i;

#if KEEP_RECEIVE_STATS
  for (i=0;i<P2P_PROTO_MAX_USED;i++)
    coreAPI->unregisterHandler(i,
			     &trafficReceive);
#endif
#if KEEP_TRANSMITTED_STATS
  coreAPI->unregisterSendNotify(&trafficSend);
#endif
#if KEEP_RECEIVE_STATS || KEEP_TRANSMITTED_STATS
  coreAPI->releaseService(stats);
  stats = NULL;
#endif
  for (i=0;i<max_message_type;i++)
    FREENONNULL(counters[i]);
  GROW(counters,
       max_message_type,
       0);
  MUTEX_DESTROY(lock);
  lock = NULL;
  coreAPI = NULL;
}



static Traffic_ServiceAPI * myApi;
static CoreAPIForApplication * myCoreAPI;

/**
 * Initialize the traffic module.
 */
int initialize_module_traffic(CoreAPIForApplication * capi) {
  GE_ASSERT(capi->ectx, myCoreAPI == NULL);
  myCoreAPI = capi;
  myApi = capi->requestService("traffic");
  if (myApi == NULL) {
    GE_BREAK(capi->ectx, 0);
    myCoreAPI = NULL;
    return SYSERR;
  }
  capi->registerClientHandler(CS_PROTO_traffic_QUERY,
			      &trafficQueryHandler);
  GE_ASSERT(capi->ectx,
	    0 == GC_set_configuration_value_string(capi->cfg,
						   capi->ectx,
						   "ABOUT",
						   "traffic",
						   gettext_noop("tracks bandwidth utilization by gnunetd")));
  return OK;				
}

/**
 * Shutdown the traffic module.
 */
void done_module_traffic() {
  GE_ASSERT(NULL, myCoreAPI != NULL);
  GE_ASSERT(myCoreAPI->ectx,
	    SYSERR != myCoreAPI->unregisterClientHandler(CS_PROTO_traffic_QUERY,
							 &trafficQueryHandler));
  myCoreAPI->releaseService(myApi);
  myApi = NULL;
  myCoreAPI = NULL;
}


/* end of traffic.c */
