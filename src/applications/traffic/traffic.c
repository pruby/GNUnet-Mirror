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

static GNUNET_Stats_ServiceAPI *stats;

static int stat_traffic_received_by_type[GNUNET_P2P_PROTO_MAX_USED];

static int stat_pt_traffic_received_by_type[GNUNET_P2P_PROTO_MAX_USED];

static int stat_traffic_transmitted_by_type[GNUNET_P2P_PROTO_MAX_USED];

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
typedef struct
{

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
typedef struct
{

  /**
   * When was this record last updated?
   */
  GNUNET_CronTime lastUpdate;

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
typedef struct
{

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
static struct GNUNET_Mutex *lock;

/**
 * Highest message type seen so far.
 */
static unsigned int max_message_type = 0;

/**
 * The actual counters.
 */
static TrafficCounter **counters = NULL;

#if DEBUG
static unsigned long long server_port;
#endif

static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * Update the use table dtc. A message of the given
 * size was processed interacting with a peer with
 * the given peerId.
 */
static void
updateUse (DirectedTrafficCounter * dtc,
           unsigned short size, int peerId, int expireOnly)
{
  GNUNET_CronTime now;
  GNUNET_CronTime delta;
  unsigned int unitNow;
  unsigned int deltaUnits;
  unsigned int minPeerId;
  unsigned int minPeerTime;
  unsigned int i;
  unsigned int slot;

  now = GNUNET_get_time ();
  unitNow = now / GNUNET_TRAFFIC_TIME_UNIT;
  delta = now - dtc->lastUpdate;
  dtc->lastUpdate = now;
  deltaUnits = delta / GNUNET_TRAFFIC_TIME_UNIT;

  if (GNUNET_NO == expireOnly)
    {
      /* update peer identities */
      minPeerTime = 0;
      minPeerId = 0;
      for (i = 0; i < MAX_PEER_IDs; i++)
        {
          if (dtc->peers[i].time < minPeerTime)
            minPeerId = i;
          if (dtc->peers[i].peerIdentity_a == peerId)
            {
              minPeerId = i;
              break;            /* if the peer is already listed, re-use
                                   that slot & update the time! */
            }
        }
      dtc->peers[minPeerId].time = unitNow;
      dtc->peers[minPeerId].peerIdentity_a = peerId;
    }

  /* update expired slots: set appropriate slots to 0 */
  if (deltaUnits > HISTORY_SIZE)
    deltaUnits = HISTORY_SIZE;
  for (i = 0; i < deltaUnits; i++)
    {
      dtc->count[HS_SLOT (unitNow - HISTORY_SIZE - i)] = 0;
      dtc->avgSize[HS_SLOT (unitNow - HISTORY_SIZE - i)] = 0.0;
    }

  if (GNUNET_NO == expireOnly)
    {
      int devideBy;

      /* update slots */
      dtc->slots = 0x80000000 | (dtc->slots >> deltaUnits);

      /* recompute average, increment count */
      slot = HS_SLOT (unitNow);
      dtc->count[slot]++;
      devideBy = dtc->count[slot];
      if (devideBy <= 0)
        dtc->avgSize[slot] = 0; /* how can this happen? */
      else
        dtc->avgSize[slot]
          = ((dtc->avgSize[slot] * (dtc->count[slot] - 1)) + size) / devideBy;
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
static void
buildSummary (TRAFFIC_COUNTER * res,
              DirectedTrafficCounter * dtc,
              unsigned int tcType,
              unsigned int countTimeUnits, unsigned short msgType)
{
  unsigned int i;
  unsigned short peerCount;
  GNUNET_CronTime now;
  unsigned int unitNow;
  unsigned int msgCount;
  unsigned long long totalMsgSize;

  updateUse (dtc, 0, 0, GNUNET_YES);    /* expire old entries */
  now = GNUNET_get_time ();
  unitNow = now / GNUNET_TRAFFIC_TIME_UNIT;

  /* count number of peers that we interacted with in
     the last countTimeUnits */
  peerCount = 0;
  for (i = 0; i < MAX_PEER_IDs; i++)
    if (dtc->peers[i].time > now - countTimeUnits)
      peerCount++;
  res->flags = htons (tcType | peerCount);

  /* determine number of messages and average size */
  msgCount = 0;
  totalMsgSize = 0;
  for (i = 0; i < countTimeUnits; i++)
    {
      unsigned int slot = HS_SLOT (unitNow - i);
      totalMsgSize += dtc->count[slot] * dtc->avgSize[slot];
      msgCount += dtc->count[slot];
    }

  res->count = htonl (msgCount);
  res->type = htons (msgType);
  if (msgCount > 0)
    res->avrg_size = htonl (totalMsgSize / msgCount);
  else
    res->avrg_size = 0;
  res->time_slots = htonl (dtc->slots);
}

/**
 * Build a reply message for the client.
 */
static CS_traffic_info_MESSAGE *
buildReply (unsigned int countTimeUnits)
{
  CS_traffic_info_MESSAGE *reply;
  unsigned int count;
  unsigned int i;
  TRAFFIC_COUNTER * tc;

  GNUNET_mutex_lock (lock);
  count = 0;
  for (i = 0; i < max_message_type; i++)
    if (counters[i] != NULL)
      {
        if (counters[i]->send.slots != 0)
          count++;
        if (counters[i]->receive.slots != 0)
          count++;
      }
  reply = GNUNET_malloc (sizeof (CS_traffic_info_MESSAGE) +
                         count * sizeof (TRAFFIC_COUNTER));
  reply->header.type = htons (GNUNET_CS_PROTO_TRAFFIC_INFO);
  reply->header.size = htons (sizeof (CS_traffic_info_MESSAGE) +
                              count * sizeof (TRAFFIC_COUNTER));
  reply->count = htonl (count);
  count = 0;
  tc = (TRAFFIC_COUNTER*) &reply[1];
  for (i = 0; i < max_message_type; i++)
    if (counters[i] != NULL)
      {
        if (counters[i]->send.slots != 0)
          buildSummary (&tc[count++], &counters[i]->send,
                        GNUNET_TRAFFIC_TYPE_SENT, countTimeUnits, i);
        if (counters[i]->receive.slots != 0)
          buildSummary (&tc[count++],
                        &counters[i]->receive,
                        GNUNET_TRAFFIC_TYPE_RECEIVED, countTimeUnits, i);
      }
  GNUNET_mutex_unlock (lock);
  return reply;
}

static int
trafficQueryHandler (struct GNUNET_ClientHandle *sock,
                     const GNUNET_MessageHeader * message)
{
  const CS_traffic_request_MESSAGE *msg;
  CS_traffic_info_MESSAGE *reply;
  int ret;

  if (sizeof (CS_traffic_request_MESSAGE) != ntohs (message->size))
    return GNUNET_SYSERR;
  msg = (const CS_traffic_request_MESSAGE *) message;
  reply = buildReply (ntohl (msg->timePeriod));
  ret = coreAPI->cs_send_message (sock, &reply->header, GNUNET_YES);
  GNUNET_free (reply);
  return ret;
}


/**
 * Get statistics over the number of messages that
 * were received or send of a given type.
 *
 * @param messageType the type of the message
 * @param sendReceive GNUNET_TRAFFIC_TYPE_SENT for sending, GNUNET_TRAFFIC_TYPE_RECEIVED for receiving
 * @param timePeriod how many TRAFFIC_TIME_UNITs to take
 *        into consideration (limited by HISTORY_SIZE)
 * @param avgMessageSize average size of the messages (set)
 * @param messageCount number of messages (set)
 * @param peerCount number of peers engaged (set)
 * @param timeDistribution bit-vector giving times of interactions,
 *        highest bit is current time-unit, bit 1 is 32 time-units ago (set)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
getTrafficStats (unsigned int timePeriod,
                 unsigned short messageType,
                 unsigned short sendReceive,
                 unsigned int *messageCount,
                 unsigned int *peerCount,
                 unsigned int *avgMessageSize, unsigned int *timeDistribution)
{
  DirectedTrafficCounter *dtc;
  unsigned int i;
  unsigned int nowUnit;
  double totSize;

  if (timePeriod > HISTORY_SIZE)
    timePeriod = HISTORY_SIZE;
  GNUNET_mutex_lock (lock);
  if ((messageType >= max_message_type) || (counters[messageType] == NULL))
    {
      *avgMessageSize = 0;
      *messageCount = 0;
      *peerCount = 0;
      *timeDistribution = 0;
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }

  if (sendReceive == GNUNET_TRAFFIC_TYPE_SENT)
    dtc = &counters[messageType]->send;
  else
    dtc = &counters[messageType]->receive;
  updateUse (dtc, 0, 0, GNUNET_YES);

  nowUnit = GNUNET_get_time () / GNUNET_TRAFFIC_TIME_UNIT;
  *peerCount = 0;
  *messageCount = 0;
  totSize = 0;
  for (i = 0; i < MAX_PEER_IDs; i++)
    if (dtc->peers[i].time > nowUnit - timePeriod)
      (*peerCount)++;
  for (i = 0; i < timePeriod; i++)
    {
      unsigned int slot;

      slot = HS_SLOT (nowUnit - i);
      (*messageCount) += dtc->count[slot];
      totSize += dtc->count[slot] * dtc->avgSize[slot];
    }
  if (*messageCount > 0)
    *avgMessageSize = (unsigned short) (totSize / (*messageCount));
  else
    *avgMessageSize = 0;
  *timeDistribution = dtc->slots;
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}


/**
 * Ensure that the counters array has the appropriate
 * size and a valid traffic counter allocated for the
 * given port.
 */
static void
checkPort (unsigned short port)
{
  if (port >= max_message_type)
    GNUNET_array_grow (counters, max_message_type, port + 1);
  if (counters[port] == NULL)
    {
      counters[port] = GNUNET_malloc (sizeof (TrafficCounter));
      memset (counters[port], 0, sizeof (TrafficCounter));
    }
}

static void
updateTrafficSendCounter (unsigned short ptyp, unsigned short plen)
{
  if (ptyp >= GNUNET_P2P_PROTO_MAX_USED)
    return;                     /* not tracked */
  if (0 == stat_traffic_transmitted_by_type[ptyp])
    {
      char *s;
      s = GNUNET_malloc (256);
      GNUNET_snprintf (s, 256, _("# bytes transmitted of type %d"), ptyp);
      stat_traffic_transmitted_by_type[ptyp] = stats->create (s);
      GNUNET_free (s);
    }
  stats->change (stat_traffic_transmitted_by_type[ptyp], plen);
}

static void
updateTrafficReceiveCounter (unsigned short ptyp, unsigned short plen)
{
  if (ptyp < GNUNET_P2P_PROTO_MAX_USED)
    {
      if (0 == stat_traffic_received_by_type[ptyp])
        {
          char *s;
          s = GNUNET_malloc (256);
          GNUNET_snprintf (s, 256, _("# bytes received of type %d"), ptyp);
          stat_traffic_received_by_type[ptyp] = stats->create (s);
          GNUNET_free (s);
        }
      stats->change (stat_traffic_received_by_type[ptyp], plen);
    }
}

static void
updatePlaintextTrafficReceiveCounter (unsigned short ptyp,
                                      unsigned short plen)
{
  if (ptyp < GNUNET_P2P_PROTO_MAX_USED)
    {
      if (0 == stat_pt_traffic_received_by_type[ptyp])
        {
          char *s;
          s = GNUNET_malloc (256);
          GNUNET_snprintf (s,
                           256, _("# bytes received in plaintext of type %d"),
                           ptyp);
          stat_pt_traffic_received_by_type[ptyp] = stats->create (s);
          GNUNET_free (s);
        }
      stats->change (stat_pt_traffic_received_by_type[ptyp], plen);
    }
}

/**
 * A message was received.  Update traffic stats.
 *
 * @param header the header of the message
 * @param sender the identity of the sender
 */
static int
trafficReceive (const GNUNET_PeerIdentity * sender,
                const GNUNET_MessageHeader * header)
{
  unsigned short port;

  if (sender == NULL)
    return GNUNET_OK;
  port = ntohs (header->type);
  updateTrafficReceiveCounter (port, ntohs (header->size));
  GNUNET_mutex_lock (lock);
  checkPort (port);
  updateUse (&counters[port]->receive,
             ntohs (header->size), sender->hashPubKey.bits[0], GNUNET_NO);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}


/**
 * A message is send.  Update traffic stats.
 *
 * @param header the header of the message
 * @param receiver the identity of the receiver
 */
static int
trafficSend (const GNUNET_PeerIdentity * receiver,
             const GNUNET_MessageHeader * header)
{
  unsigned short port;

  port = ntohs (MAKE_UNALIGNED (header->type));
  updateTrafficSendCounter (port, ntohs (MAKE_UNALIGNED (header->size)));
  GNUNET_mutex_lock (lock);
  checkPort (port);
  updateUse (&counters[port]->send,
             ntohs (MAKE_UNALIGNED (header->size)),
             receiver->hashPubKey.bits[0], GNUNET_NO);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * A message is send.  Update traffic stats.
 *
 * @param header the header of the message
 * @param receiver the identity of the receiver
 */
static int
plaintextReceive (const GNUNET_PeerIdentity * receiver,
                  const GNUNET_MessageHeader * header,
                  GNUNET_TSession * session)
{
  unsigned short port;

  port = ntohs (MAKE_UNALIGNED (header->type));
  updatePlaintextTrafficReceiveCounter (port,
                                        ntohs (MAKE_UNALIGNED
                                               (header->size)));
  return GNUNET_OK;
}


/**
 * Initialize the traffic module.
 */
GNUNET_Traffic_ServiceAPI *
provide_module_traffic (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Traffic_ServiceAPI api;
  int i;

  coreAPI = capi;
#if DEBUG
  GNUNET_GC_get_configuration_value_number (capi->cfg,
                                            "NETWORK",
                                            "PORT", 0, 65536, 2087,
                                            &server_port);
#endif
  api.get = &getTrafficStats;
  for (i = 0; i < GNUNET_P2P_PROTO_MAX_USED; i++)
    stat_traffic_transmitted_by_type[i] = 0;
  coreAPI->peer_send_notification_register (&trafficSend);
  for (i = 0; i < GNUNET_P2P_PROTO_MAX_USED; i++)
    {
      stat_traffic_received_by_type[i] = 0;
      coreAPI->p2p_ciphertext_handler_register (i, &trafficReceive);
      coreAPI->p2p_plaintext_handler_register (i, &plaintextReceive);
    }

  GNUNET_GE_ASSERT (coreAPI->ectx, counters == NULL);
  lock = GNUNET_mutex_create (GNUNET_NO);
  stats = capi->service_request ("stats");
  return &api;
}

/**
 * Shutdown the traffic module.
 */
void
release_module_traffic ()
{
  unsigned int i;

  for (i = 0; i < GNUNET_P2P_PROTO_MAX_USED; i++)
    {
      coreAPI->p2p_ciphertext_handler_unregister (i, &trafficReceive);
      coreAPI->p2p_plaintext_handler_unregister (i, &plaintextReceive);
    }
  coreAPI->peer_send_notification_unregister (&trafficSend);
  coreAPI->service_release (stats);
  stats = NULL;
  for (i = 0; i < max_message_type; i++)
    GNUNET_free_non_null (counters[i]);
  GNUNET_array_grow (counters, max_message_type, 0);
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  coreAPI = NULL;
}



static GNUNET_Traffic_ServiceAPI *myApi;
static GNUNET_CoreAPIForPlugins *myCoreAPI;

/**
 * Initialize the traffic module.
 */
int
initialize_module_traffic (GNUNET_CoreAPIForPlugins * capi)
{
  GNUNET_GE_ASSERT (capi->ectx, myCoreAPI == NULL);
  myCoreAPI = capi;
  myApi = capi->service_request ("traffic");
  if (myApi == NULL)
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      myCoreAPI = NULL;
      return GNUNET_SYSERR;
    }
  capi->cs_handler_register (GNUNET_CS_PROTO_TRAFFIC_QUERY,
                             &trafficQueryHandler);
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "traffic",
                                                                   gettext_noop
                                                                   ("tracks bandwidth utilization by gnunetd")));
  return GNUNET_OK;
}

/**
 * Shutdown the traffic module.
 */
void
done_module_traffic ()
{
  GNUNET_GE_ASSERT (NULL, myCoreAPI != NULL);
  GNUNET_GE_ASSERT (myCoreAPI->ectx,
                    GNUNET_SYSERR !=
                    myCoreAPI->cs_handler_unregister
                    (GNUNET_CS_PROTO_TRAFFIC_QUERY, &trafficQueryHandler));
  myCoreAPI->service_release (myApi);
  myApi = NULL;
  myCoreAPI = NULL;
}


/* end of traffic.c */
