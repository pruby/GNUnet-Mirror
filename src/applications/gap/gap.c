/*
  This file is part of GNUnet
  (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

/**
 * @file gap/gap.c
 * @brief protocol that performs anonymous routing
 * @author Christian Grothoff
 *
 * The code roughly falls into two main functionality groups:
 *
 * - keeping track of queries that have been routed,
 *   sending back replies along the path, deciding
 *   which old queries to drop from the routing table
 * - deciding when to forward which query to which
 *   set of peers; this includes tracking from where
 *   we receive responses to make an educated guess
 *   (also called 'hot path' routing).
 *
 */

#include "gap.h"

/**
 * Only for debugging / system analysis!
 */
#define DO_HISTOGRAM GNUNET_NO

/* ********************** GLOBALS ******************** */

/**
 * Avoiding concurrent lookups for the same ITE: lock to grant
 * access to peers to perform a lookup that matches this ITE entry.
 */
static struct GNUNET_Mutex *lookup_exclusion;

/**
 * GNUnet core.
 */
static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * Identity service.
 */
static GNUNET_Identity_ServiceAPI *identity;

/**
 * Statistics service.
 */
static GNUNET_Stats_ServiceAPI *stats;

static int stat_routing_collisions;

static int stat_routing_direct_drops;

static int stat_routing_successes;

static int stat_routing_request_repeat;

static int stat_routing_request_duplicates;

static int stat_routing_request_repeat_dttl;

static int stat_routing_totals;

static int stat_routing_slots_used;

static int stat_routing_forwards;

static int stat_routing_reply_drops;

static int stat_routing_reply_dups;

static int stat_routing_no_route_policy;

static int stat_routing_no_answer_policy;

static int stat_routing_local_results;

static int stat_routing_processed;

static int stat_memory_seen;

static int stat_memory_destinations;

static int stat_pending_rewards;

static int stat_response_count;

/**
 * Topology service.
 */
static GNUNET_Topology_ServiceAPI *topology;

/**
 * Traffic service.
 */
static GNUNET_Traffic_ServiceAPI *traffic;

/**
 * For migration / local stores, local lookup and
 * content verification.
 */
static GNUNET_Blockstore *bs;

/**
 * Function that can be used to identify unique
 * replies.
 */
static GNUNET_UniqueReplyIdentifierCallback uri;

static GNUNET_ReplyHashingCallback rhf;

/**
 * The routing table. This table has entries for all
 * queries that we have recently send out. It helps
 * GNUnet to route the replies back to the respective
 * sender.
 */
static IndirectionTableEntry *ROUTING_indTable_;

/**
 * Size of the indirection table specified in gnunet.conf
 */
static unsigned long long indirectionTableSize;

/**
 * Constant but peer-dependent value that randomizes the construction
 * of the indices into the routing table.  See
 * computeRoutingIndex.
 */
static unsigned int random_qsel;

/**
 * Array of the queries we are currently sending out.
 */
static QueryRecord queries[QUERY_RECORD_COUNT];

/**
 * Mutex for all gap structures.
 */
static struct GNUNET_Mutex *lock;

/**
 * Linked list tracking reply statistics.  Synchronize access using
 * the lock!
 */
static ReplyTrackData *rtdList;

static RewardEntry *rewards;

static unsigned int rewardSize;

static unsigned int rewardPos;

/**
 * Hard CPU limit
 */
static unsigned long long hardCPULimit;

/**
 * Hard network upload limit.
 */
static unsigned long long hardUpLimit;

#if DO_HISTOGRAM
static int histogram[65536];
static int hist_total;
#endif

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

/* ****************** helper functions ***************** */

/**
 * Adjust the TTL (priority limitation heuristic)
 */
static int
adjustTTL (int ttl, unsigned int prio)
{
  if ((ttl > 0) && (ttl > (int) (prio + 3) * TTL_DECREMENT))
    ttl = (int) (prio + 3) * TTL_DECREMENT;     /* bound! */
  return ttl;
}

/**
 * A query has been received. The question is, if it should be
 * forwarded and if with which priority. Routing decisions(to whom)
 * are to be taken elsewhere.  <p>
 *
 * @param sender the host sending us the query
 * @param priority the priority the query had when it came in,
 *        may be an arbitrary number if the
 *        sender is malicious! Cap by trustlevel first!
 *        Set to the resulting priority.
 * @return binary encoding: QUERY_XXXX constants
 */
static QUERY_POLICY
evaluateQuery (const GNUNET_PeerIdentity * sender, unsigned int *priority)
{
  unsigned int netLoad =
    GNUNET_network_monitor_get_load (coreAPI->load_monitor,
                                     GNUNET_ND_UPLOAD);

  if ((netLoad == (unsigned int) -1) || (netLoad < GAP_IDLE_LOAD_THRESHOLD))
    {
      *priority = 0;            /* minimum priority, no charge! */
      return QUERY_ANSWER | QUERY_FORWARD | QUERY_INDIRECT;
    }
  /* charge! */
  (*priority) = -identity->changeHostTrust (sender, -(*priority));
  if (netLoad < GAP_IDLE_LOAD_THRESHOLD + (*priority))
    return QUERY_ANSWER | QUERY_FORWARD | QUERY_INDIRECT;
  else if (netLoad < 90 + 10 * (*priority))
    return QUERY_ANSWER | QUERY_FORWARD;
  else if (netLoad < 100)
    return QUERY_ANSWER;
  return 0;                     /* drop entirely */
}

/**
 * Map the id to an index into the bitmap array.
 */
static unsigned int
getIndex (const GNUNET_PeerIdentity * peer)
{
  return ((unsigned int *) peer)[0] % (8 * BITMAP_SIZE);
}

static void
setBit (QueryRecord * qr, int bit)
{
  unsigned char theBit = (1 << (bit & 7));
  qr->bitmap[bit >> 3] |= theBit;
}

static int
getBit (const QueryRecord * qr, int bit)
{
  unsigned char theBit = (1 << (bit & 7));
  return (qr->bitmap[bit >> 3] & theBit) > 0;
}


/* ************* tracking replies, routing queries ********** */

/**
 * Cron job that ages the RTD data and that frees
 * memory for entries that reach 0.
 */
static void
ageRTD (void *unused)
{
  ReplyTrackData *pos;
  ReplyTrackData *prev;
  ResponseList *rpos;
  ResponseList *rprev;

  GNUNET_mutex_lock (lock);
  prev = NULL;
  pos = rtdList;
  while (pos != NULL)
    {
      /* after 10 minutes, always discard everything */
      if (pos->lastReplyReceived < GNUNET_get_time_int32 (NULL) - 600)
        {
          while (pos->responseList != NULL)
            {
              rpos = pos->responseList;
              pos->responseList = rpos->next;
              change_pid_rc (rpos->responder, -1);
              GNUNET_free (rpos);
            }
        }
      /* otherwise, age reply counts */
      rprev = NULL;
      rpos = pos->responseList;
      while (rpos != NULL)
        {
          if (stats != NULL)
            stats->change (stat_response_count, rpos->responseCount / 2);
          rpos->responseCount = rpos->responseCount / 2;
          if (rpos->responseCount == 0)
            {
              if (rprev == NULL)
                pos->responseList = rpos->next;
              else
                rprev->next = rpos->next;
              change_pid_rc (rpos->responder, -1);
              GNUNET_free (rpos);
              if (rprev == NULL)
                rpos = pos->responseList;
              else
                rpos = rprev->next;
              continue;
            }
          rprev = rpos;
          rpos = rprev->next;
        }
      /* if we have no counts for a peer anymore,
         free pos entry */
      if (pos->responseList == NULL)
        {
          if (prev == NULL)
            rtdList = pos->next;
          else
            prev->next = pos->next;
          change_pid_rc (pos->queryOrigin, -1);
          GNUNET_free (pos);
          if (prev == NULL)
            pos = rtdList;
          else
            pos = prev->next;
          continue;
        }
      prev = pos;
      pos = pos->next;
    }
  GNUNET_mutex_unlock (lock);
}

/**
 * We received a reply from 'responder' to a query received from
 * 'origin'.  Update reply track data!
 *
 * @param origin
 * @param responder peer that send the reply
 */
static void
updateResponseData (PID_INDEX origin, PID_INDEX responder)
{
  ReplyTrackData *pos;
  ReplyTrackData *prev;
  ResponseList *rpos;
  ResponseList *rprev;

  if (responder == 0)
    return;                     /* we don't track local responses */
  GNUNET_mutex_lock (lock);
  pos = rtdList;
  prev = NULL;
  while (pos != NULL)
    {
      if (origin == pos->queryOrigin)
        break;                  /* found */
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      pos = GNUNET_malloc (sizeof (ReplyTrackData));
      pos->next = NULL;
      pos->responseList = NULL;
      pos->queryOrigin = origin;
      change_pid_rc (origin, 1);
      if (prev == NULL)
        rtdList = pos;
      else
        prev->next = pos;
    }
  GNUNET_get_time_int32 (&pos->lastReplyReceived);
  rpos = pos->responseList;
  rprev = NULL;
  while (rpos != NULL)
    {
      if (responder == rpos->responder)
        {
          rpos->responseCount++;
          if (stats != NULL)
            stats->change (stat_response_count, 1);
          GNUNET_mutex_unlock (lock);
          return;
        }
      rprev = rpos;
      rpos = rpos->next;
    }
  rpos = GNUNET_malloc (sizeof (ResponseList));
  rpos->responseCount = 1;
  if (stats != NULL)
    stats->change (stat_response_count, 1);
  rpos->responder = responder;
  change_pid_rc (responder, 1);
  rpos->next = NULL;
  if (rprev == NULL)
    pos->responseList = rpos;
  else
    rprev->next = rpos;
  GNUNET_mutex_unlock (lock);
}

/**
 * Callback method for filling buffers. This method is invoked by the
 * core if a message is about to be send and there is space left for a
 * QUERY.  We then search the pending queries and fill one (or more)
 * in if possible.
 *
 * Note that the same query is not transmitted twice to a peer and that
 * queries are not queued more frequently than 2 TTL_DECREMENT.
 *
 * @param receiver the receiver of the message
 * @param position is the reference to the
 *        first unused position in the buffer where GNUnet is building
 *        the message
 * @param padding is the number of bytes left in that buffer.
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
static unsigned int
fillInQuery (const GNUNET_PeerIdentity * receiver,
             void *position, unsigned int padding)
{
  static unsigned int pos = 0;
  unsigned int start;
  unsigned int delta;
  GNUNET_CronTime now;
  QueryRecord *qr;
  PID_INDEX receiverId;

  now = GNUNET_get_time ();
  receiverId = intern_pid (receiver);
  GNUNET_mutex_lock (lock);
  start = pos;
  delta = 0;
  while (padding - delta > sizeof (P2P_gap_query_MESSAGE))
    {
      qr = &queries[pos];
      if ((qr->expires > now) &&
          (0 == getBit (qr, getIndex (receiver))) &&
          (receiverId != qr->noTarget) &&
          (0 != memcmp (&receiver->hashPubKey,
                        &qr->msg->returnTo.hashPubKey,
                        sizeof (GNUNET_HashCode)))
          && (padding - delta >= ntohs (qr->msg->header.size)))
        {
          setBit (&queries[pos], getIndex (receiver));
          memcpy (&((char *) position)[delta],
                  qr->msg, ntohs (qr->msg->header.size));
          qr->sendCount++;
          delta += ntohs (qr->msg->header.size);
        }
      pos++;
      if (pos >= QUERY_RECORD_COUNT)
        pos = 0;
      if (pos == start)
        break;
    }
  GNUNET_mutex_unlock (lock);
  change_pid_rc (receiverId, -1);
  return delta;
}

/**
 * Select a subset of the peers for forwarding.  Called
 * on each connected node by the core.
 */
static void
hotpathSelectionCode (const GNUNET_PeerIdentity * peer, void *cls)
{
  QueryRecord *qr = cls;
  ReplyTrackData *pos;
  ResponseList *rp;
  unsigned int ranking = 0;
  int distance;
  PID_INDEX id;
  unsigned int idx;
#if DEBUG_GAP
  GNUNET_EncName enc;
  GNUNET_EncName enc2;
#endif

  id = intern_pid (peer);
  /* compute some basic ranking based on historical
     queries from the same origin */
  pos = rtdList;
  while (pos != NULL)
    {
      if (pos->queryOrigin == qr->noTarget)
        break;
      pos = pos->next;
    }
  rp = NULL;
  if (pos != NULL)
    {
      rp = pos->responseList;
      while (rp != NULL)
        {
          if (rp->responder == id)
            break;
          rp = rp->next;
        }
      if (rp != NULL)
        {
          if (rp->responseCount < 0xFFFF)
            ranking = 0x7FFF * rp->responseCount;
          else
            ranking = 0x7FFFFFF;
        }
    }
  distance = GNUNET_hash_distance_u32 (&qr->msg->queries[0], &peer->hashPubKey) >> 10;  /* change to value in [0:63] */
  if (distance <= 0)
    distance = 1;
  ranking += GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 1 + 0xFFFF * 10 / (1 + distance));  /* 0 to 20 "response equivalents" for proximity */
  ranking += GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 0xFFFF);    /* 2 "response equivalents" random chance for everyone */
  if (id == qr->noTarget)
    ranking = 0;                /* no chance for blocked peers */
  idx = getIndex (peer);
#if DEBUG_GAP
  GNUNET_hash_to_enc (&qr->msg->queries[0], &enc);
  ((char *) &enc)[6] = '\0';
  GNUNET_hash_to_enc (&peer->hashPubKey, &enc2);
  ((char *) &enc2)[6] = '\0';
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Q %s peer %2u (%s) ranks (responses: %2u, distance %4d): %u%s\n",
                 &enc,
                 idx,
                 &enc2,
                 rp == NULL ? 0 : rp->responseCount,
                 distance, ranking, id == qr->noTarget ? " (no target)" : "");
#endif
  qr->rankings[idx] = ranking;
  change_pid_rc (id, -1);
}

/**
 * Return 1 if the current network (upstream) or CPU load is
 * too high, 0 if the load is ok.
 */
static int
loadTooHigh ()
{
  return ((hardCPULimit > 0) &&
          (GNUNET_cpu_get_load (ectx,
                                coreAPI->cfg) >= hardCPULimit)) ||
    ((hardUpLimit > 0) &&
     (GNUNET_network_monitor_get_load (coreAPI->load_monitor,
                                       GNUNET_ND_UPLOAD) >= hardUpLimit));
}

/**
 * A "GNUNET_NodeIteratorCallback" method that forwards the query to the selected
 * nodes.
 */
static void
sendToSelected (const GNUNET_PeerIdentity * peer, void *cls)
{
  const QueryRecord *qr = cls;
  PID_INDEX id;
#if DEBUG_GAP
  GNUNET_EncName encq;
  GNUNET_EncName encp;
#endif

  if (0 ==
      memcmp (&peer->hashPubKey, &qr->msg->returnTo.hashPubKey,
              sizeof (GNUNET_HashCode)))
    return;                     /* never send back to source */

  /* Load above hard limit? */
  if (loadTooHigh ())
    return;

  id = intern_pid (peer);
  if (id == qr->noTarget)
    {
      change_pid_rc (id, -1);
      return;                   /* never send back to source */
    }

  if (getBit (qr, getIndex (peer)) == 1)
    {
#if DEBUG_GAP
      IF_GELOG (ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&peer->hashPubKey, &encp);
                GNUNET_hash_to_enc (&qr->msg->queries[0], &encq));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Sending query `%s' to `%s'\n", &encq, &encp);
#endif
      if (stats != NULL)
        stats->change (stat_routing_forwards, 1);
      coreAPI->unicast (peer,
                        &qr->msg->header,
                        BASE_QUERY_PRIORITY * ntohl (qr->msg->priority) * 2,
                        TTL_DECREMENT);
    }
  change_pid_rc (id, -1);
}

/**
 * Take a query and forward it to the appropriate number of nodes
 * (depending on load, queue, etc).
 */
static void
forwardQuery (const P2P_gap_query_MESSAGE * msg,
              const GNUNET_PeerIdentity * target,
              const GNUNET_PeerIdentity * excludePeer)
{
  GNUNET_CronTime now;
  QueryRecord *qr;
  QueryRecord dummy;
  GNUNET_CronTime oldestTime;
  GNUNET_CronTime expirationTime;
  int oldestIndex;
  int i;
  int j;
  int noclear = GNUNET_NO;
  unsigned long long rankingSum;
  unsigned long long sel;
  unsigned long long pos;
  PID_INDEX tpid;

  if (target != NULL)
    {
      /* connect to target host -- if known */
      coreAPI->unicast (target, NULL, ntohl (msg->priority), 0);
    }
  now = GNUNET_get_time ();
  GNUNET_mutex_lock (lock);

  oldestIndex = -1;
  expirationTime = now + ntohl (msg->ttl);
  oldestTime = expirationTime;
  for (i = 0; i < QUERY_RECORD_COUNT; i++)
    {
      if (queries[i].expires < oldestTime)
        {
          oldestTime = queries[i].expires;
          oldestIndex = i;
        }
      if (queries[i].msg == NULL)
        continue;
      if ((queries[i].msg->header.size == msg->header.size) &&
          (0 == memcmp (&queries[i].msg->queries[0],
                        &msg->queries[0],
                        ntohs (msg->header.size)
                        - sizeof (P2P_gap_query_MESSAGE)
                        + sizeof (GNUNET_HashCode))))
        {
          /* We have exactly this query pending already.
             Replace existing query! */
          oldestIndex = i;
          if ((queries[i].expires > now - 4 * TTL_DECREMENT) && /* not long expired */
              (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 4) != 0))
            {
              /* do not clear the bitmap describing which peers we have
                 forwarded the query to already; but do this only with high
                 probability since we may want to try again if the query is
                 retransmitted lots (this can happen if this is the only
                 query; we may forward it to all connected peers and get no
                 reply.  If the initiator keeps retrying, we want to
                 eventually forward it again.

                 Note that the initial probability here (0.6.0/0.6.1) was
                 very low (1:64), which is far too low considering that the
                 clients do an exponential back-off.  The rule is a pure
                 optimization, and as such the probability that we
                 eventually forward must be significant.  25% seems to work
                 better... (extra-note: in small testbeds, the problem
                 is bigger than in a larger network where the case that
                 a query stays in the QM indefinitely might be much more
                 rare; so don't just trust a micro-scale benchmark when
                 trying to figure out an 'optimal' threshold). */
              noclear = GNUNET_YES;
            }
          break;                /* this is it, do not scan for other
                                   'oldest' entries */
        }
    }
  if (oldestIndex == -1)
    {
      memset (&dummy, 0, sizeof (QueryRecord));
      qr = &dummy;
    }
  else
    {
      qr = &queries[oldestIndex];
      GNUNET_free_non_null (qr->msg);
      qr->msg = NULL;
    }
  qr->expires = expirationTime;
  qr->transmissionCount = 0;
  qr->msg = GNUNET_malloc (ntohs (msg->header.size));
  memcpy (qr->msg, msg, ntohs (msg->header.size));
  if (noclear == GNUNET_NO)
    memset (&qr->bitmap[0], 0, BITMAP_SIZE);

  if (qr->noTarget != 0)
    change_pid_rc (qr->noTarget, -1);
  if (excludePeer != NULL)
    qr->noTarget = intern_pid (excludePeer);
  else
    qr->noTarget = intern_pid (coreAPI->myIdentity);
  qr->totalDistance = 0;
  qr->rankings = GNUNET_malloc (sizeof (int) * 8 * BITMAP_SIZE);
  qr->activeConnections
    = coreAPI->forAllConnectedNodes (&hotpathSelectionCode, qr);
  /* actual selection, proportional to rankings
     assigned by hotpathSelectionCode ... */
  rankingSum = 0;
  for (i = 0; i < 8 * BITMAP_SIZE; i++)
    rankingSum += qr->rankings[i];
  if (qr->activeConnections > 0)
    {
      /* select 4 peers for forwarding */
      for (i = 0; i < 4; i++)
        {
          if (rankingSum == 0)
            break;
          sel = GNUNET_random_u64 (GNUNET_RANDOM_QUALITY_WEAK, rankingSum);
          pos = 0;
          for (j = 0; j < 8 * BITMAP_SIZE; j++)
            {
              pos += qr->rankings[j];
              if (pos > sel)
                {
                  setBit (qr, j);
                  GNUNET_GE_ASSERT (ectx, rankingSum >= qr->rankings[j]);
                  rankingSum -= qr->rankings[j];
                  qr->rankings[j] = 0;
                  break;
                }
            }
        }
    }
  GNUNET_free (qr->rankings);
  qr->rankings = NULL;
  if (target != NULL)
    {
      tpid = intern_pid (target);
      setBit (qr, tpid);
      change_pid_rc (tpid, -1);
    }
  /* now forward to a couple of selected nodes */
  coreAPI->forAllConnectedNodes (&sendToSelected, qr);
  if (qr == &dummy)
    {
      change_pid_rc (dummy.noTarget, -1);
      GNUNET_free (dummy.msg);
    }
  GNUNET_mutex_unlock (lock);
}

/**
 * Stop transmitting a certain query (we don't route it anymore or
 * we have learned the answer).
 */
static int
dequeueQuery (const GNUNET_HashCode * query)
{
  int i;
  int ret;
  QueryRecord *qr;

  ret = GNUNET_SYSERR;
  GNUNET_mutex_lock (lock);
  for (i = 0; i < QUERY_RECORD_COUNT; i++)
    {
      qr = &queries[i];
      if (qr->msg != NULL)
        {
          if (0 ==
              memcmp (query, &qr->msg->queries[0], sizeof (GNUNET_HashCode)))
            {
              qr->expires = 0;  /* expire NOW! */
              ret = GNUNET_OK;
              break;
            }
        }
    }
  GNUNET_mutex_unlock (lock);
  return ret;
}

/* ********** tracking queries, forwarding replies ********** */

/**
 * Compute the hashtable index of a host id.
 */
static unsigned int
computeRoutingIndex (const GNUNET_HashCode * query)
{
  unsigned int res
    = (((unsigned int *) query)[0] ^
       ((unsigned int *) query)[1] / (1 + random_qsel))
    % indirectionTableSize;
  GNUNET_GE_ASSERT (ectx, res < indirectionTableSize);
#if DO_HISTOGRAM
  histogram[res % 65536]++;
  if (++hist_total % 10000 == 0)
    {
      int i;
      for (i = 0; i < 65536; i++)
        if (histogram[i] != 0)
          {
            printf ("%d: %d\n", i, histogram[i]);
          }
    }
#endif
  return res;
}

/**
 * Use content (forward to whoever sent the query).
 * @param hostId the peer from where the content came,
 *     NULL for the local peer
 */
static int useContent (const GNUNET_PeerIdentity * hostId,
                       const GNUNET_MessageHeader * pmsg);

/**
 * Call useContent "later" and then free the pmsg.
 */
static void
useContentLater (void *data)
{
  GNUNET_MessageHeader *pmsg = data;
  useContent (NULL, pmsg);
  GNUNET_free (pmsg);
}

/**
 * Queue a reply with cron to simulate
 * another peer returning the response with
 * some latency (and then route as usual).
 *
 * @param sender the next hop
 * @param result the content that was found
 * @param data is a GNUNET_DataContainer which
 *  wraps the content in the format that
 *  can be passed to the FS module (GapWrapper),
 *  which in turn wraps the DBlock (including
 *  the type ID).
 */
static int
queueReply (const GNUNET_PeerIdentity * sender,
            const GNUNET_HashCode * primaryKey,
            const GNUNET_DataContainer * data)
{
  P2P_gap_reply_MESSAGE *pmsg;
  IndirectionTableEntry *ite;
  unsigned int size;
#if DEBUG_GAP
  GNUNET_EncName enc;

  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (primaryKey, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Gap queues reply to query `%s' for later use.\n", &enc);
#endif

#if EXTRA_CHECKS
  /* verify data is valid */
  uri (data, GNUNET_ECRS_BLOCKTYPE_ANY, GNUNET_YES, primaryKey);
#endif

  ite = &ROUTING_indTable_[computeRoutingIndex (primaryKey)];
  if (0 != memcmp (&ite->primaryKey, primaryKey, sizeof (GNUNET_HashCode)))
    {
#if DEBUG_GAP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "GAP: Dropping reply, routing table has no query associated with it (anymore)\n");
#endif
      return GNUNET_NO;         /* we don't care for the reply (anymore) */
    }
  if (GNUNET_YES == ite->successful_local_lookup_in_delay_loop)
    {
#if DEBUG_GAP
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "GAP: Dropping reply, found reply locally during delay\n");
#endif
      return GNUNET_NO;         /* wow, really bad concurrent DB lookup and processing for
                                   the same query.  Well, at least we should not also
                                   queue the delayed reply twice... */
    }
  size =
    sizeof (P2P_gap_reply_MESSAGE) + ntohl (data->size) -
    sizeof (GNUNET_DataContainer);
  if (size >= GNUNET_MAX_BUFFER_SIZE)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  ite->successful_local_lookup_in_delay_loop = GNUNET_YES;
  pmsg = GNUNET_malloc (size);
  pmsg->header.size = htons (size);
  pmsg->header.type = htons (GNUNET_P2P_PROTO_GAP_RESULT);
  pmsg->primaryKey = *primaryKey;
  memcpy (&pmsg[1], &data[1], size - sizeof (P2P_gap_reply_MESSAGE));
  /* delay reply, delay longer if we are busy (makes it harder
     to predict / analyze, too). */
  GNUNET_cron_add_job (coreAPI->cron,
                       &useContentLater,
                       GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                          TTL_DECREMENT), 0, pmsg);
  return GNUNET_YES;
}

static void
addReward (const GNUNET_HashCode * query, unsigned int prio)
{
  if (prio == 0)
    return;
  GNUNET_mutex_lock (lock);
  rewards[rewardPos].query = *query;
  if (stats != NULL)
    stats->change (stat_pending_rewards, prio - rewards[rewardPos].prio);
  rewards[rewardPos].prio = prio;
  rewardPos++;
  if (rewardPos == rewardSize)
    rewardPos = 0;
  GNUNET_mutex_unlock (lock);
}

static unsigned int
claimReward (const GNUNET_HashCode * query)
{
  int i;
  unsigned int ret;

  ret = 0;
  GNUNET_mutex_lock (lock);
  for (i = 0; i < rewardSize; i++)
    {
      if (0 == memcmp (query, &rewards[i].query, sizeof (GNUNET_HashCode)))
        {
          ret += rewards[i].prio;
          if (stats != NULL)
            stats->change (stat_pending_rewards, -rewards[i].prio);
          rewards[i].prio = 0;
        }
    }
  GNUNET_mutex_unlock (lock);
  return ret;
}

static void
resetSeen (IndirectionTableEntry * ite)
{
  if (stats != NULL)
    stats->change (stat_memory_seen, -ite->seenIndex);
  GNUNET_array_grow (ite->seen, ite->seenIndex, 0);
}

static void
resetDestinations (IndirectionTableEntry * ite)
{
  decrement_pid_rcs (ite->destination, ite->hostsWaiting);
  if (stats != NULL)
    stats->change (stat_memory_destinations, -ite->hostsWaiting);
  GNUNET_array_grow (ite->destination, ite->hostsWaiting, 0);
}

/**
 * Add an entry to the routing table. The lock on the ite
 * must be held.
 *
 * @param mode replace or extend an existing entry?
 * @param ite slot in the routing table that is manipulated
 * @param query the query to look for
 * @param ttl how long to keep the new entry, relative ttl
 * @param priority how important is the new entry
 * @param sender for which node is the entry
 * @return GNUNET_OK if sender was added, GNUNET_SYSERR if existed already
 *            in the queue
 */
static int
addToSlot (int mode,
           IndirectionTableEntry * ite,
           const GNUNET_HashCode * query,
           int ttl, unsigned int priority, PID_INDEX sender)
{
  unsigned int i;
  GNUNET_CronTime now;
#if DEBUG__GAP
  GNUNET_EncName enc;

  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (query, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "GAP: Queueing query '%s' in slot %p\n", &enc, ite);
#endif
  GNUNET_GE_ASSERT (ectx, sender != 0); /* do NOT add to RT for local clients! */
  now = GNUNET_get_time ();
  if ((stats != NULL) && (ite->ttl == 0))
    stats->change (stat_routing_slots_used, 1);

  if (mode == ITE_REPLACE)
    {
      resetSeen (ite);
      ite->seenReplyWasUnique = GNUNET_NO;
      if (0 == memcmp (query, &ite->primaryKey, sizeof (GNUNET_HashCode)))
        {
          ite->ttl = now + ttl;
          ite->priority += priority;
          for (i = 0; i < ite->hostsWaiting; i++)
            if (ite->destination[i] == sender)
              return GNUNET_SYSERR;
          if (ite->hostsWaiting >= MAX_HOSTS_WAITING)
            resetDestinations (ite);
        }
      else
        {
          ite->successful_local_lookup_in_delay_loop = GNUNET_NO;
          /* different request, flush pending queues */
          dequeueQuery (&ite->primaryKey);
          ite->primaryKey = *query;
          resetDestinations (ite);
          ite->ttl = now + ttl;
          ite->priority = priority;
        }
    }
  else
    {                           /* GNUNET_array_grow mode */
      GNUNET_GE_ASSERT (ectx,
                        0 == memcmp (query, &ite->primaryKey,
                                     sizeof (GNUNET_HashCode)));
      /* extend lifetime */
      if (ite->ttl < now + ttl)
        ite->ttl = now + ttl;
      ite->priority += priority;
      for (i = 0; i < ite->hostsWaiting; i++)
        if (sender == ite->destination[i])
          return GNUNET_SYSERR; /* already there! */
    }
  if (stats != NULL)
    stats->change (stat_memory_destinations, 1);
  GNUNET_array_grow (ite->destination, ite->hostsWaiting,
                     ite->hostsWaiting + 1);
  ite->destination[ite->hostsWaiting - 1] = sender;
  change_pid_rc (sender, 1);
  /* again: new listener, flush seen list */
  resetSeen (ite);
  ite->seenReplyWasUnique = GNUNET_NO;
  return GNUNET_OK;
}

/**
 * Find out, if this query is already pending. If the ttl of
 * the new query is higher than the ttl of an existing query,
 * GNUNET_NO is returned since we should re-send the query.<p>
 *
 * If GNUNET_YES is returned, the slot is also marked as used by
 * the query and the sender (HostId or socket) is added.<p>
 *
 * This method contains a heuristic that attempts to do its best to
 * route queries without getting too many cycles, send a query and
 * then drop it from the routing table without sending a response,
 * etc.  Before touching this code, definitely consult Christian
 * (christian@grothoff.org) who has put more bugs in these five lines
 * of code than anyone on this planet would think is possible.
 *
 *
 * @param query the GNUNET_hash to look for
 * @param ttl how long would the new query last
 * @param priority the priority of the query
 * @param sender which peer transmitted the query?
 * @param isRouted set to GNUNET_OK if we can route this
 *        query, GNUNET_SYSERR if we can not
 * @param doForward is set to GNUNET_OK if we should
 *        forward the query, GNUNET_SYSERR if not
 * @return a case ID for debugging
 */
static int
needsForwarding (const GNUNET_HashCode * query,
                 int ttl,
                 unsigned int priority,
                 PID_INDEX sender, int *isRouted, int *doForward)
{
  IndirectionTableEntry *ite;
  GNUNET_CronTime now;
  GNUNET_CronTime new_ttl;
  int equal_to_pending;

  now = GNUNET_get_time ();
  ite = &ROUTING_indTable_[computeRoutingIndex (query)];
  equal_to_pending =
    0 == memcmp (query, &ite->primaryKey, sizeof (GNUNET_HashCode));
  if ((stats != NULL) && (equal_to_pending))
    stats->change (stat_routing_request_duplicates, 1);

  new_ttl = now + ttl;
  if ((ite->ttl < now) &&
      (ite->ttl < now - (GNUNET_CronTime) (TTL_DECREMENT * 10L)) &&
      (ttl > -TTL_DECREMENT * 5))
    {
      addToSlot (ITE_REPLACE, ite, query, ttl, priority, sender);
      *isRouted = GNUNET_YES;
      *doForward = GNUNET_YES;
      return 21;
    }
  if ((ttl < 0) && (equal_to_pending))
    {
      /* if ttl is "expired" and we have
         the exact query pending, route
         replies but do NOT forward _again_! */
      addToSlot (ITE_GNUNET_array_grow, ite, query, ttl, priority, sender);
      *isRouted = GNUNET_NO;
      /* don't go again, we are not even going to reset the seen
         list, so why bother looking locally again, if we would find
         something, the seen list would block sending the reply anyway
         since we're not resetting that (ttl too small!)! */
      *doForward = GNUNET_NO;
      return 0;
    }

  if ((ite->ttl < new_ttl) &&
      (ite->ttl +
       (GNUNET_CronTime) (TTL_DECREMENT * topology->estimateNetworkSize ()) <
       new_ttl)
      && (ite->ttl + (GNUNET_CronTime) (TTL_DECREMENT * 10L) < new_ttl)
      && (ite->ttl < now))
    {
      /* expired AND is significantly (!)
         longer expired than new query */
      /* previous entry relatively expired, start using the slot --
         and kill the old seen list! */
      resetSeen (ite);
      ite->seenReplyWasUnique = GNUNET_NO;
      if ((equal_to_pending) &&
          (GNUNET_YES == ite->successful_local_lookup_in_delay_loop))
        {
          *isRouted = GNUNET_NO;
          *doForward = GNUNET_NO;
          addToSlot (ITE_GNUNET_array_grow, ite, query, ttl, priority,
                     sender);
          return 1;
        }
      else
        {
          *isRouted = GNUNET_YES;
          *doForward = GNUNET_YES;
          if ((stats != NULL) && (equal_to_pending))
            {
              stats->change (stat_routing_request_repeat, 1);
              if (ite->ttl != 0)
                {
                  stats->change (stat_routing_request_repeat_dttl,
                                 new_ttl - ite->ttl);
                }
            }
          addToSlot (ITE_REPLACE, ite, query, ttl, priority, sender);
          return 2;
        }
    }
  if (equal_to_pending)
    {
      if (ite->seenIndex == 0)
        {
          if ((ite->ttl < new_ttl) &&
              (ite->ttl + (GNUNET_CronTime) TTL_DECREMENT < new_ttl))
            {
              /* ttl of new is SIGNIFICANTLY longer? */
              /* query again */
              if (GNUNET_YES == ite->successful_local_lookup_in_delay_loop)
                {
                  *isRouted = GNUNET_NO;        /* don't go again, we are already
                                                   processing a local lookup! */
                  *doForward = GNUNET_NO;
                  addToSlot (ITE_REPLACE, ite, query, ttl, priority, sender);
                  return 3;
                }
              else
                {
                  *isRouted = GNUNET_YES;
                  *doForward = GNUNET_YES;
                  if (stats != NULL)
                    {
                      stats->change (stat_routing_request_repeat, 1);
                      if (ite->ttl != 0)
                        {
                          stats->change (stat_routing_request_repeat_dttl,
                                         new_ttl - ite->ttl);
                        }
                    }
                  addToSlot (ITE_REPLACE, ite, query, ttl, priority, sender);
                  return 4;
                }
            }
          else
            {
              /* new TTL is lower than the old one, thus
                 just wait for the reply that may come back */
              if (GNUNET_OK ==
                  addToSlot (ITE_GNUNET_array_grow, ite, query, ttl, priority,
                             sender))
                {
                  if (GNUNET_YES ==
                      ite->successful_local_lookup_in_delay_loop)
                    {
                      *isRouted = GNUNET_NO;
                      /* don't go again, we are already processing a
                         local lookup! */
                      *doForward = GNUNET_NO;
                      return 5;
                    }
                  else
                    {
                      *isRouted = GNUNET_YES;
                      *doForward = GNUNET_NO;
                      return 6;
                    }
                }
              else
                {
                  *isRouted = GNUNET_NO;        /* same query with _higher_ TTL has already been
                                                   processed FOR THE SAME recipient! Do NOT do
                                                   the lookup *again*. */
                  *doForward = GNUNET_NO;
                  return 7;
                }
            }
        }
      /* ok, we've seen at least one reply before, replace
         more agressively */

      /* pending == new! */
      if (ite->seenReplyWasUnique)
        {
          if (ite->ttl < new_ttl)
            {                   /* ttl of new is longer? */
              /* go again */
              resetSeen (ite);
              ite->seenReplyWasUnique = GNUNET_NO;
              if (GNUNET_YES == ite->successful_local_lookup_in_delay_loop)
                {
                  *isRouted = GNUNET_NO;
                  /* don't go again, we are already processing a local lookup! */
                  *doForward = GNUNET_NO;
                  addToSlot (ITE_REPLACE, ite, query, ttl, priority, sender);
                  return 8;
                }
              else
                {
                  *isRouted = GNUNET_YES;
                  /* only forward if new TTL is significantly higher */
                  if (ite->ttl + TTL_DECREMENT < new_ttl)
                    {
                      *doForward = GNUNET_YES;
                      if (stats != NULL)
                        {
                          stats->change (stat_routing_request_repeat, 1);
                          if (ite->ttl != 0)
                            {
                              stats->change (stat_routing_request_repeat_dttl,
                                             new_ttl - ite->ttl);
                            }
                        }
                    }
                  else
                    *doForward = GNUNET_NO;
                  addToSlot (ITE_REPLACE, ite, query, ttl, priority, sender);
                  return 9;
                }
            }
          else
            {
              /* new TTL is lower than the old one, thus
                 just wait for the reply that may come back */
              if (GNUNET_OK ==
                  addToSlot (ITE_GNUNET_array_grow, ite, query, ttl, priority,
                             sender))
                {
                  if (GNUNET_YES ==
                      ite->successful_local_lookup_in_delay_loop)
                    {
                      *isRouted = GNUNET_NO;
                      *doForward = GNUNET_NO;
                      return 10;
                    }
                  else
                    {
                      *isRouted = GNUNET_YES;
                      *doForward = GNUNET_NO;
                      return 11;
                    }
                }
              else
                {
                  *isRouted = GNUNET_NO;
                  *doForward = GNUNET_NO;
                  return 12;
                }
            }
        }
      else
        {                       /* KSK or SKS, multiple results possible! */
          /* It's a pending KSK or SKS that can have multiple
             replies.  Do not re-send, just forward the
             answers that we get from now on to this additional
             receiver */
          int isttlHigher;
          if (ite->ttl < new_ttl)
            isttlHigher = GNUNET_NO;
          else
            isttlHigher = GNUNET_YES;
          if (GNUNET_OK ==
              addToSlot (ITE_GNUNET_array_grow, ite, query, ttl, priority,
                         sender))
            {
              *isRouted = GNUNET_YES;
              *doForward = GNUNET_NO;
              return 13;
            }
          else
            {
              *isRouted = isttlHigher;
              /* receiver is the same as the one that already got the
                 answer, do not bother to do this again, IF
                 the TTL is not higher! */
              *doForward = GNUNET_NO;
              return 14;
            }
        }
    }
  /* a different query that is expired a bit longer is using
     the slot; but if it is a query that has received
     a unique response already, we can eagerly throw it out
     anyway, since the request has been satisfied
     completely */
  if ((ite->ttl + TTL_DECREMENT < new_ttl) &&
      (ite->ttl < now) && (ite->seenReplyWasUnique))
    {
      /* we have seen the unique answer, get rid of it early */
      addToSlot (ITE_REPLACE, ite, query, ttl, priority, sender);
      *isRouted = GNUNET_YES;
      *doForward = GNUNET_YES;
      return 15;
    }
  /* Another still valid query is using the slot.  Now we need a _really_
     good reason to discard it... */
  if (ttl < 0)
    {
      *isRouted = GNUNET_NO;
      *doForward = GNUNET_NO;
      if (stats != NULL)
        stats->change (stat_routing_collisions, 1);
      return 16;                /* if new ttl is "expired", don't bother with priorities */
    }

  /* Finally try to find a _strong_ reason looking at priority/ttl
     relationships to replace the existing query. A low ttl with high
     priority should be preferred, so we do a cross-multiplication
     (!). Also, we want a _strong_ reason, so we add a "magic" factor
     of 10 for the additional work that the replacement would make
     (the network needs a certain amount of resilience to changes in
     the routing table, otherwise it might happen that query A
     replaces query B which replaces query A which could happen so
     quickly that no response to either query ever makes it through...
   */
  if ((long long) ((ite->ttl - now) * priority) >
      (long long) 10 * (ttl * ite->priority))
    {
      addToSlot (ITE_REPLACE, ite, query, ttl, priority, sender);
      *isRouted = GNUNET_YES;
      *doForward = GNUNET_YES;
      return 17;
    }
  if (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, TIE_BREAKER_CHANCE) == 0)
    {
      addToSlot (ITE_REPLACE, ite, query, ttl, priority, sender);
      *isRouted = GNUNET_YES;
      *doForward = GNUNET_YES;
      return 20;
    }
  /* sadly, the slot is busy with something else; we can
     not even add ourselves to the reply set */
  *isRouted = GNUNET_NO;
  *doForward = GNUNET_NO;
  if (stats != NULL)
    stats->change (stat_routing_collisions, 1);

  return 18;
}

/**
 * Send a reply to a host.
 *
 * @param ite the matching slot in the indirection table
 * @param msg the message to route
 */
static void
sendReply (IndirectionTableEntry * ite, const GNUNET_MessageHeader * msg)
{
  unsigned int j;
  unsigned int maxDelay;
  GNUNET_CronTime now;
  GNUNET_PeerIdentity recv;
#if DEBUG_GAP
  GNUNET_EncName enc;
#endif

  if (stats != NULL)
    stats->change (stat_routing_successes, 1);
  now = GNUNET_get_time ();
  if (now < ite->ttl)
    maxDelay = ite->ttl - now;
  else
    maxDelay = TTL_DECREMENT;   /* for expired queries */
  /* send to peers */
  for (j = 0; j < ite->hostsWaiting; j++)
    {
      resolve_pid (ite->destination[j], &recv);
#if DEBUG_GAP
      IF_GELOG (ectx,
                GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&recv.hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "GAP sending reply to `%s'\n", &enc);
#endif
      coreAPI->unicast (&recv, msg, BASE_REPLY_PRIORITY * (ite->priority + 5),
                        /* weigh priority */
                        maxDelay);
    }
}

struct qLRC
{
  GNUNET_DataContainer **values;
  unsigned int valueCount;
  GNUNET_HashCode query;
};

/**
 * Callback for processing local results.
 * Inserts all results into the qLRC closure.
 *
 * @param primaryKey is the key needed to decrypt
 *  the block
 * @param value is a GNUNET_DataContainer which
 *  wraps the content in the format that
 *  can be passed to the FS module (GapWrapper),
 *  which in turn wraps the DBlock (including
 *  the type ID).
 */
static int
queryLocalResultCallback (const GNUNET_HashCode * primaryKey,
                          const GNUNET_DataContainer * value, void *closure)
{
  struct qLRC *cls = closure;
  int i;

#if EXTRA_CHECKS
  /* verify data is valid */
  uri (value, GNUNET_ECRS_BLOCKTYPE_ANY, GNUNET_YES, primaryKey);
#endif
  /* check seen */
  if ((cls->valueCount > MAX_SEEN_VALUES) &&
      (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, cls->valueCount) > 8))
    return GNUNET_OK;           /* statistical drop, too many replies to keep in memory */
  for (i = 0; i < cls->valueCount; i++)
    if (0 == memcmp (value, cls->values[i], ntohl (value->size)))
      return GNUNET_OK;         /* drop, duplicate entry in DB! */
  GNUNET_array_grow (cls->values, cls->valueCount, cls->valueCount + 1);
  cls->values[cls->valueCount - 1] = GNUNET_malloc (ntohl (value->size));
  memcpy (cls->values[cls->valueCount - 1], value, ntohl (value->size));
  return GNUNET_OK;
}

/**
 * Execute a single query. Tests if the query can be routed. If yes,
 * the query is added to the routing table and the content is looked
 * for locally. If the content is available locally, a deferred
 * response is simulated with a cron job and the local content is
 * marked as valueable. The method returns GNUNET_OK if the query should
 * subsequently be routed to other peers.
 *
 * @param sender next hop in routing of the reply, NULL for us
 * @param target peer to ask primarily (maybe NULL)
 * @param prio the effective priority of the query
 * @param ttl the relative ttl of the query
 * @param query the query itself
 * @return GNUNET_OK/GNUNET_YES if the query will be routed further,
 *         GNUNET_NO if we already found the one and only response,
 *         GNUNET_SYSERR if not (out of resources)
 */
static int
execQuery (const GNUNET_PeerIdentity * sender,
           const GNUNET_PeerIdentity * target,
           unsigned int prio,
           QUERY_POLICY policy, int ttl, const P2P_gap_query_MESSAGE * query)
{
  IndirectionTableEntry *ite;
  int isRouted;
  struct qLRC cls;
  int i;
  int max;
  unsigned int *perm;
  int doForward;
  PID_INDEX senderID;
#if DEBUG_GAP
  GNUNET_EncName enc;
#endif

  /* Load above hard limit? */
  if (loadTooHigh ())
    return GNUNET_SYSERR;
  if (rhf == NULL)
    return GNUNET_SYSERR;       /* not fully initialized */

  senderID = intern_pid (sender);
  GNUNET_GE_ASSERT (ectx, (senderID != 0) || (sender == NULL));
  ite = &ROUTING_indTable_[computeRoutingIndex (&query->queries[0])];
  GNUNET_mutex_lock (lookup_exclusion);
  i = -1;
  if (sender != NULL)
    {
      if (((policy & QUERY_ANSWER) > 0) &&
          (((policy & QUERY_INDIRECT) > 0) ||
           (bs->fast_get (&query->queries[0]))))
        {
          i = needsForwarding (&query->queries[0],
                               ttl, prio, senderID, &isRouted, &doForward);
        }
      else
        {
          isRouted = GNUNET_NO;
          doForward = GNUNET_NO;
          if (stats != NULL)
            {
              if ((policy & QUERY_ANSWER) > 0)
                stats->change (stat_routing_no_route_policy, 1);
              else
                stats->change (stat_routing_no_answer_policy, 1);
            }
        }
    }
  else
    {
      addReward (&query->queries[0], prio);
      isRouted = GNUNET_YES;
      doForward = GNUNET_YES;
    }
  if ((policy & QUERY_FORWARD) == 0)
    doForward = GNUNET_NO;

#if DEBUG_GAP
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&query->queries[0], &enc));
  ((char *) &enc)[6] = '\0';
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                 "GAP is executing request for `%s':%s%s (%d)\n",
                 &enc,
                 doForward ? " forwarding" : "", isRouted ? " routing" : "",
                 i);
#endif
  if ((stats != NULL) && (isRouted || doForward))
    stats->change (stat_routing_processed, 1);
  cls.values = NULL;
  cls.valueCount = 0;
  cls.query = query->queries[0];
  if ((isRouted == GNUNET_YES) &&       /* if we can't route, lookup useless! */
      ((policy & QUERY_ANSWER) > 0))
    {
      bs->get (bs->closure,
               ntohl (query->type),
               prio,
               1 + (ntohs (query->header.size)
                    -
                    sizeof (P2P_gap_query_MESSAGE)) /
               sizeof (GNUNET_HashCode), &query->queries[0],
               &queryLocalResultCallback, &cls);
    }

  if (cls.valueCount > 0)
    {
      perm = GNUNET_permute (GNUNET_RANDOM_QUALITY_WEAK, cls.valueCount);
      max =
        GNUNET_network_monitor_get_load (coreAPI->load_monitor,
                                         GNUNET_ND_DOWNLOAD);
      if (max > 100)
        max = 100;
      if (max == -1)
        max = 50;               /* we don't know the load, assume middle-of-the-road */
      max = max / 10;           /* 1 reply per 10% free capacity */
      max = 1 + (10 - max);
      if (max > cls.valueCount)
        max = cls.valueCount;   /* can't send more back then
                                   what we have */

      for (i = 0; i < cls.valueCount; i++)
        {
          if ((i == 0) &&
              (GNUNET_SYSERR == bs->put (bs->closure,
                                         &query->queries[0],
                                         cls.values[perm[i]], ite->priority)))
            {
              GNUNET_GE_BREAK (NULL, 0);
              GNUNET_free (cls.values[perm[i]]);
              continue;
            }
          if ((i < max) &&
              (sender != NULL) &&
              (GNUNET_YES == queueReply (sender,
                                         &query->queries[0],
                                         cls.values[perm[i]]))
              && (stats != NULL))
            stats->change (stat_routing_local_results, 1);
          /* even for local results, always do 'put'
             (at least to give back results to local client &
             to update priority; but only do this for
             the first result */
          if (uri (cls.values[perm[i]], ite->type, GNUNET_NO,   /* no need to verify local results! */
                   &query->queries[0]))
            doForward = GNUNET_NO;      /* we have the one and only answer,
                                           do not bother to forward... */
          GNUNET_free (cls.values[perm[i]]);
        }
      GNUNET_free (perm);
    }
  GNUNET_array_grow (cls.values, cls.valueCount, 0);
  GNUNET_mutex_unlock (lookup_exclusion);
  if (doForward)
    forwardQuery (query, target, sender);
  change_pid_rc (senderID, -1);
  return doForward;
}

/**
 * Content has arrived. We must decide if we want to a) forward it to
 * our clients b) indirect it to other nodes. The routing module
 * should know what to do.  This method checks the routing table if we
 * have a matching route and if yes queues the reply. It also makes
 * sure that we do not send the same reply back on the same route more
 * than once.
 *
 * @param host who sent the content? NULL
 *        for locally found content.
 * @param msg the p2p reply that was received
 * @return how good this content was (effective
 *         priority of the original request)
 */
static int
useContent (const GNUNET_PeerIdentity * host,
            const GNUNET_MessageHeader * pmsg)
{
  const P2P_gap_reply_MESSAGE *msg;
  unsigned int i;
  GNUNET_HashCode contentHC;
  IndirectionTableEntry *ite;
  unsigned int size;
  int ret;
  unsigned int prio;
  GNUNET_DataContainer *value;
  double preference;
  PID_INDEX hostId;
#if DEBUG_GAP
  GNUNET_EncName enc;
  GNUNET_EncName enc2;
#endif

  if (ntohs (pmsg->size) < sizeof (P2P_gap_reply_MESSAGE))
    {
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;     /* invalid! */
    }
  msg = (const P2P_gap_reply_MESSAGE *) pmsg;
#if DEBUG_GAP
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            if (host != NULL) GNUNET_hash_to_enc (&host->hashPubKey, &enc));
  GNUNET_hash_to_enc (&msg->primaryKey, &enc2);
  ((char *) &enc2)[6] = '\0';
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "GAP received content `%s' from `%s'\n",
                 &enc2, (host != NULL) ? (const char *) &enc : "myself");
#endif

  ite = &ROUTING_indTable_[computeRoutingIndex (&msg->primaryKey)];
  ite->successful_local_lookup_in_delay_loop = GNUNET_NO;
  size = ntohs (msg->header.size) - sizeof (P2P_gap_reply_MESSAGE);
  prio = 0;

  if (rhf == NULL)
    {
      if (stats != NULL)
        stats->change (stat_routing_reply_drops, 1);
      return GNUNET_OK;         /* not fully initialized! */
    }
  value = GNUNET_malloc (size + sizeof (GNUNET_DataContainer));
  value->size = htonl (size + sizeof (GNUNET_DataContainer));
  memcpy (&value[1], &msg[1], size);
  rhf (value, &contentHC);

  /* FIRST: check if valid */
  ret = bs->put (bs->closure, &msg->primaryKey, value, 0);
  if (ret == GNUNET_SYSERR)
    {
      GNUNET_EncName enc;

      IF_GELOG (ectx,
                GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                if (host != NULL) GNUNET_hash_to_enc (&host->hashPubKey,
                                                      &enc));
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("GAP received invalid content from `%s'\n"),
                     (host != NULL) ? (const char *) &enc : _("myself"));
      GNUNET_GE_BREAK_OP (ectx, 0);
      GNUNET_free (value);
      return GNUNET_SYSERR;     /* invalid */
    }

  /* SECOND: check if seen */
  GNUNET_mutex_lock (lookup_exclusion);
  for (i = 0; i < ite->seenIndex; i++)
    {
      if (0 == memcmp (&contentHC, &ite->seen[i], sizeof (GNUNET_HashCode)))
        {
          GNUNET_mutex_unlock (lookup_exclusion);
          GNUNET_free (value);
          if (stats != NULL)
            stats->change (stat_routing_reply_dups, 1);
          return 0;             /* seen before, useless */
        }
    }
  GNUNET_mutex_unlock (lookup_exclusion);


  /* THIRD: compute content priority/value and
     send remote reply (ITE processing) */
  hostId = intern_pid (host);
  GNUNET_mutex_lock (lookup_exclusion);
  if (0 ==
      memcmp (&ite->primaryKey, &msg->primaryKey, sizeof (GNUNET_HashCode)))
    {
      prio = ite->priority;
      ite->priority = 0;
      /* remove the sender from the waiting list
         (if the sender was waiting for a response) */
      if (host != NULL)
        {
          for (i = 0; i < ite->hostsWaiting; i++)
            {
              if (hostId == ite->destination[i])
                {
                  change_pid_rc (ite->destination[i], -1);
                  ite->destination[i] =
                    ite->destination[ite->hostsWaiting - 1];
                  if (stats != NULL)
                    stats->change (stat_memory_destinations, -1);
                  GNUNET_array_grow (ite->destination,
                                     ite->hostsWaiting,
                                     ite->hostsWaiting - 1);
                }
            }
        }
      if (stats != NULL)
        stats->change (stat_memory_seen, 1);
      GNUNET_array_grow (ite->seen, ite->seenIndex, ite->seenIndex + 1);
      ite->seen[ite->seenIndex - 1] = contentHC;
      if (ite->seenIndex == 1)
        {
          ite->seenReplyWasUnique = uri (value, ite->type, GNUNET_NO,   /* already verified */
                                         &ite->primaryKey);
        }
      else
        {
          ite->seenReplyWasUnique = GNUNET_NO;
        }
      sendReply (ite, &msg->header);
      if (ite->seenIndex > MAX_SEEN_VALUES * 2)
        {
          /* kill routing entry -- we have seen so many different
             replies already that we cannot afford to continue
             to keep track of all of the responses seen (#1014) */
          resetDestinations (ite);
          resetSeen (ite);
          ite->priority = 0;
          ite->type = 0;
          ite->ttl = 0;
          if (stats != NULL)
            stats->change (stat_routing_slots_used, -1);
        }
    }
  else
    {
      if (stats != NULL)
        stats->change (stat_routing_reply_drops, 1);
    }
  GNUNET_mutex_unlock (lookup_exclusion);
  prio += claimReward (&msg->primaryKey);

  /* FOURTH: update content priority in local datastore */
  if (prio > 0)
    {
      bs->put (bs->closure, &msg->primaryKey, value, prio);
    }

  /* FIFTH: if unique reply, stop querying */
  if (uri (value, ite->type, GNUNET_NO, /* already verified */
           &ite->primaryKey))
    {
      /* unique reply, stop forwarding! */
      dequeueQuery (&ite->primaryKey);
    }
  GNUNET_free (value);

  /* SIXTH: adjust traffic preferences */
  if (host != NULL)
    {                           /* if we are the sender, hostId will be NULL */
      preference = (double) prio;
      identity->changeHostTrust (host, prio);
      for (i = 0; i < ite->hostsWaiting; i++)
        updateResponseData (ite->destination[i], hostId);
      if (preference < CONTENT_BANDWIDTH_VALUE)
        preference = CONTENT_BANDWIDTH_VALUE;
      coreAPI->preferTrafficFrom (host, preference);
    }
  change_pid_rc (hostId, -1);
  return GNUNET_OK;
}

/* ***************** GAP API implementation ***************** */

/**
 * Start GAP.
 *
 * @param datastore the storage callbacks to use for storing data
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
init (GNUNET_Blockstore * datastore, GNUNET_UniqueReplyIdentifierCallback uid,
      GNUNET_ReplyHashingCallback rh)
{
  if (bs != NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  bs = datastore;
  uri = uid;
  rhf = rh;
  return GNUNET_OK;
}

/**
 * Perform a GET operation using 'key' as the key.  Note that no
 * callback is given for the results since GAP just calls PUT on the
 * datastore on anything that is received, and the caller will be
 * listening for these puts.
 *
 * @param target peer to ask primarily (maybe NULL)
 * @param type the type of the block that we're looking for
 * @param anonymityLevel how much cover traffic is required? 1 for none
 *        (0 does not require GAP, 1 requires GAP but no cover traffic)
 * @param keys the keys to query for
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @return GNUNET_OK if we will start to query, GNUNET_SYSERR if all of our
 *  buffers are full or other error, GNUNET_NO if we already
 *  returned the one and only reply (local hit)
 */
static int
get_start (const GNUNET_PeerIdentity * target,
           unsigned int type,
           unsigned int anonymityLevel,
           unsigned int keyCount,
           const GNUNET_HashCode * keys, GNUNET_CronTime timeout,
           unsigned int prio)
{
  P2P_gap_query_MESSAGE *msg;
  unsigned int size;
  int ret;

  size =
    sizeof (P2P_gap_query_MESSAGE) + (keyCount -
                                      1) * sizeof (GNUNET_HashCode);
  if (size >= GNUNET_MAX_BUFFER_SIZE)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;     /* too many keys! */
    }

  /* anonymity level considerations:
     check cover traffic availability! */
  if (anonymityLevel > 0)
    {
      unsigned int count;
      unsigned int peers;
      unsigned int sizes;
      unsigned int timevect;

      anonymityLevel--;
      if (traffic == NULL)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Cover traffic requested but traffic service not loaded.  Rejecting request.\n"));
          return GNUNET_SYSERR;
        }
      if (GNUNET_OK !=
          traffic->get ((TTL_DECREMENT + timeout) / GNUNET_TRAFFIC_TIME_UNIT,
                        GNUNET_P2P_PROTO_GAP_QUERY,
                        GNUNET_TRAFFIC_TYPE_RECEIVED, &count, &peers, &sizes,
                        &timevect))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("Failed to get traffic stats.\n"));
          return GNUNET_SYSERR;
        }
      if (anonymityLevel > 1000)
        {
          if (peers < anonymityLevel / 1000)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _
                             ("Cannot satisfy desired level of anonymity, ignoring request.\n"));
              return GNUNET_SYSERR;
            }
          if (count < anonymityLevel % 1000)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _
                             ("Cannot satisfy desired level of anonymity, ignoring request.\n"));
              return GNUNET_SYSERR;
            }
        }
      else
        {
          if (count < anonymityLevel)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _
                             ("Cannot satisfy desired level of anonymity, ignoring request.\n"));
              return GNUNET_SYSERR;
            }
        }
    }


  msg = GNUNET_malloc (size);
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_P2P_PROTO_GAP_QUERY);
  msg->type = htonl (type);
  msg->priority = htonl (prio);
  msg->ttl = htonl (adjustTTL ((int) timeout - GNUNET_get_time (), prio));
  memcpy (&msg->queries[0], keys, sizeof (GNUNET_HashCode) * keyCount);
  msg->returnTo = *coreAPI->myIdentity;
  ret = execQuery (NULL,
                   target,
                   prio,
                   QUERY_ANSWER | QUERY_FORWARD | QUERY_INDIRECT,
                   timeout - GNUNET_get_time (), msg);
  GNUNET_free (msg);
  return ret;
}

/**
 * Stop sending out queries for a given key.  GAP will automatically
 * stop sending queries at some point, but this method can be used to
 * stop it earlier.
 */
static int
get_stop (unsigned int type, unsigned int keyCount,
          const GNUNET_HashCode * keys)
{
  if (keyCount < 1)
    return GNUNET_SYSERR;
  return dequeueQuery (&keys[0]);
}

/**
 * Try to migrate the given content.
 *
 * @param data the content to migrate
 * @param position where to write the message
 * @param padding the maximum size that the message may be
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
static unsigned int
tryMigrate (const GNUNET_DataContainer * data,
            const GNUNET_HashCode * primaryKey,
            char *position, unsigned int padding)
{
  P2P_gap_reply_MESSAGE *reply;
  unsigned int size;

  size =
    sizeof (P2P_gap_reply_MESSAGE) + ntohl (data->size) -
    sizeof (GNUNET_DataContainer);
  if ((size > padding) || (size >= GNUNET_MAX_BUFFER_SIZE))
    return 0;
  reply = (P2P_gap_reply_MESSAGE *) position;
  reply->header.type = htons (GNUNET_P2P_PROTO_GAP_RESULT);
  reply->header.size = htons (size);
  reply->primaryKey = *primaryKey;
  memcpy (&reply[1], &data[1], size - sizeof (P2P_gap_reply_MESSAGE));
  return size;
}

/**
 * Handle query for content. Depending on how we like the sender,
 * lookup, forward or even indirect.
 */
static int
handleQuery (const GNUNET_PeerIdentity * sender,
             const GNUNET_MessageHeader * msg)
{
  QUERY_POLICY policy;
  P2P_gap_query_MESSAGE *qmsg;
  unsigned int queries;
  int ttl;
  unsigned int prio;
  double preference;
#if DEBUG_GAP
  GNUNET_EncName enc;
#endif

  if (bs == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return 0;
    }
  /* Load above hard limit? */
  if (loadTooHigh ())
    {
#if DEBUG_GAP
      if (sender != NULL)
        {
          IF_GELOG (ectx,
                    GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                    GNUNET_hash_to_enc (&sender->hashPubKey, &enc));
        }
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Dropping query from %s, this peer is too busy.\n",
                     sender == NULL ? "localhost" : (char *) &enc);
#endif
      return GNUNET_OK;
    }
  queries = 1 + (ntohs (msg->size) - sizeof (P2P_gap_query_MESSAGE))
    / sizeof (GNUNET_HashCode);
  if ((queries <= 0) ||
      (ntohs (msg->size) < sizeof (P2P_gap_query_MESSAGE)) ||
      (ntohs (msg->size) != sizeof (P2P_gap_query_MESSAGE) +
       (queries - 1) * sizeof (GNUNET_HashCode)))
    {
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;     /* malformed query */
    }

  qmsg = GNUNET_malloc (ntohs (msg->size));
  memcpy (qmsg, msg, ntohs (msg->size));
  if (0 == memcmp (&qmsg->returnTo.hashPubKey,
                   &coreAPI->myIdentity->hashPubKey,
                   sizeof (GNUNET_HashCode)))
    {
      /* A to B, B sends to C without source rewriting,
         C sends back to A again without source rewriting;
         (or B directly back to A; also should not happen)
         in this case, A must just drop; however, this
         should not happen (peers should check). */
      GNUNET_GE_BREAK_OP (ectx, 0);
      GNUNET_free (qmsg);
      return GNUNET_OK;
    }
  if (stats != NULL)
    stats->change (stat_routing_totals, 1);

  /* decrement ttl (always) */
  ttl = ntohl (qmsg->ttl);
  if (ttl < 0)
    {
      ttl =
        ttl - 2 * TTL_DECREMENT -
        GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, TTL_DECREMENT);
      if (ttl > 0)
        {                       /* integer underflow => drop (should be very rare)! */
          GNUNET_free (qmsg);
          if (stats != NULL)
            stats->change (stat_routing_direct_drops, 1);
          return GNUNET_OK;     /* just abort */
        }
    }
  else
    {
      ttl =
        ttl - 2 * TTL_DECREMENT -
        GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, TTL_DECREMENT);
    }
  prio = ntohl (qmsg->priority);
  policy = evaluateQuery (sender, &prio);
#if DEBUG_GAP
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&qmsg->queries[0], &enc));
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received GAP query `%s'.\n", &enc);
#endif
  if ((policy & QUERY_DROPMASK) == 0)
    {
      /* policy says no answer/forward/indirect => direct drop;
         this happens if the peer is too busy (netload-up >= 100%).  */
      GNUNET_free (qmsg);
#if DEBUG_GAP
      if (sender != NULL)
        {
          IF_GELOG (ectx,
                    GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                    GNUNET_hash_to_enc (&sender->hashPubKey, &enc));
        }
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Dropping query from %s, policy decided that this peer is too busy.\n",
                     sender == NULL ? "localhost" : (const char *) &enc);
#endif
      if (stats != NULL)
        stats->change (stat_routing_direct_drops, 1);
      return GNUNET_OK;         /* straight drop. */
    }
  preference = (double) prio;
  if ((policy & QUERY_INDIRECT) > 0)
    {
      qmsg->returnTo = *coreAPI->myIdentity;
    }
  else
    {
      /* otherwise we preserve the original sender
         and kill the priority (since we cannot benefit) */
      prio = 0;
    }

  if (preference < QUERY_BANDWIDTH_VALUE)
    preference = QUERY_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom (sender, preference);
  /* adjust priority */
  qmsg->priority = htonl (prio);
  qmsg->ttl = htonl (adjustTTL (ttl, prio));

  ttl = ntohl (qmsg->ttl);
  if (ttl < 0)
    ttl = 0;
  execQuery (sender, NULL, prio, policy, ttl, qmsg);
  GNUNET_free (qmsg);
  return GNUNET_OK;
}

static unsigned int
getAvgPriority ()
{
  IndirectionTableEntry *ite;
  unsigned long long tot;
  int i;
  unsigned int active;

  tot = 0;
  active = 0;
  for (i = indirectionTableSize - 1; i >= 0; i--)
    {
      ite = &ROUTING_indTable_[i];
      if ((ite->hostsWaiting > 0) && (ite->seenIndex == 0))
        {
          tot += ite->priority;
          active++;
        }
    }
  if (active == 0)
    return 0;
  else
    return (unsigned int) (tot / active);
}


GNUNET_GAP_ServiceAPI *
provide_module_gap (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_GAP_ServiceAPI api;
  unsigned int i;

  ectx = capi->ectx;
  cfg = capi->cfg;
  coreAPI = capi;
  if ((-1 == GNUNET_GC_get_configuration_value_number (cfg, "LOAD", "HARDCPULIMIT", 0, 100000,  /* 1000 CPUs!? */
                                                       0,       /* 0 == no limit */
                                                       &hardCPULimit)) || (-1 == GNUNET_GC_get_configuration_value_number (cfg, "LOAD", "HARDUPLIMIT", 0, 999999999, 0, /* 0 == no limit */
                                                                                                                           &hardUpLimit))
      || (-1 ==
          GNUNET_GC_get_configuration_value_number (cfg, "GAP", "TABLESIZE",
                                                    MIN_INDIRECTION_TABLE_SIZE,
                                                    GNUNET_MAX_GNUNET_malloc_CHECKED
                                                    /
                                                    sizeof
                                                    (IndirectionTableEntry),
                                                    MIN_INDIRECTION_TABLE_SIZE,
                                                    &indirectionTableSize)))
    return NULL;
  GNUNET_GE_ASSERT (ectx, sizeof (P2P_gap_reply_MESSAGE) == 68);
  GNUNET_GE_ASSERT (ectx, sizeof (P2P_gap_query_MESSAGE) == 144);

  stats = capi->request_service ("stats");
  if (stats != NULL)
    {
      stat_routing_totals =
        stats->create (gettext_noop ("# gap requests total received"));
      stat_routing_direct_drops =
        stats->
        create (gettext_noop ("# gap requests policy: immediate drop"));
      stat_routing_no_route_policy =
        stats->create (gettext_noop ("# gap requests policy: not routed"));
      stat_routing_no_answer_policy =
        stats->create (gettext_noop ("# gap requests policy: not answered"));
      stat_routing_processed =
        stats->
        create (gettext_noop
                ("# gap requests processed: attempted add to RT"));
      stat_routing_local_results =
        stats->
        create (gettext_noop ("# gap requests processed: local result"));
      stat_routing_successes =
        stats->create (gettext_noop ("# gap routing successes (total)"));
      stat_routing_collisions =
        stats->
        create (gettext_noop ("# gap requests dropped: collision in RT"));
      stat_routing_forwards =
        stats->
        create (gettext_noop
                ("# gap requests forwarded (counting each peer)"));
      stat_routing_request_duplicates =
        stats->create (gettext_noop ("# gap duplicate requests (pending)"));
      stat_routing_request_repeat =
        stats->
        create (gettext_noop ("# gap duplicate requests that were re-tried"));
      stat_routing_request_repeat_dttl =
        stats->
        create (gettext_noop ("# gap re-try ttl difference (cummulative)"));
      stat_routing_reply_dups =
        stats->create (gettext_noop ("# gap reply duplicates"));
      stat_routing_reply_drops =
        stats->create (gettext_noop ("# gap spurious replies (dropped)"));
      stat_routing_slots_used =
        stats->create (gettext_noop ("# gap routing slots currently in use"));
      stat_memory_seen =
        stats->
        create (gettext_noop ("# gap memory used for tracking seen content"));
      stat_memory_destinations =
        stats->
        create (gettext_noop
                ("# gap memory used for tracking routing destinations"));
      stat_pending_rewards =
        stats->create (gettext_noop ("# gap rewards pending"));
      stat_response_count =
        stats->create (gettext_noop ("# gap response weights"));
    }
  init_pid_table (ectx, stats);
  GNUNET_array_grow (rewards, rewardSize, MAX_REWARD_TRACKS);


  identity = coreAPI->request_service ("identity");
  GNUNET_GE_ASSERT (ectx, identity != NULL);
  topology = coreAPI->request_service ("topology");
  GNUNET_GE_ASSERT (ectx, topology != NULL);
  traffic = coreAPI->request_service ("traffic");
  if (traffic == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Traffic service failed to load; gap cannot ensure cover-traffic availability.\n"));
    }
  random_qsel = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 0xFFFF);
  lookup_exclusion = GNUNET_mutex_create (GNUNET_NO);
  ROUTING_indTable_
    = GNUNET_malloc (sizeof (IndirectionTableEntry) * indirectionTableSize);
  memset (ROUTING_indTable_,
          0, sizeof (IndirectionTableEntry) * indirectionTableSize);
  for (i = 0; i < indirectionTableSize; i++)
    {
      ROUTING_indTable_[i].successful_local_lookup_in_delay_loop = GNUNET_NO;
    }

  for (i = 0; i < QUERY_RECORD_COUNT; i++)
    {
      queries[i].expires = 0;   /* all expired */
      queries[i].msg = NULL;
    }
  lock = coreAPI->connection_get_lock ();
  GNUNET_cron_add_job (capi->cron, &ageRTD, 2 * GNUNET_CRON_MINUTES,
                       2 * GNUNET_CRON_MINUTES, NULL);

  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering handlers %d %d\n"),
                 "gap", GNUNET_P2P_PROTO_GAP_QUERY,
                 GNUNET_P2P_PROTO_GAP_RESULT);
  capi->registerHandler (GNUNET_P2P_PROTO_GAP_QUERY, &handleQuery);
  capi->registerHandler (GNUNET_P2P_PROTO_GAP_RESULT, &useContent);
  coreAPI->
    connection_register_send_callback (sizeof
                                       (P2P_gap_query_MESSAGE), &fillInQuery);

  api.init = &init;
  api.get_start = &get_start;
  api.get_stop = &get_stop;
  api.tryMigrate = &tryMigrate;
  api.getAvgPriority = &getAvgPriority;
  return &api;
}

void
release_module_gap ()
{
  unsigned int i;
  ResponseList *rpos;
  ReplyTrackData *pos;
  IndirectionTableEntry *ite;

  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_GAP_QUERY, &handleQuery);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_GAP_RESULT, &useContent);
  coreAPI->
    connection_unregister_send_callback (sizeof
                                         (P2P_gap_query_MESSAGE),
                                         &fillInQuery);

  GNUNET_cron_del_job (coreAPI->cron, &ageRTD, 2 * GNUNET_CRON_MINUTES, NULL);

  for (i = 0; i < indirectionTableSize; i++)
    {
      ite = &ROUTING_indTable_[i];
      resetSeen (ite);
      ite->seenReplyWasUnique = GNUNET_NO;
      resetDestinations (ite);
    }

  GNUNET_mutex_destroy (lookup_exclusion);
  lookup_exclusion = NULL;
  while (rtdList != NULL)
    {
      pos = rtdList;
      rtdList = rtdList->next;
      while (pos->responseList != NULL)
        {
          rpos = pos->responseList;
          pos->responseList = rpos->next;
          GNUNET_free (rpos);
        }
      GNUNET_free (pos);
    }
  for (i = 0; i < QUERY_RECORD_COUNT; i++)
    GNUNET_free_non_null (queries[i].msg);

  coreAPI->release_service (identity);
  identity = NULL;
  coreAPI->release_service (topology);
  topology = NULL;
  if (traffic != NULL)
    {
      coreAPI->release_service (traffic);
      traffic = NULL;
    }
  GNUNET_free (ROUTING_indTable_);
  GNUNET_array_grow (rewards, rewardSize, 0);
  done_pid_table ();
  if (stats != NULL)
    {
      stats->set (stat_pending_rewards, 0);
      coreAPI->release_service (stats);
      stats = NULL;
    }
  lock = NULL;
  coreAPI = NULL;
  bs = NULL;
  uri = NULL;
  ectx = NULL;
  cfg = NULL;
}

/* end of gap.c */
