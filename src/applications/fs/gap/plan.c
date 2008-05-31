/*
      This file is part of GNUnet
      (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file fs/gap/plan.c
 * @brief code to plan when to send requests where
 * @author Christian Grothoff
 */

#include "platform.h"
#include <math.h>
#include "gnunet_protocols.h"
#include "gnunet_stats_service.h"
#include "plan.h"
#include "pid_table.h"
#include "fs_dht.h"
#include "fs.h"
#include "gap.h"
#include "shared.h"

/**
 * How many entires are we allowed to plan-ahead
 * per peer (at most)?
 */
#define MAX_ENTRIES_PER_PEER 64


/**
 * Linked list summarizing how good other peers
 * were at producing responses for a client.
 */
struct PeerHistoryList
{

  /**
   * This is a linked list.
   */
  struct PeerHistoryList *next;

  /**
   * Last time we transmitted a request to this peer.
   */
  GNUNET_CronTime last_request_time;

  /**
   * Last time we received a response from this peer.
   */
  GNUNET_CronTime last_response_time;

  /**
   * What peer is this history entry for?
   */
  PID_INDEX peer;

  /**
   * Total number of requests send to the peer so far.
   */
  unsigned int request_count;

  /**
   * Total number of replies received from this peer so far.
   */
  unsigned int response_count;

  /**
   * TTL value used for last successful request.
   */
  int last_good_ttl;

  /**
   * Priority value used for last successful request.
   */
  unsigned int last_good_prio;

  /**
   * (Relative) TTL used in the last request.
   */
  int last_ttl_used;

  /**
   * Priority used for the last request.
   */
  unsigned int last_prio_used;

};

/**
 * Linked list with information for each client.
 */
struct ClientInfoList
{

  /**
   * This is a linked list.
   */
  struct ClientInfoList *next;

  /**
   * For which client is this data kept (NULL
   * if the "client" is another peer).
   */
  struct GNUNET_ClientHandle *client;

  /**
   * List of the history of reactions of other peers
   * to queries from this client.
   */
  struct PeerHistoryList *history;

  /**
   * If "client" is NULL, this is the peer for
   * which this is the history.
   */
  PID_INDEX peer;

};

/**
 * Linked list of rankings given to connected peers.  This list is
 * used to determine which peers should be considered for forwarding
 * of the query.
 */
struct PeerRankings
{
  /**
   * This is a linked list.
   */
  struct PeerRankings *next;

  /**
   * Peer that is being ranked.
   */
  PID_INDEX peer;

  /**
   * Recommended priority for this peer.
   */
  unsigned int prio;

  /**
   * Recommended Time-to-live for this peer.
   */
  int ttl;

  /**
   * Client score (higher is better).
   */
  unsigned int score;

  /**
   * How much bandwidth were we able to
   * reserve from gnunetd (0 to 32k) for
   * responses to an eventual query.
   */
  int reserved_bandwidth;

};


static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * Plan for query execution (for each peer, a list of
 * requests and when we should consider transmitting
 * them).
 */
static struct QueryPlanList *queries;

/**
 * Information about the performance of peers
 * for requests from various clients.
 */
static struct ClientInfoList *clients;

/**
 * Log_e(2).
 */
static double LOG_2;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_gap_query_sent;

static int stat_gap_query_planned;

static int stat_gap_query_success;

static int stat_trust_spent;

/**
 * Find the entry in the client list corresponding
 * to the given client information.  If no such entry
 * exists, create one.
 */
static struct ClientInfoList *
find_or_create_client_entry (struct GNUNET_ClientHandle *client,
                             PID_INDEX peer)
{
  struct ClientInfoList *cl;

  cl = clients;
  while (cl != NULL)
    {
      if (((cl->client != NULL) &&
           (cl->client == client)) || ((cl->peer != 0) && (cl->peer == peer)))
        break;
      cl = cl->next;
    }
  if (cl != NULL)
    return cl;
  cl = GNUNET_malloc (sizeof (struct ClientInfoList));
  memset (cl, 0, sizeof (struct ClientInfoList));
  cl->next = clients;
  clients = cl;
  cl->client = client;
  cl->peer = peer;
  GNUNET_FS_PT_change_rc (peer, 1);
  return cl;
}

/**
 * Find the entry in the history corresponding
 * to the given peer ID.  If no such entry
 * exists, create one.
 */
static struct PeerHistoryList *
find_or_create_history_entry (struct ClientInfoList *cl, PID_INDEX responder)
{
  struct PeerHistoryList *hl;

  hl = cl->history;
  while (hl != NULL)
    {
      if (hl->peer == responder)
        break;
      hl = hl->next;
    }
  if (hl != NULL)
    return hl;
  hl = GNUNET_malloc (sizeof (struct PeerHistoryList));
  memset (hl, 0, sizeof (struct PeerHistoryList));
  hl->next = cl->history;
  cl->history = hl;
  hl->peer = responder;
  GNUNET_FS_PT_change_rc (responder, 1);
  return hl;
}

struct QueryPlanList *
find_or_create_query_plan_list (PID_INDEX target)
{
  struct QueryPlanList *qpl;

  /* find query plan for target */
  qpl = queries;
  while ((qpl != NULL) && (qpl->peer != target))
    qpl = qpl->next;
  if (qpl == NULL)
    {
      qpl = GNUNET_malloc (sizeof (struct QueryPlanList));
      memset (qpl, 0, sizeof (struct QueryPlanList));
      qpl->peer = target;
      GNUNET_FS_PT_change_rc (target, 1);
      qpl->next = queries;
      queries = qpl;
    }
  return qpl;
}

static unsigned int
count_query_plan_entries (struct QueryPlanList *qpl)
{
  struct QueryPlanEntry *pos;
  unsigned int total;

  total = 0;
  pos = qpl->head;
  while (pos != NULL)
    {
      total++;
      pos = pos->next;
    }
  return total;
}

/**
 * Add the given request to the list of pending requests for the
 * specified target.  A random position in the queue will
 * be used.
 *
 * @param target what peer to send the request to
 * @param request the request to send
 * @param ttl time-to-live for the request
 * @param priority priority to use for the request
 */
static void
queue_request (PID_INDEX target,
               struct RequestList *request, int ttl, unsigned int prio)
{
  struct QueryPlanList *qpl;
  struct QueryPlanEntry *entry;
  struct QueryPlanEntry *pos;
  unsigned int total;

  /* find query plan for target */
  qpl = find_or_create_query_plan_list (target);
  /* construct entry */
  entry = GNUNET_malloc (sizeof (struct QueryPlanEntry));
  memset (entry, 0, sizeof (struct QueryPlanEntry));
  entry->request = request;
  entry->prio = prio;
  entry->ttl = GNUNET_FS_HELPER_bound_ttl (ttl, prio);
  entry->list = qpl;
  /* insert entry into request plan entries list */
  entry->plan_entries_next = request->plan_entries;
  request->plan_entries = entry;

  if (stats != NULL)
    stats->change (stat_gap_query_planned, 1);
  /* compute (random) insertion position in doubly-linked list */
  total = count_query_plan_entries (qpl);
  total = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, total + 1);
  pos = qpl->head;
  while (total-- > 0)
    pos = pos->next;
  /* insert into datastructure at pos */
  if (pos == NULL)
    {
      if (qpl->tail != NULL)
        qpl->tail->next = entry;
      else
        qpl->head = entry;
      entry->prev = qpl->tail;
      qpl->tail = entry;
    }
  else
    {
      entry->next = pos->next;
      if (pos->next == NULL)
        qpl->tail = entry;
      else
        pos->next->prev = entry;
      entry->prev = pos;
      pos->next = entry;
    }
}

/**
 * Closure for rank_peers callback function.
 */
struct RankingPeerContext
{
  struct PeerRankings *rankings;
  struct ClientInfoList *info;
  struct RequestList *request;
};

/**
 * Rank peers by their quality for a given
 * request (using history with client,
 * bandwidth availability, query proximity)
 *
 * @param identity the id of the node
 */
static void
rank_peers (const GNUNET_PeerIdentity * identity, void *data)
{
  struct RankingPeerContext *rpc = data;
  struct PeerRankings *rank;
  struct PeerHistoryList *history;
  long long history_score;
  unsigned int proximity_score;
  GNUNET_CronTime now;
  GNUNET_CronTime last;
  unsigned int prio;
  int ttl;
  unsigned int allowable_prio;
  long long score;
  PID_INDEX peer;

  peer = GNUNET_FS_PT_intern (identity);
  if ((peer == rpc->request->response_target) ||
      (count_query_plan_entries (find_or_create_query_plan_list (peer)) >
       MAX_ENTRIES_PER_PEER))
    {
      GNUNET_FS_PT_change_rc (peer, -1);
      return;                   /* ignore! */
    }
  rank = GNUNET_malloc (sizeof (struct PeerRankings));
  memset (rank, 0, sizeof (struct PeerRankings));
  rank->peer = peer;
  rank->reserved_bandwidth =
    coreAPI->p2p_bandwidth_downstream_reserve (identity,
                                               GNUNET_GAP_ESTIMATED_DATA_SIZE);
  history = NULL;
  if (rpc->info != NULL)
    {
      history = rpc->info->history;
      while ((history != NULL) && (history->peer != rank->peer))
        history = history->next;
    }
  now = GNUNET_get_time ();
  history_score = 0;            /* no bias from history */
  if ((history != NULL) && (history->request_count > 0))
    {
      last = history->last_response_time;
      if (last >= now)
        last = now - 1;
      /* the more responses we have in relation
         to the number of requests we sent, the
         higher we score; the score is the more
         significant the more recent the last
         response was */
      history_score
        =
        (GNUNET_GAP_MAX_GAP_DELAY * history->response_count) /
        (history->request_count * (now - last));
      if (history->response_count == 0)
        history_score =
          -history->request_count * coreAPI->p2p_connections_iterate (NULL,
                                                                      NULL);
      if (history_score > (1 << 30))
        history_score = (1 << 30);
    }
  /* check query proximity */
  proximity_score =
    GNUNET_hash_distance_u32 (&rpc->request->queries[0],
                              &identity->hashPubKey);

  /* generate score, ttl and priority */
  prio = rpc->request->last_prio_used + GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 2);      /* increase over time */
  if ((history != NULL) && (prio < history->last_good_prio))
    prio = history->last_good_prio - GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 2); /* fall over time */
  if (prio > 1)
    {
      allowable_prio = GNUNET_FS_GAP_get_average_priority () + 1;
      if (prio > allowable_prio)
        prio = allowable_prio;
    }
  if ((rpc->request->response_client == NULL) &&
      (prio > rpc->request->remaining_value))
    prio = rpc->request->remaining_value;
  if (prio > 0)
    {
      ttl = (1 << 30);          /* bound only by priority */
    }
  else
    {
      if (rpc->request->response_client != NULL)
        ttl = 0;                /* initiator expiration is always "now" */
      else
        {
          ttl =
            (int) (((long long) (rpc->request->expiration -
                                 now)) / (long long) GNUNET_CRON_SECONDS);
        }
      if (ttl < 0)
        {
          ttl -=
            GNUNET_GAP_TTL_DECREMENT +
            GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                               2 * GNUNET_GAP_TTL_DECREMENT);
          if (ttl > 0)          /* integer underflow */
            ttl = -(1 << 30);
        }
      else
        {
          ttl -=
            GNUNET_GAP_TTL_DECREMENT +
            GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                               2 * GNUNET_GAP_TTL_DECREMENT);
        }
    }
  ttl = GNUNET_FS_HELPER_bound_ttl (ttl, prio);
  rank->prio = prio;
  rank->ttl = ttl;

  /* compute combined score */
  /* open question: any good weights for the scoring? */
  score = history_score + rank->reserved_bandwidth - proximity_score;
  if (score <= -(1 << 16))
    {
      /* would underflow, use lowest legal score */
      rank->score = 1;
    }
  else
    {
      rank->score = (unsigned int) ((1 << 16) + score);
      if (rank->score < score)  /* integer overflow */
        rank->score = -1;       /* max int */
    }

  /* insert into ranking list */
  rank->next = rpc->rankings;
  rpc->rankings = rank;
}

/**
 * Plan the transmission of the given request.  Use the history of the
 * request and the client to schedule the request for transmission.<p>
 *
 * This method is probably the most important function in the
 * anonymous file-sharing module.  It determines for each query where
 * it should be forwarded (to which peers, to how many peers) and what
 * its TTL and priority values should be.<p>
 *
 * @param client maybe NULL, in which case peer is significant
 * @param peer sender of the request (if not a local client)
 * @param request to plan
 * @return GNUNET_YES if the request is being planned, GNUNET_NO if not,
 *         GNUNET_SYSERR on error
 */
int
GNUNET_FS_PLAN_request (struct GNUNET_ClientHandle *client,
                        PID_INDEX peer, struct RequestList *request)
{
  struct ClientInfoList *info;
  struct PeerRankings *rank;
  struct RankingPeerContext rpc;
  GNUNET_PeerIdentity peerId;
  unsigned int target_count;
  unsigned int i;
  unsigned int total_peers;
  unsigned long long total_score;
  unsigned long long selector;
  double entropy;
  double prob;

  GNUNET_mutex_lock (GNUNET_FS_lock);   /* needed? */
  info = clients;
  while ((info != NULL) && ((info->client != client) || (info->peer != peer)))
    info = info->next;

  /* for all connected peers compute ranking */
  rpc.info = info;
  rpc.request = request;
  rpc.rankings = NULL;
  total_peers = coreAPI->p2p_connections_iterate (rank_peers, &rpc);
  /* use request type, priority, system load and
     entropy of ranking to determine number of peers
     to queue */

  /* use biased random selection to select
     peers according to ranking; add requests */
  total_score = 0;
  rank = rpc.rankings;
  while (rank != NULL)
    {
      GNUNET_GE_ASSERT (NULL, rank->score > 0);
      total_score += rank->score;
      rank = rank->next;
    }
  if (total_score == 0)
    {
      GNUNET_mutex_unlock (GNUNET_FS_lock);
      return GNUNET_NO;         /* no peers available */
    }

  entropy = 0;
  rank = rpc.rankings;
  while (rank != NULL)
    {
      prob = 1.0 * rank->score / total_score;
      if (prob > 0.000000001)
        entropy -= prob * log (prob) / LOG_2;
      rank = rank->next;
    }

  if (entropy < 0.001)
    entropy = 0.001;            /* should only be possible if we have virtually only one choice */
  target_count = (unsigned int) ceil (entropy);
  /* limit target count based on value of the reqeust */
  if (target_count > 2 * request->value + 3)
    target_count = 2 * request->value + 3;

  if (target_count > total_peers)
    target_count = total_peers;

  /* select target_count peers */
  for (i = 0; i < target_count; i++)
    {
      selector = GNUNET_random_u64 (GNUNET_RANDOM_QUALITY_WEAK, total_score);
      rank = rpc.rankings;
      while (rank != NULL)
        {
          if (rank->score > selector)
            {
              if (request->response_client == NULL)
                {
                  if (rank->prio > request->remaining_value)
                    {
                      if ((i == target_count - 1) ||
                          (request->remaining_value == 0))
                        rank->prio = request->remaining_value;
                      else
                        rank->prio =
                          GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                             request->remaining_value);
                    }
                  request->remaining_value -= rank->prio;
                }
              queue_request (rank->peer, request, rank->ttl, rank->prio);
              total_score -= rank->score;
              rank->score = 0;  /* mark as used */
              break;
            }
          selector -= rank->score;
          rank = rank->next;
        }
    }

  /* free rpc.rankings list */
  while (rpc.rankings != NULL)
    {
      rank = rpc.rankings;
      rpc.rankings = rank->next;
      GNUNET_FS_PT_resolve (rank->peer, &peerId);
      if (rank->score != 0)
        coreAPI->p2p_bandwidth_downstream_reserve (&peerId,
                                                   -rank->reserved_bandwidth);
      GNUNET_FS_PT_change_rc (rank->peer, -1);
      GNUNET_free (rank);
    }
  GNUNET_mutex_unlock (GNUNET_FS_lock);
  return target_count > 0 ? GNUNET_YES : GNUNET_NO;
}

/**
 * Try to add the given request to the buffer.
 *
 * @param available size of the buffer
 * @return number of bytes written to the buffer
 */
static unsigned int
try_add_request (struct RequestList *req,
                 unsigned int prio,
                 int ttl, void *buf, unsigned int available)
{
  P2P_gap_query_MESSAGE *msg = buf;
  unsigned int size;
  GNUNET_CronTime now;

  GNUNET_GE_ASSERT (NULL, req->key_count > 0);
  size = sizeof (P2P_gap_query_MESSAGE)
    + req->bloomfilter_size + (req->key_count - 1) * sizeof (GNUNET_HashCode);
  if (size > available)
    return 0;
  if ((prio > req->remaining_value) && (req->response_client == NULL))
    prio = req->remaining_value;
  ttl = GNUNET_FS_HELPER_bound_ttl (ttl, prio);
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_P2P_PROTO_GAP_QUERY);
  msg->type = htonl (req->type);
  msg->priority = htonl (prio);
  msg->ttl = htonl (ttl);
  msg->filter_mutator = htonl (req->bloomfilter_mutator);
  msg->number_of_queries = htonl (req->key_count);
  if (0 != (req->policy & GNUNET_FS_RoutingPolicy_INDIRECT))
    msg->returnTo = *coreAPI->my_identity;
  else
    GNUNET_FS_PT_resolve (req->response_target, &msg->returnTo);
  memcpy (&msg->queries[0],
          &req->queries[0], req->key_count * sizeof (GNUNET_HashCode));
  if (req->bloomfilter != NULL)
    GNUNET_bloomfilter_get_raw_data (req->bloomfilter,
                                     (char *) &msg->queries[req->key_count],
                                     req->bloomfilter_size);
  now = GNUNET_get_time ();
  if (now + ttl > req->last_request_time + req->last_ttl_used)
    {
      req->last_request_time = now;
      req->last_prio_used = prio;
      req->last_ttl_used = ttl;
    }
  req->remaining_value -= prio;
  if (stats != NULL)
    {
      stats->change (stat_gap_query_sent, 1);
      stats->change (stat_trust_spent, prio);
    }
  return size;
}

/**
 * The core has space for a query, find one!
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
query_fill_callback (const GNUNET_PeerIdentity *
                     receiver, void *position, unsigned int padding)
{
  char *buf = position;
  struct QueryPlanList *pl;
  struct QueryPlanEntry *e;
  struct QueryPlanEntry *n;
  struct QueryPlanEntry *pos;
  struct QueryPlanEntry *prev;
  struct PeerHistoryList *hl;
  struct ClientInfoList *cl;
  PID_INDEX peer;
  unsigned int off;
  unsigned int ret;

  off = 0;
  peer = GNUNET_FS_PT_intern (receiver);
  GNUNET_mutex_lock (GNUNET_FS_lock);
  pl = queries;
  while ((pl != NULL) && (pl->peer != peer))
    pl = pl->next;
  if (pl != NULL)
    {
      e = pl->head;
      while ((e != NULL) && (padding - off >= sizeof (P2P_gap_query_MESSAGE)))
        {
          ret = try_add_request (e->request,
                                 e->prio, e->ttl, &buf[off], padding - off);
          n = e->next;
          if (ret != 0)
            {
              /* remove e from e's doubly-linked list */
              if (e->prev != NULL)
                e->prev->next = e->next;
              else
                pl->head = e->next;
              if (e->next != NULL)
                e->next->prev = e->prev;
              else
                pl->tail = e->prev;
              /* remove e from singly-linked list of request */
              prev = NULL;
              pos = e->request->plan_entries;
              while (pos != e)
                {
                  prev = pos;
                  pos = pos->plan_entries_next;
                }
              if (prev == NULL)
                e->request->plan_entries = e->plan_entries_next;
              else
                prev->plan_entries_next = e->plan_entries_next;
              cl = find_or_create_client_entry (e->request->response_client,
                                                e->request->response_target);
              GNUNET_free (e);
              hl = find_or_create_history_entry (cl, peer);
              hl->last_request_time = GNUNET_get_time ();
              hl->request_count++;
            }
          off += ret;
          e = n;
        }
    }
  GNUNET_mutex_unlock (GNUNET_FS_lock);
  GNUNET_FS_PT_change_rc (peer, -1);
  return off;
}

static void
free_client_info_list (struct ClientInfoList *pos)
{
  struct PeerHistoryList *ph;

  while (pos->history != NULL)
    {
      ph = pos->history;
      pos->history = ph->next;
      GNUNET_FS_PT_change_rc (ph->peer, -1);
      GNUNET_free (ph);
    }
  GNUNET_FS_PT_change_rc (pos->peer, -1);
  GNUNET_free (pos);
}

/**
 * Method called whenever a given client disconnects.
 * Frees all of the associated data structures.
 */
static void
handle_client_exit (struct GNUNET_ClientHandle *client)
{
  struct ClientInfoList *pos;
  struct ClientInfoList *prev;

  GNUNET_mutex_lock (GNUNET_FS_lock);
  pos = clients;
  prev = NULL;
  while (pos != NULL)
    {
      if (pos->client == client)
        {
          if (prev == NULL)
            clients = pos->next;
          else
            prev->next = pos->next;
          free_client_info_list (pos);
          if (prev == NULL)
            pos = clients;
          else
            pos = prev->next;
        }
      else
        {
          prev = pos;
          pos = pos->next;
        }
    }
  GNUNET_mutex_unlock (GNUNET_FS_lock);
}


/**
 * Notify the plan that a request succeeded.
 */
void
GNUNET_FS_PLAN_success (PID_INDEX responder,
                        struct GNUNET_ClientHandle *client,
                        PID_INDEX peer, const struct RequestList *success)
{
  struct ClientInfoList *cl;
  struct PeerHistoryList *hl;

  GNUNET_mutex_lock (GNUNET_FS_lock);
  cl = find_or_create_client_entry (client, peer);
  hl = find_or_create_history_entry (cl, responder);
  hl->response_count++;
  hl->last_good_ttl = success->last_ttl_used;
  hl->last_good_prio = success->last_prio_used;
  hl->last_response_time = GNUNET_get_time ();
  hl->response_count++;
  GNUNET_mutex_unlock (GNUNET_FS_lock);
  if (stats != NULL)
    stats->change (stat_gap_query_success, 1);
}

/**
 * Free the given query plan list and all of its entries.
 */
static void
free_query_plan_list (struct QueryPlanList *qpl)
{
  struct QueryPlanEntry *el;
  struct QueryPlanEntry *pred;

  while (qpl->head != NULL)
    {
      el = qpl->head;
      qpl->head = el->next;
      pred = el->request->plan_entries;
      if (pred == el)
        el->request->plan_entries = el->plan_entries_next;
      else
        {
          while (pred->plan_entries_next != el)
            pred = pred->plan_entries_next;
          pred->plan_entries_next = el->plan_entries_next;
        }
      GNUNET_free (el);
    }
  GNUNET_FS_PT_change_rc (qpl->peer, -1);
  GNUNET_free (qpl);
}

/**
 * Connection to another peer was cut.  Clean up
 * all state associated with that peer (except for
 * active requests, that's not our job).
 */
static void
peer_disconnect_handler (const GNUNET_PeerIdentity * peer, void *unused)
{
  PID_INDEX pid;
  struct QueryPlanList *qpos;
  struct QueryPlanList *qprev;
  struct ClientInfoList *cpos;
  struct ClientInfoList *cprev;

  GNUNET_mutex_lock (GNUNET_FS_lock);
  pid = GNUNET_FS_PT_intern (peer);
  qprev = NULL;
  qpos = queries;
  while (qpos != NULL)
    {
      if (qpos->peer == pid)
        {
          if (qprev != NULL)
            qprev->next = qpos->next;
          else
            queries = qpos->next;
          free_query_plan_list (qpos);
          if (qprev != NULL)
            qpos = qprev->next;
          else
            qpos = queries;
          continue;
        }
      qprev = qpos;
      qpos = qpos->next;
    }
  cprev = NULL;
  cpos = clients;
  while (cpos != NULL)
    {
      if ((cpos->peer == pid) && (cpos->client == NULL))
        {
          if (cprev == NULL)
            clients = cpos->next;
          else
            cprev->next = cpos->next;
          free_client_info_list (cpos);
          if (cprev == NULL)
            cpos = clients;
          else
            cpos = cprev->next;
          continue;
        }
      cprev = cpos;
      cpos = cpos->next;
    }
  GNUNET_FS_PT_change_rc (pid, -1);
  GNUNET_mutex_unlock (GNUNET_FS_lock);
}


int
GNUNET_FS_PLAN_init (GNUNET_CoreAPIForPlugins * capi)
{
  LOG_2 = log (2);
  coreAPI = capi;
  GNUNET_GE_ASSERT (capi->ectx,
                    GNUNET_SYSERR !=
                    capi->cs_disconnect_handler_register
                    (&handle_client_exit));
  GNUNET_GE_ASSERT (capi->ectx,
                    GNUNET_SYSERR !=
                    capi->peer_disconnect_notification_register
                    (&peer_disconnect_handler, NULL));
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    GNUNET_SYSERR !=
                    coreAPI->send_callback_register (sizeof
                                                     (P2P_gap_query_MESSAGE),
                                                     GNUNET_FS_GAP_QUERY_POLL_PRIORITY,
                                                     &query_fill_callback));
  stats = capi->service_request ("stats");
  if (stats != NULL)
    {
      stat_gap_query_sent =
        stats->create (gettext_noop ("# gap requests total sent"));
      stat_gap_query_planned =
        stats->create (gettext_noop ("# gap content total planned"));
      stat_gap_query_success =
        stats->create (gettext_noop ("# gap routes succeeded"));
      stat_trust_spent = stats->create (gettext_noop ("# trust spent"));
    }
  return 0;
}

int
GNUNET_FS_PLAN_done ()
{
  struct QueryPlanList *qpl;

  while (queries != NULL)
    {
      qpl = queries;
      queries = qpl->next;
      free_query_plan_list (qpl);
    }
  /* clean up clients */
  while (clients != NULL)
    handle_client_exit (clients->client);
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_disconnect_handler_unregister
                    (&handle_client_exit));
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    GNUNET_SYSERR !=
                    coreAPI->peer_disconnect_notification_unregister
                    (&peer_disconnect_handler, NULL));
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    GNUNET_SYSERR !=
                    coreAPI->send_callback_unregister (sizeof
                                                       (P2P_gap_query_MESSAGE),
                                                       &query_fill_callback));
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }
  return 0;
}

/* end of plan.c */
