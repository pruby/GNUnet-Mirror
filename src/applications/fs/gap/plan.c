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
 *
 * TODO:
 * - code to clean up plans (remove
 *   plans for peers that we are no longer
 *   connected to) -- using cron?
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "plan.h"
#include "pid_table.h"
#include "fs_dht.h"
#include "fs.h"
#include "shared.h"

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

/**
 * Add the given request to the list of pending requests for the
 * specified target.  A random position in the queue will
 * be used.
 *
 * @param target what peer to send the request to
 * @param request the request to send
 * @param ttl time-to-live for the request
 * @param prio priority to use for the request
 */
static void
add_request (PID_INDEX target,
             struct RequestList *request, int ttl, unsigned int prio)
{
  struct QueryPlanList *qpl;
  struct QueryPlanEntry *entry;
  struct QueryPlanEntry *pos;
  unsigned int total;

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
  /* construct entry */
  entry = GNUNET_malloc (sizeof (struct QueryPlanEntry));
  memset (entry, 0, sizeof (struct QueryPlanEntry));
  entry->request = request;
  entry->prio = prio;
  entry->ttl = GNUNET_FS_HELPER_bound_ttl (ttl, prio);

  /* insert entry into request plan entries list */
  entry->plan_entries_next = request->plan_entries;
  request->plan_entries = entry;

  /* compute (random) insertion position in doubly-linked list */
  total = 0;
  pos = qpl->head;
  while (pos != NULL)
    {
      total++;
      pos = pos->next;
    }
  total = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, total + 1);
  pos = qpl->head;
  while (total-- > 0)
    pos = pos->next;
  /* insert into datastructure at pos */
  if (pos == NULL)
    {
      qpl->tail->next = entry;
      entry->prev = qpl->tail;
      qpl->tail = entry;
    }
  else
    {
      entry->next = pos->next;
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

  rank = GNUNET_malloc (sizeof (struct PeerRankings));
  memset (rank, 0, sizeof (struct PeerRankings));
  rank->peer = GNUNET_FS_PT_intern (identity);

  history = NULL;
  if (rpc->info != NULL)
    {
      history = rpc->info->history;
      while ((history != NULL) && (history->peer != rank->peer))
        history = history->next;
    }
  if (history != NULL)
    {
      /* how do we score the history? */
    }
  else
    {
      /* what are good start values? */
    }

  /* reserve response-bandwidth from core!
     (also, don't forget to unreserve for
     peers that were not selected!) */


  /* check query proximity */

  /* generate score, ttl and priority */
  rank->prio = 42;              /* FIXME */
  rank->ttl = 112;              /* FIXME */
  rank->score = 1;              /* FIXME */

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
 */
void
GNUNET_FS_PLAN_request (struct GNUNET_ClientHandle *client,
                        PID_INDEX peer, struct RequestList *request)
{
  struct ClientInfoList *info;
  struct PeerRankings *rank;
  struct RankingPeerContext rpc;
  unsigned int target_count;
  unsigned int i;
  unsigned int total_peers;
  unsigned long long total_score;
  unsigned long long selector;

  GNUNET_mutex_lock (GNUNET_FS_lock);   /* needed? */
  info = clients;
  while ((info != NULL) && ((info->client != client) || (info->peer != peer)))
    info = info->next;

  /* for all connected peers compute ranking */
  rpc.info = info;
  rpc.request = request;
  rpc.rankings = NULL;
  total_peers = coreAPI->forAllConnectedNodes (rank_peers, &rpc);
  /* use request type, priority, system load and
     entropy of ranking to determine number of peers
     to queue */
  target_count = 2;             /* FIXME */

  if (target_count > total_peers)
    target_count = total_peers;

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
  /* select target_count peers */
  for (i = 0; i < target_count; i++)
    {
      selector = GNUNET_random_u64 (GNUNET_RANDOM_QUALITY_WEAK, total_score);
      rank = rpc.rankings;
      while (rank != NULL)
        {
          if (rank->score > selector)
            {
              add_request (rank->peer, request, rank->ttl, rank->prio);
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
      GNUNET_FS_PT_change_rc (rank->peer, -1);
      GNUNET_free (rank);
    }
  GNUNET_mutex_unlock (GNUNET_FS_lock);
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

  GNUNET_GE_ASSERT (NULL, req->key_count > 0);
  size = sizeof (P2P_gap_query_MESSAGE)
    + req->bloomfilter_size + (req->key_count - 1) * sizeof (GNUNET_HashCode);
  if (size > available)
    return 0;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_P2P_PROTO_GAP_QUERY);
  msg->type = htonl (req->type);
  msg->priority = htonl (prio);
  msg->ttl = htonl (ttl);
  msg->filter_mutator = htonl (req->bloomfilter_mutator);
  msg->number_of_queries = htonl (req->key_count);
  msg->returnTo = *coreAPI->myIdentity; /* FIXME? */
  memcpy (&msg->queries[0],
          &req->queries[0], req->key_count * sizeof (GNUNET_HashCode));
  if (req->bloomfilter != NULL)
    GNUNET_bloomfilter_get_raw_data (req->bloomfilter,
                                     (char *) &msg->queries[req->key_count],
                                     req->bloomfilter_size);

  /* FIXME: update state tracking
     what queries were sent with
     what priorities/ ttls / etc */
  req->last_request_time = GNUNET_get_time ();
  req->last_ttl_used = ttl;
  req->value = prio;

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
              GNUNET_free (e);
              cl = find_or_create_client_entry (e->request->response_client,
                                                e->request->response_target);
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

/**
 * Method called whenever a given client disconnects.
 * Frees all of the associated data structures.
 */
static void
handle_client_exit (struct GNUNET_ClientHandle *client)
{
  struct ClientInfoList *pos;
  struct ClientInfoList *prev;
  struct PeerHistoryList *ph;

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
          while (pos->history != NULL)
            {
              ph = pos->history;
              pos->history = ph->next;
              GNUNET_FS_PT_change_rc (ph->peer, -1);
              GNUNET_free (ph);
            }
          GNUNET_FS_PT_change_rc (pos->peer, -1);
          GNUNET_free (pos);
          if (prev == NULL)
            pos = clients;
          else
            pos = prev->next;
        }
      else
        {
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
  hl->last_good_prio = success->value;
  hl->last_response_time = GNUNET_get_time ();
  hl->response_count++;
  GNUNET_mutex_unlock (GNUNET_FS_lock);
}


int
GNUNET_FS_PLAN_init (GNUNET_CoreAPIForPlugins * capi)
{
  coreAPI = capi;
  GNUNET_GE_ASSERT (capi->ectx,
                    GNUNET_SYSERR !=
                    capi->cs_exit_handler_register (&handle_client_exit));
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    connection_register_send_callback (sizeof
                                                       (P2P_gap_query_MESSAGE),
                                                       GNUNET_FS_GAP_QUERY_POLL_PRIORITY,
                                                       &query_fill_callback));
  return 0;
}

int
GNUNET_FS_PLAN_done ()
{
  struct QueryPlanList *qpl;
  struct QueryPlanEntry *el;
  struct QueryPlanEntry *pred;

  while (queries != NULL)
    {
      qpl = queries;
      queries = qpl->next;
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
  /* clean up clients */
  while (clients != NULL)
    handle_client_exit (clients->client);
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    cs_exit_handler_unregister (&handle_client_exit));
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    connection_unregister_send_callback (sizeof
                                                         (P2P_gap_query_MESSAGE),
                                                         &query_fill_callback));
  return 0;
}

/* end of plan.c */
