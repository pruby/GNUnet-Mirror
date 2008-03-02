/*
      This file is part of GNUnet
      (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file fs/gap/gap.c
 * @brief protocol that performs anonymous routing
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"
#include "gnunet_stats_service.h"
#include "gap.h"
#include "fs.h"
#include "ondemand.h"
#include "plan.h"
#include "pid_table.h"
#include "migration.h"

/**
 * How many entries are allowed per slot in the
 * collision list?
 */
#define MAX_ENTRIES_PER_SLOT 2

/**
 * How often do we check have_more?
 */
#define HAVE_MORE_FREQUENCY (100 * GNUNET_CRON_MILLISECONDS)

/**
 * The GAP routing table.
 */
static struct RequestList **table;

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Datastore_ServiceAPI *datastore;

static struct GNUNET_CronManager *cron;

/**
 * Size of the routing table.
 */
static unsigned int table_size;

/**
 * Constant but peer-dependent value that randomizes the construction
 * of the indices into the routing table.  See
 * computeRoutingIndex.
 */
static unsigned int random_qsel;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_gap_query_dropped;

static int stat_gap_query_dropped_redundant;

static int stat_gap_query_routed;

static int stat_gap_query_refreshed;

static int stat_gap_content_found_locally;

static int stat_trust_earned;



static unsigned int
get_table_index (const GNUNET_HashCode * key)
{
  unsigned int res
    = (((unsigned int *) key)[0] ^
       ((unsigned int *) key)[1] / (1 + random_qsel)) % table_size;
  GNUNET_GE_ASSERT (coreAPI->ectx, res < table_size);
  return res;
}

/**
 * Cron-job to inject (artificially) delayed messages.
 */
static void
send_delayed (void *cls)
{
  GNUNET_MessageHeader *msg = cls;

  if (stats != NULL)
    stats->change (stat_gap_content_found_locally, 1);
  coreAPI->p2p_inject_message (NULL,
                               (const char *) msg,
                               ntohs (msg->size), GNUNET_YES, NULL);
  GNUNET_free (msg);
}

struct DVPClosure
{
  struct RequestList *request;
  unsigned int iteration_count;
  unsigned int result_count;
};

/**
 * An iterator over a set of Datastore items.  This
 * function is called whenever GAP is processing a
 * request.  It should
 * 1) abort if the load is getting too high
 * 2) try on-demand encoding (and if that fails,
 *    discard the entry)
 * 3) assemble a response and inject it via
 *    loopback WITH a delay
 *
 * @param datum called with the next item
 * @param closure user-defined extra argument
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 *
 * @return GNUNET_SYSERR to abort the iteration, GNUNET_OK to continue,
 *         GNUNET_NO to delete the item and continue (if supported)
 */
static int
datastore_value_processor (const GNUNET_HashCode * key,
                           const GNUNET_DatastoreValue *
                           value, void *closure, unsigned long long uid)
{
  struct DVPClosure *cls = closure;
  struct RequestList *req = cls->request;
  P2P_gap_reply_MESSAGE *msg;
  GNUNET_DatastoreValue *enc;
  unsigned int size;
  unsigned long long et;
  GNUNET_CronTime now;
  int ret;
  GNUNET_HashCode hc;
  GNUNET_HashCode mhc;
  int want_more;

  want_more = GNUNET_OK;
  cls->iteration_count++;
  if (cls->iteration_count > 10 * (1 + req->value))
    {
      if (cls->result_count > 0)
        req->have_more += HAVE_MORE_INCREMENT;
      want_more = GNUNET_SYSERR;
    }
  enc = NULL;
  if (ntohl (value->type) == GNUNET_ECRS_BLOCKTYPE_ONDEMAND)
    {
      if (GNUNET_OK !=
          GNUNET_FS_ONDEMAND_get_indexed_content (value, key, &enc))
        return GNUNET_NO;
      value = enc;
    }
  if (req->bloomfilter != NULL)
    {
      GNUNET_hash (&value[1],
                   ntohl (value->size) - sizeof (GNUNET_DatastoreValue), &hc);
      GNUNET_FS_HELPER_mingle_hash (&hc, req->bloomfilter_mutator, &mhc);
      if (GNUNET_YES == GNUNET_bloomfilter_test (req->bloomfilter, &mhc))
        return want_more;       /* not useful */
    }
  et = GNUNET_ntohll (value->expirationTime);
  now = GNUNET_get_time ();
  if (now > et)
    et -= now;
  else
    et = 0;
  et %= MAX_MIGRATION_EXP;
  size =
    sizeof (P2P_gap_reply_MESSAGE) + ntohl (value->size) -
    sizeof (GNUNET_DatastoreValue);
  msg = GNUNET_malloc (size);
  msg->header.type = htons (GNUNET_P2P_PROTO_GAP_RESULT);
  msg->header.size = htons (size);
  msg->reserved = htonl (0);
  msg->expiration = et;
  memcpy (&msg[1], &value[1], size - sizeof (P2P_gap_reply_MESSAGE));
  cls->result_count++;
  if (cls->result_count > 2 * (1 + req->value))
    {
      req->have_more += HAVE_MORE_INCREMENT;
      want_more = GNUNET_SYSERR;
    }
  if (stats != NULL)
    {
      stats->change (stat_trust_earned, req->value_offered);
      req->value_offered = 0;
    }
  req->remaining_value = 0;
  GNUNET_cron_add_job (cron,
                       send_delayed,
                       GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                          TTL_DECREMENT), 0, msg);
  ret =
    (ntohl (value->type) ==
     GNUNET_ECRS_BLOCKTYPE_DATA) ? GNUNET_SYSERR : want_more;
  GNUNET_free_non_null (enc);
  return ret;
}

/**
 * Execute a GAP query.  Determines where to forward
 * the query and when (and captures state for the response).
 * Also check the local datastore.
 *
 * @param respond_to where to send replies
 * @param priority how important is the request for us?
 * @param original_priority how important is the request to the sender?
 * @param ttl how long should the query live?
 * @param type type of content requested
 * @param query_count how many queries are in the queries array?
 * @param queries hash codes of the query
 * @param filter_mutator how to map replies to the bloom filter
 * @param filter_size size of the bloom filter
 * @param bloomfilter_data the bloom filter bits
 */
void
GNUNET_FS_GAP_execute_query (const GNUNET_PeerIdentity * respond_to,
                             unsigned int priority,
                             unsigned int original_priority,
                             enum GNUNET_FS_RoutingPolicy policy,
                             int ttl,
                             unsigned int type,
                             unsigned int query_count,
                             const GNUNET_HashCode * queries,
                             int filter_mutator,
                             unsigned int filter_size,
                             const void *bloomfilter_data)
{
  struct RequestList *rl;
  struct RequestList *prev;
  struct DVPClosure cls;
  PID_INDEX peer;
  unsigned int index;
  GNUNET_CronTime now;
  GNUNET_CronTime newTTL;
  GNUNET_CronTime minTTL;
  unsigned int total;
  int ret;

  GNUNET_GE_ASSERT (NULL, query_count > 0);
  GNUNET_mutex_lock (GNUNET_FS_lock);
  index = get_table_index (&queries[0]);
  now = GNUNET_get_time ();
  newTTL = now + ttl * GNUNET_CRON_SECONDS;
  peer = GNUNET_FS_PT_intern (respond_to);
  /* check if entry already exists and compute
     maxTTL if not */
  minTTL = -1;
  total = 0;
  rl = table[index];
  while (rl != NULL)
    {
      if ((rl->type == type) &&
          (rl->response_target == peer) &&
          (0 == memcmp (&rl->queries[0], queries,
                        query_count * sizeof (GNUNET_HashCode))))
        {
          if (rl->expiration > newTTL)
            {
              /* ignore */
              GNUNET_FS_PT_change_rc (peer, -1);
              if (stats != NULL)
                stats->change (stat_gap_query_dropped_redundant, 1);
              if (type != GNUNET_ECRS_BLOCKTYPE_DATA)
                goto CHECK;     /* we may have more local results! */
              GNUNET_mutex_unlock (GNUNET_FS_lock);
              return;
            }
          if (stats != NULL)
            stats->change (stat_gap_query_refreshed, 1);
          rl->value += priority;
          rl->remaining_value += priority;
          rl->expiration = newTTL;
          rl->policy = policy;
          if ((rl->bloomfilter_size == filter_size) &&
              (rl->bloomfilter_mutator == filter_mutator))
            {
              if (rl->bloomfilter_size > 0)
                {
                  /* update ttl / BF */
                  GNUNET_bloomfilter_or (rl->bloomfilter,
                                         bloomfilter_data, filter_size);
                }
              GNUNET_FS_PT_change_rc (peer, -1);
              if (type != GNUNET_ECRS_BLOCKTYPE_DATA)
                goto CHECK;     /* we may have more local results! */
              GNUNET_mutex_unlock (GNUNET_FS_lock);
              return;
            }
          /* update BF */
          if (rl->bloomfilter != NULL)
            GNUNET_bloomfilter_free (rl->bloomfilter);
          rl->bloomfilter_mutator = filter_mutator;
          rl->bloomfilter_size = filter_size;
          if (filter_size > 0)
            rl->bloomfilter = GNUNET_bloomfilter_init (coreAPI->ectx,
                                                       bloomfilter_data,
                                                       filter_size,
                                                       GAP_BLOOMFILTER_K);
          else
            rl->bloomfilter = NULL;
          GNUNET_FS_PT_change_rc (peer, -1);
          if (type != GNUNET_ECRS_BLOCKTYPE_DATA)
            goto CHECK;         /* we may have more local results! */
          GNUNET_mutex_unlock (GNUNET_FS_lock);
          return;
        }
      if (rl->expiration < minTTL)
        minTTL = rl->expiration;
      total++;
      rl = rl->next;
    }

  if ((total >= MAX_ENTRIES_PER_SLOT) && (minTTL > newTTL))
    {
      /* do not process */
      GNUNET_FS_PT_change_rc (peer, -1);
      GNUNET_mutex_unlock (GNUNET_FS_lock);
      if (stats != NULL)
        stats->change (stat_gap_query_dropped, 1);
      return;
    }
  /* delete oldest table entry */
  prev = NULL;
  rl = table[index];
  if (total >= MAX_ENTRIES_PER_SLOT)
    {
      while (rl->expiration != minTTL)
        {
          prev = rl;
          rl = rl->next;
        }
      if (prev == NULL)
        table[index] = rl->next;
      else
        prev->next = rl->next;
      GNUNET_FS_SHARED_free_request_list (rl);
    }
  /* create new table entry */
  rl =
    GNUNET_malloc (sizeof (struct RequestList) +
                   (query_count - 1) * sizeof (GNUNET_HashCode));
  memset (rl, 0, sizeof (struct RequestList));
  memcpy (&rl->queries[0], queries, query_count * sizeof (GNUNET_HashCode));
  rl->key_count = query_count;
  if (filter_size > 0)
    {
      rl->bloomfilter_size = filter_size;
      rl->bloomfilter_mutator = filter_mutator;
      rl->bloomfilter = GNUNET_bloomfilter_init (coreAPI->ectx,
                                                 bloomfilter_data,
                                                 filter_size,
                                                 GAP_BLOOMFILTER_K);
    }
  rl->anonymityLevel = 1;
  rl->type = type;
  rl->value = priority;
  rl->remaining_value = priority > 0 ? priority - 1 : 0;
  rl->value_offered = original_priority;
  rl->expiration = newTTL;
  rl->next = table[index];
  rl->response_target = peer;
  rl->policy = policy;
  table[index] = rl;
  if (stats != NULL)
    stats->change (stat_gap_query_routed, 1);
  /* check local data store */
CHECK:
  cls.request = rl;
  cls.iteration_count = 0;
  cls.result_count = 0;
  ret = datastore->get (&queries[0], type, &datastore_value_processor, &cls);
  if ((type == GNUNET_ECRS_BLOCKTYPE_DATA) && (ret != 1))
    ret = datastore->get (&queries[0],
                          GNUNET_ECRS_BLOCKTYPE_ONDEMAND,
                          &datastore_value_processor, &cls);

  /* if not found or not unique, forward */
  if (((ret != 1) || (type != GNUNET_ECRS_BLOCKTYPE_DATA)) &&
      (0 != (policy & GNUNET_FS_RoutingPolicy_FORWARD)) &&
      (rl->plan_entries == NULL))
    GNUNET_FS_PLAN_request (NULL, peer, rl);
  GNUNET_mutex_unlock (GNUNET_FS_lock);
}

/**
 * Handle the given response (by forwarding it to
 * other peers as necessary).
 *
 * @param sender who send the response (good too know
 *        for future routing decisions)
 * @param primary_query hash code used for lookup
 *        (note that namespace membership may
 *        require additional verification that has
 *        not yet been performed; checking the
 *        signature has already been done)
 * @param expiration relative time until the content
 *        will expire
 * @param size size of the data
 * @param data the data itself
 * @return how much was this content worth to us?
 */
unsigned int
GNUNET_FS_GAP_handle_response (const GNUNET_PeerIdentity * sender,
                               const GNUNET_HashCode * primary_query,
                               GNUNET_CronTime expiration,
                               unsigned int size, const DBlock * data)
{
  GNUNET_HashCode hc;
  GNUNET_PeerIdentity target;
  struct RequestList *rl;
  struct RequestList *prev;
  unsigned int value;
  P2P_gap_reply_MESSAGE *msg;
  PID_INDEX rid;
  unsigned int index;
  PID_INDEX blocked[MAX_ENTRIES_PER_SLOT + 1];
  unsigned int block_count;
  int was_new;

  value = 0;
  GNUNET_mutex_lock (GNUNET_FS_lock);
  rid = GNUNET_FS_PT_intern (sender);
  index = get_table_index (primary_query);
  rl = table[index];
  prev = NULL;
  if (rid != 0)
    {
      blocked[0] = rid;
      block_count = 1;
    }
  else
    {
      block_count = 0;
    }
  was_new = GNUNET_NO;
  while (rl != NULL)
    {
      if (GNUNET_OK == GNUNET_FS_SHARED_test_valid_new_response (rl,
                                                                 primary_query,
                                                                 size,
                                                                 data, &hc))
        {
          was_new = GNUNET_YES;
          GNUNET_GE_ASSERT (NULL, rl->response_target != 0);
          GNUNET_FS_PT_resolve (rl->response_target, &target);
          GNUNET_GE_ASSERT (NULL, block_count <= MAX_ENTRIES_PER_SLOT);
          blocked[block_count++] = rl->response_target;
          /* queue response */
          msg = GNUNET_malloc (sizeof (P2P_gap_reply_MESSAGE) + size);
          msg->header.type = htons (GNUNET_P2P_PROTO_GAP_RESULT);
          msg->header.size = htons (sizeof (P2P_gap_reply_MESSAGE) + size);
          msg->reserved = 0;
          msg->expiration = GNUNET_htonll (expiration);
          memcpy (&msg[1], data, size);
          coreAPI->unicast (&target,
                            &msg->header,
                            BASE_REPLY_PRIORITY * (1 + rl->value),
                            MAX_GAP_DELAY);
          GNUNET_free (msg);
          if (stats != NULL)
            {
              stats->change (stat_trust_earned, rl->value_offered);
              rl->value_offered = 0;
            }
          if (rl->type != GNUNET_ECRS_BLOCKTYPE_DATA)
            GNUNET_FS_SHARED_mark_response_seen (rl, &hc);
          GNUNET_FS_PLAN_success (rid, NULL, rl->response_target, rl);
          value += rl->value;
          rl->value = 0;
          if (rl->type == GNUNET_ECRS_BLOCKTYPE_DATA)
            {
              if (prev == NULL)
                table[index] = rl->next;
              else
                prev->next = rl->next;
              GNUNET_FS_SHARED_free_request_list (rl);
              if (prev == NULL)
                rl = table[index];
              else
                rl = prev->next;
              continue;
            }
        }
      prev = rl;
      rl = rl->next;
    }
  if (was_new == GNUNET_YES)
    GNUNET_FS_MIGRATION_inject (primary_query,
                                size, data, expiration, block_count, blocked);
  GNUNET_mutex_unlock (GNUNET_FS_lock);
  GNUNET_FS_PT_change_rc (rid, -1);
  return value;
}

/**
 * Compute the average priority of inbound requests
 * (rounded up).
 */
unsigned int
GNUNET_FS_GAP_get_average_priority ()
{
  struct RequestList *rl;
  unsigned long long tot;
  unsigned int i;
  unsigned int active;

  tot = 0;
  active = 0;
  GNUNET_mutex_lock (GNUNET_FS_lock);
  for (i = 0; i < table_size; i++)
    {
      rl = table[i];
      while (rl != NULL)
        {
          tot += rl->value;
          active++;
          rl = rl->next;
        }
    }
  GNUNET_mutex_unlock (GNUNET_FS_lock);
  if (active == 0)
    return 0;
  if (active * (tot / active) < tot)
    return (unsigned int) (tot / active) + 1;
  return (unsigned int) (tot / active);
}

/**
 * We were disconnected from another peer.
 * Remove all of its pending queries.
 */
static void
cleanup_on_peer_disconnect (const GNUNET_PeerIdentity * peer, void *unused)
{
  unsigned int i;
  struct RequestList *rl;
  struct RequestList *prev;
  PID_INDEX pid;

  GNUNET_mutex_lock (GNUNET_FS_lock);
  pid = GNUNET_FS_PT_intern (peer);
  for (i = 0; i < table_size; i++)
    {
      rl = table[i];
      prev = NULL;
      while (rl != NULL)
        {
          if (pid == rl->response_target)
            {
              if (prev == NULL)
                table[i] = rl->next;
              else
                prev->next = rl->next;
              GNUNET_FS_SHARED_free_request_list (rl);
              if (prev == NULL)
                rl = table[i];
              else
                rl = prev->next;
            }
          else
            {
              prev = rl;
              rl = rl->next;
            }
        }
    }
  GNUNET_FS_PT_change_rc (pid, -1);
  GNUNET_mutex_unlock (GNUNET_FS_lock);
}

/**
 * Cron-job to find and transmit more results (beyond
 * the initial batch) over time -- assuming the entry
 * is still valid and we have more data.
 */
static void
have_more_processor (void *unused)
{
  static unsigned int pos;
  struct RequestList *req;
  GNUNET_CronTime now;
  struct DVPClosure cls;

  GNUNET_mutex_lock (GNUNET_FS_lock);
  now = GNUNET_get_time ();
  if (pos >= table_size)
    pos = 0;
  req = table[pos];
  while (req != NULL)
    {
      if ((GNUNET_cpu_get_load (coreAPI->ectx,
                                coreAPI->cfg) > 50) ||
          (GNUNET_disk_get_load (coreAPI->ectx, coreAPI->cfg) > 25))
        break;
      if (req->have_more > 0)
        {
          req->have_more--;
          cls.request = req;
          cls.iteration_count = 0;
          cls.result_count = 0;
          datastore->get (&req->queries[0], req->type,
                          &datastore_value_processor, &cls);
        }
      req = req->next;
    }
  if (req == NULL)
    pos++;
  GNUNET_mutex_unlock (GNUNET_FS_lock);
}

int
GNUNET_FS_GAP_init (GNUNET_CoreAPIForPlugins * capi)
{
  unsigned long long ts;

  coreAPI = capi;
  datastore = capi->request_service ("datastore");
  random_qsel = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 0xFFFF);
  if (-1 ==
      GNUNET_GC_get_configuration_value_number (coreAPI->cfg, "GAP",
                                                "TABLESIZE",
                                                MIN_INDIRECTION_TABLE_SIZE,
                                                GNUNET_MAX_GNUNET_malloc_CHECKED
                                                /
                                                sizeof (struct RequestList *),
                                                MIN_INDIRECTION_TABLE_SIZE,
                                                &ts))
    return GNUNET_SYSERR;
  table_size = ts;
  table = GNUNET_malloc (sizeof (struct RequestList *) * table_size);
  memset (table, 0, sizeof (struct RequestList *) * table_size);
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    register_notify_peer_disconnect
                    (&cleanup_on_peer_disconnect, NULL));
  GNUNET_cron_add_job (capi->cron,
                       &have_more_processor,
                       HAVE_MORE_FREQUENCY, HAVE_MORE_FREQUENCY, NULL);

  stats = capi->request_service ("stats");
  if (stats != NULL)
    {
      stat_gap_query_dropped =
        stats->create (gettext_noop ("# gap queries dropped (table full)"));
      stat_gap_query_dropped_redundant =
        stats->create (gettext_noop ("# gap queries dropped (redundant)"));
      stat_gap_query_routed =
        stats->create (gettext_noop ("# gap queries routed"));
      stat_gap_content_found_locally =
        stats->create (gettext_noop ("# gap content found locally"));
      stat_gap_query_refreshed =
        stats->
        create (gettext_noop ("# gap queries refreshed existing record"));
      stat_trust_earned = stats->create (gettext_noop ("# trust earned"));
    }
  cron = GNUNET_cron_create (coreAPI->ectx);
  GNUNET_cron_start (cron);
  return 0;
}

int
GNUNET_FS_GAP_done ()
{
  unsigned int i;
  struct RequestList *rl;

  GNUNET_cron_del_job (coreAPI->cron,
                       &have_more_processor, HAVE_MORE_FREQUENCY, NULL);

  for (i = 0; i < table_size; i++)
    {
      while (NULL != (rl = table[i]))
        {
          table[i] = rl->next;
          GNUNET_FS_SHARED_free_request_list (rl);
        }
    }
  GNUNET_free (table);
  table = NULL;
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    unregister_notify_peer_disconnect
                    (&cleanup_on_peer_disconnect, NULL));
  coreAPI->release_service (datastore);
  datastore = NULL;
  GNUNET_cron_stop (cron);
  GNUNET_cron_destroy (cron);
  if (stats != NULL)
    {
      coreAPI->release_service (stats);
      stats = NULL;
    }
  return 0;
}

/* end of gap.c */
