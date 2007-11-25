/*
      This file is part of GNUnet
      (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file module/routing.c
 * @brief state for active DHT routing operations
 * @author Christian Grothoff
 *
 * LATER:
 * - prioritization
 * - delay selection
 * - implement extra_get_callback
 * - add similar callback for discovery in table.c
 */

#include "platform.h"
#include "routing.h"
#include "table.h"
#include "dstore.h"
#include "gnunet_protocols.h"
#include "gnunet_stats_service.h"

#define DEBUG_ROUTING GNUNET_NO

/**
 * @brief record used for sending response back
 */
typedef struct DHT_Source_Route
{

  /**
   * This is a linked list.
   */
  struct DHT_Source_Route *next;

  /**
   * Source of the request.  Replies should be forwarded to
   * this peer.
   */
  GNUNET_PeerIdentity source;

  /**
   * If local peer is NOT interested in results, this callback
   * will be NULL.
   */
  GNUNET_ResultProcessor receiver;

  void *receiver_closure;

} DHT_Source_Route;

/**
 * @brief message send for DHT lookup
 */
typedef struct
{

  GNUNET_MessageHeader header;

  /**
   * Type of the requested content (NBO)
   */
  unsigned int type;

  /**
   * Priority of requested content (NBO)
   */
  unsigned int prio;

  /**
   * Relative time to live in GNUNET_CRON_MILLISECONDS (NBO)
   */
  int ttl;

  /**
   * Search key.
   */
  GNUNET_HashCode key;

} DHT_GET_MESSAGE;

/**
 * @brief message send for DHT put
 *
 * Message is followed by the data.
 */
typedef struct
{

  GNUNET_MessageHeader header;

  /**
   * Type of the content (NBO)
   */
  unsigned int type;

  /**
   * When to discard the content (relative time, NBO)
   */
  GNUNET_CronTime timeout;

  /**
   * Key for the content.
   */
  GNUNET_HashCode key;

} DHT_PUT_MESSAGE;

/**
 * @brief message send for DHT put
 *
 * Message is followed by the data.
 */
typedef struct
{

  GNUNET_MessageHeader header;

  /**
   * Type of the content (NBO)
   */
  unsigned int type;

  /**
   * Key for the content.
   */
  GNUNET_HashCode key;

} DHT_RESULT_MESSAGE;

/**
 * Entry in the DHT routing table.
 */
typedef struct DHTQueryRecord
{

  /**
   * When do we stop forwarding this request?
   */
  GNUNET_CronTime expires;

  /**
   * Information about where to send the results back to.
   */
  DHT_Source_Route *sources;

  /**
   * GET message of this record.
   */
  DHT_GET_MESSAGE *get;

  /**
   * Hashcodes of the results that we have send back
   * so far.
   */
  GNUNET_HashCode *results;

  /**
   * Number of entries in results.
   */
  unsigned int result_count;
} DHTQueryRecord;

/**
 * How far into the future can requests continue?
 * Note that this also caps the frequency of how
 * often peers will re-issue requests.
 */
#define MAX_TTL (5 * GNUNET_CRON_MINUTES)

/**
 * Linked list of active records.
 */
static DHTQueryRecord **records;

/**
 * Size of records
 */
static unsigned int rt_size;

/**
 * Statistics service.
 */
static GNUNET_Stats_ServiceAPI *stats;

static struct GNUNET_Mutex *lock;

static GNUNET_CoreAPIForPlugins *coreAPI;

static unsigned int stat_replies_routed;

static unsigned int stat_results_received;

static unsigned int stat_requests_routed;

static unsigned int stat_get_requests_received;

static unsigned int stat_put_requests_received;

/**
 * Given a result, lookup in the routing table
 * where to send it next.
 */
static void
routeResult (const GNUNET_HashCode * key,
             unsigned int type,
             unsigned int size, const char *data, void *cls)
{
  DHTQueryRecord *q;
  int i;
  int j;
  int found;
  GNUNET_HashCode hc;
  DHT_RESULT_MESSAGE *result;
  unsigned int routed;
  unsigned int tracked;
  DHT_Source_Route *pos;

  if (cls != NULL)
    {
      result = cls;
    }
  else
    {
      result = GNUNET_malloc (sizeof (DHT_RESULT_MESSAGE) + size);
      result->header.size = htons (sizeof (DHT_RESULT_MESSAGE) + size);
      result->header.type = htons (GNUNET_P2P_PROTO_DHT_RESULT);
      result->type = htonl (type);
      result->key = *key;
      memcpy (&result[1], data, size);
    }
  GNUNET_hash (data, size, &hc);
  routed = 0;
  tracked = 0;
  GNUNET_mutex_lock (lock);
  for (i = 0; i < rt_size; i++)
    {
      q = records[i];
      if (q == NULL)
        continue;
      tracked++;
      if ((ntohl (q->get->type) != type) ||
          (0 != memcmp (key, &q->get->key, sizeof (GNUNET_HashCode))))
        continue;
      found = GNUNET_NO;
      for (j = 0; j < q->result_count; j++)
        if (0 == memcmp (&hc, &q->results[j], sizeof (GNUNET_HashCode)))
          {
            found = GNUNET_YES;
            break;
          }
      if (found == GNUNET_YES)
        continue;
      GNUNET_array_grow (q->results, q->result_count, q->result_count + 1);
      routed++;
      q->results[q->result_count - 1] = hc;
      pos = q->sources;
      while (pos != NULL)
        {
          if (0 != memcmp (&pos->source,
                           coreAPI->myIdentity, sizeof (GNUNET_PeerIdentity)))
            {
#if DEBUG_ROUTING
              GNUNET_GE_LOG (coreAPI->ectx,
                      GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                      "Routing result to other peer\n");
#endif
              coreAPI->unicast (&pos->source, &result->header, 0,       /* FIXME: priority */
                                5 * GNUNET_CRON_SECONDS);       /* FIXME */
              if (stats != NULL)
                stats->change (stat_replies_routed, 1);
            }
          else if (pos->receiver != NULL)
            {
#if DEBUG_ROUTING
              GNUNET_GE_LOG (coreAPI->ectx,
                      GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                      "Routing result to local client\n");
#endif
              pos->receiver (key, type, size, data, pos->receiver_closure);
              if (stats != NULL)
                stats->change (stat_replies_routed, 1);
            }
          pos = pos->next;
        }
    }
  GNUNET_mutex_unlock (lock);
#if DEBUG_ROUTING
  GNUNET_GE_LOG (coreAPI->ectx,
          GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
          "Routed result to %u out of %u pending requests\n",
          routed, tracked);
#endif
  if (cls == NULL)
    GNUNET_free (result);
}

/**
 * @return GNUNET_OK if route was added, GNUNET_SYSERR if not
 */
static int
addRoute (const GNUNET_PeerIdentity * sender,
          GNUNET_ResultProcessor handler, void *cls, const DHT_GET_MESSAGE * get)
{
  DHTQueryRecord *q;
  unsigned int i;
  unsigned int rt_pos;
  GNUNET_CronTime expire;
  GNUNET_CronTime now;
  int ttl;
  struct DHT_Source_Route *pos;

  ttl = ntohl (get->ttl);
  if (ttl > MAX_TTL)
    ttl = 0;                    /* implausibly high */
  now = GNUNET_get_time ();
  expire = now + ttl;
  GNUNET_mutex_lock (lock);
  rt_pos = rt_size;
  for (i = 0; i < rt_size; i++)
    {
      if ((sender != NULL) &&
          (records[i] != NULL) &&
          (0 == memcmp (&records[i]->get->key,
                        &get->key,
                        sizeof (GNUNET_HashCode))) &&
          (records[i]->get->type == get->type) &&
          (records[i]->expires > now - MAX_TTL))
        {
          /* do not route, same request already (recently)
             active (possibly from other initiator) */
          /* FIXME: support sending replies back to
             multiple peers!? */
          GNUNET_mutex_unlock (lock);
          return GNUNET_SYSERR;
        }
      if (records[i] == NULL)
        {
          rt_pos = i;
          expire = 0;
        }
      else if (records[i]->expires < expire)
        {
          expire = records[i]->expires;
          rt_pos = i;
        }
    }
  if (rt_pos == rt_size)
    {
      /* do not route, expiration time too high */
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (records[rt_pos] == NULL)
    {
      records[rt_pos] = GNUNET_malloc (sizeof (DHTQueryRecord));
      records[rt_pos]->get = NULL;
    }
  if (records[rt_pos]->get != NULL)
    {
      GNUNET_free (records[rt_pos]->get);
      while (records[rt_pos]->sources != NULL)
        {
          pos = records[rt_pos]->sources;
          records[rt_pos]->sources = pos->next;
          GNUNET_free (pos);
        }
    }
  q = records[rt_pos];
  memset (q, 0, sizeof (DHTQueryRecord));
  q->expires = now + ttl;
  q->get = GNUNET_malloc (ntohs (get->header.size));
  memcpy (q->get, get, ntohs (get->header.size));
  pos = GNUNET_malloc (sizeof (DHT_Source_Route));
  pos->next = q->sources;
  q->sources = pos;
  if (sender != NULL)
    pos->source = *sender;
  else
    pos->source = *coreAPI->myIdentity;
  pos->receiver = handler;
  pos->receiver_closure = cls;
#if DEBUG_ROUTING
  GNUNET_GE_LOG (coreAPI->ectx,
          GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
          "Tracking request in slot %u\n", rt_pos);
#endif
  rt_pos = (rt_pos + 1) % rt_size;
  GNUNET_mutex_unlock (lock);
  if (stats != NULL)
    stats->change (stat_requests_routed, 1);
  return GNUNET_OK;
}

/**
 * Larger factors will result in more aggressive routing of GET
 * operations (each peer will either forward to GET_TRIES peers that
 * are closer to the key).
 */
#define GET_TRIES 4

/**
 * Handle GET message.
 */
static int
handleGet (const GNUNET_PeerIdentity * sender,
           const GNUNET_MessageHeader * msg)
{
  GNUNET_PeerIdentity next[GET_TRIES];
  const DHT_GET_MESSAGE *get;
  DHT_GET_MESSAGE aget;
  int total;
  int ttl;
  int i;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
#endif

  if (ntohs (msg->size) != sizeof (DHT_GET_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  get = (const DHT_GET_MESSAGE *) msg;
#if DEBUG_ROUTING
  GNUNET_hash_to_enc (&get->key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
          GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
          "Received DHT GET for key `%s'.\n", &enc);
#endif
  if (stats != NULL)
    stats->change (stat_get_requests_received, 1);
  if ((sender != NULL) && (GNUNET_OK != addRoute (sender, NULL, NULL, get)))
    return GNUNET_OK;           /* could not route */
  total = dht_store_get (&get->key, ntohl (get->type), &routeResult, NULL);
  if ((total > GET_TRIES) && (sender != NULL))
    {
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
              GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
              "Found %d results locally, will not route GET any further\n",
              total);
#endif
      return GNUNET_OK;
    }
  total = 0;
  for (i = 0; i < GET_TRIES; i++)
    {
      if (GNUNET_OK != select_dht_peer (&next[i], &get->key, &next[0], i))
        break;
      if (-1 == GNUNET_hash_xorcmp (&next[i].hashPubKey,
                                    &coreAPI->myIdentity->hashPubKey,
                                    &get->key))
        {
          if (total == 0)
            {
              aget = *get;
              ttl = ntohl (get->ttl);
              if (ttl > MAX_TTL)
                ttl = MAX_TTL;
              ttl -= 5 * GNUNET_CRON_SECONDS;
              aget.ttl = htonl (ttl);
              total = 1;
            }
          coreAPI->unicast (&next[i], msg, 0,   /* FIXME: priority */
                            5 * GNUNET_CRON_SECONDS);   /* FIXME */
        }
    }
  return GNUNET_OK;
}

/**
 * Larger factors will result in more replication and
 * more aggressive routing of PUT operations (each
 * peer will either forward to PUT_TRIES peers that
 * are closer to the key, or replicate the content).
 */
#define PUT_TRIES 2

/**
 * Handle PUT message.
 */
static int
handlePut (const GNUNET_PeerIdentity * sender,
           const GNUNET_MessageHeader * msg)
{
  GNUNET_PeerIdentity next[PUT_TRIES];
  const DHT_PUT_MESSAGE *put;
  GNUNET_CronTime now;
  int store;
  int i;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
#endif

  if (ntohs (msg->size) < sizeof (DHT_PUT_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_put_requests_received, 1);
  put = (const DHT_PUT_MESSAGE *) msg;
#if DEBUG_ROUTING
  GNUNET_hash_to_enc (&put->key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
          GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
          "Received DHT PUT for key `%s'.\n", &enc);
#endif
  store = 0;
  for (i = 0; i < PUT_TRIES; i++)
    {
      if (GNUNET_OK != select_dht_peer (&next[i], &put->key, &next[0], i))
        {
          store = 1;
          break;
        }
      if (1 == GNUNET_hash_xorcmp (&next[i].hashPubKey,
                                   &coreAPI->myIdentity->hashPubKey,
                                   &put->key))
        store = 1;              /* we're closer than the selected target */
      else
        coreAPI->unicast (&next[i], msg, 0,     /* FIXME: priority */
                          5 * GNUNET_CRON_SECONDS);     /* FIXME */
    }
  if (store != 0)
    {
      now = GNUNET_get_time ();
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
              GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
              "Decided to cache data `%.*s' locally until %llu (for %llu ms)\n",
              ntohs (put->header.size) - sizeof (DHT_PUT_MESSAGE),
              &put[1], GNUNET_ntohll (put->timeout) + now,
              GNUNET_ntohll (put->timeout));
#endif
      dht_store_put (ntohl (put->type),
                     &put->key,
                     GNUNET_ntohll (MAKE_UNALIGNED (put->timeout)) + now,
                     ntohs (put->header.size) - sizeof (DHT_PUT_MESSAGE),
                     (const char *) &put[1]);
    }
  else
    {
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
              GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
              "Decided NOT to cache data `%.*s' locally\n",
              ntohs (put->header.size) - sizeof (DHT_PUT_MESSAGE), &put[1]);
#endif
    }
  return GNUNET_OK;
}

/**
 * Handle RESULT message.
 */
static int
handleResult (const GNUNET_PeerIdentity * sender,
              const GNUNET_MessageHeader * msg)
{
  const DHT_RESULT_MESSAGE *result;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
#endif

  if (ntohs (msg->size) < sizeof (DHT_RESULT_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_results_received, 1);
  result = (const DHT_RESULT_MESSAGE *) msg;
#if DEBUG_ROUTING
  GNUNET_hash_to_enc (&result->key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
          GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
          "Received DHT RESULT for key `%s'.\n", &enc);
#endif
  routeResult (&result->key,
               ntohl (result->type),
               ntohs (result->header.size) - sizeof (DHT_RESULT_MESSAGE),
               (const char *) &result[1], (void *) msg);
  return GNUNET_OK;
}

/**
 * Start a DHT get operation.
 */
void
dht_get_start (const GNUNET_HashCode * key,
               unsigned int type, GNUNET_ResultProcessor handler, void *cls)
{
  DHT_GET_MESSAGE get;

  get.header.size = htons (sizeof (DHT_GET_MESSAGE));
  get.header.type = htons (GNUNET_P2P_PROTO_DHT_GET);
  get.type = htonl (type);
  get.prio = htonl (0);         /* FIXME */
  get.ttl = htonl (MAX_TTL);    /* FIXME? */
  get.key = *key;
  if (GNUNET_OK == addRoute (NULL, handler, cls, &get))
    handleGet (NULL, &get.header);
}

/**
 * Stop a DHT get operation (prevents calls to
 * the given iterator).
 */
void
dht_get_stop (const GNUNET_HashCode * key,
              unsigned int type, GNUNET_ResultProcessor handler, void *cls)
{
  int i;
  struct DHT_Source_Route *pos;
  struct DHT_Source_Route *prev;
  int done;

  done = GNUNET_NO;
  GNUNET_mutex_lock (lock);
  for (i = 0; i < rt_size; i++)
    {
      if (records[i] == NULL)
        continue;
      prev = NULL;
      pos = records[i]->sources;
      while (pos != NULL)
        {
          if ((pos->receiver == handler) &&
              (pos->receiver_closure == cls) &&
              (0 == memcmp (key,
                            &records[i]->get->key, sizeof (GNUNET_HashCode))))
            {
              if (prev == NULL)
                records[i]->sources = pos->next;
              else
                prev->next = pos->next;
              GNUNET_free (pos);
              done = GNUNET_YES;
              break;
            }
          prev = pos;
          pos = prev->next;
        }
      if (records[i]->sources == NULL)
        {
          GNUNET_free (records[i]->get);
          GNUNET_free (records[i]);
          records[i] = NULL;
        }
      if (done == GNUNET_YES)
        break;
    }
  GNUNET_mutex_unlock (lock);
}

/**
 * Perform a DHT put operation.  Note that PUT operations always
 * expire after a period of time and the client is responsible for
 * doing periodic refreshs.  The given expiration time is ONLY used to
 * ensure that the datum is certainly deleted by that time (it maybe
 * deleted earlier).
 *
 * @param expirationTime absolute expiration time
 */
void
dht_put (const GNUNET_HashCode * key,
         unsigned int type,
         unsigned int size, GNUNET_CronTime expirationTime, const char *data)
{
  DHT_PUT_MESSAGE *put;

  put = GNUNET_malloc (sizeof (DHT_PUT_MESSAGE) + size);
  put->header.size = htons (sizeof (DHT_PUT_MESSAGE) + size);
  put->header.type = htons (GNUNET_P2P_PROTO_DHT_PUT);
  put->key = *key;
  put->type = htonl (type);
  put->timeout = GNUNET_htonll (expirationTime - GNUNET_get_time ());   /* convert to relative time */
  memcpy (&put[1], data, size);
  handlePut (NULL, &put->header);
  GNUNET_free (put);
}

/**
 * We have additional "free" bandwidth available.
 * Possibly find a good query to add to the message
 * to the given receiver.
 *
 * @param padding maximum number of bytes available
 * @return number of bytes added at position
 */
static unsigned int
extra_get_callback (const GNUNET_PeerIdentity * receiver,
                    void *position, unsigned int padding)
{
  return 0;
}

/**
 * Initialize routing DHT component.
 *
 * @param capi the core API
 * @return GNUNET_OK on success
 */
int
init_dht_routing (GNUNET_CoreAPIForPlugins * capi)
{
  unsigned long long rts;

  coreAPI = capi;
  rts = 65536;
  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                     "DHT",
                                     "TABLESIZE",
                                     128, 1024 * 1024, 1024, &rts);
  GNUNET_array_grow (records, rt_size, rts);
  lock = GNUNET_mutex_create (GNUNET_NO);
  stats = capi->requestService ("stats");
  if (stats != NULL)
    {
      stat_replies_routed =
        stats->create (gettext_noop ("# dht replies routed"));
      stat_requests_routed =
        stats->create (gettext_noop ("# dht requests routed"));
      stat_get_requests_received =
        stats->create (gettext_noop ("# dht get requests received"));
      stat_put_requests_received =
        stats->create (gettext_noop ("# dht put requests received"));
      stat_results_received =
        stats->create (gettext_noop ("# dht results received"));
    }
  GNUNET_GE_LOG (coreAPI->ectx,
          GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
          _("`%s' registering p2p handlers: %d %d %d\n"),
          "dht", GNUNET_P2P_PROTO_DHT_GET, GNUNET_P2P_PROTO_DHT_PUT, GNUNET_P2P_PROTO_DHT_RESULT);
  coreAPI->registerHandler (GNUNET_P2P_PROTO_DHT_GET, &handleGet);
  coreAPI->registerHandler (GNUNET_P2P_PROTO_DHT_PUT, &handlePut);
  coreAPI->registerHandler (GNUNET_P2P_PROTO_DHT_RESULT, &handleResult);
  coreAPI->registerSendCallback (sizeof (DHT_GET_MESSAGE),
                                 &extra_get_callback);
  return GNUNET_OK;
}

/**
 * Shutdown routing DHT component.
 *
 * @return GNUNET_OK on success
 */
int
done_dht_routing ()
{
  unsigned int i;

  coreAPI->unregisterSendCallback (sizeof (DHT_GET_MESSAGE),
                                   &extra_get_callback);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_DHT_GET, &handleGet);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_DHT_PUT, &handlePut);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_DHT_RESULT, &handleResult);
  if (stats != NULL)
    {
      coreAPI->releaseService (stats);
      stats = NULL;
    }
  GNUNET_mutex_destroy (lock);
  for (i = 0; i < rt_size; i++)
    {
      if (records[i] != NULL)
        {
          GNUNET_free (records[i]->get);
          GNUNET_free (records[i]);
        }
    }
  GNUNET_array_grow (records, rt_size, 0);
  return GNUNET_OK;
}

/* end of routing.c */
