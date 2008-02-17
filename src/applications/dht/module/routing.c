/*
      This file is part of GNUnet
      (C) 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * TODO:
 * - implement extra_get_callback
 * - use "network_size" field to improve our network size estimate(s)
 */

#include "platform.h"
#include "routing.h"
#include "table.h"
#include "gnunet_protocols.h"
#include "gnunet_core.h"
#include "gnunet_stats_service.h"

#define DEBUG_ROUTING GNUNET_NO

/**
 * What is the request priority for DHT operations?
 */
#define DHT_PRIORITY 0

/**
 * What is the estimated per-hop delay for DHT operations
 * (this is how much we will request from the GNUnet core)
 */
#define DHT_DELAY (5 * GNUNET_CRON_SECONDS)

/**
 * What is the maximum number of results returned by any DHT
 * operation?
 */
#define MAX_RESULTS 64

/**
 * How many peers should a DHT GET request reach on averge?
 *
 * Larger factors will result in more aggressive routing of GET
 * operations (each peer will either forward to GET_TRIES peers that
 * are closer to the key).
 */
#define GET_TRIES 7

/**
 * At how many peers should a DHT PUT request be replicated
 * on average?
 *
 * Larger factors will result in more replication and
 * more aggressive routing of PUT operations (each
 * peer will either forward to PUT_TRIES peers that
 * are closer to the key, or replicate the content).
 */
#define PUT_TRIES 3

/**
 * How long do we keep content after receiving a PUT request for it?
 */
#define CONTENT_LIFETIME (12 * GNUNET_CRON_HOURS)

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

  /**
   * At what time will this record automatically
   * expire?
   */
  GNUNET_CronTime expire;

} DHT_Source_Route;

/**
 * @brief message send for DHT get, put or result.
 *        PUT and RESULT messages are followed by
 *        the content.  "header.type" distinguishes
 *        the three types of messages.
 */
typedef struct
{

  GNUNET_MessageHeader header;

  /**
   * Type of the requested content (NBO)
   */
  unsigned int type;

  /**
   * Number of hops this message has passed (NBO)
   */
  unsigned int hop_count;

  /**
   * Network size estimate -- sum of the logs of the
   * network size estimates of all hops this message
   * has passed so far.
   */
  unsigned int network_size;

  /**
   * Search key.
   */
  GNUNET_HashCode key;

} DHT_MESSAGE;

/**
 * Entry in the DHT routing table.
 */
typedef struct DHTQueryRecord
{

  /**
   * When does this record expire?  Should be the max
   * of the individual source records.
   */
  GNUNET_CronTime expire;

  /**
   * Information about where to send the results back to.
   */
  DHT_Source_Route *sources;

  /**
   * GET message of this record (what we are forwarding).
   */
  DHT_MESSAGE get;

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
 * Linked list of active records.
 */
static DHTQueryRecord *records;

/**
 * Size of records
 */
static unsigned int rt_size;

/**
 * Statistics service.
 */
static GNUNET_Stats_ServiceAPI *stats;

static GNUNET_Dstore_ServiceAPI *dstore;

static struct GNUNET_Mutex *lock;

static GNUNET_CoreAPIForPlugins *coreAPI;

static unsigned int stat_replies_routed;

static unsigned int stat_results_received;

static unsigned int stat_requests_routed;

static unsigned int stat_get_requests_received;

static unsigned int stat_put_requests_received;


/**
 * To how many peers should we (on average)
 * forward the request to obtain the desired
 * target_replication count (on average).
 */
static unsigned int
get_forward_count (unsigned int hop_count, double target_replication)
{
  double target_count;
  unsigned int target_value;
  unsigned int diameter;

  diameter = GNUNET_DHT_estimate_network_diameter ();
  if (hop_count > (diameter + 1) * 2)
    return 0;
  target_count =
    target_replication / (target_replication * (hop_count + 1) + diameter);
  target_value = 0;
  while (target_value < target_count)
    target_value++;
#define LARGE_INT 0xFFFFFF
  if ((target_count + 1 - target_value) >
      GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                         LARGE_INT) / ((double) LARGE_INT))
    target_value++;
  return target_value;
}


/**
 * Given a result, lookup in the routing table
 * where to send it next.
 */
static int
routeResult (const GNUNET_HashCode * key,
             unsigned int type,
             unsigned int size, const char *data, void *cls)
{
  DHTQueryRecord *q;
  unsigned int i;
  unsigned int j;
  int found;
  GNUNET_HashCode hc;
  DHT_MESSAGE *result;
  unsigned int routed;
  unsigned int tracked;
  DHT_Source_Route *pos;
  DHT_Source_Route *prev;
  GNUNET_CronTime now;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
#endif

#if DEBUG_ROUTING
  GNUNET_hash_to_enc (key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "DHT-Routing of result for key `%s'.\n", &enc);
#endif
  if (cls != NULL)
    {
      result = cls;
    }
  else
    {
      result = GNUNET_malloc (sizeof (DHT_MESSAGE) + size);
      result->header.size = htons (sizeof (DHT_MESSAGE) + size);
      result->header.type = htons (GNUNET_P2P_PROTO_DHT_RESULT);
      result->type = htonl (type);
      result->hop_count = htonl (0);
      result->network_size = htonl (GNUNET_DHT_estimate_network_diameter ());
      result->key = *key;
      memcpy (&result[1], data, size);
    }
  GNUNET_hash (data, size, &hc);
  routed = 0;
  tracked = 0;
  GNUNET_mutex_lock (lock);
  now = GNUNET_get_time ();
  for (i = 0; i < rt_size; i++)
    {
      q = &records[i];
      tracked++;
      if ((ntohl (q->get.type) != type) ||
          (0 != memcmp (key, &q->get.key, sizeof (GNUNET_HashCode))))
        continue;
      found = GNUNET_NO;
      for (j = 0; j < q->result_count; j++)
        if (0 == memcmp (&hc, &q->results[j], sizeof (GNUNET_HashCode)))
          {
            found = GNUNET_YES;
            break;
          }
      if (found == GNUNET_YES)
        {
#if DEBUG_ROUTING
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                         GNUNET_GE_DEVELOPER,
                         "Seen the same result earlier, not routing it again.\n");
#endif
          break;
        }
      routed++;
      GNUNET_array_grow (q->results, q->result_count, q->result_count + 1);
      q->results[q->result_count - 1] = hc;
      pos = q->sources;
      prev = NULL;
      while (pos != NULL)
        {
          if (pos->expire < now)
            {
#if DEBUG_ROUTING
              GNUNET_hash_to_enc (&pos->source.hashPubKey, &enc);
              GNUNET_GE_LOG (coreAPI->ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_DEVELOPER,
                             "Route to peer `%s' has expired (%llu < %llu)\n",
                             &enc, pos->expire, now);
#endif
              if (prev == NULL)
                q->sources = pos->next;
              else
                prev->next = pos->next;
              GNUNET_free (pos);
              if (prev == NULL)
                pos = q->sources;
              else
                pos = prev->next;
              continue;
            }
          if (0 != memcmp (&pos->source,
                           coreAPI->myIdentity, sizeof (GNUNET_PeerIdentity)))
            {
#if DEBUG_ROUTING
              GNUNET_hash_to_enc (&pos->source.hashPubKey, &enc);
              GNUNET_GE_LOG (coreAPI->ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_DEVELOPER,
                             "Routing result to `%s'\n", &enc);
#endif
              coreAPI->unicast (&pos->source,
                                &result->header, DHT_PRIORITY, DHT_DELAY);
              if (stats != NULL)
                stats->change (stat_replies_routed, 1);
            }
          if (pos->receiver != NULL)
            {
#if DEBUG_ROUTING
              GNUNET_GE_LOG (coreAPI->ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_DEVELOPER,
                             "Routing result to local client\n");
#endif
              pos->receiver (key, type, size, data, pos->receiver_closure);
              if (stats != NULL)
                stats->change (stat_replies_routed, 1);
            }
          pos = pos->next;
        }
      if (q->result_count >= MAX_RESULTS)
        q->expire = 0;
      break;
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
  return GNUNET_OK;
}

/**
 * @return GNUNET_OK if route was added, GNUNET_SYSERR if not
 */
static int
addRoute (const GNUNET_PeerIdentity * sender,
          GNUNET_ResultProcessor handler, void *cls, const DHT_MESSAGE * get)
{
  DHTQueryRecord *q;
  unsigned int i;
  unsigned int rt_pos;
  unsigned int diameter;
  GNUNET_CronTime expire;
  GNUNET_CronTime now;
  unsigned int hops;
  struct DHT_Source_Route *pos;

  hops = ntohl (get->hop_count);
  diameter = GNUNET_DHT_estimate_network_diameter ();
  if (hops > 2 * diameter)
    return GNUNET_SYSERR;
  now = GNUNET_get_time ();
  expire = now + DHT_DELAY * diameter * 4;
  GNUNET_mutex_lock (lock);
  rt_pos = rt_size;
  for (i = 0; i < rt_size; i++)
    {
      q = &records[i];
      if ((q->expire > now) &&
          ((0 != memcmp (&q->get.key,
                         &get->key,
                         sizeof (GNUNET_HashCode))) ||
           (q->get.type == get->type)))
        continue;               /* used and not an identical request */
      if (q->expire < now)
        {
          rt_pos = i;
          while (q->sources != NULL)
            {
              pos = q->sources;
              q->sources = pos->next;
              GNUNET_free (pos);
            }
          GNUNET_array_grow (q->results, q->result_count, 0);
          q->expire = 0;
        }
      if ((0 == memcmp (&q->get.key,
                        &get->key,
                        sizeof (GNUNET_HashCode)) &&
           (q->get.type == get->type)))
        {
          GNUNET_array_grow (q->results, q->result_count, 0);
          rt_pos = i;
          break;
        }
    }
  if (rt_pos == rt_size)
    {
      /* do not route, no slot available */
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  q = &records[rt_pos];
  if (q->expire < expire)
    q->expire = expire;
  q->get = *get;
  pos = GNUNET_malloc (sizeof (DHT_Source_Route));
  pos->next = q->sources;
  q->sources = pos;
  if (sender != NULL)
    pos->source = *sender;
  else
    pos->source = *coreAPI->myIdentity;
  pos->expire = expire;
  pos->receiver = handler;
  pos->receiver_closure = cls;
#if DEBUG_ROUTING
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "Tracking request in slot %u\n", rt_pos);
#endif
  GNUNET_mutex_unlock (lock);
  if (stats != NULL)
    stats->change (stat_requests_routed, 1);
  return GNUNET_OK;
}

/**
 * Handle GET message.
 */
static int
handleGet (const GNUNET_PeerIdentity * sender,
           const GNUNET_MessageHeader * msg)
{
  GNUNET_PeerIdentity next[GET_TRIES];
  const DHT_MESSAGE *get;
  DHT_MESSAGE aget;
  unsigned int target_value;
  unsigned int hop_count;
  int total;
  int i;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
  GNUNET_EncName henc;
#endif

  if (ntohs (msg->size) != sizeof (DHT_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  get = (const DHT_MESSAGE *) msg;
#if DEBUG_ROUTING
  GNUNET_hash_to_enc (&get->key, &enc);
  if (sender != NULL)
    GNUNET_hash_to_enc (&sender->hashPubKey, &henc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "Received DHT GET for key `%s' from `%s'.\n", &enc,
                 sender == NULL ? "me" : (char *) &henc);
#endif
  if (stats != NULL)
    stats->change (stat_get_requests_received, 1);
  if ((sender != NULL) && (GNUNET_OK != addRoute (sender, NULL, NULL, get)))
    {
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Failed to add entry in routing table for request.\n");
#endif
      return GNUNET_OK;         /* could not route */
    }
  total = dstore->get (&get->key, ntohl (get->type), &routeResult, NULL);
  if (total > MAX_RESULTS)
    {
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Found %d results locally, will not route GET any further\n",
                     total);
#endif
      return GNUNET_OK;
    }
  aget = *get;
  hop_count = ntohl (get->hop_count);
  target_value = get_forward_count (hop_count, GET_TRIES);
  aget.hop_count = htonl (1 + hop_count);
  aget.network_size =
    htonl (ntohl (get->network_size) +
           GNUNET_DHT_estimate_network_diameter ());
  if (target_value > GET_TRIES)
    target_value = GET_TRIES;
  for (i = 0; i < target_value; i++)
    {
      if (GNUNET_OK !=
          GNUNET_DHT_select_peer (&next[i], &get->key, &next[0], i))
        {
#if DEBUG_ROUTING
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                         GNUNET_GE_DEVELOPER,
                         "Failed to select peer for fowarding in round %d/%d\n",
                         i, GET_TRIES);
#endif
          break;
        }
#if DEBUG_ROUTING
      GNUNET_hash_to_enc (&next[i].hashPubKey, &enc);
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Forwarding DHT GET request to peer `%s'.\n", &enc);
#endif
      coreAPI->unicast (&next[i], &aget.header, DHT_PRIORITY, DHT_DELAY);
    }
  return GNUNET_OK;
}

/**
 * Handle PUT message.
 */
static int
handlePut (const GNUNET_PeerIdentity * sender,
           const GNUNET_MessageHeader * msg)
{
  GNUNET_PeerIdentity next[PUT_TRIES];
  const DHT_MESSAGE *put;
  DHT_MESSAGE *aput;
  GNUNET_CronTime now;
  unsigned int hop_count;
  unsigned int target_value;
  int store;
  int i;
  unsigned int j;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
#endif

  if (ntohs (msg->size) < sizeof (DHT_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_put_requests_received, 1);
  put = (const DHT_MESSAGE *) msg;
#if DEBUG_ROUTING
  GNUNET_hash_to_enc (&put->key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "Received DHT PUT for key `%s'.\n", &enc);
#endif
  store = 0;
  hop_count = htons (put->hop_count);
  target_value = get_forward_count (hop_count, PUT_TRIES);
  aput = GNUNET_malloc (ntohs (msg->size));
  memcpy (aput, put, ntohs (msg->size));
  aput->hop_count = htons (hop_count + 1);
  aput->network_size =
    htonl (ntohl (put->network_size) +
           GNUNET_DHT_estimate_network_diameter ());
  if (target_value > PUT_TRIES)
    target_value = PUT_TRIES;
  j = 0;
  for (i = 0; i < target_value; i++)
    {
      if (GNUNET_OK !=
          GNUNET_DHT_select_peer (&next[j], &put->key, &next[0], j))
        {
#if DEBUG_ROUTING
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                         GNUNET_GE_DEVELOPER,
                         "Failed to select peer for PUT fowarding in round %d/%d\n",
                         i, PUT_TRIES);
#endif
          store = 1;
          continue;
        }
      if (1 == GNUNET_hash_xorcmp (&next[j].hashPubKey,
                                   &coreAPI->myIdentity->hashPubKey,
                                   &put->key))
        store = 1;              /* we're closer than the selected target */
#if DEBUG_ROUTING
      GNUNET_hash_to_enc (&next[j].hashPubKey, &enc);
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Forwarding DHT PUT request to peer `%s'.\n", &enc);
#endif
      coreAPI->unicast (&next[j], &aput->header, DHT_PRIORITY, DHT_DELAY);
      j++;
    }
  GNUNET_free (aput);
  if (store != 0)
    {
      now = GNUNET_get_time ();
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Decided to cache data `%.*s' locally until %llu (for %llu ms)\n",
                     ntohs (put->header.size) - sizeof (DHT_MESSAGE),
                     &put[1], CONTENT_LIFETIME + now, CONTENT_LIFETIME);
#endif
      dstore->put (&put->key,
                   ntohl (put->type),
                   CONTENT_LIFETIME + now,
                   ntohs (put->header.size) - sizeof (DHT_MESSAGE),
                   (const char *) &put[1]);
    }
  else
    {
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "Decided NOT to cache data `%.*s' locally\n",
                     ntohs (put->header.size) - sizeof (DHT_MESSAGE),
                     &put[1]);
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
  const DHT_MESSAGE *result;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
#endif

  if (ntohs (msg->size) < sizeof (DHT_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_results_received, 1);
  result = (const DHT_MESSAGE *) msg;
#if DEBUG_ROUTING
  GNUNET_hash_to_enc (&result->key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "Received REMOTE DHT RESULT for key `%s'.\n", &enc);
#endif
  routeResult (&result->key,
               ntohl (result->type),
               ntohs (result->header.size) - sizeof (DHT_MESSAGE),
               (const char *) &result[1], (void *) msg);
  return GNUNET_OK;
}

/**
 * Start a DHT get operation.
 */
int
GNUNET_DHT_get_start (const GNUNET_HashCode * key,
                      unsigned int type, GNUNET_ResultProcessor handler,
                      void *cls)
{
  DHT_MESSAGE get;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
#endif

  get.header.size = htons (sizeof (DHT_MESSAGE));
  get.header.type = htons (GNUNET_P2P_PROTO_DHT_GET);
  get.type = htonl (type);
  get.hop_count = htonl (0);
  get.network_size = htonl (GNUNET_DHT_estimate_network_diameter ());
  get.key = *key;
#if DEBUG_ROUTING
  GNUNET_hash_to_enc (&get.key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "Initiating DHT GET (based on local request) for key `%s'.\n",
                 &enc);
#endif
  if (GNUNET_OK != addRoute (NULL, handler, cls, &get))
    return GNUNET_SYSERR;
  handleGet (NULL, &get.header);
  return GNUNET_OK;
}

/**
 * Stop a DHT get operation (prevents calls to
 * the given iterator).
 */
int
GNUNET_DHT_get_stop (const GNUNET_HashCode * key,
                     unsigned int type, GNUNET_ResultProcessor handler,
                     void *cls)
{
  unsigned int i;
  struct DHT_Source_Route *pos;
  struct DHT_Source_Route *prev;
  int done;

  done = GNUNET_NO;
  GNUNET_mutex_lock (lock);
  for (i = 0; i < rt_size; i++)
    {
      prev = NULL;
      pos = records[i].sources;
      while (pos != NULL)
        {
          if ((pos->receiver == handler) &&
              (pos->receiver_closure == cls) &&
              (0 == memcmp (key,
                            &records[i].get.key, sizeof (GNUNET_HashCode))))
            {
              if (prev == NULL)
                records[i].sources = pos->next;
              else
                prev->next = pos->next;
              GNUNET_free (pos);
              done = GNUNET_YES;
              break;
            }
          prev = pos;
          pos = prev->next;
        }
      if (records[i].sources == NULL)
        {
          GNUNET_array_grow (records[i].results, records[i].result_count, 0);
          records[i].expire = 0;
        }
      if (done == GNUNET_YES)
        break;
    }
  GNUNET_mutex_unlock (lock);
  if (done != GNUNET_YES)
    return GNUNET_SYSERR;
  return GNUNET_OK;
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
int
GNUNET_DHT_put (const GNUNET_HashCode * key,
                unsigned int type, unsigned int size, const char *data)
{
  DHT_MESSAGE *put;

  put = GNUNET_malloc (sizeof (DHT_MESSAGE) + size);
  put->header.size = htons (sizeof (DHT_MESSAGE) + size);
  put->header.type = htons (GNUNET_P2P_PROTO_DHT_PUT);
  put->key = *key;
  put->type = htonl (type);
  put->hop_count = htonl (0);
  put->network_size = htonl (GNUNET_DHT_estimate_network_diameter ());
  memcpy (&put[1], data, size);
  handlePut (NULL, &put->header);
  GNUNET_free (put);
  return GNUNET_OK;
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
  /* FIXME */
  return 0;
}

/**
 * Initialize routing DHT component.
 *
 * @param capi the core API
 * @return GNUNET_OK on success
 */
int
GNUNET_DHT_init_routing (GNUNET_CoreAPIForPlugins * capi)
{
  unsigned long long rts;

  coreAPI = capi;
  rts = 65536;
  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DHT",
                                            "TABLESIZE",
                                            128, 1024 * 1024, 1024, &rts);
  dstore = coreAPI->request_service ("dstore");
  if (dstore == NULL)
    return GNUNET_SYSERR;
  GNUNET_array_grow (records, rt_size, rts);

  lock = GNUNET_mutex_create (GNUNET_NO);
  stats = capi->request_service ("stats");
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
                 "dht", GNUNET_P2P_PROTO_DHT_GET, GNUNET_P2P_PROTO_DHT_PUT,
                 GNUNET_P2P_PROTO_DHT_RESULT);
  coreAPI->registerHandler (GNUNET_P2P_PROTO_DHT_GET, &handleGet);
  coreAPI->registerHandler (GNUNET_P2P_PROTO_DHT_PUT, &handlePut);
  coreAPI->registerHandler (GNUNET_P2P_PROTO_DHT_RESULT, &handleResult);
  coreAPI->
    connection_register_send_callback (sizeof (DHT_MESSAGE), 0,
                                       &extra_get_callback);
  return GNUNET_OK;
}

/**
 * Shutdown routing DHT component.
 *
 * @return GNUNET_OK on success
 */
int
GNUNET_DHT_done_routing ()
{
  unsigned int i;
  struct DHT_Source_Route *pos;

  coreAPI->
    connection_unregister_send_callback (sizeof (DHT_MESSAGE),
                                         &extra_get_callback);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_DHT_GET, &handleGet);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_DHT_PUT, &handlePut);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_DHT_RESULT, &handleResult);
  if (stats != NULL)
    {
      coreAPI->release_service (stats);
      stats = NULL;
    }
  GNUNET_mutex_destroy (lock);
  for (i = 0; i < rt_size; i++)
    {
      while (records[i].sources != NULL)
        {
          pos = records[i].sources;
          records[i].sources = pos->next;
          GNUNET_free (pos);
        }
      GNUNET_array_grow (records[i].results, records[i].result_count, 0);
    }
  GNUNET_array_grow (records, rt_size, 0);
  coreAPI->release_service (dstore);
  return GNUNET_OK;
}

/* end of routing.c */
