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
 * @brief state for active DV_DHT routing operations
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
#include "gnunet_dv_service.h"
#include "gnunet_dhtlog_service.h"

#define DEBUG_ROUTING GNUNET_YES
#define DEBUG_INSANE GNUNET_YES

/**
 * What is the request priority for DV_DHT operations?
 */
#define DV_DHT_PRIORITY 0

/*
 * Number of hash functions for bloom filter
 */
#define DV_DHT_BLOOM_K 16

/*
 * Size in bytes of bloom filter
 */
#define DV_DHT_BLOOM_SIZE 4


/**
 * What is the estimated per-hop delay for DV_DHT operations
 * (this is how much we will request from the GNUnet core);
 * Must not be zero!
 */
#define DV_DHT_DELAY (500 * GNUNET_CRON_MILLISECONDS)

/**
 * What is the maximum number of results returned by any DV_DHT
 * operation?
 */
#define MAX_RESULTS 64

/**
 * How many peers should a DV_DHT GET request reach on averge?
 *
 * Larger factors will result in more aggressive routing of GET
 * operations (each peer will either forward to GET_TRIES peers that
 * are closer to the key).
 */
#define GET_TRIES 7

/**
 * At how many peers should a DV_DHT PUT request be replicated
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
typedef struct DV_DHT_Source_Route
{

  /**
   * This is a linked list.
   */
  struct DV_DHT_Source_Route *next;

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

  /*
   * Have we sent this specific response to a local client yet?
   * (So we only give a single response to an application)
   */
  unsigned int received;

  void *receiver_closure;


} DV_DHT_Source_Route;

/**
 * @brief message send for DV_DHT get, put or result.
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

  /*
   * Bloomfilter to stop circular routes
   */
  char bloomfilter[4];

#if DEBUG_ROUTING
  /*
   * Unique query id for sql database interaction.
   */
  unsigned long long queryuid;

  /*
   * Unique trial id for sql database interaction
   */
  unsigned long long trialuid;

#endif

} DV_DHT_MESSAGE;

/**
 * Entry in the DV_DHT routing table.
 */
typedef struct DV_DHTQueryRecord
{

  /**
   * Information about where to send the results back to.
   */
  DV_DHT_Source_Route *sources;

  /**
   * GET message of this record (what we are forwarding).
   */
  DV_DHT_MESSAGE get;

  /**
   * Hashcodes of the results that we have sent back
   * so far.
   */
  GNUNET_HashCode *results;

  /**
   * Number of entries in results.
   */
  unsigned int result_count;

} DV_DHTQueryRecord;

/**
 * Array of active records.
 */
static DV_DHTQueryRecord *records;

/**
 * Size of records
 */
static unsigned int rt_size;
static unsigned int next_record;

#if DEBUG_INSANE
static unsigned int indentation;
#endif

/*
 * Whether or not to send routing debugging information
 * to the dht logging server
 */
static unsigned int debug_routes;

/*
 * Whether or not to send FULL route information to
 * logging server
 */
static unsigned int debug_routes_extended;

/**
 * Statistics service.
 */
static GNUNET_Stats_ServiceAPI *stats;

static GNUNET_Dstore_ServiceAPI *dstore;

/*
 * DHT Logging service.
 */
static GNUNET_dhtlog_ServiceAPI *dhtlog;

static GNUNET_DV_ServiceAPI *dvapi;

static struct GNUNET_Mutex *lock;

static GNUNET_CoreAPIForPlugins *coreAPI;

static unsigned int stat_replies_routed;

static unsigned int stat_results_received;

static unsigned int stat_requests_routed;

static unsigned int stat_get_requests_received;

static unsigned int stat_put_requests_received;

#if DEBUG_INSANE
static void
print_entry (char *function)
{
  int i;

  for (i = 0; i < indentation; i++)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK, "  ");
    }

  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, _("Entering `%s'\n"), function);
  indentation++;
}

static void
print_exit (char *function)
{
  int i;
  for (i = 0; i < indentation; i++)
    {
      if (indentation >= 1)
        indentation--;
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK, "  ");
    }
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, _("Exiting `%s'\n"), function);
}
#endif

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

  diameter = GNUNET_DV_DHT_estimate_network_diameter ();
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
route_result (const GNUNET_HashCode * key,
              unsigned int type,
              unsigned int size, const char *data, void *cls)
{
  DV_DHTQueryRecord *q;
  GNUNET_HashCode hc;
  DV_DHT_MESSAGE *result;
  struct GNUNET_BloomFilter *bloom;
  unsigned int routed;
  unsigned int tracked;
  unsigned int i;
  int match;
  DV_DHT_Source_Route *pos;
  DV_DHT_Source_Route *prev;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
  unsigned long long queryuid;
  unsigned long long *dhtqueryuid_ptr = NULL;
  unsigned long long dhtqueryuid;
#endif

#if DEBUG_ROUTING
  GNUNET_hash_to_enc (key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 _("DHT-Routing of result for key `%s'.\n"), &enc);
#endif

  if (cls != NULL)
    {
      result = cls;
#if DEBUG_ROUTING
      result->hop_count = htonl (ntohl (result->hop_count) + 1);
#endif
    }
  if ((cls == NULL)
      || (ntohs (result->header.type) != GNUNET_P2P_PROTO_DHT_RESULT))
    {
#if DEBUG_ROUTING

      if ((cls != NULL)
          && (ntohs (result->header.type) != GNUNET_P2P_PROTO_DHT_RESULT))
        {
          dhtqueryuid_ptr = cls;
          dhtqueryuid = *dhtqueryuid_ptr;
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
                         | GNUNET_GE_BULK,
                         _
                         ("cls not null and type is wrong! Got dhtqueryuid of %llu"),
                         dhtqueryuid);
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
                         | GNUNET_GE_BULK,
                         _("got header type of %d or %d, wanted %d"),
                         ntohs (result->header.type), result->header.type,
                         GNUNET_P2P_PROTO_DHT_RESULT);

        }
      else
        {
          dhtqueryuid = 0;
        }
#endif
      result = GNUNET_malloc (sizeof (DV_DHT_MESSAGE) + size);
      result->header.size = htons (sizeof (DV_DHT_MESSAGE) + size);
      result->header.type = htons (GNUNET_P2P_PROTO_DHT_RESULT);
      result->type = htonl (type);
      result->hop_count = htonl (0);
      result->network_size =
        htonl (GNUNET_DV_DHT_estimate_network_diameter ());
      result->key = *key;
      memset (&result->bloomfilter, 0, DV_DHT_BLOOM_SIZE);
      if ((debug_routes) && (dhtlog != NULL))
        {
          dhtlog->insert_query (&queryuid, dhtqueryuid, DHTLOG_RESULT,
                                ntohl (result->hop_count), GNUNET_NO,
                                coreAPI->my_identity, key);
        }
#if DEBUG_ROUTING
      if (dhtqueryuid != 0)
        result->queryuid = htonl (dhtqueryuid);
      else
        result->queryuid = htonl (queryuid);
#endif
      memcpy (&result[1], data, size);
    }

  bloom =
    GNUNET_bloomfilter_init (NULL, &result->bloomfilter[0], DV_DHT_BLOOM_SIZE,
                             DV_DHT_BLOOM_K);
  GNUNET_bloomfilter_add (bloom, &coreAPI->my_identity->hashPubKey);
  GNUNET_bloomfilter_get_raw_data (bloom, &result->bloomfilter[0],
                                   DV_DHT_BLOOM_SIZE);

  GNUNET_hash (data, size, &hc);
  routed = 0;
  tracked = 0;
  GNUNET_mutex_lock (lock);

  for (i = 0; i < rt_size; i++)
    {
      q = &records[i];
      tracked++;
      if ((ntohl (q->get.type) != type)
          || (0 != memcmp (key, &q->get.key, sizeof (GNUNET_HashCode))))
        continue;
      else
        {
#if DEBUG_ROUTING
          GNUNET_hash_to_enc (&q->get.key, &enc);
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                         GNUNET_GE_USER | GNUNET_GE_BULK,
                         "Found matching request for reply `%s'\n", &enc);
#endif
        }
      routed++;
      pos = q->sources;
      prev = NULL;
      while (pos != NULL)
        {
          if (0 != memcmp (&pos->source,
                           coreAPI->my_identity,
                           sizeof (GNUNET_PeerIdentity)))
            {
#if DEBUG_ROUTING
              GNUNET_hash_to_enc (&pos->source.hashPubKey, &enc);
              GNUNET_GE_LOG (coreAPI->ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                             GNUNET_GE_USER | GNUNET_GE_BULK,
                             "Routing result to `%s'\n", &enc);
#endif
              if ((debug_routes_extended) && (dhtlog != NULL))
                {
                  queryuid = ntohl (result->queryuid);
                  dhtlog->insert_route (NULL, queryuid,
                                        DHTLOG_RESULT,
                                        ntohl (result->hop_count), GNUNET_NO,
                                        coreAPI->my_identity, key, NULL,
                                        &pos->source);
                }
              match = GNUNET_NO;
              match = GNUNET_bloomfilter_test (bloom, &pos->source.hashPubKey);
              if (match == GNUNET_YES)
              {
                pos = pos->next;
                continue;
              }
              dvapi->dv_send (&pos->source,
                              &result->header, DV_DHT_PRIORITY, DV_DHT_DELAY);

              if (stats != NULL)
                stats->change (stat_replies_routed, 1);
            }
          if ((pos->receiver != NULL) && (pos->received != GNUNET_YES))
            {
#if DEBUG_ROUTING
              GNUNET_GE_LOG (coreAPI->ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                             GNUNET_GE_USER | GNUNET_GE_BULK,
                             "Routing result to local client\n");
#endif
              pos->receiver (key, type, size, data, pos->receiver_closure);
              pos->received = GNUNET_YES;
              if ((debug_routes) && (dhtlog != NULL))
                {
                  queryuid = ntohl (result->queryuid);
                  dhtlog->insert_query (NULL, queryuid, DHTLOG_RESULT,
                                        ntohl (result->hop_count), GNUNET_YES,
                                        coreAPI->my_identity, key);
                }

              if ((debug_routes_extended) && (dhtlog != NULL))
                {
                  queryuid = ntohl (result->queryuid);
                  dhtlog->insert_route (NULL, queryuid,
                                        DHTLOG_RESULT,
                                        ntohl (result->hop_count), GNUNET_YES,
                                        coreAPI->my_identity, key, NULL,
                                        NULL);
                }
              if (stats != NULL)
                stats->change (stat_replies_routed, 1);
            }
          pos = pos->next;
        }
    }
  GNUNET_mutex_unlock (lock);
#if DEBUG_ROUTING
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "Routed result to %u out of %u pending requests\n",
                 routed, tracked);
#endif
  GNUNET_bloomfilter_free (bloom);
  if (cls == NULL)
    GNUNET_free (result);
  return GNUNET_OK;
}

/**
 * @return GNUNET_OK if route was added, GNUNET_SYSERR if not
 */
static int
add_route (const GNUNET_PeerIdentity * sender,
           GNUNET_ResultProcessor handler, void *cls,
           const DV_DHT_MESSAGE * get)
{

/*
 * TODO: Eventually change to using a hash
 * map for more efficient lookup of return routing information!
 */
  DV_DHTQueryRecord *q;
  unsigned int diameter;
  unsigned int hops;
  struct DV_DHT_Source_Route *pos;

  hops = ntohl (get->hop_count);
  diameter = GNUNET_DV_DHT_estimate_network_diameter ();
  /*if (hops > 2 * diameter) */
  if (hops > 2 * diameter)
    {
      fprintf (stderr,
               "hops (%d) > 2 * diameter (%d) so failing (diameter %d)\n",
               hops, 2 * diameter, diameter);
      return GNUNET_SYSERR;
    }

  GNUNET_mutex_lock (lock);

  q = &records[next_record];
#if DEBUG_ROUTING
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Tracking request in slot %u\n",
                 next_record);
#endif
  if (q->sources != NULL)
    {
      while (q->sources != NULL)
        {
          pos = q->sources;
          q->sources = pos->next;
          GNUNET_free (pos);
        }
      GNUNET_array_grow (q->results, q->result_count, 0);
    }

  q->get = *get;
  pos = GNUNET_malloc (sizeof (DV_DHT_Source_Route));
  pos->next = q->sources;
  q->sources = pos;
  if (sender != NULL)
    pos->source = *sender;
  else
    pos->source = *coreAPI->my_identity;
  pos->receiver = handler;
  pos->receiver_closure = cls;

  /* We loop through the records, allows peer
   * to control how many concurrent responses
   * are known about.
   */
  if (next_record == rt_size - 1)
    {
      next_record = 0;
    }
  else
    next_record++;

  GNUNET_mutex_unlock (lock);
  if (stats != NULL)
    stats->change (stat_requests_routed, 1);
  return GNUNET_OK;
}

/**
 * Handle GET message.
 */
static int
handle_get (const GNUNET_PeerIdentity * sender,
            const GNUNET_MessageHeader * msg)
{
  GNUNET_PeerIdentity next[GET_TRIES + 1];
  const DV_DHT_MESSAGE *get;
  DV_DHT_MESSAGE aget;
  unsigned int target_value;
  unsigned int hop_count;
  struct GNUNET_BloomFilter *bloom;
  int total;
  int i;
  int j;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
  GNUNET_EncName henc;
  unsigned long long queryuid;
#endif

  if (ntohs (msg->size) != sizeof (DV_DHT_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  get = (const DV_DHT_MESSAGE *) msg;
#if DEBUG_ROUTING
  GNUNET_hash_to_enc (&get->key, &enc);
  if (sender != NULL)
    GNUNET_hash_to_enc (&sender->hashPubKey, &henc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "Received DV_DHT GET for key `%s' from `%s'.\n", &enc,
                 sender == NULL ? "me" : (char *) &henc);
#endif

  if (stats != NULL)
    stats->change (stat_get_requests_received, 1);
  if ((sender != NULL) && (GNUNET_OK != add_route (sender, NULL, NULL, get)))
    {
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Failed to add entry in routing table for request.\n");

      if ((debug_routes) && (dhtlog != NULL))
        {
          hop_count = ntohl (get->hop_count);
          queryuid = ntohl (get->queryuid);
          dhtlog->insert_query (NULL, queryuid, DHTLOG_GET,
                                hop_count, GNUNET_NO, coreAPI->my_identity,
                                &get->key);
        }
#endif
      return GNUNET_OK;         /* could not route */
    }

#if DEBUG_ROUTING
  queryuid = ntohl (get->queryuid);
  total =
    dstore->get (&get->key, ntohl (get->type), &route_result,
                 (void *) &queryuid);
#else
  total = dstore->get (&get->key, ntohl (get->type), &route_result, NULL);
#endif

  if (total > 0)
    {
      if ((debug_routes) && (dhtlog != NULL))
        {
          queryuid = ntohl (get->queryuid);
          hop_count = ntohl (get->hop_count);
          dhtlog->insert_query (NULL, queryuid, DHTLOG_GET,
                                hop_count, GNUNET_YES, coreAPI->my_identity,
                                &get->key);
        }

      if ((debug_routes_extended) && (dhtlog != NULL))
        {
          queryuid = ntohl (get->queryuid);
          dhtlog->insert_route (NULL, ntohl (get->queryuid), DHTLOG_GET,
                                hop_count, GNUNET_YES, coreAPI->my_identity,
                                &get->key, sender, NULL);
        }
    }

  if (total > MAX_RESULTS)
    {
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Found %d results locally, will not route GET any further\n",
                     total);
#endif
      return GNUNET_OK;
    }
  aget = *get;

  bloom =
    GNUNET_bloomfilter_init (NULL, &aget.bloomfilter[0], DV_DHT_BLOOM_SIZE,
                             DV_DHT_BLOOM_K);
  GNUNET_bloomfilter_add (bloom, &coreAPI->my_identity->hashPubKey);
  GNUNET_bloomfilter_get_raw_data (bloom, &aget.bloomfilter[0],
                                   DV_DHT_BLOOM_SIZE);

  hop_count = ntohl (get->hop_count);
  target_value = get_forward_count (hop_count, GET_TRIES);
  aget.hop_count = htonl (1 + hop_count);
  aget.network_size =
    htonl (ntohl (get->network_size) +
           GNUNET_DV_DHT_estimate_network_diameter ());
  if (target_value > GET_TRIES)
    target_value = GET_TRIES;
  j = 0;
  if (sender != NULL)
    next[j++] = *sender;        /* do not send back to sender! */
  for (i = 0; i < target_value; i++)
    {
      if (GNUNET_OK !=
          GNUNET_DV_DHT_select_peer (&next[j], &get->key, &next[0], j, bloom))
        {
#if DEBUG_ROUTING
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
                         | GNUNET_GE_BULK,
                         "Failed to select peer for fowarding in round %d/%d\n",
                         i + 1, GET_TRIES);
#endif
          break;
        }
#if DEBUG_ROUTING
      GNUNET_hash_to_enc (&next[j].hashPubKey, &enc);
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Forwarding DV_DHT GET request to peer `%s'.\n", &enc);
#endif
      if ((debug_routes_extended) && (dhtlog != NULL))
        {
          queryuid = ntohl (get->queryuid);
          dhtlog->insert_route (NULL, ntohl (get->queryuid), DHTLOG_GET,
                                hop_count, GNUNET_NO, coreAPI->my_identity,
                                &get->key, sender, &next[j]);
        }

      dvapi->dv_send (&next[j], &aget.header, DV_DHT_PRIORITY, DV_DHT_DELAY);
      j++;
    }

  GNUNET_bloomfilter_free (bloom);
  return GNUNET_OK;
}

/**
 * Handle PUT message.
 */
static int
handle_put (const GNUNET_PeerIdentity * sender,
            const GNUNET_MessageHeader * msg)
{
  GNUNET_PeerIdentity next[PUT_TRIES + 1];
  const DV_DHT_MESSAGE *put;
  DV_DHT_MESSAGE *aput;
  GNUNET_CronTime now;
  struct GNUNET_BloomFilter *bloom;
  unsigned int hop_count;
  unsigned int target_value;
  int store;
  int i;
  unsigned int j;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
  unsigned long long queryuid;
#endif
  if (ntohs (msg->size) < sizeof (DV_DHT_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_put_requests_received, 1);
  put = (const DV_DHT_MESSAGE *) msg;
#if DEBUG_ROUTING
  GNUNET_hash_to_enc (&put->key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 _("Received DV_DHT PUT for key `%s'.\n"), &enc);
#endif
  store = 0;
  hop_count = htonl (put->hop_count);
  target_value = get_forward_count (hop_count, PUT_TRIES);
  aput = GNUNET_malloc (ntohs (msg->size));
  memcpy (aput, put, ntohs (msg->size));
  aput->hop_count = htonl (hop_count + 1);
  aput->network_size =
    htonl (ntohl (put->network_size) +
           GNUNET_DV_DHT_estimate_network_diameter ());
  if (target_value > PUT_TRIES)
    target_value = PUT_TRIES;
  j = 0;
  if (sender != NULL)
    next[j++] = *sender;        /* do not send back to sender! */

  bloom =
    GNUNET_bloomfilter_init (NULL, &aput->bloomfilter[0], DV_DHT_BLOOM_SIZE,
                             DV_DHT_BLOOM_K);
  GNUNET_bloomfilter_add (bloom, &coreAPI->my_identity->hashPubKey);
  GNUNET_bloomfilter_get_raw_data (bloom, &aput->bloomfilter[0],
                                   DV_DHT_BLOOM_SIZE);

  for (i = 0; i < target_value; i++)
    {
      if (GNUNET_OK !=
          GNUNET_DV_DHT_select_peer (&next[j], &put->key, &next[0], j, bloom))
        {
#if DEBUG_ROUTING
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER
                         | GNUNET_GE_BULK,
                         "Failed to select peer for PUT fowarding in round %d/%d\n",
                         i + 1, PUT_TRIES);
#endif
          continue;
        }
#if DEBUG_ROUTING
      GNUNET_hash_to_enc (&next[j].hashPubKey, &enc);
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Forwarding DV_DHT PUT request to peer `%s'.\n", &enc);
#endif
      if ((debug_routes_extended) && (dhtlog != NULL))
        {
          queryuid = ntohl (put->queryuid);
          dhtlog->insert_route (NULL, queryuid, DHTLOG_PUT,
                                hop_count, GNUNET_NO,
                                coreAPI->my_identity, &put->key, sender,
                                &next[j]);
        }
      dvapi->dv_send (&next[j], &aput->header, DV_DHT_PRIORITY, DV_DHT_DELAY);
      j++;
    }

  GNUNET_bloomfilter_free (bloom);
  GNUNET_free (aput);

  store = 0;
  if (GNUNET_YES == GNUNET_DV_DHT_am_closest_peer (&put->key))
    store = 1;

  if ((store == 0) && (target_value == 0) && (debug_routes_extended)
      && (dhtlog != NULL))
    {
      queryuid = ntohl (put->queryuid);
      dhtlog->insert_route (NULL, queryuid, DHTLOG_PUT,
                            hop_count, GNUNET_NO,
                            coreAPI->my_identity, &put->key, sender, NULL);
    }

  if (store != 0)
    {
      now = GNUNET_get_time ();
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Decided to cache data `%.*s' locally until %llu (for %llu ms)\n",
                     ntohs (put->header.size) - sizeof (DV_DHT_MESSAGE),
                     &put[1], CONTENT_LIFETIME + now, CONTENT_LIFETIME);
#endif

      if ((debug_routes) && (dhtlog != NULL))
        {
          queryuid = ntohl (put->queryuid);
          dhtlog->insert_query (NULL, queryuid, DHTLOG_PUT,
                                hop_count, GNUNET_YES,
                                coreAPI->my_identity, &put->key);
        }

      if ((debug_routes_extended) && (dhtlog != NULL))
        {
          queryuid = ntohl (put->queryuid);
          dhtlog->insert_route (NULL, queryuid, DHTLOG_PUT,
                                hop_count, GNUNET_YES,
                                coreAPI->my_identity, &put->key, sender,
                                NULL);
        }
      dstore->put (&put->key,
                   ntohl (put->type),
                   CONTENT_LIFETIME + now,
                   ntohs (put->header.size) - sizeof (DV_DHT_MESSAGE),
                   (const char *) &put[1]);
    }
  else
    {
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Decided NOT to cache data `%.*s' locally\n",
                     ntohs (put->header.size) - sizeof (DV_DHT_MESSAGE),
                     &put[1]);
#endif
    }
  return GNUNET_OK;
}

/**
 * Handle RESULT message.
 */
static int
handle_result (const GNUNET_PeerIdentity * sender,
               const GNUNET_MessageHeader * msg)
{
  const DV_DHT_MESSAGE *result;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
#endif

  if (ntohs (msg->size) < sizeof (DV_DHT_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_results_received, 1);
  result = (const DV_DHT_MESSAGE *) msg;
#if DEBUG_ROUTING
  GNUNET_hash_to_enc (&result->key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "Received REMOTE DV_DHT RESULT for key `%s'.\n", &enc);
#endif

  route_result (&result->key,
                ntohl (result->type),
                ntohs (result->header.size) - sizeof (DV_DHT_MESSAGE),
                (const char *) &result[1], (void *) msg);
  return GNUNET_OK;
}

/**
 * Start a DV_DHT get operation.
 */
int
GNUNET_DV_DHT_get_start (const GNUNET_HashCode * key,
                         unsigned int type, GNUNET_ResultProcessor handler,
                         void *cls)
{
  DV_DHT_MESSAGE get;
#if DEBUG_ROUTING
  GNUNET_EncName enc;
  unsigned long long queryuid;
  queryuid = 0;
#endif

  get.header.size = htons (sizeof (DV_DHT_MESSAGE));
  get.header.type = htons (GNUNET_P2P_PROTO_DHT_GET);
  get.type = htonl (type);
  get.hop_count = htonl (0);
  get.network_size = htonl (GNUNET_DV_DHT_estimate_network_diameter ());
  get.key = *key;
  memset (&get.bloomfilter, 0, DV_DHT_BLOOM_SIZE);
  if ((debug_routes) && (dhtlog != NULL))
    {
      dhtlog->insert_query (&queryuid, 0, DHTLOG_GET, 0, GNUNET_NO,
                            coreAPI->my_identity, key);
    }
#if DEBUG_ROUTING
  get.queryuid = htonl (queryuid);
  GNUNET_hash_to_enc (&get.key, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "Initiating DV_DHT GET (based on local request) for key `%s'.\n",
                 &enc);

#endif
  if (GNUNET_OK != add_route (NULL, handler, cls, &get))
    return GNUNET_SYSERR;
  handle_get (NULL, &get.header);
  return GNUNET_OK;
}

/**
 * Stop a DV_DHT get operation (prevents calls to
 * the given iterator).
 */
int
GNUNET_DV_DHT_get_stop (const GNUNET_HashCode * key,
                        unsigned int type, GNUNET_ResultProcessor handler,
                        void *cls)
{
  unsigned int i;
  struct DV_DHT_Source_Route *pos;
  struct DV_DHT_Source_Route *prev;
  int done;
  unsigned int records_removed;

  done = GNUNET_NO;
  GNUNET_mutex_lock (lock);
  records_removed = 0;
  for (i = 0; i < rt_size; i++)
    {
      prev = NULL;
      pos = records[i].sources;
      while (pos != NULL)
        {
          if ((pos->receiver == handler) &&
              (pos->receiver_closure == cls) &&
              (0 == memcmp (key,
                            &records[i].get.key, sizeof (GNUNET_HashCode)))
                            &&
              (0 == memcmp (&pos->source.hashPubKey,
                            &coreAPI->my_identity->hashPubKey, sizeof (GNUNET_HashCode))))
          {
              if (prev == NULL)
                records[i].sources = pos->next;
              else
                prev->next = pos->next;
              GNUNET_free (pos);
              records_removed++;
              break;
          }
          prev = pos;
          pos = prev->next;
        }
      if (records[i].sources == NULL)
        {
          GNUNET_array_grow (records[i].results, records[i].result_count, 0);
        }
    }
  GNUNET_mutex_unlock (lock);
#if DEBUG_ROUTING
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Removed %u total records\n", records_removed);
#endif
  if (done != GNUNET_YES)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Perform a DV_DHT put operation.  Note that PUT operations always
 * expire after a period of time and the client is responsible for
 * doing periodic refreshes.  The given expiration time is ONLY used to
 * ensure that the datum is certainly deleted by that time (it maybe
 * deleted earlier).
 *
 * @param expiration_time absolute expiration time
 */
int
GNUNET_DV_DHT_put (const GNUNET_HashCode * key,
                   unsigned int type, unsigned int size, const char *data)
{
  DV_DHT_MESSAGE *put;
#if DEBUG_ROUTING
  unsigned long long queryuid;
  unsigned long long keyuid;
#endif
  put = GNUNET_malloc (sizeof (DV_DHT_MESSAGE) + size);
  put->header.size = htons (sizeof (DV_DHT_MESSAGE) + size);
  put->header.type = htons (GNUNET_P2P_PROTO_DHT_PUT);
  put->key = *key;
  put->type = htonl (type);
  put->hop_count = htonl (0);
  memset (&put->bloomfilter, 0, DV_DHT_BLOOM_SIZE);
  put->network_size = htonl (GNUNET_DV_DHT_estimate_network_diameter ());
#if DEBUG_ROUTING
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK, "Insert called\n");
#endif
  if ((debug_routes) && (dhtlog != NULL))
    {
      dhtlog->insert_dhtkey (&keyuid, key);
      dhtlog->insert_query (&queryuid, 0, DHTLOG_PUT,
                            ntohl (put->hop_count), GNUNET_NO,
                            coreAPI->my_identity, key);
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "Inserted dhtkey, uid: %llu, inserted query, uid: %llu\n",
                     keyuid, queryuid);
#endif
    }
#if DEBUG_ROUTING
  put->queryuid = htonl (queryuid);
#endif
  memcpy (&put[1], data, size);
  handle_put (NULL, &put->header);
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
 * Initialize routing DV_DHT component.
 *
 * @param capi the core API
 * @return GNUNET_OK on success
 */
int
GNUNET_DV_DHT_init_routing (GNUNET_CoreAPIForPlugins * capi)
{
  unsigned long long rts;
  unsigned long long nodeuid;
  coreAPI = capi;
  rts = 65536;

#if DEBUG_INSANE
  print_entry ("GNUNET_DV_DHT_init_routing");
#endif

  GNUNET_GC_get_configuration_value_number (coreAPI->cfg,
                                            "DHT",
                                            "TABLESIZE",
                                            128, 1024 * 1024, 1024, &rts);
  dstore = coreAPI->service_request ("dstore");
  if (dstore == NULL)
    return GNUNET_SYSERR;
  dvapi = coreAPI->service_request ("dv");
  if (dvapi == NULL)
    return GNUNET_SYSERR;
  GNUNET_array_grow (records, rt_size, rts);

  lock = GNUNET_mutex_create (GNUNET_NO);
  stats = capi->service_request ("stats");
  if (stats != NULL)
    {
      stat_replies_routed =
        stats->create (gettext_noop ("# dv_dht replies routed"));
      stat_requests_routed =
        stats->create (gettext_noop ("# dv_dht requests routed"));
      stat_get_requests_received =
        stats->create (gettext_noop ("# dv_dht get requests received"));
      stat_put_requests_received =
        stats->create (gettext_noop ("# dv_dht put requests received"));
      stat_results_received =
        stats->create (gettext_noop ("# dv_dht results received"));
    }

  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 _("`%s' registering p2p handlers: %d %d %d\n"),
                 "dv_dht", GNUNET_P2P_PROTO_DHT_GET, GNUNET_P2P_PROTO_DHT_PUT,
                 GNUNET_P2P_PROTO_DHT_RESULT);
  coreAPI->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_DHT_GET,
                                            &handle_get);
  coreAPI->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_DHT_PUT,
                                            &handle_put);
  coreAPI->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_DHT_RESULT,
                                            &handle_result);
  coreAPI->send_callback_register (sizeof (DV_DHT_MESSAGE), 0,
                                   &extra_get_callback);

  if (GNUNET_YES ==
      GNUNET_GC_get_configuration_value_yesno (coreAPI->cfg, "DHT", "LOGSQL",
                                               GNUNET_NO))
    {
      debug_routes = GNUNET_YES;
    }
  if (GNUNET_YES ==
      GNUNET_GC_get_configuration_value_yesno (coreAPI->cfg, "DHT",
                                               "LOGSQLEXTENDED", GNUNET_NO))
    {
      debug_routes = GNUNET_YES;
      debug_routes_extended = GNUNET_YES;
    }
  if (GNUNET_YES == debug_routes_extended)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     _("`%s' extended logging enabled\n"), "dv_dht");
    }
  else if (GNUNET_YES == debug_routes)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     _("`%s' reduced logging enabled\n"), "dv_dht");
    }
  else
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK, _("`%s' logging disabled\n"), "dv_dht");

    }

  if (GNUNET_YES == GNUNET_GC_get_configuration_value_yesno (coreAPI->cfg,
                                                             "DHT",
                                                             "DHTLOG_MYSQL",
                                                             GNUNET_NO))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     _("`%s' loading logging context %s\n"),
                     "dv_dht", "dhtlog_mysql");
#if DEBUG_ROUTING
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     _
                     ("routing debugging enabled, expect lots of messages!\n"));

#endif
      dhtlog = coreAPI->service_request ("dhtlog_mysql");
      dhtlog->insert_node (&nodeuid, coreAPI->my_identity);
      GNUNET_GE_ASSERT (coreAPI->ectx, dhtlog != NULL);
    }
#if DEBUG_INSANE
  print_exit ("GNUNET_DV_DHT_init_routing");
#endif
  return GNUNET_OK;
}

/**
 * Shutdown routing DV_DHT component.
 *
 * @return GNUNET_OK on success
 */
int
GNUNET_DV_DHT_done_routing ()
{
  unsigned int i;
  struct DV_DHT_Source_Route *pos;

  coreAPI->send_callback_unregister (sizeof (DV_DHT_MESSAGE),
                                     &extra_get_callback);
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_DHT_GET,
                                              &handle_get);
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_DHT_PUT,
                                              &handle_put);
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_DHT_RESULT,
                                              &handle_result);
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }

  if (dhtlog != NULL)
    {
      coreAPI->service_release (dhtlog);
      dhtlog = NULL;
    }

  if (dvapi != NULL)
    {
      coreAPI->service_release (dvapi);
      dvapi = NULL;
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
  coreAPI->service_release (dstore);
  return GNUNET_OK;
}

/* end of routing.c */
