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
 * @file fs/gap/shared.h
 * @brief shared helper functions and data structures
 * @author Christian Grothoff
 */
#ifndef SHARED_H
#define SHARED_H

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "ecrs_core.h"
#include "pid_table.h"
#include "gap.h"

/**
 * Linked list of responses that we have gotten for
 * this request.  Used to avoid forwarding the same
 * response to the client multiple times and to
 * construct the bloom filter to block duplicates.
 */
struct ResponseList
{

  /**
   * This is a linked list.
   */
  struct ResponseList *next;

  /**
   * Hash of the dblocks of the responses.
   */
  GNUNET_HashCode hash;

};

/**
 * Linked list with the active requests of a client.
 */
struct RequestList
{

  /**
   * This is a linked list.
   */
  struct RequestList *next;

  /**
   * Linked list of responses that we have
   * already received for this request.
   */
  struct ResponseList *responses;

  /**
   * Linked list of query plan entries that this
   * request is part of (when a request is done,
   * these entries should be removed from the
   * respective query plans).  This is the head
   * of a linked list that is constructed using
   * the "plan_entries_next" field of QueryPlanEntry.
   */
  struct QueryPlanEntry *plan_entries;

  /**
   * Bloomfilter for the query (maybe NULL).
   */
  struct GNUNET_BloomFilter *bloomfilter;

  /**
   * NULL if this request is for another peer,
   * otherwise the handle of the client for which
   * this request is made.
   */
  struct GNUNET_ClientHandle *response_client;

  /**
   * Last time we tried to get a response for this
   * query from the DHT (will always be zero for
   * anonymous requests).
   */
  GNUNET_CronTime last_dht_get;

  /**
   * How long should we wait before re-trying the
   * DHT-get operation?
   */
  GNUNET_CronTime dht_back_off;

  /**
   * When does this query record expire? (0 for never).
   */
  GNUNET_CronTime expiration;

  /**
   * When did we last issue this request? (0 for never).
   */
  GNUNET_CronTime last_request_time;

  /**
   * Size of the bloomfilter (in bytes); must be a power of 2.
   */
  unsigned int bloomfilter_size;

  /**
   * Number of entries in the bloomfilter (used to tell when
   * we should grow its size).
   */
  unsigned int bloomfilter_entry_count;

  /**
   * Mutator used for the bloom filter.
   */
  int bloomfilter_mutator;

  /**
   * Desired level of (receiver) anonymity.
   */
  unsigned int anonymityLevel;

  /**
   * Number of queries at the end of this struct.
   */
  unsigned int key_count;

  /**
   * Type of the expected response.
   */
  unsigned int type;

  /**
   * If there is no peer that is suspected to have the result,
   * the PID_INDEX will be zero.
   */
  PID_INDEX primary_target;

  /**
   * Where to send a response (if we get one).
   * Maybe zero (if we are the peer that cares).
   */
  PID_INDEX response_target;

  /**
   * (Relative) TTL used in the last request.
   */
  int last_ttl_used;

  /**
   * Priority used for the last request.
   */
  unsigned int last_prio_used;

  /**
   * Total value of the request (the priority
   * that we accepted for the inbound query).
   */
  unsigned int value;

  /**
   * Total offered value of the request (how much
   * trust we will earn from the other peer).
   */
  unsigned int value_offered;

  /**
   * Remaining value of the request (invalid
   * if response_client == NULL).
   */
  unsigned int remaining_value;

  /**
   * What is the chance that we have more results
   * locally for this request?  Set to a positive
   * number if we think we have more results,
   * decremented by one each time we fail to find
   * more results; set to zero if we are sure
   * that we have no more results.
   */
  unsigned int have_more;

  /**
   * Routing policy for the request (foward, indirect).
   */
  enum GNUNET_FS_RoutingPolicy policy;

  /**
   * The queries of this request.  At least one,
   * if there are more, the key count field will say
   * so.
   */
  GNUNET_HashCode queries[1];

};

/**
 * Doubly-linked list of the queries to consider for
 * a peer.  All QueryPlanEntries are ALSO part of a
 * simple linked list starting at the respective
 * RequestList.
 */
struct QueryPlanEntry
{

  /**
   * This is a doubly-linked list.
   */
  struct QueryPlanEntry *next;

  /**
   * This is a doubly-linked list.
   */
  struct QueryPlanEntry *prev;

  /**
   * Query plan that this entry belongs to.
   */
  struct QueryPlanList *list;

  /**
   * Details about the request in the plan.
   */
  struct RequestList *request;

  /**
   * Other query plan entires for the same
   * request (those entries will be part of
   * other query plan lists).
   */
  struct QueryPlanEntry *plan_entries_next;

  /**
   * Request priority that should be used.
   */
  unsigned int prio;

  /**
   * Request TTL that should be used.
   */
  int ttl;

};


/**
 * Linked list of queries to consider for each peer.
 */
struct QueryPlanList
{

  /**
   * This is a linked list.
   */
  struct QueryPlanList *next;

  /**
   * Head of the doubly-linked list of queries to consider.
   */
  struct QueryPlanEntry *head;

  /**
   * Tail of the doubly-linked list of queries to consider.
   */
  struct QueryPlanEntry *tail;

  /**
   * For which peer is this the current plan?
   */
  PID_INDEX peer;

};

/**
 * Lock used to synchronize access to
 * all shared datastructures.
 */
extern struct GNUNET_Mutex *GNUNET_FS_lock;


/**
 * Free the request list, including the associated
 * list of pending requests, its entries in the
 * plans for various peers and known responses.
 */
void GNUNET_FS_SHARED_free_request_list (struct RequestList *rl);

/**
 * Check if the given value is a valid
 * and new response for the given request list
 * entry.
 *
 * @param hc set to the hash of the data if successful
 * @return GNUNET_OK if so, GNUNET_NO if not new or not
 *         applicable, GNUNET_SYSERR on error
 */
int
GNUNET_FS_SHARED_test_valid_new_response (struct RequestList *rl,
                                          const GNUNET_HashCode * primary_key,
                                          unsigned int size,
                                          const GNUNET_EC_DBlock * data,
                                          GNUNET_HashCode * hc);

/**
 * Mark the response corresponding to the given
 * hash code as seen (update linked list and bloom filter).
 */
void
GNUNET_FS_SHARED_mark_response_seen (struct RequestList *rl,
                                     const GNUNET_HashCode * hc);

/**
 * If the data portion and type of the value match our value in the
 * closure, copy the header (priority, anonymity_level, expiration_time) and
 * abort the iteration: we found what we're looing for.  Otherwise
 * continue.
 */
int
GNUNET_FS_HELPER_complete_value_from_database_callback (const GNUNET_HashCode
                                                        * key,
                                                        const
                                                        GNUNET_DatastoreValue
                                                        * value,
                                                        void *closure,
                                                        unsigned long long
                                                        uid);


/**
 * Mingle hash with the mingle_number to
 * produce different bits.  We use this
 * to generate many different bloomfilters
 * for the same data.
 */
void
GNUNET_FS_HELPER_mingle_hash (const GNUNET_HashCode * in,
                              int mingle_number, GNUNET_HashCode * hc);

/**
 * The priority level imposes a bound on the maximum
 * value for the ttl that can be requested.
 *
 * @param ttl_in requested ttl
 * @param priority given priority
 * @return ttl_in if ttl_in is below the limit,
 *         otherwise the ttl-limit for the given priority
 */
int GNUNET_FS_HELPER_bound_ttl (int ttl_in, unsigned int prio);


/**
 * Send a response to a local client.
 *
 * @param request used to check if the response is new and
 *        unique, maybe NULL (skip test in that case)
 * @param hc set to hash of the message by this function
 *
 * @return GNUNET_OK on success,
 *         GNUNET_NO on temporary failure,
 *         GNUNET_SYSERR on serious error
 */
int
GNUNET_FS_HELPER_send_to_client (GNUNET_CoreAPIForPlugins * coreAPI,
                                 const GNUNET_HashCode * key,
                                 const GNUNET_DatastoreValue * value,
                                 struct GNUNET_ClientHandle *client,
                                 struct RequestList *request,
                                 GNUNET_HashCode * hc);


#endif
