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
 * @file fs/gap/gap.h
 * @brief protocol that performs anonymous routing
 * @author Christian Grothoff
 */
#ifndef GAP_H
#define GAP_H

#include "gnunet_util.h"
#include "ecrs_core.h"

enum GNUNET_FS_RoutingPolicy
{
  GNUNET_FS_RoutingPolicy_ANSWER = 1,
  GNUNET_FS_RoutingPolicy_FORWARD = 2,
  GNUNET_FS_RoutingPolicy_INDIRECT = 4,
  GNUNET_FS_RoutingPolicy_ALL = 7
};

int GNUNET_FS_GAP_init (GNUNET_CoreAPIForPlugins * capi);

int GNUNET_FS_GAP_done (void);

/**
 * Execute a GAP query.  Determines where to forward
 * the query and when (and captures state for the response).
 * Also check the local datastore.
 *
 * @param respond_to where to send replies
 * @param priority how important is the request for us?
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
                             const void *bloomfilter_data);

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
                               unsigned int size,
                               const GNUNET_EC_DBlock * data);

/**
 * Compute the average priority of inbound requests
 * (rounded up).
 */
unsigned int GNUNET_FS_GAP_get_average_priority (void);

#endif
