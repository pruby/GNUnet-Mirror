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
 * @file include/gnunet_dhtlog_service.h
 * @brief dhtlog is a service that implements logging of dht operations
 * for testing
 * @author Nathan Evans
 */

#ifndef GNUNET_DHTLOG_SERVICE_H
#define GNUNET_DHTLOG_SERVICE_H

#include "gnunet_core.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

typedef enum
{
  /**
   * No special options.
   */
  DHTLOG_GET = 1,

  /**
   * Encrypt the message so that only the
   * receiver can decrypt it.
   */
  DHTLOG_PUT = 2,

  /**
   * Hide the identity of the sender.
   */
  DHTLOG_RESULT = 3,
} DHTLOG_MESSAGE_TYPES;

typedef struct
{

  /*
   * Insert the result of a query into the database
   *
   * @param sqlqueryuid return value for the sql uid for this query
   * @param queryid gnunet internal query id (doesn't exist)
   * @param type the type of query (DHTLOG_GET, DHTLOG_PUT, DHTLOG_RESULT)
   * @param hops the hops the query has traveled
   * @param query is successful or not (GNUNET_YES or GNUNET_NO)
   * @param GNUNET_PeerIdentity of the node the query is at now
   * @param key the GNUNET_HashCode of this query
   *
   */
  int (*insert_query) (unsigned long long *sqlqueryuid,
                       unsigned long long queryid, DHTLOG_MESSAGE_TYPES type,
                       unsigned int hops, int succeeded,
                       const GNUNET_PeerIdentity * node,
                       const GNUNET_HashCode * key);

  /*
   * Inserts the trial information into the database
   */
  int (*insert_trial) (unsigned long long *trialuid, int num_nodes,
                       int topology, int puts, int gets, int concurrent,
                       int settle_time, int num_rounds, int malicious_getters,
                       int malicious_putters, int malicious_droppers,
                       char *message);

  /*
   * Update the trial information with the ending time and dropped message stats
   */
  int (*update_trial) (unsigned long long trialuid,
                       unsigned long long totalMessagesDropped,
                       unsigned long long totalBytesDropped);

  /*
   * Update the trial information with the total connections
   */
  int (*update_connections) (unsigned long long trialuid,
                             unsigned int totalConnections);

  /*
   * Insert the query information from a single hop into the database
   *
   * @param sqlqueryuid return value for the sql uid for this query
   * @param queryid gnunet internal query id (doesn't exist)
   * @param type the type of query (DHTLOG_GET, DHTLOG_PUT, DHTLOG_RESULT)
   * @param hops the hops the query has traveled
   * @param query is successful or not (GNUNET_YES or GNUNET_NO)
   * @param node GNUNET_PeerIdentity of the node the query is at now
   * @param key the GNUNET_HashCode of this query
   * @param from_node GNUNET_PeerIdentity of the node the query was
   *        received from (NULL if origin)
   * @param to_node GNUNET_PeerIdentity of the node this node will forward
   *        to (NULL if none)
   *
   */
  int (*insert_route) (unsigned long long *sqlqueryuid,
                       unsigned long long queryid,
                       unsigned int type, unsigned int hops,
                       unsigned int dvhops, int succeeded,
                       const GNUNET_PeerIdentity * node,
                       const GNUNET_HashCode * key,
                       const GNUNET_PeerIdentity * from_node,
                       const GNUNET_PeerIdentity * to_node);

  /*
   * Inserts the specified node into the dhttests.nodes table
   */
  int (*insert_node) (unsigned long long *nodeuid,
                      GNUNET_PeerIdentity * node);

  /*
   * Inserts a dhtkey into the database
   */
  int (*insert_dhtkey) (unsigned long long *dhtkeyuid,
                        const GNUNET_HashCode * dhtkey);

} GNUNET_dhtlog_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_dhtlog_service.h */
#endif
