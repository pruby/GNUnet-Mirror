/*
     This file is part of GNUnet

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
 * Routing interface. This is the interface that does the routing.
 * @author Christian Grothoff
 * @file applications/afs/module/routing.h
 */

#ifndef ROUTING_H
#define ROUTING_H

#include "afs.h"
#include "policy.h"

/**
 * Initialize routing module.
 */
void initRouting();

/**
 * Shutdown the routing module.
 */
void doneRouting();

/**
 * Print the current routing table.
 */
void printRoutingTable();

/**
 * Execute the query. <p>
 *
 * Execute means to test if we can route the query (or, in the case
 * of a multi-query, any of the sub-queries). If yes, we lookup the
 * content locally and potentially route it deferred. Regardless if
 * the content was found or not, the queries that we can route are
 * forwarded to other peers (by the querymanager code).<p>
 *
 * The decision if we can route is made by "needsForwarding". Note that
 * queries that we are already routing do not "need forwarding". If
 * we do route the query, execQuery decides if we are going to do source
 * rewriting or not.<p>
 *
 * If we route a query, execSingleQuery will use the bloom filters and
 * the databases to locate the content and queue a cron job that will
 * pass the response to "useContent" as if it came from another peer.
 * Note that if the query originated from a local client, the response
 * is instant (no cron job scheduled).
 * 
 * @param qp the polciy (priority) for the query
 * @param msg the query message (with host identity for the reply)
 * @param sock the TCP socket to send the answer to if it is
 *        a query from the local host, otherwise NULL.
 */
int execQuery(QUERY_POLICY qp, 
	      AFS_p2p_QUERY * msg,
	      ClientHandle sock);

/**
 * Content has arrived. We must decide if we want to a) forward it to
 * our clients b) indirect it to other nodes. The routing module
 * should know what to do.
 *
 * @param sender who sent the message
 * @param queryHash the hashcode from the query
 * @param msg the p2p message we received, good for indirecting,
 *        must potentially be turned into the adequate CS message.
 * @return how good this content was (priority of the original 
 *        request)
 */
int useContent(const PeerIdentity * sender,
	       const HashCode160 * queryHash,
	       const p2p_HEADER * msg);

/**
 * Handle query for current average routing priority.
 */
int csHandleRequestAvgPriority(ClientHandle sock,
			       const p2p_HEADER * msg);



#endif
/* end of routing.h */
