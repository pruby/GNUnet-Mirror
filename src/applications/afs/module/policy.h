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
 * Policy interface. This is the interface to the C part of the policy.
 * @author Christian Grothoff
 * @file applications/afs/module/policy.h
 */

#ifndef AFS_POLICY_H
#define AFS_POLICY_H

#include "afs.h"

/** 
 * Type of the results of the polciy module 
 */
typedef unsigned int QUERY_POLICY;

/**
 * Send answer if local files match 
 */
#define QUERY_ANSWER   0x00020000

/**
 * Forward the query, priority is encoded in QUERY_PRIORITY_BITMASK 
 */
#define QUERY_FORWARD  0x00040000

/**
 * Indirect the query (use this as the originating node)
 */
#define QUERY_INDIRECT 0x00080000

/**
 * Drop the query if & with this bitmask is 0 
 */
#define QUERY_DROPMASK (QUERY_ANSWER|QUERY_FORWARD|QUERY_INDIRECT)

/**
 * Maximum priority to use (apply this bitmask to the QUERY_POLICY)
 */
#define QUERY_PRIORITY_BITMASK 0x0000FFFF

/**
 * Bandwidth value of an (effectively) 0-priority query.
 */
#define QUERY_BANDWIDTH_VALUE 0.01

/**
 * Bandwidth value of a 0-priority content (must be
 * fairly high compared to query since content is
 * typically significantly larger -- and more valueable
 * since it can take many queries to get one piece of
 * content).
 */
#define CONTENT_BANDWIDTH_VALUE 0.8

/**
 * Until which load do we consider the peer idle and do not 
 * charge at all?
 */
#define IDLE_LOAD_THRESHOLD 50


/**
 * A query has been received. The question is, if it should be forwarded
 * and if with which priority. Routing decisions(to whom) are to be taken elsewhere.
 * <p>
 *
 * @param sender the host sending us the query
 * @param priority the priority the query had when it came in, may be an arbitrary number if the 
 *        sender is malicious! Cap by trustlevel first!
 * @return binary encoding: QUERY_XXXX constants
 */
QUERY_POLICY evaluateQuery(const PeerIdentity * sender, 
			   unsigned int priority);



/**
 * Some content dropped by. We may want to store it locally, or not.
 * The policy adjusts the priority and returns the effective
 * importance for the content.
 *
 * @param hc the query 
 * @param priority of the original query
 * @return SYSERR if the content should be dropped, the
 *   priority for keeping it otherwise
 */
int evaluateContent(const HashCode160 * hc,
		    int priority);

#endif
/* end of policy.h */
