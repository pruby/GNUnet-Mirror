/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/policy.c
 * @brief resource allocation (storage space, routing) implementation 
 * @author Christian Grothoff
 */

#include "policy.h"


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
			   unsigned int priority) {
  int netLoad = getNetworkLoadUp();

  if (netLoad < IDLE_LOAD_THRESHOLD)
    return 0 /* minimum priority, no charge! */ |
      QUERY_ANSWER | QUERY_FORWARD | QUERY_INDIRECT;
  /* charge! */
  priority = - coreAPI->changeTrust(sender, -priority);
  if (priority > QUERY_PRIORITY_BITMASK)
    priority = QUERY_PRIORITY_BITMASK;
  if ((unsigned int)netLoad < IDLE_LOAD_THRESHOLD + priority)
    return priority | QUERY_ANSWER | QUERY_FORWARD | QUERY_INDIRECT;
  else if ((unsigned int)netLoad < 90 + 10 * priority)
    return priority | QUERY_ANSWER | QUERY_FORWARD;
  else if ((unsigned int)netLoad < 100)
    return priority | QUERY_ANSWER;
  else
    return 0; /* drop entirely */
}

/**
 * Some content dropped by. We may want to store it locally, or not.
 * The policy adjusts the priority and returns the effective
 * importance for the content.
 *
 * @param hc the query
 * @param priority of the query
 * @return SYSERR if the content should not be replicated,
 *   otherwise the new priority for the lookup database
 */
int evaluateContent(const HashCode160 * hc,
		    int priority) {
  int distance;
  int j;
  
  distance = distanceHashCode160(hc,
				 &coreAPI->myIdentity->hashPubKey);
  /* compute 'log' of distance */
  j = 16;
  while (distance > 0) {
    distance = distance>>1;
    j--;
  }
  if (j < 0)
    return SYSERR;
  else
    return priority * j;
}


/* end of policy.c */

