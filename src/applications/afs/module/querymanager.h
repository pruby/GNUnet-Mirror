/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * The query manager is responsible for queueing queries
 *
 * @author Christian Grothoff
 * @file applications/afs/module/querymanager.h
 **/

#ifndef QUERYMANAGER_H
#define QUERYMANAGER_H

#include "afs.h"

/**
 * Initialize the query management.
 **/
int initQueryManager();

/**
 * Shutdown query management.
 **/
void doneQueryManager();

/**
 * Take a query and forward it to the appropriate
 * number of nodes (depending on load, queue, etc).
 *
 * @param origin where did the query come from?
 * @param client where did the query come from? (if it was a client)
 **/
void forwardQuery(AFS_p2p_QUERY * msg,
		  const PeerIdentity * origin,
		  const ClientHandle client);

/**
 * Stop transmitting a certain query (we don't route it anymore or
 * we have learned the answer).
 */
void dequeueQuery(const HashCode160 * query);

/**
 * We received a reply from 'responder' to a query
 * received from 'origin' (or 'localOrigin').  Update
 * reply track data!
 * @param origin only valid if localOrigin == NULL
 * @param localOrigin origin if query was initiated by local client
 * @param responder peer that send the reply
 */
void updateResponseData(const PeerIdentity * origin,
			ClientHandle localOrigin,
			const PeerIdentity * responder);
 
#endif
