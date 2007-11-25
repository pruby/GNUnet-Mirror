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
 * @file applications/fs/module/querymanager.h
 * @author Christian Grothoff
 * @brief code responsible for queueing queries
 */

#ifndef QUERYMANAGER_H
#define QUERYMANAGER_H

#include "gnunet_datastore_service.h"

/**
 * Initialize the query management.
 */
int initQueryManager (GNUNET_CoreAPIForPlugins * capi);

/**
 * Shutdown query management.
 */
void doneQueryManager (void);

/**
 * Keep track of a query.  If a matching response
 * shows up, transmit the response to the client.
 *
 * @param msg the query
 * @param client where did the query come from?
 */
void trackQuery (const GNUNET_HashCode * query,
                 unsigned int type, struct GNUNET_ClientHandle *client);

/**
 * Stop keeping track of a query.
 *
 * @param msg the query
 * @param client where did the query come from?
 */
void untrackQuery (const GNUNET_HashCode * query,
                   struct GNUNET_ClientHandle *client);

/**
 * We received a reply from 'responder'.
 * Forward to client (if appropriate).
 *
 * @param value the response
 */
void processResponse (const GNUNET_HashCode * key,
                      const GNUNET_DatastoreValue * value);

#endif
