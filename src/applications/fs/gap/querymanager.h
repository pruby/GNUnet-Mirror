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
 * @file fs/gap/querymanager.h
 * @brief management of queries from our clients
 * @author Christian Grothoff
 */
#ifndef QUERYMANAGER_H
#define QUERYMANAGER_H

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "ecrs_core.h"
#include "shared.h"

int GNUNET_FS_QUERYMANAGER_init (GNUNET_CoreAPIForPlugins * capi);

int GNUNET_FS_QUERYMANAGER_done (void);


/**
 * A client is asking us to run a query.  The query should be issued
 * until either a unique response has been obtained, the client
 * requests us to stop or until the client disconnects.
 *
 * @param target peer known to have the content, maybe NULL.
 * @param have_more do we have more results in our local datastore?
 */
void
GNUNET_FS_QUERYMANAGER_start_query (const GNUNET_HashCode * query,
                                    unsigned int key_count,
                                    unsigned int anonymityLevel,
                                    unsigned int type,
                                    struct GNUNET_ClientHandle *client,
                                    const GNUNET_PeerIdentity * target,
                                    const struct GNUNET_MultiHashMap *seen,
                                    int have_more);

/**
 * A client is asking us to stop running a query (without disconnect).
 */
int
GNUNET_FS_QUERYMANAGER_stop_query (const GNUNET_HashCode * query,
                                   unsigned int key_count,
                                   unsigned int anonymityLevel,
                                   unsigned int type,
                                   struct GNUNET_ClientHandle *client);

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
 * @param size size of the data
 * @param data the data itself (a GNUNET_EC_DBlock)
 * @return how much was this content worth to us?
 */
unsigned int
GNUNET_FS_QUERYMANAGER_handle_response (const GNUNET_PeerIdentity * sender,
                                        const GNUNET_HashCode * primary_query,
                                        GNUNET_CronTime expirationTime,
                                        unsigned int size,
                                        const GNUNET_EC_DBlock * data);


#endif
