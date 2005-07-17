/*
      This file is part of GNUnet
      (C) 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_dht_lib.h
 * @brief convenience API to the DHT infrastructure for use by clients
 * @author Christian Grothoff
 */

#ifndef GNUNET_DHT_LIB_H
#define GNUNET_DHT_LIB_H

#include "gnunet_blockstore.h"
#include "gnunet_dht_service.h"

/**
 * Initialize DHT_LIB. Call first.
 */
void DHT_LIB_init(void);

/**
 * Shutdown DHT_LIB. Call after leaving all tables!
 */
void DHT_LIB_done(void);

/**
 * Join a table (start storing data for the table).  Join
 * fails if the node is already joint with the particular
 * table.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @param timeout how long to wait for other peers to respond to
 *   the join request (has no impact on success or failure)
 * @param flags
 * @return SYSERR on error, OK on success
 */
int DHT_LIB_join(Blockstore * store,
		 const DHT_TableId * table);


/**
 * Leave a table (stop storing data for the table).  Leave
 * fails if the node is not joint with the table.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @param timeout how long to wait for other peers to respond to
 *   the leave request (has no impact on success or failure);
 *   but only timeout time is available for migrating data, so
 *   pick this value with caution.
 * @param flags maximum number of parallel puts for migration (0
 *   implies 'use value from gnunet.conf').
 * @return SYSERR on error, OK on success
 */
int DHT_LIB_leave(const DHT_TableId * table);


/**
 * Perform a synchronous GET operation on the DHT identified by
 * 'table' using 'key' as the key; store the result in 'result'.  If
 * result->dataLength == 0 the result size is unlimited and
 * result->data needs to be allocated; otherwise result->data refers
 * to dataLength bytes and the result is to be stored at that
 * location; dataLength is to be set to the actual size of the
 * result.
 *
 * The peer does not have to be part of the table!
 *
 * @param table table to use for the lookup
 * @param keys the keys to look up
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param resultCallback function to call for results
 * @return number of results on success, SYSERR on error (i.e. timeout)
 */
int DHT_LIB_get(const DHT_TableId * table,
		unsigned int type,
		unsigned int prio,
		unsigned int keyCount,
		const HashCode512 * keys,
		cron_t timeout,
		DataProcessor resultCallback,
		void * resCallbackClosure);
	
/**
 * Perform a synchronous put operation.   The peer does not have
 * to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to store
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param value what to store
 * @return OK on success, SYSERR on error (or timeout)
 */
int DHT_LIB_put(const DHT_TableId * table,
		const HashCode512 * key,
		unsigned int prio,
		cron_t timeout,
		const DataContainer * value);

/**
 * Perform a synchronous remove operation.  The peer does not have
 * to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to store
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param value what to remove; NULL for all values matching the key
 * @return OK on success, SYSERR on error (or timeout)
 */
int DHT_LIB_remove(const DHT_TableId * table,
		   const HashCode512 * key,
		   cron_t timeout,
		   const DataContainer * value);

#endif /* GNUNET_DHT_LIB_H */
