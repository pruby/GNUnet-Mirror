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
 * @file include/gnunet_dht_service.h
 * @brief API to the DHT-module.  This API is what will be used by
 *     DHT clients that run as modules within gnunetd.  If you
 *     are writing a client look at either gnunet_dht.h (if you
 *     want to handle the communication with gnunetd yourself) or
 *     at gnunet_dht_lib to use the convenience library.
 * @author Christian Grothoff
 */

#ifndef GNUNET_DHT_SERVICE_H
#define GNUNET_DHT_SERVICE_H

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_dht.h"
#include "gnunet_blockstore.h"

struct DHT_GET_RECORD;

struct DHT_PUT_RECORD;

struct DHT_REMOVE_RECORD;

/**
 * DHT operation 'complete' (i.e timed out).
 */
typedef void (*DHT_OP_Complete)(void * closure);

/**
 * Functions of the DHT Service API.
 */
typedef struct {

  /**
   * Join a table (start storing data for the table).  Join
   * fails if the node is already joint with the particular
   * table.
   *
   * @param datastore the storage callbacks to use for the table
   * @param table the ID of the table
   * @param timeout how long to wait for other peers to respond to
   *   the join request (has no impact on success or failure)
   * @return SYSERR on error, OK on success
   */
  int (*join)(Blockstore * datastore,
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
   *   implies 'use value from gnunet.conf').
   * @return SYSERR on error, OK on success
   */
  int (*leave)(const DHT_TableId * table);


  /**
   * Perform an asynchronous GET operation on the DHT identified by
   * 'table' using 'key' as the key.  The peer does not have to be part
   * of the table (if so, we will attempt to locate a peer that is!)
   *
   * @param table table to use for the lookup
   * @param key the key to look up
   * @param timeout how long to wait until this operation should
   *        automatically time-out
   * @param callback function to call on each result
   * @param closure extra argument to callback
   * @return handle to stop the async get
   */
  struct DHT_GET_RECORD * (*get_start)(const DHT_TableId * table,
				       unsigned int type,
				       unsigned int keyCount,
				       const HashCode512 * keys,
				       cron_t timeout,
				       DataProcessor callback,
				       void * cls,
				       DHT_OP_Complete callbackComplete,
				       void * closure);

  /**
   * Stop async DHT-get.  Frees associated resources.
   */
  int (*get_stop)(struct DHT_GET_RECORD * record);

  /**
   * Perform an asynchronous PUT operation on the DHT identified by
   * 'table' storing a binding of 'key' to 'value'.  The peer does not
   * have to be part of the table (if so, we will attempt to locate a
   * peer that is!)
   *
   * @param table table to use for the lookup
   * @param key the key to look up
   * @param timeout how long to wait until this operation should
   *        automatically time-out
   * @param callback function to call on successful completion
   * @param closure extra argument to callback
   * @return handle to stop the async put
   */
  struct DHT_PUT_RECORD * (*put_start)(const DHT_TableId * table,
				       const HashCode512 * key,
				       cron_t timeout,
				       const DataContainer * value,
				       DHT_OP_Complete callback,
				       void * closure);

  /**
   * Stop async DHT-put.  Frees associated resources.
   */
  int (*put_stop)(struct DHT_PUT_RECORD * record);

  /**
   * Perform an asynchronous REMOVE operation on the DHT identified by
   * 'table' removing the binding of 'key' to 'value'.  The peer does not
   * have to be part of the table (if so, we will attempt to locate a
   * peer that is!)
   *
   * @param table table to use for the lookup
   * @param key the key to look up
   * @param timeout how long to wait until this operation should
   *        automatically time-out
   * @param callback function to call on successful completion
   * @param closure extra argument to callback
   * @return handle to stop the async remove
   */
  struct DHT_REMOVE_RECORD * (*remove_start)(const DHT_TableId * table,
					     const HashCode512 * key,
					     cron_t timeout,
					     const DataContainer * value,
					     DHT_OP_Complete callback,
					     void * closure);

  /**
   * Stop async DHT-remove.  Frees associated resources.
   */
  int (*remove_stop)(struct DHT_REMOVE_RECORD * record);

} DHT_ServiceAPI;

#endif /* DHT_SERVICE_API_H */
