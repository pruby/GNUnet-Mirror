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
 * @file include/gnunet_gap_service.h
 * @brief API to the GAP-module.  This API is what will be used by
 *     GAP clients that run as modules within gnunetd.  If you
 *     are writing a client look at either gnunet_gap.h (if you
 *     want to handle the communication with gnunetd yourself) or
 *     at gnunet_gap_lib to use the convenience library.
 * @author Christian Grothoff
 */

#ifndef GAP_SERVICE_API_H
#define GAP_SERVICE_API_H

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_blockstore.h"

/**
 * Functions of the GAP Service API.
 */
typedef struct {

  /**
   * Start GAP.  
   *
   * @param datastore the storage callbacks to use for storing data
   * @return SYSERR on error, OK on success
   */
  int (*init)(Blockstore * datastore);
  
  /**
   * Perform a GET operation using 'key' as the key.  Note that no
   * callback is given for the results since GAP just calls PUT on the
   * datastore on anything that is received, and the caller will be
   * listening for these puts.
   *
   * @param type the type of the block that we're looking for
   * @param keys the keys to query for
   * @param timeout how long to wait until this operation should
   *        automatically time-out
   * @return OK if we will start to query, SYSERR if all of our
   *  buffers are full or other error
   */
  int (*get_start)(unsigned int type,
		   unsigned int anonymityLevel,
		   unsigned int keyCount,
		   const HashCode160 * keys,
		   cron_t timeout,
		   unsigned int prio);

  /**
   * Stop sending out queries for a given key.  GAP will automatically
   * stop sending queries at some point, but this method can be used
   * to stop it earlier.
   */
  int (*get_stop)(unsigned int type,
		  unsigned int keyCount,
		  const HashCode160 * keys);

  /**
   * Try to migrate the given content.
   *
   * @param data the content to migrate
   * @param position where to write the message
   * @param padding the maximum size that the message may be
   * @return the number of bytes written to
   *   that buffer (must be a positive number).
   */
  unsigned int (*tryMigrate)(const DataContainer * data,
			     unsigned int type,
			     const HashCode160 * primaryKey,
			     char * position,
			     unsigned int padding);
    
} GAP_ServiceAPI;

#endif /* GAP_SERVICE_API_H */
