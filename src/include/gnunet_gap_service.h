/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 *     GAP clients that run as modules within gnunetd.  GAP is
 *     currently not supposed to be used directly by clients,
 *     look at the gnunet_fs_lib.h for the lowest-level client API.
 * @author Christian Grothoff
 */

#ifndef GAP_SERVICE_API_H
#define GAP_SERVICE_API_H

#include "gnunet_core.h"
#include "gnunet_blockstore.h"


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Estimated size of most blocks transported with
 * the GAP protocol.  32k DBlocks plus overhead.
 */
#define GNUNET_GAP_ESTIMATED_DATA_SIZE (33*1024)

/**
 * Function that helps the routing code to find out if
 * a given reply is the one and only reply for a given
 * request.
 * @param verify check that content is valid? (GNUNET_YES/GNUNET_NO)
 */
typedef int (*GNUNET_UniqueReplyIdentifierCallback) (const
                                                     GNUNET_DataContainer *
                                                     content,
                                                     unsigned int query_type,
                                                     int verify,
                                                     const GNUNET_HashCode *
                                                     primaryKey);

/**
 * Given some content, compute the unique
 * GNUNET_hash of the content that can then be used
 * to sort out duplicates.
 */
typedef int (*GNUNET_ReplyHashingCallback) (const GNUNET_DataContainer * data,
                                            GNUNET_HashCode * hc);

/**
 * Functions of the GAP Service API.
 */
typedef struct
{

  /**
   * Start GAP.
   *
   * @param datastore the storage callbacks to use for storing data
   * @return GNUNET_SYSERR on error, GNUNET_OK on success
   */
  int (*init) (GNUNET_Blockstore * datastore,
               GNUNET_UniqueReplyIdentifierCallback uri,
               GNUNET_ReplyHashingCallback rhf);

  /**
   * Perform a GET operation using 'key' as the key.  Note that no
   * callback is given for the results since GAP just calls PUT on the
   * datastore on anything that is received, and the caller will be
   * listening for these puts.
   *
   * @param target peer to ask primarily (maybe NULL)
   * @param type the type of the block that we're looking for
   * @param keys the keys to query for
   * @param timeout how long to wait until this operation should
   *        automatically time-out
   * @return GNUNET_OK if we will start to query, GNUNET_SYSERR if all of our
   *  buffers are full or other error
   */
  int (*get_start) (const GNUNET_PeerIdentity * target,
                    unsigned int type,
                    unsigned int anonymityLevel,
                    unsigned int keyCount,
                    const GNUNET_HashCode * keys,
                    GNUNET_CronTime timeout, unsigned int prio);

  /**
   * Stop sending out queries for a given key.  GAP will automatically
   * stop sending queries at some point, but this method can be used
   * to stop it earlier.
   */
  int (*get_stop) (unsigned int type,
                   unsigned int keyCount, const GNUNET_HashCode * keys);

  /**
   * Try to migrate the given content.
   *
   * @param data the content to migrate
   * @param position where to write the message
   * @param padding the maximum size that the message may be
   * @return the number of bytes written to
   *   that buffer (must be a positive number).
   */
  unsigned int (*tryMigrate) (const GNUNET_DataContainer * data,
                              const GNUNET_HashCode * primaryKey,
                              char *position, unsigned int padding);

  /**
   * What is the average priority of requests that we
   * are currently routing?
   */
  unsigned int (*getAvgPriority) (void);

} GNUNET_GAP_ServiceAPI;


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif /* GAP_SERVICE_API_H */
