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
 * @file include/gnunet_fs_lib.h
 * @brief convenience methods to access the FS application from clients
 * @author Christian Grothoff
 *
 * User interfaces should NOT use this library directly, look
 * first into the ECRS and FSUI libraries, they are higher level
 * and probably more suitable for writing UI code.
 */

#ifndef GNUNET_FS_LIB_H
#define GNUNET_FS_LIB_H

#include "gnunet_util.h"
#include "gnunet_util_network_client.h"
#include "gnunet_datastore_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


struct GNUNET_FS_SearchContext;

struct GNUNET_FS_SearchContext *GNUNET_FS_create_search_context (struct
                                                                 GNUNET_GE_Context
                                                                 *ectx,
                                                                 struct
                                                                 GNUNET_GC_Configuration
                                                                 *cfg,
                                                                 struct
                                                                 GNUNET_Mutex
                                                                 *lock);

void GNUNET_FS_destroy_search_context (struct GNUNET_FS_SearchContext *ctx);

struct GNUNET_FS_SearchHandle;

/**
 * Search for blocks matching the given key and type.
 *
 * @param target identity of host known to have the
 *        content, NULL if no such identity is known
 * @param timeout how long to search
 * @param anonymityLevel what are the anonymity
 *        requirements for this request? 0 for no
 *        anonymity (DHT/direct transfer ok)
 * @param callback method to call for each result
 * @param prio priority to use for the search
 */
struct GNUNET_FS_SearchHandle *GNUNET_FS_start_search (struct
                                                       GNUNET_FS_SearchContext
                                                       *ctx,
                                                       const
                                                       GNUNET_PeerIdentity *
                                                       target,
                                                       unsigned int type,
                                                       unsigned int keyCount,
                                                       const GNUNET_HashCode *
                                                       keys,
                                                       unsigned int
                                                       anonymityLevel,
                                                       unsigned int prio,
                                                       GNUNET_CronTime
                                                       timeout,
                                                       GNUNET_DatastoreValueIterator
                                                       callback,
                                                       void *closure);

/**
 * Stop searching.
 */
void GNUNET_FS_stop_search (struct GNUNET_FS_SearchContext *ctx,
                            struct GNUNET_FS_SearchHandle *handle);

/**
 * What is the current average priority of entries
 * in the routing table like?  Returns -1 on error.
 */
int GNUNET_FS_get_current_average_priority (struct
                                            GNUNET_ClientServerConnection
                                            *sock);

/**
 * Insert a block.  Note that while the API is VERY similar to
 * GNUNET_FS_index in terms of signature, the block for GNUNET_FS_index must be in
 * plaintext, whereas the block passed to GNUNET_FS_insert must be encrypted!
 *
 * @param block the block (properly encoded and all)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 * @see ecrs_core.h::GNUNET_EC_file_block_encode
 */
int GNUNET_FS_insert (struct GNUNET_ClientServerConnection *sock,
                      const GNUNET_DatastoreValue * block);


/**
 * Initialize to index a file.  Tries to do the symlinking.
 */
int GNUNET_FS_prepare_to_index (struct GNUNET_ClientServerConnection *sock,
                                const GNUNET_HashCode * fileHc,
                                const char *fn);

/**
 * Index a block.  Note that while the API is VERY similar to
 * GNUNET_FS_insert in terms of signature, the block for GNUNET_FS_index must be in
 * plaintext, whereas the block passed to GNUNET_FS_insert must be encrypted!
 *
 * @param fileHc the GNUNET_hash of the entire file
 * @param block the data from the file (in plaintext)
 * @param offset the offset of the block into the file
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_FS_index (struct GNUNET_ClientServerConnection *sock,
                     const GNUNET_HashCode * fileHc,
                     const GNUNET_DatastoreValue * block,
                     unsigned long long offset);

/**
 * Delete a block.  The arguments are the same as the ones for
 * GNUNET_FS_insert.
 *
 * @param block the block (properly encoded and all)
 * @return number of items deleted on success,
 *    GNUNET_SYSERR on error
 */
int GNUNET_FS_delete (struct GNUNET_ClientServerConnection *sock,
                      const GNUNET_DatastoreValue * block);

/**
 * Unindex a file.
 *
 * @param hc the GNUNET_hash of the entire file
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_FS_unindex (struct GNUNET_ClientServerConnection *sock,
                       unsigned int blocksize, const GNUNET_HashCode * hc);

/**
 * Test if a file of the given GNUNET_hash is indexed.
 *
 * @param hc the GNUNET_hash of the entire file
 * @return GNUNET_YES if so, GNUNET_NO if not, GNUNET_SYSERR on error
 */
int GNUNET_FS_test_indexed (struct GNUNET_ClientServerConnection *sock,
                            const GNUNET_HashCode * hc);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
