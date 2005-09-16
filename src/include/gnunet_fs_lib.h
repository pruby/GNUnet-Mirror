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
#include "gnunet_datastore_service.h"

struct FS_SEARCH_CONTEXT;

struct FS_SEARCH_CONTEXT * FS_SEARCH_makeContext(Mutex * lock);

void FS_SEARCH_destroyContext(struct FS_SEARCH_CONTEXT * ctx);

struct FS_SEARCH_HANDLE;

/**
 * Search for blocks matching the given key and type.
 *
 * @param timeout how long to search
 * @param anonymityLevel what are the anonymity
 *        requirements for this request? 0 for no
 *        anonymity (DHT/direct transfer ok)
 * @param callback method to call for each result
 * @param prio priority to use for the search
 */
struct FS_SEARCH_HANDLE * FS_start_search(struct FS_SEARCH_CONTEXT * ctx,
					  unsigned int type,
					  unsigned int keyCount,
					  const HashCode512 * keys,
					  unsigned int anonymityLevel,
					  unsigned int prio,
					  cron_t timeout,
					  Datum_Iterator callback,
					  void * closure);

/**
 * Stop searching.
 */
void FS_stop_search(struct FS_SEARCH_CONTEXT * ctx,
		    struct FS_SEARCH_HANDLE * handle);

/**
 * What is the current average priority of entries
 * in the routing table like?  Returns -1 on error.
 */
int FS_getAveragePriority(GNUNET_TCP_SOCKET * sock);

/**
 * Insert a block.  Note that while the API is VERY similar to
 * FS_index in terms of signature, the block for FS_index must be in
 * plaintext, whereas the block passed to FS_insert must be encrypted!
 *
 * @param block the block (properly encoded and all)
 * @return OK on success, SYSERR on error
 * @see ecrs_core.h::fileBlockEncode
 */
int FS_insert(GNUNET_TCP_SOCKET * sock,
	      const Datastore_Value * block);


/**
 * Initialize to index a file.  Tries to do the symlinking.
 */
int FS_initIndex(GNUNET_TCP_SOCKET * sock,
		 const HashCode512 * fileHc,
		 const char * fn);

/**
 * Index a block.  Note that while the API is VERY similar to
 * FS_insert in terms of signature, the block for FS_index must be in
 * plaintext, whereas the block passed to FS_insert must be encrypted!
 *
 * @param fileHc the hash of the entire file
 * @param block the data from the file (in plaintext)
 * @param offset the offset of the block into the file
 * @return OK on success, SYSERR on error
 */
int FS_index(GNUNET_TCP_SOCKET * sock,
	     const HashCode512 * fileHc,	
	     const Datastore_Value * block,
	     unsigned long long offset);

/**
 * Delete a block.  The arguments are the same as the ones for
 * FS_insert.
 *
 * @param block the block (properly encoded and all)
 * @return number of items deleted on success,
 *    SYSERR on error
 */
int FS_delete(GNUNET_TCP_SOCKET * sock,
	      const Datastore_Value * block);

/**
 * Unindex a file.
 *
 * @param hc the hash of the entire file
 * @return OK on success, SYSERR on error
 */
int FS_unindex(GNUNET_TCP_SOCKET * sock,
	       unsigned int blocksize,
	       const HashCode512 * hc);

/**
 * Test if a file of the given hash is indexed.
 *
 * @param hc the hash of the entire file
 * @return YES if so, NO if not, SYSERR on error
 */
int FS_testIndexed(GNUNET_TCP_SOCKET * sock,
		   const HashCode512 * hc);

#endif
