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
 * @file include/gnunet_sqstore_service.h
 * @brief An SQ store is responsible for storing blocks with
 *   additional indices that allow traversing the store in
 *   order of expiration time or priority, in addition to
 *   queries by key and block type.  The name comes from SQL,
 *   because using an SQL database to do this should be
 *   particularly easy.  But that is of course not the only
 *   way to implement an sqstore.
 * @author Christian Grothoff
 */

#ifndef GNUNET_SQSTORE_SERVICE_H
#define GNUNET_SQSTORE_SERVICE_H

#include "gnunet_core.h"
#include "gnunet_datastore_service.h"

/**
 * @brief Definition of the SQ-Store API.
 */
typedef struct {

  /**
   * Get the current on-disk size of the SQ store.
   * Estimates are fine, if that's the only thing
   * available.
   * @return number of bytes used on disk
   */
  unsigned long long (*getSize)(void);

  /**
   * Store an item in the datastore.
   *
   * @return OK on success, SYSERR on error
   */
  int (*put)(const HashCode512 * key,
	     const Datastore_Value * value);

  /**
   * Iterate over the results for a particular key
   * in the datastore.
   *
   * @param key maybe NULL (to match all entries)
   * @param type entries of which type are relevant?
   *     Use 0 for any type.
   * @param iter maybe NULL (to just count)
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*get)(const HashCode512 * key,
	     unsigned int type,
	     Datum_Iterator iter,
	     void * closure);

  /**
   * Update the priority for a particular key in the datastore.  If
   * the expiration time in value is different than the time found in
   * the datastore, the higher value should be kept.  For the
   * anonymity level, the lower value is to be used.  The specified
   * priority should be added to the existing priority, ignoring the
   * priority in value.
   *
   * Note that it is possible for multiple values to match this put.
   * In that case, all of the respective values are updated.
   *
   * @param key never NULL
   * @param value the value to update (priority
   *     maybe different than in DB, only match
   *     on content and use other data as in DB!)
   * @param delta by how much should the priority
   *     change?  If priority + delta < 0 the
   *     priority should be set to 0 (never go
   *     negative).
   * @return OK if a match was found and the update
   *     was successful, SYSERR on error
   */
  int (*update)(const HashCode512 * key,
		const Datastore_Value * value,
		int delta);

  /**
   * Iterate over the items in the datastore in ascending
   * order of priority.
   *
   * @param type entries of which type should be considered?
   *        Use 0 for any type.
   * @param iter never NULL
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*iterateLowPriority)(unsigned int type,
			    Datum_Iterator iter,
			    void * closure);

  /**
   * Iterate over the items in the datastore in ascending
   * order of expiration time.
   *
   * @param type entries of which type should be considered?
   *        Use 0 for any type.
   * @param iter never NULL
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*iterateExpirationTime)(unsigned int type,
			       Datum_Iterator iter,
			       void * closure);

  /**
   * Delete an item from the datastore.
   *
   * Note that it is possible for multiple values to match this del
   * (even if a value is given).  In that case, only ONE of the
   * respective values is deleted, and it should be the one with an
   * expired expiration time or, if such an entry does not exist, the
   * lowest priority.  (This is done such that if multiple files
   * contain the same data, the data has multiple replicas and all are
   * kept, avoiding unavaialbility if just one of the files is
   * removed).
   *
   * @param value maybe NULL, then all items under the
   *        given key are deleted
   * @return the number of items deleted (if possible, the
   *        database should delete only ONE matching item and
   *        pick the one with the lowest priority [and then
   *        lowest expiration time]; if the DB cannot do that,
   *        deleting multiple entries will be 'tolerated' for now,
   *        but the result is a slightly worse performance of the
   *        peer; however, that there are multiple matches should
   *        also be rare).
   *        0 if no matching items were found, SYSERR on errors
   */
  int (*del)(const HashCode512 * key,
	     const Datastore_Value * value);

  /**
   * Delete the database.  The next operation is
   * guaranteed to be unloading of the module.
   */
  void (*drop)(void);
  
  /* *** Key/Value-Table support *** */
  
  /**
   * @brief Open a Key/Value-Table
   * @param table the name of the Key/Value-Table
   * @return a handle
   */
  KVHandle *(*kvGetTable)(const char *table);

  /**
   * @brief Get data from a Key/Value-Table
   * @param kv handle to the table
   * @param key the key to retrieve
   * @param keylen length of the key
   * @param sort 0 = dont, sort, 1 = random, 2 = sort by age
   * @param limit limit result set to n rows
   * @param handler callback function to be called for every result (may be NULL)
   * @param closure optional parameter for handler
   */
  void * (*kvGet)(KVHandle *kv, void *key, int keylen, unsigned int sort,
    unsigned int limit, KVCallback handler, void *closure);

  /**
   * @brief Store Key/Value-Pair in a table
   * @param kv handle to the table
   * @param key key of the pair
   * @param keylen length of the key (int because of SQLite!)
   * @param val value of the pair
   * @param vallen length of the value (int because of SQLite!)
   * @param optional creation time
   * @return OK on success, SYSERR otherwise
   */
  int (* kvPut)(KVHandle *kv, void *key, int keylen, void *val, int vallen,
    unsigned long long age);
  
  /**
   * @brief Delete values from a Key/Value-Table
   * @param key key to delete (may be NULL)
   * @param keylen length of the key
   * @param age age of the items to delete (may be 0)
   * @return OK on success, SYSERR otherwise
   */
  int (* kvDel)(KVHandle *kv, void *key, int keylen, unsigned long long age);
  
  /**
   * @brief Close a handle to a Key/Value-Table
   * @param kv the handle to close
   */
  void (* kvClose)(KVHandle *kv);

  /**
   * @brief Drop a Key/Value-Table
   * @param the handle to the table
   * @return OK on success, SYSERR otherwise
   */
  int (* kvDropTable)(KVHandle *kv);
} SQstore_ServiceAPI;


/* end of gnunet_sqstore_service.h */
#endif
