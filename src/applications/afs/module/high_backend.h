/*
     This file is part of GNUnet
     (C) 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/high_backend.h
 * @brief A header specifying the interfaces that each (high-level) database
 *        backend (gdbm, tdb, mysql, etc.) must provide.
 * @author Igor Wronsky
 * @author Christian Grothoff
 */
#ifndef DATABASE_LIBRARY_H
#define DATABASE_LIBRARY_H

#include "gnunet_afs_esed2.h"

#define CONTENTDIR "content/"

/**
 * Handle for a high-level database (mysql, simple)
 */
typedef void * HighDBHandle;

/**
 * Callback function type used by the iterator.  Contains the key,
 * index information, the block (NULL if there is no block in the
 * database), the length of the block and the closure.
 *
 * The callback is responsible for freeing data if data is not NULL.
 *
 * Note that the callback function may not perform additional
 * read, write or delete operations on the database!
 */ 
typedef void (*EntryCallback)(const HashCode160 * key,
			      const ContentIndex * ce,
			      void * data,
			      unsigned int dataLen,
			      void * closure);


/**
 * Open the database.
 * @param i number used to distinguish
 *  multiple backends of the same type.
 * @param n parameter for naming the database configuration (e.g. quota)
 *
 * @return the database handle
 */
HighDBHandle initContentDatabase(unsigned int i,
				 unsigned int n);

/**
 * Close the database.
 */ 
void doneContentDatabase(HighDBHandle handle);

/**
 * Call a method for each key in the database and
 * call the callback method on it.
 * 
 * @param callback the callback method
 * @param data second argument to all callback calls
 * @return the number of items stored in the content database
 */
int forEachEntryInDatabase(HighDBHandle handle,
                           EntryCallback callback,
                           void * data);

/**
 * Get the number of entries in the database.
 * @return SYSERR on error, otherwise the number of entries
 */
int countContentEntries(HighDBHandle handle);

/**
 * Read the contents of a block to a buffer. 
 *
 * @param handle the database handle
 * @param query the query hash (3HASH o CHK)
 * @param ce what to look for (will be modified on return)
 * @param result the buffer to write the result to
 *        (*result should be NULL, sufficient space is allocated;
 *         if the content is on-demand encoded, *result==NULL on return)
 * @param prio the amount to change priority of the entry if its found
 * @return the number of bytes read on success, -1 on failure
 */
int readContent(HighDBHandle handle,
		const HashCode160 * query,
                ContentIndex * ce,
                void ** result,
		int prio);

/**
 * Write content to the db.  Overwrites existing data.
 * If ce->type is LOOKUP_TYPE_3HASH, ce->hash will contain
 * a double hash which must be converted to 3HASH, later to be 
 * retrievable by 3HASH, but the 2HASH must be stored so it can
 * be retrieved by readContent(). For indexed content,
 * ce->fileOffset and ce->fileNameIndex must be stored.
 * Note that block can be NULL for on-demand encoded content
 * (in this case, len must also be 0).
 *
 * @param handle the database handle
 * @param ce the meta-data for the entry
 * @param len the size of the block
 * @param block the data to store
 * @return SYSERR on error, OK on success
 */
int writeContent(HighDBHandle handle,
                 const ContentIndex * ce,
                 unsigned int len,
                 const void * block);

/**
 * Free space in the database by removing an entry.
 *
 * @param name the query of the entry to remove
 * @return SYSERR on error, OK if ok.
 */
int unlinkFromDB(HighDBHandle handle,
                 const HashCode160 * query);

/**
 * Return a random key from the database (and data too,
 * if _not_ ondemand!)
 *
 * @param ce output information about the key
 * @return SYSERR on error, OK if ok.
 */
int getRandomContent(HighDBHandle handle,
                     ContentIndex * ce,
		     CONTENT_Block ** data);

/**
 * Delete low-priority content from the database
 *
 * @param count the number of 1kb blocks to free
 * @param callback method to call on each deleted item
 */
int deleteContent(HighDBHandle handle,
                  unsigned int count,
		  EntryCallback callback,
		  void * closure);

/**
 * Get the lowest priority of content in the store.
 */
unsigned int getMinimumPriority(HighDBHandle handle);

/**
 * Estimate how many blocks can be stored in the DB
 * before the quota is reached.
 *
 * @quota the number of kb available for the DB
 */ 
int estimateAvailableBlocks(HighDBHandle handle,
			    unsigned int quota);


/**
 * Remove the database (entirely!). Also implicitly
 * calls "doneContentDatabase".
 */
void deleteDatabase(HighDBHandle handle);


#endif

/* end of high_backend.h */
