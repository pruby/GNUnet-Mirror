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
 * This module is responsible for content management (what to
 * keep, what to discard, content ageing, content migration).
 *
 * The manager.h header defines the external interface to the
 * GNUnet databases.  The manager code is responsible for
 * space management and on-demand encoding of blocks.  The
 * high-level database abstraction defined in high_backend.h
 * is responsible for lookup (3HASH and CHK) and block retrieval
 * (ContentEntries and inserted blocks). 
 * 
 * There are two implementations of the high_backend API,
 * the high_mysql.c implementation which provides all-in-one
 * over MySQL.
 *
 * Then there is the high_simple.c implementation which
 * provides an implementation of high_backend.h using the
 * low_backend.h API.  The low_backend.h API is close to 
 * the gdbm/tdb interfaces.  Thus high_simple.c can use
 * either of the low_XXXX implementations, in particular
 * low_gdbm, low_tdb and low_directory.
 * 
 * Here's the picture:
 *
 * manager.h
 * -> manager.c
 *    => high_backend.h
 *       -> high_mysql.c
 *       -> low_simple.c
 *          => low_backend.h
 *             -> low_gdbm.c
 *             -> low_tdb.c
 *             -> low_directory.c
 *
 * -> denotes "implements" and => denotes uses API defined in.
 * Multiple implementations are interchangable (+- performance)
 *
 * Note that manager binds to the implementation of high-backend
 * dynamically and that the 3 customizations of low_backend are
 * resulting in 3 statically linked "high" libraries (linking
 * the low_XXXX together with high_simple to database_XXXX).
 *
 * @file applications/afs/module/manager.h
 * @author Christian Grothoff
 * @author Igor Wronsky
 */

#ifndef AFS_MANAGER_H
#define AFS_MANAGER_H

#include "afs.h"
#include "high_backend.h"


/**
 * API for the "high-level" database libraries.
 * Equivalent to what is specified in high_backend.h.
 */
typedef struct {

  /** 
   * Open the high-level database.
   *
   * @return the database handle
   */
  HighDBHandle (*initContentDatabase)(unsigned int i,
				      unsigned int n);
  
  /** 
   * Close the lowlevel database
   * 
   * @param handle the database handle
  */
  void (*doneContentDatabase)(HighDBHandle handle);
  
  /**
   * Call a method for each key in the database and
   * call the callback method on it.
   * 
   * @param callback the callback method
   * @param data second argument to all callback calls
   * @return the number of items stored in the content database
   */
  int (*forEachEntryInDatabase)(HighDBHandle handle,
				EntryCallback callback,
				void * data);
  
  /**
   * Get the number of entries in the database.
   * @return SYSERR on error, otherwise the number of entries
   */
  int (*countContentEntries)(HighDBHandle handle);

  /**
   * Get the lowest priority of content in the DB.
   */
  unsigned int (*getMinimumPriority)(HighDBHandle handle);
  
  /**
   * Read the contents of a block to a buffer. In the case of 3HASH
   * query, readContent must also return the respective 2HASH in
   * ce->hash [so that hash(ce->hash)==3HASH].
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
  int (*readContent)(HighDBHandle handle,
		     const HashCode160 * query,
		     ContentIndex * ce,
		     void ** result,
		     int prio);
  
  /**
   * Write content to a file. Check for reduncancy and eventually
   * append.
   *
   * @param handle the database handle
   * @param ce information related to the block to store
   * @param len the size of the block
   * @param block the data to store
   * @return SYSERR on error, OK if ok.
   */
  int (*writeContent)(HighDBHandle handle,
		      const ContentIndex * ce,
		      int len,
		      const void * block);
  
  /**
   * Free space in the database by removing an entry.
   *
   * @param handle the handle to the database
   * @param fn the key of the entry to remove
   * @return SYSERR on error, OK if ok.
   */
  int (*unlinkFromDB)(HighDBHandle handle,
		      const HashCode160 * name);
  
  /** 
   * Return a random key from the database.
   *
   * @param handle the handle to the database
   * @param ce output information about the key 
   * @param data the data block, if not on-demand entry
   * @return SYSERR on error, OK if ok.
   */
  int (*getRandomContent)(HighDBHandle handle,
			  ContentIndex * ce,
			  CONTENT_Block ** data);
  
  /**
   * Delete low-priority content from the database
   *
   * @param handle the handle to the database
   * @param count the number of 1kb blocks to free
   */
  int (*deleteContent)(HighDBHandle handle,	
		       int count,
		       EntryCallback callback,
		       void * closure);

  /**
   * Estimate how many blocks can be stored in the DB
   * before the quota is reached.
   *
   * @param handle the handle to the database
   * @param quota the number of kb available for the DB
   */ 
  int (*estimateAvailableBlocks)(HighDBHandle handle,
				 int quota); 

  /**
   * Remove the database (entirely!). Also implicitly
   * calls "doneContentDatabase".
   *
   * @param handle the handle to the database
   */
  void (*deleteDatabase)(HighDBHandle handle);
  
  /** 
   * Handle of the database as returned by initContentDatabase()
   */
  HighDBHandle * dbHandles;

  /**
   * The number of buckets 
   *
   * [ (although technically "unsigned", using that causes funny 
   *   stuff in the code occasionally when arithmetic with signeds 
   *   is done... :( ( For example, check out what is 
   *   ((int)(-3))/((unsigned int)4). :( -Igor ) ]
   */
  unsigned int buckets;
  
  /**
   * The actual "lowlevel" database library used
   */
  void * dynamicLibrary;
 
  /**
   * cache estimated available blocks for each bucket
   */
  int * dbAvailableBlocks;
 
  
} DatabaseAPI;

/**
 * Initialize the manager module.
 */
void initManager();

/**
 * Shutdown the manager module.
 */
void doneManager();

/**
 * Load the high-level database as specified by
 * the given dtype.
 */
DatabaseAPI * initializeDatabaseAPI(const char * dtype);


/**
 * Store content (if the priority is high enough), potentially
 * discarding less important content. If this method is called
 * for indexed content, * data should be NULL and len==0 and
 * fields of ce filled properly. For 3HASH inserts, 2HASH must
 * be provided in ce->hash.
 * 
 * @param ce the content entry describing the content
 * @param len the length of the data in bytes
 * @param data the block itself
 * @param sender from where does the content come? NULL for
 *        from local client.
 * @param duplicate output param, will be YES if content was already there
 * @return OK if the block was stored, SYSERR if not
 */
int insertContent(ContentIndex * ce,
		  int len,
		  const void * data,
		  const PeerIdentity * sender,
		  int * duplicate);

/**
 * Locate content. This method locates the data matching the
 * query.  The data is on-demand encrypted if it is
 * indexed content or retrieved from the contentdatabase
 * if it was inserted content.  The ContentIndex entry is
 * filled with the appropriate values.
 *
 * @param query the CHK or the tripleHash key of the conten
 * @param ce the content entry describing what to look for
 * @param result where to write the result, space will be
 *        allocated by retrieveContent, *result should be
 *        NULL when this function is invoked.
 * @param prio the amount to modify the priority of the entry
 * @param isLocal is the request a local request? (YES/NO)
 * @return the length of the resulting content, SYSERR on error
 */
int retrieveContent(const HashCode160 * query,
		    ContentIndex * ce,
		    void ** result,
		    unsigned int prio,
		    int isLocal);

/**
 * Explicitly delete content.  This method is not currently used
 * (the manager discards data internally if we run out of space)
 * but it could be used by a "gnunet-remove" application in the
 * near future.
 * <p>
 *
 * Note that if multiple keywords correspond to the query, all are
 * removed. To selectively remove one keyword, use retrieveContent and
 * then insertContent if there are multiple results.
 * 
 * @param query the query that corresponds to the block to remove
 * @param bucket where to delete, <0 == autocompute
 */
int removeContent(const HashCode160 * query,
                  int bucket);

/**
 * Get some random contet.
 */
int retrieveRandomContent(ContentIndex * ce, 
			  CONTENT_Block ** data);

/**
 * Iterator over all the queries in the database
 * as needed by resizeBloomfilter.  
 *
 * The idea is to use this code in the startup
 * of the AFS module when the quota/memory limitations
 * have changed and the bloomfilter needs to be
 * resized. Note that the iterator is quite costly,
 * but we can assume that the user is not going to
 * change the configuration all the time :-).
 */
int databaseIterator(void * state,
		     HashCode160 * hc,
		     ContentIndex * ce,
		     int * bucket, 
		     void ** data,
		     int * datalen);

/**
 * Create the state required for a database iterator.
 */
void * makeDatabaseIteratorState();

/**
 * Compute the database bucket id (for gnunet-check) 
 */
unsigned int computeBucket(const HashCode160 * query,
                           unsigned int maxBuckets);

/**
 * Use this, if initManager() has been executed and 
 * the global dbAPI has the correct bucket count
 **/
unsigned int computeBucketGlobal(const HashCode160 * query);

int encodeOnDemand(const ContentIndex * ce,
                   CONTENT_Block ** result,
                   int readCount);				      

#endif
/* end of manager.h */

