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
 * @file applications/afs/module/low_backend.h
 * @brief low-level database abstraction used by high_simple.c
 * @author Christian Grothoff
 * @author Igor Wronsky
 *
 * This file specifies subroutines that gdbm,tdb and directory
 * modules provide for db_simple.c, which is a higher level wrapper
 * implementing calls in high_backend.h. 
 */

#ifndef DB_SIMPLE_SUBROUTINES_H
#define DB_SIMPLE_SUBROUTINES_H

#include "gnunet_util.h"

/**
 * Handle for a low-level database (tdb, gdbm, directory).
 */
typedef void * LowDBHandle;

/**
 * @brief callback used to iterate over all entries of a low_backend database
 *
 * @param key the key of the entry
 * @param closure additional client specific argument
 */
typedef void (*LowEntryCallback)(const HashCode160 * key,
				 void * closure);


/**
 * Initialize the storage module.
 * @param dir the name of the directory/file
 *        containing the content database
 */
LowDBHandle lowInitContentDatabase(const char * dir);

/**
 * Delete the low content database.
 * @param handle the database
 */
void lowDeleteContentDatabase(LowDBHandle handle);

/**
 * Normal shutdown of the storage module.
 * @param handle the database
 */
void lowDoneContentDatabase(LowDBHandle handle);

/**
 * Free space in the database by removing an entry.
 *
 * @param handle the database
 * @param fn the key of the entry to remove
 * @return SYSERR on error, OK if ok.
 */
int lowUnlinkFromDB(LowDBHandle handle, 
                    const HashCode160 * fn);
 
/**
 * Get the number of entries in the database.
 * @return SYSERR on error, otherwise the number of entries
 */
int lowCountContentEntries(LowDBHandle handle);

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param handle the database
 * @param fn the hashcode representing the entry
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of bytes read on success, SYSERR on failure
 */ 
int lowReadContent(LowDBHandle handle,
		   const HashCode160 * fn,
		   void ** result);

/**
 * Write content to a file.  Overrides existing entry.
 *
 * @param handle the database
 * @param fn the key for the entry
 * @param len the size of the block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int lowWriteContent(LowDBHandle handle,
		    const HashCode160 * fn, 
		    int len,
		    const void * block);

/**
 * Call a method for each key in the database and
 * call the callback method on it. 
 *
 * @param handle the database
 * @param callback the callback method
 * @param data second argument to all callback calls
 * @return the number of items stored in the content database
 */
int lowForEachEntryInDatabase(LowDBHandle handle,
			      LowEntryCallback callback,
			      void * data);

/**
 * Estimate the size of the database on the drive.
 *
 * @param handle the database
 * @return the number of kb that the DB is assumed to use at the moment.
 */
int lowEstimateSize(LowDBHandle handle);
 
#endif

/* end of low_backend.h */
