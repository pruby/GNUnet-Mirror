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
 * @author Christian Grothoff
 * @author Igor Wronsky
 * @file applications/afs/module/high_simple_helper.h
 *
 * This file specifies subroutines for a pidx database.
 */

#ifndef HIGH_SIMPLE_HELPER_H
#define HIGH_SIMPLE_HELPER_H

#include "gnunet_util.h"

/**
 * Handle for a pidx-level database.
 */
typedef struct {
  char * dir;
  Mutex lock;
} pidx_struct;

typedef pidx_struct * PIDX;

/**
 * Initialize the storage module.
 * @param dir the name of the directory/file
 *        containing the content database
 */
PIDX pidxInitContentDatabase(char * dir);

/**
 * Remove the pidx database.
 */
void pidxDeleteContentDatabase(PIDX handle);


/**
 * Clean shutdown of the storage module.
 */
void pidxDoneContentDatabase(PIDX handle);

/**
 * Free space in the database by removing an entry.
 *
 * @param fn the key of the entry to remove
 * @return SYSERR on error, OK if ok.
 */
int pidxUnlinkFromDB(PIDX handle, 
		     unsigned int priority);
 
/**
 * Read the contents of a bucket to a buffer.
 *
 * @param priority the priority to look for
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of HashCodes read on success, SYSERR on failure
 */ 
int pidxReadContent(PIDX handle,
		    unsigned int priority,
		    HashCode160 ** result);


/**
 * Read the contents of a bucket to a buffer.
 *
 * @param fn the hashcode representing the entry
 * @param result the buffer to write the result to 
 * @return OK on success, SYSERR on failure
 */ 
int pidxReadRandomContent(PIDX dbh,
			  unsigned int name,
			  HashCode160 * result);


/**
 * Truncate last blocks of a file.
 *
 * @param fn the key for the entry
 * @param len the number of block to keep
 * @return SYSERR on error, OK if ok.
 */
int pidxTruncateAt(PIDX handle,
		   unsigned int name,
		   unsigned int len);

/**
 * Append content to file.
 *
 * @param fn the key for the entry
 * @param len the number of blocks
 * @param blocks the data to store
 * @return SYSERR on error, OK if ok.
 */
int pidxAppendContent(PIDX handle,
		      unsigned int name,
		      unsigned int len,
		      const HashCode160 * blocks);

/**
 * Write content to a file.  Overrides existing entry.
 *
 * @param fn the key for the entry
 * @param len the number of blopcks
 * @param blocks the data to store
 * @return SYSERR on error, OK if ok.
 */
int pidxWriteContent(PIDX handle,
		     unsigned int priority,
		     unsigned int len,
		     HashCode160 * blocks);

#endif

/* end of high_simple_helper.h */
