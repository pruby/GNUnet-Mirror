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
 * @file applications/afs/module/large_file_support.h
 * @brief Support for special handling of very large (3HASH) reply sets.
 * @author Christian Grothoff
 *
 * The databases (gdbm in particular, but also the others) do not
 * handle very large entries very well.  This is no problem for CHK,
 * but there can be several thousand (!)  results for a very popular
 * keyword, like a mime-type.  These 3HASH codes with more than
 * VERY_LARGE_SIZE (16) results are thus stored in separate files.
 *
 * The reason is, that gdbm would grow quadratic when the file is
 * build and that it would also be very slow: every read or write to
 * these very large content entries would require reading and writing
 * the *entire* 2 MB block (2 MB for 2,000 entries).  This API allows
 * a random access to one of the results and the use of "append" to
 * add a single entry.  It also does not suffer from the quadratic
 * explosion in space consumption that gdbm has.  So essentially, this
 * is a crapload of code that does not add any real functionality but
 * overcomes problems with the crude database implementations that we
 * would have to use otherwise (and that would be really bad for
 * performance without this).
 */


#ifndef LARGE_FILE_SUPPORT_H
#define LARGE_FILE_SUPPORT_H

#include "afs.h"

/**
 * Handle for a lfs-level database.
 */
typedef struct {
  char * dir;
  Mutex lock;
} lfs_struct;

typedef lfs_struct * LFS;

/**
 * Initialize the storage module.
 * @param dir the name of the directory/file
 *        containing the content database
 */
LFS lfsInit(char * dir);

/**
 * Remove the lfs database.
 */
void lfsDelete(LFS handle);

/**
 * Clean shutdown of the storage module.
 */
void lfsDone(LFS handle);

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of blocks read on success, SYSERR on failure
 */ 
int lfsRead(LFS handle,
	    const HashCode160 * query,
	    CONTENT_Block ** result);

/**
 * Read one random block from an entry
 *
 * @param result the buffer to write the result to
 * @return number of blocks read on success, SYSERR on failure
 */ 
int lfsReadRandom(LFS handle,
		  const HashCode160 * query,
		  CONTENT_Block ** result,
		  unsigned int prio);

/**
 * Truncate last blocks of a file.
 *
 * @param query the key for the entry
 * @param data what to append
 * @return SYSERR on error, OK if ok.
 */
int lfsAppend(LFS handle,
	      const HashCode160 * query,
	      const CONTENT_Block * data);

/**
 * Remove an entry.
 *
 * @param query the key for the entry
 * @return SYSERR on error, OK if ok.
 */
int lfsRemove(LFS handle,
	      const HashCode160 * query);

#endif

/* end of large_file_support.h */
