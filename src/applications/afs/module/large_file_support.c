/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/large_file_support.c 
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
 *
 * TODO: replace use of HEX with use of ENC.  That'd be easy, but
 * also a converter must be added to gnunet-check that updates the
 * database.
 */

#include "large_file_support.h"

#define LFS_DEBUG 0

#define DIR_EXT ".lfs"

/**
 * Initialize the Directory module, expand filename
 * @param dir the directory where content is configured to be stored (e.g. ~/.gnunet/data/content).
 */
static char * getDirectory(const char * dir) {
  char * result;
  char * tmp;
  size_t n;

#if LFS_DEBUG
  LOG(LOG_INFO, 
      "Database (Directory): %s\n", 
      dir);
#endif
  n = strlen(dir) + strlen(DIR_EXT) + 5;
  tmp = MALLOC(n);
  SNPRINTF(tmp, n, "%s%s", dir, DIR_EXT);
  result = expandFileName(tmp);
  FREE(tmp);
  return result;
}

LFS lfsInit(char * dir) {
  LFS idx;

  idx = MALLOC(sizeof(lfs_struct));
  idx->dir = getDirectory(dir);  
  if (idx->dir == NULL) 
    errexit(_("Could not open directory '%s'!\n"),
	    idx->dir);
  mkdirp(idx->dir);
  MUTEX_CREATE_RECURSIVE(&idx->lock);
  return idx;
}

/**
 * Remove the lfs database.
 * @param handle the database
 */
void lfsDelete(LFS handle) {
  if (OK != rm_minus_rf(handle->dir))
    LOG(LOG_ERROR,
	_("lfs: could not remove entry '%s': %s\n"),
	handle->dir,
	STRERROR(errno));
  FREE(handle->dir);
  MUTEX_DESTROY(&handle->lock);
  FREE(handle);
}

/**
 * Clean shutdown of the storage module
 * @param handle the database
 */
void lfsDone(LFS handle) {
  FREE(handle->dir);
  MUTEX_DESTROY(&handle->lock);
  FREE(handle);
}

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param dbh handle to the database
 * @param query the hashcode representing the entry
 * @param blocks the buffer to write the result to 
 *        (*blocks should be NULL, sufficient space is allocated)
 * @return the number of blocks read on success, -1 on failure
 */ 
int lfsRead(LFS dbh,
	    const HashCode160 * query,
	    CONTENT_Block ** blocks) {
  /* open file, must exist, open read only */
  int fd;
  int size;
  char * fil;
  size_t fsize;
  HexName name;
  size_t n;

  if (blocks == NULL)
    return -1;
  n = strlen(dbh->dir) + 45;
  fil = MALLOC(n);
  hash2hex(query,
	   &name);
  SNPRINTF(fil, 
	   n,
	   "%s/%s", 
	   dbh->dir, 
	   (char*)&name);
  MUTEX_LOCK(&dbh->lock);
  fd = OPEN(fil, 
	    O_RDONLY,
	    S_IRUSR);
  if (fd == -1) {
    MUTEX_UNLOCK(&dbh->lock);
    FREE(fil);
    return -1;
  }
  fsize = getFileSize(fil);
  FREE(fil);
  if (fsize <= 0) {
    CLOSE(fd);
    MUTEX_UNLOCK(&dbh->lock);
    return -1;
  }
  if ( (fsize % sizeof(CONTENT_Block)) != 0) {
    LOG(LOG_WARNING,
	_("lfs database corrupt (file has bad length), trying to fix.\n"));
    fsize = (fsize / sizeof(CONTENT_Block)) * sizeof(CONTENT_Block);
    ftruncate(fd, 
	      fsize);
  }

  *blocks = MALLOC(fsize);
  size = READ(fd, 
	      *blocks, 
	      fsize);
  MUTEX_UNLOCK(&dbh->lock);
  CLOSE(fd);
  if ((size_t)size != fsize) {
    FREE(*blocks);
    *blocks = NULL;
    return -1;
  }
  return (int) (fsize / sizeof(CONTENT_Block));
}

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param dbh handle to the database 
 * @param query the hashcode representing the entry
 * @param block the buffer to write the result to 
 * @param prio the priority of the query (influences how many
 *        results we will return if we have the choice)
 * @return number of blocks read on success, SYSERR on failure
 */ 
int lfsReadRandom(LFS dbh,
		  const HashCode160 * query,
		  CONTENT_Block ** block,
		  unsigned int prio) {
  /* open file, must exist, open read only */
  int fd;
  int size;
  char * fil;
  size_t fsize;
  HexName name;
  int max;
  int * perm;
  int i;
  size_t n;

  max = (50-getNetworkLoadUp())*(prio+1);
  if (max <= 0)
    max = 1;
  if (block == NULL)
    return SYSERR;
  n = strlen(dbh->dir) + 45;
  fil = MALLOC(n);
  hash2hex(query,
	   &name);
  SNPRINTF(fil, 
	   n,
	   "%s/%s", 
	   dbh->dir, 
	   (char*) &name);
  MUTEX_LOCK(&dbh->lock);
  fd = OPEN(fil, 
	    O_RDONLY,
	    S_IRUSR);
  if (fd == -1) {
    MUTEX_UNLOCK(&dbh->lock);
    FREE(fil);
    return -1;
  }
  fsize = getFileSize(fil);
  FREE(fil);
  if (fsize <= 0) {
    CLOSE(fd);
    MUTEX_UNLOCK(&dbh->lock);
    return -1;
  }
  if ( (fsize % sizeof(CONTENT_Block)) != 0) {
    LOG(LOG_WARNING,
	_("lfs database corrupt (file has bad length), trying to fix.\n"));
    fsize = (fsize / sizeof(CONTENT_Block)) * sizeof(CONTENT_Block);
    ftruncate(fd, 
	      fsize);
  }
  fsize = fsize / sizeof(CONTENT_Block);
  if (fsize == 0)
    return SYSERR;
  if ((size_t)max > fsize)
    max = fsize;
  LOG(LOG_DEBUG,
      "received query, have %d results, adding %d to queue.\n",
      fsize,
      max);
  *block = MALLOC(max * sizeof(CONTENT_Block));
  perm = permute(fsize);
  for (i=0;i<max;i++) {
    lseek(fd, 
	  perm[i] * sizeof(CONTENT_Block), 
	  SEEK_SET);
    size = READ(fd, 
		&((*block)[i]), 
		sizeof(CONTENT_Block));
    if (size != sizeof(CONTENT_Block)) {
      FREE(perm);
      FREE(*block);
      *block = NULL;
      return SYSERR;
    }
  }
  FREE(perm);
  MUTEX_UNLOCK(&dbh->lock);
  CLOSE(fd);
  return max;
}

/**
 * Append content to file.
 *
 * @param handle the database
 * @param query the key for the entry
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int lfsAppend(LFS handle,
	      const HashCode160 * query,
	      const CONTENT_Block * block) {
  char * fil;
  int fd;
  off_t offlen;
  HexName name;
  size_t n;

  n = strlen(handle->dir) + 45;
  fil = MALLOC(n);
  hash2hex(query,
	   &name);
  SNPRINTF(fil,
	   n,
	   "%s/%s", 
	   handle->dir, 
	   (char*)&name);
  MUTEX_LOCK(&handle->lock);
  fd = OPEN(fil,
	    O_RDWR|O_CREAT,
	    S_IRUSR|S_IWUSR);
  if (fd == -1) {
    LOG_FILE_STRERROR(LOG_WARNING, "open", fil);
    MUTEX_UNLOCK(&handle->lock);
    FREE(fil);
    return SYSERR; /* failed! */
  }
  offlen = lseek(fd, 
		 0, 
		 SEEK_END);
  if (offlen == (off_t)-1) {
    LOG_FILE_STRERROR(LOG_FAILURE, "lseek", fil);
    FREE(fil);
    CLOSE(fd);
    MUTEX_UNLOCK(&handle->lock);
    return SYSERR;
  }
  if ( (offlen % sizeof(CONTENT_Block)) != 0) {
    LOG(LOG_WARNING,
	_("lfs database corrupt (file has bad length), trying to fix.\n"));
    offlen = (offlen / sizeof(CONTENT_Block)) * sizeof(CONTENT_Block);
    lseek(fd, 
	  offlen, 
	  SEEK_SET);
    if (0 != ftruncate(fd, 
		       offlen))
      LOG_FILE_STRERROR(LOG_FAILURE, "truncate", fil);
  }
  FREE(fil);  
  WRITE(fd, 
	block, 
	sizeof(CONTENT_Block));
  CLOSE(fd);
  MUTEX_UNLOCK(&handle->lock);
  return OK;
}

/**
 * Free space in the database by removing one file
 *
 * @param handle the database
 * @param query the hashcode representing the entry
 */
int lfsRemove(LFS handle,
	      const HashCode160 * query) {
  char * fil;
  HexName name;
  size_t n;

  n = strlen(handle->dir) + 45;
  fil = MALLOC(n);
  hash2hex(query,
	   &name);
  SNPRINTF(fil, 
	   n,
	   "%s/%s",
	   handle->dir, 
	   (char*)&name);
  MUTEX_LOCK(&handle->lock);
  UNLINK(fil);
  MUTEX_UNLOCK(&handle->lock);
  FREE(fil);
  return OK;
}



/* end of large_file_support.c */
