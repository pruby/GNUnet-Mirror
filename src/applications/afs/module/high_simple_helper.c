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
 * @file applications/afs/module/high_simple_helper.c
 * @brief Directory based implementation of priority indexed keys
 * @author Christian Grothoff
 */

#include "high_simple_helper.h"
#include "platform.h"

#define PIDX_DEBUG 0

#define DIR_EXT ".pidx"



/**
 * Initialize the Directory module, expand filename
 * @param dir the directory where content is 
 *  configured to be stored (e.g. ~/.gnunet/data/content).
 * @return the full path to the DB file
 */
static char * getDirectory(char * dir) {
  char * result;
  char * tmp;
  size_t n;

#if PIDX_DEBUG
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

/**
 * @param dir the directory where content is 
 *  configured to be stored (e.g. ~/.gnunet/data/content).
 * @return handle to the database
 */
PIDX pidxInitContentDatabase(char * dir) {
  PIDX idx;

  idx = MALLOC(sizeof(pidx_struct));
  idx->dir = getDirectory(dir);  
  if (idx->dir == NULL) 
    DIE_FILE_STRERROR("getDirectory", idx->dir);
  mkdirp(idx->dir);
  MUTEX_CREATE_RECURSIVE(&idx->lock);
  return idx;
}

/**
 * Remove the pidx database.
 *
 * @param handle handle to the databaes
 */
void pidxDeleteContentDatabase(PIDX handle) {
  if (OK != rm_minus_rf(handle->dir))
    LOG_FILE_STRERROR(LOG_ERROR, "rm -rf", handle->dir);
  FREE(handle->dir);
  MUTEX_DESTROY(&handle->lock);
  FREE(handle);
}

/**
 * Clean shutdown of the storage module (not used at the moment)
 *
 * @param handle handle to the databaes
 */
void pidxDoneContentDatabase(PIDX handle) {
  FREE(handle->dir);
  MUTEX_DESTROY(&handle->lock);
  FREE(handle);
}

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param dbh handle to the databaes
 * @param name the priority of the entry
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of HashCodes read on success, -1 on failure
 */ 
int pidxReadContent(PIDX dbh,
		    unsigned int name,
		    HashCode160 ** result) {
  /* open file, must exist, open read only */
  int fd;
  int size;
  char * fil;
  size_t fsize;
  size_t n;

  if (result == NULL)
    return -1;
  n = strlen(dbh->dir) + 20;
  fil = MALLOC(n);
  SNPRINTF(fil, 
	   n,
	   "%s/%u", 
	   dbh->dir, 
	   name);
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
  if ( (fsize / sizeof(HashCode160)) * sizeof(HashCode160) != fsize) {
    LOG(LOG_WARNING,
	_("pidx database corrupt (file has bad length), trying to fix.\n"));
    fsize = (fsize / sizeof(HashCode160)) * sizeof(HashCode160);
    ftruncate(fd, 
	      fsize);
  }

  *result = MALLOC(fsize);
  size = READ(fd, 
	      *result, 
	      fsize);
  MUTEX_UNLOCK(&dbh->lock);
  CLOSE(fd);
  if ((size_t)size != fsize) {
    FREE(*result);
    *result = NULL;
    return -1;
  }
  return size / sizeof(HashCode160);
}

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param dbh handle to the database
 * @param name the priority of the entry
 * @param result the buffer to write the result to 
 * @return OK on success, SYSERR on failure
 */ 
int pidxReadRandomContent(PIDX dbh,
			  unsigned int name,
			  HashCode160 * result) {
  /* open file, must exist, open read only */
  int fd;
  int size;
  char * fil;
  size_t fsize;
  size_t n;

  if (result == NULL)
    return -1;
  n = strlen(dbh->dir) + 20;
  fil = MALLOC(n);
  SNPRINTF(fil, 
	   n,
	   "%s/%u", 
	   dbh->dir, 
	   name);
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
  if ( (fsize / sizeof(HashCode160)) * sizeof(HashCode160) != fsize) {
    LOG(LOG_WARNING,
	_("pidx database corrupt (file has bad length), trying to fix.\n"));
    fsize = (fsize / sizeof(HashCode160)) * sizeof(HashCode160);
    ftruncate(fd, 
	      fsize);
  }
  fsize = fsize / sizeof(HashCode160);
  if (fsize <= 0) {
    CLOSE(fd);
    MUTEX_UNLOCK(&dbh->lock);
    return -1;
  }
  fsize = randomi(fsize);
  lseek(fd, 
	fsize * sizeof(HashCode160),
	SEEK_SET);
  size = READ(fd, 
	      result, 
	      sizeof(HashCode160));
  MUTEX_UNLOCK(&dbh->lock);
  CLOSE(fd);
  if (size != sizeof(HashCode160)) 
    return SYSERR;
  else
    return OK;
}


/**
 * Append content to file.
 *
 * @param handle handle to the database
 * @param name the priority of the entry
 * @param len the number of blopcks
 * @param blocks the data to store
 * @return SYSERR on error, OK if ok.
 */
int pidxAppendContent(PIDX handle,
		      unsigned int name,
		      unsigned int len,
		      const HashCode160 * blocks) {
  char * fil;
  int fd;
  off_t offlen;
  size_t n;

  n = strlen(handle->dir) + 20;
  fil = MALLOC(n);
  SNPRINTF(fil,
	   n,
	   "%s/%u", 
	   handle->dir, 
	   name);
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
  if ( (off_t)((offlen / sizeof(HashCode160)) * sizeof(HashCode160)) != offlen) {
    LOG(LOG_WARNING,
	_("pidx database corrupt (file has bad length), trying to fix.\n"));
    offlen = (offlen / sizeof(HashCode160)) * sizeof(HashCode160);
    lseek(fd, 
	  offlen, 
	  SEEK_SET);
    if (0 != ftruncate(fd, 
		       offlen))
      LOG_FILE_STRERROR(LOG_FAILURE, "ftruncate", fil);
  }
  FREE(fil);
  
  WRITE(fd, 
	blocks, 
	len*sizeof(HashCode160));
  CLOSE(fd);
  MUTEX_UNLOCK(&handle->lock);
  return OK;
}

/**
 * Truncate file at a certain length.
 *
 * @param handle handle to the database
 * @param name the priority of the entry
 * @param len the number of blocks to keep
 * @return SYSERR on error, OK if ok.
 */
int pidxTruncateAt(PIDX handle,
		   unsigned int name,
		   unsigned int len) {
  char * fil;
  int fd;
  int ret;
  size_t n;

  n = strlen(handle->dir) + 20;
  fil = MALLOC(n);
  SNPRINTF(fil,
	   n,
	   "%s/%u", 
	   handle->dir, 
	   name);
  MUTEX_LOCK(&handle->lock);
  fd = OPEN(fil,
	    O_RDWR|O_CREAT,
	    S_IRUSR|S_IWUSR);
  if (fd == -1) {
    MUTEX_UNLOCK(&handle->lock);
    LOG_FILE_STRERROR(LOG_WARNING, "open", fil);
    FREE(fil);
    return SYSERR; /* failed! */
  }
  ret = ftruncate(fd, 
		  len*sizeof(HashCode160));
  CLOSE(fd);
  MUTEX_UNLOCK(&handle->lock);
  if (ret == 0) {
    FREE(fil);
    return OK;
  } else {
    LOG_FILE_STRERROR(LOG_ERROR, "ftruncate", fil);
    FREE(fil);
    return SYSERR;
  }
}

/**
 * Write content to a file. 
 *
 * @param handle handle to the database
 * @param name the priority of the entry
 * @param len the number of blopcks
 * @param blocks the data to store
 * @return SYSERR on error, OK if ok.
 */
int pidxWriteContent(PIDX handle,
		     unsigned int name,
		     unsigned int len,
		     HashCode160 * blocks) {
  char * fil;
  int fd;
  int ret;
  size_t n;

  n = strlen(handle->dir) + 20;
  fil = MALLOC(n);
  SNPRINTF(fil,
	   n,
	   "%s/%u", 
	   handle->dir, 
	   name);
  MUTEX_LOCK(&handle->lock);
  truncate(fil, 0);
  fd = OPEN(fil,
	    O_RDWR|O_CREAT,
	    S_IRUSR|S_IWUSR);
  if (fd == -1) {
    MUTEX_UNLOCK(&handle->lock);
    LOG_FILE_STRERROR(LOG_WARNING, "open", fil);
    FREE(fil);
    return SYSERR; /* failed! */
  }
  ret = WRITE(fd, 
	      blocks, 
	      len * sizeof(HashCode160));
  if ((unsigned int)ret != len * sizeof(HashCode160)) {
    MUTEX_UNLOCK(&handle->lock);
    LOG_FILE_STRERROR(LOG_FAILURE, "write", fil);
    CLOSE(fd);
    truncate(fil, 0);
    FREE(fil);
    return SYSERR;
  }
  FREE(fil);
  CLOSE(fd);
  MUTEX_UNLOCK(&handle->lock);
  return OK;
}

/**
 * Free space in the database by removing one file
 *
 * @param handle handle to the database
 * @param priority the priority of the entry
 * @return OK on success, SYSERR on error
 */
int pidxUnlinkFromDB(PIDX handle,
		     unsigned int priority) {
  char * fil;
  size_t n;

  n = strlen(handle->dir) + 20;
  fil = MALLOC(n);
  SNPRINTF(fil, 
	   n,
	   "%s/%u",
	   handle->dir, 
	   priority);
  MUTEX_LOCK(&handle->lock);
  UNLINK(fil);
  MUTEX_UNLOCK(&handle->lock);
  FREE(fil);
  return OK;
}



/* end of high_simple_helper.c */
