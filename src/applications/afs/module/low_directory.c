/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/low_directory.c
 * @brief Block database (directory based implementation). 
 * @author Christian Grothoff
 */

#include "low_backend.h"
#include "platform.h"

#define DIRECTORY_DEBUG 0

#define DIR_EXT ".dir"

typedef struct {
  char * dir;
  int count;
  Mutex lock;
} DirHandle;

/**
 * Initialize the Directory module, expand filename
 * @param dir the directory where content is configured to be stored (e.g. ~/.gnunet/data/content).
 */
static char * getDirectory(const char * dir) {
  char * result;
  char * tmp;
  size_t n;

#if DIRECTORY_DEBUG
  LOG(LOG_INFO, 
      "Database '%s' (Directory)\n", 
      dir);
#endif
  n = strlen(dir) + strlen(DIR_EXT) + 5;
  tmp = MALLOC(n);
  SNPRINTF(tmp, n, "%s%s/", dir, DIR_EXT);
  result = expandFileName(tmp);
  FREE(tmp);
  return result;
}

#define HEX "0123456789ABCDEF"

typedef int (*ForAllSubdirCallback)(void * handle,
				    const char * subdir,
				    void * closure);

static int forAllSubdirs(void * handle,
			 ForAllSubdirCallback callback,
			 void * closure) {
  DirHandle * dbh = handle;
  char * subs;
  unsigned int i;
  unsigned int j;
  int l;
  int retSum = 0;

  l = strlen(dbh->dir);
  subs = MALLOC(l + 4);
  strcat(subs, dbh->dir);
  strcat(subs, "/");
  subs[l+3] = '\0';
  for (i=0;i<strlen(HEX);i++)
    for (j=0;j<strlen(HEX);j++) {
      subs[l+1] = HEX[i];
      subs[l+2] = HEX[j];
      retSum += callback(handle, subs, closure);
    }
  FREE(subs);
  return retSum;
}

static int mkdirpWrap(void * handle,
		      const char * dir,
		      void * unused) {
  mkdirp(dir);
  return 0;
}

void * lowInitContentDatabase(const char * dir) {
  DirHandle * dbh;

  dbh = MALLOC(sizeof(DirHandle));
  dbh->dir = getDirectory(dir);  
  MUTEX_CREATE_RECURSIVE(&dbh->lock);
  if (dbh->dir == NULL) 
    DIE_FILE_STRERROR("getDirectory", dir);
  mkdirp(dbh->dir);
  forAllSubdirs(dbh, &mkdirpWrap, NULL);
  dbh->count = lowForEachEntryInDatabase(dbh, 
					 NULL, 
					 NULL);
  return dbh;
}

/**
 * Clean shutdown of the storage module (not used at the moment)
 *
 * @param handle the directory
 */
void lowDoneContentDatabase(void * handle) {
  DirHandle * dbh = handle;
  MUTEX_DESTROY(&dbh->lock);
  FREE(dbh->dir);
  FREE(dbh);
}

typedef struct {
  char vals[sizeof(HexName)+1];
} DHexName;

static void hash2dhex(const HashCode160 * hc,
		      DHexName * dhex) {
  hash2hex(hc,
	   (HexName*)&dhex->vals[1]);
  dhex->vals[0] = dhex->vals[1];
  dhex->vals[1] = dhex->vals[2];
  dhex->vals[2] = DIR_SEPARATOR;
}

/*
static void dhex2hash(DHexName * dhex,
		      HashCode160 * hc) {
  HexName hn;

  memcpy(&((char*)&hn)[2],
	 &dhex->vals[3],
	 sizeof(HexName)-2);
  memcpy(&hn,
	 dhex,
	 2);
  hex2hash(&hn,
	   hc);
}
*/

/**
 * Remove the Content database.
 *
 * @param handle the directory
 */
void lowDeleteContentDatabase(void * handle) {
  DirHandle * dbh = handle;

  if (OK != rm_minus_rf(dbh->dir))
    LOG_FILE_STRERROR(LOG_ERROR, "rm_minus_rf", dbh->dir);
  MUTEX_DESTROY(&dbh->lock);
  FREE(dbh->dir);
  FREE(dbh);
}

typedef struct {
  LowEntryCallback callback;
  void * data;
} ForEachClosure;

static int forEachEntryInSubdir(void * handle,
				char * dir,
				ForEachClosure * cls) {
  DIR * dinfo;
  struct dirent *finfo;
  struct stat istat;
  int count;
  HashCode160 hash;
  HexName hex;

  /* last 2 characters in dir are first 2 characters
     in hex-name! */
  memcpy(&hex,
	 &dir[strlen(dir)-2],
	 2);
  STAT(dir, &istat);
  if (!S_ISDIR(istat.st_mode)) {   
    LOG(LOG_ERROR,
	_("Content database location '%s' is not a directory.\n"),
	dir);
    return -1;
  }
  errno = 0;
  dinfo = OPENDIR(dir);
  if ((errno == EACCES) || (dinfo == NULL)) {    
    LOG_FILE_STRERROR(LOG_ERROR, "opendir", dir);
    return -1;
  }
  count = 0;
  while ((finfo = readdir(dinfo)) != NULL)
    if (strlen(finfo->d_name) == sizeof(HashCode160)*2-2) {
      if (cls->callback != NULL) {
	memcpy(&((char*)&hex)[2],
	       finfo->d_name,
	       sizeof(HexName)-2);
	hex2hash(&hex,
		 &hash);
	cls->callback(&hash, cls->data);
      }
      count++;
    }

  closedir(dinfo);
  return count;
}

/**
 * Call a method for each entry in the database and call the callback
 * method on it.
 *
 * @param handle the directory
 * @param callback the function to call on each file
 * @param data extra argument to callback
 * @return the number of items stored in the content database
 */
int lowForEachEntryInDatabase(void * handle,
			      LowEntryCallback callback,
			      void * data) {
  ForEachClosure cls;
  DirHandle * dbh = handle;
  int ret;

  cls.callback = callback;
  cls.data = data;
  MUTEX_LOCK(&dbh->lock);
  ret = forAllSubdirs(handle,
		       (ForAllSubdirCallback)&forEachEntryInSubdir,
		       &cls);
  MUTEX_UNLOCK(&dbh->lock);
  return ret;
}

/**
 * How many entries are in the database?
 *
 * @param handle the directory
 * @return the number of entries, -1 on failure
 */ 
int lowCountContentEntries(void * handle) {
  DirHandle * dbh = handle;
  return dbh->count;
}

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param handle the directory
 * @param name the hashcode representing the entry
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of bytes read on success, -1 on failure
 */ 
int lowReadContent(void * handle,
		   const HashCode160 * name,
	           void ** result) {
  /* open file, must exist, open read only */
  DirHandle * dbh = handle;
  int fd;
  int size;
  DHexName fn;
  char * fil;
  size_t fsize;

  if ( (name == NULL) || 
       (result == NULL) )
    return -1;
  hash2dhex(name, &fn);
  fil = MALLOC(strlen(dbh->dir) + strlen((char*)&fn) + 1);
  strcpy(fil, dbh->dir);
  strcat(fil, &fn.vals[0]);
  MUTEX_LOCK(&dbh->lock);
  fd = OPEN(fil, O_RDONLY, S_IRUSR);
  if (fd == -1) {
    MUTEX_UNLOCK(&dbh->lock);
    FREE(fil);
    return -1;
  }
  fsize = getFileSize(fil);
  FREE(fil);
  *result = MALLOC(fsize);
  size = READ(fd, *result, fsize);
  CLOSE(fd);
  MUTEX_UNLOCK(&dbh->lock);
  if (size == -1) {
    FREE(*result);
    *result = NULL;
  }
  return size;
}


/**
 * Write content to a file. Check for reduncancy and eventually
 * append.
 *
 * @param handle the directory
 * @param name the key for the entry
 * @param len the size of the block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int lowWriteContent(void * handle,
		    const HashCode160 * name, 
		    int len,
		    const void * block) {
  DirHandle * dbh = handle;
  DHexName fn;
  char * fil;
  int fd;
  int unl;

  hash2dhex(name, &fn);
  fil = MALLOC(strlen(dbh->dir) + strlen((char*)&fn) + 1);
  strcpy(fil, dbh->dir);
  strcat(fil, &fn.vals[0]);
  MUTEX_LOCK(&dbh->lock);
  unl = UNLINK(fil);
  fd = OPEN(fil, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
  if (fd == -1) {
    LOG_FILE_STRERROR(LOG_WARNING, "open", fil);
    FREE(fil);
    MUTEX_UNLOCK(&dbh->lock);
    return SYSERR; /* failed! */
  }
  FREE(fil);
  WRITE(fd, block, len);
  if (unl != 0) /* file did not exist before */
    dbh->count++;
  CLOSE(fd);
  MUTEX_UNLOCK(&dbh->lock);
  return OK;
}

/**
 * Free space in the database by removing one file
 *
 * @param handle the directory
 * @param name the hashcode representing the name of the file 
 *        (without directory)
 * @return OK on success, SYSERR on error
 */
int lowUnlinkFromDB(void * handle,
		    const HashCode160 * name) {
  DirHandle * dbh = handle;
  DHexName fn;
  char * fil;

  if (name == NULL)
    return SYSERR;
  hash2dhex(name, &fn);
  fil = MALLOC(strlen(dbh->dir) + strlen((char*)&fn) + 1);
  strcpy(fil, dbh->dir);
  strcat(fil, &fn.vals[0]);
  MUTEX_LOCK(&dbh->lock);
  if (0 == UNLINK(fil)) {
    dbh->count--;
    MUTEX_UNLOCK(&dbh->lock);
    FREE(fil);
    return OK; 
  } else {
    LOG_FILE_STRERROR(LOG_WARNING, "unlink", fil);
    MUTEX_UNLOCK(&dbh->lock);
    FREE(fil);
    return SYSERR;
  }
}

/**
 * Estimate the size of the database.
 *
 * @param handle the directory
 * @return the number of kb that the DB is assumed to use at the moment.
 */
int lowEstimateSize(LowDBHandle handle) {
  return lowCountContentEntries(handle) * 5; /* 100 MB use 450 MB in GDBM according to EH */
}

/* end of low_directory.c */
