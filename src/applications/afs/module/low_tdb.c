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
 * @file applications/afs/module/low_tdb.c
 * @brief tdb based implementation of low database API
 *
 * @author Christian Grothoff
 * @author Uli Luckas
 * @author Igor Wronsky
 */

#include "low_backend.h"
#include "platform.h"
#include <tdb.h>


#define TDB_DEBUG 0

#define GIGA_BYTE (1024 * 1024 * 1024)

/**
 * Extension for the TDB database.
 */
#define TDB_EXT ".tdb"

/**
 * After how-many insert operations test
 * DB size?
 */
#define TEST_FREQUENCY 1024

/**
 * @brief tdb wrapper
 */ 
typedef struct {
  TDB_CONTEXT * dbf;
  unsigned char * filename;
  int insertCount;
  int deleteSize;  
  Mutex DATABASE_Lock_;
} tdbHandle;


/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_TDB(cmd, dbh) do { errexit(_("'%s' failed on file '%s' at %s:%d with error: %s\n"), cmd,  dbh->filename, __FILE__, __LINE__,tdb_errorstr(dbh->dbf)); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_TDB(level, cmd, dbh) do { LOG(level, _("'%s' failed on file '%s' at %s:%d with error: %s\n"), cmd,  dbh->filename, __FILE__, __LINE__, tdb_errorstr(dbh->dbf)); } while(0);


/**
 * Open a tdb database (for content)
 * @param dir the directory where content is configured 
 * to be stored (e.g. data/content). A file called ${dir}.dbf is used instead
 */
static tdbHandle * getDatabase(const char * dir) {
  char * ff;
  tdbHandle * dbh;
 
  int fnSize = strlen(dir) + strlen(TDB_EXT) + 1;

#if TDB_DEBUG  
  LOG(LOG_DEBUG,
      "Database: '%s' (TDB)\n", 
      dir);
#endif
  dbh = MALLOC(sizeof(tdbHandle));
  ff = MALLOC(fnSize);
  strcpy(ff, dir);
  if (ff[strlen(ff)-1] == DIR_SEPARATOR)
    ff[strlen(ff) - 1] = 0; /* eat the '/' at the end */
  else
    ff[strlen(ff)] = 0; /* no '/' to eat */
  strcat(ff, TDB_EXT);
  dbh->filename = expandFileName(ff);
 
  dbh->dbf = tdb_open(dbh->filename, 0, TDB_NOMMAP, O_RDWR | O_CREAT, S_IRUSR|S_IWUSR);
  if (NULL == dbh->dbf) 
    DIE_TDB("tdb_open", dbh);

  FREE(ff);
  dbh->insertCount = TEST_FREQUENCY; 
  dbh->deleteSize = 0;
  return dbh;
}

void * lowInitContentDatabase(const char * dir) {
  tdbHandle * dbh;
  
  dbh = getDatabase(dir);
  MUTEX_CREATE_RECURSIVE(&dbh->DATABASE_Lock_);	

  return dbh;
}

/**
 * Delete the TDB database.
 *
 * @param handle the database
 */
void lowDeleteContentDatabase(void * handle) {
  tdbHandle * dbh = handle;

  MUTEX_DESTROY(&dbh->DATABASE_Lock_);
  tdb_close(dbh->dbf);
  if (0 != REMOVE(dbh->filename))
    LOG_FILE_STRERROR(LOG_ERROR, "remove", dbh->filename);
  FREE(dbh->filename);
  FREE(dbh);
}

/**
 * Normal shutdown of the storage module
 *
 * @param handle the database
 */
void lowDoneContentDatabase(void * handle) {
  tdbHandle * dbh = handle;

  MUTEX_DESTROY(&dbh->DATABASE_Lock_);
  tdb_close(dbh->dbf);
  FREE(dbh->filename);
  FREE(dbh);
}


/**
 * Call a method for each key in the database and
 * call the callback method on it. 
 *
 * @param handle the database
 * @param callback the callback method
 * @param data second argument to all callback calls
 * @return the number of items stored in the content database
 */
int lowForEachEntryInDatabase(void * handle,
			      LowEntryCallback callback,
			      void * data) {
  tdbHandle * dbh = handle;
  TDB_DATA prevkey, key;
  HashCode160 doubleHash;
  int count;

  count = 0;
  /* scan database data/content.dbf and add entries to database 
     if not already present */
  key = tdb_firstkey(dbh->dbf);
  while (key.dptr) {
    if (strlen(key.dptr) == sizeof(HashCode160)*2) {	
      if (callback != NULL) {
	  hex2hash((HexName*)key.dptr,
   	    &doubleHash);
  	  callback(&doubleHash, 
		   data);
      }
      count++; /* one more file */
    }
    prevkey = key;
    key = tdb_nextkey(dbh->dbf, prevkey);
    free(prevkey.dptr);
  }
  return count;
}

#define COUNTENTRY "count_token"

/**
 * @param handle the database
 * @param count number to store
 */
static void storeCount(void * handle,
		       int count) {
  tdbHandle * dbh = handle;
  TDB_DATA key;
  TDB_DATA buffer;

  key.dptr = COUNTENTRY;
  key.dsize = strlen(COUNTENTRY)+1;
  buffer.dptr = (char*)&count;
  buffer.dsize = sizeof(int);
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  if (0 != tdb_store(dbh->dbf, key, buffer, TDB_REPLACE)) 
    LOG_TDB(LOG_WARNING, "tdb_store", dbh);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
}

/**
 * Get the number of entries in the database.
 *
 * @param handle the database
 * @return number of entries
 */
int lowCountContentEntries(void * handle) {
  tdbHandle * dbh = handle;
  TDB_DATA key;
  TDB_DATA buffer;
  int count;

  key.dptr = COUNTENTRY;
  key.dsize = strlen(COUNTENTRY)+1;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  buffer = tdb_fetch(dbh->dbf, key);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  if ( (!buffer.dptr) || 
       (buffer.dsize != sizeof(int)) ) {
    count = lowForEachEntryInDatabase(dbh, NULL, NULL);  
    storeCount(dbh, count);
  } else {
    count = *(int*) buffer.dptr;
    free(buffer.dptr);
  }
  return count;
}

/**
 * Read the contents of a bucket to a buffer.
 *
 * @param handle the database
 * @param name the hashcode representing the entry
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of bytes read on success, -1 on failure
 */ 
int lowReadContent(void * handle,
		   const HashCode160 * name,
		   void ** result) {
  tdbHandle * dbh = handle;
  HexName fn;
  TDB_DATA key, buffer;

  hash2hex(name, &fn);  
  key.dptr = fn.data;
  key.dsize = strlen(key.dptr) + 1;

  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  buffer = tdb_fetch(dbh->dbf, key);
  MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  if (!buffer.dptr) 
    return -1;
  *result = MALLOC(buffer.dsize);
  memcpy(*result,
	 buffer.dptr,
	 buffer.dsize);
  free(buffer.dptr);
  return buffer.dsize;  
}

/**
 * Write content to a file. Check for reduncancy and eventually
 * append.
 *
 * @param handle the database
 * @param name the key for the entry
 * @param len the size of the block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int lowWriteContent(void * handle,
		    const HashCode160 * name, 
		    int len,
		    const void * block) {
  tdbHandle * dbh = handle;
  HexName fn;
  TDB_DATA buffer, key, old;
  int cnt;

  if (dbh->insertCount > 1024) {
    if (getFileSize(dbh->filename) > 
	(unsigned long long) 2 * GIGA_BYTE - 3 * TEST_FREQUENCY * len) {
      LOG(LOG_WARNING,
	  _("Single tdb database is limited to 2 GB, cannot store more data.\n"));
      return SYSERR; /* enforce TDB size limit of 2 GB minus 3*TF_len slack */
    }
    dbh->insertCount = 0;
  } else
    dbh->insertCount++;
  cnt = lowCountContentEntries(dbh);
  hash2hex(name, &fn);
  key.dptr = fn.data;
  key.dsize = strlen(key.dptr) + 1;
  buffer.dptr = (void*) block;
  buffer.dsize = len;
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  old = tdb_fetch(dbh->dbf, key);
  if ( (old.dsize > 0) ||
       (old.dptr != NULL) ) {
    cnt--;
    free(old.dptr);
  }
  if (0 !=  tdb_store(dbh->dbf, key, buffer, TDB_REPLACE)) {
    LOG_TDB(LOG_WARNING, "tdb_store", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
  } else {
    dbh->deleteSize -= len;
    if (dbh->deleteSize < 0)
      dbh->deleteSize = 0;
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    storeCount(dbh, cnt + 1);
  }
  return OK;
}

/**
 * Free space in the database by removing one file
 *
 * @param handle the database
 * @param name hashcode representing the name of the file (without directory)
 * @return OK on success, SYSERR on error
 */
int lowUnlinkFromDB(void * handle,
		    const HashCode160 * name) {
  tdbHandle * dbh = handle;
  TDB_DATA key, buffer;
  HexName fn;
  int cnt;

  hash2hex(name, &fn);
 
  key.dptr = fn.data;
  key.dsize = strlen(key.dptr) + 1;
  MUTEX_LOCK(&dbh->DATABASE_Lock_);
  cnt = lowCountContentEntries(dbh);
  buffer = tdb_fetch(dbh->dbf, key);
  if (0 == tdb_delete(dbh->dbf, key)) {
    dbh->deleteSize += buffer.dsize;
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    if (buffer.dptr != NULL)
      free(buffer.dptr);
    storeCount(dbh, cnt - 1);
    return OK;
  } else {
    LOG_TDB(LOG_WARNING, "tdb_delete", dbh);
    MUTEX_UNLOCK(&dbh->DATABASE_Lock_);
    return SYSERR;
  }
}

/**
 * Estimate the size of the database.
 *
 * @param handle the database
 * @return the number of kb that the DB is assumed to use at the moment.
 */
int lowEstimateSize(LowDBHandle handle) {
  tdbHandle * dbh = handle;

  return 
    ( (getFileSize(dbh->filename) * 120 / 100) -
      (dbh->deleteSize) +
      (sizeof(HashCode160) * lowCountContentEntries(handle))  
    ) / 1024; /* in kb */
}
 
/* end of low_tdb.c */
