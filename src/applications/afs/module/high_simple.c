/*
     This file is part of GNUnet.
     (C) 2003 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/high_simple.c
 * @param implementation of high_backend.h database API
 *        using the low_backend.h database API
 * @author Christian Grothoff
 * @author Igor Wronsky
 */

#include "gnunet_util.h"
#include "high_backend.h"
#include "low_backend.h"
#include "high_simple_helper.h"
#include "platform.h"

#define DEBUG_HIGH_SIMPLE NO

/**
 * @brief internal state of a high_simple database.
 */
typedef struct {

  /**
   * Low-level database handle for the DB
   * with the actual data (ContentEntry, content)
   */
  LowDBHandle dbfs;

  /**
   * Priority index.  Maps priorities to
   * data.
   */
  PIDX pIdx;

  /**
   * Smallest known priority in database.
   */
  unsigned int minPriority;

  /**
   * DB index.
   */
  int i;

  /**
   * Total number of databases.
   */
  int n;

  /**
   * Lock used to ensure pIdx and dbfs are consistent.
   */
  Mutex lock;

} DatabaseHandle;

/**
 * Initialize content database
 * 
 * @param i index of this specific database
 * @param n total number of databases used
 * @return handle to the opened database
 */
HighDBHandle initContentDatabase(unsigned int i,
				 unsigned int n) {
  DatabaseHandle * result;
  char * afsdir;
  char * dir;
  char * bucketname;
  char * dbtype;
  int * lastMinPriority;
  char statename[64];
  size_t nX;

  result = MALLOC(sizeof(DatabaseHandle));
  MUTEX_CREATE_RECURSIVE(&result->lock);
  result->i = i;
  result->n = n;
  SNPRINTF(statename,
	   64,
	   "AFS-MINPRIORITY%d%d",
	   i, n);
  lastMinPriority = NULL;
  if (sizeof(int) == stateReadContent(statename,
				      (void**) &lastMinPriority))
    result->minPriority = *lastMinPriority;
  else
    result->minPriority = 0;
  FREENONNULL(lastMinPriority);
  afsdir = getFileName("AFS",
		       "AFSDIR",
		       _("Configuration file must specify directory for storing AFS data"
			 " in section '%s' under '%s'.\n"));
  dir = MALLOC(strlen(afsdir)+
	       strlen(CONTENTDIR)+2);
  strcpy(dir, afsdir);
  strcat(dir, "/");
  strcat(dir, CONTENTDIR);
  FREE(afsdir);
  mkdirp(dir);
  dbtype = getConfigurationString("AFS",
				  "DATABASETYPE");
  nX = strlen(dir) + strlen("bucket") + 256 + strlen(dbtype);
  bucketname = MALLOC(nX);
  SNPRINTF(bucketname,
	   nX,
	   "%s/bucket.%u.%u", 
	   dir,
	   n,
	   i);
  result->dbfs = lowInitContentDatabase(bucketname);  
  SNPRINTF(bucketname,
	   nX,
	   "%s/pindex.%s.%u.%u",
	   dir,
	   dbtype,
	   n,
	   i);
  FREE(dbtype);
  result->pIdx = pidxInitContentDatabase(bucketname);
  FREE(bucketname);
  FREE(dir);
  return result;
}

/**
 * Shutdown of the storage module
 * 
 * @param handle handle to the DB that is shutdown
 */
void doneContentDatabase(HighDBHandle handle) {
  DatabaseHandle * dbf = handle;
  char statename[64];

  SNPRINTF(statename,
	   64,
	   "AFS-MINPRIORITY%d%d",
	   dbf->i, 
	   dbf->n); 
  stateWriteContent(statename,
		    sizeof(int),
		    &dbf->minPriority);
  lowDoneContentDatabase(dbf->dbfs);  
  pidxDoneContentDatabase(dbf->pIdx);
  MUTEX_DESTROY(&dbf->lock);
  FREE(dbf);
}

/**
 * Closure used by the high_simple.c implementation of
 * forEachEntryInDatabase
 */
typedef struct {
  void * handle;
  EntryCallback callback;
  void * callback_closure;
} HighFEEIDClosure;

static void helper_callback(const HashCode160 * query,
			    HighFEEIDClosure * cls) {
  void * data;
  int len;
  ContentIndex ce;

  data = NULL;
  len = readContent(cls->handle,
		    query,
		    &ce,
		    &data,
		    0);
  if (len == SYSERR)
    return;
  cls->callback(query,
		&ce,
		data,
		len,
		cls->callback_closure);
}

/**
 * Call a method for each key in the database and call the callback
 * method on it.
 *
 * @param handle the database
 * @param callback the callback method
 * @param data second argument to all callback calls
 * @return the number of items stored in the content database
 */
int forEachEntryInDatabase(HighDBHandle handle,
			   EntryCallback callback,
			   void * data) {
  DatabaseHandle * dbf = handle;
  HighFEEIDClosure cls;

  cls.handle = handle;
  cls.callback = callback;
  cls.callback_closure = data;
  return lowForEachEntryInDatabase(dbf->dbfs,
				   (LowEntryCallback)&helper_callback,
				   &cls);
}

/**
 * Get the number of entries in the database.
 *
 * @param handle the database
 * @return SYSERR on error, otherwise the number of entries
 */
int countContentEntries(HighDBHandle handle) {
  DatabaseHandle * dbf = handle;
  
  return lowCountContentEntries(dbf->dbfs);
}

/**
 * Add the specified query to the index of the given priority.
 *
 * @param priority the priority of the data
 * @param query the search-query for the data
 * @param handle the database
 */ 
static void addToPriorityIdx(HighDBHandle handle,
			     const HashCode160 * query,
			     unsigned int priority) {
  DatabaseHandle * dbf = handle;

  if (priority < dbf->minPriority) {
    dbf->minPriority = priority;
    stateWriteContent("AFS-MINPRIORITY",
		      sizeof(int),
		      &dbf->minPriority);
  }
  pidxAppendContent(dbf->pIdx,
		    priority,
		    1,
		    query);
}

/**
 * Delete the specified query from the index of the given priority.
 *
 * @param priority the priority of the data
 * @param query the search-query for the data
 * @param handle the database
 */
static void delFromPriorityIdx(HighDBHandle handle,
			       const HashCode160 * query,
			       unsigned int priority) {
  DatabaseHandle * dbf = handle;
  HashCode160 * keys;
  int res;
  int i;

  keys = NULL;
  res = pidxReadContent(dbf->pIdx,
			priority,
			&keys);
  if ( (res == -1) || 
       (keys == NULL) ) {
    LOG(LOG_WARNING,
	_("pIdx database corrupt (content not indexed) in %s:%d\n"),
	__FILE__, __LINE__);
  } else {
    for (i=0;i<res;i++)
      if (equalsHashCode160(query,
			    &keys[i]))
	break;
    if (i == res) {
      LOG(LOG_WARNING,
	  _("pIdx database corrupt (content not indexed) in %s:%d\n"),
	  __FILE__, __LINE__);
    } else {
      memcpy(&keys[i],
	     &keys[res-1],
	     sizeof(HashCode160));
      res--;
      if (res > 0) {
	pidxWriteContent(dbf->pIdx,
			 priority,
			 res,
			 keys);
      } else {
	pidxUnlinkFromDB(dbf->pIdx,
			 priority);
      }
    }       
    FREE(keys);
  }
}

/**
 * Get the lowest priority of content in the store.
 *
 * @param handle the database
 * @return the lowest priority of content in the DB
 */
unsigned int getMinimumPriority(HighDBHandle handle) {
  DatabaseHandle * dbf = handle;

  return dbf->minPriority;
}



/**
 * Read the contents of a bucket to a buffer.
 *
 * @param handle the database to read from
 * @param query the hashcode representing the entry
 * @param ce the meta-data for the content (filled in)
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @param prio if found, by how much should the priority be changed?
 * @return the number of bytes read on success, -1 on failure
 */ 
int readContent(HighDBHandle handle,
		const HashCode160 * query,
		ContentIndex * ce,
		void ** result,
		int prio) {
  DatabaseHandle * dbf = handle;
  void * ires;
  int len;
  HexName hex;

#if DEBUG_HIGH_SIMPLE
  LOG(LOG_DEBUG,
      "%s::%s called\n",
      __FILE__, __FUNCTION__);
#endif
  ires = NULL;
  len = lowReadContent(dbf->dbfs,
		       query,
		       &ires);
  if (len < 0) {
    IFLOG(LOG_DEBUG,
	  hash2hex(query,
		   &hex));
#if DEBUG_HIGH_SIMPLE
    LOG(LOG_DEBUG,
	"low %p did not find response for %s, returning not found\n",
	dbf->dbfs,
	&hex);
#endif
    return -1;
  }
  if ((unsigned int)len < sizeof(ContentIndex)) {
    BREAK();
    lowUnlinkFromDB(dbf->dbfs,
		    query);
    return -1;  
  }

  /* meta-data is first 32 bytes... */
  memcpy(ce,
	 ires,
	 sizeof(ContentIndex));

  /* update priority */
  if (prio != 0) {
    unsigned int oprio;

    MUTEX_LOCK(&dbf->lock);

    /* remove old priority entry from pIdx */
    oprio = ntohl(ce->importance);
    delFromPriorityIdx(handle,
		       query,
		       oprio);
 
    /* add new priority entry to pIdx */
    oprio += prio;      
    addToPriorityIdx(handle,
		     query,
		     oprio); 
    /* actually add the entry to the dbfs database */
    ce->importance = htonl(oprio);
    memcpy(ires,
	   ce,
	   sizeof(ContentIndex));
    lowWriteContent(dbf->dbfs,
		    query,
		    len,
		    ires);

    MUTEX_UNLOCK(&dbf->lock);
  }

  len -= sizeof(ContentIndex);
  if (len == 0) {
    FREE(ires);
#if DEBUG_HIGH_SIMPLE
    LOG(LOG_DEBUG,
	"Found on-demand encoded content.\n");
#endif
    return 0;
  }
  if (len < 0) {
    BREAK();
    FREE(ires);
    return -1;
  }
  /* copy remaining data to result */
  *result = MALLOC(len);
  memcpy(*result,
	 &((char*)ires)[sizeof(ContentIndex)],
	 len);
  FREE(ires);
#if DEBUG_HIGH_SIMPLE
  LOG(LOG_DEBUG,
      "Found %d bytes of content.\n",
      len);
#endif
  return len;
}

/**
 * Write content to a file. Check for reduncancy and eventually
 * append.
 *
 * @param handle the database to read from
 * @param ce the meta-data of the entry
 * @param len the size of the block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int writeContent(HighDBHandle handle,
		 const ContentIndex * ce,
		 unsigned int len,
		 const void * block) {
  DatabaseHandle * dbf = handle;
  HashCode160 query;
  void * ibl;
  int ok;
  HexName hex;

  MUTEX_LOCK(&dbf->lock);
  if (ntohs(ce->type) == LOOKUP_TYPE_3HASH)
    hash(&ce->hash,
	 sizeof(HashCode160),
	 &query);
  else
    memcpy(&query,
	   &ce->hash,
	   sizeof(HashCode160));
  unlinkFromDB(handle,
	       &query);

  ibl = MALLOC(len + sizeof(ContentIndex));
  memcpy(ibl,
	 ce,
	 sizeof(ContentIndex));
  memcpy(&((char*)ibl)[sizeof(ContentIndex)],
	 block,
	 len);
  ok = lowWriteContent(dbf->dbfs,
		       &query,
		       len+sizeof(ContentIndex),
		       ibl);
  IFLOG(LOG_DEBUG,
	hash2hex(&query,
		 &hex));
#if DEBUG_HIGH_SIMPLE
  LOG(LOG_DEBUG,
      "low %p wrote content %s: %d\n",
      dbf->dbfs,
      &hex,
      ok);
#endif
  if (ok == OK) 
    addToPriorityIdx(handle,
		     &query,
		     ntohl(ce->importance));  
  FREE(ibl);
  MUTEX_UNLOCK(&dbf->lock);
  return ok;
}

/**
 * Free space in the database by removing an entry.
 *
 * @param handle the database
 * @param name the key of the entry to remove
 * @return SYSERR on error, OK if ok.
 */
int unlinkFromDB(HighDBHandle handle,
		 const HashCode160 * name) {
  DatabaseHandle * dbf = handle;
  ContentIndex ce;
  void * result;
  int ok;

  MUTEX_LOCK(&dbf->lock);
  result = NULL;
  ok = readContent(handle,
		   name,
		   &ce,
		   &result,
		   0);
  if (ok == -1) {
    MUTEX_UNLOCK(&dbf->lock);
    return SYSERR;
  }
  FREENONNULL(result);
  delFromPriorityIdx(handle,
		     name,
		     ntohl(ce.importance));
  ok = lowUnlinkFromDB(dbf->dbfs,
		       name);
  MUTEX_UNLOCK(&dbf->lock);
  return ok;
}



/**
 * Return the number of files that contains data with priority
 * higher than given.
 *
 * @param file the filename of the current file
 * @param dir the directory name
 * @param counter total size of the file in blocks (set)
 */
static void countFiles(const char *file, 
		       const char *dir, 
		       int * counter) {
  int filenum;
  char * fil;
  size_t n;

  filenum = atoi(file);
  if (filenum < 0)
    return;
  n = strlen(dir) + 20;
  fil = MALLOC(n);
  SNPRINTF(fil, 
	   n,
	   "%s/%u", 
	   dir, 
	   filenum); 
  (*counter) += getFileSize(fil) / sizeof(HashCode160);
  FREE(fil);
}

/**
 * Return the nth file from the list of selected files
 *
 * @param file the filename of the current file
 * @param dir the directory name
 * @param nb two numbers that represents the number of files still to be
 *        passed and the name of the selected file (which is set when 
 *        the first number hits 0)
 */
static void getRandomFileName(const char *file, 
			      const char *dir, 
			      int * nb)
{
  int filenum;
  char * fil;
  int oldnb;
  size_t n;

  filenum = atoi(file);
  if (filenum < 0)
    return;
  
  n = strlen(dir) + 20;
  fil = MALLOC(n);
  SNPRINTF(fil, 
	   n,
	   "%s/%u", 
	   dir, 
	   filenum); 
  oldnb = nb[0];
  nb[0] -= getFileSize(fil) / sizeof(HashCode160);
  FREE(fil);
  if ( (nb[0] < 0)  &&
       (oldnb >= 0) )
    nb[1] = filenum;    
}

/**
 * Return a random key from the database (content too, if not
 * on-demand). Note that the selection is not strictly random but
 * strongly biased towards content of a low priority (which we are
 * likely to discard soon).
 *
 * @param handle the database to read from
 * @param ce output information about the key
 * @return SYSERR on error, OK if ok.
 */
int getRandomContent(HighDBHandle handle,
                     ContentIndex * ce,
		     CONTENT_Block ** data) {
  DatabaseHandle * dbf = handle;
  HashCode160 query;
  int finiteLoop;
  int res=-1;
  
  finiteLoop = 0; /* at most 1000 iterations! */
  while ( (res == -1) &&
          (finiteLoop < 100000) ) {
    int counter;
    int retrievefile[2];
    PIDX pidx = dbf->pIdx;

    finiteLoop += 100;

    /* count the number of file name with a valid name */
    counter = 0;    
    scanDirectory(pidx->dir,
		  (DirectoryEntryCallback)&countFiles,
		  &counter);
    if (counter == 0)
      break;

    /* select a random file */
    retrievefile[0] = randomi(counter);
    retrievefile[1] = -1;

    scanDirectory(pidx->dir,
		  (DirectoryEntryCallback)&getRandomFileName,
		  &retrievefile[0]);
    if (retrievefile[1] == -1) {
      LOG(LOG_DEBUG,
	  "Concurrent modification of directory (%d, %d), oops.\n",
	  counter, retrievefile[1]);
      break;
    }
    res = pidxReadRandomContent(pidx,
				retrievefile[1], /* filename */
				&query);
    if (res == SYSERR) {
      LOG(LOG_DEBUG,
	  "Concurrent modification of directory or bad file in directory (%d).\n",
	  retrievefile[1]);
      break;
    }    
  }
  if (res == -1)
    return SYSERR;

  /* now get the ContentIndex */
  res = readContent(handle,
                    &query,
                    ce,
                    data,
                    0);
  if (res == -1)
    return SYSERR;
  return OK;
}


/**
 * Delete low-priority content from the database
 *
 * @param handle the database
 * @param count the number of 1kb blocks to free
 * @param callback method to call on each entry before freeing
 * @param closure extra argument to callback
 * @return OK on success, SYSERR on error
 */
int deleteContent(HighDBHandle handle,
                  unsigned int count,
		  EntryCallback callback,
		  void * closure) {
  DatabaseHandle * dbf = handle;
  HashCode160 * result;
  int res;
  int cnt;
  int corruptBailOut = 0;

  MUTEX_LOCK(&dbf->lock);
  while ( (count > 0) &&
	  (countContentEntries(handle) > 0) &&
	  (corruptBailOut < 100000) ) {
    corruptBailOut++;
    result = NULL;
    cnt = pidxReadContent(dbf->pIdx,
			  dbf->minPriority,
			  &result);
    if (cnt == -1) {
      dbf->minPriority++;
      continue;
    }
    if (cnt == 0) {
      LOG(LOG_WARNING,
	  _("pIdx database corrupt, trying to fix (%d)\n"),
	  dbf->minPriority);
      pidxUnlinkFromDB(dbf->pIdx,
		       dbf->minPriority);
      FREENONNULL(result);
      continue;
    }
    while ( (count > 0) &&
	    (cnt > 0) ) {
      ContentIndex ce;
      void * data;
      int dlen;
      
      cnt--;
      data = NULL;
      dlen = readContent(handle,
			 &result[cnt],
			 &ce,
			 &data,
			 0);
      if (dlen >= 0) {
	if (callback != NULL) {
	  callback(&result[cnt-1],
		   &ce,
		   data,
		   dlen,
		   closure);
	} else
	  FREENONNULL(data);
	res = lowUnlinkFromDB(dbf->dbfs,
			      &result[cnt]);
      } else {
	res = SYSERR;
      }
      if (res == OK) {
	count--;
      } else {
	BREAK();
      }
    }
    if (cnt == 0) {
      pidxUnlinkFromDB(dbf->pIdx,
		       dbf->minPriority);
      dbf->minPriority++;
    } else {
      pidxTruncateAt(dbf->pIdx,
		     dbf->minPriority,
		     cnt);
    }
    FREE(result);
  }
  MUTEX_UNLOCK(&dbf->lock);
  if (count == 0)
    return OK;
  else
    return SYSERR;
}


/**
 * Estimate how many blocks can be stored in the DB before the quota
 * is reached.
 *
 * @param handle the database
 * @param quota the number of kb available for the DB
 */ 
int estimateAvailableBlocks(HighDBHandle handle,
			    unsigned int quota) {
  DatabaseHandle * dbf = handle;

  return quota - lowEstimateSize(dbf->dbfs);
}

/**
 * Close and delete the database.
 *
 * @param handle the database
 */
void deleteDatabase(HighDBHandle handle) {
  DatabaseHandle * dbf = handle;

  lowDeleteContentDatabase(dbf->dbfs);  
  pidxDeleteContentDatabase(dbf->pIdx);
  MUTEX_DESTROY(&dbf->lock);
  FREE(dbf);
}

/* end of high_simple.c */
