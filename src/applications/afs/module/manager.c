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
 * @file applications/afs/module/manager.c
 * @brief This module is responsible to manage content, in particular 
 *        it needs to decide what content to keep.
 * @author Christian Grothoff
 */

#include "manager.h"
#include "high_backend.h"
#include "fileindex.h"
#include "large_file_support.h"
#include "bloomfilter.h"

#ifndef CYGWIN
#include <limits.h>
#endif

#define DSO_PREFIX "libgnunetafs_database_"

/**
 * Entry length that indicates that the entry
 * was too large for the usual DB and has been
 * stored in a separate file instead.
 */
#define VERY_LARGE_FILE 42

/**
 * How large is very large? (number of ContentEntries)
 * Mysql seems to have some limit at 16k, so let's pick 15 to
 * be on the good side for sure.
 */
#define VERY_LARGE_SIZE 15

#define VLS_DIR "large"

#define DB_DIRTY_AVAILABLE INT_MIN

#define TRACK_INDEXED_FILES NO 
#define TRACKFILE "indexed_requests.txt"

/* ********************* GLOBALS ***************** */


/**
 * The current base value for fresh content (used to time-out old
 * content).
 */
static int MANAGER_age;

/**
 * Is active migration allowed? This is about us receiving
 * data from the network, actively pushing content out is
 * always ok.
 */
static int useActiveMigration;

/**
 * Global database handle
 */
static DatabaseAPI * dbAPI = NULL;

/**
 * Large file handling.
 */
static LFS lfs;

/**
 * Statistics handles
 */
static int stat_handle_lookup_3hash;
static int stat_handle_lookup_sblock;
static int stat_handle_lookup_chk;
static int stat_handle_lookup_ondemand;
static int stat_handle_lookup_notfound;
static int stat_handle_spaceleft;

#define AGEFILE "database.age"

/**
 * Open the AGE file and return the handle.
 */
static int getAgeFileHandle() {
  char * fileName;
  char * ef;
  int handle;
  
  LOG(LOG_CRON, 
      "Enter '%s'.\n",
      __FUNCTION__);
  fileName = getFileName("AFS",
			 "AFSDIR",
			 _("Configuration file must specify directory for"
			   " storage of AFS data in section '%s' under '%s'.\n"));
  ef = MALLOC(strlen(fileName) + 
	      strlen(AGEFILE) +2);
  strcpy(ef, fileName);
  strcat(ef, "/");
  strcat(ef, AGEFILE);
  FREE(fileName);
  handle = OPEN(ef,
		O_CREAT|O_RDWR,
		S_IRUSR|S_IWUSR);
  if (handle < 0) {
    LOG_FILE_STRERROR(LOG_ERROR, "open", ef);
    FREE(ef);
    return SYSERR;
  }
  FREE(ef);
  return handle;
}

/**
 * Cron-job that decreases the importance-level of all
 * files by 1. Runs 'not very often'.
 */
static void cronReduceImportance(void * unused) {
  int handle;
    
  LOG(LOG_CRON, 
      "Enter '%s'.\n",
      __FUNCTION__);
  handle = getAgeFileHandle();
  if (handle == SYSERR)
    return;
  MANAGER_age++;
  WRITE(handle, 
	&MANAGER_age,
	sizeof(int));
  CLOSE(handle);
  LOG(LOG_CRON, 
      "Exit '%s'.\n",
      __FUNCTION__);
}

/**
 * Encode a block from a file on the drive, put the
 * result in the result buffer (allocate) and return
 * the size of the buffer. If readCount is larger than
 * one, the routine tries to read a longer linear block,
 * starting from the location given by ce (this can
 * be used for more efficient migration buffer filling).
 */ 
int encodeOnDemand(const ContentIndex * ce,
 	           CONTENT_Block ** result,
	           int readCount) {
  char * fn;
  int fileHandle;
  ssize_t blen;
  HashCode160 hc;
  CONTENT_Block * iobuf;
  EncName enc;
  int i;
  int lastBlockSize = sizeof(CONTENT_Block);
  
  /* on-demand encoding mechanism */
  fn = getIndexedFileName(ntohs(ce->fileNameIndex));
  if (fn == NULL) {
    LOG(LOG_FAILURE, 
	_("Database inconsistent! "
	  "(index points to invalid offset (%u)\n"),
	ntohs(ce->fileNameIndex));
    return SYSERR;
  }
  fileHandle = OPEN(fn, O_EXCL, S_IRUSR);
  if (fileHandle == -1) {
    LOG_FILE_STRERROR(LOG_ERROR, "open", fn);
    FREE(fn);
    return SYSERR;
  }
#if TRACK_INDEXED_FILES
  {
    FILE * fp;
    char * afsDir;
    char * scratch;
    int n;
  
    afsDir = getFileName("AFS",
			 "AFSDIR",
			 _("Configuration file must specify directory for"
			   " storage of AFS data in section '%s' under '%s'.\n"));
    n = strlen(afsDir)+strlen(TRACKFILE)+8;
    scratch = MALLOC(n);
    SNPRINTF(scratch,
	     n,
	     "%s/%s", afsDir, TRACKFILE);
    fp = FOPEN(scratch, "a");
    fprintf(fp,
	    "%u %llu\n", 
	    ntohs(ce->fileNameIndex), 
	    (unsigned long long)TIME(NULL));
    fclose(fp);
    FREE(scratch);
    FREE(afsDir);
  }
#endif
  if ((off_t)ntohl(ce->fileOffset) != lseek(fileHandle, 
					   ntohl(ce->fileOffset), 
					   SEEK_SET)) {
    LOG_FILE_STRERROR(LOG_WARNING, "lseek", fn);
    FREE(fn);
    CLOSE(fileHandle);
    return SYSERR;
  }
  iobuf = MALLOC(sizeof(CONTENT_Block) * readCount);
  blen = READ(fileHandle, 
	      iobuf,
	      sizeof(CONTENT_Block) * readCount);
  if (blen <= 0) {
    if (blen == 0)      
      LOG(LOG_WARNING,
     	  _("Read 0 bytes from file '%s' at %s:%d.\n"),
  	  fn, __FILE__, __LINE__);
    else
      LOG_FILE_STRERROR(LOG_ERROR, "read", fn);
    FREE(fn);
    FREE(iobuf);
    CLOSE(fileHandle);
    return SYSERR;
  }
  readCount = blen / sizeof(CONTENT_Block);
  if (blen % sizeof(CONTENT_Block) != 0) {
/*     LOG(LOG_DEBUG, "Tuning last block\n"); */
    readCount++;
    lastBlockSize = sizeof(CONTENT_Block) 
                    - (readCount*sizeof(CONTENT_Block) - blen);
    memset(&((char*)iobuf)[blen],
	   0,
	   readCount*sizeof(CONTENT_Block)-blen);
  }
  LOG(LOG_DEBUG,
      "Read %u bytes from %s for ODE at %u, realized rc %d lb %d\n",
      blen, 
      fn,
      ntohl(ce->fileOffset),
      readCount,
      lastBlockSize);
  FREE(fn);
  CLOSE(fileHandle);
  *result = MALLOC(sizeof(CONTENT_Block)*readCount);
  for (i=0;i<readCount;i++) {
    if (i == readCount - 1) {
      hash(&iobuf[i],
           lastBlockSize, 
           &hc);
    } else {
      hash(&iobuf[i],
           sizeof(CONTENT_Block), 
           &hc);
    }
    
    if (SYSERR == encryptContent(&iobuf[i],
		  	         &hc,
			         &(*result)[i])) 
      GNUNET_ASSERT(0);
  }

  FREE(iobuf);
  IFLOG(LOG_DEBUG,
	hash(result[0],
	     sizeof(CONTENT_Block),
	     &hc);
	hash2enc(&hc,
		 &enc));
  /*LOG(LOG_DEBUG,
    " on-demand encoded content has query %s\n",
    &enc);*/
  return sizeof(CONTENT_Block)*readCount;
}

static void * bindDynamicMethod_(void * libhandle,
				 const char * methodprefix,
				 const char * dsoname) {
  void * ret;
  ret = bindDynamicMethod(libhandle,
			  methodprefix,
			  dsoname);  
  if (ret == NULL)
    errexit(_("Could not find method '%s' in database module '%s'.\n"),
	    methodprefix,
	    dsoname);
  return ret;
}

/**
 * Load the high-level database as specified by
 * the given dtype.
 */
DatabaseAPI * initializeDatabaseAPI(const char * dtype) {
  DatabaseAPI * dbAPI;
  char * odtype;
  int len;
  void * lib;
  unsigned int i;
    
  if (dtype == NULL)
    errexit(_("You must specify the '%s' option in section '%s' in the configuration.\n"),
	    "DATABASETYPE", "AFS");
  odtype = NULL;
  len = stateReadContent("AFS-DATABASETYPE",
			 (void**)&odtype);
  if (len < 0) {
    stateWriteContent("AFS-DATABASETYPE",
		      strlen(dtype),
		      dtype);
  } else {
    if ( ((unsigned int)len != strlen(dtype)) ||
	 (strncmp(dtype, odtype, len)) )
      errexit(_("AFS database type was changed, run gnunet-convert.\n"));
  }
  FREENONNULL(odtype);
  dbAPI = MALLOC(sizeof(DatabaseAPI));
  lib = loadDynamicLibrary(DSO_PREFIX,
                           dtype);
  if (lib == NULL)
    errexit(_("Failed to load database library '%s'.\n"),
	    dtype);
  dbAPI->initContentDatabase    
    = bindDynamicMethod_(lib,
			 "",
			 "initContentDatabase");
  dbAPI->doneContentDatabase
    = bindDynamicMethod_(lib,
			 "",
			 "doneContentDatabase");
  dbAPI->forEachEntryInDatabase
    = bindDynamicMethod_(lib,
			 "",
			 "forEachEntryInDatabase");
  dbAPI->countContentEntries 
    = bindDynamicMethod_(lib,
			 "",
			 "countContentEntries");
  dbAPI->getMinimumPriority
    = bindDynamicMethod_(lib,
			 "",
			 "getMinimumPriority");
  dbAPI->readContent    
    = bindDynamicMethod_(lib,
			 "",
			 "readContent");
  dbAPI->writeContent   
    = bindDynamicMethod_(lib,
			 "",
			 "writeContent");
  dbAPI->unlinkFromDB   
    = bindDynamicMethod_(lib,
			 "",
			 "unlinkFromDB");
  dbAPI->deleteContent  
    = bindDynamicMethod_(lib,
			 "",
			 "deleteContent");
  dbAPI->getRandomContent
    = bindDynamicMethod_(lib,
			 "",
			 "getRandomContent");
  dbAPI->estimateAvailableBlocks
    = bindDynamicMethod_(lib,
			 "",
			 "estimateAvailableBlocks");
  dbAPI->deleteDatabase
    = bindDynamicMethod_(lib,
			 "",
			 "deleteDatabase");
  dbAPI->dynamicLibrary = lib;
  dbAPI->buckets
    = 4 * getConfigurationInt("AFS",
			      "DISKQUOTA") / 1024; /* one bucket per 250 MB */
  if (dbAPI->buckets == 0)
    dbAPI->buckets = 1; /* at least 1 bucket! */
  dbAPI->dbHandles
    = MALLOC(dbAPI->buckets * sizeof(HighDBHandle));
  dbAPI->dbAvailableBlocks
    = MALLOC(dbAPI->buckets * sizeof(int));
  for (i=0;i<dbAPI->buckets;i++) {
    dbAPI->dbHandles[i] 
      = dbAPI->initContentDatabase(i, 
				   getConfigurationInt("AFS",
						       "DISKQUOTA"));
    if (dbAPI->dbHandles[i] == NULL)
      errexit(_("Failed to initialize AFS database %u.\n"), 
	      i);
    dbAPI->dbAvailableBlocks[i]
      = DB_DIRTY_AVAILABLE; /* not yet initialized */
  }
  return dbAPI;
}

typedef struct IterState {
  int hasNext;
  Semaphore * wsem;
  Semaphore * sem;
  HashCode160 next;
  ContentIndex ce;
  int bucket;
  void * data;
  int len;
  PTHREAD_T db_iterator;
} IterState;

static void iterator_helper_callback(const HashCode160 * key,
				     const ContentIndex * ce,
				     void * data,
				     int dataLen,
				     IterState * state) {
  SEMAPHORE_DOWN(state->wsem);
  memcpy(&state->next,
	 key,
	 sizeof(HashCode160));
  memcpy(&state->ce,
	 ce,
	 sizeof(ContentIndex));
  state->data = data;
  state->len = dataLen;    
  SEMAPHORE_UP(state->sem);
}

/**
 * Thread that fetches the next entry from the database.
 * The thread is created by makeDatabaseIteratorState
 * and exits once we're through the database.
 */
static void * iterator_helper(IterState * state) {
  unsigned int i;

  state->hasNext = YES;
  for (i=0;i<dbAPI->buckets;i++) {
    SEMAPHORE_DOWN(state->wsem);
    state->bucket = i;
    SEMAPHORE_UP(state->wsem);  
    dbAPI->forEachEntryInDatabase(dbAPI->dbHandles[i],
				  (EntryCallback)&iterator_helper_callback,
				  state);
  }
  SEMAPHORE_DOWN(state->wsem);
  state->hasNext = NO;
  SEMAPHORE_UP(state->sem);  
  return NULL;
}

/**
 * Create the state required for a database iterator.  Calling this
 * method requires to call databaseIterator with the state returned
 * until "SYSERR" is returned.
 */
void * makeDatabaseIteratorState() {
  IterState * ret;

  ret = MALLOC(sizeof(IterState));
  ret->sem = SEMAPHORE_NEW(0);
  ret->wsem = SEMAPHORE_NEW(1);
  if (0 != PTHREAD_CREATE(&ret->db_iterator,
			  (PThreadMain)&iterator_helper,
			  ret,
			  8 * 1024))
    DIE_STRERROR("pthread_create");
  return ret;
}

/**
 * Iterator over all the queries in the database as needed by
 * resizeBloomfilter (and gnunet-check).  Typical use:
 * <code>
 * state = makeDatabaseIteratorState();
 * while (OK == databaseIterator(state, &x, &y, &z, &t))
 *   ...do something...
 * </code>
 * 
 * @param state the iterator state as created by
 *        makeDatabaseIteratorState
 * @param hc next hash code (set)
 * @param ce next content index (set)
 * @param bucket where the data actually was (set) 
 * @param data corresponding data (set)
 * @param datalen length of data (set)
 * @returns OK if the iterator has filled in another element
 *  from the database, SYSERR if there are no more elements
 */
int databaseIterator(void * state,
		     HashCode160 * hc,
		     ContentIndex * ce,
		     int * bucket,
		     void ** data,
		     int * datalen) {
  IterState * st = state;

  SEMAPHORE_DOWN(st->sem);
  if (st->hasNext == NO) {
    void * unused;

    SEMAPHORE_FREE(st->sem);
    SEMAPHORE_FREE(st->wsem);
    PTHREAD_JOIN(&st->db_iterator, &unused);
    FREE(st);
    return SYSERR;
  }
  memcpy(hc, 
	 &st->next,
	 sizeof(HashCode160));
  memcpy(ce,
	 &st->ce,
	 sizeof(ContentIndex));
  *bucket = st->bucket;
  *data = st->data;
  *datalen = st->len;
  SEMAPHORE_UP(st->wsem);
  return OK;
}

/**
 * calculates the global available space using
 * cached bucket availability estimates
 */
static int estimateGlobalAvailableBlocks() {
  unsigned int i;
  int ret = 0;
  int perBucketQuota = getConfigurationInt("AFS",
                         "DISKQUOTA") * 1024 / dbAPI->buckets;

  for (i = 0; i < dbAPI->buckets; ++i) {
    if (dbAPI->dbAvailableBlocks[i] == DB_DIRTY_AVAILABLE) {
      dbAPI->dbAvailableBlocks[i]
        = dbAPI->estimateAvailableBlocks(dbAPI->dbHandles[i],
					 perBucketQuota);
    }
    ret += dbAPI->dbAvailableBlocks[i];
  }
  return ret;
}

/**
 * Initialize the manager-module.
 */
void initManager() {  
  int handle;
  int delta;
  unsigned int i;
  char * dtype;
  char * afsdir;
  char * dir;

  dtype = getConfigurationString("AFS",
  	 	 	         "DATABASETYPE");
  dbAPI = initializeDatabaseAPI(dtype);
  FREE(dtype);
  stat_handle_lookup_sblock
    = statHandle(_("# lookup (SBlock, search results)"));
  stat_handle_lookup_3hash
    = statHandle(_("# lookup (3HASH, search results)"));
  stat_handle_lookup_chk
    = statHandle(_("# lookup (CHK, inserted or migrated content)"));
  stat_handle_lookup_ondemand
    = statHandle(_("# lookup (ONDEMAND, indexed content)"));
  stat_handle_lookup_notfound
    = statHandle(_("# lookup (data not found)"));
  stat_handle_spaceleft
    = statHandle(_("# blocks AFS storage left (estimate)"));
  handle = getAgeFileHandle();
  MANAGER_age = 0;
  if (handle != SYSERR) {
    READ(handle, 
	 &MANAGER_age,
	 sizeof(int));
    CLOSE(handle);
  }
  useActiveMigration
    = testConfigurationString("AFS",
			      "ACTIVEMIGRATION",
			      "YES");
  addCronJob(&cronReduceImportance,
	     6 * cronHOURS,
	     12 * cronHOURS,
	     NULL); 

  delta = estimateGlobalAvailableBlocks();
  if (delta < 0) {
    int * perm = permute(dbAPI->buckets);
    /* we permute to delete content in random order since
       users may interrupt the process (in particular at
       the beginning) and we want to make sure that the
       chances are distributed reasonably at random) */
    for (i=0;i<dbAPI->buckets;i++) {
      dbAPI->deleteContent(dbAPI->dbHandles[perm[i]],
			   16-delta/dbAPI->buckets,
			   &bf_deleteEntryCallback,
			   NULL);
      dbAPI->dbAvailableBlocks[perm[i]]
        = DB_DIRTY_AVAILABLE;
    }
    FREE(perm);
    delta = (16-delta/dbAPI->buckets)*dbAPI->buckets;
  }
  statSet(stat_handle_spaceleft,
	  delta);
  afsdir = getFileName("AFS",
		       "AFSDIR",
		       _("Configuration file must specify directory for storing AFS data"
		       " in section '%s' under '%s'.\n"));
  dir = MALLOC(strlen(afsdir)+
	       strlen(VLS_DIR)+2);
  strcpy(dir, afsdir);
  strcat(dir, "/");
  strcat(dir, VLS_DIR);
  FREE(afsdir);
  lfs = lfsInit(dir);
  FREE(dir);
}

/**
 * Shutdown the manager module.
 */
void doneManager() {
  unsigned int i;

  delCronJob(&cronReduceImportance,
	     12 * cronHOURS,
	     NULL); 
  for (i=0;i<dbAPI->buckets;i++) 
    dbAPI->doneContentDatabase(dbAPI->dbHandles[i]);
  FREE(dbAPI->dbAvailableBlocks);
  FREE(dbAPI->dbHandles);
  unloadDynamicLibrary(dbAPI->dynamicLibrary);
  FREE(dbAPI);
  dbAPI = NULL;
  lfsDone(lfs);
}

/**
 * This function is as crazy as it is since RIPE160 hashes do not seem
 * to be quite random as we may want the to be...  So to get evenly
 * distributed indices, we have to be a bit tricky. And no, there is
 * high science but just a bit playing with the formula here.
 */
unsigned int computeBucket(const HashCode160 * query,
                           unsigned int maxBuckets) {

  HashCode160 qt;
  hash(query, sizeof(HashCode160), &qt);
  return ( (unsigned int) (((query->a - qt.a) ^
  	  	            (query->b - qt.b) ^ 
		            (query->c - qt.c) ^ 
	 	            (query->d - qt.d) ^
	   	            (query->e - qt.e))) >> 4) % maxBuckets;
}

/**
 * Use this, if initManager() has been executed and 
 * the global dbAPI has the correct bucket count
 */
unsigned int computeBucketGlobal(const HashCode160 * query) {
  return computeBucket(query, 
		       dbAPI->buckets);
}

static HighDBHandle * computeHighDB(const HashCode160 * query) {
  return dbAPI->dbHandles[computeBucket(query, 
                                        dbAPI->buckets)];
}

/**
 * Locate content.  This method locates the data matching the content
 * entry.  The data is on-demand encrypted if it is indexed content or
 * retrieved from the contentdatabase if it was inserted content.
 *
 * @param query the query for the content (CHK or 3HASH)
 * @param ce the meta-data for the content
 * @param result where to write the result, space will be
 *        allocated by retrieveContent, *result should be
 *        NULL when this function is invoked.
 * @param prio by how much should the priority of the content
 *        be changed (if it is found)?
 * @param isLocal is the request a local request? (YES/NO)
 * @return the length of the resulting content, SYSERR on error
 */
int retrieveContent(const HashCode160 * query,
		    ContentIndex * ce,
		    void ** result,
		    unsigned int prio,
		    int isLocal) {
  int ret;
  
  ret = dbAPI->readContent(computeHighDB(query),
			   query,
      		  	   ce,
			   result,
			   prio);
  if (ret == -1) {
    statChange(stat_handle_lookup_notfound, 1);
    return SYSERR;
  }
  if (ret == VERY_LARGE_FILE) {
    FREE(*result);
    *result = NULL;
    if (isLocal)
      ret = lfsRead(lfs,
		    query, 
		    (CONTENT_Block**)result);
    else
      ret = lfsReadRandom(lfs, 
			  query, 
			  (CONTENT_Block**)result,
			  prio); 
    if (ret != SYSERR) {
      ret *= sizeof(CONTENT_Block);
    } else {
      FREE(*result);
      *result = NULL;
      ret = SYSERR;
    }
  }
  if ( (ret % sizeof(CONTENT_Block)) != 0) {
    BREAK();
    FREE(*result);
    *result = NULL;
    return SYSERR;
  }        
  if (ntohs(ce->fileNameIndex) == 0) {
    switch (ntohs(ce->type)) {
    case LOOKUP_TYPE_CHK:
    case LOOKUP_TYPE_CHKS:
      statChange(stat_handle_lookup_chk, 1);
      break;
    case LOOKUP_TYPE_3HASH:
      statChange(stat_handle_lookup_3hash, 1);
      break;
    case LOOKUP_TYPE_SBLOCK:
      statChange(stat_handle_lookup_sblock, 1);
      break;
    case LOOKUP_TYPE_SUPER:
      /* only gnunet-check will be doing this,  */
      /* don't bother to keep up stats          */
      break;
    default:
      LOG(LOG_ERROR,
	  _("Manager got unexpected content type %d.\n"),
	  ntohs(ce->type));
      break;
    }
    return ret;
  } 
  if (*result != NULL) {
    LOG(LOG_ERROR,
	_("Retrieved content but index says on-demand encoded!\n"));
    FREE(*result);
    *result = NULL;
  }
  statChange(stat_handle_lookup_ondemand, 1);
  return encodeOnDemand(ce, 
			(CONTENT_Block**)result,
			1);
}

static int handleVLSResultSet(const HashCode160 * query,
			      const void * data,
			      int * duplicate) {
  /* append to VLS */
  CONTENT_Block * blocks;
  int i;
  int ret;
  
  blocks = NULL;
  ret = lfsRead(lfs, query, &blocks);
  if (ret == SYSERR) {
    LOG(LOG_WARNING,
	_("lfs database inconsistent, trying to fix\n"));
    if (OK == dbAPI->unlinkFromDB(computeHighDB(query), query)) {
      dbAPI->dbAvailableBlocks[computeBucketGlobal(query)]
	= DB_DIRTY_AVAILABLE;
    } else
      LOG(LOG_WARNING,
	  _("Failed to fix lfs database inconsistency!\n"));
    return SYSERR;
  }
  /* check if the content is already present */
  for (i=0;i<ret;i++) {
    if (0 == memcmp(data, 
		    &blocks[i],
		    sizeof(CONTENT_Block))) {
      *duplicate = YES;
      FREE(blocks);
      return OK;
    }
  }
  FREENONNULL(blocks);
  return lfsAppend(lfs, 
		   query,
		   (CONTENT_Block*) data);
}

static int migrateToVLS(void * old,
			int oldLen,
			const HashCode160 * query,
			const void * data,
			const ContentIndex * ce) {  
  unsigned int i;
  int ret;
  
  ret = OK;
  i = 0;
  while ( (i < oldLen / sizeof(CONTENT_Block) ) &&
	  (ret == OK) ) {
    ret = lfsAppend(lfs,
		    query,
		    &((CONTENT_Block*)old)[i]);
    i++;
  }	
  FREENONNULL(old);
  if (ret == OK)
    ret = lfsAppend(lfs,
		    query, 
		    (CONTENT_Block*) data);
  if (ret != OK) {
    lfsRemove(lfs, query);
    return ret;
  }
  /* put forwarding content (marked by size) */
  ret = dbAPI->writeContent(computeHighDB(query),
			    ce,
			    VERY_LARGE_FILE,
			    data); /* data: random bits */
  dbAPI->dbAvailableBlocks[computeBucketGlobal(query)]
    = DB_DIRTY_AVAILABLE;
  return ret;
}

/**
 * 3HASH and SBlock results require special treatment
 * since multiple results are possible.
 */
static int handle3HSBInsert(const HashCode160 * query,
			    ContentIndex * ce,
			    const void * data,
			    int oldLen,
			    int * duplicate,
			    int len,
			    void * old,
			    int oldImportance) {
  int ret;
  char * tmp;

  if (oldLen == SYSERR) {
    /* no old content, just write */      
    dbAPI->dbAvailableBlocks[computeBucketGlobal(query)]
      = DB_DIRTY_AVAILABLE;
    if (SYSERR == dbAPI->writeContent(computeHighDB(query),
				      ce,
				      len,
				      data)) 
      return SYSERR; /* something went wrong... */    
    else
      return OK;
  }
  
  /* check if content is ALREADY in VLS store */
  if (oldLen == VERY_LARGE_FILE) {
    FREENONNULL(old);
    return handleVLSResultSet(query,
			      data,
			      duplicate);
    }
  
  /* Not VLS, check if the content is already present */
  for (ret=0;ret<oldLen/len;ret++) {
    if (0 == memcmp(&(((char*)old)[len*ret]),
		    data,
		    len)) {
      /* content already there, abort */
      FREENONNULL(old);
      *duplicate = YES; 
      return OK;
    }	   
  }
  
  /* check if we need to *move* the content to VLS store */
  if (oldLen / sizeof(CONTENT_Block) >= VERY_LARGE_SIZE) 
    return migrateToVLS(old, oldLen, query, data, ce);      
  
  /* else: default behavior: append */
  
  tmp = MALLOC(oldLen + len);
  memcpy(tmp,
	 old,
	 oldLen);
  memcpy(&tmp[oldLen],
	 data,
	 len);
  /* Discussion: perhaps we should use eg max(a,b)? Otherwise n local inserts
     throws this through the ceiling... OTOH, if the same block was part
     of two files, it is really twice as important, so adding makes sense
     in some cases. */
  ce->importance = htonl(oldImportance + ntohl(ce->importance));
  ret = dbAPI->writeContent(computeHighDB(query),
			    ce,
			    oldLen + len,
			    tmp);
  dbAPI->dbAvailableBlocks[computeBucketGlobal(query)]
    = DB_DIRTY_AVAILABLE;
  FREE(tmp);
  FREENONNULL(old);
  return ret;  
}
 
/**
 * Store content (if the priority is high enough), potentially
 * discarding less important content. 
 * 
 * @param ce the content entry describing the content
 * @param len the length of the data in bytes, either 0 for no data (e.g. on-demand encoding
 *         of indexed content or sizeof(CONTENT_Block) for normal data.
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
		  int * duplicate) {
  void * old;
  ContentIndex oldce;
  int oldLen;
  int avail;
  HashCode160 query;
  unsigned int importance;

  if (ntohs(ce->fileNameIndex)>0)
    LOG(LOG_EVERYTHING, 
	"using fileNameIndex %u\n",
	ntohs(ce->fileNameIndex));

  if ( (0 != len) &&
       (len != sizeof(CONTENT_Block)) ) {
    BREAK();
    return SYSERR;
  }

  *duplicate = NO;
  if ( (sender != NULL) &&
       (useActiveMigration == NO) )
    return SYSERR; /* forbidden! */
  importance = ntohl(ce->importance);
  if ( ( sender != NULL) &&
       ( randomi(2 + importance) == 0) )
    return SYSERR; /* don't bother... */
       
  ce->importance 
    = htonl(importance + MANAGER_age);
  switch (ntohs(ce->type)) {
  case LOOKUP_TYPE_3HASH:
    hash(&ce->hash, 
         sizeof(HashCode160),
         &query);
    break;
  case LOOKUP_TYPE_CHK:
  case LOOKUP_TYPE_CHKS:
  case LOOKUP_TYPE_SUPER:
  case LOOKUP_TYPE_SBLOCK:
    memcpy(&query,
	   &ce->hash,
	   sizeof(HashCode160));
    break;
  default:
    LOG(LOG_WARNING,
	_("Unexpected content type %d.\n"),
	ntohs(ce->type));
    return SYSERR;
  }

  memcpy(&oldce, 
	 ce, 
	 sizeof(ContentIndex));
  avail = estimateGlobalAvailableBlocks();
  if (avail <= 0) {
    if (importance + MANAGER_age <= dbAPI->getMinimumPriority(computeHighDB(&query)))
      return SYSERR; /* new content has such a low priority that
			we should not even bother! */
    dbAPI->deleteContent(computeHighDB(&query),
			 16-avail,
			 &bf_deleteEntryCallback,
			 NULL);
    statSet(stat_handle_spaceleft,
	    16-avail);
    dbAPI->dbAvailableBlocks[computeBucketGlobal(&query)]
      = DB_DIRTY_AVAILABLE;
  } else
    statSet(stat_handle_spaceleft,
	    avail);

  /* try to read existing */
  old = NULL;
  oldLen = dbAPI->readContent(computeHighDB(&query),
			      &query,
			      &oldce,
			      &old,
			      0);
  /* add the content */
  switch (ntohs(ce->type)) {
  case LOOKUP_TYPE_3HASH:
    if (len != sizeof(CONTENT_Block) ) {
      BREAK();
      return SYSERR;
    }
    return handle3HSBInsert(&query,
			    ce,
			    data,
			    oldLen,
			    duplicate,
			    len,
			    old,
			    ntohl(oldce.importance));
  case LOOKUP_TYPE_SBLOCK: 
    if (len != sizeof(CONTENT_Block) ) {
      BREAK();
      return SYSERR;
    }
    return handle3HSBInsert(&query,
			    ce,
			    data,
			    oldLen,
			    duplicate,
			    len,
			    old,
			    ntohl(oldce.importance));
  case LOOKUP_TYPE_CHK:
  case LOOKUP_TYPE_CHKS:
  case LOOKUP_TYPE_SUPER:
    {
      int replace = NO;
      /*
       * This is a bit messy. The intended idea is that missing blocks
       * are always replaced. Indexed blocks are replaced only if the
       * new one is indexed AND has a higher priority than the old one. 
       * Nonindexed, existing blocks are replaced if the size differs OR if new
       * is more important OR if new is an indexed block. This scheme
       * should never replace an indexed block with a nonindexed block.
       * We are not setting *duplicate=YES in the true replace case because
       * we don't want the bloomfilters to be unnecessarily incremented 
       * outside insertContent().
       */
      *duplicate = YES;
      if (oldLen == SYSERR) {
	replace = YES;
	*duplicate = NO;
      } else if (ntohs(oldce.fileNameIndex) > 0) {
        if(ntohs(ce->fileNameIndex) > 0 
	   && ntohl(ce->importance) > ntohl(oldce.importance) ) {
	  replace = YES;
	} else {
	  replace = NO;
	}
      } else {
	if(oldLen != len 
	    || ntohl(ce->importance) > ntohl(oldce.importance) 
	    || ntohs(ce->fileNameIndex)>0) {
          replace = YES;  
	} else {
	  replace = NO;
	}
      }

      FREENONNULL(old);
      if(replace == NO) {
        return OK;
      } else {
        dbAPI->dbAvailableBlocks[computeBucketGlobal(&query)]
          = DB_DIRTY_AVAILABLE;
        if (SYSERR == dbAPI->writeContent(computeHighDB(&query),
		  	  	  	  ce,
					  len,
					  data)) 
	  return SYSERR; /* something went wrong... */    
        else
	  return OK;
      }
    }
    break;
  default:
    LOG(LOG_WARNING,
	_("Unexpected content type %d.\n"),
	ntohs(ce->type));
    FREENONNULL(old);
    return SYSERR;
  }
  BREAK();
  return SYSERR;
}

/** 
 * Return a random key from the database.
 * @param ce output information about the key 
 * @return SYSERR on error, OK if ok.
 */
int retrieveRandomContent(ContentIndex * ce, 
			  CONTENT_Block ** data) {
  int bucket = randomi(dbAPI->buckets);
  GNUNET_ASSERT(dbAPI->dbHandles[bucket] != NULL);
  return dbAPI->getRandomContent(dbAPI->dbHandles[bucket],
				 ce,
				 data);
}

/**
 * Explicitly remove some content from the database.
 *
 * @param bucket where to delete (<0 == autocompute)
 *               >=0 is used by gnunet-check. 
 */  
int removeContent(const HashCode160 * query, 
		  int bucket) {
  int ok;
  ContentIndex ce;
  void * data;
  HighDBHandle * db;

  if (bucket < 0)
    db = computeHighDB(query);
  else
    db = dbAPI->dbHandles[bucket];

  data = NULL;
  ok = dbAPI->readContent(db,
			  query,
			  &ce,
			  &data,
			  0);
  if (ok == SYSERR) {
    EncName enc;
    hash2enc(query,
	     &enc);
    LOG(LOG_DEBUG,
	"%s on '%s' failed, readContent did not find content!\n",
	__FUNCTION__,
	&enc);
    return SYSERR; /* not found! */
  }
  if (ok == VERY_LARGE_FILE) {
    /* need to remove from VLS index, too -- this is 
       unusual, but we can do it (should currently
       never happen in practice) */
    ok = lfsRemove(lfs, query);
    if (ok == SYSERR) 
      BREAK();
  }
  
  ok = dbAPI->unlinkFromDB(db,
			   query);
  if (OK == ok) {
    int delta;
    
    dbAPI->dbAvailableBlocks[computeBucketGlobal(query)]
      = DB_DIRTY_AVAILABLE;
    delta = estimateGlobalAvailableBlocks();
    if (delta < 0)  /* should not happen */
      delta = 0;
    statSet(stat_handle_spaceleft,
	    delta);
  }
  return ok;
}

/* end of manager.c */
