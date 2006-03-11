/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file applications/fs/module/ondemand.c
 * @brief access to the list of indexed files
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "ecrs_core.h"
#include "ondemand.h"

#define DEBUG_ONDEMAND NO

#define TRACK_INDEXED_FILES NO
#define TRACKFILE "indexed_requests.txt"

/**
 * Format of an on-demand block.
 */
typedef struct {
  Datastore_Value header;

  unsigned int type;

  /**
   * At what offset in the plaintext file is
   * this content stored?
   */
  unsigned long long fileOffset;

  /**
   * Size of the on-demand encoded part of the file
   * that this Block represents.
   */
  unsigned int blockSize;

  /**
   * What is the hash of the file that contains
   * this block?  Used to determine the name
   * of the file in the on-demand datastore.
   */
  HashCode512 fileId;

} OnDemandBlock;

static char * index_directory;

static char * getOnDemandFile(const HashCode512 * fileId) {
  EncName enc;
  char * fn;

  hash2enc(fileId,
	   &enc);
  fn = MALLOC(strlen(index_directory) + sizeof(EncName) + 1);
  strcpy(fn, index_directory);
  strcat(fn, "/");
  strcat(fn, (char*) &enc);
  return fn;
}


/**
 * Test if the 'closure' OnDemandBlock is already
 * present in the datastore.  Presence is indicated
 * by aborting the iteration.
 */
static int checkPresent(const HashCode512 * key,
			const Datastore_Value * value,
			void * closure) {
  Datastore_Value * comp = closure;

  if ( (comp->size != value->size) ||
       (0 != memcmp(&value[1],
		    &comp[1],
		    ntohl(value->size) - sizeof(Datastore_Value))) )
    return OK;
  return SYSERR;
}

/**
 * Creates a symlink to the given file in the shared directory
 *
 * @param fn the file that was indexed
 * @param fileId the file's hash code
 * @return SYSERR on error, NO if symlinking failed,
 *         YES on success
 */
int ONDEMAND_initIndex(const HashCode512 * fileId,
		       const char *fn) {
  EncName enc;
  char * serverFN;
  char unavail_key[256];
  HashCode512 linkId;

  if ( (SYSERR == getFileHash(fn,
			      &linkId)) ||
       (! equalsHashCode512(&linkId,
			    fileId)) ) {
    return NO;
  }

  serverFN = MALLOC(strlen(index_directory) + 2 + sizeof(EncName));
  strcpy(serverFN,
	 index_directory);
  strcat(serverFN,
	 DIR_SEPARATOR_STR);
  hash2enc(fileId,
	   &enc);
  strcat(serverFN,
	 (char*)&enc);
  UNLINK(serverFN);
  if (0 != SYMLINK(fn, serverFN)) {
    LOG_FILE_STRERROR(LOG_ERROR, "symlink", fn);
    LOG_FILE_STRERROR(LOG_ERROR, "symlink", serverFN);
    FREE(serverFN);
    return NO;
  }
  SNPRINTF(unavail_key,
	   256,
	   "FIRST_UNAVAILABLE-%s",
	   (char*)&enc);
  stateUnlinkFromDB(unavail_key);
  FREE(serverFN);
  return YES;
}

/**
 * Writes the given content to the file at the specified offset
 * and stores an OnDemandBlock into the datastore.
 *
 * @return NO if already present, YES on success,
 *  SYSERR on other error (i.e. datastore full)
 */
int ONDEMAND_index(Datastore_ServiceAPI * datastore,
		   unsigned int prio,
		   cron_t expiration,
		   unsigned long long fileOffset,
		   unsigned int anonymityLevel,
		   const HashCode512 * fileId,
		   unsigned int size,
		   const DBlock * content) {
  int ret;
  OnDemandBlock odb;
  HashCode512 key;
  struct stat sbuf;
  char * fn;
#if DEBUG_ONDEMAND
  EncName enc;
#endif


  if (size <= sizeof(DBlock)) {
    BREAK();
    return SYSERR;
  }

  fn = getOnDemandFile(fileId);
  if ( (0 != LSTAT(fn,
		   &sbuf))
#ifdef S_ISLNK
       || (! S_ISLNK(sbuf.st_mode))
#endif
       ) {
    int fd;

    /* not sym-linked, write content to offset! */
#if DEBUG_ONDEMAND
    LOG(LOG_DEBUG,
	"Storing on-demand encoded data in `%s'.\n",
	fn);
#endif
    fd = fileopen(fn,
#ifdef O_LARGEFILE
		  O_LARGEFILE |
#endif
		  O_CREAT|O_WRONLY,
		  S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); /* 644 */
    if(fd == -1) {
      LOG_FILE_STRERROR(LOG_ERROR, "open", fn);
      FREE(fn);
      return SYSERR;
    }
    lseek(fd,
	  fileOffset,
	  SEEK_SET);
    ret = WRITE(fd,
		&content[1],
		size - sizeof(DBlock));
    if (ret == size - sizeof(DBlock)) {
      ret = OK;
    } else {
      LOG_FILE_STRERROR(LOG_ERROR, "write", fn);
      ret = SYSERR;
    }
    closefile(fd);
    if (ret == SYSERR) {
      FREE(fn);
      return ret;
    }
  }
  FREE(fn);

  odb.header.size = htonl(sizeof(OnDemandBlock));
  odb.header.type = htonl(ONDEMAND_BLOCK);
  odb.header.prio = htonl(prio);
  odb.header.anonymityLevel = htonl(anonymityLevel);
  odb.header.expirationTime = htonll(expiration);
  odb.type = htonl(ONDEMAND_BLOCK);
  odb.fileOffset = htonll(fileOffset);
  odb.blockSize = htonl(size - sizeof(DBlock));
  odb.fileId = *fileId;
  /* compute the primary key */
  fileBlockGetQuery(content,
		    size,
		    &key);
#if EXTRA_CHECKS
  {
    Datastore_Value * dsvalue;
    if (OK != fileBlockEncode(content,
			      size,
			      &key,
			      &dsvalue)) {
      BREAK();
    } else {
      FREE(dsvalue);
    }
  }
#endif

#if DEBUG_ONDEMAND
  IFLOG(LOG_DEBUG,
	hash2enc(&key, &enc));
  LOG(LOG_DEBUG,
      "Storing on-demand content for query `%s'\n",
      &enc);
#endif

  ret = datastore->get(&key,
		       ONDEMAND_BLOCK,
		       &checkPresent,
		       &odb.header);
  if (ret <= 0) {
    ret = datastore->put(&key,
			 &odb.header);
  } else {
    ret = NO; /* already present! */
  }
  return ret;
}

struct adJ {
  Datastore_ServiceAPI * datastore;
  Datastore_Value  * dbv;
  HashCode512 query;
};

static void asyncDelJob(struct adJ * job) {
  job->datastore->del(&job->query,
		      job->dbv);
  FREE(job->dbv);
  FREE(job);
}

/**
 * Delete the query that still references the unavailable file.  This
 * must be done asynchronously since we are in the "get" iterator and
 * a del operation during "get" would deadlock!
 */
static void asyncDelete(Datastore_ServiceAPI * datastore,
			const Datastore_Value * dbv,
			const HashCode512 * query) {
  struct adJ * job;
#if DEBUG_ONDEMAND
  EncName enc;
#endif

  job = MALLOC(sizeof(struct adJ));
  job->datastore = datastore;
  job->query = *query;
  job->dbv = MALLOC(ntohl(dbv->size));
  memcpy(job->dbv,
	 dbv,
	 ntohl(dbv->size));
#if DEBUG_ONDEMAND
  hash2enc(query,
	   &enc);
  LOG(LOG_DEBUG,
      _("Indexed file disappeared, deleting block for query `%s'\n"),
      &enc);
#endif
  /* schedule for "immediate" execution */
  addCronJob((CronJob) &asyncDelJob,
	     0,
	     0,
	     job);
}

/**
 * A query on the datastore resulted in the on-demand
 * block dbv.  On-demand encode the block and return
 * the resulting DSV in enc.  If the on-demand
 * encoding fails because the file is no longer there,
 * this function also removes the OD-Entry
 *
 * @return OK on success, SYSERR if there was an error
 */
int ONDEMAND_getIndexed(Datastore_ServiceAPI * datastore,
			const Datastore_Value * dbv,
			const HashCode512 * query,
			Datastore_Value ** enc) {
  char * fn;
  char * iobuf;
  int blen;
  int fileHandle;
  int ret;
  OnDemandBlock * odb;
  DBlock * db;

  if (ntohl(dbv->size) != sizeof(OnDemandBlock)) {
    BREAK();
    return SYSERR;
  }
  odb = (OnDemandBlock*) dbv;
  fn = getOnDemandFile(&odb->fileId);

  fileHandle = fileopen(fn,
#ifdef O_LARGEFILE
			O_LARGEFILE |
#endif
			O_RDONLY,
			0);
  if (fileHandle == -1) {
    char unavail_key[256];
    EncName enc;
    cron_t * first_unavail;
    struct stat linkStat;

    LOG_FILE_STRERROR(LOG_ERROR, "open", fn);

    /* Is the symlink there? */
    if (LSTAT(fn, &linkStat) == -1) {
      asyncDelete(datastore, dbv, query);
    } else {
      /* For how long has the file been unavailable? */
      hash2enc(&odb->fileId,
	       &enc);
      SNPRINTF(unavail_key,
	       256,
	       "FIRST_UNVAILABLE-%s",
	       (char *) &enc);
      if (stateReadContent(unavail_key,
			   (void *) &first_unavail) == SYSERR) {
        unsigned long long now = htonll(cronTime(NULL));
        stateWriteContent(unavail_key, sizeof(cron_t), (void *) &now);
      } else {
        /* Delete it after 3 days */
        if (*first_unavail - cronTime(NULL) > 3 * cronDAYS) {
	  unsigned int len;
	  char * ofn;
	  int ret;

	  len = 256;
	  ofn = MALLOC(len);
	  while ( ((ret = READLINK(fn, ofn, len)) == -1) &&
		  (errno == ENAMETOOLONG) &&
		  (len < 4 * 1024 * 1024) )
	    if (len * 2 < len) {
	      BREAK();
	      GROW(ofn, len, 0);
	      FREE(fn);
	      return SYSERR;
	    }
	    GROW(ofn,
		 len,
		 len*2);
	  	
          if (ret != -1) {
            LOG(LOG_ERROR,
		_("Because the file `%s' has been unavailable for 3 days"
		  " it got removed from your share.  Please unindex files before"
		  " deleting them as the index now contains invalid references!\n"),
		ofn);
	  }
	  FREE(ofn);
	  asyncDelete(datastore, dbv, query);
          stateUnlinkFromDB(unavail_key);
          UNLINK(fn);
        }
      }
    }

    FREE(fn);
    return SYSERR;
  }

#if TRACK_INDEXED_FILES
  {
    FILE * fp;
    char * afsDir;
    char * scratch;
    int n;

    afsDir = getFileName("FS",
			 "DIR",
			 _("Configuration file must specify directory for"
			   " storage of FS data in section `%s'"
			   " under `%s'.\n"));
    n = strlen(afsDir)+strlen(TRACKFILE)+8;
    scratch = MALLOC(n);
    SNPRINTF(scratch,
	     n,
	     "%s/%s", afsDir, TRACKFILE);
    fp = FOPEN(scratch, "a");
    FPRINTF(fp,
	    "%u %llu\n",
	    ntohs(ce->fileNameIndex),
	    (unsigned long long)TIME(NULL));
    fclose(fp);
    FREE(scratch);
    FREE(afsDir);
  }
#endif
  if (ntohll(odb->fileOffset) != lseek(fileHandle,
				       ntohll(odb->fileOffset),
				       SEEK_SET)) {
    LOG_FILE_STRERROR(LOG_WARNING, "lseek", fn);
    FREE(fn);
    closefile(fileHandle);
    return SYSERR;
  }
  db = MALLOC(sizeof(DBlock) + ntohl(odb->blockSize));
  db->type = htonl(D_BLOCK);
  iobuf = (char*) &db[1];
  blen = READ(fileHandle,
	      iobuf,
	      ntohl(odb->blockSize));
  if (blen != ntohl(odb->blockSize)) {
    LOG_FILE_STRERROR(LOG_ERROR, "read", fn);
    FREE(fn);
    FREE(db);
    closefile(fileHandle);
    return SYSERR;
  }
  closefile(fileHandle);
  ret = fileBlockEncode(db,
			ntohl(odb->blockSize) + sizeof(DBlock),
			query,
			enc);
  FREE(db);
  FREE(fn);
  if (ret == SYSERR) {
    BREAK();
    return SYSERR;
  }

  (*enc)->anonymityLevel = dbv->anonymityLevel;
  (*enc)->expirationTime = dbv->expirationTime;
  (*enc)->prio = dbv->prio;
  return OK;
}

/**
 * Test if the file with the given ID is
 * indexed.
 * @return YES if so, NO if not.
 */
int ONDEMAND_testindexed(Datastore_ServiceAPI * datastore,
			 const HashCode512 * fileId) {
  char * fn;
  int fd;

  fn = getOnDemandFile(fileId);
  fd = fileopen(fn,
	    O_RDONLY);
  FREE(fn);
  if(fd == -1)
    return NO;
  closefile(fd);
  return YES;
}


/**
 * If the data portion and type of the value match our value in the
 * closure, copy the header (prio, anonymityLevel, expirationTime) and
 * abort the iteration: we found what we're looing for.  Otherwise
 * continue.
 */
static int completeValue(const HashCode512 * key,
			 const Datastore_Value * value,
			 void * closure) {
  Datastore_Value * comp = closure;

  if ( (comp->size != value->size) ||
       (0 != memcmp(&value[1],
		    &comp[1],
		    ntohl(value->size) - sizeof(Datastore_Value))) ) {
#if DEBUG_ONDEMAND
    LOG(LOG_DEBUG,
	"`%s' found value that does not match (%u, %u).\n",
	__FUNCTION__,
	ntohl(comp->size),
	ntohl(value->size));
#endif
    return OK;
  }
  *comp = *value; /* make copy! */
#if DEBUG_ONDEMAND
  LOG(LOG_DEBUG,
      "`%s' found value that matches.\n",
      __FUNCTION__);
#endif
  return SYSERR;
}

/**
 * Unindex the file with the given ID.  Removes the file from the
 * filesystem and all of the corresponding obd blocks from the
 * datastore.  Note that the IBlocks are NOT removed by this function.
 *
 * @param blocksize the size of each of the
 *        indexed blocks (required to break
 *        up the file properly when computing
 *        the keys of the odb blocks).
 */
int ONDEMAND_unindex(Datastore_ServiceAPI * datastore,
		     unsigned int blocksize,
		     const HashCode512 * fileId) {
  char * fn;
  int fd;
  int ret;
  OnDemandBlock odb;
  HashCode512 key;
  unsigned long long pos;
  unsigned long long size;
  unsigned long long delta;
  DBlock * block;
  EncName enc;
  char unavail_key[256];

  fn = getOnDemandFile(fileId);
#if DEBUG_ONDEMAND
  LOG(LOG_DEBUG,
      "Removing on-demand encoded data stored in `%s'.\n",
      fn);
#endif
  fd = fileopen(fn,
#ifdef O_LARGEFILE
	    O_RDONLY | O_LARGEFILE,
#else
	    O_RDONLY,
#endif
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); /* 644 */
  if(fd == -1) {
    LOG_FILE_STRERROR(LOG_ERROR, "open", fn);
    FREE(fn);
    return SYSERR;
  }
  pos = 0;
  if (OK != getFileSize(fn,
			&size)) {
    FREE(fn);
    return SYSERR;
  }
  block = MALLOC(sizeof(DBlock) + blocksize);
  block->type = htonl(D_BLOCK);
  while (pos < size) {
    delta = size - pos;
    if (delta > blocksize)
      delta = blocksize;
    if (delta != READ(fd,
		      &block[1],
		      delta)) {
      LOG_FILE_STRERROR(LOG_ERROR, "read", fn);
      closefile(fd);
      FREE(fn);
      FREE(block);
      return SYSERR;
    }
    odb.header.size = htonl(sizeof(OnDemandBlock));
    odb.header.type = htonl(ONDEMAND_BLOCK);
    odb.header.prio = 0;
    odb.header.anonymityLevel = 0;
    odb.header.expirationTime = 0;
    odb.type = htonl(ONDEMAND_BLOCK);
    odb.fileOffset = htonll(pos);
    odb.blockSize = htonl(delta);
    odb.fileId = *fileId;
    /* compute the primary key */
    fileBlockGetQuery(block,
		      delta + sizeof(DBlock),
		      &key);
    if (SYSERR == datastore->get(&key,
				 ONDEMAND_BLOCK,
				 &completeValue,
				 &odb.header)) /* aborted == found! */
      ret = datastore->del(&key,
			   &odb.header);
    else /* not found */
      ret = SYSERR;
    if (ret == SYSERR) {
      IFLOG(LOG_WARNING,
	    hash2enc(&key,
		     &enc));
      LOG(LOG_WARNING,
	  _("Unindexed ODB block `%s' from offset %llu already missing from datastore.\n"),
	  &enc,
	  pos);
    }
    pos += delta;
  }
  FREE(block);
  closefile(fd);
  UNLINK(fn);

  /* Remove information about unavailability */
  hash2enc(fileId,
	   &enc);
  SNPRINTF(unavail_key,
	   256,
	   "FIRST_UNAVAILABLE-%s",
	   (char*)&enc);
  stateUnlinkFromDB(unavail_key);


  FREE(fn);
  return OK;
}

int ONDEMAND_init() {
  char * tmp;


  tmp
    = getConfigurationString("FS",
			     "INDEX-DIRECTORY");
  if (NULL == tmp) {
    tmp = getConfigurationString("GNUNETD",
				 "GNUNETD_HOME");
    GNUNET_ASSERT(NULL != tmp);
    tmp = REALLOC(tmp,
			      strlen(tmp) +
			      strlen("/data/shared/") + 1);
    strcat(tmp, "/data/shared/");
  }
  index_directory = expandFileName(tmp);
  FREE(tmp);
  mkdirp(index_directory); /* just in case */  
  return OK;
}

int ONDEMAND_done() {
  FREE(index_directory);
  return OK;
}

/* end of ondemand.c */
