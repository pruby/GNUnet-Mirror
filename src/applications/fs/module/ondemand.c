/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/fileindex.c
 * @brief access to the list of indexed files
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "ecrs_core.h"
#include "ondemand.h"

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
  HashCode160 fileId;
  
} OnDemandBlock;

static char * getOnDemandFile(const HashCode160 * fileId) {
  EncName enc;
  char * fn;
  char * dir;

  dir = getFileName("FS",
		    "INDEX-DIRECTORY",
		    _("You must specify a directory for FS files in the"
		      " configuration in section '%s' under '%s'."));
  mkdirp(dir); /* just in case */
  hash2enc(fileId,
	   &enc);
  fn = MALLOC(strlen(dir) + sizeof(EncName) + 1);
  strcpy(fn, dir);
  FREE(dir);
  strcat(fn, "/");
  strcat(fn, (char*) &enc);
  return fn;
}


/**
 * Test if the 'closure' OnDemandBlock is already
 * present in the datastore.  Presence is indicated
 * by aborting the iteration.
 */
static int checkPresent(const HashCode160 * key,
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
 * Writes the given content to the file at the specified offset
 * and stores an OnDemandBlock into the datastore.
 *
 *
 *
 * @return NO if already present, YES on success,
 *  SYSERR on other error (i.e. datastore full)
 */
int ONDEMAND_index(Datastore_ServiceAPI * datastore,
		   unsigned int prio,
		   cron_t expiration,
		   unsigned long long fileOffset,
		   unsigned int anonymityLevel,
		   const HashCode160 * fileId,
		   unsigned int size,
		   const DBlock * content) {
  char * fn;
  int fd;
  int ret;
  OnDemandBlock odb;
  HashCode160 key;

  if (size <= sizeof(DBlock)) {
    BREAK();
    return SYSERR;
  }
  fn = getOnDemandFile(fileId);
  fd = OPEN(fn, 
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
  CLOSE(fd);
  FREE(fn);
  if (ret == SYSERR)
    return ret;

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
			const HashCode160 * query,
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
    goto FAILURE;
  }
  odb = (OnDemandBlock*) dbv;
  fn = getOnDemandFile(&odb->fileId);

  fileHandle = OPEN(fn, O_EXCL, S_IRUSR);
  if (fileHandle == -1) {
    LOG_FILE_STRERROR(LOG_ERROR, "open", fn);
    FREE(fn);
    goto FAILURE;
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
			   " storage of FS data in section '%s'"
			   " under '%s'.\n"));
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
  if (ntohll(odb->fileOffset) != lseek(fileHandle, 
				       ntohll(odb->fileOffset), 
				       SEEK_SET)) {
    LOG_FILE_STRERROR(LOG_WARNING, "lseek", fn);
    FREE(fn);
    CLOSE(fileHandle);
    goto FAILURE;
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
    CLOSE(fileHandle);
    goto FAILURE;
  }
  ret = fileBlockEncode(db,
			ntohl(odb->blockSize) + sizeof(DBlock),
			query,
			enc);  
  FREE(db);
  FREE(fn);
  if (ret == SYSERR)
    goto FAILURE;
  return OK;   
 FAILURE:
  datastore->del(query,
		 dbv);
  return SYSERR;
}

/**
 * Test if the file with the given ID is
 * indexed.
 * @return YES if so, NO if not.
 */
int ONDEMAND_testindexed(Datastore_ServiceAPI * datastore,
			 const HashCode160 * fileId) {
  char * fn;
  int fd;

  fn = getOnDemandFile(fileId);
  fd = OPEN(fn, 
	    O_RDONLY);
  FREE(fn);
  if(fd == -1) 
    return NO;
  CLOSE(fd);
  return YES;
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
		     const HashCode160 * fileId) {
  char * fn;
  int fd;
  int ret;
  OnDemandBlock odb;
  HashCode160 key;
  unsigned long long pos;
  unsigned long long size;
  unsigned long long delta;
  char * block;

  fn = getOnDemandFile(fileId);
  fd = OPEN(fn, 
	    O_RDONLY,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); /* 644 */
  if(fd == -1) {    
    LOG_FILE_STRERROR(LOG_ERROR, "open", fn);
    FREE(fn);
    return SYSERR;
  }
  pos = 0;
  size = getFileSize(fn);
  block = MALLOC(blocksize);
  while (pos < size) {
    delta = size - pos;
    if (delta > blocksize)
      delta = blocksize;
    if (delta != READ(fd,
		      block,
		      delta)) {
      LOG_FILE_STRERROR(LOG_ERROR, "read", fn);
      CLOSE(fd);
      FREE(fn);
      FREE(block);
      return SYSERR;
    }
    odb.header.size = htonl(sizeof(OnDemandBlock));
    odb.header.type = htonl(ONDEMAND_BLOCK);
    odb.header.prio = 0;
    odb.header.anonymityLevel = 0;
    odb.header.expirationTime = 0;
    odb.fileOffset = htonll(pos);
    odb.blockSize = htonl(delta);
    odb.fileId = *fileId;
    /* compute the primary key */
    fileBlockGetQuery(block,
		      delta,
		      &key);  
    ret = datastore->del(&key,
			 &odb.header);
    if (ret == SYSERR) {
      LOG(LOG_DEBUG,
	  "ODB block from offset %llu already missing from datastore.\n",
	  pos);
    }
    pos += delta;
  }
  FREE(block);
  CLOSE(fd);
  UNLINK(fn);
  FREE(fn);
  return OK;
}


/* end of ondemand.c */
