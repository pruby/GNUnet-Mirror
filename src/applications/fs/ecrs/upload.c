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
 * @file applications/fs/ecrs/upload.c
 * @brief Break file that is inserted into blocks and encrypts
 *        them according to the ECRS scheme.
 * @see http://www.ovmj.org/GNUnet/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "gnunet_getoption_lib.h"
#include "gnunet_protocols.h"
#include "ecrs.h"
#include "ecrs_core.h"
#include "uri.h"
#include "tree.h"

/**
 * Append the given key and query to the iblock[level].
 * If iblock[level] is already full, compute its chk
 * and push it to level+1.  iblocks is guaranteed to
 * be big enough.
 */
static int pushBlock(GNUNET_TCP_SOCKET * sock,
		     const CHK * chk,	
		     unsigned int level,
		     Datastore_Value ** iblocks) {
  unsigned int size;
  unsigned int present;
  Datastore_Value * value;
  CHK ichk;

  size = ntohl(iblocks[level]->size) - sizeof(Datastore_Value);
  present = size / sizeof(CHK);
  if (present == CHK_PER_INODE) {
    fileBlockGetKey((char*) &iblocks[level][1],
		    size,
		    &ichk.key);
    fileBlockGetQuery((char*) &iblocks[level][1],
		      size,
		      &ichk.query);
    if (OK != pushBlock(sock, &ichk, level+1, iblocks))
      return SYSERR;
    fileBlockEncode((char*) &iblocks[level][1],
		    size,
		    &ichk.query,
		    &value);
    if (OK != FS_insert(sock,
			value)) {
      FREE(value);
      return SYSERR;
    }
    FREE(value);
    size = 0;
  }
  /* append CHK */
  memcpy(&((char*)&iblocks[level][1])[size],
	 chk,
	 sizeof(CHK));
  iblocks[level]->size = htonl(size + sizeof(Datastore_Value));
  return OK;
}

/**
 * sym-linking operation (if allowed by config): 
 * a) check if hash matches,
 * b) rename old file (fn)
 * c) symlink filename to target, if fails,
 *    undo renaming (and abort)
 * d) delete old file
 */
static void trySymlinking(const char * fn,
			  const HashCode160 * fileId,
			  GNUNET_TCP_SOCKET * sock) {
  EncName enc;
  char * serverDir;
  char * serverFN;
  char * tmpName;
  HashCode160 serverFileId;

  if (testConfigurationString("AFS",
			      "DISABLE-SYMLINKING",
			      "YES"))
    return;
  serverDir 
    = getConfigurationOptionValue(sock,
				  "AFS",
				  "INDEX-DIRECTORY");
  if (serverDir == NULL)
    return;
  serverFN = MALLOC(strlen(serverDir) + 2 + sizeof(EncName));
  strcpy(serverFN,
	 serverDir);
  FREE(serverDir);
  strcat(serverFN,
	 DIR_SEPARATOR_STR);
  hash2enc(fileId,
	   &enc);
  strcat(serverFN,
	 (char*)&enc);
  if (OK != getFileHash(serverFN,
			&serverFileId)) {
    FREE(serverFN);
    return;
  }
  if (! equalsHashCode160(&serverFileId,
			  fileId)) {
    BREAK(); /* rather odd... */
    return;
  }
  tmpName = MALLOC(strlen(fn) + 4);
  strcpy(tmpName, fn);
  strcat(tmpName, "_");
  if (0 != RENAME(fn,
		  tmpName)) {
    LOG_FILE_STRERROR(LOG_ERROR, "rename", fn);
    FREE(tmpName);
    FREE(serverFN);
    return;
  }
  if (0 != SYMLINK(serverFN,
		   fn)) {
    LOG_FILE_STRERROR(LOG_ERROR, "symlink", fn);
    if (0 != RENAME(tmpName,
		    fn)) {
      /* oops, error recovery failed, how can this happen??? 
	 Well, at least let's give the user some good warning... */
      LOG_FILE_STRERROR(LOG_ERROR, "rename", fn);
      LOG(LOG_NOTHING,
	  _("RISK OF DATA LOSS, READ THIS: "
	    "I failed to symlink a file and then failed to"
	    " rename your original file back to its original name.  "
	    "You should find your file '%s' under the new name '%s'."),
	  fn,
	  tmpName);
      BREAK();
    }
    FREE(tmpName);
    FREE(serverFN);
    return;
  }
  if (0 != UNLINK(tmpName)) 
    LOG_FILE_STRERROR(LOG_ERROR, "unlink", tmpName);
  FREE(tmpName);
  FREE(serverFN);
}


/**
 * Index or insert a file.
 *
 * @param priority what is the priority for OUR node to
 *   keep this file available?  Use 0 for maximum anonymity and
 *   minimum reliability...
 * @param doIndex YES for index, NO for insertion
 * @param uri set to the URI of the uploaded file
 * @return SYSERR if the upload failed (i.e. not enough space
 *  or gnunetd not running)
 */
int ECRS_uploadFile(const char * filename,
		    int doIndex,
		    unsigned int anonymityLevel,
		    unsigned int priority,
		    cron_t expirationTime,
		    ECRS_UploadProgressCallback upcb,
		    void * upcbClosure,
		    ECRS_TestTerminate tt,
		    void * ttClosure,
		    struct ECRS_URI ** uri) {
  unsigned long long filesize;
  unsigned long long pos;
  unsigned int treedepth;
  int fd;
  int i;
  unsigned int size;
  Datastore_Value ** iblocks;
  Datastore_Value * dblock;
  Datastore_Value * value;
  GNUNET_TCP_SOCKET * sock;
  HashCode160 fileId;
  CHK chk;
  cron_t eta;
  cron_t start;
  cron_t now;
  char * uris;
  FileIdentifier fid; 

  cronTime(&start);
  if (isDirectory(filename)) {
    BREAK();
    return SYSERR;
  }
  if (0 == assertIsFile(filename)) {
    BREAK();
    return SYSERR;
  }
  sock = getClientSocket();
  if (sock == NULL) 
    return SYSERR;  
  filesize = getFileSize(filename);
  eta = 0;
  if (upcb != NULL)
    upcb(filesize, 0, eta, upcbClosure);
  if (doIndex) {
    if (SYSERR == getFileHash(filename,
			      &fileId)) {
      releaseClientSocket(sock);
      return SYSERR;
    }
    cronTime(&now);
    eta = now + 2 * (now - start); 
    /* very rough estimate: hash reads once through the file,
       we'll do that once more and write it.  But of course
       the second read may be cached, and we have the encryption,
       so a factor of two is really, really just a rough estimate */
    start = now;
    /* reset the counter since the formula later does not
       take the time for getFileHash into account */
  }
  treedepth = computeDepth(filesize);

#ifdef O_LARGEFILE
  fd = OPEN(filename, O_RDONLY | O_LARGEFILE);
#else
  fd = OPEN(filename, O_RDONLY);
#endif
  if (fd == -1) {
    LOG_FILE_STRERROR(LOG_WARNING, "OPEN", filename);
    return SYSERR;
  }
  dblock = MALLOC(sizeof(Datastore_Value) + DBLOCK_SIZE);
  dblock->size = htonl(sizeof(Datastore_Value) + DBLOCK_SIZE);
  dblock->anonymityLevel = htonl(anonymityLevel);
  dblock->prio = htonl(priority);
  dblock->type = htonl(D_BLOCK);
  dblock->expirationTime = htonll(expirationTime);
  iblocks = MALLOC(sizeof(Datastore_Value*) * treedepth);
  for (i=0;i<treedepth;i++) {
    iblocks[i] = MALLOC(sizeof(Datastore_Value) + IBLOCK_SIZE);
    iblocks[i]->size = htonl(sizeof(Datastore_Value));
    iblocks[i]->anonymityLevel = htonl(anonymityLevel);
    iblocks[i]->prio = htonl(priority);
    iblocks[i]->type = htonl(I_BLOCK);
    iblocks[i]->expirationTime = htonll(expirationTime);
  }

  pos = 0;
  while (pos < filesize) {
    if (upcb != NULL)
      upcb(filesize, pos, eta, upcbClosure);
    if (tt != NULL)
      if (OK != tt(ttClosure))
	goto ERROR;
    size = DBLOCK_SIZE;
    if (size > filesize - pos) {
      size = filesize - pos;
      memset(&dblock[1], 0, DBLOCK_SIZE);
    }
    if (size != READ(fd, &dblock[1], size)) {
      LOG_FILE_STRERROR(LOG_WARNING, "READ", filename);
      goto ERROR;
    }   
    size = DBLOCK_SIZE; /* padding! */
    if (tt != NULL)
      if (OK != tt(ttClosure))
	goto ERROR;
    fileBlockGetKey((char*) &dblock[1],
		    size,
		    &chk.key);
    fileBlockGetQuery((char*) &dblock[1],
		      size,
		      &chk.query);
    if (OK != pushBlock(sock,
			&chk,
			0, /* dblocks are on level 0 */
			iblocks))
      goto ERROR;
    if (doIndex) {
      if (OK != FS_index(sock,
			 &fileId,
			 dblock,
			 pos))
	goto ERROR;
    } else {
      fileBlockEncode((char*) &dblock[1],
		      size,
		      &chk.query,
		      &value);
      *value = *dblock; /* copy options! */
      if (OK != FS_insert(sock,
			  value)) {
	FREE(value);
	goto ERROR;
      }
      FREE(value);
    }
    pos += size;
    cronTime(&now);
    eta = (cron_t) (start +
		    (((double)(now - start)/(double)pos)) 
		    * (double)filesize);
  }
  if (tt != NULL)
    if (OK != tt(ttClosure))
      goto ERROR;  
  for (i=0;i<treedepth;i++) {
    size = ntohl(iblocks[i]->size) - sizeof(Datastore_Value);
    fileBlockGetKey((char*) &iblocks[i],
		    size,
		    &chk.key);
    fileBlockGetQuery((char*) &iblocks[i],
		      size,
		      &chk.query);   
    if (OK != pushBlock(sock, 
			&chk,
			i+1, 
			iblocks))
      goto ERROR;
    fileBlockEncode((char*) &iblocks[i][1],
		    size,
		    &chk.query,
		    &value);
    if (OK != FS_insert(sock,
			value)) {
      FREE(value);
      goto ERROR;
    }
    FREE(value);
    FREE(iblocks[i]);
    iblocks[i] = NULL;
  }
  if (doIndex) {
    trySymlinking(filename,
		  &fileId,
		  sock);
  }
  /* build URI */
  fid.file_length = htonll(filesize);
  fid.chk = chk;
  uris = createFileURI(&fid);
  *uri = ECRS_stringToUri(uris);
  FREE(uris);

  /* free resources */
  FREE(iblocks);
  FREE(dblock);
  CLOSE(fd);
  releaseClientSocket(sock);
  return OK;
 ERROR:
  for (i=0;i<treedepth;i++)
    FREENONNULL(iblocks[i]);
  FREE(iblocks);
  FREE(dblock);
  CLOSE(fd);
  releaseClientSocket(sock);
  return SYSERR;
}

/* end of upload.c */
