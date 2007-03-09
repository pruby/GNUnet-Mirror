/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @see http://gnunet.org/encoding.php3
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

#define DEBUG_UPLOAD NO

/**
 * Append the given key and query to the iblock[level].  If
 * iblock[level] is already full, compute its chk and push it to
 * level+1 and clear the level.  iblocks is guaranteed to be big
 * enough.
 */
static int pushBlock(struct ClientServerConnection * sock,
                     const CHK * chk,
                     unsigned int level,
                     Datastore_Value ** iblocks,
		     unsigned int prio,
		     cron_t expirationTime) {
  unsigned int size;
  unsigned int present;
  Datastore_Value * value;
  DBlock * db;
  CHK ichk;
#if DEBUG_UPLOAD
  EncName enc;
#endif

  size = ntohl(iblocks[level]->size);
  GE_ASSERT(NULL, size > sizeof(Datastore_Value));
  size -= sizeof(Datastore_Value);
  GE_ASSERT(NULL, size - sizeof(DBlock) <= IBLOCK_SIZE);
  present = (size - sizeof(DBlock)) / sizeof(CHK);
  db = (DBlock*) &iblocks[level][1];
  if (present == CHK_PER_INODE) {
    fileBlockGetKey(db,
                    size,
                    &ichk.key);
    fileBlockGetQuery(db,
                      size,
                      &ichk.query);
    if (OK != pushBlock(sock,
                        &ichk,
                        level+1,
                        iblocks,
			prio,
			expirationTime))
      return SYSERR;
    fileBlockEncode(db,
                    size,
                    &ichk.query,
                    &value);
    if (value == NULL) {
      GE_BREAK(NULL, 0);
      return SYSERR;
    }
    value->prio = htonl(prio);
    value->expirationTime = htonll(expirationTime);
    if (OK != FS_insert(sock,
                        value)) {
      FREE(value);
      return SYSERR;
    }
    FREE(value);
    size = sizeof(DBlock); /* type */
  }
  /* append CHK */
  memcpy(&((char*)db)[size],
         chk,
         sizeof(CHK));
  size += sizeof(CHK) + sizeof(Datastore_Value);
  GE_ASSERT(NULL, size < MAX_BUFFER_SIZE);
  iblocks[level]->size = htonl(size);

  return OK;
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
int ECRS_uploadFile(struct GE_Context * ectx,
		    struct GC_Configuration * cfg,
		    const char * filename,
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
  DBlock * db;
  Datastore_Value * value;
  struct ClientServerConnection * sock;
  HashCode512 fileId;
  CHK mchk;
  cron_t eta;
  cron_t start;
  cron_t now;
  FileIdentifier fid;
#if DEBUG_UPLOAD
  EncName enc;
#endif

  GE_ASSERT(ectx, cfg != NULL);
  start = get_time();
  memset(&mchk, 0, sizeof(CHK));
  if (YES != disk_file_test(ectx,
			    filename)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("`%s' is not a file.\n"),
	   filename);
    return SYSERR;
  }
  if (OK != disk_file_size(ectx,
			   filename,
			   &filesize,
			   YES)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("Cannot get size of file `%s'"),
	   filename);

    return SYSERR;
  }
  sock = client_connection_create(ectx, cfg);
  if (sock == NULL) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("Failed to connect to gnunetd."));
    return SYSERR;
  }
  eta = 0;
  if (upcb != NULL)
    upcb(filesize, 0, eta, upcbClosure);
  if (doIndex) {
    if (SYSERR == getFileHash(ectx,
			      filename,
                              &fileId)) {
      GE_LOG(ectx,
	     GE_ERROR | GE_BULK | GE_USER,
	     _("Cannot hash `%s'.\n"),
	     filename);
      connection_destroy(sock);
      return SYSERR;
    }
    now = get_time();
    eta = now + 2 * (now - start);
    /* very rough estimate: hash reads once through the file,
       we'll do that once more and write it.  But of course
       the second read may be cached, and we have the encryption,
       so a factor of two is really, really just a rough estimate */
    start = now;
    /* reset the counter since the formula later does not
       take the time for getFileHash into account */

    switch (FS_initIndex(sock, &fileId, filename)) {
    case SYSERR:
      GE_LOG(ectx,
	     GE_ERROR | GE_BULK | GE_USER,
	     _("Initialization for indexing file `%s' failed.\n"),
	     filename);
      connection_destroy(sock);
      return SYSERR;
    case NO:
      GE_LOG(ectx,
	     GE_ERROR | GE_BULK | GE_USER,
	     _("Indexing file `%s' failed. Trying to insert file...\n"),
	     filename);
      doIndex = YES;
      break;
    default:
      break;
    }
  }
  treedepth = computeDepth(filesize);
  fd = disk_file_open(ectx,
		      filename,
		      O_RDONLY | O_LARGEFILE);
  if (fd == -1) {
    GE_LOG(ectx,
     GE_ERROR | GE_BULK | GE_USER,
     _("Cannot open file `%s': `%s'"),
     filename,
     STRERROR(errno));

    connection_destroy(sock);
    return SYSERR;
  }

  dblock = MALLOC(sizeof(Datastore_Value) + DBLOCK_SIZE + sizeof(DBlock));
  dblock->size = htonl(sizeof(Datastore_Value) + DBLOCK_SIZE + sizeof(DBlock));
  dblock->anonymityLevel = htonl(anonymityLevel);
  dblock->prio = htonl(priority);
  dblock->type = htonl(D_BLOCK);
  dblock->expirationTime = htonll(expirationTime);
  db = (DBlock*) &dblock[1];
  db->type = htonl(D_BLOCK);
  iblocks = MALLOC(sizeof(Datastore_Value*) * (treedepth+1));
  for (i=0;i<=treedepth;i++) {
    iblocks[i] = MALLOC(sizeof(Datastore_Value) + IBLOCK_SIZE + sizeof(DBlock));
    iblocks[i]->size = htonl(sizeof(Datastore_Value) + sizeof(DBlock));
    iblocks[i]->anonymityLevel = htonl(anonymityLevel);
    iblocks[i]->prio = htonl(priority);
    iblocks[i]->type = htonl(D_BLOCK);
    iblocks[i]->expirationTime = htonll(expirationTime);
    ((DBlock*) &iblocks[i][1])->type = htonl(D_BLOCK);
  }

  pos = 0;
  while (pos < filesize) {
    if (upcb != NULL)
      upcb(filesize, pos, eta, upcbClosure);
    if (tt != NULL)
      if (OK != tt(ttClosure))
        goto FAILURE;
    size = DBLOCK_SIZE;
    if (size > filesize - pos) {
      size = filesize - pos;
      memset(&db[1],
             0,
             DBLOCK_SIZE);
    }
    GE_ASSERT(ectx,
	      sizeof(Datastore_Value) + size + sizeof(DBlock) < MAX_BUFFER_SIZE);
    dblock->size = htonl(sizeof(Datastore_Value) + size + sizeof(DBlock));
    if (size != READ(fd,
                     &db[1],
                     size)) {
      GE_LOG_STRERROR_FILE(ectx,
			   GE_ERROR | GE_BULK | GE_ADMIN | GE_USER,
			   "READ",
			   filename);
      goto FAILURE;
    }
    if (tt != NULL)
      if (OK != tt(ttClosure))
        goto FAILURE;
    fileBlockGetKey(db,
                    size + sizeof(DBlock),
                    &mchk.key);
    fileBlockGetQuery(db,
                      size + sizeof(DBlock),
                      &mchk.query);
#if DEBUG_UPLOAD
    IF_GELOG(ectx,
	     GE_DEBUG | GE_REQUEST | GE_USER,
	     hash2enc(&mchk.query,
		      &enc));
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Query for current block of size %u is %s\n",
	   size,
	   &enc);
#endif
    if (doIndex) {
      if (SYSERR == FS_index(sock,
                             &fileId,
                             dblock,
                             pos)) {
	GE_LOG(ectx,
	       GE_ERROR | GE_BULK | GE_USER,
	       _("Indexing data failed at position %i.\n"), pos);
	goto FAILURE;
      }
    } else {
      value = NULL;
      if (OK !=
          fileBlockEncode(db,
                          size + sizeof(DBlock),
                          &mchk.query,
                          &value)) {
        GE_BREAK(ectx, 0);
        goto FAILURE;
      }
      GE_ASSERT(ectx, value != NULL);
      *value = *dblock; /* copy options! */

      if (SYSERR == FS_insert(sock,
                              value)) {
        GE_BREAK(ectx, 0);
        FREE(value);
        goto FAILURE;
      }
      FREE(value);
    }
    pos += size;
    now = get_time();
    if (pos > 0) {
      eta = (cron_t) (start +
                      (((double)(now - start)/(double)pos))
                      * (double)filesize);
    }
    if (OK != pushBlock(sock,
                        &mchk,
                        0, /* dblocks are on level 0 */
                        iblocks,
			priority,
			expirationTime)) {
      GE_BREAK(ectx, 0);
      goto FAILURE;
    }
  }
  if (tt != NULL)
    if (OK != tt(ttClosure))
      goto FAILURE;
#if DEBUG_UPLOAD
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Tree depth is %u, walking up tree.\n",
	 treedepth);
#endif
  for (i=0;i<treedepth;i++) {
    size = ntohl(iblocks[i]->size) - sizeof(Datastore_Value);
    GE_ASSERT(ectx, size < MAX_BUFFER_SIZE);
    if (size == sizeof(DBlock)) {
#if DEBUG_UPLOAD
      GE_LOG(ectx,
	     GE_DEBUG | GE_REQUEST | GE_USER,
	     "Level %u is empty\n",
	     i);
#endif
      continue;
    }
    db = (DBlock*) &iblocks[i][1];
    fileBlockGetKey(db,
                    size,
                    &mchk.key);
#if DEBUG_UPLOAD
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Computing query for %u bytes content.\n",
	   size);
#endif
    fileBlockGetQuery(db,
                      size,
                      &mchk.query);
#if DEBUG_UPLOAD
    IF_GELOG(ectx,
	     GE_DEBUG | GE_REQUEST | GE_USER,
	     hash2enc(&mchk.query,
		      &enc));
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Query for current block at level %u is `%s'.\n",
	   i,
	   &enc);
#endif
    if (OK != pushBlock(sock,
                        &mchk,
                        i+1,
                        iblocks,
			priority,
			expirationTime)) {
      GE_BREAK(ectx, 0);
      goto FAILURE;
    }
    fileBlockEncode(db,
                    size,
                    &mchk.query,
                    &value);
    if (value == NULL) {
      GE_BREAK(ectx, 0);
      goto FAILURE;
    }
    value->expirationTime = htonll(expirationTime);
    value->prio = htonl(priority);
    if (OK != FS_insert(sock,
                        value)) {
      GE_BREAK(ectx, 0);
      FREE(value);
      goto FAILURE;
    }
    FREE(value);
    FREE(iblocks[i]);
    iblocks[i] = NULL;
  }
#if DEBUG_UPLOAD
  IF_GELOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
        hash2enc(&mchk.query,
                 &enc));
  GE_LOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
      "Query for top block is %s\n",
      &enc);
#endif
  /* build URI */
  fid.file_length = htonll(filesize);
  db = (DBlock*) &iblocks[treedepth][1];

  fid.chk = *(CHK*)&(db[1]);
  *uri = MALLOC(sizeof(URI));
  (*uri)->type = chk;
  (*uri)->data.fi = fid;

  /* free resources */
  FREENONNULL(iblocks[treedepth]);
  FREE(iblocks);
  FREE(dblock);
  if (upcb != NULL)
    upcb(filesize, filesize, eta, upcbClosure);
  CLOSE(fd);
  connection_destroy(sock);
  return OK;
 FAILURE:
  for (i=0;i<=treedepth;i++)
    FREENONNULL(iblocks[i]);
  FREE(iblocks);
  FREE(dblock);
  CLOSE(fd);
  connection_destroy(sock);
  return SYSERR;
}

/* end of upload.c */
