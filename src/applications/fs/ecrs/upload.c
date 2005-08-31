/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
static int pushBlock(GNUNET_TCP_SOCKET * sock,
                     const CHK * chk,
                     unsigned int level,
                     Datastore_Value ** iblocks) {
  unsigned int size;
  unsigned int present;
  Datastore_Value * value;
  DBlock * db;
  CHK ichk;
#if DEBUG_UPLOAD
  EncName enc;
#endif

  size = ntohl(iblocks[level]->size);
  GNUNET_ASSERT(size > sizeof(Datastore_Value));
  size -= sizeof(Datastore_Value);
  GNUNET_ASSERT(size - sizeof(DBlock) <= IBLOCK_SIZE);
  present = (size - sizeof(DBlock)) / sizeof(CHK);
  db = (DBlock*) &iblocks[level][1];
  if (present == CHK_PER_INODE) {
    fileBlockGetKey(db,
                    size,
                    &ichk.key);
    fileBlockGetQuery(db,
                      size,
                      &ichk.query);
#if DEBUG_UPLOAD
    IFLOG(LOG_DEBUG,
          hash2enc(&ichk.query,
                   &enc));
    LOG(LOG_DEBUG,
        "Query for current iblock at level %u is %s\n",
        level,
        &enc);
#endif
    if (OK != pushBlock(sock,
                        &ichk,
                        level+1,
                        iblocks))
      return SYSERR;
    fileBlockEncode(db,
                    size,
                    &ichk.query,
                    &value);
    if (value == NULL) {
      BREAK();
      return SYSERR;
    }
#if DEBUG_UPLOAD
    IFLOG(LOG_DEBUG,
          hash2enc(&ichk.query,
                   &enc));
    LOG(LOG_DEBUG,
        "Publishing block (query: %s)\n",
        &enc);
#endif
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
  GNUNET_ASSERT(size < MAX_BUFFER_SIZE);
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
  DBlock * db;
  Datastore_Value * value;
  GNUNET_TCP_SOCKET * sock;
  HashCode512 fileId;
  CHK chk;
  cron_t eta;
  cron_t start;
  cron_t now;
  char * uris;
  FileIdentifier fid;
#if DEBUG_UPLOAD
  EncName enc;
#endif

  cronTime(&start);
  memset(&chk, 0, sizeof(CHK));
  if (isDirectory(filename)) {
    BREAK();
    /* Should not happen */
    LOG(LOG_ERROR, "Cannot upload file `%s', it seems to be a directory!", filename);
    return SYSERR;
  }
  if (0 == assertIsFile(filename)) {
    LOG(LOG_ERROR,
        _("`%s' is not a file.\n"),
        filename);
    return SYSERR;
  }
  if (OK != getFileSize(filename,
                        &filesize)) {
    LOG(LOG_ERROR, _("Cannot get size of file `%s'"), filename);

    return SYSERR;
  }
  sock = getClientSocket();
  if (sock == NULL) {
    LOG(LOG_ERROR, _("Not connected to gnunetd."));

    return SYSERR;
  }
  eta = 0;
  if (upcb != NULL)
    upcb(filesize, 0, eta, upcbClosure);
  if (doIndex) {
    if (SYSERR == getFileHash(filename,
                              &fileId)) {
      LOG(LOG_ERROR,
          _("Cannot hash `%s'.\n"),
          filename);
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

    switch (FS_initIndex(sock, &fileId, filename)) {
    case SYSERR:
      LOG(LOG_ERROR,
          _("Initialization for indexing file `%s' failed.\n"),
          filename);
      releaseClientSocket(sock);
      return SYSERR;
    case NO:
      LOG(LOG_ERROR,
          _("Indexing file `%s' failed. Trying to insert file...\n"),
          filename);
      doIndex = YES;
    }
  }
  treedepth = computeDepth(filesize);

#ifdef O_LARGEFILE
  fd = fileopen(filename, O_RDONLY | O_LARGEFILE);
#else
  fd = fileopen(filename, O_RDONLY);
#endif
  if (fd == -1) {
    LOG_FILE_STRERROR(LOG_WARNING, "OPEN", filename);
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
    GNUNET_ASSERT(sizeof(Datastore_Value) + size + sizeof(DBlock) < MAX_BUFFER_SIZE);
    dblock->size = htonl(sizeof(Datastore_Value) + size + sizeof(DBlock));
    if (size != READ(fd,
                     &db[1],
                     size)) {
      LOG_FILE_STRERROR(LOG_WARNING,
                        "READ",
                        filename);
      goto FAILURE;
    }
    if (tt != NULL)
      if (OK != tt(ttClosure))
        goto FAILURE;
    fileBlockGetKey(db,
                    size + sizeof(DBlock),
                    &chk.key);
    fileBlockGetQuery(db,
                      size + sizeof(DBlock),
                      &chk.query);
#if DEBUG_UPLOAD
    IFLOG(LOG_DEBUG,
          hash2enc(&chk.query,
                   &enc));
    LOG(LOG_DEBUG,
        "Query for current block of size %u is %s\n",
        size,
        &enc);
#endif
    if (doIndex) {
      if (SYSERR == FS_index(sock,
                             &fileId,
                             dblock,
                             pos)) {
                                LOG(LOG_ERROR, _("Indexing data failed at position %i.\n"), pos);
                                goto FAILURE;
                        }
    } else {
      value = NULL;
      if (OK !=
          fileBlockEncode(db,
                          size + sizeof(DBlock),
                          &chk.query,
                          &value))
        goto FAILURE;
      GNUNET_ASSERT(value != NULL);
      *value = *dblock; /* copy options! */
      if (SYSERR == FS_insert(sock,
                              value)) {
        FREE(value);
        goto FAILURE;
      }
      FREE(value);
    }
    pos += size;
    cronTime(&now);
    if (pos > 0) {
      eta = (cron_t) (start +
                      (((double)(now - start)/(double)pos))
                      * (double)filesize);
    }
    if (OK != pushBlock(sock,
                        &chk,
                        0, /* dblocks are on level 0 */
                        iblocks))
      goto FAILURE;
  }
  if (tt != NULL)
    if (OK != tt(ttClosure))
      goto FAILURE;
#if DEBUG_UPLOAD
  LOG(LOG_DEBUG,
      "Tree depth is %u, walking up tree.\n",
      treedepth);
#endif
  for (i=0;i<treedepth;i++) {
    size = ntohl(iblocks[i]->size) - sizeof(Datastore_Value);
    GNUNET_ASSERT(size < MAX_BUFFER_SIZE);
    if (size == sizeof(DBlock)) {
#if DEBUG_UPLOAD
      LOG(LOG_DEBUG,
          "Level %u is empty\n",
          i);
#endif
      continue;
    }
    db = (DBlock*) &iblocks[i][1];
    fileBlockGetKey(db,
                    size,
                    &chk.key);
#if DEBUG_UPLOAD
    LOG(LOG_DEBUG,
        "Computing query for %u bytes content.\n",
        size);
#endif
    fileBlockGetQuery(db,
                      size,
                      &chk.query);
#if DEBUG_UPLOAD
    IFLOG(LOG_DEBUG,
          hash2enc(&chk.query,
                   &enc));
    LOG(LOG_DEBUG,
        "Query for current block at level %u is `%s'.\n",
        i,
        &enc);
#endif
    if (OK != pushBlock(sock,
                        &chk,
                        i+1,
                        iblocks))
      goto FAILURE;
    fileBlockEncode(db,
                    size,
                    &chk.query,
                    &value);
    if (value == NULL) {
      BREAK();
      goto FAILURE;
    }
    if (OK != FS_insert(sock,
                        value)) {
      FREE(value);
      goto FAILURE;
    }
    FREE(value);
    FREE(iblocks[i]);
    iblocks[i] = NULL;
  }
#if DEBUG_UPLOAD
  IFLOG(LOG_DEBUG,
        hash2enc(&chk.query,
                 &enc));
  LOG(LOG_DEBUG,
      "Query for top block is %s\n",
      &enc);
#endif
  /* build URI */
  fid.file_length = htonll(filesize);
  db = (DBlock*) &iblocks[treedepth][1];

  fid.chk = *(CHK*)&(db[1]);
  uris = createFileURI(&fid);
  *uri = ECRS_stringToUri(uris);
  FREE(uris);

  /* free resources */
  FREENONNULL(iblocks[treedepth]);
  FREE(iblocks);
  FREE(dblock);
  closefile(fd);
  releaseClientSocket(sock);
  return OK;
 FAILURE:
  for (i=0;i<=treedepth;i++)
    FREENONNULL(iblocks[i]);
  FREE(iblocks);
  FREE(dblock);
  closefile(fd);
  releaseClientSocket(sock);
  return SYSERR;
}

/* end of upload.c */
