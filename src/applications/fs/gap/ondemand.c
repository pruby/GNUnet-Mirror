/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/gap/ondemand.c
 * @brief functions for handling on-demand encoding
 * @author Christian Grothoff
 */



#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"
#include "gnunet_state_service.h"
#include "ecrs_core.h"
#include "shared.h"
#include "ondemand.h"

/**
 * Format of an on-demand block.
 */
typedef struct
{
  GNUNET_DatastoreValue header;

  unsigned int type;

  /**
   * Size of the on-demand encoded part of the file
   * that this Block represents.
   */
  unsigned int blockSize;

  /**
   * At what offset in the plaintext file is
   * this content stored?
   */
  unsigned long long fileOffset;

  /**
   * What is the GNUNET_hash of the file that contains
   * this block?  Used to determine the name
   * of the file in the on-demand datastore.
   */
  GNUNET_HashCode fileId;

} OnDemandBlock;

/**
 * Name of the directory where we store symlinks to indexed
 * files.
 */
static char *index_directory;

static GNUNET_State_ServiceAPI *state;

static GNUNET_Datastore_ServiceAPI *datastore;

static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * Get the name of the symbolic link corresponding
 * to the given hash of an indexed file.
 */
static char *
get_indexed_filename (const GNUNET_HashCode * fileId)
{
  GNUNET_EncName enc;
  char *fn;

  GNUNET_hash_to_enc (fileId, &enc);
  fn = GNUNET_malloc (strlen (index_directory) + sizeof (GNUNET_EncName) + 1);
  strcpy (fn, index_directory);
  strcat (fn, DIR_SEPARATOR_STR);
  strcat (fn, (char *) &enc);
  return fn;
}

/**
 * We use the state-DB to mark that certain indexed
 * files have disappeared.  If they are indexed again
 * or explicitly unindexed, we should remove the
 * respective markers.
 *
 * @param fileId hash of the file for which the marker
 *        should be removed
 */
static void
remove_unavailable_mark (const GNUNET_HashCode * fileId)
{
  GNUNET_EncName enc;
  char unavail_key[256];

  GNUNET_hash_to_enc (fileId, &enc);
  GNUNET_snprintf (unavail_key, 256, "FIRST_UNAVAILABLE-%s", (char *) &enc);
  state->unlink (coreAPI->ectx, unavail_key);
}

/**
 * We use the state-DB to mark that certain indexed
 * files have disappeared.  If they are marked as
 * disappeared for a while, we remove all traces of
 * those files from the database.  This function is
 * called to either initially mark a file as unavailable,
 * or, if the condition persists, to trigger its
 * removal from the database.
 */
static void
publish_unavailable_mark (const GNUNET_HashCode * fileId)
{
  char unavail_key[256];
  GNUNET_EncName enc;
  unsigned long long *first_unavail;
  unsigned long long now;
  unsigned int len;
  char *ofn;
  char *fn;
  int ret;

  now = GNUNET_get_time ();
  GNUNET_hash_to_enc (fileId, &enc);
  GNUNET_snprintf (unavail_key, 256, "FIRST_UNVAILABLE-%s", (char *) &enc);
  if (state->read (coreAPI->ectx, unavail_key, (void *) &first_unavail) !=
      sizeof (GNUNET_CronTime))
    {
      now = GNUNET_htonll (now);
      state->write (coreAPI->ectx,
                    unavail_key, sizeof (GNUNET_CronTime), (void *) &now);
      return;
    }
  if (GNUNET_ntohll (*first_unavail) - now < 3 * GNUNET_CRON_DAYS)
    return;                     /* do nothing for first 3 days */
  fn = get_indexed_filename (fileId);
  /* Delete it after 3 days */
  len = 256;
  ofn = GNUNET_malloc (len);
  while (((ret = READLINK (fn, ofn, len)) == -1) &&
         (errno == ENAMETOOLONG) && (len < 4 * 1024 * 1024))
    if (len * 2 < len)
      {
        GNUNET_GE_BREAK (coreAPI->ectx, 0);
        GNUNET_array_grow (ofn, len, 0);
        GNUNET_free (fn);
        return;
      }
  GNUNET_array_grow (ofn, len, len * 2);
  if (ret != -1)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK |
                     GNUNET_GE_USER,
                     _
                     ("Because the file `%s' has been unavailable for 3 days"
                      " it got removed from your share.  Please unindex files before"
                      " deleting them as the index now contains invalid references!\n"),
                     ofn);
    }
  GNUNET_free (ofn);
  state->unlink (coreAPI->ectx, unavail_key);
  UNLINK (fn);
  GNUNET_free (fn);
}

/**
 * Creates a symlink to the given file in the shared directory
 *
 * @param fn the file that was indexed
 * @param fileId the file's GNUNET_hash code
 * @return GNUNET_SYSERR on error, GNUNET_NO if symlinking failed,
 *         GNUNET_YES on success
 */
int
GNUNET_FS_ONDEMAND_index_prepare_with_symlink (struct GNUNET_GE_Context *ectx,
                                               const GNUNET_HashCode * fileId,
                                               const char *fn)
{
  GNUNET_EncName enc;
  char *serverFN;
  GNUNET_HashCode linkId;

  if ((GNUNET_SYSERR == GNUNET_hash_file (ectx,
                                          fn,
                                          &linkId)) ||
      (0 != memcmp (&linkId, fileId, sizeof (GNUNET_HashCode))))
    return GNUNET_SYSERR;
  serverFN =
    GNUNET_malloc (strlen (index_directory) + 2 + sizeof (GNUNET_EncName));
  strcpy (serverFN, index_directory);
  strcat (serverFN, DIR_SEPARATOR_STR);
  GNUNET_hash_to_enc (fileId, &enc);
  strcat (serverFN, (char *) &enc);
  UNLINK (serverFN);
  GNUNET_disk_directory_create_for_file (ectx, serverFN);
  if (0 != SYMLINK (fn, serverFN))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "symlink",
                                   fn);
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "symlink",
                                   serverFN);
      GNUNET_free (serverFN);
      return GNUNET_NO;
    }
  GNUNET_free (serverFN);
  remove_unavailable_mark (fileId);
  return GNUNET_YES;
}

/**
 * Writes the given content to the file at the specified offset
 * and stores an OnDemandBlock into the datastore.
 *
 * @return GNUNET_NO if already present, GNUNET_YES on success,
 *  GNUNET_SYSERR on other error (i.e. datastore full)
 */
int
GNUNET_FS_ONDEMAND_add_indexed_content (struct GNUNET_GE_Context *ectx,
                                        GNUNET_Datastore_ServiceAPI *
                                        datastore, unsigned int prio,
                                        GNUNET_CronTime expiration,
                                        unsigned long long fileOffset,
                                        unsigned int anonymityLevel,
                                        const GNUNET_HashCode * fileId,
                                        unsigned int size,
                                        const GNUNET_EC_DBlock * content)
{
  int ret;
  OnDemandBlock odb;
  GNUNET_HashCode key;
  struct stat sbuf;
  char *fn;
  int fd;

  if (size <= sizeof (GNUNET_EC_DBlock))
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  fn = get_indexed_filename (fileId);
  if ((0 != LSTAT (fn, &sbuf))
#ifdef S_ISLNK
      || (!S_ISLNK (sbuf.st_mode))
#endif
    )
    {
      /* not sym-linked, write content to offset! */
      fd = GNUNET_disk_file_open (ectx, fn, O_LARGEFILE | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);   /* 644 */
      if (fd == -1)
        {
          GNUNET_free (fn);
          return GNUNET_SYSERR;
        }
      LSEEK (fd, fileOffset, SEEK_SET);
      ret = WRITE (fd, &content[1], size - sizeof (GNUNET_EC_DBlock));
      if (ret == size - sizeof (GNUNET_EC_DBlock))
        {
          ret = GNUNET_OK;
        }
      else
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                       GNUNET_GE_USER | GNUNET_GE_BULK,
                                       "write", fn);
          ret = GNUNET_SYSERR;
        }
      CLOSE (fd);
      if (ret == GNUNET_SYSERR)
        {
          GNUNET_free (fn);
          return GNUNET_SYSERR;
        }
    }
  GNUNET_free (fn);

  odb.header.size = htonl (sizeof (OnDemandBlock));
  odb.header.type = htonl (GNUNET_ECRS_BLOCKTYPE_ONDEMAND);
  odb.header.priority = htonl (prio);
  odb.header.anonymity_level = htonl (anonymityLevel);
  odb.header.expiration_time = GNUNET_htonll (expiration);
  odb.type = htonl (GNUNET_ECRS_BLOCKTYPE_ONDEMAND);
  odb.fileOffset = GNUNET_htonll (fileOffset);
  odb.blockSize = htonl (size - sizeof (GNUNET_EC_DBlock));
  odb.fileId = *fileId;
  /* compute the primary key */
  GNUNET_EC_file_block_get_query (content, size, &key);
#if EXTRA_CHECKS
  {
    GNUNET_DatastoreValue *dsvalue;
    if (GNUNET_OK !=
        GNUNET_EC_file_block_encode (content, size, &key, &dsvalue))
      {
        GNUNET_GE_BREAK (ectx, 0);
        GNUNET_GE_BREAK (coreAPI->ectx, 0);
      }
    else
      {
        GNUNET_free (dsvalue);
      }
  }
#endif
  return datastore->putUpdate (&key, &odb.header);
}

/**
 * Call datastore's delete method using the
 * query and datastore value from the closure.
 * (and free the closure).
 */
static void
async_delete_job (void *cls)
{
  GNUNET_HashCode *query = cls;
  GNUNET_DatastoreValue *dbv = (GNUNET_DatastoreValue *) & query[1];

  datastore->del (query, dbv);
  GNUNET_free (query);
}

/**
 * Delete the query that still references the unavailable file.  This
 * must be done asynchronously since we are in the "get" iterator and
 * a del operation during "get" would deadlock!
 */
static void
delete_content_asynchronously (const GNUNET_DatastoreValue * dbv,
                               const GNUNET_HashCode * query)
{
  GNUNET_HashCode *ctx;

  ctx = GNUNET_malloc (sizeof (GNUNET_HashCode) + ntohl (dbv->size));
  *ctx = *query;
  memcpy (&ctx[1], dbv, ntohl (dbv->size));
  GNUNET_cron_add_job (coreAPI->cron, &async_delete_job, 0, 0, ctx);
}

/**
 * A query on the datastore resulted in the on-demand
 * block dbv.  On-demand encode the block and return
 * the resulting DSV in enc.  If the on-demand
 * encoding fails because the file is no longer there,
 * this function also removes the OD-Entry
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if there was an error
 */
int
GNUNET_FS_ONDEMAND_get_indexed_content (const GNUNET_DatastoreValue * dbv,
                                        const GNUNET_HashCode * query,
                                        GNUNET_DatastoreValue ** enc)
{
  char *fn;
  char *iobuf;
  int blen;
  int fileHandle;
  int ret;
  const OnDemandBlock *odb;
  GNUNET_EC_DBlock *db;
  struct stat linkStat;


  if ((ntohl (dbv->size) != sizeof (OnDemandBlock)) ||
      (ntohl (dbv->type) != GNUNET_ECRS_BLOCKTYPE_ONDEMAND))
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      return GNUNET_SYSERR;
    }
  odb = (const OnDemandBlock *) dbv;
  fn = get_indexed_filename (&odb->fileId);
  if ((GNUNET_YES != GNUNET_disk_file_test (coreAPI->ectx,
                                            fn)) ||
      (-1 == (fileHandle = GNUNET_disk_file_open (coreAPI->ectx,
                                                  fn, O_LARGEFILE | O_RDONLY,
                                                  0))))
    {
      GNUNET_GE_LOG_STRERROR_FILE (coreAPI->ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "open",
                                   fn);
      /* Is the symlink (still) there? */
      if (LSTAT (fn, &linkStat) == -1)
        delete_content_asynchronously (dbv, query);
      else
        publish_unavailable_mark (&odb->fileId);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }

  if (GNUNET_ntohll (odb->fileOffset) != LSEEK (fileHandle,
                                                GNUNET_ntohll
                                                (odb->fileOffset), SEEK_SET))
    {
      GNUNET_GE_LOG_STRERROR_FILE (coreAPI->ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "lseek",
                                   fn);
      GNUNET_free (fn);
      CLOSE (fileHandle);
      delete_content_asynchronously (dbv, query);
      return GNUNET_SYSERR;
    }
  db = GNUNET_malloc (sizeof (GNUNET_EC_DBlock) + ntohl (odb->blockSize));
  db->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  iobuf = (char *) &db[1];
  blen = READ (fileHandle, iobuf, ntohl (odb->blockSize));
  if (blen != ntohl (odb->blockSize))
    {
      GNUNET_GE_LOG_STRERROR_FILE (coreAPI->ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "read",
                                   fn);
      GNUNET_free (fn);
      GNUNET_free (db);
      CLOSE (fileHandle);
      delete_content_asynchronously (dbv, query);
      return GNUNET_SYSERR;
    }
  CLOSE (fileHandle);
  ret = GNUNET_EC_file_block_encode (db,
                                     ntohl (odb->blockSize) +
                                     sizeof (GNUNET_EC_DBlock), query, enc);
  GNUNET_free (db);
  GNUNET_free (fn);
  if (ret == GNUNET_SYSERR)
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Indexed content changed (does not match its hash).\n"));
      delete_content_asynchronously (dbv, query);
      return GNUNET_SYSERR;
    }
  (*enc)->anonymity_level = dbv->anonymity_level;
  (*enc)->expiration_time = dbv->expiration_time;
  (*enc)->priority = dbv->priority;
  return GNUNET_OK;
}

/**
 * Test if the file with the given ID is
 * indexed.
 * @return GNUNET_YES if so, GNUNET_NO if not.
 */
int
GNUNET_FS_ONDEMAND_test_indexed_file (GNUNET_Datastore_ServiceAPI * datastore,
                                      const GNUNET_HashCode * fileId)
{
  struct stat filestat;
  char *fn;

  fn = get_indexed_filename (fileId);
  if (0 != STAT (fn, &filestat))
    {
      GNUNET_free (fn);
      return GNUNET_NO;
    }
  GNUNET_free (fn);
  return GNUNET_YES;
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
int
GNUNET_FS_ONDEMAND_delete_indexed_content (struct GNUNET_GE_Context *ectx,
                                           GNUNET_Datastore_ServiceAPI *
                                           datastore, unsigned int blocksize,
                                           const GNUNET_HashCode * fileId)
{
  char *fn;
  int fd;
  int ret;
  OnDemandBlock odb;
  GNUNET_HashCode key;
  unsigned long long pos;
  unsigned long long size;
  unsigned long long delta;
  GNUNET_EC_DBlock *block;
  GNUNET_EncName enc;

  fn = get_indexed_filename (fileId);
  fd = GNUNET_disk_file_open (ectx, fn, O_RDONLY | O_LARGEFILE, 0);
  if (fd == -1)
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  pos = 0;
  if (GNUNET_OK != GNUNET_disk_file_size (ectx, fn, &size, GNUNET_YES))
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  block = GNUNET_malloc (sizeof (GNUNET_EC_DBlock) + blocksize);
  block->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  while (pos < size)
    {
      delta = size - pos;
      if (delta > blocksize)
        delta = blocksize;
      if (delta != READ (fd, &block[1], delta))
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                       GNUNET_GE_USER | GNUNET_GE_BULK,
                                       "read", fn);
          CLOSE (fd);
          GNUNET_free (fn);
          GNUNET_free (block);
          return GNUNET_SYSERR;
        }
      odb.header.size = htonl (sizeof (OnDemandBlock));
      odb.header.type = htonl (GNUNET_ECRS_BLOCKTYPE_ONDEMAND);
      odb.header.priority = 0;
      odb.header.anonymity_level = 0;
      odb.header.expiration_time = 0;
      odb.type = htonl (GNUNET_ECRS_BLOCKTYPE_ONDEMAND);
      odb.fileOffset = GNUNET_htonll (pos);
      odb.blockSize = htonl (delta);
      odb.fileId = *fileId;
      /* compute the primary key */
      GNUNET_EC_file_block_get_query (block,
                                      delta + sizeof (GNUNET_EC_DBlock),
                                      &key);
      if ((0 <
           datastore->get (&key, GNUNET_ECRS_BLOCKTYPE_ONDEMAND,
                           &GNUNET_FS_HELPER_complete_value_from_database_callback,
                           &odb.header)) && (odb.header.expiration_time != 0))
        ret = datastore->del (&key, &odb.header);
      else                      /* not found */
        ret = GNUNET_SYSERR;
      if (ret == GNUNET_SYSERR)
        {
          IF_GELOG (ectx,
                    GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                    GNUNET_hash_to_enc (&key, &enc));
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _
                         ("Unindexed ODB block `%s' from offset %llu already missing from datastore.\n"),
                         &enc, pos);
        }
      pos += delta;
    }
  GNUNET_free (block);
  CLOSE (fd);
  UNLINK (fn);
  GNUNET_free (fn);
  remove_unavailable_mark (fileId);
  return GNUNET_OK;
}



int
GNUNET_FS_ONDEMAND_init (GNUNET_CoreAPIForPlugins * capi)
{
  char *tmp;

  coreAPI = capi;
  GNUNET_GC_get_configuration_value_filename (capi->cfg,
                                              "GNUNETD",
                                              "GNUNETD_HOME",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY,
                                              &tmp);
  tmp = GNUNET_realloc (tmp, strlen (tmp) + strlen ("/data/shared/") + 1);
  strcat (tmp, "/data/shared/");
  GNUNET_GC_get_configuration_value_filename (capi->cfg,
                                              "FS",
                                              "INDEX-DIRECTORY",
                                              tmp, &index_directory);
  GNUNET_free (tmp);
  GNUNET_disk_directory_create (coreAPI->ectx, index_directory);        /* just in case */

  state = capi->service_request ("state");
  if (state == NULL)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      GNUNET_free (index_directory);
      return GNUNET_SYSERR;
    }
  datastore = capi->service_request ("datastore");
  if (datastore == NULL)
    {
      GNUNET_GE_BREAK (coreAPI->ectx, 0);
      coreAPI->service_release (state);
      state = NULL;
      GNUNET_free (index_directory);
      return GNUNET_SYSERR;
    }

  return 0;
}

int
GNUNET_FS_ONDEMAND_done ()
{
  coreAPI->service_release (state);
  state = NULL;
  coreAPI->service_release (datastore);
  datastore = NULL;
  GNUNET_free (index_directory);
  index_directory = NULL;
  return 0;
}


/* end of ondemand.c */
