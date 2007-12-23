/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_directories.h"
#include "ecrs_core.h"
#include "ondemand.h"
#include "gnunet_state_service.h"

#define DEBUG_ONDEMAND GNUNET_NO

#define TRACK_INDEXED_FILES GNUNET_NO

#define TRACKFILE "indexed_requests.txt"

/**
 * Use GNUnet 0.7.2 compatibility mode?
 */
#define MIG72 GNUNET_YES

/**
 * Format of an on-demand block.
 */
typedef struct
{
  /**
   *
   */
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

#if MIG72
/**
 * Format of an OLD on-demand block.
 */
typedef struct
{
  /**
   *
   */
  GNUNET_DatastoreValue header;

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
   * What is the GNUNET_hash of the file that contains
   * this block?  Used to determine the name
   * of the file in the on-demand datastore.
   */
  GNUNET_HashCode fileId;

} OnDemandBlock72;
#endif

static char *index_directory;

static struct GNUNET_GE_Context *ectx;

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_State_ServiceAPI *state;

static char *
getOnDemandFile (const GNUNET_HashCode * fileId)
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
 * Creates a symlink to the given file in the shared directory
 *
 * @param fn the file that was indexed
 * @param fileId the file's GNUNET_hash code
 * @return GNUNET_SYSERR on error, GNUNET_NO if symlinking failed,
 *         GNUNET_YES on success
 */
int
ONDEMAND_initIndex (struct GNUNET_GE_Context *cectx,
                    const GNUNET_HashCode * fileId, const char *fn)
{
  GNUNET_EncName enc;
  char *serverFN;
  char unavail_key[256];
  GNUNET_HashCode linkId;

  if ((GNUNET_SYSERR == GNUNET_hash_file (cectx,
                                          fn,
                                          &linkId)) ||
      (0 != memcmp (&linkId, fileId, sizeof (GNUNET_HashCode))))
    {
      return GNUNET_NO;
    }

  serverFN =
    GNUNET_malloc (strlen (index_directory) + 2 + sizeof (GNUNET_EncName));
  strcpy (serverFN, index_directory);
  strcat (serverFN, DIR_SEPARATOR_STR);
  GNUNET_hash_to_enc (fileId, &enc);
  strcat (serverFN, (char *) &enc);
  UNLINK (serverFN);
  GNUNET_disk_directory_create_for_file (cectx, serverFN);
  if (0 != SYMLINK (fn, serverFN))
    {
      GNUNET_GE_LOG_STRERROR_FILE (cectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "symlink",
                                   fn);
      GNUNET_GE_LOG_STRERROR_FILE (cectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "symlink",
                                   serverFN);
      GNUNET_free (serverFN);
      return GNUNET_NO;
    }
  GNUNET_snprintf (unavail_key, 256, "FIRST_UNAVAILABLE-%s", (char *) &enc);
  state->unlink (ectx, unavail_key);
  GNUNET_free (serverFN);
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
ONDEMAND_index (struct GNUNET_GE_Context *cectx,
                GNUNET_Datastore_ServiceAPI * datastore,
                unsigned int prio,
                GNUNET_CronTime expiration,
                unsigned long long fileOffset,
                unsigned int anonymityLevel,
                const GNUNET_HashCode * fileId,
                unsigned int size, const DBlock * content)
{
  int ret;
  OnDemandBlock odb;
  GNUNET_HashCode key;
  struct stat sbuf;
  char *fn;
#if DEBUG_ONDEMAND
  GNUNET_EncName enc;
#endif


  if (size <= sizeof (DBlock))
    {
      GNUNET_GE_BREAK (cectx, 0);
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }

  fn = getOnDemandFile (fileId);
  if ((0 != LSTAT (fn, &sbuf))
#ifdef S_ISLNK
      || (!S_ISLNK (sbuf.st_mode))
#endif
    )
    {
      int fd;

      /* not sym-linked, write content to offset! */
#if DEBUG_ONDEMAND
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Storing on-demand encoded data in `%s'.\n", fn);
#endif
      fd = GNUNET_disk_file_open (cectx, fn, O_LARGEFILE | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);  /* 644 */
      if (fd == -1)
        {
          GNUNET_free (fn);
          return GNUNET_SYSERR;
        }
      LSEEK (fd, fileOffset, SEEK_SET);
      ret = WRITE (fd, &content[1], size - sizeof (DBlock));
      if (ret == size - sizeof (DBlock))
        {
          ret = GNUNET_OK;
        }
      else
        {
          GNUNET_GE_LOG_STRERROR_FILE (cectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                       GNUNET_GE_USER | GNUNET_GE_BULK,
                                       "write", fn);
          ret = GNUNET_SYSERR;
        }
      CLOSE (fd);
      if (ret == GNUNET_SYSERR)
        {
          GNUNET_free (fn);
          return ret;
        }
    }
  GNUNET_free (fn);

  odb.header.size = htonl (sizeof (OnDemandBlock));
  odb.header.type = htonl (GNUNET_ECRS_BLOCKTYPE_ONDEMAND);
  odb.header.prio = htonl (prio);
  odb.header.anonymityLevel = htonl (anonymityLevel);
  odb.header.expirationTime = GNUNET_htonll (expiration);
  odb.type = htonl (GNUNET_ECRS_BLOCKTYPE_ONDEMAND);
  odb.fileOffset = GNUNET_htonll (fileOffset);
  odb.blockSize = htonl (size - sizeof (DBlock));
  odb.fileId = *fileId;
  /* compute the primary key */
  GNUNET_EC_file_block_get_query (content, size, &key);
#if EXTRA_CHECKS
  {
    GNUNET_DatastoreValue *dsvalue;
    if (GNUNET_OK !=
        GNUNET_EC_file_block_encode (content, size, &key, &dsvalue))
      {
        GNUNET_GE_BREAK (cectx, 0);
        GNUNET_GE_BREAK (ectx, 0);
      }
    else
      {
        GNUNET_free (dsvalue);
      }
  }
#endif

#if DEBUG_ONDEMAND
  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&key, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Storing on-demand content for query `%s'\n", &enc);
#endif

  ret = datastore->putUpdate (&key, &odb.header);
  return ret;
}

struct adJ
{
  GNUNET_Datastore_ServiceAPI *datastore;
  GNUNET_DatastoreValue *dbv;
  GNUNET_HashCode query;
};

static void
asyncDelJob (void *cls)
{
  struct adJ *job = cls;
  job->datastore->del (&job->query, job->dbv);
  GNUNET_free (job->dbv);
  GNUNET_free (job);
}

/**
 * Delete the query that still references the unavailable file.  This
 * must be done asynchronously since we are in the "get" iterator and
 * a del operation during "get" would deadlock!
 */
static void
asyncDelete (GNUNET_Datastore_ServiceAPI * datastore,
             const GNUNET_DatastoreValue * dbv, const GNUNET_HashCode * query)
{
  struct adJ *job;
#if DEBUG_ONDEMAND
  GNUNET_EncName enc;
#endif

  job = GNUNET_malloc (sizeof (struct adJ));
  job->datastore = datastore;
  job->query = *query;
  job->dbv = GNUNET_malloc (ntohl (dbv->size));
  memcpy (job->dbv, dbv, ntohl (dbv->size));
#if DEBUG_ONDEMAND
  GNUNET_hash_to_enc (query, &enc);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _
                 ("Indexed file disappeared, deleting block for query `%s'\n"),
                 &enc);
#endif
  /* schedule for "immediate" execution */
  GNUNET_cron_add_job (coreAPI->cron, &asyncDelJob, 0, 0, job);
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
ONDEMAND_getIndexed (GNUNET_Datastore_ServiceAPI * datastore,
                     const GNUNET_DatastoreValue * dbv,
                     const GNUNET_HashCode * query,
                     GNUNET_DatastoreValue ** enc)
{
  char *fn;
  char *iobuf;
  int blen;
  int fileHandle;
  int ret;
  const OnDemandBlock *odb;
  DBlock *db;

#if MIG72
  const OnDemandBlock72 *odb_old;
  OnDemandBlock odb_stack;
  switch (ntohl (dbv->type))
    {
    case GNUNET_ECRS_BLOCKTYPE_ONDEMAND:
      if (ntohl (dbv->size) != sizeof (OnDemandBlock))
	{
          GNUNET_GE_BREAK (ectx, 0);
          return GNUNET_SYSERR;
	}
      odb = (const OnDemandBlock *) dbv;
      break;
    case GNUNET_ECRS_BLOCKTYPE_ONDEMAND_OLD:    
      if (ntohl (dbv->size) != sizeof (OnDemandBlock72))
        {
          GNUNET_GE_BREAK (ectx, 0);
          return GNUNET_SYSERR;
        }
      odb_old = (OnDemandBlock72 *) dbv;
      odb_stack.header = odb_old->header;
      odb_stack.type = odb_old->type;
      odb_stack.fileOffset = odb_old->fileOffset;
      odb_stack.blockSize = odb_old->blockSize;
      odb_stack.fileId = odb_old->fileId;
      odb = &odb_stack;
      break;
    default:
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
#else
  if ( (ntohl (dbv->size) != sizeof (OnDemandBlock)) ||
       (ntohl (dbv->type) != GNUNET_ECRS_BLOCKTYPE_ONDEMAND) )
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  odb = (const OnDemandBlock *) dbv;
#endif
  fn = getOnDemandFile (&odb->fileId);
  if ((GNUNET_YES != GNUNET_disk_file_test (ectx,
                                            fn)) ||
      (-1 == (fileHandle = GNUNET_disk_file_open (ectx,
                                                  fn, O_LARGEFILE | O_RDONLY,
                                                  0))))
    {
      char unavail_key[256];
      GNUNET_EncName enc;
      unsigned long long *first_unavail;
      struct stat linkStat;

      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "open",
                                   fn);

      /* Is the symlink there? */
      if (LSTAT (fn, &linkStat) == -1)
        {
          asyncDelete (datastore, dbv, query);
        }
      else
        {
          /* For how long has the file been unavailable? */
          GNUNET_hash_to_enc (&odb->fileId, &enc);
          GNUNET_snprintf (unavail_key, 256, "FIRST_UNVAILABLE-%s",
                           (char *) &enc);
          if (state->read (ectx, unavail_key, (void *) &first_unavail) !=
              sizeof (GNUNET_CronTime))
            {
              unsigned long long now = GNUNET_htonll (GNUNET_get_time ());
              state->write (ectx,
                            unavail_key, sizeof (GNUNET_CronTime),
                            (void *) &now);
            }
          else
            {
              /* Delete it after 3 days */
              if (GNUNET_ntohll (*first_unavail) - GNUNET_get_time () >
                  3 * GNUNET_CRON_DAYS)
                {
                  unsigned int len;
                  char *ofn;
                  int ret;

                  len = 256;
                  ofn = GNUNET_malloc (len);
                  while (((ret = READLINK (fn, ofn, len)) == -1) &&
                         (errno == ENAMETOOLONG) && (len < 4 * 1024 * 1024))
                    if (len * 2 < len)
                      {
                        GNUNET_GE_BREAK (ectx, 0);
                        GNUNET_array_grow (ofn, len, 0);
                        GNUNET_free (fn);
                        return GNUNET_SYSERR;
                      }
                  GNUNET_array_grow (ofn, len, len * 2);

                  if (ret != -1)
                    {
                      GNUNET_GE_LOG (ectx,
                                     GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                     GNUNET_GE_USER,
                                     _
                                     ("Because the file `%s' has been unavailable for 3 days"
                                      " it got removed from your share.  Please unindex files before"
                                      " deleting them as the index now contains invalid references!\n"),
                                     ofn);
                    }
                  GNUNET_free (ofn);
                  asyncDelete (datastore, dbv, query);
                  state->unlink (ectx, unavail_key);
                  UNLINK (fn);
                }
            }
        }

      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }

#if TRACK_INDEXED_FILES
  {
    FILE *fp;
    char *afsDir;
    char *scratch;
    int n;

    afsDir = getFileName ("FS",
                          "DIR",
                          _("Configuration file must specify directory for"
                            " storage of FS data in section `%s'"
                            " under `%s'.\n"));
    n = strlen (afsDir) + strlen (TRACKFILE) + 8;
    scratch = GNUNET_malloc (n);
    GNUNET_snprintf (scratch, n, "%s/%s", afsDir, TRACKFILE);
    fp = FOPEN (scratch, "a");
    FPRINTF (fp,
             "%u %llu\n",
             ntohs (ce->fileNameIndex),
             (unsigned long long) GNUNET_get_time_int32 (NULL));
    fclose (fp);
    GNUNET_free (scratch);
    GNUNET_free (afsDir);
  }
#endif
  if (GNUNET_ntohll (odb->fileOffset) != LSEEK (fileHandle,
                                                GNUNET_ntohll (odb->
                                                               fileOffset),
                                                SEEK_SET))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "lseek",
                                   fn);
      GNUNET_free (fn);
      CLOSE (fileHandle);
      asyncDelete (datastore, dbv, query);
      return GNUNET_SYSERR;
    }
  db = GNUNET_malloc (sizeof (DBlock) + ntohl (odb->blockSize));
  db->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  iobuf = (char *) &db[1];
  blen = READ (fileHandle, iobuf, ntohl (odb->blockSize));
  if (blen != ntohl (odb->blockSize))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                   GNUNET_GE_USER | GNUNET_GE_BULK, "read",
                                   fn);
      GNUNET_free (fn);
      GNUNET_free (db);
      CLOSE (fileHandle);
      asyncDelete (datastore, dbv, query);
      return GNUNET_SYSERR;
    }
  CLOSE (fileHandle);
  ret = GNUNET_EC_file_block_encode (db,
                                     ntohl (odb->blockSize) + sizeof (DBlock),
                                     query, enc);
  GNUNET_free (db);
  GNUNET_free (fn);
  if (ret == GNUNET_SYSERR)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Indexed content changed (does not match its hash).\n"));
      asyncDelete (datastore, dbv, query);
      return GNUNET_SYSERR;
    }

  (*enc)->anonymityLevel = dbv->anonymityLevel;
  (*enc)->expirationTime = dbv->expirationTime;
  (*enc)->prio = dbv->prio;
  return GNUNET_OK;
}

/**
 * Test if the file with the given ID is
 * indexed.
 * @return GNUNET_YES if so, GNUNET_NO if not.
 */
int
ONDEMAND_testindexed (GNUNET_Datastore_ServiceAPI * datastore,
                      const GNUNET_HashCode * fileId)
{
  char *fn;
  int fd;

  fn = getOnDemandFile (fileId);
  fd = GNUNET_disk_file_open (ectx, fn, O_RDONLY);
  GNUNET_free (fn);
  if (fd == -1)
    return GNUNET_NO;
  CLOSE (fd);
  return GNUNET_YES;
}


/**
 * If the data portion and type of the value match our value in the
 * closure, copy the header (prio, anonymityLevel, expirationTime) and
 * abort the iteration: we found what we're looing for.  Otherwise
 * continue.
 */
static int
completeValue (const GNUNET_HashCode * key,
               const GNUNET_DatastoreValue * value, void *closure,
               unsigned long long uid)
{
  GNUNET_DatastoreValue *comp = closure;

#if MIG72
  const OnDemandBlock72 *odb1 = (const OnDemandBlock72 *) &value[1];
  const OnDemandBlock72 *odb2 = (const OnDemandBlock72 *) &comp[1];
  if ((comp->size != value->size) ||
      (((ntohl (value->size) - sizeof (GNUNET_DatastoreValue) !=
         sizeof (OnDemandBlock72)) || (odb1->type != odb2->type)
        || (odb1->fileOffset != odb2->fileOffset)
        || (odb1->blockSize != odb2->blockSize)
        || (0 !=
            memcmp (&odb1->fileId, &odb2->fileId, sizeof (GNUNET_HashCode))))
       && (0 !=
           memcmp (&value[1], &comp[1],
                   ntohl (value->size) - sizeof (GNUNET_DatastoreValue)))))
#else
  if ((comp->size != value->size) ||
      (0 != memcmp (&value[1],
                    &comp[1],
                    ntohl (value->size) - sizeof (GNUNET_DatastoreValue))))
#endif
    {
#if DEBUG_ONDEMAND
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "`%s' found value that does not match (%u, %u).\n",
                     __FUNCTION__, ntohl (comp->size), ntohl (value->size));
#endif
      return GNUNET_OK;
    }
  *comp = *value;               /* make copy! */
#if DEBUG_ONDEMAND
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "`%s' found value that matches.\n", __FUNCTION__);
#endif
  return GNUNET_SYSERR;
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
ONDEMAND_unindex (struct GNUNET_GE_Context *cectx,
                  GNUNET_Datastore_ServiceAPI * datastore,
                  unsigned int blocksize, const GNUNET_HashCode * fileId)
{
  char *fn;
  int fd;
  int ret;
  OnDemandBlock odb;
#if MIG72
  OnDemandBlock72 odb_old;
#endif
  GNUNET_HashCode key;
  unsigned long long pos;
  unsigned long long size;
  unsigned long long delta;
  DBlock *block;
  GNUNET_EncName enc;
  char unavail_key[256];

  fn = getOnDemandFile (fileId);
#if DEBUG_ONDEMAND
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Removing on-demand encoded data stored in `%s'.\n", fn);
#endif
  fd = GNUNET_disk_file_open (cectx, fn, O_RDONLY | O_LARGEFILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);        /* 644 */
  if (fd == -1)
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  pos = 0;
  if (GNUNET_OK != GNUNET_disk_file_size (cectx, fn, &size, GNUNET_YES))
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  block = GNUNET_malloc (sizeof (DBlock) + blocksize);
  block->type = htonl (GNUNET_ECRS_BLOCKTYPE_DATA);
  while (pos < size)
    {
      delta = size - pos;
      if (delta > blocksize)
        delta = blocksize;
      if (delta != READ (fd, &block[1], delta))
        {
          GNUNET_GE_LOG_STRERROR_FILE (cectx,
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
      odb.header.prio = 0;
      odb.header.anonymityLevel = 0;
      odb.header.expirationTime = 0;
      odb.type = htonl (GNUNET_ECRS_BLOCKTYPE_ONDEMAND);
      odb.fileOffset = GNUNET_htonll (pos);
      odb.blockSize = htonl (delta);
      odb.fileId = *fileId;
      /* compute the primary key */
      GNUNET_EC_file_block_get_query (block, delta + sizeof (DBlock), &key);
      if (GNUNET_SYSERR == datastore->get (&key, GNUNET_ECRS_BLOCKTYPE_ONDEMAND, &completeValue, &odb.header))  /* aborted == found! */
        ret = datastore->del (&key, &odb.header);
      else                      /* not found */
        ret = GNUNET_SYSERR;
#if MIG72
      if (ret == GNUNET_SYSERR)
        {
          memset (&odb_old, 0, sizeof (OnDemandBlock72));
          odb_old.header.size = htonl (sizeof (OnDemandBlock));
          odb_old.header.type = htonl (GNUNET_ECRS_BLOCKTYPE_ONDEMAND);
          odb_old.header.prio = 0;
          odb_old.header.anonymityLevel = 0;
          odb_old.header.expirationTime = 0;
          odb_old.type = htonl (GNUNET_ECRS_BLOCKTYPE_ONDEMAND);
          odb_old.fileOffset = GNUNET_htonll (pos);
          odb_old.blockSize = htonl (delta);
          odb_old.fileId = *fileId;
          if (GNUNET_SYSERR == datastore->get (&key, GNUNET_ECRS_BLOCKTYPE_ONDEMAND_OLD, &completeValue, &odb_old.header))      /* aborted == found! */
            ret = datastore->del (&key, &odb_old.header);
          else                  /* not found */
            ret = GNUNET_SYSERR;
        }
#endif
      if (ret == GNUNET_SYSERR)
        {
          IF_GELOG (cectx,
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
  /* Remove information about unavailability */
  GNUNET_hash_to_enc (fileId, &enc);
  GNUNET_snprintf (unavail_key, 256, "FIRST_UNAVAILABLE-%s", (char *) &enc);
  state->unlink (ectx, unavail_key);
  GNUNET_free (fn);
  return GNUNET_OK;
}

int
ONDEMAND_init (GNUNET_CoreAPIForPlugins * capi)
{
  char *tmp;

  coreAPI = capi;
  state = capi->request_service ("state");
  if (state == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  ectx = capi->ectx;
  GNUNET_GC_get_configuration_value_filename (capi->cfg,
                                              "GNUNETD",
                                              "GNUNETD_HOME",
                                              GNUNET_DEFAULT_DAEMON_VAR_DIRECTORY,
                                              &tmp);
  GNUNET_GE_ASSERT (ectx, NULL != tmp);
  tmp = GNUNET_realloc (tmp, strlen (tmp) + strlen ("/data/shared/") + 1);
  strcat (tmp, "/data/shared/");
  GNUNET_GC_get_configuration_value_filename (capi->cfg,
                                              "FS",
                                              "INDEX-DIRECTORY",
                                              tmp, &index_directory);
  GNUNET_free (tmp);
  GNUNET_disk_directory_create (ectx, index_directory); /* just in case */
  return GNUNET_OK;
}

int
ONDEMAND_done ()
{
  coreAPI->release_service (state);
  state = NULL;
  GNUNET_free (index_directory);
  return GNUNET_OK;
}

/* end of ondemand.c */
