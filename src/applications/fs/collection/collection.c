/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/collection.c
 * @brief Helper functions for building a collection
 * @author Christian Grothoff
 *
 * A collection is a special kind of namespace.  A collection is the
 * set of files provided by the same user, but unlike namespaces it is
 * automatically managed by the GNUnet UI.  A collection is a single
 * directory in a namespace that is automatically updated each time
 * the user updates or deletes a file.  That is, once the user starts
 * a collection the gnunet-tools will always keep the corresponding
 * directory and namespace entries up-to-date.
 *
 * A good way of thinking about a collection is a lazy user's
 * namespace.
 */

#include "platform.h"
#include "gnunet_blockstore.h"
#include "gnunet_directories.h"
#include "gnunet_collection_lib.h"
#include "gnunet_util_crypto.h"

/**
 * Filename used to store collection information
 */
#define COLLECTION "collection"

/**
 * How long does a collection advertisement live?
 */
#define COLLECTION_ADV_LIFETIME (12 * cronMONTHS)

/**
 * @brief information about a collection
 */
typedef struct CollectionData
{

  /**
   * What is the last ID for the publication?
   */
  HashCode512 lastId;

  /**
   * What is the next ID for the publication?
   */
  HashCode512 nextId;

  /**
   * What is the update interval? (NBO!)
   */
  TIME_T updateInterval;

  /**
   * What is the update interval? (NBO!)
   */
  TIME_T lastPublication;

  /**
   * Anonymity level for the collection. (NBO)
   */
  unsigned int anonymityLevel;

  /**
   * Priority of the collection (NBO).
   */
  unsigned int priority;

} CollectionData;


typedef struct
{

  CollectionData data;

  /**
   * Name of the collection
   */
  char *name;

  /**
   * Metadata describing the collection
   */
  struct ECRS_MetaData *meta;

  /**
   * Files in the collection.
   */
  ECRS_FileInfo *files;

  /**
   * How many files are in files?
   */
  unsigned int file_count;

  /**
   * Has this collection changed since the last publication?
   */
  int changed;

} CollectionInfo;

static CollectionInfo *collectionData;

static struct MUTEX *lock;

static struct GE_Context *ectx;

static struct GC_Configuration *cfg;

static char *
getCollectionFileName ()
{
  char *fn;
  char *fnBase;

  GC_get_configuration_value_filename (cfg,
                                       "GNUNET",
                                       "GNUNET_HOME",
                                       GNUNET_HOME_DIRECTORY, &fnBase);
  fn = MALLOC (strlen (fnBase) + strlen (COLLECTION) + 4);
  strcpy (fn, fnBase);
  disk_directory_create (ectx, fn);
  strcat (fn, DIR_SEPARATOR_STR);
  strcat (fn, COLLECTION);
  FREE (fnBase);
  return fn;
}

/**
 * Initialize collection module.
 */
void
CO_init (struct GE_Context *e, struct GC_Configuration *c)
{
  char *fn;
  int len;
  unsigned int mlen;
  unsigned long long size;
  char *buf;
  int fd;
  const char *pos;
  size_t rsize;
  unsigned int i;
  char *tmp;

  cfg = c;
  ectx = e;
  lock = MUTEX_CREATE (YES);
  fn = getCollectionFileName ();
  if (!disk_file_test (ectx, fn))
    {
      FREE (fn);
      return;
    }
  /* read collection data */
  if (OK != disk_file_size (ectx, fn, &size, YES))
    {
      FREE (fn);
      return;
    }
  if ((size > 0x7FFFFFFF) ||
      (size < sizeof (CollectionData) + 4 * sizeof (int)))
    {
      GE_BREAK (ectx, 0);
      UNLINK (fn);
      FREE (fn);
      return;
    }
  fd = OPEN (fn, O_RDONLY | O_LARGEFILE);
  if (fd == -1)
    {
      GE_BREAK (ectx, 0);
      UNLINK (fn);
      FREE (fn);
      return;
    }
  rsize = (size_t) size;
  buf = MMAP (NULL, rsize, PROT_READ, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED)
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                            "mmap", fn);
      CLOSE (fd);
      FREE (fn);
      return;
    }
  collectionData = MALLOC (sizeof (CollectionInfo));
  memcpy (&collectionData->data, buf, sizeof (CollectionData));
  pos = &buf[sizeof (CollectionData)];
  rsize -= sizeof (CollectionData);
  len = ntohl (*(int *) pos);
  if (len > 1024 * 1024 * 4)
    {
      GE_BREAK (ectx, 0);
      len = 1024 * 1024 * 4;
    }
  GROW (collectionData->files, collectionData->file_count, len);
  pos += sizeof (int);
  collectionData->changed = ntohl (*(int *) pos);
  pos += sizeof (int);
  mlen = ntohl (*(int *) pos);
  pos += sizeof (int);
  len = ntohl (*(int *) pos);
  if (len > 1024)
    {
      GE_BREAK (ectx, 0);
      len = 1024;
    }
  collectionData->name = MALLOC (len + 1);
  pos += sizeof (int);
  rsize -= 4 * sizeof (int);
  if (len > rsize)
    {
      GE_BREAK (ectx, 0);
      len = rsize;
    }
  memcpy (collectionData->name, pos, len);
  rsize -= len;
  pos += len;
  if (mlen > rsize)
    {
      GE_BREAK (ectx, 0);
      mlen = rsize;
    }
  collectionData->meta = ECRS_deserializeMetaData (ectx, pos, mlen);
  rsize -= mlen;
  pos += mlen;
  GE_BREAK (ectx, collectionData->meta != NULL);
  for (i = 0; i < collectionData->file_count; i++)
    {
      if (rsize < 2 * sizeof (int))
        {
          GE_BREAK (ectx, 0);
          break;
        }
      len = ntohl (*(int *) pos);
      pos += sizeof (int);
      mlen = ntohl (*(int *) pos);
      pos += sizeof (int);
      rsize -= 2 * sizeof (int);
      if (rsize < mlen + len)
        {
          GE_BREAK (ectx, 0);
          break;
        }
      if (len > 1024 * 16)
        {
          GE_BREAK (ectx, 0);
          len = 1024 * 16;
        }
      tmp = MALLOC (len + 1);
      tmp[len] = '\0';
      memcpy (tmp, pos, len);
      pos += len;
      rsize -= len;
      collectionData->files[i].uri = ECRS_stringToUri (ectx, tmp);
      GE_ASSERT (ectx, collectionData->files[i].uri != NULL);
      FREE (tmp);
      collectionData->files[i].meta
        = ECRS_deserializeMetaData (ectx, pos, mlen);
      GE_ASSERT (ectx, collectionData->files[i].meta != NULL);
      pos += mlen;
      rsize -= mlen;
    }
  GE_ASSERT (ectx, rsize == 0);
  MUNMAP (buf, (size_t) size);
  CLOSE (fd);
  FREE (fn);
  /* kill invalid entries (meta or uri == NULL) */
  for (i = 0; i < collectionData->file_count; i++)
    {
      if ((collectionData->files[i].uri != NULL) &&
          (collectionData->files[i].meta != NULL))
        continue;
      if (collectionData->files[i].uri != NULL)
        ECRS_freeUri (collectionData->files[i].uri);
      if (collectionData->files[i].meta != NULL)
        ECRS_freeMetaData (collectionData->files[i].meta);
      collectionData->files[i]
        = collectionData->files[collectionData->file_count - 1];
      GROW (collectionData->files,
            collectionData->file_count, collectionData->file_count - 1);
    }
}

static void
WRITEINT (int fd, int val)
{
  int bval;

  bval = htonl (val);
  WRITE (fd, &bval, sizeof (int));
}

static void
writeCO ()
{
  char *fn;
  unsigned int mlen;
  char *buf;
  int fd;
  unsigned int i;
  char *tmp;

  if (collectionData == NULL)
    return;

  /* write collection data */
  mlen = ECRS_sizeofMetaData (collectionData->meta, NO);
  buf = MALLOC (mlen);
  if (mlen != ECRS_serializeMetaData (ectx,
                                      collectionData->meta, buf, mlen, NO))
    {
      GE_BREAK (ectx, 0);
      FREE (buf);
      return;
    }

  fn = getCollectionFileName ();
  fd = OPEN (fn,
             O_CREAT | O_LARGEFILE | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
  if (fd == -1)
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_USER | GE_ADMIN | GE_ERROR | GE_BULK,
                            "open", fn);
      FREE (fn);
      FREE (buf);
      return;
    }
  GE_BREAK (ectx, collectionData->file_count <= 1024 * 1024 * 4);
  WRITE (fd, collectionData, sizeof (CollectionData));
  WRITEINT (fd, collectionData->file_count);
  WRITEINT (fd, collectionData->changed);
  WRITEINT (fd, mlen);
  GE_BREAK (ectx, strlen (collectionData->name) < 1024);
  WRITEINT (fd, strlen (collectionData->name));
  WRITE (fd, collectionData->name, strlen (collectionData->name));
  WRITE (fd, buf, mlen);
  FREE (buf);
  for (i = 0; i < collectionData->file_count; i++)
    {
      mlen = ECRS_sizeofMetaData (collectionData->files[i].meta, NO);
      buf = MALLOC (mlen);
      if (mlen != ECRS_serializeMetaData (ectx,
                                          collectionData->files[i].meta,
                                          buf, mlen, NO))
        {
          GE_BREAK (ectx, 0);
          FREE (buf);
          break;
        }
      tmp = ECRS_uriToString (collectionData->files[i].uri);
      WRITEINT (fd, strlen (tmp));
      WRITEINT (fd, mlen);
      GE_BREAK (ectx, strlen (tmp) < 16 * 1024);
      WRITE (fd, tmp, strlen (tmp));
      FREE (tmp);
      WRITE (fd, buf, mlen);
      FREE (buf);
    }
  CLOSE (fd);
  FREE (fn);
}

/**
 * Shutdown collection module.
 */
void
CO_done ()
{
  writeCO ();
  CO_stopCollection ();
  MUTEX_DESTROY (lock);
  lock = NULL;
  ectx = NULL;
  cfg = NULL;
}


/**
 * Start collection.
 *
 * @param updateInterval of ECRS_SBLOCK_UPDATE_NONE
 *        means to update _immediately_ on any change,
 *        wherease ECRS_SBLOCK_UPDATE_SPORADIC means
 *        to publish updates when the CO_Context
 *        is destroyed (i.e. on exit from the UI).
 */
int
CO_startCollection (unsigned int anonymityLevel,
                    unsigned int prio,
                    TIME_T updateInterval,
                    const char *name, const struct ECRS_MetaData *meta)
{
  struct ECRS_URI *advertisement;
  struct ECRS_URI *rootURI;
  HashCode512 nextId;
  TIME_T now;

  MUTEX_LOCK (lock);
  CO_stopCollection ();         /* cancel old collection */
  GE_ASSERT (ectx, name != NULL);
  advertisement = ECRS_parseCharKeywordURI (ectx, COLLECTION);
  GE_ASSERT (ectx, advertisement != NULL);
  TIME (&now);
  makeRandomId (&nextId);
  rootURI = ECRS_createNamespace (ectx,
                                  cfg,
                                  name,
                                  meta,
                                  anonymityLevel,
                                  prio,
                                  get_time () + COLLECTION_ADV_LIFETIME,
                                  advertisement, &nextId);
  if (rootURI == NULL)
    {
      ECRS_freeUri (advertisement);
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  ECRS_freeUri (advertisement);
  ECRS_freeUri (rootURI);
  collectionData = MALLOC (sizeof (CollectionInfo));
  memset (collectionData, 0, sizeof (CollectionInfo));
  makeRandomId (&collectionData->data.lastId);
  collectionData->data.nextId = nextId;
  collectionData->data.updateInterval = htonl (updateInterval);
  collectionData->data.anonymityLevel = htonl (anonymityLevel);
  collectionData->data.priority = htonl (prio);
  collectionData->meta = ECRS_dupMetaData (meta);
  collectionData->name = STRDUP (name);
  MUTEX_UNLOCK (lock);
  return OK;
}

/**
 * Stop collection.
 *
 * @return OK on success, SYSERR if no collection is active
 */
int
CO_stopCollection ()
{
  unsigned int i;

  MUTEX_LOCK (lock);
  if (collectionData == NULL)
    {
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  ECRS_deleteNamespace (ectx, cfg, collectionData->name);
  ECRS_freeMetaData (collectionData->meta);
  for (i = 0; i < collectionData->file_count; i++)
    {
      ECRS_freeMetaData (collectionData->files[i].meta);
      ECRS_freeUri (collectionData->files[i].uri);
    }
  GROW (collectionData->files, collectionData->file_count, 0);
  FREE (collectionData->name);
  FREE (collectionData);
  collectionData = NULL;
  MUTEX_UNLOCK (lock);
  return OK;
}

/**
 * Are we using a collection?
 *
 * @return NULL if there is no collection, otherwise its name
 */
char *
CO_getCollection ()
{
  char *name;

  MUTEX_LOCK (lock);
  if (collectionData == NULL)
    {
      MUTEX_UNLOCK (lock);
      return NULL;
    }
  name = STRDUP (collectionData->name);
  MUTEX_UNLOCK (lock);
  return name;
}

/**
 * Upload an update of the current collection information to the
 * network now.  The function has no effect if the collection has not
 * changed since the last publication.  If we are currently not
 * collecting, this function does nothing.
 *
 * Note that clients typically don't have to call this
 * function explicitly.  CO will call the function on
 * exit (for sporadically updated collections), on any
 * change to the collection (for immediately updated
 * content) or when the publication time has arrived
 * (for periodically updated collections).
 *
 * However, clients may want to call this function if
 * explicit publication of an update at another
 * time is desired.
 */
void
CO_publishCollectionNow ()
{
  HashCode512 delta;
  TIME_T now;
  struct ECRS_URI *uri;
  struct ECRS_URI *directoryURI;
  unsigned long long dirLen;
  char *tmpName;
  int fd;
  char *dirData;

  MUTEX_LOCK (lock);
  if ((collectionData == NULL) || (collectionData->changed == NO))
    {
      MUTEX_UNLOCK (lock);
      return;
    }
  TIME (&now);
  if ((ntohl (collectionData->data.updateInterval) != ECRS_SBLOCK_UPDATE_NONE)
      && (ntohl (collectionData->data.updateInterval) !=
          ECRS_SBLOCK_UPDATE_SPORADIC)
      && (ntohl (collectionData->data.lastPublication) +
          ntohl (collectionData->data.updateInterval) < now))
    {
      MUTEX_UNLOCK (lock);
      return;
    }
  if ((ntohl (collectionData->data.updateInterval) != ECRS_SBLOCK_UPDATE_NONE)
      && (ntohl (collectionData->data.updateInterval) !=
          ECRS_SBLOCK_UPDATE_SPORADIC))
    {
      deltaId (&collectionData->data.nextId,
               &collectionData->data.lastId, &delta);
      collectionData->data.lastId = collectionData->data.nextId;
      addHashCodes (&collectionData->data.nextId,
                    &delta, &collectionData->data.nextId);
    }
  else
    {
      collectionData->data.lastId = collectionData->data.nextId;
      makeRandomId (&collectionData->data.nextId);
    }
  tmpName = STRDUP ("/tmp/gnunet-collectionXXXXXX");
  fd = mkstemp (tmpName);
  if (fd == -1)
    {
      GE_LOG_STRERROR (ectx, GE_ERROR | GE_ADMIN | GE_BULK, "mkstemp");
      FREE (tmpName);
      MUTEX_UNLOCK (lock);
      return;
    }
  dirData = NULL;
  GE_ASSERT (ectx,
             OK == ECRS_createDirectory (ectx,
                                         &dirData,
                                         &dirLen,
                                         collectionData->file_count,
                                         collectionData->files,
                                         collectionData->meta));
  if (-1 == WRITE (fd, dirData, dirLen))
    {
      GE_LOG_STRERROR (ectx, GE_ERROR | GE_ADMIN | GE_BULK, "write");
      FREE (tmpName);
      FREE (dirData);
      MUTEX_UNLOCK (lock);
      return;
    }
  FREE (dirData);
  CLOSE (fd);
  if (OK != ECRS_uploadFile (ectx, cfg, tmpName, NO,    /* indexing */
                             ntohl (collectionData->data.anonymityLevel),
                             ntohl (collectionData->data.priority),
                             get_time () + COLLECTION_ADV_LIFETIME,
                             NULL, NULL, NULL, NULL, &directoryURI))
    {
      UNLINK (tmpName);
      FREE (tmpName);
      MUTEX_UNLOCK (lock);
      return;
    }
  UNLINK (tmpName);
  FREE (tmpName);
  uri = ECRS_addToNamespace (ectx,
                             cfg,
                             collectionData->name,
                             ntohl (collectionData->data.anonymityLevel),
                             ntohl (collectionData->data.priority),
                             get_time () + COLLECTION_ADV_LIFETIME,
                             now,
                             ntohl (collectionData->data.updateInterval),
                             &collectionData->data.lastId,
                             &collectionData->data.nextId,
                             directoryURI, collectionData->meta);
  if (uri != NULL)
    {
      collectionData->data.lastPublication = htonl (now);
      collectionData->changed = NO;
      ECRS_freeUri (uri);
    }
  MUTEX_UNLOCK (lock);
}

/**
 * If we are currently building a collection, publish
 * the given file information in that collection.
 * If we are currently not collecting, this function
 * does nothing.
 *
 * Note that clients typically don't have to call this
 * function explicitly -- by using the CO library it
 * should be called automatically by CO code whenever
 * needed.  However, the function maybe useful if you're
 * inserting files using libECRS directly or need other
 * ways to explicitly extend a collection.
 */
void
CO_publishToCollection (const ECRS_FileInfo * fi)
{
  unsigned int i;
  ECRS_FileInfo fc;

  if ((ECRS_isKeywordUri (fi->uri)))
    {
      GE_BREAK (ectx, 0);
      return;
    }
  if (lock == NULL)
    {
      GE_BREAK (ectx, 0);
      return;
    }
  MUTEX_LOCK (lock);
  if (collectionData == NULL)
    {
      MUTEX_UNLOCK (lock);
      return;
    }
  for (i = 0; i < collectionData->file_count; i++)
    {
      if (ECRS_equalsUri (fi->uri, collectionData->files[i].uri))
        {
          MUTEX_UNLOCK (lock);
          return;
        }
    }
  fc.uri = ECRS_dupUri (fi->uri);
  fc.meta = ECRS_dupMetaData (fi->meta);
  APPEND (collectionData->files, collectionData->file_count, fc);
  collectionData->changed = YES;
  if (ntohl (collectionData->data.updateInterval) == ECRS_SBLOCK_UPDATE_NONE)
    CO_publishCollectionNow ();
  MUTEX_UNLOCK (lock);
}

/* end of collection.c */
