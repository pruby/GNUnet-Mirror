/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/namespace/update_info.c
 * @brief support for content updates
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_util.h"
#include "common.h"


struct UpdateData
{
  GNUNET_Int32Time updateInterval;
  GNUNET_Int32Time lastPubTime;
  GNUNET_HashCode nextId;
  GNUNET_HashCode thisId;
};

/**
 * Read content update information about content
 * published in the given namespace under 'lastId'.
 *
 * @param fi maybe NULL
 * @return GNUNET_OK if update data was found, GNUNET_SYSERR if not.
 */
static int
read_update_data (struct GNUNET_GE_Context *ectx,
                  struct GNUNET_GC_Configuration *cfg,
                  const GNUNET_HashCode * nsid,
                  const GNUNET_HashCode * lastId,
                  GNUNET_HashCode * nextId,
                  GNUNET_ECRS_FileInfo * fi,
                  GNUNET_Int32Time * updateInterval,
                  GNUNET_Int32Time * lastPubTime)
{
  char *fn;
  struct UpdateData *buf;
  char *uri;
  unsigned long long size;
  size_t pos;

  fn = GNUNET_NS_internal_get_data_filename_ (ectx,
                                              cfg,
                                              NS_UPDATE_DIR, nsid, lastId);
  if (GNUNET_OK != GNUNET_disk_file_size (ectx, fn, &size, GNUNET_YES))
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  if ((size == 0) ||
      (size <= sizeof (struct UpdateData)) || (size > 1024 * 1024 * 16))
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  buf = GNUNET_malloc (size);
  if (size != GNUNET_disk_file_read (ectx, fn, size, buf))
    {
      GNUNET_free (buf);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fn);
  if (0 != memcmp (lastId, &buf->thisId, sizeof (GNUNET_HashCode)))
    {
      GNUNET_free (buf);
      return GNUNET_SYSERR;
    }
  uri = (char *) &buf[1];
  size -= sizeof (struct UpdateData);
  pos = 0;
  while ((pos < size) && (uri[pos] != '\0'))
    pos++;
  pos++;
  size -= pos;
  if (size == 0)
    {
      GNUNET_free (buf);
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (fi != NULL)
    {
      fi->meta = GNUNET_ECRS_meta_data_deserialize (ectx, &uri[pos], size);
      if (fi->meta == NULL)
        {
          GNUNET_free (buf);
          GNUNET_GE_BREAK (ectx, 0);
          return GNUNET_SYSERR;
        }
      fi->uri = GNUNET_ECRS_string_to_uri (ectx, uri);
      if (fi->uri == NULL)
        {
          GNUNET_ECRS_meta_data_destroy (fi->meta);
          fi->meta = NULL;
          GNUNET_free (buf);
          GNUNET_GE_BREAK (ectx, 0);
          return GNUNET_SYSERR;
        }
    }
  if (updateInterval != NULL)
    *updateInterval = ntohl (buf->updateInterval);
  if (lastPubTime != NULL)
    *lastPubTime = ntohl (buf->lastPubTime);
  if (nextId != NULL)
    *nextId = buf->nextId;
  GNUNET_free (buf);
  return GNUNET_OK;
}

/**
 * Write content update information.
 */
static int
write_update_data (struct GNUNET_GE_Context *ectx,
                   struct GNUNET_GC_Configuration *cfg,
                   const GNUNET_HashCode * nsid,
                   const GNUNET_HashCode * thisId,
                   const GNUNET_HashCode * nextId,
                   const GNUNET_ECRS_FileInfo * fi,
                   const GNUNET_Int32Time updateInterval,
                   const GNUNET_Int32Time lastPubTime)
{
  char *fn;
  char *uri;
  size_t metaSize;
  size_t size;
  struct UpdateData *buf;

  uri = GNUNET_ECRS_uri_to_string (fi->uri);
  metaSize =
    GNUNET_ECRS_meta_data_get_serialized_size (fi->meta,
                                               GNUNET_ECRS_SERIALIZE_FULL);
  size = sizeof (struct UpdateData) + metaSize + strlen (uri) + 1;
  buf = GNUNET_malloc (size);
  buf->nextId = *nextId;
  buf->thisId = *thisId;
  buf->updateInterval = htonl (updateInterval);
  buf->lastPubTime = htonl (lastPubTime);
  memcpy (&buf[1], uri, strlen (uri) + 1);
  GNUNET_GE_ASSERT (ectx,
                    metaSize ==
                    GNUNET_ECRS_meta_data_serialize (ectx,
                                                     fi->meta,
                                                     &((char *)
                                                       &buf[1])[strlen (uri) +
                                                                1], metaSize,
                                                     GNUNET_ECRS_SERIALIZE_FULL));
  GNUNET_free (uri);
  fn = GNUNET_NS_internal_get_data_filename_ (ectx,
                                              cfg,
                                              NS_UPDATE_DIR, nsid, thisId);
  GNUNET_disk_file_write (ectx, fn, buf, size, "400");  /* no editing, just deletion */
  GNUNET_free (fn);
  GNUNET_free (buf);
  return GNUNET_OK;
}


/**
 * Compute the next ID for peridodically updated content.
 * @param updateInterval MUST be a peridic interval (not NONE or SPORADIC)
 * @param thisId MUST be known to NAMESPACE
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_NS_compute_next_identifier (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const GNUNET_HashCode * nsid,
                                   const GNUNET_HashCode * lastId,
                                   const GNUNET_HashCode * thisId,
                                   GNUNET_Int32Time updateInterval,
                                   GNUNET_HashCode * nextId)
{
  GNUNET_HashCode delta;
  GNUNET_CronTime now;
  GNUNET_Int32Time tnow;
  GNUNET_Int32Time lastTime;
  GNUNET_Int32Time ui;

  if ((updateInterval == GNUNET_ECRS_SBLOCK_UPDATE_SPORADIC) ||
      (updateInterval == GNUNET_ECRS_SBLOCK_UPDATE_NONE))
    return GNUNET_SYSERR;

  if (GNUNET_OK != read_update_data (ectx,
                                     cfg, nsid, lastId, NULL, NULL, &ui,
                                     &lastTime))
    return GNUNET_SYSERR;
  GNUNET_hash_difference (lastId, thisId, &delta);
  now = GNUNET_get_time ();
  GNUNET_get_time_int32 (&tnow);
  *nextId = *thisId;
  while (lastTime < tnow + updateInterval / 2)
    {
      lastTime += updateInterval;
      GNUNET_hash_sum (nextId, &delta, nextId);
    }
  return GNUNET_OK;
}


/**
 * Add an entry into a namespace (also for publishing
 * updates).
 *
 * @param name in which namespace to publish
 * @param updateInterval the desired frequency for updates
 * @param lastId the ID of the last value (maybe NULL)
 * @param thisId the ID of the update (maybe NULL)
 * @param nextId the ID of the next update (maybe NULL)
 * @param dst to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @param uri set to the resulting URI
 */
struct GNUNET_ECRS_URI *
GNUNET_NS_add_to_namespace (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg,
                            unsigned int anonymityLevel,
                            unsigned int insertPriority,
                            GNUNET_CronTime insertExpiration,
                            const GNUNET_HashCode * nsid,
                            GNUNET_Int32Time updateInterval,
                            const GNUNET_HashCode * lastId,
                            const GNUNET_HashCode * thisId,
                            const GNUNET_HashCode * nextId,
                            const struct GNUNET_ECRS_URI *dst,
                            const struct GNUNET_ECRS_MetaData *md)
{
  GNUNET_Int32Time creationTime;
  GNUNET_HashCode nid;
  GNUNET_HashCode tid;
  GNUNET_HashCode delta;
  GNUNET_Int32Time now;
  GNUNET_Int32Time lastTime;
  GNUNET_Int32Time lastInterval;
  GNUNET_ECRS_FileInfo fi;
  char *old;
  struct GNUNET_ECRS_URI *uri;

  /* computation of IDs of update(s).  Not as terrible as
     it looks, just enumerating all of the possible cases
     of periodic/sporadic updates and how IDs are computed. */
  creationTime = GNUNET_get_time_int32 (&now);
  if (updateInterval != GNUNET_ECRS_SBLOCK_UPDATE_NONE)
    {
      if ((lastId != NULL) &&
          (GNUNET_OK == read_update_data (ectx,
                                          cfg,
                                          nsid,
                                          lastId,
                                          &tid, NULL, &lastInterval,
                                          &lastTime)))
        {
          if (lastInterval != updateInterval)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_BULK |
                             GNUNET_GE_USER,
                             _
                             ("Publication interval for periodic publication changed."));
            }
          /* try to compute tid and/or
             nid based on information read from lastId */

          if (updateInterval != GNUNET_ECRS_SBLOCK_UPDATE_SPORADIC)
            {
              GNUNET_hash_difference (lastId, &tid, &delta);

              creationTime = lastTime + updateInterval;
              while (creationTime < now - updateInterval)
                {
                  creationTime += updateInterval;
                  GNUNET_hash_sum (&tid, &delta, &tid);
                }
              if (creationTime > GNUNET_get_time () + 7 * GNUNET_CRON_DAYS)
                {
                  GNUNET_GE_LOG (ectx,
                                 GNUNET_GE_WARNING | GNUNET_GE_BULK |
                                 GNUNET_GE_USER,
                                 _
                                 ("Publishing update for periodically updated "
                                  "content more than a week ahead of schedule.\n"));
                }
              if (thisId != NULL)
                tid = *thisId;  /* allow override! */
              GNUNET_hash_sum (&tid, &delta, &nid);
              if (nextId != NULL)
                nid = *nextId;  /* again, allow override */
            }
          else
            {
              /* sporadic ones are unpredictable,
                 tid has been obtained from IO, pick random nid if
                 not specified */
              if (thisId != NULL)
                tid = *thisId;  /* allow user override */
              if (nextId == NULL)
                {
                  GNUNET_create_random_hash (&nid);
                }
              else
                {
                  nid = *nextId;
                }
            }
        }
      else
        {                       /* no previous ID found or given */
          if (nextId == NULL)
            {
              /* no previous block found and nextId not specified;
                 pick random nid */
              GNUNET_create_random_hash (&nid);
            }
          else
            {
              nid = *nextId;
            }
          if (thisId != NULL)
            {
              tid = *thisId;
            }
          else
            {
              GNUNET_create_random_hash (&tid);
            }
        }
    }
  else
    {
      if (thisId != NULL)
        {
          nid = tid = *thisId;
        }
      else
        {
          GNUNET_create_random_hash (&tid);
          nid = tid;
        }
    }
  uri = GNUNET_ECRS_namespace_add_content (ectx,
                                           cfg,
                                           nsid,
                                           anonymityLevel,
                                           insertPriority,
                                           insertExpiration,
                                           creationTime,
                                           updateInterval, &tid, &nid, dst,
                                           md);
  if ((uri != NULL) && (dst != NULL))
    {
      fi.uri = (struct GNUNET_ECRS_URI *) dst;
      fi.meta = (struct GNUNET_ECRS_MetaData *) md;
      write_update_data (ectx,
                         cfg,
                         nsid, &tid, &nid, &fi, updateInterval, creationTime);
      if (lastId != NULL)
        {
          old = GNUNET_NS_internal_get_data_filename_ (ectx,
                                                       cfg,
                                                       NS_UPDATE_DIR,
                                                       nsid, lastId);
          UNLINK (old);
          GNUNET_free (old);
        }
    }
  return uri;
}

struct ListNamespaceContentsClosure
{
  GNUNET_HashCode nsid;
  GNUNET_NS_UpdateIterator it;
  void *closure;
  int cnt;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
};

static int
list_namespace_contents_helper (const char *fil, const char *dir, void *ptr)
{
  struct ListNamespaceContentsClosure *cls = ptr;
  GNUNET_ECRS_FileInfo fi;
  GNUNET_HashCode lastId;
  GNUNET_HashCode nextId;
  GNUNET_Int32Time pubFreq;
  GNUNET_Int32Time lastTime;
  GNUNET_Int32Time nextTime;
  GNUNET_Int32Time now;

  if (GNUNET_OK != GNUNET_enc_to_hash (fil, &lastId))
    {
      GNUNET_GE_BREAK (cls->ectx, 0);
      return GNUNET_OK;
    }
  fi.uri = NULL;
  fi.meta = NULL;
  if (GNUNET_OK != read_update_data (cls->ectx,
                                     cls->cfg,
                                     &cls->nsid,
                                     &lastId,
                                     &nextId, &fi, &pubFreq, &lastTime))
    {
      GNUNET_GE_BREAK (cls->ectx, 0);
      return GNUNET_OK;
    }
  cls->cnt++;
  if (pubFreq == GNUNET_ECRS_SBLOCK_UPDATE_SPORADIC)
    {
      nextTime = 0;
    }
  else
    {
      GNUNET_get_time_int32 (&now);
      nextTime = lastTime;
      if ((nextTime + pubFreq < now) && (nextTime + pubFreq > nextTime))
        nextTime += pubFreq * ((now - nextTime) / pubFreq);
    }
  if (cls->it != NULL)
    {
      if (GNUNET_OK != cls->it (cls->closure,
                                &fi, &lastId, &nextId, pubFreq, nextTime))
        {
          GNUNET_ECRS_uri_destroy (fi.uri);
          GNUNET_ECRS_meta_data_destroy (fi.meta);
          return GNUNET_SYSERR;
        }
    }
  GNUNET_ECRS_uri_destroy (fi.uri);
  GNUNET_ECRS_meta_data_destroy (fi.meta);
  return GNUNET_OK;
}

/**
 * List all updateable content in a given namespace.
 */
int
GNUNET_NS_namespace_list_contents (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const GNUNET_HashCode * nsid,
                                   GNUNET_NS_UpdateIterator iterator,
                                   void *closure)
{
  struct ListNamespaceContentsClosure cls;
  char *dirName;

  cls.nsid = *nsid;
  cls.it = iterator;
  cls.closure = closure;
  cls.cnt = 0;
  cls.ectx = ectx;
  cls.cfg = cfg;
  dirName = GNUNET_NS_internal_get_data_filename_ (ectx,
                                                   cfg,
                                                   NS_UPDATE_DIR, nsid, NULL);
  GNUNET_disk_directory_create (ectx, dirName);
  if (GNUNET_SYSERR ==
      GNUNET_disk_directory_scan (ectx, dirName,
                                  &list_namespace_contents_helper, &cls))
    {
      GNUNET_free (dirName);
      return GNUNET_SYSERR;
    }
  GNUNET_free (dirName);
  return cls.cnt;
}


/* end of update_info.c */
