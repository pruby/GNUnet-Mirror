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
                  const GNUNET_HashCode * lid,
                  char **thisId, char **nextId, GNUNET_ECRS_FileInfo * fi)
{
  char *fn;
  char *buf;
  unsigned long long size;
  unsigned int pos;
  const char *pthis;
  const char *pnext;
  const char *puri;

  fn = GNUNET_NS_internal_get_data_filename_ (ectx,
                                              cfg, NS_UPDATE_DIR, nsid, lid);
  if (GNUNET_OK != GNUNET_disk_file_size (ectx, fn, &size, GNUNET_YES))
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  if ((size == 0) || (size > 1024 * 1024 * 16))
    {
      UNLINK (fn);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  buf = GNUNET_malloc (size);
  if (size != GNUNET_disk_file_read (ectx, fn, size, buf))
    {
      GNUNET_free (buf);
      UNLINK (fn);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  GNUNET_free (fn);
  pos = GNUNET_string_buffer_tokenize (buf, size, 3, &pthis, &pnext, &puri);
  if (pos == 0)
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_free (buf);
      return GNUNET_SYSERR;
    }
  if (fi != NULL)
    {
      fi->meta = GNUNET_meta_data_deserialize (ectx, &buf[pos], size - pos);
      if (fi->meta == NULL)
        {
          GNUNET_free (buf);
          GNUNET_GE_BREAK (ectx, 0);
          return GNUNET_SYSERR;
        }
      fi->uri = GNUNET_ECRS_string_to_uri (ectx, puri);
      if (fi->uri == NULL)
        {
          GNUNET_meta_data_destroy (fi->meta);
          fi->meta = NULL;
          GNUNET_free (buf);
          GNUNET_GE_BREAK (ectx, 0);
          return GNUNET_SYSERR;
        }
    }
  if (nextId != NULL)
    *nextId = GNUNET_strdup (pnext);
  if (thisId != NULL)
    *thisId = GNUNET_strdup (pthis);
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
                   const char *thisId,
                   const char *nextId, const GNUNET_ECRS_FileInfo * fi)
{
  char *fn;
  char *uri;
  size_t metaSize;
  size_t size;
  char *buf;
  unsigned int pos;
  GNUNET_HashCode tid;

  if (nextId == NULL)
    nextId = "";
  GNUNET_hash (thisId, strlen (thisId), &tid);
  uri = GNUNET_ECRS_uri_to_string (fi->uri);
  metaSize =
    GNUNET_meta_data_get_serialized_size (fi->meta, GNUNET_SERIALIZE_FULL);
  size = metaSize +
    GNUNET_string_buffer_fill (NULL, 0, 3, uri, thisId, nextId);
  buf = GNUNET_malloc (size);
  pos = GNUNET_string_buffer_fill (buf, size, 3, thisId, nextId, uri);
  GNUNET_GE_ASSERT (ectx, pos != 0);
  GNUNET_GE_ASSERT (ectx,
                    metaSize ==
                    GNUNET_meta_data_serialize (ectx,
                                                fi->meta,
                                                &buf[pos], metaSize,
                                                GNUNET_SERIALIZE_FULL));
  GNUNET_free (uri);
  fn = GNUNET_NS_internal_get_data_filename_ (ectx,
                                              cfg, NS_UPDATE_DIR, nsid, &tid);
  GNUNET_disk_file_write (ectx, fn, buf, size, "400");  /* no editing, just deletion */
  GNUNET_free (fn);
  GNUNET_free (buf);
  return GNUNET_OK;
}

/**
 * Add an entry into a namespace (also for publishing
 * updates).
 *
 * @param name in which namespace to publish
 * @param thisId the ID of the current value
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
                            const char *thisId,
                            const char *nextId,
                            const struct GNUNET_ECRS_URI *dst,
                            const struct GNUNET_MetaData *md)
{
  GNUNET_ECRS_FileInfo fi;
  struct GNUNET_ECRS_URI *uri;

  uri = GNUNET_ECRS_namespace_add_content (ectx,
                                           cfg,
                                           nsid,
                                           anonymityLevel,
                                           insertPriority,
                                           insertExpiration,
                                           thisId, nextId, dst, md);
  if ((uri != NULL) && (dst != NULL))
    {
      fi.uri = (struct GNUNET_ECRS_URI *) dst;
      fi.meta = (struct GNUNET_MetaData *) md;
      write_update_data (ectx, cfg, nsid, thisId, nextId, &fi);
    }
  return uri;
}

struct ListNamespaceContentsClosure
{
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  GNUNET_NS_UpdateIterator it;
  void *closure;
  GNUNET_HashCode nsid;
  int cnt;
};

static int
list_namespace_contents_helper (void *ptr, const char *fullname)
{
  struct ListNamespaceContentsClosure *cls = ptr;
  GNUNET_ECRS_FileInfo fi;
  GNUNET_HashCode lid;
  char *lastId;
  char *nextId;
  int ret;
  const char *fil;

  if (strlen (fullname) < sizeof (GNUNET_EncName))
    return GNUNET_OK;
  fil = &fullname[strlen (fullname) + 1 - sizeof (GNUNET_EncName)];
  if (fil[-1] != DIR_SEPARATOR)
    {
      GNUNET_GE_BREAK (cls->ectx, 0);
      return GNUNET_OK;
    }
  if (GNUNET_OK != GNUNET_enc_to_hash (fil, &lid))
    {
      GNUNET_GE_BREAK (cls->ectx, 0);
      return GNUNET_OK;
    }
  fi.uri = NULL;
  fi.meta = NULL;
  if (GNUNET_OK != read_update_data (cls->ectx,
                                     cls->cfg,
                                     &cls->nsid, &lid, &lastId, &nextId, &fi))
    {
      GNUNET_GE_BREAK (cls->ectx, 0);
      return GNUNET_OK;
    }
  cls->cnt++;
  ret = GNUNET_OK;
  if (cls->it != NULL)
    ret = cls->it (cls->closure, &fi, lastId, nextId);
  GNUNET_free (lastId);
  GNUNET_free (nextId);
  GNUNET_ECRS_uri_destroy (fi.uri);
  GNUNET_meta_data_destroy (fi.meta);
  return ret;
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
