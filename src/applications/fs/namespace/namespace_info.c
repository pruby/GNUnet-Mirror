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
 * @file applications/fs/namespace/namespace_info.c
 * @brief keeping track of namespaces and metadata about them
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_util.h"
#include "namespace_info.h"
#include "namespace_notification.h"
#include "common.h"


static void
write_namespace_info (struct GNUNET_GE_Context *ectx,
                      struct GNUNET_GC_Configuration *cfg,
                      const GNUNET_HashCode * nsid,
                      const struct GNUNET_ECRS_MetaData *meta,
                      int ranking, const char *ns_name)
{
  unsigned int size;
  unsigned int tag;
  unsigned int off;
  char *buf;
  char *fn;

  fn = GNUNET_NS_internal_get_data_filename_ (ectx,
                                              cfg,
                                              NS_METADATA_DIR, nsid, NULL);
  size =
    GNUNET_ECRS_meta_data_get_serialized_size (meta,
                                               GNUNET_ECRS_SERIALIZE_FULL);
  tag = size + sizeof (int) + 1;
  off = 0;
  if (ns_name != NULL)
    {
      off = strlen (ns_name);
      tag += off;
    }
  buf = GNUNET_malloc (tag);
  ((int *) buf)[0] = htonl (ranking);   /* ranking */
  if (ns_name != NULL)
    {
      memcpy (&buf[sizeof (int)], ns_name, off + 1);
    }
  else
    {
      buf[sizeof (int)] = '\0';
    }
  GNUNET_GE_ASSERT (ectx,
                    size == GNUNET_ECRS_meta_data_serialize (ectx,
                                                             meta,
                                                             &buf[sizeof
                                                                  (int) +
                                                                  off + 1],
                                                             size,
                                                             GNUNET_ECRS_SERIALIZE_FULL));
  GNUNET_disk_file_write (ectx, fn, buf, tag, "660");
  GNUNET_free (fn);
  GNUNET_free (buf);
  /* create entry for namespace name in names */
  GNUNET_free_non_null (GNUNET_NS_nsid_to_name (ectx, cfg, nsid));
}

int
GNUNET_NS_internal_read_namespace_info_ (struct GNUNET_GE_Context *ectx,
                                         struct GNUNET_GC_Configuration *cfg,
                                         const GNUNET_HashCode * nsid,
                                         struct GNUNET_ECRS_MetaData **meta,
                                         int *ranking, char **ns_name)
{
  unsigned long long len;
  unsigned int size;
  unsigned int zend;
  char *buf;
  char *fn;

  if (meta != NULL)
    *meta = NULL;
  if (ns_name != NULL)
    *ns_name = NULL;
  fn = GNUNET_NS_internal_get_data_filename_ (ectx,
                                              cfg,
                                              NS_METADATA_DIR, nsid, NULL);
  if ((GNUNET_OK != GNUNET_disk_file_test (ectx,
                                           fn) ||
       (GNUNET_OK != GNUNET_disk_file_size (ectx, fn, &len, GNUNET_YES))))
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  if (len <= sizeof (int) + 1)
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  if (len > 16 * 1024 * 1024)
    {
      /* too big, must be invalid! remove! */
      GNUNET_GE_BREAK (ectx, 0);
      UNLINK (fn);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  buf = GNUNET_malloc (len);
  if (len != GNUNET_disk_file_read (ectx, fn, len, buf))
    {
      GNUNET_free (buf);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  if (ranking != NULL)
    *ranking = ntohl (((int *) buf)[0]);
  zend = sizeof (int);
  while ((zend < len) && (buf[zend] != '\0'))
    zend++;
  if (zend == len)
    {
      GNUNET_free (buf);
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  if (ns_name != NULL)
    {
      if (zend != sizeof (int))
        *ns_name = GNUNET_strdup (&buf[sizeof (int)]);
      else
        *ns_name = NULL;
    }
  zend++;
  size = len - zend;
  if (meta != NULL)
    {
      *meta = GNUNET_ECRS_meta_data_deserialize (ectx, &buf[zend], size);
      if ((*meta) == NULL)
        {
          /* invalid data! remove! */
          GNUNET_GE_BREAK (ectx, 0);
          UNLINK (fn);
          GNUNET_free (buf);
          GNUNET_free (fn);
          return GNUNET_SYSERR;
        }
    }
  GNUNET_free (fn);
  GNUNET_free (buf);
  return GNUNET_OK;
}

struct ListNamespaceClosure
{
  GNUNET_NS_NamespaceIterator iterator;
  void *closure;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
};

static int
list_namespace_helper (const char *fn, const char *dirName, void *cls)
{
  struct ListNamespaceClosure *c = cls;
  int ret;
  GNUNET_HashCode id;
  char *name;
  int rating;
  struct GNUNET_ECRS_MetaData *meta;

  ret = GNUNET_OK;
  if (GNUNET_OK != GNUNET_enc_to_hash (fn, &id))
    return GNUNET_OK;           /* invalid name */
  if (GNUNET_OK !=
      GNUNET_NS_internal_read_namespace_info_ (c->ectx, c->cfg, &id, &meta,
                                               &rating, NULL))
    return GNUNET_OK;           /* ignore entry */
  name = GNUNET_NS_nsid_to_name (c->ectx, c->cfg, &id);
  if (c->iterator != NULL)
    ret = c->iterator (c->closure, name, &id, meta, rating);
  GNUNET_free_non_null (name);
  GNUNET_ECRS_meta_data_destroy (meta);
  return ret;
}

/**
 * List all available namespaces.
 */
int
GNUNET_NS_namespace_list_all (struct GNUNET_GE_Context *ectx,
                              struct GNUNET_GC_Configuration *cfg,
                              GNUNET_NS_NamespaceIterator iterator,
                              void *closure)
{
  struct ListNamespaceClosure cls;
  char *fn;
  int ret;

  cls.iterator = iterator;
  cls.closure = closure;
  cls.ectx = ectx;
  cls.cfg = cfg;
  fn =
    GNUNET_NS_internal_get_data_filename_ (ectx, cfg, NS_METADATA_DIR, NULL,
                                           NULL);
  GNUNET_disk_directory_create (ectx, fn);
  ret = GNUNET_disk_directory_scan (ectx, fn, &list_namespace_helper, &cls);
  GNUNET_free (fn);
  return ret;
}

/**
 * Create a new namespace (and publish an advertismement).
 * This function is synchronous, but may block the system
 * for a while since it must create a public-private key pair!
 *
 * @param meta meta-data about the namespace (maybe NULL)
 * @return namespace root URI on success, NULL on error (namespace already exists)
 */
struct GNUNET_ECRS_URI *
GNUNET_NS_namespace_create (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg,
                            unsigned int anonymityLevel,
                            unsigned int insertPriority,
                            GNUNET_CronTime insertExpiration,
                            const char *namespaceName,
                            const struct GNUNET_ECRS_MetaData *meta,
                            const struct GNUNET_ECRS_URI *advertisementURI,
                            const GNUNET_HashCode * rootEntry)
{
  struct GNUNET_ECRS_URI *ret;
  GNUNET_HashCode id;

  ret = GNUNET_ECRS_namespace_create (ectx,
                                      cfg,
                                      namespaceName,
                                      meta,
                                      anonymityLevel,
                                      insertPriority,
                                      insertExpiration, advertisementURI,
                                      rootEntry);
  if (ret != NULL)
    {
      GNUNET_NS_namespace_set_root (ectx, cfg, ret);
      GNUNET_ECRS_uri_get_namespace_from_sks (ret, &id);
      write_namespace_info (ectx, cfg, &id, meta, 0, namespaceName);
      GNUNET_NS_internal_notify_ (namespaceName, &id, meta, 0);
    }
  return ret;
}

/**
 * Delete a local namespace.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_NS_namespace_delete (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg,
                            const GNUNET_HashCode * nsid)
{
  int ret;
  char *ns_name;
  char *fn;

  if (GNUNET_OK != GNUNET_NS_internal_read_namespace_info_ (ectx,
                                                            cfg,
                                                            nsid,
                                                            NULL,
                                                            NULL, &ns_name))
    return GNUNET_SYSERR;
  if (ns_name == NULL)
    return GNUNET_SYSERR;
  ret = GNUNET_ECRS_namespace_delete (ectx, cfg, ns_name);
  GNUNET_free (ns_name);
  fn = GNUNET_NS_internal_get_data_filename_ (ectx,
                                              cfg, NS_UPDATE_DIR, nsid, NULL);
  GNUNET_disk_directory_remove (ectx, fn);
  GNUNET_free (fn);
  return ret;
}

/**
 * Change the ranking of a namespace.
 *
 * @param nsid id of the namespace
 * @param delta by how much should the rating be
 *  changed?
 * @return new rating of the namespace
 */
int
GNUNET_NS_namespace_rank (struct GNUNET_GE_Context *ectx,
                          struct GNUNET_GC_Configuration *cfg,
                          const GNUNET_HashCode * nsid, int delta)
{
  struct GNUNET_ECRS_MetaData *meta;
  int ret;
  int ranking;
  char *name;

  ret =
    GNUNET_NS_internal_read_namespace_info_ (ectx, cfg, nsid, &meta, &ranking,
                                             &name);
  if (ret == GNUNET_SYSERR)
    {
      ranking = 0;
      meta = GNUNET_ECRS_meta_data_create ();
    }
  ranking += delta;
  write_namespace_info (ectx, cfg, nsid, meta, ranking, name);
  GNUNET_ECRS_meta_data_destroy (meta);
  GNUNET_free (name);
  return ranking;
}

/**
 * Insert metadata into existing MD record (passed as cls).
 */
static int
merge_meta_helper (EXTRACTOR_KeywordType type, const char *data, void *cls)
{
  struct GNUNET_ECRS_MetaData *meta = cls;
  GNUNET_ECRS_meta_data_insert (meta, type, data);
  return GNUNET_OK;
}

/**
 * Add a namespace to the set of known namespaces.
 * For all namespace advertisements that we discover
 * FSUI should automatically call this function.
 *
 * @param ns the namespace identifier
 */
void
GNUNET_NS_namespace_add_information (struct GNUNET_GE_Context *ectx,
                                     struct GNUNET_GC_Configuration *cfg,
                                     const struct GNUNET_ECRS_URI *uri,
                                     const struct GNUNET_ECRS_MetaData *meta)
{
  char *name;
  int ranking;
  struct GNUNET_ECRS_MetaData *old;
  GNUNET_HashCode id;

  if (!GNUNET_ECRS_uri_test_sks (uri))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return;
    }
  GNUNET_ECRS_uri_get_namespace_from_sks (uri, &id);
  ranking = 0;
  if (GNUNET_OK ==
      GNUNET_NS_internal_read_namespace_info_ (ectx, cfg, &id, &old, &ranking,
                                               &name))
    {
      GNUNET_ECRS_meta_data_get_contents (meta, &merge_meta_helper, old);
      write_namespace_info (ectx, cfg, &id, old, ranking, name);
      GNUNET_ECRS_meta_data_destroy (old);
    }
  else
    {
      write_namespace_info (ectx, cfg, &id, meta, ranking, NULL);
    }
  GNUNET_NS_internal_notify_ (name, &id, meta, ranking);
  GNUNET_free_non_null (name);
}


/* end of namespace_info.c */
