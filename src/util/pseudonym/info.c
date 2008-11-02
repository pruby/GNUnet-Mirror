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
 * @file util/pseudonym/info.c
 * @brief keeping track of pseudonyms and metadata about them
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "info.h"
#include "notification.h"
#include "common.h"


static void
write_pseudonym_info (struct GNUNET_GE_Context *ectx,
                      struct GNUNET_GC_Configuration *cfg,
                      const GNUNET_HashCode * nsid,
                      const struct GNUNET_MetaData *meta,
                      int ranking, const char *ns_name)
{
  unsigned int size;
  unsigned int tag;
  unsigned int off;
  char *buf;
  char *fn;

  fn = GNUNET_pseudonym_internal_get_data_filename_ (ectx,
                                                     cfg, PS_METADATA_DIR,
                                                     nsid);
  size = GNUNET_meta_data_get_serialized_size (meta, GNUNET_SERIALIZE_FULL);
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
                    size == GNUNET_meta_data_serialize (ectx,
                                                        meta,
                                                        &buf[sizeof
                                                             (int) +
                                                             off + 1],
                                                        size,
                                                        GNUNET_SERIALIZE_FULL));
  GNUNET_disk_file_write (ectx, fn, buf, tag, "660");
  GNUNET_free (fn);
  GNUNET_free (buf);
  /* create entry for pseudonym name in names */
  GNUNET_free_non_null (GNUNET_pseudonym_id_to_name (ectx, cfg, nsid));
}

int
GNUNET_pseudonym_internal_read_info_ (struct GNUNET_GE_Context *ectx,
                                      struct GNUNET_GC_Configuration *cfg,
                                      const GNUNET_HashCode * nsid,
                                      struct GNUNET_MetaData **meta,
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
  fn = GNUNET_pseudonym_internal_get_data_filename_ (ectx,
                                                     cfg, PS_METADATA_DIR,
                                                     nsid);
  if ((GNUNET_OK != GNUNET_disk_file_test (ectx, fn)
       || (GNUNET_OK != GNUNET_disk_file_size (ectx, fn, &len, GNUNET_YES))))
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
      *meta = GNUNET_meta_data_deserialize (ectx, &buf[zend], size);
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

struct ListPseudonymClosure
{
  GNUNET_PseudonymIterator iterator;
  void *closure;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
};

static int
list_pseudonym_helper (void *cls, const char *fullname)
{
  struct ListPseudonymClosure *c = cls;
  int ret;
  GNUNET_HashCode id;
  int rating;
  struct GNUNET_MetaData *meta;
  const char *fn;

  if (strlen (fullname) < sizeof (GNUNET_EncName))
    return GNUNET_OK;
  fn = &fullname[strlen (fullname) + 1 - sizeof (GNUNET_EncName)];
  if (fn[-1] != DIR_SEPARATOR)
    return GNUNET_OK;
  ret = GNUNET_OK;
  if (GNUNET_OK != GNUNET_enc_to_hash (fn, &id))
    return GNUNET_OK;           /* invalid name */
  if (GNUNET_OK !=
      GNUNET_pseudonym_internal_read_info_ (c->ectx, c->cfg, &id, &meta,
                                            &rating, NULL))
    return GNUNET_OK;           /* ignore entry */
  if (c->iterator != NULL)
    ret = c->iterator (c->closure, &id, meta, rating);
  GNUNET_meta_data_destroy (meta);
  return ret;
}

/**
 * List all available pseudonyms.
 */
int
GNUNET_pseudonym_list_all (struct GNUNET_GE_Context *ectx,
                           struct GNUNET_GC_Configuration *cfg,
                           GNUNET_PseudonymIterator iterator, void *closure)
{
  struct ListPseudonymClosure cls;
  char *fn;
  int ret;

  cls.iterator = iterator;
  cls.closure = closure;
  cls.ectx = ectx;
  cls.cfg = cfg;
  fn =
    GNUNET_pseudonym_internal_get_data_filename_ (ectx, cfg, PS_METADATA_DIR,
                                                  NULL);
  GNUNET_disk_directory_create (ectx, fn);
  ret = GNUNET_disk_directory_scan (ectx, fn, &list_pseudonym_helper, &cls);
  GNUNET_free (fn);
  return ret;
}

/**
 * Change the ranking of a pseudonym.
 *
 * @param nsid id of the pseudonym
 * @param delta by how much should the rating be
 *  changed?
 * @return new rating of the pseudonym
 */
int
GNUNET_pseudonym_rank (struct GNUNET_GE_Context *ectx,
                       struct GNUNET_GC_Configuration *cfg,
                       const GNUNET_HashCode * nsid, int delta)
{
  struct GNUNET_MetaData *meta;
  int ret;
  int ranking;
  char *name;

  name = NULL;
  ret =
    GNUNET_pseudonym_internal_read_info_ (ectx, cfg, nsid, &meta, &ranking,
                                          &name);
  if (ret == GNUNET_SYSERR)
    {
      ranking = 0;
      meta = GNUNET_meta_data_create ();
    }
  ranking += delta;
  write_pseudonym_info (ectx, cfg, nsid, meta, ranking, name);
  GNUNET_meta_data_destroy (meta);
  GNUNET_free_non_null (name);
  return ranking;
}

/**
 * Insert metadata into existing MD record (passed as cls).
 */
static int
merge_meta_helper (EXTRACTOR_KeywordType type, const char *data, void *cls)
{
  struct GNUNET_MetaData *meta = cls;
  GNUNET_meta_data_insert (meta, type, data);
  return GNUNET_OK;
}

/**
 * Add a pseudonym to the set of known pseudonyms.
 * For all pseudonym advertisements that we discover
 * FSUI should automatically call this function.
 *
 * @param id the pseudonym identifier
 */
void
GNUNET_pseudonym_add (struct GNUNET_GE_Context *ectx,
                      struct GNUNET_GC_Configuration *cfg,
                      const GNUNET_HashCode * id,
                      const struct GNUNET_MetaData *meta)
{
  char *name;
  int ranking;
  struct GNUNET_MetaData *old;

  ranking = 0;
  if (GNUNET_OK ==
      GNUNET_pseudonym_internal_read_info_ (ectx, cfg, id, &old, &ranking,
                                            &name))
    {
      GNUNET_meta_data_get_contents (meta, &merge_meta_helper, old);
      write_pseudonym_info (ectx, cfg, id, old, ranking, name);
      GNUNET_meta_data_destroy (old);
    }
  else
    {
      write_pseudonym_info (ectx, cfg, id, meta, ranking, NULL);
    }
  GNUNET_pseudonym_internal_notify_ (id, meta, ranking);
  GNUNET_free_non_null (name);
}


/* end of info.c */
