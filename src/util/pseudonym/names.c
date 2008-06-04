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
 * @file util/pseudonym/names.c
 * @brief create unique, human-readable names for namespaces
 * @author Christian Grothoff
 */

#include "platform.h"
#include <extractor.h>
#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "info.h"
#include "common.h"


/**
 * Return the unique, human readable name for the given namespace.
 *
 * @return NULL on failure (should never happen)
 */
char *
GNUNET_pseudonym_id_to_name (struct GNUNET_GE_Context *ectx,
                             struct GNUNET_GC_Configuration *cfg,
                             const GNUNET_HashCode * nsid)
{
  struct GNUNET_MetaData *meta;
  char *name;
  GNUNET_HashCode nh;
  char *fn;
  unsigned long long len;
  int fd;
  unsigned int i;
  unsigned int idx;
  char *ret;

  meta = NULL;
  name = NULL;
  if (GNUNET_OK ==
      GNUNET_pseudonym_internal_read_info_ (ectx, cfg, nsid, &meta, NULL,
                                            &name))
    {
      if ((meta != NULL) && (name == NULL))
        name = GNUNET_meta_data_get_first_by_types (meta,
                                                    EXTRACTOR_TITLE,
                                                    EXTRACTOR_FILENAME,
                                                    EXTRACTOR_DESCRIPTION,
                                                    EXTRACTOR_SUBJECT,
                                                    EXTRACTOR_PUBLISHER,
                                                    EXTRACTOR_AUTHOR,
                                                    EXTRACTOR_COMMENT,
                                                    EXTRACTOR_SUMMARY,
                                                    EXTRACTOR_OWNER, -1);
      if (meta != NULL)
        {
          GNUNET_meta_data_destroy (meta);
          meta = NULL;
        }
    }
  if (name == NULL)
    name = GNUNET_strdup (_("no-name"));
  GNUNET_hash (name, strlen (name), &nh);
  fn = GNUNET_pseudonym_internal_get_data_filename_ (ectx,
                                                     cfg, PS_NAMES_DIR, &nh);
  len = 0;
  GNUNET_disk_file_size (ectx, fn, &len, GNUNET_YES);
  fd = GNUNET_disk_file_open (ectx, fn, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
  i = 0;
  idx = -1;
  while ((len >= sizeof (GNUNET_HashCode)) &&
         (sizeof (GNUNET_HashCode)
          == READ (fd, &nh, sizeof (GNUNET_HashCode))))
    {
      if (0 == memcmp (&nh, nsid, sizeof (GNUNET_HashCode)))
        {
          idx = i;
          break;
        }
      i++;
      len -= sizeof (GNUNET_HashCode);
    }
  if (idx == -1)
    {
      idx = i;
      WRITE (fd, nsid, sizeof (GNUNET_HashCode));
    }
  CLOSE (fd);
  ret = GNUNET_malloc (strlen (name) + 32);
  GNUNET_snprintf (ret, strlen (name) + 32, "%s-%u", name, idx);
  GNUNET_free (name);
  GNUNET_free (fn);
  return ret;
}

/**
 * Get the namespace ID belonging to the given namespace name.
 *
 * @return GNUNET_OK on success
 */
int
GNUNET_pseudonym_name_to_id (struct GNUNET_GE_Context *ectx,
                             struct GNUNET_GC_Configuration *cfg,
                             const char *ns_uname, GNUNET_HashCode * nsid)
{
  size_t slen;
  unsigned long long len;
  unsigned int idx;
  char *name;
  GNUNET_HashCode nh;
  char *fn;
  int fd;

  idx = -1;
  slen = strlen (ns_uname);
  while ((slen > 0) && (1 != sscanf (&ns_uname[slen - 1], "-%u", &idx)))
    slen--;
  if (slen == 0)
    return GNUNET_SYSERR;
  name = GNUNET_strdup (ns_uname);
  name[slen - 1] = '\0';
  GNUNET_hash (name, strlen (name), &nh);
  GNUNET_free (name);
  fn = GNUNET_pseudonym_internal_get_data_filename_ (ectx,
                                                     cfg, PS_NAMES_DIR, &nh);
  if ((GNUNET_OK != GNUNET_disk_file_test (ectx,
                                           fn) ||
       (GNUNET_OK != GNUNET_disk_file_size (ectx, fn, &len, GNUNET_YES))) ||
      ((idx + 1) * sizeof (GNUNET_HashCode) > len))
    {
      GNUNET_free (fn);
      return GNUNET_SYSERR;
    }
  fd = GNUNET_disk_file_open (ectx, fn, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
  GNUNET_free (fn);
  LSEEK (fd, idx * sizeof (GNUNET_HashCode), SEEK_SET);
  if (sizeof (GNUNET_HashCode) != READ (fd, nsid, sizeof (GNUNET_HashCode)))
    {
      CLOSE (fd);
      return GNUNET_SYSERR;
    }
  CLOSE (fd);
  return GNUNET_OK;
}


/* end of names.c */
