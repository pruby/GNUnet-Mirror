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
 * @brief keeping track of namespaces roots
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_util.h"
#include "common.h"

/**
 * Get the root of the namespace (if we have one).
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_NS_namespace_get_root (struct GNUNET_GE_Context *ectx,
                              struct GNUNET_GC_Configuration *cfg,
                              const GNUNET_HashCode * ns_id,
                              GNUNET_HashCode * root)
{
  char *fn;
  int ret;

  fn = GNUNET_NS_internal_get_data_filename_ (ectx,
                                              cfg, NS_ROOTS_DIR, ns_id, NULL);
  if (sizeof (GNUNET_HashCode)
      == GNUNET_disk_file_read (ectx, fn, sizeof (GNUNET_HashCode), root))
    ret = GNUNET_OK;
  else
    ret = GNUNET_SYSERR;
  GNUNET_free (fn);
  return ret;
}

void
GNUNET_NS_namespace_set_root (struct GNUNET_GE_Context *ectx,
                              struct GNUNET_GC_Configuration *cfg,
                              const struct GNUNET_ECRS_URI *uri)
{
  char *fn;
  GNUNET_HashCode ns;
  GNUNET_HashCode rt;

  if (GNUNET_OK != GNUNET_ECRS_uri_get_namespace_from_sks (uri, &ns))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return;
    }
  fn = GNUNET_NS_internal_get_data_filename_ (ectx,
                                              cfg, NS_ROOTS_DIR, &ns, NULL);
  if (GNUNET_OK == GNUNET_ECRS_uri_get_content_hash_from_sks (uri, &rt))
    GNUNET_disk_file_write (ectx, fn, &rt, sizeof (GNUNET_HashCode), "644");
  GNUNET_free (fn);
}


/* end of root_info.c */
