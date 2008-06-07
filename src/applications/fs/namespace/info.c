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
 * @file applications/fs/namespace/info.c
 * @brief create and destroy namespaces
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_util.h"
#include "common.h"

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
                            const struct GNUNET_MetaData *meta,
                            const struct GNUNET_ECRS_URI *advertisementURI,
                            const char *rootEntry)
{
  struct GNUNET_ECRS_URI *ret;
  GNUNET_HashCode id;

  ret = GNUNET_ECRS_namespace_create (ectx,
                                      cfg,
                                      meta,
                                      anonymityLevel,
                                      insertPriority,
                                      insertExpiration, advertisementURI,
                                      rootEntry);
  if (ret != NULL)
    {
      GNUNET_NS_namespace_set_root (ectx, cfg, ret);
      GNUNET_ECRS_uri_get_namespace_from_sks (ret, &id);
      GNUNET_pseudonym_add (ectx, cfg, &id, meta);
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
  char *fn;

  ret = GNUNET_ECRS_namespace_delete (ectx, cfg, nsid);
  fn = GNUNET_NS_internal_get_data_filename_ (ectx,
                                              cfg, NS_UPDATE_DIR, nsid, NULL);
  GNUNET_disk_directory_remove (ectx, fn);
  GNUNET_free (fn);
  return ret;
}

/* end of info.c */
