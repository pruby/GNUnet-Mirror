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
 * @file applications/fs/namespace/common.h
 * @brief helper functions
 * @author Christian Grothoff
 */


#include "gnunet_namespace_lib.h"

#ifndef NS_COMMON_H
#define NS_COMMON_H

#define NS_METADATA_DIR "data" DIR_SEPARATOR_STR "namespace/metadata" DIR_SEPARATOR_STR
#define NS_UPDATE_DIR   "data" DIR_SEPARATOR_STR "namespace/updates"  DIR_SEPARATOR_STR
#define NS_ROOTS_DIR    "data" DIR_SEPARATOR_STR "namespace/roots"    DIR_SEPARATOR_STR
#define NS_NAMES_DIR    "data" DIR_SEPARATOR_STR "namespace/names"    DIR_SEPARATOR_STR

/**
 * Get the filename (or directory name) for the given
 * namespace and content identifier and directory
 * prefix.
 *
 * @param prefix NS_DIR, NS_UPDATE_DIR or NS_ROOTS
 * @param nsid maybe NULL
 * @param lastId maybe NULL
 */
char *GNUNET_NS_internal_get_data_filename_ (struct GNUNET_GE_Context *ectx,
                                             struct GNUNET_GC_Configuration
                                             *cfg, const char *prefix,
                                             const GNUNET_HashCode * nsid,
                                             const GNUNET_HashCode * lastId);

#endif
