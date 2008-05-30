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
 * @file applications/fs/pseudonyms/common.h
 * @brief helper functions
 * @author Christian Grothoff
 */


#include "gnunet_pseudonym_lib.h"

#ifndef PS_COMMON_H
#define PS_COMMON_H

#define PS_METADATA_DIR "data" DIR_SEPARATOR_STR "pseudonyms/metadata" DIR_SEPARATOR_STR
#define PS_NAMES_DIR    "data" DIR_SEPARATOR_STR "pseudonyms/names"    DIR_SEPARATOR_STR

/**
 * Get the filename (or directory name) for the given
 * pseudonym identifier and directory prefix.
 *
 * @param prefix PS_METADATA_DIR or PS_NAMES_DIR
 * @param psid maybe NULL
 */
char *GNUNET_PSEUDO_internal_get_data_filename_ (struct GNUNET_GE_Context
                                                 *ectx,
                                                 struct
                                                 GNUNET_GC_Configuration *cfg,
                                                 const char *prefix,
                                                 const GNUNET_HashCode *
                                                 psid);

#endif
