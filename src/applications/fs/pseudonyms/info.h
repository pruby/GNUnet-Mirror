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
 * @file applications/fs/pseudonym/info.h
 * @brief keeping track of pseudonyms and metadata about them
 * @author Christian Grothoff
 */

#ifndef NAMESPACE_INFO_H
#define NAMESPACE_INFO_H

#include "gnunet_namespace_lib.h"
#include "gnunet_util.h"

int
GNUNET_PSEUDO_internal_read_info_ (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const GNUNET_HashCode * nsid,
                                   struct GNUNET_ECRS_MetaData **meta,
                                   int *ranking, char **ns_name);

#endif
