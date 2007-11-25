/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/datastore/prefetch.h
 * @author Christian Grothoff
 * @brief this module is responsible prefetching
 *  content that can then be pushed out into
 *  the network.
 */
#ifndef PREFETCH_H
#define PREFETCH_H

#include "gnunet_sqstore_service.h"

/**
 * Initialize the migration module.
 */
void initPrefetch (struct GNUNET_GE_Context *ectx,
                   struct GNUNET_GC_Configuration *cfg,
                   GNUNET_SQstore_ServiceAPI * sq);

void donePrefetch (void);

/**
 * Get a random value from the datastore that has
 * a key close to the given approx value.
 *
 * @param value set to an approximate match
 * @param type if a particular type is desired, 0
 *        for any type.
 * @return GNUNET_OK if a value was found, GNUNET_SYSERR if not
 */
int getRandom (GNUNET_HashCode * key, GNUNET_DatastoreValue ** value);


/* end of prefetch.h */
#endif
