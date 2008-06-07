/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_collection_lib.h
 * @brief support for collections
 * @author Christian Grothoff
 */

#ifndef GNUNET_COLLECTION_LIB_H
#define GNUNET_COLLECTION_LIB_H

#include "gnunet_ecrs_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Initialize collection module.
 */
void GNUNET_CO_init (struct GNUNET_GE_Context *ectx,
                     struct GNUNET_GC_Configuration *cfg);

/**
 * Shutdown collection module.
 */
void GNUNET_CO_done (void);


/**
 * Start a collection (also automatically stops
 * an existing collection).
 */
int GNUNET_CO_collection_start (unsigned int anonymityLevel,
                                unsigned int priority,
                                const struct GNUNET_MetaData *meta);

/**
 * Stop collection.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if no collection is active
 */
int GNUNET_CO_collection_stop (void);


/**
 * Are we using a collection?
 *
 * @return NULL if there is no collection, otherwise its metadata
 */
struct GNUNET_MetaData *GNUNET_CO_collection_get_name (void);

/**
 * Publish an update of the current collection information to the
 * network now.  The function has no effect if the collection has not
 * changed since the last publication.  If we are currently not
 * collecting, this function does nothing.
 */
void GNUNET_CO_collection_publish_now (void);

/**
 * If we are currently building a collection, publish the given file
 * information in that collection.  If we are currently not
 * collecting, this function does nothing.
 */
void GNUNET_CO_collection_add_item (const GNUNET_ECRS_FileInfo * fi);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
