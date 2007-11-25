/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
                                GNUNET_Int32Time updateInterval,
                                const char *name,
                                const struct GNUNET_ECRS_MetaData *meta);

/**
 * Stop collection.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if no collection is active
 */
int GNUNET_CO_collection_stop (void);

/**
 * Are we using a collection?
 *
 * @return NULL if there is no collection, otherwise its name
 */
char *GNUNET_CO_collection_get_name (void);

/**
 * GNUNET_ND_UPLOAD an update of the current collection information to the
 * network now.  The function has no effect if the collection has not
 * changed since the last publication.  If we are currently not
 * collecting, this function does nothing.
 *
 * Note that clients typically don't have to call this function
 * explicitly.  CO will call the function on exit (for sporadically
 * updated collections), on any change to the collection (for
 * immediately updated content) or when the publication time has
 * arrived (for periodically updated collections).
 *
 * However, clients may want to call this function if explicit
 * publication of an update at another time is desired.
 */
void GNUNET_CO_collection_publish_now (void);

/**
 * If we are currently building a collection, publish the given file
 * information in that collection.  If we are currently not
 * collecting, this function does nothing.
 *
 * Note that clients typically don't have to call this function
 * explicitly -- by using the CO library it should be called
 * automatically by CO code whenever needed.  However, the function
 * maybe useful if you're inserting files using libECRS directly or
 * need other ways to explicitly extend a collection.
 */
void GNUNET_CO_collection_add_item (const GNUNET_ECRS_FileInfo * fi);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
