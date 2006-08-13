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
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Start collection.
 */
int FSUI_startCollection(struct GE_Context * ectx,
			 struct GC_Configuration * cfg,
			 unsigned int anonymityLevel,
			 TIME_T updateInterval,
			 const char * name,
			 const struct ECRS_MetaData * meta); /* collection.c */

/**
 * Stop collection.
 *
 * @return OK on success, SYSERR if no collection is active
 */
int FSUI_stopCollection(struct GE_Context * ectx,
			struct GC_Configuration * cfg); /* collection.c */

/**
 * Are we using a collection?
 *
 * @return NULL if there is no collection, otherwise its name
 */
const char * FSUI_getCollection(struct GE_Context * ectx,
				struct GC_Configuration * cfg); /* collection.c */

/**
 * Upload an update of the current collection information to the
 * network now.  The function has no effect if the collection has not
 * changed since the last publication.  If we are currently not
 * collecting, this function does nothing.
 *
 * Note that clients typically don't have to call this function
 * explicitly.  FSUI will call the function on exit (for sporadically
 * updated collections), on any change to the collection (for
 * immediately updated content) or when the publication time has
 * arrived (for periodically updated collections).
 *
 * However, clients may want to call this function if explicit
 * publication of an update at another time is desired.
 */
void FSUI_publishCollectionNow(struct GE_Context * ectx,
			       struct GC_Configuration * cfg);

/**
 * If we are currently building a collection, publish the given file
 * information in that collection.  If we are currently not
 * collecting, this function does nothing.
 *
 * Note that clients typically don't have to call this function
 * explicitly -- by using the FSUI library it should be called
 * automatically by FSUI code whenever needed.  However, the function
 * maybe useful if you're inserting files using libECRS directly or
 * need other ways to explicitly extend a collection.
 */
void FSUI_publishToCollection(struct GE_Context * ectx,
			      struct GC_Configuration * cfg,
			      const ECRS_FileInfo * fi);




#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
