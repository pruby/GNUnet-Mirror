/*
     This file is part of GNUnet
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_dstore_service.h
 * @brief An SQ store is responsible for storing blocks with
 *   additional indices that allow traversing the store in
 *   order of expiration time or priority, in addition to
 *   queries by key and block type.  The name comes from SQL,
 *   because using an SQL database to do this should be
 *   particularly easy.  But that is of course not the only
 *   way to implement an dstore.
 * @author Christian Grothoff
 */

#ifndef GNUNET_DSTORE_SERVICE_H
#define GNUNET_DSTORE_SERVICE_H

#include "gnunet_core.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

typedef void (*ResultHandler)(const HashCode512 * key,
			      unsigned int type,
			      unsigned int size,
			      const char * data,
			      void * cls);

/**
 * @brief Definition of the SQ-Store API.
 */
typedef struct {

  /**
   * Store an item in the datastore.
   *
   * @return OK on success, SYSERR on error
   */
  int (*put)(const HashCode512 * key,
	     unsigned int type,
	     cron_t discard_time,
	     unsigned int size,
	     const char * data);

  /**
   * Iterate over the results for a particular key
   * in the datastore.
   *
   * @param key
   * @param type entries of which type are relevant?
   * @param iter maybe NULL (to just count)
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*get)(const HashCode512 * key,
	     unsigned int type,
	     ResultHandler handler,
	     void * closure);

} Dstore_ServiceAPI;

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_dstore_service.h */
#endif
