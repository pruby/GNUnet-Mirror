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
 * @brief dstore is a simple persistent GNUNET_hash table
 *        of bounded size with content expiration
 *        In contrast to the sqstore there is
 *        no prioritization, deletion or iteration.
 *        Furthermore, all of the data is
 *        discarded when the peer shuts down!
 * @author Christian Grothoff
 */

#ifndef GNUNET_DSTORE_SERVICE_H
#define GNUNET_DSTORE_SERVICE_H

#include "gnunet_core.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

typedef void (*GNUNET_ResultProcessor) (const GNUNET_HashCode * key,
                                        unsigned int type,
                                        unsigned int size,
                                        const char *data, void *cls);

/**
 * @brief Definition of the SQ-Store API.
 */
typedef struct
{

  /**
   * Store an item in the datastore.
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on error
   */
  int (*put) (const GNUNET_HashCode * key,
              unsigned int type,
              GNUNET_CronTime discard_time, unsigned int size,
              const char *data);

  /**
   * Iterate over the results for a particular key
   * in the datastore.
   *
   * @param key
   * @param type entries of which type are relevant?
   * @param iter maybe NULL (to just count)
   * @return the number of results, GNUNET_SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*get) (const GNUNET_HashCode * key,
              unsigned int type, GNUNET_ResultProcessor handler,
              void *closure);

} GNUNET_Dstore_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_dstore_service.h */
#endif
