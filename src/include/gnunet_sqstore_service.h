/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_sqstore_service.h
 * @brief An SQ store is responsible for storing blocks with
 *   additional indices that allow traversing the store in
 *   order of expiration time or priority, in addition to
 *   queries by key and block type.  The name comes from SQL,
 *   because using an SQL database to do this should be
 *   particularly easy.  But that is of course not the only
 *   way to implement an sqstore.
 * @author Christian Grothoff
 */

#ifndef GNUNET_SQSTORE_SERVICE_H
#define GNUNET_SQSTORE_SERVICE_H

#include "gnunet_core.h"
#include "gnunet_datastore_service.h"


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * @brief Definition of the SQ-Store API.
 */
typedef struct
{

  /**
   * Get the current on-disk size of the SQ store.
   * Estimates are fine, if that's the only thing
   * available.
   * @return number of bytes used on disk
   */
  unsigned long long (*getSize) (void);

  /**
   * Store an item in the datastore.
   *
   * @return OK on success, SYSERR on error, NO on temporary error
   */
  int (*put) (const HashCode512 * key, const Datastore_Value * value);

  /**
   * Iterate over the results for a particular key
   * in the datastore.
   *
   * @param key maybe NULL (to match all entries)
   * @param type entries of which type are relevant?
   *     Use 0 for any type.
   * @param iter maybe NULL (to just count)
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*get) (const HashCode512 * key,
              unsigned int type, Datum_Iterator iter, void *closure);

  /**
   * Update the priority for a particular key in the datastore.  If
   * the expiration time in value is different than the time found in
   * the datastore, the higher value should be kept.  For the
   * anonymity level, the lower value is to be used.  The specified
   * priority should be added to the existing priority, ignoring the
   * priority in value.
   *
   * Note that it is possible for multiple values to match this put.
   * In that case, all of the respective values are updated.
   *
   * @param uid unique identifier of the datum
   * @param delta by how much should the priority
   *     change?  If priority + delta < 0 the
   *     priority should be set to 0 (never go
   *     negative).
   * @param expire new expiration time should be the
   *     MAX of any existing expiration time and
   *     this value
   * @return OK if a match was found and the update
   *     was successful, SYSERR on error
   */
  int (*update) (unsigned long long uid, int delta, cron_t expire);

  /**
   * Iterate over the items in the datastore in ascending
   * order of priority.
   *
   * @param type entries of which type should be considered?
   *        Use 0 for any type.
   * @param iter never NULL
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*iterateLowPriority) (unsigned int type,
                             Datum_Iterator iter, void *closure);

  /**
   * Iterate over content with anonymity zero.
   *
   * @param type entries of which type should be considered?
   *        Use 0 for any type.
   * @param iter never NULL
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*iterateNonAnonymous) (unsigned int type,
                              Datum_Iterator iter, void *closure);

  /**
   * Iterate over the items in the datastore in ascending
   * order of expiration time.
   *
   * @param type entries of which type should be considered?
   *        Use 0 for any type.
   * @param iter never NULL
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*iterateExpirationTime) (unsigned int type,
                                Datum_Iterator iter, void *closure);


  /**
   * Iterate over the items in the datastore in migration
   * order.
   *
   * @param iter never NULL
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*iterateMigrationOrder) (Datum_Iterator iter, void *closure);

  /**
   * Iterate over all the items in the datastore
   * as fast as possible in a single transaction
   * (can lock datastore while this happens, focus
   * is on doing it fast).
   *
   * @param iter never NULL
   * @return the number of results, SYSERR if the
   *   iter is non-NULL and aborted the iteration
   */
  int (*iterateAllNow) (Datum_Iterator iter, void *closure);

  /**
   * Delete the database.  The next operation is
   * guaranteed to be unloading of the module.
   */
  void (*drop) (void);

} SQstore_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_sqstore_service.h */
#endif
