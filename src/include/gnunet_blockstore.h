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
 * @file include/gnunet_blockstore.h
 * @brief common API for DHT and GAP service to obtain local data (from FS)
 * @author Christian Grothoff
 */

#ifndef GNUNET_BLOCKSTORE_H
#define GNUNET_BLOCKSTORE_H

#include "gnunet_util.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Data stored in the blockstore.
 */
typedef struct
{
  /**
   * Size of the data container (in NBO).  This field
   * is followed by size-sizeof(unsigned int) bytes
   * of data.
   */
  unsigned int size;
} GNUNET_DataContainer;

/**
 * Callback function type for items in the GAP datastore.
 *
 * @param key the current key
 * @param value the current value
 * @param cls argument passed for context (closure)
 * @return GNUNET_OK to continue with iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_DataProcessor) (const GNUNET_HashCode * key,
                                     const GNUNET_DataContainer * value,
                                     void *cls);

/**
 * GAP and DHT clients must implement this interface to tell
 * the routing code how to get to local data.
 *
 * The use of key in this API maybe confusing.  The specific content
 * of keys is not specified, the routing code only transmits the
 * number of keys and the type.  Only the first key is used for
 * routing, the other parts are just passed along and untouched by the
 * routing code.  The type is typically used to tell what they refer
 * to.  The assumption is that they (including the type) can be
 * reproduced from the GNUNET_DataContainer and thus the Iterator
 * methods do not communicate those values.
 *
 * The put method is (ab)used to check an item that is merely routed
 * for its integrity.
 */
typedef struct
{

  /**
   * First argument to be passed to all functions in this struct.
   */
  void *closure;

  /**
   * Do a quick test if we MAY have the content.
   */
  int (*fast_get) (const GNUNET_HashCode * key);

  /**
   * Lookup an item in the datastore.
   *
   * @param type kind of item to look up
   * @param prio how important is this lookup
   * @param keyCount number of keys given
   * @param keys to look up
   * @param resultCallback function to call for each result that was found
   * @param resCallbackClosure extra argument to resultCallback
   * @return number of results, GNUNET_SYSERR on error
   */
  int (*get) (void *closure,
              unsigned int type,
              unsigned int prio,
              unsigned int keyCount,
              const GNUNET_HashCode * keys,
              GNUNET_DataProcessor resultCallback, void *resCallbackClosure);

  /**
   * Store an item in the datastore.
   *
   * @param key the key of the item, NULL if not known
   *        (client should try to figure it out)
   * @param value the value to store
   * @return GNUNET_OK if the value could be stored,
   *         GNUNET_NO if the value verifies but is not stored,
   *         GNUNET_SYSERR if the value is malformed
   */
  int (*put) (void *closure,
              const GNUNET_HashCode * key,
              const GNUNET_DataContainer * value, unsigned int prio);

  /**
   * Remove an item from the datastore.
   *
   * @param key the key of the item
   * @param value the value to remove, NULL for all values of the key
   * @return GNUNET_OK if the value could be removed, GNUNET_SYSERR if not (i.e. not present)
   */
  int (*del) (void *closure,
              const GNUNET_HashCode * key,
              const GNUNET_DataContainer * value);

  /**
   * Iterate over all keys in the local datastore
   *
   * @param processor function to call on each item
   * @param cls argument to processor
   * @return number of results, GNUNET_SYSERR on error
   */
  int (*iterate) (void *closure, GNUNET_DataProcessor processor, void *cls);

} GNUNET_Blockstore;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
