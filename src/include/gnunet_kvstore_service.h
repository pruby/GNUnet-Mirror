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
 * @file include/gnunet_kvstore_service.h
 * @brief An KV store is responsible for storing Key/Value-
 *        pairs.
 * @author Nils Durner
 */

#ifndef GNUNET_KVSTORE_SERVICE_H
#define GNUNET_KVSTORE_SERVICE_H

#include "gnunet_core.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * @brief Handle to a Key/Value-Table
 */
typedef struct
{
  char *table;
  char *db;
} KVHandle;

/**
 * @brief Callback for multiple results from Key/Value-Tables
 * @param closure optional parameter
 * @param val the value retrieved
 * @param vallen the length von val
 * @return OK on success
 */
typedef int (*KVCallback) (void *closure, void *val, int vallen);


/**
 * @brief Definition of the KV-Store API.
 */
typedef struct
{
  /**
   * @brief Open a Key/Value-Table
   * @param table the name of the Key/Value-Table
   * @return a handle
   */
  KVHandle *(*getTable) (const char *database, const char *table);

  /**
   * @brief Get data from a Key/Value-Table
   * @param kv handle to the table
   * @param key the key to retrieve
   * @param keylen length of the key
   * @param sort 0 = dont, sort, 1 = random, 2 = sort by age
   * @param limit limit result set to n rows
   * @param handler callback function to be called for every result (may be NULL)
   * @param closure optional parameter for handler
   */
  void *(*get) (KVHandle * kv,
                void *key,
                int keylen,
                unsigned int sort,
                unsigned int limit, KVCallback handler, void *closure);

  /**
   * @brief Store Key/Value-Pair in a table
   * @param kv handle to the table
   * @param key key of the pair
   * @param keylen length of the key (int because of SQLite!)
   * @param val value of the pair
   * @param vallen length of the value (int because of SQLite!)
   * @param optional creation time
   * @return OK on success, SYSERR otherwise
   */
  int (*put) (KVHandle * kv,
              void *key,
              int keylen, void *val, int vallen, unsigned long long age);

  /**
   * @brief Delete values from a Key/Value-Table
   * @param key key to delete (may be NULL)
   * @param keylen length of the key
   * @param age age of the items to delete (may be 0)
   * @return OK on success, SYSERR otherwise
   */
  int (*del) (KVHandle * kv, void *key, int keylen, unsigned long long age);

  /**
   * @brief Close a handle to a Key/Value-Table
   * @param kv the handle to close
   */
  void (*closeTable) (KVHandle * kv);

  /**
   * @brief Drop a Key/Value-Table
   * @param the handle to the table
   * @return OK on success, SYSERR otherwise
   */
  int (*dropTable) (KVHandle * kv);

  /**
   * @brief Delete the database.
   */
  void (*dropDatabase) (const char *name);

} KVstore_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_kvstore_service.h */
#endif
