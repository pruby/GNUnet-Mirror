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
 * @file module/dstore.h
 * @brief entries in local DHT
 * @author Christian Grothoff
 */

#ifndef DHT_DSTORE_H
#define DHT_DSTORE_H

#include "gnunet_util.h"
#include "gnunet_dstore_service.h"

/**
 * Lookup in the local datastore.
 * @return total number of results found
 */
int dht_store_get(const HashCode512 * key,
		  unsigned int type,
		  ResultHandler handler,
		  void * cls);

/**
 * Store the given data in the local datastore.
 */
void dht_store_put(unsigned int type,
		   const HashCode512 * key,
		   cron_t discard_time,
		   unsigned int size,
		   const char * data);

/**
 * Initialize dstore DHT component.
 *
 * @param capi the core API
 * @return OK on success
 */
int init_dht_store(size_t max_size,
		   CoreAPIForApplication * capi);

/**
 * Shutdown dstore DHT component.
 *
 * @return OK on success
 */
int done_dht_store(void);

#endif
