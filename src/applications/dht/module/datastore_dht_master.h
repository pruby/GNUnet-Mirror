 /*
      This file is part of GNUnet

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
 * @file applications/dht/module/datastore_dht_master.h
 * @brief provides the implementation of the
 * Blockstore API for keeping the table data in memory.
 * @author Simo Viitanen, Christian Grothoff
 */

#ifndef DHT_DATASTORE_MASTER_H
#define DHT_DATASTORE_MASTER_H

#include "gnunet_blockstore.h"

/**
 * Create a DHT Master Datastore
 * @param max_memory do not use more than max_memory memory.
 */
Blockstore * create_datastore_dht_master(size_t max_memory);

/**
 * Destroy a DHT Master Datastore (in memory)
 * @param ds the Datastore to destroy; must have been
 *  created by create_datastore_memory.
 */
void destroy_datastore_dht_master(Blockstore * ds);

#endif
