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
 * @file include/gnunet_dht_datastore_memory.h
 * @brief provides the implementation of the
 * Blockstore for keeping the table data in memory.
 * @author Simo Viitanen, Christian Grothoff
 */

#ifndef GNUNET_DHT_DATASTORE_MEMORY_H
#define GNUNET_DHT_DATASTORE_MEMORY_H

#include "gnunet_blockstore.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Create a DHT Datastore (in memory)
 * @param max_memory do not use more than max_memory memory.
 */
Blockstore * create_blockstore_memory(size_t max_memory);

/**
 * Destroy a DHT Datastore (in memory)
 * @param ds the Datastore to destroy; must have been
 *  created by create_datastore_memory.
 */
void destroy_blockstore_memory(Blockstore * ds);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
