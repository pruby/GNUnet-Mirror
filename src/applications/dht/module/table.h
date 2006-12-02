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
 * @file module/table.h
 * @brief DHT connection table internal API
 * @author Christian Grothoff
 */

#ifndef DHT_TABLE_H
#define DHT_TABLE_H

#include "gnunet_util.h"
#include "gnunet_core.h"

/**
 * Select a peer from the routing table that would be a good routing
 * destination for sending a message for "target".  The resulting peer
 * must not be in the set of blocked peers.<p>
 *
 * Note that we should not ALWAYS select the closest peer to the
 * target, peers further away from the target should be chosen with
 * exponentially declining probability (this function is also used for
 * populating the target's routing table).
 *
 * @return OK on success, SYSERR on error
 */
int select_dht_peer(PeerIdentity * set,
		    const HashCode512 * target,
		    const PeerIdentity * blocked,
		    unsigned int blocked_size);

/**
 * Initialize table DHT component.
 *
 * @param capi the core API
 * @return OK on success
 */
int init_dht_table(CoreAPIForApplication * capi);

/**
 * Shutdown table DHT component.
 *
 * @return OK on success
 */
int done_dht_table(void);

#endif
