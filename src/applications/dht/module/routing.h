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
 * @file module/routing.h
 * @brief state for active DHT routing operations
 * @author Christian Grothoff
 */

#ifndef DHT_ROUTING_H
#define DHT_ROUTING_H

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "dstore.h"


/**
 * Start a DHT get operation.
 */
void dht_get_start(const HashCode512 * key,
		   unsigned int type,
		   ResultHandler handler,
		   void * cls);

/**
 * Stop a DHT get operation (prevents calls to
 * the given iterator).
 */
void dht_get_stop(const HashCode512 * key,
		  unsigned int type,
		  ResultHandler handler,
		  void * cls);

/**
 * Perform a DHT put operation.  Note that PUT operations always
 * expire after a period of time and the client is responsible for
 * doing periodic refreshs.  The given expiration time is ONLY used to
 * ensure that the datum is certainly deleted by that time (it maybe
 * deleted earlier).
 *
 * @param expirationTime absolute expiration time
 */
void dht_put(const HashCode512 * key,
	     unsigned int type,
	     unsigned int size,
	     cron_t expirationTime,
	     const char * data);

/**
 * Initialize routing DHT component.
 *
 * @param capi the core API
 * @return OK on success
 */
int init_dht_routing(CoreAPIForApplication * capi);

/**
 * Shutdown routing DHT component.
 *
 * @return OK on success
 */
int done_dht_routing(void);

#endif
