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
 * @file include/gnunet_dht_lib.h
 * @brief convenience API to the DHT infrastructure for use by clients
 * @author Christian Grothoff
 */

#ifndef GNUNET_DHT_LIB_H
#define GNUNET_DHT_LIB_H

#include "gnunet_blockstore.h"
#include "gnunet_dht_service.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Perform a synchronous GET operation on the DHT looking for
 * key.
 *
 * @param key the key to look up
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param resultCallback function to call for results,
 *        the operation also aborts if the callback returns 
 *        SYSERR
 * @return number of results on success, SYSERR on error (i.e. timeout)
 */
int DHT_LIB_get(struct GC_Configuration * cfg,
		struct GE_Context * ectx,
		unsigned int type,
		const HashCode512 * key,
		cron_t timeout,
		DataProcessor resultCallback,
		void * resCallbackClosure);
	
/**
 * Perform a synchronous put operation.
 *
 * @param key the key to store
 * @param expire when should the content expire
 * @param value what to store
 * @return OK on success, SYSERR on error 
 */
int DHT_LIB_put(struct GC_Configuration * cfg,
		struct GE_Context * ectx,
		const HashCode512 * key,
		unsigned int type,
		cron_t expire,
		const DataContainer * value);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_DHT_LIB_H */
