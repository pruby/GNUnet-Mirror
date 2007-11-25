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
 * @file module/dstore.c
 * @brief entries in local DHT
 * @author Simo Viitanen, Christian Grothoff
 */

#include "platform.h"
#include "dstore.h"
#include "gnunet_blockstore.h"

#define DEBUG_DSTORE GNUNET_NO

static GNUNET_Dstore_ServiceAPI *dstore;

static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * Lookup in the local datastore.
 * @return total number of results found
 */
int
dht_store_get (const GNUNET_HashCode * key,
               unsigned int type, GNUNET_ResultProcessor handler, void *cls)
{
  return dstore->get (key, type, handler, cls);
}

/**
 * Store the given data in the local datastore.
 */
void
dht_store_put (unsigned int type,
               const GNUNET_HashCode * key,
               GNUNET_CronTime discard_time, unsigned int size,
               const char *data)
{
  if (discard_time < GNUNET_get_time ())
    {
#if DEBUG_DSTORE
      GNUNET_GE_LOG (coreAPI->ectx,
              GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
              "Content already expired (%llu < %llu), will not keep.\n",
              discard_time, GNUNET_get_time ());
#endif
      return;
    }
  dstore->put (key, type, discard_time, size, data);
}

/**
 * Initialize dstore DHT component.
 *
 * @param capi the core API
 * @return GNUNET_OK on success
 */
int
init_dht_store (size_t max_size, GNUNET_CoreAPIForPlugins * capi)
{
  coreAPI = capi;
  dstore = coreAPI->requestService ("dstore");
  if (dstore == NULL)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Shutdown dstore DHT component.
 *
 * @return GNUNET_OK on success
 */
int
done_dht_store ()
{
  coreAPI->releaseService (dstore);
  coreAPI = NULL;
  dstore = NULL;
  return GNUNET_OK;
}

/* end of dstore.c */
