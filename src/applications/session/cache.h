/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file session/cache.h
 * @brief module responsible for caching
 *   sessionkey exchange requests
 * @author Christian Grothoff
 */
#ifndef SESSION_CACHE_H
#define SESSION_CACHE_H

#include "gnunet_util.h"

/**
 * Query the cache, obtain a cached key exchange message
 * if possible.
 *
 * @param peer for the key
 * @param msg set to key exchange message
 * @return GNUNET_OK on success
 */
int
GNUNET_session_cache_get (const GNUNET_PeerIdentity * peer,
                          GNUNET_Int32Time time_limit,
                          const GNUNET_AES_SessionKey * key,
                          unsigned short size, GNUNET_MessageHeader ** msg);

/**
 * Store a message in the cache.
 *
 * @param peer for the key
 * @param msg the key exchange message
 * @return GNUNET_OK on success
 */
void
GNUNET_session_cache_put (const GNUNET_PeerIdentity * peer,
                          GNUNET_Int32Time time_limit,
                          const GNUNET_AES_SessionKey * key,
                          const GNUNET_MessageHeader * msg);

#endif
