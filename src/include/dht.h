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
 * @file include/gnunet_dht.h
 * @brief data structures exchanged between between DHT clients and the GNUnet DHT module
 * @author Tomi Tukiainen, Marko Räihä, Christian Grothoff
 *
 * Typical clients are likely to prefer using the synchronous
 * gnunet_dht_lib instead of sending these messages manually.
 * Only code in src/applications/dht/ should refer to this file!
 */

#ifndef GNUNET_DHT_H
#define GNUNET_DHT_H

#include "gnunet_util.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * TCP communication: put <key,value>-mapping to table.
 * When sent by a client to gnunetd, this message is
 * used to initiate a PUT on the DHT.  gnunetd also
 * uses this message to communicate results from a GET
 * operation back to the client.<p>
 *
 * The given struct is followed by the value.
 */
typedef struct
{

  GNUNET_MessageHeader header;

  unsigned int type GNUNET_PACKED;            /* nbo */

  GNUNET_HashCode key GNUNET_PACKED;

} CS_dht_request_put_MESSAGE;

/**
 * TCP communication: get <key,value>-mappings for given key. Reply is
 * a CS_dht_request_put_MESSAGE messages.  Clients can abort
 * the GET operation early by closing the connection.
 */
typedef struct
{

  GNUNET_MessageHeader header;

  unsigned int type GNUNET_PACKED;            /* nbo */

  GNUNET_HashCode key GNUNET_PACKED;

} CS_dht_request_get_MESSAGE;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif /* GNUNET_DHT_H */
