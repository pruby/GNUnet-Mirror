/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2006 Christian Grothoff (and other contributing authors)

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

#ifndef GNUNET_PINGPONG_SERVICE_H
#define GNUNET_PINGPONG_SERVICE_H

#include "gnunet_core.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * @file include/gnunet_pingpong_service/pingpong.h
 * @brief Pings a host and triggers an action if a reply is received.
 * @author Christian Grothoff
 */

/**
 * @brief PingPong API.
 */
typedef struct
{

  /**
   * Ping a host an call a method if a reply comes back. Uses
   * an encrypted ping routed using the core.
   *
   * @param receiver the peer that should be PINGed
   * @param usePlaintext send the PING in plaintext (GNUNET_YES/GNUNET_NO)
   * @param method the method to call if a PONG comes back
   * @param data an argument to pass to the method, if not
   *   NULL and the ping does not come back, ping will GNUNET_free data!
   * @returns GNUNET_OK on success, GNUNET_SYSERR on error
   */
  int (*ping) (const GNUNET_PeerIdentity * receiver,
               GNUNET_CronJob method, void *data, int usePlaintext,
               int challenge);

  /**
   * Ping a host an call a method if a reply comes back.
   * Does NOT send the ping message but rather returns it
   * to the caller.  The caller is responsible for both sending
   * and freeing the message.
   *
   * @param receiver the peer that should be PINGed
   * @param method the method to call if a PONG comes back
   * @param data an argument to pass to the method, if not
   *   NULL and the ping does not come back, ping will GNUNET_free data!
   * @returns NULL on error, otherwise the PING message
   */
  GNUNET_MessageHeader *(*pingUser) (const GNUNET_PeerIdentity * receiver,
                                     GNUNET_CronJob method,
                                     void *data, int plaintext,
                                     int challenge);

  unsigned int ping_size;

} GNUNET_Pingpong_ServiceAPI;


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
