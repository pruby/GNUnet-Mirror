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
 * @file include/gnunet_session_service.h
 * @brief Code that maintains the GNUnet session.
 *  It is responsible for establishing connections.
 * @author Christian Grothoff
 */

#ifndef GNUNET_SESSION_SERVICE_H
#define GNUNET_SESSION_SERVICE_H

#include "gnunet_util.h"

/**
 * @brief session service API
 *
 * Session is responsible for establishing a session with another
 * peer (SKEY exchange).
 */
typedef struct {

  /**
   * Try to connect to the given peer.
   *
   * @return SYSERR if that is impossible,
   *         YES if a connection is established upon return,
   *         NO if we're going to try to establish one asynchronously
   */
  int (*tryConnect)(const PeerIdentity * peer);

} Session_ServiceAPI;

#endif
/* end of gnunet_session_service.h */

