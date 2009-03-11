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
 * @author Nathan Evans
 * @file include/gnunet_dv_lib.h
 * @brief Provides access to applications wishing to use the fisheye
 * distance vector routing algorithm.
 */
#ifndef GNUNET_DV_LIB_H
#define GNUNET_DV_LIB_H

#include "gnunet_core.h"

/*
 * Provides handler for sending a message via the dv module
 *
 * @recipient for which peer the message is intended
 * @message the message being sent
 */
int GNUNET_DV_send_message (const GNUNET_PeerIdentity * recipient,
                            const GNUNET_MessageHeader * message,
                            unsigned int importance, unsigned int maxdelay);

/**
 * Calls a given method for each dv connected host.
 *
 * @param method method to call for each connected peer
 * @param arg second argument to method
 * @return number of connected nodes
 */
int
GNUNET_DV_connection_iterate_peers (GNUNET_NodeIteratorCallback method,
                                    void *arg);

#endif

/* end of gnunet_dv_lib.h */
