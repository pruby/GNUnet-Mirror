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
 * @file include/gnunet_dv_service.h
 * @brief dv is a distance vector type algorithm for providing distance vector
 * routing. This is a simple service api for using it.
 */

#ifndef GNUNET_DV_SERVICE_H
#define GNUNET_DV_SERVICE_H

#include "gnunet_core.h"

/**
 * Functions of the DV Service API.
 */
typedef struct
{
  /**
   * Send a message via DV
   *
   * @param recipient to which neighbor should this go
   * @param message the message which should be sent
   */
  int (*dv_send) (const GNUNET_PeerIdentity * recipient,
                  const GNUNET_MessageHeader * message,
                  unsigned int importance, unsigned int maxdelay);

  int (*dv_connections_iterate) (GNUNET_NodeIteratorCallback method,
                                 void *arg);

  /**
   * For core, Query how much bandwidth is availabe FROM the given
   * node to this node in bpm (at the moment).  For DV, currently
   * only returns GNUNET_OK if node is known in DV tables.  Should
   * be obsoleted by DV/transports/Core integration.  Necessary
   * now because DHT uses this call to check if peer is known
   * before adding to DHT routing tables.
   *
   * @param bpm set to the bandwidth
   * @param last_seen set to last time peer was confirmed up
   * @return GNUNET_OK on success, GNUNET_SYSERR if if we are NOT connected
   */
  int (*p2p_connection_status_check) (const GNUNET_PeerIdentity * node,
                                      unsigned int *bpm,
                                      GNUNET_CronTime * last_seen);

} GNUNET_DV_ServiceAPI;

#endif /* end of gnunet_dv_service.h */
