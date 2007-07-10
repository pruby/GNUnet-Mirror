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
 * @file include/gnunet_topology_service.h
 * @brief Code that maintains the GNUnet topology.
 *  It is responsible for establishing connections.
 * @author Christian Grothoff
 */

#ifndef GNUNET_TOPOLOGY_SERVICE_H
#define GNUNET_TOPOLOGY_SERVICE_H

#include "gnunet_util.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * @brief topology service API
 *
 * Note that while there are few requests that will be made
 * specifically to the topology, the topology service should do a lot
 * more: topology should be actively establishing connections, even if
 * they are not requested explicitly.
 *
 * Topology is responsible for deciding which sessions should be
 * established, which ones should be maintained and which ones
 * should be shut down.  Topology is also responsible for sending
 * PINGs in time to keep alive sessions that are otherwise in
 * danger of timing out.
 *
 * Actual time-outs are done by the core.  Topology may also
 * request the core to shutdown a connection explictly (before
 * the timeout).
 *
 * Topology relies on advertising to learn about other peers, and
 * on session for establishing sessions.
 */
typedef struct
{

  /**
   * Get an estimate of the network size.
   * @return the estimated number of nodes, SYSERR on error
   */
  int (*estimateNetworkSize) (void);

  /**
   * How big is our current desire to connect to other peers?
   * @return 1 for ideal, 0 for maximum desire, > 1 for too many
   *    connections (percent of desired number of connections)
   */
  double (*getSaturation) (void);

  /**
   * Will the topology allow a connection from the specified peer?
   * @return OK if a connection maybe established, SYSERR if not.
   */
  int (*allowConnectionFrom) (const PeerIdentity * peer);


} Topology_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
/* end of gnunet_topology_service.h */
