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
 * @file include/dv.h
 * @brief Structs necessary for the distance vector service providing
 * distance vector type routing.
 */
#ifndef DV_H
#define DV_H

#include "gnunet_core.h"

#define GNUNET_DV_LEAST_COST 1
#define GNUNET_DV_MAX_COST -1
#define GNUNET_DV_MAX_TABLE_SIZE -1
#define GNUNET_DV_DEFAULT_SEND_INTERVAL 2000

/**
 * Message that gets sent between nodes updating dv infos
 */
typedef struct
{
  GNUNET_MessageHeader header GNUNET_PACKED;

  /**
   * Cost from received from node to neighbor node, takes distance into account
   */
  unsigned int cost GNUNET_PACKED;

  /**
   * Identity of neighbor of received from node
   */
  GNUNET_PeerIdentity neighbor GNUNET_PACKED;

} p2p_dv_MESSAGE_NeighborInfo;

/*
 * Struct where actual neighbor information is stored,
 * referenced by min_heap and max_heap.  Freeing dealt
 * with when items removed from hashmap.
 */
struct GNUNET_dv_neighbor
{
  /*
   * Back-pointer location in min heap
   */
  struct GNUNET_dv_heap_node *min_loc;

  /*
   * Back-pointer location in max heap
   */
  struct GNUNET_dv_heap_node *max_loc;

  /**
   * Identity of neighbor
   */
  GNUNET_PeerIdentity *neighbor;

  /**
   * Identity of referrer (where we got the information)
   */
  GNUNET_PeerIdentity *referrer;

  /**
   * Cost to neighbor, used for actual distance vector computations
   */
  unsigned int cost;
};


#endif

/* end of dv.h */
