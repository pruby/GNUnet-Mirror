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


typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Reserved (for alignment).
   */
  unsigned int reserved;

  /**
   * Cost from received from node to neighbor node, takes distance into account
   */
  unsigned int cost;

  /**
   * Identity of neighbor of received from node
   */
  GNUNET_PeerIdentity neighbor;

} p2p_dv_MESSAGE_NeighborInfo;

struct GNUNET_dv_neighbor
*findNeighbor(const GNUNET_PeerIdentity *);

static int
addUpdateNeighbor(const GNUNET_PeerIdentity *, const GNUNET_PeerIdentity *, unsigned int);

static void
initialAddNeighbor(const GNUNET_PeerIdentity *, void *);

struct GNUNET_dv_neighbor *
chooseToNeighbor();

struct GNUNET_dv_neighbor *
chooseAboutNeighbor();

#endif

/* end of dv.h */
