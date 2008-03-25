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
 * @file applications/testing/remote.h
 * @brief header for remote.c
 * @author Nathan Evans
 */

#ifndef REMOTE_H_
#define REMOTE_H_

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_lib.h"
#include "gnunet_util.h"
#include "gnunet_testing_lib.h"

typedef enum
{
  GNUNET_REMOTE_CLIQUE = 0,
  GNUNET_REMOTE_SMALL_WORLD = 1,
  GNUNET_REMOTE_RING = 2,
  GNUNET_REMOTE_2D_TORUS,

} GNUNET_REMOTE_TOPOLOGIES;

struct GNUNET_REMOTE_daemon_list
{
  struct GNUNET_REMOTE_daemon_list *next;
  char *hostname;
  unsigned long long port;

};




/**
 * Establish a connection between two GNUnet daemons
 *
 * @param port1 client port of the first daemon
 * @param port2 client port of the second daemon
 * @param ip1 client ip or hostname for the first daemon
 * @param ip2 client ip or hostname for the second daemon
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_REMOTE_connect_daemons (char *ip1, unsigned short port1, char *ip2,
                               unsigned short port2);

/**
 * Create a topology (connect the running gnunetd's) that corresponds
 * to the type specified in t.
 */
int
GNUNET_REMOTE_create_topology (GNUNET_REMOTE_TOPOLOGIES t,
                               int number_of_daemons);

#endif /*REMOTE_H_ */

/* end of remote.h */
