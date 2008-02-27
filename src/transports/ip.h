/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2007 Christian Grothoff (and other contributing authors)

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
 * @file transports/ip.h
 * @brief code to determine the IP of the local machine
 *        and to do DNS resolution (with caching)
 *
 * @author Christian Grothoff
 */

#ifndef IP_H
#define IP_H

#include "gnunet_util.h"

/**
 * @brief Determine the (external) IP of the local machine.
 *
 * We have many ways to get that IP:
 * a) from the interface (ifconfig)
 * b) via DNS from our HOSTNAME (environment)
 * c) from the configuration (HOSTNAME specification or static IP)
 *
 * Which way applies depends on the OS, the configuration
 * (dynDNS? static IP? NAT?) and at the end what the user
 * needs.
 *
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int GNUNET_IP_get_public_ipv4_address (struct GNUNET_GC_Configuration *cfg,
                                       struct GNUNET_GE_Context *ectx,
                                       struct in_addr *address);

/**
 * @brief Get the IPv6 address for the local machine.
 *
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int GNUNET_IP_get_public_ipv6_address (struct GNUNET_GC_Configuration *cfg,
                                       struct GNUNET_GE_Context *ectx,
                                       struct in6_addr *address);


/**
 * We only have the GNUNET_PeerIdentity.  Do we have any
 * clue about the address based on
 * the "accept" of the connection?  Note that the
 * response is just the best guess.
 *
 * @param sa set to the address
 * @return GNUNET_OK if we found an address, GNUNET_SYSERR if not
 */
int GNUNET_IP_get_address_from_peer_identity (const GNUNET_PeerIdentity *
                                              peer, void **sa,
                                              unsigned int *salen);

/**
 * We have accepted a connection from a particular
 * address (here given as a string) and received
 * a welcome message that claims that this connection
 * came from a particular peer.  This information is
 * NOT validated (and it may well be impossible for
 * us to validate the address).
 */
void GNUNET_IP_set_address_for_peer_identity (const GNUNET_PeerIdentity *
                                              peer, const void *sa,
                                              unsigned int salen);

#endif
