/*
     This file is part of GNUnet
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
 * @file transports/common.h
 * @brief Common definitions for TCP, HTTP and UDP transports
 * @author Christian Grothoff
 */
#ifndef TRANSPORTS_COMMON_H
#define TRANSPORTS_COMMON_H

/**
 * Constants for which IP versions are
 * actually available for the peer.
 */
#define VERSION_AVAILABLE_NONE 0
#define VERSION_AVAILABLE_IPV4 1
#define VERSION_AVAILABLE_IPV6 2

/**
 * Host-Address in the network.
 */
typedef struct
{
  /**
   * IPv6 address of the sender, network byte order
   */
  struct in6_addr ipv6;

  /**
   * claimed IP of the sender, network byte order
   */
  struct in_addr ipv4;

  /**
   * claimed port of the sender, network byte order
   */
  unsigned short port;

  /**
   * Availability.  1 for IPv4 only, 2 for IPv6 only,
   * 3 for IPv4 and IPv6.
   */
  unsigned short availability;

} HostAddress;

#endif
