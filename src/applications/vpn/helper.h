/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/vpn/helper.h
 * @author Michael John Wensley
 * @brief tunnel RFC 4193 in GNUnet
 */
#ifndef VPN_HELPER_H
#define VPN_HELPER_H

#include "gnunet_core.h"
#include "vpn.h"

/** Test if two GNUNET_RSA_PublicKey are equal or not */
int
isEqualP (const GNUNET_RSA_PublicKey * first,
          const GNUNET_RSA_PublicKey * second);

/**
 * Render IPv4 or IPv6 packet info for logging.
 */
void ipinfo (char *info, const struct ip6_hdr *fp);

/** Test if two GNUNET_PeerIdentity are equal or not */
int isEqual (const GNUNET_PeerIdentity * first,
             const GNUNET_PeerIdentity * second);

/* convert GNUNET_PeerIdentity into network octet order IPv6 address */
void id2net (struct in6_addr *buf, const GNUNET_PeerIdentity * them);

#endif
