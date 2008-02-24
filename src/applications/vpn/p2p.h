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
 * @file applications/vpn/p2p.h
 * @author Michael John Wensley
 * @brief handling of P2P messages for VPN
 */
#ifndef VPN_P2P_H
#define VPN_P2P_H

/**
 * Pass IP packet to tap. Which tap depends on what the GNUNET_PeerIdentity is.
 * If we've not seen the peer before, create a new TAP and tell our thread about it?
 * else scan the array of TAPS and copy the message into it.
 *
 * Mainly this routine exchanges the GNUNET_MessageHeader on incoming ipv6 packets
 * for a TUN/TAP header for writing it to TUNTAP.
 */
int
handlep2pMSG (const GNUNET_PeerIdentity * sender,
              const GNUNET_MessageHeader * gp);

#endif
