/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file identity/identity.h
 * @author Christian Grothoff
 */
#ifndef IDENTITY_H
#define IDENTITY_H

/**
 * Format of the message to inform gnunetd about a 
 * HELLO from the client-side.  
 *
 * @see P2P_hello_MESSAGE!
 */
typedef struct {
  MESSAGE_HEADER header;

  /**
   * The signature
   */
  Signature signature;

  /**
   * The public key
   */
  PublicKey publicKey;

  /**
   * Whose identity follows? No, this is NOT a duplicate
   * as a node may send us the identity of ANOTHER node!
   */
  PeerIdentity senderIdentity;

  /**
   * time this address expires  (network byte order)
   */
  TIME_T expirationTime;

  /**
   * advertised MTU for sending (replies can have a different
   * MTU!)
   */
  unsigned int MTU;

  /**
   * size of the sender address
   */
  unsigned short senderAddressSize;

  /**
   * protocol supported by the node (only one protocol
   * can be advertised by the same hello)
   * Examples are UDP, TCP, etc. This field is
   * in network byte order
   */
  unsigned short protocol;


} CS_identity_hello_MESSAGE;


#endif
