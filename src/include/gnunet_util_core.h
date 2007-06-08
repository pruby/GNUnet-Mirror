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
 * @file include/gnunet_util_core.h
 * @brief shared stuff between clients and core
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_UTIL_CORE_H
#define GNUNET_UTIL_CORE_H

#include "gnunet_util.h"
#include "gnunet_util_crypto.h"


/**
 * @brief hello.  A hello body contains the current HostAddress, the
 * host identity (hash), the time how long the HostAddress is valid, a
 * signature signing the information above and the public key of the
 * host.  The hash of the public key must match the host identity.<p>
 *
 * The signature goes over the message starting at the PeerIdentity
 * and includes the senderAddress.  Since the senderAddress may be
 * long, what is actually signed is the hash of these bytes.
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
   * Whose identity follows? Must be hash of PublicKey.
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

} P2P_hello_MESSAGE;

#define P2P_hello_MESSAGE_size(hello) ((sizeof(P2P_hello_MESSAGE) + ntohs((hello)->senderAddressSize)))




/* ifndef GNUNET_UTIL_CORE_H */
#endif
/* end of gnunet_util_core.h */
