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

#include "gnunet_core.h"

/**
 * Format of the message to inform gnunetd about a 
 * HELLO from the client-side.  Just another name
 * for the P2P_hello_MESSAGE -- except that in this
 * struct the "type" will be different!  Note that
 * the code depends on the structual (and size-wise)
 * equality of CS_identity_hello_MESSAGE and
 * P2P_hello_MESSAGE.
 */
typedef struct {

  P2P_hello_MESSAGE m;

} CS_identity_hello_MESSAGE;


/**
 * Format of the signature response.
 */
typedef struct {
  MESSAGE_HEADER header;

  Signature sig;
} CS_identity_signature_MESSAGE;


#endif
