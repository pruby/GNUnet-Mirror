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
 * Format of the signature response.
 */
typedef struct {
  MESSAGE_HEADER header;

  Signature sig;
} CS_identity_signature_MESSAGE;

/**
 * Format of the connection request.
 */
typedef struct {
  MESSAGE_HEADER header;

  PeerIdentity other;
} CS_identity_connect_MESSAGE;

/**
 * Format of the peer information response.
 *
 * Note that the struct is followed by a zero-terminated,
 * variable-size string with the peer's address as given by the
 * transport.
 */
typedef struct {
  MESSAGE_HEADER header;

  unsigned int trust;

  PeerIdentity peer;

  cron_t last_message;

  unsigned int bpm;
} CS_identity_peer_info_MESSAGE;



#endif
