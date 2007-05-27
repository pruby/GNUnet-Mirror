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
 * @file identity/clientapi.c
 * @author Christian Grothoff
 * @brief API for clients to talk to the identity module
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_lib.h"
#include "identity.h"

/**
 * Inform gnunetd about another peer.
 *
 * @param sock socket to talk to gnunetd over
 * @return OK on success, SYSERR on error
 */
int gnunet_identity_peer_add(struct ClientServerConnection * sock,
			     const PublicKey * key,
			     TIME_T expirationTime,
			     unsigned short proto,
			     unsigned short sas,
			     unsigned int mtu,
			     const char * address,
			     const Signature * signature) {
  CS_identity_hello_MESSAGE * msg;

  msg = MALLOC(sizeof(CS_identity_hello_MESSAGE) + sas);
  msg->header.type = htons(CS_PROTO_identity_HELLO);
  msg->header.size = htons(sizeof(CS_identity_hello_MESSAGE) + sas);
  msg->signature = *signature;
  msg->publicKey = *key;
  hash(key,
       sizeof(PublicKey),
       &msg->senderIdentity.hashPubKey);
  msg->expirationTime = expirationTime;
  msg->MTU = mtu;
  msg->senderAddressSize = sas;
  msg->protocol = proto;
  memcpy(&msg[1],
	 address,
	 sas);
  /* FIXME: check that signature is valid! */
  if (SYSERR == connection_write(sock,
				 &msg->header)) {
    FREE(msg);
    return SYSERR;
  }
  FREE(msg);
  return OK;
}


/* end of clientapi.c */
