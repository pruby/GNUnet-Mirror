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
  msg->m.header.type = htons(CS_PROTO_identity_HELLO);
  msg->m.header.size = htons(sizeof(CS_identity_hello_MESSAGE) + sas);
  msg->m.signature = *signature;
  msg->m.publicKey = *key;
  hash(key,
       sizeof(PublicKey),
       &msg->m.senderIdentity.hashPubKey);
  msg->m.expirationTime = expirationTime;
  msg->m.MTU = mtu;
  msg->m.senderAddressSize = sas;
  msg->m.protocol = proto;
  memcpy(&msg[1],
	 address,
	 sas);
  /* check that signature is valid -- internal
     sanity check... */
  if (SYSERR == verifySig(&msg->m.senderIdentity,
			  P2P_hello_MESSAGE_size(&msg->m)
			  - sizeof(Signature)
			  - sizeof(PublicKey)
			  - sizeof(MESSAGE_HEADER),
			  &msg->m.signature,
			  key)) {
    GE_BREAK(NULL, 0);
    FREE(msg);
    return SYSERR;
  } 
  fprintf(stderr, "Yepee!\n");

  if (SYSERR == connection_write(sock,
				 &msg->m.header)) {
    FREE(msg);
    return SYSERR;
  }
  FREE(msg);
  return OK;
}


/**
 * Function to request the peer to sign something
 * with the private key of the peer.
 */
int gnunet_identity_sign_function(struct ClientServerConnection * sock,
				  unsigned short size,
				  const void * data,
				  Signature * result) {
  MESSAGE_HEADER * req;
  CS_identity_signature_MESSAGE * reply;
  
  req = MALLOC(sizeof(MESSAGE_HEADER) + size);
  req->size = htons(sizeof(MESSAGE_HEADER) + size);
  req->type = htons(CS_PROTO_identity_request_SIGN);
  memcpy(&req[1],
	 data,
	 size);
  if (SYSERR == connection_write(sock,
				 req)) {
    FREE(req);
    return SYSERR;
  }
  FREE(req);
  if (OK != connection_read(sock,
			    (MESSAGE_HEADER**)&reply)) {
    connection_close_temporarily(sock);
    return SYSERR;
  }
  if ( (ntohs(reply->header.size) != sizeof(CS_identity_signature_MESSAGE)) ||
       (ntohs(reply->header.type) != CS_PROTO_identity_SIGNATURE) ) {
    FREE(reply);
    return SYSERR;
  }
  *result = reply->sig;
  FREE(reply);
  return OK;
}

/**
 * Function to request one of the peer's identities 
 * (that is, external addresses).
 * Except for the "sock" argument, all arguments are
 * set by the function.
 * @return SYSERR on error, OK on success
 */
int gnunet_identity_get_self(struct ClientServerConnection * sock,
			     PublicKey * key,
			     TIME_T * expirationTime,
			     unsigned short * proto,
			     unsigned short * sas,
			     unsigned int * mtu,
			     char ** address) {
  MESSAGE_HEADER req;
  CS_identity_hello_MESSAGE * reply;

  req.size = htons(sizeof(MESSAGE_HEADER));
  req.type = htons(CS_PROTO_identity_request_HELLO);
  if (SYSERR == connection_write(sock,
				 &req)) 
    return SYSERR;  
  if (OK != connection_read(sock,
			    (MESSAGE_HEADER**)&reply)) {
    connection_close_temporarily(sock);
    return SYSERR;
  }
  if ( (ntohs(reply->m.header.size) < sizeof(CS_identity_hello_MESSAGE)) ||
       (ntohs(reply->m.header.type) != CS_PROTO_identity_HELLO) ||
       (ntohs(reply->m.header.size) != ntohs(reply->m.senderAddressSize) + sizeof(CS_identity_hello_MESSAGE)) ) {
    FREE(reply);
    return SYSERR;
  }
  *key = reply->m.publicKey;
  *expirationTime = ntohl(reply->m.expirationTime);
  *proto = ntohs(reply->m.protocol);
  *sas = ntohs(reply->m.senderAddressSize);
  *mtu = ntohl(reply->m.MTU);
  if (*sas > 0) {
    *address = MALLOC(*sas);
    memcpy(*address,
	   &reply[1],
	   *sas);
  } 
  FREE(reply);
  return OK;
}




/* end of clientapi.c */
