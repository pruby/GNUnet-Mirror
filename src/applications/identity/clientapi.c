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
int
gnunet_identity_peer_add (struct ClientServerConnection *sock,
                          const P2P_hello_MESSAGE * hello)
{
  P2P_hello_MESSAGE *msg;

  msg = MALLOC (P2P_hello_MESSAGE_size (hello));
  memcpy (msg, hello, P2P_hello_MESSAGE_size (hello));
  msg->header.type = htons (CS_PROTO_identity_HELLO);
  /* check that signature is valid -- internal
     sanity check... */
  if (SYSERR == verifySig (&msg->senderIdentity,
                           P2P_hello_MESSAGE_size (msg)
                           - sizeof (Signature)
                           - sizeof (PublicKey)
                           - sizeof (MESSAGE_HEADER),
                           &msg->signature, &msg->publicKey))
    {
      GE_BREAK (NULL, 0);
      FREE (msg);
      return SYSERR;
    }
  if (SYSERR == connection_write (sock, &msg->header))
    {
      FREE (msg);
      return SYSERR;
    }
  FREE (msg);
  return OK;
}


/**
 * Function to request the peer to sign something
 * with the private key of the peer.
 */
int
gnunet_identity_sign_function (struct ClientServerConnection *sock,
                               unsigned short size,
                               const void *data, Signature * result)
{
  MESSAGE_HEADER *req;
  CS_identity_signature_MESSAGE *reply;

  req = MALLOC (sizeof (MESSAGE_HEADER) + size);
  req->size = htons (sizeof (MESSAGE_HEADER) + size);
  req->type = htons (CS_PROTO_identity_request_SIGN);
  memcpy (&req[1], data, size);
  if (SYSERR == connection_write (sock, req))
    {
      FREE (req);
      return SYSERR;
    }
  FREE (req);
  if (OK != connection_read (sock, (MESSAGE_HEADER **) & reply))
    {
      connection_close_temporarily (sock);
      return SYSERR;
    }
  if ((ntohs (reply->header.size) != sizeof (CS_identity_signature_MESSAGE))
      || (ntohs (reply->header.type) != CS_PROTO_identity_SIGNATURE))
    {
      FREE (reply);
      return SYSERR;
    }
  *result = reply->sig;
  FREE (reply);
  return OK;
}

/**
 * Function to request one of the peer's identities
 * (that is, external addresses).
 * Except for the "sock" argument, all arguments are
 * set by the function.
 * @return SYSERR on error, OK on success
 */
int
gnunet_identity_get_self (struct ClientServerConnection *sock,
                          P2P_hello_MESSAGE ** msg)
{
  MESSAGE_HEADER req;
  P2P_hello_MESSAGE *reply;

  req.size = htons (sizeof (MESSAGE_HEADER));
  req.type = htons (CS_PROTO_identity_request_HELLO);
  if (SYSERR == connection_write (sock, &req))
    return SYSERR;
  if (OK != connection_read (sock, (MESSAGE_HEADER **) & reply))
    {
      connection_close_temporarily (sock);
      return SYSERR;
    }
  if ((ntohs (reply->header.size) < sizeof (P2P_hello_MESSAGE)) ||
      (ntohs (reply->header.type) != CS_PROTO_identity_HELLO) ||
      (ntohs (reply->header.size) != P2P_hello_MESSAGE_size (reply)))
    {
      FREE (reply);
      return SYSERR;
    }
  reply->header.type = htons (p2p_PROTO_hello);
  *msg = reply;
  return OK;
}


/**
 * Request the peer to connect to another peer
 * @return SYSERR on error, YES if connection is now there
 *         NO if connection is not yet present
 */
int
gnunet_identity_request_connect (struct ClientServerConnection *sock,
                                 const PeerIdentity * peer)
{

  CS_identity_connect_MESSAGE msg;
  int result;

  msg.header.type = htons (CS_PROTO_identity_CONNECT);
  msg.header.size = htons (sizeof (CS_identity_connect_MESSAGE));
  msg.other = *peer;
  if (SYSERR == connection_write (sock, &msg.header))
    return SYSERR;
  if (SYSERR == connection_read_result (sock, &result))
    return SYSERR;
  return result;
}

/**
 * Request information about all known peers
 *
 * @return SYSERR if iteration was aborted,
 *         otherwise number of peers known
 */
int
gnunet_identity_request_peer_infos (struct ClientServerConnection *sock,
                                    GNUnetIdentityPeerInfoCallback callback,
                                    void *cls)
{
  MESSAGE_HEADER req;
  MESSAGE_HEADER *reply;
  CS_identity_peer_info_MESSAGE *info;
  unsigned int count;

  req.size = htons (sizeof (MESSAGE_HEADER));
  req.type = htons (CS_PROTO_identity_request_INFO);
  if (SYSERR == connection_write (sock, &req))
    return SYSERR;
  count = 0;
  while (OK == connection_read (sock, &reply))
    {
      if (ntohs (reply->size) < sizeof (MESSAGE_HEADER))
        {
          GE_BREAK (NULL, 0);
          FREE (reply);
          return SYSERR;
        }
      if (ntohs (reply->type) == CS_PROTO_RETURN_VALUE)
        {
          FREE (reply);
          return count;
        }
      count++;
      if ((ntohs (reply->type) != CS_PROTO_identity_INFO) ||
          (ntohs (reply->size) < sizeof (CS_identity_peer_info_MESSAGE)))
        {
          GE_BREAK (NULL, 0);
          FREE (reply);
          return SYSERR;
        }
      if (callback != NULL)
        {
          info = (CS_identity_peer_info_MESSAGE *) reply;
          if (OK != callback (cls,
                              &info->peer,
                              &info[1],
                              ntohs (reply->size) -
                              sizeof (CS_identity_peer_info_MESSAGE),
                              ntohll (info->last_message),
                              ntohl (info->trust), ntohl (info->bpm)))
            {
              FREE (reply);
              return SYSERR;
            }
        }
      FREE (reply);
    }
  return SYSERR;
}



/* end of clientapi.c */
