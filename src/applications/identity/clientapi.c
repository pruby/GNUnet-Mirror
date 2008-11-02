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
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_IDENTITY_peer_add (struct GNUNET_ClientServerConnection *sock,
                          const GNUNET_MessageHello * hello)
{
  GNUNET_MessageHello *msg;

  msg = GNUNET_malloc (GNUNET_sizeof_hello (hello));
  memcpy (msg, hello, GNUNET_sizeof_hello (hello));
  msg->header.type = htons (GNUNET_CS_PROTO_IDENTITY_HELLO);
  /* check that signature is valid -- internal
     sanity check... */
  if (GNUNET_SYSERR == GNUNET_RSA_verify (&msg->senderIdentity,
                                          GNUNET_sizeof_hello (msg)
                                          - sizeof (GNUNET_RSA_Signature)
                                          - sizeof (GNUNET_RSA_PublicKey)
                                          - sizeof (GNUNET_MessageHeader),
                                          &msg->signature, &msg->publicKey))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_free (msg);
      return GNUNET_SYSERR;
    }
  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &msg->header))
    {
      GNUNET_free (msg);
      return GNUNET_SYSERR;
    }
  GNUNET_free (msg);
  return GNUNET_OK;
}


/**
 * Function to request the peer to GNUNET_RSA_sign something
 * with the private key of the peer.
 */
int
GNUNET_IDENTITY_sign_function (struct GNUNET_ClientServerConnection *sock,
                               unsigned short size,
                               const void *data,
                               GNUNET_RSA_Signature * result)
{
  GNUNET_MessageHeader *req;
  CS_identity_signature_MESSAGE *reply;

  req = GNUNET_malloc (sizeof (GNUNET_MessageHeader) + size);
  req->size = htons (sizeof (GNUNET_MessageHeader) + size);
  req->type = htons (GNUNET_CS_PROTO_IDENTITY_REQUEST_SIGNATURE);
  memcpy (&req[1], data, size);
  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, req))
    {
      GNUNET_free (req);
      return GNUNET_SYSERR;
    }
  GNUNET_free (req);
  if (GNUNET_OK !=
      GNUNET_client_connection_read (sock, (GNUNET_MessageHeader **) & reply))
    {
      GNUNET_client_connection_close_temporarily (sock);
      return GNUNET_SYSERR;
    }
  if ((ntohs (reply->header.size) != sizeof (CS_identity_signature_MESSAGE))
      || (ntohs (reply->header.type) != GNUNET_CS_PROTO_IDENTITY_SIGNATURE))
    {
      GNUNET_free (reply);
      return GNUNET_SYSERR;
    }
  *result = reply->sig;
  GNUNET_free (reply);
  return GNUNET_OK;
}

/**
 * Function to request one of the peer's identities
 * (that is, external addresses).
 * Except for the "sock" argument, all arguments are
 * set by the function.
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_IDENTITY_get_self (struct GNUNET_ClientServerConnection *sock,
                          GNUNET_MessageHello ** msg)
{
  GNUNET_MessageHeader req;
  GNUNET_MessageHello *reply;

  req.size = htons (sizeof (GNUNET_MessageHeader));
  req.type = htons (GNUNET_CS_PROTO_IDENTITY_REQUEST_HELLO);
  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &req))
    return GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_client_connection_read (sock, (GNUNET_MessageHeader **) & reply))
    {
      GNUNET_client_connection_close_temporarily (sock);
      return GNUNET_SYSERR;
    }
  if ((ntohs (reply->header.size) < sizeof (GNUNET_MessageHello)) ||
      (ntohs (reply->header.type) != GNUNET_CS_PROTO_IDENTITY_HELLO) ||
      (ntohs (reply->header.size) != GNUNET_sizeof_hello (reply)))
    {
      GNUNET_free (reply);
      return GNUNET_SYSERR;
    }
  reply->header.type = htons (GNUNET_P2P_PROTO_HELLO);
  *msg = reply;
  return GNUNET_OK;
}


/**
 * Request the peer to connect to another peer
 * @return GNUNET_SYSERR on error, GNUNET_YES if connection is now there
 *         GNUNET_NO if connection is not yet present
 */
int
GNUNET_IDENTITY_request_connect (struct GNUNET_ClientServerConnection *sock,
                                 const GNUNET_PeerIdentity * peer)
{

  CS_identity_connect_MESSAGE msg;
  int result;

  msg.header.type = htons (GNUNET_CS_PROTO_IDENTITY_CONNECT);
  msg.header.size = htons (sizeof (CS_identity_connect_MESSAGE));
  msg.other = *peer;
  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &msg.header))
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR == GNUNET_client_connection_read_result (sock, &result))
    return GNUNET_SYSERR;
  return result;
}

/**
 * Request information about all known peers
 *
 * @return GNUNET_SYSERR if iteration was aborted,
 *         otherwise number of peers known
 */
int
GNUNET_IDENTITY_request_peer_infos (struct GNUNET_ClientServerConnection
                                    *sock,
                                    GNUNET_IDENTITY_PeerInfoCallback callback,
                                    void *cls)
{
  GNUNET_MessageHeader req;
  GNUNET_MessageHeader *reply;
  CS_identity_peer_info_MESSAGE *info;
  unsigned int count;

  req.size = htons (sizeof (GNUNET_MessageHeader));
  req.type = htons (GNUNET_CS_PROTO_IDENTITY_REQUEST_INFO);
  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &req))
    return GNUNET_SYSERR;
  count = 0;
  while (GNUNET_OK == GNUNET_client_connection_read (sock, &reply))
    {
      if (ntohs (reply->size) < sizeof (GNUNET_MessageHeader))
        {
          GNUNET_GE_BREAK (NULL, 0);
          GNUNET_free (reply);
          return GNUNET_SYSERR;
        }
      if (ntohs (reply->type) == GNUNET_CS_PROTO_RETURN_VALUE)
        {
          GNUNET_free (reply);
          return count;
        }
      count++;
      if ((ntohs (reply->type) != GNUNET_CS_PROTO_IDENTITY_INFO) ||
          (ntohs (reply->size) < sizeof (CS_identity_peer_info_MESSAGE)))
        {
          GNUNET_GE_BREAK (NULL, 0);
          GNUNET_free (reply);
          return GNUNET_SYSERR;
        }
      info = (CS_identity_peer_info_MESSAGE *) reply;
      if ((callback != NULL) &&
          (GNUNET_OK != callback (cls,
                                  &info->peer,
                                  &info[1],
                                  ntohs (reply->size) -
                                  sizeof (CS_identity_peer_info_MESSAGE),
                                  GNUNET_ntohll (info->last_message),
                                  ntohl (info->trust), ntohl (info->bpm))))
        {
          GNUNET_free (reply);
          return GNUNET_SYSERR;
        }
      GNUNET_free (reply);
    }
  return GNUNET_SYSERR;
}



/* end of clientapi.c */
