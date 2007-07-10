/*
      This file is part of GNUnet
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
 * @file include/gnunet_identity_lib.h
 * @brief convenience API to the IDENTITIY service
 * @author Christian Grothoff
 */

#ifndef GNUNET_IDENTITY_LIB_H
#define GNUNET_IDENTITY_LIB_H

#include "gnunet_util_core.h"
#include "gnunet_util_network_client.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Inform gnunetd about another peer.  The given
 * HELLO will be subjected to evaluation for validity
 * just like HELLOs received from other peers.
 *
 * @param sock socket to talk to gnunetd over
 * @return OK on success, SYSERR on error
 */
int gnunet_identity_peer_add (struct ClientServerConnection *sock,
                              const P2P_hello_MESSAGE * hello);

/**
 * Function to request the peer to sign something
 * with the private key of the peer.
 */
int gnunet_identity_sign_function (struct ClientServerConnection *sock,
                                   unsigned short size,
                                   const void *data, Signature * result);

/**
 * Function to request one of the peer's identities
 * (that is, external addresses).
 *
 * @return SYSERR on error, OK on success
 */
int gnunet_identity_get_self (struct ClientServerConnection *sock,
                              P2P_hello_MESSAGE ** hello);


/**
 * Request the peer to connect to another peer
 * @return SYSERR on error, YES if connection is now there
 *         NO if connection is not yet present
 */
int gnunet_identity_request_connect (struct ClientServerConnection *sock,
                                     const PeerIdentity * peer);


/**
 * Callback called to give information about all known peers
 *
 * @param trust amount of trust that this peer has earned
 *        with us
 * @param address address of the peer (as given by the
 *        transport; likely to be an IP+PORT, but could
 *        be anything!)
 * @param last_message if currently connected, when did we
 *        hear last from this peer (estimate)
 * @param bpmFromPeer 0 if peer is not connected, otherwise
 *        number of bytes per minute that we currently allow
 *        this peer to sent to us
 * @param identity the id of the node
 * @return OK to continue to iterate, SYSERR to abort
 */
typedef int (*GNUnetIdentityPeerInfoCallback) (void *data,
                                               const PeerIdentity * identity,
                                               const void *address,
                                               unsigned int addr_len,
                                               cron_t last_message,
                                               unsigned int trust,
                                               unsigned int bpmFromPeer);

/**
 * Request information about all known peers
 *
 * @return SYSERR if iteration was aborted,
 *         otherwise number of peers known
 */
int gnunet_identity_request_peer_infos (struct ClientServerConnection *sock,
                                        GNUnetIdentityPeerInfoCallback
                                        callback, void *cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
