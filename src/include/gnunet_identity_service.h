/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_identity_service.h
 * @brief Code to maintain the list of currently known hosts
 *   (in memory structure of data/hosts), their credit ratings
 *   (in memory structure of data/trust), and temporary
 *   blacklisting information (misbehavior, failed connection
 *   attempts)
 * @author Christian Grothoff
 */

#ifndef GNUNET_IDENTITY_SERVICE_H
#define GNUNET_IDENTITY_SERVICE_H

#include "gnunet_core.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * How long may a hello be valid (in seconds). We use 10 days, do not
 * change (would break compatibility with peers that have a different
 * limit).
 */
#define GNUNET_MAX_HELLO_EXPIRES (60 * 60 * 24 * 10)

/**
 * Type of an iterator over the hosts.  Note that each
 * host will be called with each available protocol.
 *
 * @param identity the identity of the host
 * @param protocol the available protocol
 * @param confirmed is the address confirmed (GNUNET_YES),
 *        if GNUNET_NO the host is in the temporary list
 * @param data callback closure
 * @return GNUNET_OK to continue iteration
 */
typedef int (*GNUNET_HostProcessor) (const GNUNET_PeerIdentity * identity,
                                     unsigned short protocol,
                                     int confirmed, void *data);

/**
 * @brief Definition of the Identity API.
 */
typedef struct
{

  /**
   * Get the public key of this peer.
   *
   * @return reference to the public key. Do not free it!
   */
  const GNUNET_RSA_PublicKey *(*getPublicPrivateKey) (void);

  /**
   * Obtain identity from publicPrivateKey.
   *
   * @param pubKey the public key of the host
   * @param result address where to write the identity of the node
   */
  void (*getPeerIdentity) (const GNUNET_RSA_PublicKey * pubKey,
                           GNUNET_PeerIdentity * result);


  /**
   * Sign arbitrary data. ALWAYS use only on data we entirely generated.
   * @param data what to GNUNET_RSA_sign
   * @param size how big is the data
   * @param result where to store the result
   * @returns GNUNET_SYSERR on failure, GNUNET_OK on success
   */
  int (*signData) (const void *data, unsigned short size,
                   GNUNET_RSA_Signature * result);

  /**
   * Decrypt a given block with the hostkey.
   * @param block the data to decrypt, encoded as returned by encrypt, not consumed
   * @param result pointer to a location where the result can be stored
   * @param max the maximum number of bits to store for the result, if
   *        the decrypted block is bigger, an error is returned
   * @returns the size of the decrypted block, -1 on error
   */
  int (*decryptData) (const GNUNET_RSA_EncryptedData * block,
                      void *result, unsigned int max);

  /**
   * Delete a host from the list
   */
  void (*delHostFromKnown) (const GNUNET_PeerIdentity * identity,
                            unsigned short protocol);

  /**
   * Add a host to the temporary list.
   */
  void (*addHostTemporarily) (const GNUNET_MessageHello * tmp);

  /**
   * Add a host to the persistent list.
   * @param msg the verified (!) hello message
   */
  void (*addHost) (const GNUNET_MessageHello * msg);

  /**
   * Call a method for each known host.
   * @param callback the method to call for each host, may be NULL
   * @param now the time to use for excluding hosts due to blacklisting, use 0
   *        to go through all hosts.
   * @param data an argument to pass to the method
   * @return the number of known hosts matching
   */
  int (*forEachHost) (GNUNET_CronTime now, GNUNET_HostProcessor callback,
                      void *data);

  /**
   * Obtain the public key and address of a known host. If no specific
   * protocol is specified (GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY), the hello for the
   * cheapest confirmed protocol is returned.
   *
   * @param hostId the host id
   * @param protocol the protocol that we need,
   *        GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY  if we do not care which protocol
   * @return NULL on failure, the hello on success
   */
  GNUNET_MessageHello *(*identity2Hello) (const GNUNET_PeerIdentity * hostId,
                                          unsigned short protocol,
                                          int tryTemporaryList);

  /**
   *
   *
   * @param signer the identity of the host that presumably signed the message
   * @param message the signed message
   * @param size the size of the message
   * @param sig the signature
   * @return GNUNET_OK on success, GNUNET_SYSERR on error (verification failed)
   */
  int (*verifyPeerSignature) (const GNUNET_PeerIdentity * signer,
                              const void *message,
                              int size, const GNUNET_RSA_Signature * sig);

  /**
   * Blacklist a host. This method is called if a host
   * failed to respond to a connection attempt.
   *
   * @param desparation how long the blacklist will be in effect
   *                    (in seconds)
   * @param strict should we reject incoming connections?
   *               (and also not possibly attempt to connect
   *                to this peer from our side)?
   *               If set to GNUNET_YES, the desperation value
   *               is also definite, otherwise an algorithm
   *               for back-off and limiting is applied.
   * @return GNUNET_OK on success GNUNET_SYSERR on error
   */
  int (*blacklistHost) (const GNUNET_PeerIdentity * identity,
                        unsigned int desperation, int strict);

  /**
   * Is the node currently blacklisted.
   * If "strict" is true, only count strictly blacklisted
   * peers, which are peers where the node
   * misbehaved badly and we also reject inbound connections.
   *
   * @param identity node to check
   * @param strict GNUNET_YES if we should only care about
   *        strict blacklisting
   * @return GNUNET_YES if true, else GNUNET_NO
   */
  int (*isBlacklisted) (const GNUNET_PeerIdentity * identity, int strict);

  /**
   * Whitelist a host. This method is called if a host
   * successfully established a connection. It typically
   * resets the exponential backoff to the smallest value.
   *
   * @return GNUNET_OK on success GNUNET_SYSERR on error
   */
  int (*whitelistHost) (const GNUNET_PeerIdentity * identity);

  /**
   * Change the host trust by a value.
   *
   * @param hostId is the identity of the host
   * @param value is the int value by which the host credit is to be increased
   * @returns the new credit
   */
  int (*changeHostTrust) (const GNUNET_PeerIdentity * hostId, int value);

  /**
   * Get the amount of trust we have in a host.
   *
   * @param hostId is the identity of the host
   * @returns trust we have in the host (-1 on error)
   */
  int (*getHostTrust) (const GNUNET_PeerIdentity * hostId);

} GNUNET_Identity_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* end of gnunet_identity_service.h */
#endif
