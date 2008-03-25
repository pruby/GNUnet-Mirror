/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_transport_service.h
 * @author Christian Grothoff
 * @brief wrapper around the transport services
 */

#ifndef GNUNET_TRANSPORT_SERVICE_H
#define GNUNET_TRANSPORT_SERVICE_H

#include "gnunet_transport.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Type of the per-transport callback method.
 */
typedef void (*GNUNET_TransportCallback) (GNUNET_TransportAPI * tapi,
                                          void *data);

/**
 * @brief Transport service definition.
 */
typedef struct
{

          /**
	   * Add an implementation of a transport protocol.
	   */
  int (*add) (GNUNET_TransportAPI * tapi);

  /**
   * Actually start the transport services and begin
   * receiving messages.
   */
  void (*start) (GNUNET_TransportPacketProcessor mpp);

  /**
   * Stop the transport services, stop receiving messages.
   */
  void (*stop) (void);

  /**
   * Is this transport mechanism available (for sending)?
   * @return GNUNET_YES or GNUNET_NO
   */
  int (*test_available) (unsigned short ttype);

  /**
   * Iterate over all available transport mechanisms.
   * @param callback the method to call on each transport API implementation
   * @param data second argument to callback
   * @return number of transports, GNUNET_SYSERR on error
   */
  int (*iterate_available) (GNUNET_TransportCallback callback, void *data);

  /**
   * Get the cost of a message in for the given transport mechanism.
   */
  unsigned int (*cost_get) (int ttype);

  /**
   * Get the MTU for a given transport type.
   */
  int (*mtu_get) (unsigned short ttype);


  /**
   * Connect to a remote host using the advertised transport
   * layer. This may fail if the appropriate transport mechanism is
   * not available.
   *
   * @param hello the hello of the target node
   * @param may_reuse can an existing connection be
   *        re-used?
   * @param token string identifying who is holding the reference
   *              (must match when disconnect is called)
   * @return session handle on success, NULL on error
   */
  GNUNET_TSession *(*connect) (const GNUNET_MessageHello * hello,
                               const char *token, int may_reuse);

  /**
   * Connect to another peer, picking any transport that
   * works.
   *
   * @param peer which peer to connect to
   * @param allowTempLists may we even select hellos that have
   *        not yet been confirmed?
   * @param token string identifying who is holding the reference
   *              (must match when disconnect is called)
   * @return session handle on success, NULL on error
   */
  GNUNET_TSession *(*connect_freely) (const GNUNET_PeerIdentity * peer,
                                      int allowTempList, const char *token);

  /**
   * A (core) Session is to be associated with a transport session. The
   * transport service may want to know in order to call back on the
   * core if the connection is being closed. Associate can also be
   * called to test if it would be possible to associate the session
   * later, in this case, use disconnect afterwards.
   *
   * @param tsession the session handle passed along
   *   from the call to receive that was made by the transport
   *   layer
   * @param token string identifying who is holding the reference
   *              (must match when disconnect is called)
   * @return GNUNET_OK if the session could be associated,
   *         GNUNET_SYSERR if not.
   */
  int (*associate) (GNUNET_TSession * tsession, const char *token);

  /**
   * Close the session with the remote node. May only be called on
   * either connected or associated sessions.
   * @param token string identifying who is holding the reference
   *              (must match when connect/assciate call)
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on error
   */
  int (*disconnect) (GNUNET_TSession * session, const char *token);

  /**
   * Send a message.  Drop if the operation would block.
   *
   * @param session the session identifying the connection
   * @param msg the message to send
   * @param size the size of the message
   * @param important the message is important
   * @return GNUNET_OK on success, GNUNET_SYSERR on persistent error, GNUNET_NO on
   *         temporary error
   */
  int (*send) (GNUNET_TSession * session,
               const void *msg, unsigned int size, int important);

  /**
   * Test if the transport would even try to send
   * a message of the given size and importance
   * for the given session.<br>
   * This function is used to check if the core should
   * even bother to construct (and encrypt) this kind
   * of message.
   *
   * @return GNUNET_YES if the transport would try (i.e. queue
   *         the message or call the OS to send),
   *         GNUNET_NO if the transport would just drop the message,
   *         GNUNET_SYSERR if the size/session is invalid
   */
  int (*send_now_test) (GNUNET_TSession * tsession, unsigned int size,
                        int important);

  /**
   * Verify that a hello is ok. Call a method
   * if the verification was successful.
   * @return GNUNET_OK if the attempt to verify is on the way,
   *        GNUNET_SYSERR if the transport mechanism is not supported
   */
  int (*hello_verify) (const GNUNET_MessageHello * hello);

  /**
   * Get the network address from a HELLO.
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on error
   */
  int (*hello_to_address) (const GNUNET_MessageHello * hello,
                           void **sa, unsigned int *sa_len);

  /**
   * Create a hello advertisement for the given
   * transport type for this node.
   */
  GNUNET_MessageHello *(*hello_create) (unsigned short ttype);

  /**
   * Get a message consisting of (if possible) all addresses that this
   * node is currently advertising.  This method is used to send out
   * possible ways to contact this node when sending a (plaintext) PING
   * during node discovery. Note that if we have many transport
   * implementations, it may not be possible to advertise all of our
   * addresses in one message, thus the caller can bound the size of the
   * advertisements.
   *
   * @param maxLen the maximum size of the hello message collection in bytes
   * @param buff where to write the hello messages
   * @return the number of bytes written to buff, -1 on error
   */
  int (*hello_advertisements_get) (unsigned int maxLen, char *buff);

  /**
   * Verify that this session is associated (with the given
   * token).
   */
  int (*assert_associated) (GNUNET_TSession * tsession, const char *token);

} GNUNET_Transport_ServiceAPI;

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_transport_service.h */
#endif
