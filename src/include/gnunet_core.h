/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_core.h
 * @brief The APIs to the GNUnet core. See also core.c.
 * @author Christian Grothoff
 */

#ifndef COREAPI_H
#define COREAPI_H

#include "gnunet_util.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Just the version number of GNUnet-core API.
 * Encoded as
 * 0.6.1d  => 0x00060100
 * 4.5.2   => 0x04050200
 *
 * Note that this version number is only changed if
 * something changes in the core API.  It follows
 * roughly the main GNUnet version scheme, but is
 * more a compatibility ID.
 */
#define GNUNET_CORE_VERSION 0x00070005


/**
 * Priority for special administrative messages that
 * for example overrules drop-rules.
 */
#define EXTREME_PRIORITY 0xFFFFFF

/**
 * Overhead of the core for encapsulating P2P messages.
 * Should be subtracted from the transport MTU to compute
 * the amount of space available for an unfragmented
 * message.
 */
#define P2P_MESSAGE_OVERHEAD 76

/**
 * Opaque handle for a session representation on the transport
 * layer side
 */
typedef struct {
  unsigned short ttype;
  void * internal;
} TSession;

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
  P2P_MESSAGE_HEADER header;

  /**
   * The signature
   */
  Signature signature;

  /**
   * The public key
   */
  PublicKey publicKey;

  /**
   * Whose identity follows? No, this is NOT a duplicate
   * as a node may send us the identity of ANOTHER node!
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

#define P2P_hello_MESSAGE_size(helo) ((sizeof(P2P_hello_MESSAGE) + ntohs((helo)->senderAddressSize)))

/**
 * Opaque handle for client connections passed by
 * the core to the CSHandlers.
 */
typedef struct ClientH * ClientHandle;

/**
 * Type of a handler for messages from clients.
 */
typedef int (*CSHandler)(ClientHandle client,
			 const CS_MESSAGE_HEADER * message);

/**
 * Method called whenever a given client disconnects.
 */
typedef void (*ClientExitHandler)(ClientHandle client);

/**
 * Type of a handler for some message type.
 */
typedef int (*MessagePartHandler)(const PeerIdentity * sender,
				  const P2P_MESSAGE_HEADER * message);

/**
 * Type of a handler for plaintext messages.  Since we cannot
 * be certain about the sender's identity, it is NOT passed to
 * the callback.
 */
typedef int (*PlaintextMessagePartHandler)(const PeerIdentity * sender,
					   const P2P_MESSAGE_HEADER * message,
					   TSession * session);

/**
 * Type of a handler for some message type.
 * @param identity the id of the node
 */
typedef void (*PerNodeCallback)(const PeerIdentity * identity,
				void * data);

/**
 * Type of a send callback to fill up buffers.
 * @param receiver the receiver of the message
 * @param position is the reference to the
 *        first unused position in the buffer where GNUnet is building
 *        the message
 * @param padding is the number of bytes left in that buffer.
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
typedef unsigned int (*BufferFillCallback)(const PeerIdentity * receiver,
					   void * position,
					   unsigned int padding);

/**
 * Callback that is used to fill in a message into the send buffer.
 * Note that the size of the message was specified when the callback
 * was installed.
 *
 * @param buf pointer to the buffer where to copy the msg to
 * @param closure context argument that was given when the callback was installed
 * @param len the expected number of bytes to write to buf,
 *   note that this can be 0 to indicate that the core wants
 *   to discard the message!
 * @return OK on success, SYSERR on error
 */
typedef int (*BuildMessageCallback)(void * buf,
				    void * closure,
				    unsigned short len);

/**
 * Send a message to the client identified by the handle.  Note that
 * the core will typically buffer these messages as much as possible
 * and only return SYSERR if it runs out of buffers.  Returning OK
 * on the other hand does NOT confirm delivery since the actual
 * transfer happens asynchronously.
 */
typedef int (*SendToClientCallback)(ClientHandle handle,
                                    const CS_MESSAGE_HEADER * message);

/**
 * GNUnet CORE API for applications and services that are implemented
 * on top of the GNUnet core.
 */
typedef struct {

  /**
   * The version of the CORE API. For now, always "0".
   */
  unsigned int version;

  /**
   * The identity of the local node.
   */
  PeerIdentity * myIdentity;

  /* ****************** services and applications **************** */

  /**
   * Load an application module.  This function must be called
   * while cron is suspended.  Note that the initialization and
   * shutdown function of modules are always run while cron is
   * disabled, so suspending cron is not necesary if modules
   * are loaded or unloaded inside the module initialization or
   * shutdown code.
   *
   * @return OK on success, SYSERR on error
   */
  int (*loadApplicationModule)(const char * name);

  /**
   * Unload an application module.  This function must be called
   * while cron is suspended.  Note that the initialization and
   * shutdown function of modules are always run while cron is
   * disabled, so suspending cron is not necesary if modules
   * are loaded or unloaded inside the module initialization or
   * shutdown code.
   *
   * @return OK on success, SYSERR on error
   */
  int (*unloadApplicationModule)(const char * name);

  /**
   * Load a service module of the given name. This function must be
   * called while cron is suspended.  Note that the initialization and
   * shutdown function of modules are always run while cron is
   * disabled, so suspending cron is not necesary if modules are
   * loaded or unloaded inside the module initialization or shutdown
   * code.
   */
  void * (*requestService)(const char * name);

  /**
   * Notification that the given service is no longer required. This
   * function must be called while cron is suspended.  Note that the
   * initialization and shutdown function of modules are always run
   * while cron is disabled, so suspending cron is not necesary if
   * modules are loaded or unloaded inside the module initialization
   * or shutdown code.
   *
   * @return OK if service was successfully released, SYSERR on error
   */
  int (*releaseService)(void * service);

  /* ****************** P2P data exchange **************** */

  /**
   * Send a plaintext message to another node.  This is
   * not the usual way for communication and should ONLY be
   * used by modules that are responsible for setting up
   * sessions.  This bypasses resource allocation, bandwidth
   * scheduling, knapsack solving and lots of other goodies
   * from the GNUnet core.
   *
   * @param session the transport session
   * @param msg the message to transmit, should contain P2P_MESSAGE_HEADERs
   * @return OK on success, SYSERR on failure
   */
  int (*sendPlaintext)(TSession * session,
		       const char * msg,
		       unsigned int size);

  /**
   * Send an encrypted message to another node.
   *
   * @param receiver the target node
   * @param msg the message to send, NULL to tell
   *   the core to try to establish a session
   * @param importance how important is the message?
   * @param maxdelay how long can the message be delayed?
   */
  void (*unicast)(const PeerIdentity * receiver,
		  const P2P_MESSAGE_HEADER * msg,
		  unsigned int importance,
		  unsigned int maxdelay);

  /**
   * Send an encrypted, on-demand build message to another node.
   *
   * @param receiver the target node
   * @param callback the callback to build the message
   * @param closure the second argument to callback
   * @param len how long is the message going to be?
   * @param importance how important is the message?
   * @param maxdelay how long can the message wait?
   */
  void (*unicastCallback)(const PeerIdentity * receiver,
			  BuildMessageCallback callback,
			  void * closure,
			  unsigned short len,
			  unsigned int importance,
			  unsigned int maxdelay);

  /**
   * Perform an operation for all connected hosts.
   * No synchronization or other checks are performed.
   *
   * @param method the method to invoke (NULL for counting only)
   * @param arg the second argument to the method
   * @return the number of connected hosts
   */
  int (*forAllConnectedNodes)(PerNodeCallback method,
			      void * arg);

  /**
   * Register a callback method that should be invoked whenever a message
   * is about to be send that has more than minimumPadding bytes left
   * before maxing out the MTU.
   * The callback method can then be used to add additional content
   * to the message (instead of the random noise that is added by
   * otherwise). Note that if the MTU is 0 (for streams), the
   * callback method will always be called with padding set to the
   * maximum number of bytes left in the buffer allocated for the
   * send.
   * @param minimumPadding how large must the padding be in order
   *   to call this method?
   * @param callback the method to invoke. The receiver is the
   *   receiver of the message, position is the reference to the
   *   first unused position in the buffer where GNUnet is building
   *   the message, padding is the number of bytes left in that buffer.
   *   The callback method must return the number of bytes written to
   *   that buffer (must be a positive number).
   * @return OK if the handler was registered, SYSERR on error
   */
  int (*registerSendCallback)(const unsigned int minimumPadding,
			      BufferFillCallback callback);

  /**
   * Unregister a handler that was registered with registerSendCallback.
   * @return OK if the handler was removed, SYSERR on error
   */
  int (*unregisterSendCallback)(const unsigned int minimumPadding,
				BufferFillCallback callback);

  /**
   * Register a handler that is to be called for each
   * message that leaves the peer.
   *
   * @param callback the method to call for each
   *        P2P message part that is transmitted
   * @return OK on success, SYSERR if there is a problem
   */
  int (*registerSendNotify)(MessagePartHandler callback);

  /**
   * Unregister a handler that is to be called for each
   * message that leaves the peer.
   *
   * @param callback the method to call for each
   *        P2P message part that is transmitted
   * @return OK on success, SYSERR if there is a problem
   */
  int (*unregisterSendNotify)(MessagePartHandler callback);


  /* ********************* handlers ***************** */

  /**
   * Register a method as a handler for specific message
   * types. Only for encrypted messages!
   * @param type the message type
   * @param callback the method to call if a message of
   *        that type is received
   * @return OK on success, SYSERR if there is already a
   *         handler for that type
   */
  int (*registerHandler)(unsigned short type,
			 MessagePartHandler callback);

  /**
   * Unregister a method as a handler for specific message
   * types. Only for encrypted messages!
   * @param type the message type
   * @param callback the method to call if a message of
   *        that type is received
   * @return OK on success, SYSERR if there is a different
   *         handler for that type
   */
  int (*unregisterHandler)(unsigned short type,
			   MessagePartHandler callback);

  /**
   * Is a handler registered for messages of the given type?
   * @param type the message type
   * @param handlerType 0 for plaintext P2P,
   *                    1 for ciphertext P2P,
   *                    2 for either plaintext or ciphertext P2P,
   *                    3 for client-server
   *        NO for ciphertext handlers, SYSERR for either
   * @return number of handlers registered, 0 for none,
   *        SYSERR for invalid value of handlerType
   */
  int (*isHandlerRegistered)(unsigned short type,
			     unsigned short handlerType);

  /**
   * Register a method as a handler for specific message
   * types. Only for encrypted messages!
   * @param type the message type
   * @param callback the method to call if a message of
   *        that type is received
   * @return OK on success, SYSERR if there is already a
   *         handler for that type
   */
  int (*registerPlaintextHandler)(unsigned short type,
				  PlaintextMessagePartHandler callback);

  /**
   * Unregister a method as a handler for specific message
   * types. Only for encrypted messages!
   *
   * @param type the message type
   * @param callback the method to call if a message of
   *        that type is received
   * @return OK on success, SYSERR if there is a different
   *         handler for that type
   */
  int (*unregisterPlaintextHandler)(unsigned short type,
				    PlaintextMessagePartHandler callback);

  /* ***************** traffic management ******************* */

  /**
   * Offer the core a session for communication with the
   * given peer.  This is useful after establishing a connection
   * with another peer to hand it of to the core.  Note that
   * the core will take over the session and disconnect
   * it as it feels like.  Thus the client should no longer
   * use it after this call.  If the core does not want/need
   * the session, it will also be disconnected.
   */
  void (*offerTSessionFor)(const PeerIdentity * peer,
			   TSession * session);

  /**
   * Assign a session key for traffic from or to a given peer.
   * If the core does not yet have an entry for the given peer
   * in the connection table, a new entry is created.
   *
   * @param key the sessionkey,
   * @param peer the other peer,
   * @param forSending NO if it is the key for receiving,
   *                   YES if it is the key for sending
   */
  void (*assignSessionKey)(const SESSIONKEY * key,
			   const PeerIdentity * peer,
			   TIME_T age,
			   int forSending);

  /**
   * Obtain the session key used for traffic from or to a given peer.
   *
   * @param key the sessionkey (set)
   * @param age the age of the key (set)
   * @param peer the other peer,
   * @param forSending NO if it is the key for receiving,
   *                   YES if it is the key for sending
   * @return SYSERR if no sessionkey is known to the core,
   *         OK if the sessionkey was set.
   */
  int (*getCurrentSessionKey)(const PeerIdentity * peer,
			      SESSIONKEY * key,
			      TIME_T * age,
			      int forSending);

  /**
   * We have confirmed that the other peer is communicating with us,
   * mark the session as up-and-running (assuming the
   * core has both sessionkeys, otherwise this method fails --
   * this could happen if in between the core has discarded
   * the session information).
   */
  void (*confirmSessionUp)(const PeerIdentity * peer);

  /**
   * Increase the preference for traffic from some other peer.
   *
   * @param node the identity of the other peer
   * @param preference how much should the traffic preference be increased?
   */
  void (*preferTrafficFrom)(const PeerIdentity * node,
			    double preference);

  /**
   * Query how much bandwidth is availabe FROM the given node to
   * this node in bpm (at the moment).
   *
   * @return 0 only if we are NOT connected at all,
   *  this way, this method can be used to test if we
   *  are currently connected to a peer.
   */
  unsigned int (*queryBPMfromPeer)(const PeerIdentity * node);

  /**
   * Disconnect a particular peer. Sends a HANGUP message to the other
   * side and marks all sessionkeys as dead.
   *
   * @param peer  the peer to disconnect
   */
  void (*disconnectFromPeer)(const PeerIdentity *peer);

  /* **************** Client-server interaction **************** */

  /**
   * Send a message to the client identified by the handle.  Note that
   * the core will typically buffer these messages as much as possible
   * and only return SYSERR if it runs out of buffers.  Returning OK
   * on the other hand does NOT confirm delivery since the actual
   * transfer happens asynchronously.
   */
  int (*sendValueToClient)(ClientHandle handle,
			   int value);

  /**
   * Send a message to the client identified by the handle.  Note that
   * the core will typically buffer these messages as much as possible
   * and only return SYSERR if it runs out of buffers.  Returning OK
   * on the other hand does NOT confirm delivery since the actual
   * transfer happens asynchronously.
   */
  SendToClientCallback sendToClient;

  /**
   * Register a method as a handler for specific message
   * types.
   * @param type the message type
   * @param callback the method to call if a message of
   *        that type is received
   * @return OK on success, SYSERR if there is already a
   *         handler for that type
   */
  int (*registerClientHandler)(unsigned short type,
			       CSHandler callback);

  /**
   * Remove a method as a handler for specific message
   * types.
   * @param type the message type
   * @param callback the method to call if a message of
   *        that type is received
   * @return OK on success, SYSERR if there is a different
   *         handler for that type
   */
  int (*unregisterClientHandler)(unsigned short type,
				 CSHandler callback);

  /**
   * Register a handler to call if any client exits.
   * @param callback a method to call with the socket
   *   of every client that disconnected.
   * @return OK on success, SYSERR on error
   */
  int (*registerClientExitHandler)(ClientExitHandler callback);

  /**
   * Unregister a handler to call if any client exits.
   * @param callback a method to call with the socket
   *   of every client that disconnected.
   * @return OK on success, SYSERR on error
   */
  int (*unregisterClientExitHandler)(ClientExitHandler callback);

  /**
   * Terminate the connection with the given client (asynchronous
   * detection of a protocol violation).
   */
  void (*terminateClientConnection)(ClientHandle handle);

  /* ************************ MISC ************************ */

  /**
   * Send a message to ourselves (simulated loopback).
   * Handle a message (that was decrypted if needed).  Processes the
   * message by calling the registered handler for each message part.
   *
   * @param wasEncrypted YES if it was encrypted,
   *                     NO if plaintext.
   * @param session for plaintext messages, the
   *  assumed transport session.  Maybe NULL.
   */
  void (*injectMessage)(const PeerIdentity * sender,
			const char * msg,
			unsigned int size,
			int wasEncrypted,
			TSession * session);

  /**
   * Compute the index (small, positive, pseudo-unique identification
   * number) of a hostId.
   */
  unsigned int (*computeIndex)(const PeerIdentity * hostId);

  /**
   * The the lock of the connection module. A module that registers
   * callbacks may need this.
   */
  Mutex * (*getConnectionModuleLock)(void);

  /**
   * Get the current number of slots in the connection table (as computed
   * from the available bandwidth).
   */
  int (*getSlotCount)(void);

  /**
   * Is the given slot used?
   * @return 0 if not, otherwise number of peers in
   * the slot
   */
  int (*isSlotUsed)(int slot);

  /**
   * Get the time of the last encrypted message that was received
   * from the given peer.
   * @param time updated with the time
   * @return SYSERR if we are not connected to the peer at the moment
   */
  int (*getLastActivityOf)(const PeerIdentity * peer,
			   cron_t * time);

} CoreAPIForApplication;

/**
 * Type of the initialization method implemented by GNUnet protocol
 * plugins.
 *
 * @param capi the core API
 */
typedef int (*ApplicationInitMethod) (CoreAPIForApplication * capi);

/**
 * Type of the shutdown method implemented by GNUnet protocol
 * plugins.
 */
typedef void (*ApplicationDoneMethod)(void);

/**
 * Type of the initialization method implemented by GNUnet service
 * plugins.
 *
 * @param capi the core API
 */
typedef void * (*ServiceInitMethod)(CoreAPIForApplication * capi);

/**
 * Type of the shutdown method implemented by GNUnet service
 * plugins.
 */
typedef void (*ServiceDoneMethod)(void);



/**
 * API for version updates.  Each module may define a function
 * update_MODULE-NAME which must have the signature of an
 * UpdateMethod.  Whenever the GNUnet version changes, gnunet-update
 * will then call that function to allow the module to perform the
 * necessary updates.
 */
typedef struct {

  /**
   * Trigger updates for another module.
   */
  int (*updateModule)(const char * module);

  /**
   * Load a service module of the given name. This function must be
   * called while cron is suspended.  Note that the initialization and
   * shutdown function of modules are always run while cron is
   * disabled, so suspending cron is not necesary if modules are
   * loaded or unloaded inside the module initialization or shutdown
   * code.
   */
  void * (*requestService)(const char * name);

  /**
   * Notification that the given service is no longer required. This
   * function must be called while cron is suspended.  Note that the
   * initialization and shutdown function of modules are always run
   * while cron is disabled, so suspending cron is not necesary if
   * modules are loaded or unloaded inside the module initialization
   * or shutdown code.
   *
   * @return OK if service was successfully released, SYSERR on error
   */
  int (*releaseService)(void * service);


} UpdateAPI;

typedef void (*UpdateMethod)(UpdateAPI * uapi);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
