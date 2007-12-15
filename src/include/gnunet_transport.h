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
 * @file include/gnunet_transport.h
 * @brief The APIs for GNUnet transport layer implementations.
 * @author Christian Grothoff
 */

#ifndef GNUNET_TRANSPORT_H
#define GNUNET_TRANSPORT_H

#include "gnunet_core.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Just the version number of GNUnet-transport implementation.
 * Encoded as
 * 0.6.1d  => 0x00060100
 * 4.5.2   => 0x04050200
 *
 * Note that this version number is only changed if
 * something changes in the transport API.  It follows
 * roughly the main GNUnet version scheme, but is
 * more a compatibility ID.
 */
#define GNUNET_TRANSPORT_VERSION 0x00070000

/**
 * Type of a struct passed to receive.
 */
typedef struct
{
  /**
   * The session associated with the message
   * on the transport layer side. Maybe passed to "associate"
   * in order to send replies on a bi-directional pipe (if
   * possible).
   */
  GNUNET_TSession *tsession;

  /**
   * The identity of the sender node
   */
  GNUNET_PeerIdentity sender;

  /**
   * The message itself. The GNUnet core will call 'GNUNET_free' once
   * processing of msg is complete.
   */
  char *msg;

  /**
   * The size of the message
   */
  unsigned int size;

} GNUNET_TransportPacket;

/**
 * Function that is to be used to process messages
 * received from the transport.
 *
 * @param mp the message, freed by the callee once processed!
 */
typedef void (*GNUNET_TransportPacketProcessor) (GNUNET_TransportPacket * mp);

/**
 * This header file contains a draft for the gnunetd
 * core API. This API is used by the transport layer
 * for communication with the GNUnet core.
 *
 * A pointer to an instance of this struct is passed
 * to the init method of each Transport API.
 */
typedef struct
{

  /**
   * The version of the CORE API. For now, always "1".
   */
  unsigned int version;

  /**
   * The identity of the local node.
   */
  GNUNET_PeerIdentity *myIdentity;

  /**
   * System error context
   */
  struct GNUNET_GE_Context *ectx;

  /**
   * System configuration
   */
  struct GNUNET_GC_Configuration *cfg;

  /**
   * System load monitor
   */
  struct GNUNET_LoadMonitor *load_monitor;

  /**
   * System cron Manager.
   */
  struct GNUNET_CronManager *cron;

  /**
   * Data was received (potentially encrypted), make the core process
   * it.
   */
  GNUNET_TransportPacketProcessor receive;

  /**
   * Load a service module of the given name. This function must be
   * called while cron is suspended.  Note that the initialization and
   * shutdown function of modules are always run while cron is
   * disabled, so suspending cron is not necesary if modules are
   * loaded or unloaded inside the module initialization or shutdown
   * code.
   */
  void *(*request_service) (const char *name);

  /**
   * Notification that the given service is no longer required. This
   * function must be called while cron is suspended.  Note that the
   * initialization and shutdown function of modules are always run
   * while cron is disabled, so suspending cron is not necesary if
   * modules are loaded or unloaded inside the module initialization
   * or shutdown code.
   *
   * @return GNUNET_OK if service was successfully released, GNUNET_SYSERR on error
   */
  int (*release_service) (void *service);

  int (*connection_assert_tsession_unused) (GNUNET_TSession * tsession);


} GNUNET_CoreAPIForTransport;


/**
 * This header file contains a list of the methods that every
 * transport layer implementation must provide. The basic idea is that
 * gnunetd calls "inittransport_XXX" on every transport-api, passing a
 * struct with gnunetd core services to the transport api, and getting
 * a struct with services provided by the transport api back (or null
 * on error). The return value of init is of type GNUNET_TransportAPI.
 *
 * Example:
 *
 * GNUNET_TransportAPI * inittransport_XXX(CoreGNUNET_TransportAPI * api) {
 *   if (api->version != 0)
 *     return NULL;
 *   // ...
 *   return myApi;
 * }
 *
 * The type of inittransport_XXX is GNUNET_TransportMainMethod.
 */
typedef struct
{

  /**
   * This field is used by the core internally;
   * the transport should never do ANYTHING
   * with it.
   */
  struct GNUNET_PluginHandle *libHandle;

  /**
   * The name of the transport, set by the
   * core. Read only for the service itself!
   */
  char *transName;

  /**
   * This field holds a cached hello for this
   * transport. hellos must be signed with RSA,
   * so caching the result for a while is a good
   * idea.  The field is updated by a cron job
   * periodically.
   */
  GNUNET_MessageHello *hello;

  /**
   * The number of the protocol that is supported by this transport
   * API (i.e. 6 tcp, 17 udp, 80 http, 25 smtp, etc.)
   */
  unsigned short protocolNumber;

  /**
   * The MTU for the protocol (e.g. 1472 for UDP).
   * Can be up to 65535 for stream-oriented transport
   * protocols)
   */
  unsigned short mtu;

  /**
   * How costly is this transport protocol (compared to the other
   * transports, UDP and TCP are scaled to be both 100). The cost is
   * used by GNUnet to select the most preferable mode of
   * transportation.
   */
  unsigned int cost;

  /**
   * Verify that a hello-Message is correct (a node
   * is potentially reachable at that address). Core
   * will only play ping pong after this verification passed.
   * @param hello the hello message to verify
   *        (the signature/crc have been verified before)
   * @return GNUNET_OK if the helo is well-formed
   */
  int (*verifyHello) (const GNUNET_MessageHello * hello);

  /**
   * Create a hello-Message for the current node. The hello is
   * created without signature, timestamp, senderIdentity
   * or publicKey. The GNUnet core will GNUNET_RSA_sign the message
   * and add these other fields. The callee is only
   * responsible for filling in the protocol number,
   * senderAddressSize and the senderAddress itself.
   *
   * @return GNUNET_OK on success, GNUNET_SYSERR on error (e.g. send-only
   *  transports return GNUNET_SYSERR here)
   */
  GNUNET_MessageHello *(*createhello) (void);

  /**
   * Establish a connection to a remote node.
   *
   * @param hello the hello-Message for the target node
   * @param tsession the session handle that is to be set
   * @param may_reuse can an existing connection be re-used?
   * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
   */
  int (*connect) (const GNUNET_MessageHello * hello,
                  GNUNET_TSession ** tsession, int may_reuse);

  /**
   * Send a message to the specified remote node.
   * @param tsession an opaque session handle (e.g. a socket
   *        or the hello_message from connect)
   * @param msg the message
   * @param size the size of the message, <= mtu
   * @param important GNUNET_YES if message is important (i.e. grow
   *        buffers to queue if needed)
   * @return GNUNET_SYSERR on error, GNUNET_NO on temporary error (retry),
   *         GNUNET_YES/GNUNET_OK on success; after any persistent error,
   *         the caller must call "disconnect" and not continue
   *         using the session afterwards (useful if the other
   *         side closed the connection).
   */
  int (*send) (GNUNET_TSession * tsession,
               const void *msg, unsigned int size, int important);

  /**
   * A (core) Session is to be associated with a transport session. The
   * transport service may want to know in order to call back on the
   * core if the connection is being closed. Associate can also be
   * called to test if it would be possible to associate the session
   * later, in this case, call disconnect afterwards. This can be used
   * to test if the connection must be closed by the core or if the core
   * can assume that it is going to be self-managed (if associate
   * returns GNUNET_OK and session was NULL, the transport layer is responsible
   * for eventually freeing resources associated with the tesession). If
   * session is not NULL, the core takes responsbility for eventually
   * calling disconnect.
   *
   * @param tsession the session handle passed along
   *   from the call to receive that was made by the transport
   *   layer
   * @return GNUNET_OK if the session could be associated,
   *         GNUNET_SYSERR if not.
   */
  int (*associate) (GNUNET_TSession * tsession);

  /**
   * Disconnect from a remote node. A session can be closed
   * by either the transport layer calling "closeSession" on
   * the core API or by the core API calling "disconnect"
   * on the transport API. Neither closeSession nor
   * disconnect should call the other method. Due to
   * potentially concurrent actions (both sides close the
   * connection simultaneously), either API must tolerate
   * being called from the other side.
   *
   * @param tsession the session that is to be closed
   * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
   */
  int (*disconnect) (GNUNET_TSession * tsession);

  /**
   * Start the server process to receive inbound traffic.
   * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
   */
  int (*startTransportServer) (void);

  /**
   * Shutdown the server process (stop receiving inbound
   * traffic). Maybe restarted later!
   */
  int (*stopTransportServer) (void);

  /**
   * Convert hello to network address.
   * @return GNUNET_OK on success, GNUNET_SYSERR on error
   */
  int (*helloToAddress) (const GNUNET_MessageHello * hello,
                         void **sa, unsigned int *sa_len);

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
  int (*testWouldTry) (GNUNET_TSession * tsession, unsigned int size,
                       int important);

} GNUNET_TransportAPI;

/**
 * This header file contains a draft of the methods that every
 * transport layer implementation should implement. The basic idea is
 * that gnunetd calls "inittransport_XXX" on every transport-api, passing a struct
 * with gnunetd core services to the transport api, and getting a
 * struct with services provided by the transport api back (or null
 * on error). The return value of init is of type GNUNET_TransportAPI.
 *
 * Example:
 *
 * GNUNET_TransportAPI * inittransport_XXX(CoreGNUNET_TransportAPI * api) {
 *   if (api->version != 0)
 *     return NULL;
 *   // ...
 *   return myApi;
 * }
 *
 * The type of inittransport_XXX is GNUNET_TransportMainMethod.
 */
typedef GNUNET_TransportAPI
  * (*GNUNET_TransportMainMethod) (GNUNET_CoreAPIForTransport *);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_transport.h */
#endif
