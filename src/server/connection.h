/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file server/connection.h
 * @author Tzvetan Horozov
 * @author Christian Grothoff
 */

#ifndef CONNECTION_H
#define CONNECTION_H

#include "gnunet_util.h"
#include "gnunet_core.h"
#include "gnunet_transport.h"
#include "gnunet_fragmentation_service.h"

/**
 * @brief General packet header for all encrypted peer-to-peer
 * packets.  This is the format that handler(.c) expects after
 * decrypting the packet.  It provides a timestamp and sequence
 * number (to guard against replay attacks).  The header is followed
 * by the 'data' which contains a sequence of GNUnet p2p messages,
 * each with its own GNUNET_MessageHeader.
 */
typedef struct
{
  /* GNUNET_hash of the plaintext, used to verify message integrity;
     ALSO used as the IV for the symmetric cipher! */
  GNUNET_HashCode hash GNUNET_PACKED;
  /* sequence number, in network byte order, 0 for plaintext messages! */
  unsigned int sequenceNumber GNUNET_PACKED;
  /* timestamp  (network byte order), 0 for plaintext messages! */
  GNUNET_Int32Time timeStamp GNUNET_PACKED;
  /* desired bandwidth, 0 for plaintext messages! */
  unsigned int bandwidth GNUNET_PACKED;
} GNUNET_TransportPacket_HEADER;        /* 76 bytes */

/* ***************** GNUnet core internals ************ */

/**
 * Initialize this module.
 */
void GNUNET_CORE_connection_init (struct GNUNET_GE_Context *ectx,
                                  struct GNUNET_GC_Configuration *cfg,
                                  struct GNUNET_LoadMonitor *mon,
                                  struct GNUNET_CronManager *cron);

/**
 * Shutdown the connection module.
 */
void GNUNET_CORE_connection_done (void);

/**
 * For debugging.
 */
void GNUNET_CORE_connection_print_buffer (void);

/**
 * Check the sequence number and timestamp.  Decrypts the
 * message if it was encrypted.  Updates the sequence
 * number as a side-effect.
 *
 * @param sender from which peer did we receive the SEQ message
 * @param msg the p2p message (the decrypted message is stored here, too!)
 * @param size the size of the message
 * @return GNUNET_YES if the message was encrypted,
 *         GNUNET_NO if it was in plaintext,
 *         GNUNET_SYSERR if it was malformed
 */
int GNUNET_CORE_connection_check_header (const GNUNET_PeerIdentity * sender,
                                         GNUNET_TransportPacket_HEADER * msg,
                                         unsigned short size);

/**
 * Consider switching the transport mechanism used for contacting the
 * given node.  This function is called when the handler handles an
 * encrypted connection.  For example, if we are sending SMTP messages
 * to a node behind a NAT box, but that node has established a TCP
 * connection to us, it might just be better to send replies on that
 * TCP connection instead of keeping SMTP going.
 *
 * @param tsession the transport session that is for grabs
 * @param sender the identity of the other node
 */
void GNUNET_CORE_connection_consider_takeover (const GNUNET_PeerIdentity *
                                               sender,
                                               GNUNET_TSession * tsession);

/* ***************** CORE API methods ************* */

/**
 * Call method for every connected node.
 */
int GNUNET_CORE_connection_iterate_peers (GNUNET_NodeIteratorCallback method,
                                          void *arg);


/**
 * Send a plaintext message to another node.  This is
 * not the usual way for communication and should ONLY be
 * used by modules that are responsible for setting up
 * sessions.  This bypasses resource allocation, bandwidth
 * scheduling, knapsack solving and lots of other goodies
 * from the GNUnet core.
 *
 * @param session the transport session
 * @param msg the message to transmit, should contain MESSAGE_HEADERs
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int GNUNET_CORE_connection_send_plaintext (GNUNET_TSession * tsession,
                                           const char *msg,
                                           unsigned int size);

/**
 * Compute the hashtable index of a host id.
 */
unsigned int GNUNET_CORE_connection_compute_index_of_peer (const
                                                           GNUNET_PeerIdentity
                                                           * hostId);

/**
 * Register a callback method that should be invoked whenever a
 * message is about to be send that has more than minimumPadding bytes
 * left before maxing out the MTU. The callback method can then be
 * used to add additional content to the message (instead of the
 * random noise that is added by otherwise).  Note that if the MTU is
 * 0 (for streams), the callback method will always be called with
 * padding set to the maximum number of bytes left in the buffer
 * allocated for the send.
 *
 * @param minimumPadding how large must the padding be in order
 *   to call this method?
 * @param callback the method to invoke. The receiver is the
 *   receiver of the message, position is the reference to the
 *   first unused position in the buffer where GNUnet is building
 *   the message, padding is the number of bytes left in that buffer.
 *   The callback method must return the number of bytes written to
 *   that buffer (must be a positive number).
 * @return GNUNET_OK if the handler was registered, GNUNET_SYSERR on error
 */
int GNUNET_CORE_connection_register_send_callback (unsigned int
                                                   minimumPadding,
                                                   unsigned int prio,
                                                   GNUNET_BufferFillCallback
                                                   callback);

/**
 * Unregister a handler that was registered with GNUNET_CORE_connection_register_send_callback.
 * @return GNUNET_OK if the handler was removed, GNUNET_SYSERR on error
 */
int GNUNET_CORE_connection_unregister_send_callback (unsigned int
                                                     minimumPadding,
                                                     GNUNET_BufferFillCallback
                                                     callback);

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
void GNUNET_CORE_connection_send_using_callback (const GNUNET_PeerIdentity *
                                                 hostId,
                                                 GNUNET_BuildMessageCallback
                                                 callback, void *closure,
                                                 unsigned short len,
                                                 unsigned int importance,
                                                 unsigned int maxdelay);

/**
 * Send an encrypted message to another node.
 *
 * @param receiver the target node
 * @param msg the message to send
 * @param importance how important is the message?
 * @param maxdelay how long can the message be delayed?
 */
void GNUNET_CORE_connection_unicast (const GNUNET_PeerIdentity * receiver,
                                     const GNUNET_MessageHeader * msg,
                                     unsigned int importance,
                                     unsigned int maxdelay);

/**
 * Return a pointer to the lock of the connection module.
 */
struct GNUNET_Mutex *GNUNET_CORE_connection_get_lock (void);


/* ******************** traffic management ********** */

/**
 * How many bpm did we assign this peer (how much traffic
 * may the given peer send to us per minute?)
 */
int GNUNET_CORE_connection_get_bandwidth_assigned_to_peer (const
                                                           GNUNET_PeerIdentity
                                                           * hostId,
                                                           unsigned int *bpm,
                                                           GNUNET_CronTime *
                                                           last_seen);

/**
 * Increase the preference for traffic from some other peer.
 * @param node the identity of the other peer
 * @param preference how much should the traffic preference be increased?
 */
void GNUNET_CORE_connection_update_traffic_preference_for_peer (const
                                                                GNUNET_PeerIdentity
                                                                * node,
                                                                double
                                                                preference);


/**
 * Disconnect a particular peer. Send a HANGUP message to the other side
 * and mark the sessionkey as dead.
 *
 * @param peer  the peer to disconnect
 */
void GNUNET_CORE_connection_disconnect_from_peer (const GNUNET_PeerIdentity *
                                                  node);


/**
 * Assign a session key for traffic from or to a given peer.
 * If the core does not yet have an entry for the given peer
 * in the connection table, a new entry is created.
 *
 * @param key the sessionkey,
 * @param peer the other peer,
 * @param forSending GNUNET_NO if it is the key for receiving,
 *                   GNUNET_YES if it is the key for sending
 */
void GNUNET_CORE_connection_assign_session_key_to_peer (const
                                                        GNUNET_AES_SessionKey
                                                        * key,
                                                        const
                                                        GNUNET_PeerIdentity *
                                                        peer,
                                                        GNUNET_Int32Time age,
                                                        int forSending);

/**
 * Obtain the session key used for traffic from or to a given peer.
 *
 * @param key the sessionkey (set)
 * @param age the age of the key (set)
 * @param peer the other peer,
 * @param forSending GNUNET_NO if it is the key for receiving,
 *                   GNUNET_YES if it is the key for sending
 * @return GNUNET_SYSERR if no sessionkey is known to the core,
 *         GNUNET_OK if the sessionkey was set.
 */
int GNUNET_CORE_connection_get_session_key_of_peer (const GNUNET_PeerIdentity
                                                    * peer,
                                                    GNUNET_AES_SessionKey *
                                                    key,
                                                    GNUNET_Int32Time * age,
                                                    int forSending);


/**
 * Get the current number of slots in the connection table (as computed
 * from the available bandwidth).
 */
int GNUNET_CORE_connection_get_slot_count (void);

/**
 * Is the given slot used?
 * @return 0 if not, otherwise number of peers in
 * the slot
 */
int GNUNET_CORE_connection_is_slot_used (int slot);

/**
 * Get the time of the last encrypted message that was received
 * from the given peer.
 * @param time updated with the time
 * @return GNUNET_SYSERR if we are not connected to the peer at the moment
 */
int GNUNET_CORE_connection_get_last_activity_of_peer (const
                                                      GNUNET_PeerIdentity *
                                                      peer,
                                                      GNUNET_CronTime * time);


/**
 * Confirm that a connection is up.
 *
 * @param peer the other peer,
 */
void GNUNET_CORE_connection_mark_session_as_confirmed (const
                                                       GNUNET_PeerIdentity *
                                                       peer);


/**
 * Register a handler that is to be called for each
 * message that leaves the peer.
 *
 * @param callback the method to call for each
 *        P2P message part that is transmitted
 * @return GNUNET_OK on success, GNUNET_SYSERR if there is a problem
 */
int
  GNUNET_CORE_connection_register_send_notification_callback
  (GNUNET_P2PRequestHandler callback);

/**
 * Unregister a handler that is to be called for each
 * message that leaves the peer.
 *
 * @param callback the method to call for each
 *        P2P message part that is transmitted
 * @return GNUNET_OK on success, GNUNET_SYSERR if there is a problem
 */
int
  GNUNET_CORE_connection_unregister_send_notification_callback
  (GNUNET_P2PRequestHandler callback);

/**
 * Verify that the given session handle is not in use.
 * @return GNUNET_OK if that is true, GNUNET_SYSERR if not.
 */
int GNUNET_CORE_connection_assert_tsession_unused (GNUNET_TSession *
                                                   tsession);

/**
 * Call the given function whenever we get
 * disconnected from a particular peer.
 *
 * @return GNUNET_OK
 */
int
  GNUNET_CORE_connection_register_notify_peer_disconnect
  (GNUNET_NodeIteratorCallback callback, void *cls);

/**
 * Stop calling the given function whenever we get
 * disconnected from a particular peer.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR
 *         if this callback is not registered
 */
int
  GNUNET_CORE_connection_unregister_notify_peer_disconnect
  (GNUNET_NodeIteratorCallback callback, void *cls);

/**
 * Call the given function whenever we
 * connect to a peer.
 *
 * @return GNUNET_OK
 */
int
  GNUNET_CORE_connection_register_notify_peer_connect
  (GNUNET_NodeIteratorCallback callback, void *cls);

/**
 * Stop calling the given function whenever we
 * connect to a peer.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR
 *         if this callback is not registered
 */
int
  GNUNET_CORE_connection_unregister_notify_peer_connect
  (GNUNET_NodeIteratorCallback callback, void *cls);

/**
 * Try to reserve downstream bandwidth for a particular peer.
 *
 * @param peer with whom should bandwidth be reserved?
 * @param amount how many bytes should we expect to receive?
 *        (negative amounts can be used to undo a (recent)
 *        reservation request
 * @return amount that could actually be reserved
 */
int GNUNET_CORE_connection_reserve_downstream_bandwidth (const
                                                         GNUNET_PeerIdentity *
                                                         peer, int amount);

#endif
/* end of connection.h */
