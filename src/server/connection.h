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
 * each with its own MESSAGE_HEADER.
 */
typedef struct {
  /* hash of the plaintext, used to verify message integrity;
     ALSO used as the IV for the symmetric cipher! */
  HashCode512 hash;
  /* sequence number, in network byte order, 0 for plaintext messages! */
  unsigned int sequenceNumber;
  /* timestamp  (network byte order), 0 for plaintext messages! */
  TIME_T timeStamp;
  /* desired bandwidth, 0 for plaintext messages! */
  unsigned int bandwidth;
} P2P_PACKET_HEADER; /* 76 bytes */

/* ***************** GNUnet core internals ************ */

/**
 * Initialize this module.
 */
void initConnection(struct GE_Context * ectx,
		    struct GC_Configuration * cfg,
		    struct LoadMonitor * mon,
		    struct CronManager * cron);

/**
 * Shutdown the connection module.
 */
void doneConnection(void);

/**
 * For debugging.
 */
void printConnectionBuffer(void);

/**
 * Check the sequence number and timestamp.  Decrypts the
 * message if it was encrypted.  Updates the sequence
 * number as a side-effect.
 *
 * @param sender from which peer did we receive the SEQ message
 * @param msg the p2p message (the decrypted message is stored here, too!)
 * @param size the size of the message
 * @return YES if the message was encrypted,
 *         NO if it was in plaintext,
 *         SYSERR if it was malformed
 */
int checkHeader(const PeerIdentity * sender,
		P2P_PACKET_HEADER * msg,
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
void considerTakeover(const PeerIdentity * sender,
		      TSession * tsession);

/* ***************** CORE API methods ************* */

/**
 * Are we connected to this host?
 * @return YES or NO.
 */
int isConnected(const PeerIdentity * hi);

/**
 * Call method for every connected node.
 */
int forEachConnectedNode(PerNodeCallback method,
			 void * arg);


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
 * @return OK on success, SYSERR on failure
 */
int sendPlaintext(TSession * tsession,
		  const char * msg,
		  unsigned int size);

/**
 * Compute the hashtable index of a host id.
 */
unsigned int computeIndex(const PeerIdentity * hostId);

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
 * @return OK if the handler was registered, SYSERR on error
 */
int registerSendCallback(const unsigned int minimumPadding,
			 BufferFillCallback callback);

/**
 * Unregister a handler that was registered with registerSendCallback.
 * @return OK if the handler was removed, SYSERR on error
 */
int unregisterSendCallback(const unsigned int minimumPadding,
			   BufferFillCallback callback);

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
void unicastCallback(const PeerIdentity * hostId,
		     BuildMessageCallback callback,
		     void * closure,
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
void unicast(const PeerIdentity * receiver,
	     const MESSAGE_HEADER * msg,
	     unsigned int importance,
	     unsigned int maxdelay);

/**
 * Return a pointer to the lock of the connection module.
 */
struct MUTEX * getConnectionModuleLock(void);


/* ******************** traffic management ********** */

/**
 * How many bpm did we assign this peer (how much traffic
 * may the given peer send to us per minute?)
 */
int getBandwidthAssignedTo(const PeerIdentity * hostId,
			   unsigned int * bpm,
			   cron_t * last_seen);

/**
 * Increase the preference for traffic from some other peer.
 * @param node the identity of the other peer
 * @param preference how much should the traffic preference be increased?
 */
void updateTrafficPreference(const PeerIdentity * node,
			     double preference);


/**
 * Disconnect a particular peer. Send a HANGUP message to the other side
 * and mark the sessionkey as dead.
 *
 * @param peer  the peer to disconnect
 */
void disconnectFromPeer(const PeerIdentity *node);


/**
 * Offer the core a session for communication with the
 * given peer.  This is useful after establishing a connection
 * with another peer to hand it of to the core.  Note that
 * the core will take over the session and disconnect
 * it as it feels like.  Thus the client should no longer
 * use it after this call.  If the core does not want/need
 * the session, it will also be disconnected.
 */
void offerTSessionFor(const PeerIdentity * peer,
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
void assignSessionKey(const SESSIONKEY * key,
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
int getCurrentSessionKey(const PeerIdentity * peer,
			 SESSIONKEY * key,
			 TIME_T * age,
			 int forSending);


/**
 * Get the current number of slots in the connection table (as computed
 * from the available bandwidth).
 */
int getSlotCount();

/**
 * Is the given slot used?
 * @return 0 if not, otherwise number of peers in
 * the slot
 */
int isSlotUsed(int slot);

/**
 * Get the time of the last encrypted message that was received
 * from the given peer.
 * @param time updated with the time
 * @return SYSERR if we are not connected to the peer at the moment
 */
int getLastActivityOf(const PeerIdentity * peer,
		      cron_t * time);


/**
 * Confirm that a connection is up.
 *
 * @param peer the other peer,
 */
void confirmSessionUp(const PeerIdentity * peer);


/**
 * Register a handler that is to be called for each
 * message that leaves the peer.
 *
 * @param callback the method to call for each
 *        P2P message part that is transmitted
 * @return OK on success, SYSERR if there is a problem
 */
int registerSendNotify(MessagePartHandler callback);

/**
 * Unregister a handler that is to be called for each
 * message that leaves the peer.
 *
 * @param callback the method to call for each
 *        P2P message part that is transmitted
 * @return OK on success, SYSERR if there is a problem
 */
int unregisterSendNotify(MessagePartHandler callback);



#endif
/* end of connection.h */
