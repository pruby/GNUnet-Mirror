/*
     This file is part of GNUnet

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
 * @file transports/nat.c
 * @brief Implementation of the NAT transport service
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport.h"
#include "platform.h"

#define DEBUG_NAT NO

/**
 * Host-Address in a NAT network.  Since the idea behind
 * NAT is that it can not be contacted from the outside,
 * the address is empty.
 */
typedef struct {
} HostAddress;

/* *********** globals ************* */

/* apis (our advertised API and the core api ) */
static TransportAPI natAPI;
static CoreAPIForTransport * coreAPI = NULL;


/* *************** API implementation *************** */

/**
 * Verify that a HELO-Message is correct (a node is reachable at that
 * address). 
 *
 * @param helo the HELO message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on failure
 */
static int verifyHelo(const HELO_Message * helo) {

  if ( (ntohs(helo->senderAddressSize) != sizeof(HostAddress)) ||
       (ntohs(helo->header.size) != HELO_Message_size(helo)) ||
       (ntohs(helo->header.type) != p2p_PROTO_HELO) ) {
    return SYSERR; /* obviously invalid */
  } else {
    if (testConfigurationString("NAT",
				"LIMITED",
				"YES")) {
      /* if WE are a NAT and this is not our HELO,
	 it is invalid since NAT-to-NAT is not possible! */
      if (equalsHashCode160(&coreAPI->myIdentity->hashPubKey,
			    &helo->senderIdentity.hashPubKey))
	return OK;
      else
	return SYSERR;
    }
    return OK;  
  }
}

/**
 * Create a HELO-Message for the current node. The HELO is created
 * without signature and without a timestamp. The GNUnet core will
 * sign the message and add an expiration time.
 *
 * @param helo where to store the HELO message
 * @return OK on success, SYSERR on error
 */
static int createHELO(HELO_Message ** helo) {
  HELO_Message * msg;

  if (! testConfigurationString("NAT",
				"LIMITED",
				"YES"))
    return SYSERR;

  msg = MALLOC(sizeof(HELO_Message) + sizeof(HostAddress));
  msg->senderAddressSize = htons(sizeof(HostAddress));
  msg->protocol          = htons(NAT_PROTOCOL_NUMBER);
  msg->MTU               = htonl(0);
  *helo = msg;
  return OK;
}

/**
 * Establish a connection to a remote node.
 * @param helo the HELO-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @return always fails (returns SYSERR)
 */
static int natConnect(HELO_Message * helo,
		      TSession ** tsessionPtr) {
  return SYSERR;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return OK if the session could be associated,
 *         SYSERR if not.
 */
int natAssociate(TSession * tsession) {
  return SYSERR; /* NAT connections can never be associated */
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the HELO_Message identifying the remote node
 * @param message what to send
 * @param size the size of the message
 * @return SYSERR (always fails)
 */
static int natSend(TSession * tsession,
		   const void * message,
		   const unsigned int size) {
  return SYSERR;
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return always SYSERR
 */
static int natDisconnect(TSession * tsession) {
  return SYSERR;
}

/**
 * Start the server process to receive inbound traffic.
 *
 * @return OK on success, SYSERR if the operation failed
 */
static int startTransportServer(void) {
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int stopTransportServer() {
  return OK;
}

/**
 * Reload the configuration. Should never fail.
 */
static void reloadConfiguration(void) {
}

/**
 * Convert NAT address to a string.
 */
static char * addressToString(const HELO_Message * helo) {
  return STRDUP("NAT");
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the nat transport API.
 */ 
TransportAPI * inittransport_nat(CoreAPIForTransport * core) {
  coreAPI = core;
  natAPI.protocolNumber       = NAT_PROTOCOL_NUMBER;
  natAPI.mtu                  = 0;
  natAPI.cost                 = 30000;
  natAPI.verifyHelo           = &verifyHelo;
  natAPI.createHELO           = &createHELO;
  natAPI.connect              = &natConnect;
  natAPI.send                 = &natSend;
  natAPI.sendReliable         = &natSend; /* can't increase reliability */
  natAPI.associate            = &natAssociate;
  natAPI.disconnect           = &natDisconnect;
  natAPI.startTransportServer = &startTransportServer;
  natAPI.stopTransportServer  = &stopTransportServer;
  natAPI.reloadConfiguration  = &reloadConfiguration;
  natAPI.addressToString      = &addressToString;

  return &natAPI;
}

void donetransport_nat() {
}

/* end of nat.c */
