/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2007 Christian Grothoff (and other contributing authors)

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
#include "ip.h"

#define DEBUG_NAT NO

/**
 * Host-Address in a NAT network.  Since the idea behind
 * NAT is that it can not be contacted from the outside,
 * the address is empty.
 */
typedef struct
{
} HostAddress;

/* *********** globals ************* */

/* apis (our advertised API and the core api ) */
static TransportAPI natAPI;

static CoreAPIForTransport *coreAPI;


/* *************** API implementation *************** */

/**
 * Verify that a hello-Message is correct (a node is reachable at that
 * address).
 *
 * @param hello the hello message to verify
 *        (the signature/crc have been verified before)
 * @return OK on success, SYSERR on failure
 */
static int
verifyHello (const P2P_hello_MESSAGE * hello)
{
  if ((ntohs (hello->senderAddressSize) != sizeof (HostAddress)) ||
      (ntohs (hello->header.size) != P2P_hello_MESSAGE_size (hello)) ||
      (ntohs (hello->header.type) != p2p_PROTO_hello))
    return SYSERR;              /* obviously invalid */
  if (YES == GC_get_configuration_value_yesno (coreAPI->cfg,
                                               "NAT", "LIMITED", NO))
    {
      /* if WE are a NAT and this is not our hello,
         it is invalid since NAT-to-NAT is not possible! */
      if (0 == memcmp (&coreAPI->myIdentity->hashPubKey,
                       &hello->senderIdentity.hashPubKey,
                       sizeof (HashCode512)))
        return OK;
      return SYSERR;
    }
  return OK;
}

/**
 * Create a hello-Message for the current node. The hello is created
 * without signature and without a timestamp. The GNUnet core will
 * sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static P2P_hello_MESSAGE *
createhello ()
{
  P2P_hello_MESSAGE *msg;

  if (NO == GC_get_configuration_value_yesno (coreAPI->cfg,
                                              "NAT", "LIMITED", NO))
    return NULL;
  msg = MALLOC (sizeof (P2P_hello_MESSAGE) + sizeof (HostAddress));
  msg->senderAddressSize = htons (sizeof (HostAddress));
  msg->protocol = htons (NAT_PROTOCOL_NUMBER);
  msg->MTU = htonl (0);
  return msg;
}

/**
 * Establish a connection to a remote node.
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @return always fails (returns SYSERR)
 */
static int
natConnect (const P2P_hello_MESSAGE * hello, TSession ** tsessionPtr,
            int may_reuse)
{
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
int
natAssociate (TSession * tsession)
{
  return SYSERR;                /* NAT connections can never be associated */
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the P2P_hello_MESSAGE identifying the remote node
 * @param message what to send
 * @param size the size of the message
 * @return SYSERR (always fails)
 */
static int
natSend (TSession * tsession,
         const void *message, const unsigned int size, int important)
{
  return SYSERR;
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return always SYSERR
 */
static int
natDisconnect (TSession * tsession)
{
  return SYSERR;
}

/**
 * Start the server process to receive inbound traffic.
 *
 * @return OK on success, SYSERR if the operation failed
 */
static int
startTransportServer ()
{
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int
stopTransportServer ()
{
  return OK;
}

/**
 * Convert NAT address to a string.
 */
static int
helloToAddress (const P2P_hello_MESSAGE * hello,
                void **sa, unsigned int *sa_len)
{
  return getIPaddressFromPID (&hello->senderIdentity, sa, sa_len);
}

static int
testWouldTry (TSession * tsession, unsigned int size, int important)
{
  return SYSERR;
}

/**
 * The exported method. Makes the core api available via a global and
 * returns the nat transport API.
 */
TransportAPI *
inittransport_nat (CoreAPIForTransport * core)
{
  coreAPI = core;
  natAPI.protocolNumber = NAT_PROTOCOL_NUMBER;
  natAPI.mtu = 0;
  natAPI.cost = 30000;
  natAPI.verifyHello = &verifyHello;
  natAPI.createhello = &createhello;
  natAPI.connect = &natConnect;
  natAPI.send = &natSend;
  natAPI.associate = &natAssociate;
  natAPI.disconnect = &natDisconnect;
  natAPI.startTransportServer = &startTransportServer;
  natAPI.stopTransportServer = &stopTransportServer;
  natAPI.helloToAddress = &helloToAddress;
  natAPI.testWouldTry = &testWouldTry;

  return &natAPI;
}

void
donetransport_nat ()
{
}

/* end of nat.c */
