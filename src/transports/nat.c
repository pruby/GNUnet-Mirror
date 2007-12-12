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

#define DEBUG_NAT GNUNET_NO

/* *********** globals ************* */

/* apis (our advertised API and the core api ) */
static GNUNET_TransportAPI natAPI;

static GNUNET_CoreAPIForTransport *coreAPI;

static const char *nat_limited_choices[] = { "YES", "NO", "AUTO", NULL };


/* *************** API implementation *************** */

static int
lan_ip_detected ()
{
  GNUNET_IPv4Address addr;
  unsigned int anum;

  if (GNUNET_SYSERR == GNUNET_IP_get_public_ipv4_address (coreAPI->cfg,
                                                          coreAPI->ectx,
                                                          &addr))
    return GNUNET_YES;          /* kind-of */
  anum = ntohl (addr.addr);
  if (((anum >= 0x0a000000) && (anum <= 0x0affffff)) || /* 10.x.x.x */
      ((anum >= 0xac100000) && (anum <= 0xac10ffff)) || /* 172.16.0.0-172.31.0.0 */
      ((anum >= 0xc0a80000) && (anum <= 0xc0a8ffff)) || /* 192.168.x.x */
      ((anum >= 0x7f000000) && (anum <= 0x7fffffff))    /* 127.x.x.x */
    )
    return GNUNET_YES;
  return GNUNET_NO;
}

/**
 * Verify that a hello-Message is correct (a node is reachable at that
 * address).
 *
 * @param hello the hello message to verify
 *        (the signature/crc have been verified before)
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
verifyHello (const GNUNET_MessageHello * hello)
{
  const char *choice;

  if ((ntohs (hello->senderAddressSize) != 0) ||
      (ntohs (hello->header.size) != GNUNET_sizeof_hello (hello)) ||
      (ntohs (hello->header.type) != GNUNET_P2P_PROTO_HELLO))
    return GNUNET_SYSERR;       /* obviously invalid */

  choice = "AUTO";
  GNUNET_GC_get_configuration_value_choice (coreAPI->cfg,
                                            "NAT", "LIMITED",
                                            nat_limited_choices,
                                            "AUTO", &choice);
  if (((0 == strcmp (choice, "YES")) ||
       ((0 == strcmp (choice, "AUTO")) &&
        (lan_ip_detected ()))) &&
      (0 != memcmp (&coreAPI->myIdentity->hashPubKey,
                    &hello->senderIdentity.hashPubKey,
                    sizeof (GNUNET_HashCode))))
    {
      /* if WE are a NAT and this is not our hello,
         it is invalid since NAT-to-NAT is not possible! */
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * Create a hello-Message for the current node. The hello is created
 * without signature and without a timestamp. The GNUnet core will
 * GNUNET_RSA_sign the message and add an expiration time.
 *
 * @return hello on success, NULL on error
 */
static GNUNET_MessageHello *
createhello ()
{
  const char *choice;
  GNUNET_MessageHello *msg;

  choice = "AUTO";
  GNUNET_GC_get_configuration_value_choice (coreAPI->cfg,
                                            "NAT", "LIMITED",
                                            nat_limited_choices,
                                            "AUTO", &choice);
  if (((0 == strcmp (choice, "NO")) ||
       ((0 == strcmp (choice, "AUTO")) && (!lan_ip_detected ()))))
    return NULL;
  msg = GNUNET_malloc (sizeof (GNUNET_MessageHello));
  msg->senderAddressSize = htons (0);
  msg->protocol = htons (GNUNET_TRANSPORT_PROTOCOL_NUMBER_NAT);
  msg->MTU = htonl (0);
  return msg;
}

/**
 * Establish a connection to a remote node.
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @return always fails (returns GNUNET_SYSERR)
 */
static int
natConnect (const GNUNET_MessageHello * hello, GNUNET_TSession ** tsessionPtr,
            int may_reuse)
{
  return GNUNET_SYSERR;
}

/**
 * A (core) Session is to be associated with a transport session. The
 * transport service may want to know in order to call back on the
 * core if the connection is being closed.
 *
 * @param tsession the session handle passed along
 *   from the call to receive that was made by the transport
 *   layer
 * @return GNUNET_OK if the session could be associated,
 *         GNUNET_SYSERR if not.
 */
int
natAssociate (GNUNET_TSession * tsession)
{
  return GNUNET_SYSERR;         /* NAT connections can never be associated */
}

/**
 * Send a message to the specified remote node.
 *
 * @param tsession the GNUNET_MessageHello identifying the remote node
 * @param message what to send
 * @param size the size of the message
 * @return GNUNET_SYSERR (always fails)
 */
static int
natSend (GNUNET_TSession * tsession,
         const void *message, const unsigned int size, int important)
{
  return GNUNET_SYSERR;
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return always GNUNET_SYSERR
 */
static int
natDisconnect (GNUNET_TSession * tsession)
{
  return GNUNET_SYSERR;
}

/**
 * Start the server process to receive inbound traffic.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
startTransportServer ()
{
  return GNUNET_OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int
stopTransportServer ()
{
  return GNUNET_OK;
}

/**
 * Convert NAT address to a string.
 */
static int
helloToAddress (const GNUNET_MessageHello * hello,
                void **sa, unsigned int *sa_len)
{
  return GNUNET_IP_get_address_from_peer_identity (&hello->senderIdentity, sa,
                                                   sa_len);
}

static int
testWouldTry (GNUNET_TSession * tsession, unsigned int size, int important)
{
  return GNUNET_SYSERR;
}

/**
 * The exported method. Makes the core api available via a global and
 * returns the nat transport API.
 */
GNUNET_TransportAPI *
inittransport_nat (GNUNET_CoreAPIForTransport * core)
{
  coreAPI = core;
  natAPI.protocolNumber = GNUNET_TRANSPORT_PROTOCOL_NUMBER_NAT;
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
