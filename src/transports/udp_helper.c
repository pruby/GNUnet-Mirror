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
 * @file transports/udp_helper.c
 * @brief common code for UDP transports
 * @author Christian Grothoff
 */

typedef int (*BlacklistedTester) (const void *addr, unsigned int addr_len);

/**
 * Message-Packet header.
 */
typedef struct
{
  /**
   * size of the message, in bytes, including this header.
   */
  GNUNET_MessageHeader header;

  /**
   * What is the identity of the sender (GNUNET_hash of public key)
   */
  GNUNET_PeerIdentity sender;

} UDPMessage;

/* *********** globals ************* */

static GNUNET_CoreAPIForTransport *coreAPI;

static GNUNET_TransportAPI udpAPI;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

static int stat_udpConnected;

static struct GNUNET_GE_Context *ectx;

/**
 * thread that listens for inbound messages
 */
static struct GNUNET_SelectHandle *selector;

/**
 * the socket that we transmit all data with
 */
static struct GNUNET_SocketHandle *udp_sock;

/**
 * The socket of session has data waiting, process!
 *
 * This function may only be called if the tcplock is
 * already held by the caller.
 */
static int
select_message_handler (void *mh_cls,
                        struct GNUNET_SelectHandle *sh,
                        struct GNUNET_SocketHandle *sock,
                        void *sock_ctx, const GNUNET_MessageHeader * msg)
{
  unsigned int len;
  GNUNET_TransportPacket *mp;
  const UDPMessage *um;

  len = ntohs (msg->size);
  if (len <= sizeof (UDPMessage))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("Received malformed message from udp-peer connection. Closing.\n"));
      return GNUNET_SYSERR;
    }
#if DEBUG_UDP
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_BULK,
                 "Received %d bytes via UDP\n", len);
#endif
  um = (const UDPMessage *) msg;
  mp = GNUNET_malloc (sizeof (GNUNET_TransportPacket));
  mp->msg = GNUNET_malloc (len - sizeof (UDPMessage));
  memcpy (mp->msg, &um[1], len - sizeof (UDPMessage));
  mp->sender = um->sender;
  mp->size = len - sizeof (UDPMessage);
  mp->tsession = NULL;
  coreAPI->receive (mp);
  if (stats != NULL)
    stats->change (stat_bytesReceived, len);
  return GNUNET_OK;
}

static void *
select_accept_handler (void *ah_cls,
                       struct GNUNET_SelectHandle *sh,
                       struct GNUNET_SocketHandle *sock,
                       const void *addr, unsigned int addr_len)
{
  static int nonnullpointer;
  BlacklistedTester blt = ah_cls;
  if (GNUNET_NO != blt (addr, addr_len))
    return NULL;
  return &nonnullpointer;
}

/**
 * Select has been forced to close a connection.
 * Free the associated context.
 */
static void
select_close_handler (void *ch_cls,
                      struct GNUNET_SelectHandle *sh,
                      struct GNUNET_SocketHandle *sock, void *sock_ctx)
{
  /* do nothing */
}

/**
 * Establish a connection to a remote node.
 *
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
udpConnect (const GNUNET_MessageHello * hello, GNUNET_TSession ** tsessionPtr,
            int may_reuse)
{
  GNUNET_TSession *tsession;

  tsession = GNUNET_malloc (sizeof (GNUNET_TSession));
  memset (tsession, 0, sizeof (GNUNET_TSession));
  tsession->internal = GNUNET_malloc (GNUNET_sizeof_hello (hello));
  memcpy (tsession->internal, hello, GNUNET_sizeof_hello (hello));
  tsession->ttype = udpAPI.protocolNumber;
  tsession->peer = hello->senderIdentity;
  *tsessionPtr = tsession;
  if (stats != NULL)
    stats->change (stat_udpConnected, 1);
  return GNUNET_OK;
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
udpAssociate (GNUNET_TSession * tsession)
{
  return GNUNET_SYSERR;         /* UDP connections can never be associated */
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static int
udpDisconnect (GNUNET_TSession * tsession)
{
  if (tsession != NULL)
    {
      if (tsession->internal != NULL)
        GNUNET_free (tsession->internal);
      GNUNET_free (tsession);
      if (stats != NULL)
        stats->change (stat_udpConnected, -1);
    }
  return GNUNET_OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int
stopTransportServer ()
{
  GNUNET_GE_ASSERT (ectx, udp_sock != NULL);
  if (selector != NULL)
    {
      GNUNET_select_destroy (selector);
      selector = NULL;
    }
  GNUNET_socket_destroy (udp_sock);
  udp_sock = NULL;
  return GNUNET_OK;
}

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
static int
testWouldTry (GNUNET_TSession * tsession, unsigned int size, int important)
{
  const GNUNET_MessageHello *hello;

  if (udp_sock == NULL)
    return GNUNET_SYSERR;
  if (size == 0)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (size > udpAPI.mtu)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  hello = (const GNUNET_MessageHello *) tsession->internal;
  if (hello == NULL)
    return GNUNET_SYSERR;
  return GNUNET_YES;
}


/* end of udp_helper.c */
