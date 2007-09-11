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
  MESSAGE_HEADER header;

  /**
   * What is the identity of the sender (hash of public key)
   */
  PeerIdentity sender;

} UDPMessage;

/* *********** globals ************* */

static CoreAPIForTransport *coreAPI;

static TransportAPI udpAPI;

static Stats_ServiceAPI *stats;

static int stat_bytesReceived;

static int stat_bytesSent;

static int stat_bytesDropped;

static int stat_udpConnected;

static struct GE_Context *ectx;

/**
 * thread that listens for inbound messages
 */
static struct SelectHandle *selector;

/**
 * the socket that we transmit all data with
 */
static struct SocketHandle *udp_sock;

/**
 * The socket of session has data waiting, process!
 *
 * This function may only be called if the tcplock is
 * already held by the caller.
 */
static int
select_message_handler (void *mh_cls,
                        struct SelectHandle *sh,
                        struct SocketHandle *sock,
                        void *sock_ctx, const MESSAGE_HEADER * msg)
{
  unsigned int len;
  P2P_PACKET *mp;
  const UDPMessage *um;

  len = ntohs (msg->size);
  if (len <= sizeof (UDPMessage))
    {
      GE_LOG (ectx,
              GE_WARNING | GE_USER | GE_BULK,
              _
              ("Received malformed message from udp-peer connection. Closing.\n"));
      return SYSERR;
    }
#if DEBUG_UDP
  GE_LOG (ectx,
          GE_DEBUG | GE_USER | GE_BULK, "Received %d bytes via UDP\n", len);
#endif
  um = (const UDPMessage *) msg;
  mp = MALLOC (sizeof (P2P_PACKET));
  mp->msg = MALLOC (len - sizeof (UDPMessage));
  memcpy (mp->msg, &um[1], len - sizeof (UDPMessage));
  mp->sender = um->sender;
  mp->size = len - sizeof (UDPMessage);
  mp->tsession = NULL;
  coreAPI->receive (mp);
  if (stats != NULL)
    stats->change (stat_bytesReceived, len);
  return OK;
}

static void *
select_accept_handler (void *ah_cls,
                       struct SelectHandle *sh,
                       struct SocketHandle *sock,
                       const void *addr, unsigned int addr_len)
{
  static int nonnullpointer;
  BlacklistedTester blt = ah_cls;
  if (NO != blt (addr, addr_len))
    return NULL;
  return &nonnullpointer;
}

/**
 * Select has been forced to close a connection.
 * Free the associated context.
 */
static void
select_close_handler (void *ch_cls,
                      struct SelectHandle *sh,
                      struct SocketHandle *sock, void *sock_ctx)
{
  /* do nothing */
}

/**
 * Establish a connection to a remote node.
 *
 * @param hello the hello-Message for the target node
 * @param tsessionPtr the session handle that is to be set
 * @return OK on success, SYSERR if the operation failed
 */
static int
udpConnect (const P2P_hello_MESSAGE * hello, TSession ** tsessionPtr,
            int may_reuse)
{
  TSession *tsession;

  tsession = MALLOC (sizeof (TSession));
  memset (tsession, 0, sizeof (TSession));
  tsession->internal = MALLOC (P2P_hello_MESSAGE_size (hello));
  memcpy (tsession->internal, hello, P2P_hello_MESSAGE_size (hello));
  tsession->ttype = udpAPI.protocolNumber;
  tsession->peer = hello->senderIdentity;
  *tsessionPtr = tsession;
  if (stats != NULL)
    stats->change (stat_udpConnected, 1);
  return OK;
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
udpAssociate (TSession * tsession)
{
  return SYSERR;                /* UDP connections can never be associated */
}

/**
 * Disconnect from a remote node.
 *
 * @param tsession the session that is closed
 * @return OK on success, SYSERR if the operation failed
 */
static int
udpDisconnect (TSession * tsession)
{
  if (tsession != NULL)
    {
      if (tsession->internal != NULL)
        FREE (tsession->internal);
      FREE (tsession);
      if (stats != NULL)
        stats->change (stat_udpConnected, -1);
    }
  return OK;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 */
static int
stopTransportServer ()
{
  GE_ASSERT (ectx, udp_sock != NULL);
  if (selector != NULL)
    {
      select_destroy (selector);
      selector = NULL;
    }
  socket_destroy (udp_sock);
  udp_sock = NULL;
  return OK;
}

/**
 * Test if the transport would even try to send
 * a message of the given size and importance
 * for the given session.<br>
 * This function is used to check if the core should
 * even bother to construct (and encrypt) this kind
 * of message.
 *
 * @return YES if the transport would try (i.e. queue
 *         the message or call the OS to send),
 *         NO if the transport would just drop the message,
 *         SYSERR if the size/session is invalid
 */
static int
testWouldTry (TSession * tsession, unsigned int size, int important)
{
  const P2P_hello_MESSAGE *hello;

  if (udp_sock == NULL)
    return SYSERR;
  if (size == 0)
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  if (size > udpAPI.mtu)
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  hello = (const P2P_hello_MESSAGE *) tsession->internal;
  if (hello == NULL)
    return SYSERR;
  return YES;
}


/* end of udp_helper.c */
