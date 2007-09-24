/*
     This file is part of GNUnet.
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
 * @file session/connect.c
 * @brief module responsible for the sessionkey exchange
 *   which establishes a session with another peer
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_pingpong_service.h"
#include "gnunet_session_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_topology_service.h"

#define hello_HELPER_TABLE_START_SIZE 64

#define DEBUG_SESSION NO

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS

static CoreAPIForApplication *coreAPI;

static Identity_ServiceAPI *identity;

static Transport_ServiceAPI *transport;

static Pingpong_ServiceAPI *pingpong;

static Topology_ServiceAPI *topology;

static Stats_ServiceAPI *stats;

static struct GE_Context *ectx;

static int stat_skeySent;

static int stat_skeyRejected;

static int stat_skeyAccepted;

static int stat_sessionEstablished;

static int stat_pongSent;

static int stat_pingSent;

/**
 * @brief message for session key exchange.
 */
typedef struct
{
  MESSAGE_HEADER header;
  /**
   * time when this key was created  (network byte order)
   * Must be the first field after the header since
   * the signature starts at this offset.
   */
  TIME_T creationTime;

  /**
   * The encrypted session key.  May ALSO contain
   * encrypted PINGs and PONGs.
   */
  RSAEncryptedData key;

  /**
   * Signature of the stuff above.
   */
  Signature signature;

} P2P_setkey_MESSAGE;

/**
 * @brief message for session key exchange.
 */
typedef struct
{
  MESSAGE_HEADER header;
  /**
   * time when this key was created  (network byte order)
   * Must be the first field after the header since
   * the signature starts at this offset.
   */
  TIME_T creationTime;

  /**
   * The encrypted session key.  May ALSO contain
   * encrypted PINGs and PONGs.
   */
  RSAEncryptedData key;

  /**
   * Who is the intended recipient?
   */
  PeerIdentity target;

  /**
   * Signature of the stuff above.
   */
  Signature signature;

} P2P_new_setkey_MESSAGE;


#if DEBUG_SESSION
/**
 * Not thread-safe, only use for debugging!
 */
static const char *
printSKEY (const SESSIONKEY * sk)
{
  static char r[512];
  static char t[12];
  int i;

  strcpy (r, "");
  for (i = 0; i < SESSIONKEY_LEN; i++)
    {
      SNPRINTF (t, 12, "%02x", sk->key[i]);
      strcat (r, t);
    }
  return r;
}
#endif

/**
 * We received a sign of life from this host.
 *
 * @param hostId the peer that gave a sign of live
 */
static void
notifyPONG (void *arg)
{
  PeerIdentity *hostId = arg;
#if DEBUG_SESSION
  EncName enc;
#endif

  GE_ASSERT (ectx, hostId != NULL);
#if DEBUG_SESSION
  IF_GELOG (ectx,
            GE_DEBUG | GE_USER | GE_REQUEST,
            hash2enc (&hostId->hashPubKey, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_USER | GE_REQUEST,
          "Received `%s' from `%s', marking session as up.\n", "PONG", &enc);
#endif
  GE_ASSERT (ectx, hostId != NULL);
  if (stats != NULL)
    stats->change (stat_sessionEstablished, 1);
  coreAPI->confirmSessionUp (hostId);
  FREE (hostId);
}


/**
 * Check if the received session key is properly signed
 * and if connections to this peer are allowed according
 * to policy.
 *
 * @param hostId the sender of the key
 * @param sks the session key message
 * @return SYSERR if invalid, OK if valid, NO if
 *  connections are disallowed
 */
static int
verifySKS (const PeerIdentity * hostId,
           const P2P_setkey_MESSAGE * sks, const Signature * signature)
{
  char *limited;
  EncName enc;
  unsigned int rsize;

  if ((sks == NULL) || (hostId == NULL))
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  /* check if we are allowed to accept connections
     from that peer */
  limited = NULL;
  GC_get_configuration_value_string (coreAPI->cfg,
                                     "GNUNETD", "LIMIT-ALLOW", "", &limited);
  if (strlen (limited) > 0)
    {
      hash2enc (&hostId->hashPubKey, &enc);
      if (NULL == strstr (limited, (char *) &enc))
        {
#if DEBUG_SESSION
          GE_LOG (ectx,
                  GE_DEBUG | GE_USER | GE_REQUEST,
                  "Connection from peer `%s' was rejected (not allowed).\n",
                  &enc);
#endif
          FREE (limited);
          return NO;
        }
    }
  FREE (limited);
  limited = NULL;
  GC_get_configuration_value_string (coreAPI->cfg,
                                     "GNUNETD", "LIMIT-DENY", "", &limited);
  if (strlen (limited) > 0)
    {
      hash2enc (&hostId->hashPubKey, &enc);
      if (NULL != strstr (limited, (char *) &enc))
        {
#if DEBUG_SESSION
          GE_LOG (ectx,
                  GE_DEBUG | GE_USER | GE_REQUEST,
                  "Connection from peer `%s' was rejected (explicitly denied).\n",
                  &enc);
#endif
          FREE (limited);
          return NO;
        }
    }
  FREE (limited);

  rsize = ntohs (sks->header.size);
  while (rsize > sizeof (P2P_new_setkey_MESSAGE))
    rsize -= pingpong->ping_size;
  if (rsize < sizeof (P2P_setkey_MESSAGE))
    {
      EncName enc;

      GE_BREAK_OP (ectx, 0);
      IF_GELOG (ectx,
                GE_INFO | GE_USER | GE_REQUEST,
                hash2enc (&hostId->hashPubKey, &enc));
      GE_LOG (ectx,
              GE_INFO | GE_USER | GE_REQUEST,
              _("Session key from peer `%s' could not be verified.\n"), &enc);
      return SYSERR;
    }
  if (OK != identity->verifyPeerSignature (hostId,
                                           sks,
                                           rsize - sizeof (Signature),
                                           signature))
    {
#if DEBUG_SESSION
      EncName enc;

      IF_GELOG (ectx,
                GE_INFO | GE_USER | GE_REQUEST,
                hash2enc (&hostId->hashPubKey, &enc));
      GE_LOG (ectx,
              GE_INFO | GE_USER | GE_REQUEST,
              _("Session key from peer `%s' could not be verified.\n"), &enc);
#endif
      return SYSERR;            /*reject! */
    }
  return OK;                    /* ok */
}

/**
 * Force creation of a new Session key for the given host.
 *
 * @param hostId the identity of the other host
 * @param sk the SESSIONKEY to use
 * @param created the timestamp to use
 * @param ping optional PING to include (otherwise NULL)
 * @param pong optional PONG to include (otherwise NULL)
 * @param ret the address where to write the signed
 *        session key message
 * @return message on success, NULL on failure
 */
static P2P_new_setkey_MESSAGE *
makeSessionKeySigned (const PeerIdentity * hostId,
                      const SESSIONKEY * sk,
                      TIME_T created,
                      const MESSAGE_HEADER * ping,
                      const MESSAGE_HEADER * pong)
{
  P2P_hello_MESSAGE *foreignHello;
  int size;
  P2P_new_setkey_MESSAGE *msg;
  char *pt;
  EncName enc;
  PeerIdentity hc;

  GE_ASSERT (ectx, sk != NULL);
  foreignHello = identity->identity2Hello (hostId, ANY_PROTOCOL_NUMBER, YES);
  /* create and encrypt sessionkey */
  if (NULL == foreignHello)
    {
      hash2enc (&hostId->hashPubKey, &enc);
      GE_LOG (ectx,
              GE_INFO | GE_USER | GE_REQUEST,
              _("Cannot encrypt sessionkey, peer `%s' not known!\n"), &enc);
      return NULL;              /* other host not known */
    }
  identity->getPeerIdentity (&foreignHello->publicKey, &hc);
  if ((0 != memcmp (&hc,
                    hostId,
                    sizeof (PeerIdentity))) ||
      (0 != memcmp (&hc,
                    &foreignHello->senderIdentity, sizeof (PeerIdentity))))
    {
      GE_BREAK_OP (NULL,
                   0 == memcmp (&hc,
                                &foreignHello->senderIdentity,
                                sizeof (PeerIdentity)));
      GE_BREAK_OP (NULL, 0 == memcmp (&hc, hostId, sizeof (PeerIdentity)));
      GE_BREAK_OP (NULL, 0);
      FREE (foreignHello);
      return NULL;
    }


  size = sizeof (P2P_new_setkey_MESSAGE);
  if (ping != NULL)
    size += ntohs (ping->size);
  if (pong != NULL)
    size += ntohs (pong->size);
  msg = MALLOC (size);
  msg->target = *hostId;
  if (SYSERR == encryptPrivateKey (sk,
                                   sizeof (SESSIONKEY),
                                   &foreignHello->publicKey, &msg->key))
    {
      GE_BREAK_OP (ectx, 0);
      FREE (foreignHello);
      FREE (msg);
      return NULL;              /* encrypt failed */
    }
  FREE (foreignHello);

  /* complete header */
  msg->header.size = htons (size);
  msg->header.type = htons (P2P_PROTO_setkey);
  msg->creationTime = htonl (created);
  GE_ASSERT (ectx,
             SYSERR !=
             identity->signData (msg,
                                 sizeof (P2P_new_setkey_MESSAGE)
                                 - sizeof (Signature), &msg->signature));
#if EXTRA_CHECKS
  /* verify signature/SKS */
  GE_ASSERT (ectx,
             SYSERR != verifySKS (coreAPI->myIdentity,
                                  (const P2P_setkey_MESSAGE *) msg,
                                  &msg->signature));
#endif

  size = 0;
  if (ping != NULL)
    size += ntohs (ping->size);
  if (pong != NULL)
    size += ntohs (pong->size);
  if (size > 0)
    {
      pt = MALLOC (size);
      size = 0;
      if (ping != NULL)
        {
          memcpy (&pt[size], ping, ntohs (ping->size));
          size += ntohs (ping->size);
        }
      if (pong != NULL)
        {
          memcpy (&pt[size], pong, ntohs (pong->size));
          size += ntohs (pong->size);
        }
#if DEBUG_SESSION
      GE_LOG (ectx,
              GE_DEBUG | GE_USER | GE_REQUEST,
              "Encrypting %d bytes of PINGPONG with key %s and IV %u\n",
              size, printSKEY (sk), *(int *) &msg->signature);
#endif
      GE_ASSERT (ectx,
                 -1 != encryptBlock (pt,
                                     size,
                                     sk,
                                     (const INITVECTOR *) &msg->signature,
                                     (char *) &msg[1]));
      FREE (pt);
    }
  return msg;
}

/**
 * Perform a session key exchange.  First sends a hello
 * and then the new SKEY (in two plaintext packets). When called, the
 * semaphore of at the given index must already be down
 *
 * @param receiver peer to exchange a key with
 * @param tsession session to use for the exchange (maybe NULL)
 * @param pong pong to include (maybe NULL)
 */
static int
exchangeKey (const PeerIdentity * receiver,
             TSession * tsession, MESSAGE_HEADER * pong)
{
  P2P_hello_MESSAGE *hello;
  P2P_new_setkey_MESSAGE *skey;
  SESSIONKEY sk;
  TIME_T age;
  MESSAGE_HEADER *ping;
  PeerIdentity *sndr;
  EncName enc;

  GE_ASSERT (ectx, receiver != NULL);
  if ((tsession != NULL) &&
      (0 != memcmp (&tsession->peer, receiver, sizeof (PeerIdentity))))
    {
      GE_BREAK (ectx, 0);
      tsession = NULL;
    }
  if ((topology != NULL) &&
      (topology->allowConnectionFrom (receiver) == SYSERR))
    return SYSERR;
  hash2enc (&receiver->hashPubKey, &enc);
  /* then try to connect on the transport level */
  if ((tsession == NULL)
      || (transport->associate (tsession, __FILE__) == SYSERR))
    tsession = transport->connectFreely (receiver, YES, __FILE__);
  if (tsession == NULL)
    {
#if DEBUG_SESSION
      GE_LOG (ectx,
              GE_DEBUG | GE_USER | GE_REQUEST,
              "Key exchange with `%s' failed: could not connect.\n", &enc);
#endif
      return SYSERR;            /* failed to connect */
    }

  /* create our ping */
  sndr = MALLOC (sizeof (PeerIdentity));
  *sndr = *receiver;
  ping = pingpong->pingUser (receiver, &notifyPONG, sndr, NO, rand ());
  if (ping == NULL)
    {
      FREE (sndr);
      transport->disconnect (tsession, __FILE__);
      return SYSERR;
    }

  /* get or create our session key */
  if (OK != coreAPI->getCurrentSessionKey (receiver, &sk, &age, YES))
    {
      age = TIME (NULL);
      makeSessionkey (&sk);
#if DEBUG_SESSION
      GE_LOG (ectx,
              GE_DEBUG | GE_USER | GE_REQUEST,
              "Created fresh sessionkey `%s' for peer `%s'.\n",
              printSKEY (&sk), &enc);
#endif
    }

  /* build SKEY message */
  skey = makeSessionKeySigned (receiver, &sk, age, ping, pong);
  FREE (ping);
  if (skey == NULL)
    {
      transport->disconnect (tsession, __FILE__);
      return SYSERR;
    }

  /* create hello */
  hello = transport->createhello (tsession->ttype);
  if (NULL == hello)
    hello = transport->createhello (ANY_PROTOCOL_NUMBER);
  if (NULL == hello)
    {
      GE_LOG (ectx,
              GE_ERROR | GE_USER | GE_IMMEDIATE,
              _("Could not create any HELLO for myself!\n"));
    }
#if DEBUG_SESSION
  GE_LOG (ectx,
          GE_DEBUG | GE_USER | GE_REQUEST,
          "Sending session key  to peer `%s'.\n", &enc);
#endif
  if (stats != NULL)
    {
      stats->change (stat_pingSent, 1);
      stats->change (stat_skeySent, 1);
      /* pong, if present, is accounted for
         by caller */
    }
  if (hello != NULL)
    {
      coreAPI->sendPlaintext (tsession,
                              (const char *) hello,
                              P2P_hello_MESSAGE_size (hello));
      FREE (hello);
      hello = NULL;
      coreAPI->sendPlaintext (tsession,
                              (const char *) skey, ntohs (skey->header.size));
    }
  FREE (skey);
  if (0 != memcmp (receiver, &tsession->peer, sizeof (PeerIdentity)))
    {
      GE_BREAK (NULL, 0);
    }
  else
    {
      coreAPI->offerTSessionFor (receiver, tsession);
    }
  transport->disconnect (tsession, __FILE__);
  coreAPI->assignSessionKey (&sk, receiver, age, YES);
  return OK;
}

/**
 * Accept a session-key that has been sent by another host.
 * The other host must be known (public key).  Notifies
 * the core about the new session key and possibly
 * triggers sending a session key ourselves (if not
 * already done).
 *
 * @param sender the identity of the sender host
 * @param tsession the transport session handle
 * @param msg message with the session key
 * @return SYSERR or OK
 */
static int
acceptSessionKey (const PeerIdentity * sender,
                  const MESSAGE_HEADER * msg, TSession * tsession)
{
  SESSIONKEY key;
  MESSAGE_HEADER *ping;
  MESSAGE_HEADER *pong;
  const P2P_setkey_MESSAGE *sessionkeySigned;
  int size;
  int pos;
  char *plaintext;
  EncName enc;
  int ret;
  const Signature *sig;
  const P2P_new_setkey_MESSAGE *newMsg;
  const void *end;

  if (sender == NULL)
    {
      GE_BREAK (NULL, 0);
      return SYSERR;
    }
  hash2enc (&sender->hashPubKey, &enc);
  if ((topology != NULL) &&
      (topology->allowConnectionFrom (sender) == SYSERR))
    {
#if DEBUG_SESSION
      GE_LOG (ectx,
              GE_DEBUG | GE_USER | GE_REQUEST,
              "Topology rejected session key from peer `%s'.\n", &enc);
#endif
      return SYSERR;
    }
  if (equalsHashCode512 (&sender->hashPubKey,
                         &coreAPI->myIdentity->hashPubKey))
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
#if DEBUG_SESSION
  GE_LOG (ectx,
          GE_DEBUG | GE_USER | GE_REQUEST,
          "Received session key from peer `%s'.\n", &enc);
#endif

  if (ntohs (msg->size) < sizeof (P2P_setkey_MESSAGE))
    {
      GE_LOG (ectx,
              GE_WARNING | GE_DEVELOPER | GE_USER | GE_BULK,
              _
              ("Session key received from peer `%s' has invalid format (discarded).\n"),
              &enc);
      return SYSERR;
    }
  if ((OK != coreAPI->getCurrentSessionKey (sender,
                                            NULL,
                                            NULL,
                                            YES)) &&
      ((YES == identity->isBlacklisted (sender, NO)) ||
       ((coreAPI->forAllConnectedNodes (NULL, NULL) >= 3) &&
        (os_cpu_get_load (ectx, coreAPI->cfg) > IDLE_LOAD_THRESHOLD))))
    return SYSERR;              /* other peer initiated but is
                                   listed as not allowed => discard */

  sessionkeySigned = (const P2P_setkey_MESSAGE *) msg;

  if ((ntohs (msg->size) == sizeof (P2P_new_setkey_MESSAGE)) ||
      (ntohs (msg->size) ==
       sizeof (P2P_new_setkey_MESSAGE) + pingpong->ping_size)
      || (ntohs (msg->size) ==
          sizeof (P2P_new_setkey_MESSAGE) + pingpong->ping_size * 2))
    {
      newMsg = (const P2P_new_setkey_MESSAGE *) msg;

      if (!equalsHashCode512 (&coreAPI->myIdentity->hashPubKey,
                              &newMsg->target.hashPubKey))
        {
          EncName ta;
          hash2enc (&newMsg->target.hashPubKey, &ta);
          GE_LOG (ectx,
                  GE_WARNING | GE_DEVELOPER | GE_USER | GE_BULK,
                  _
                  ("Session key received from peer `%s' is for `%s' and not for me!\n"),
                  &enc, &ta);
          return SYSERR;        /* not for us! */
        }
      sig = &newMsg->signature;
    }
  else
    {
      sig = &sessionkeySigned->signature;
      newMsg = NULL;
    }
  ret = verifySKS (sender, sessionkeySigned, sig);
  if (OK != ret)
    {
#if DEBUG_SESSION
      if (ret == SYSERR)
        GE_LOG (ectx,
                GE_INFO | GE_USER | GE_REQUEST | GE_DEVELOPER,
                "Signature of session key from `%s' failed"
                " verification (discarded).\n", &enc);
#endif
      if (stats != NULL)
        stats->change (stat_skeyRejected, 1);
      return SYSERR;            /* rejected */
    }
  memset (&key, 0, sizeof (SESSIONKEY));
  size = identity->decryptData (&sessionkeySigned->key,
                                &key, sizeof (SESSIONKEY));
  if (size != sizeof (SESSIONKEY))
    {
      GE_LOG (ectx,
              GE_WARNING | GE_DEVELOPER | GE_USER | GE_BULK,
              _("Invalid `%s' message received from peer `%s'.\n"),
              "setkey", &enc);
      return SYSERR;
    }
  if (key.crc32 != htonl (crc32N (&key, SESSIONKEY_LEN)))
    {
#if DEBUG_SESSION
      GE_LOG (ectx,
              GE_WARNING | GE_DEVELOPER | GE_USER | GE_BULK,
              _
              ("setkey `%s' from `%s' fails CRC check (have: %u, want %u).\n"),
              printSKEY (&key), &enc, ntohl (key.crc32), crc32N (&key,
                                                                 SESSIONKEY_LEN));
#endif
      GE_BREAK_OP (ectx, 0);
      stats->change (stat_skeyRejected, 1);
      return SYSERR;
    }

#if DEBUG_SESSION
  GE_LOG (ectx,
          GE_DEBUG | GE_USER | GE_REQUEST,
          "Received setkey message from `%s' with %u bytes of data and key `%s'.\n",
          &enc, ntohs (sessionkeySigned->header.size), printSKEY (&key));
#endif
  if (stats != NULL)
    stats->change (stat_skeyAccepted, 1);
  /* notify core about session key */
  coreAPI->assignSessionKey (&key,
                             sender,
                             ntohl (sessionkeySigned->creationTime), NO);
  pos = sizeof (P2P_setkey_MESSAGE);
  ping = NULL;
  pong = NULL;
  plaintext = NULL;
  size = ntohs (sessionkeySigned->header.size);
  if (((newMsg == NULL) &&
       (sizeof (P2P_setkey_MESSAGE) < size)) ||
      ((newMsg != NULL) && (sizeof (P2P_new_setkey_MESSAGE) < size)))
    {
      if (newMsg == NULL)
        {
          size -= sizeof (P2P_setkey_MESSAGE);
          end = &sessionkeySigned[1];
        }
      else
        {
          size -= sizeof (P2P_new_setkey_MESSAGE);
          end = &newMsg[1];
        }
      plaintext = MALLOC (size);
#if DEBUG_SESSION
      GE_LOG (ectx,
              GE_DEBUG | GE_USER | GE_REQUEST,
              "Decrypting %d bytes of PINGPONG from `%s' with key `%s' and IV %u\n",
              size, &enc, printSKEY (&key), *(int *) sig);
#endif
      GE_ASSERT (ectx,
                 -1 != decryptBlock (&key,
                                     end,
                                     size,
                                     (const INITVECTOR *) sig, plaintext));
      pos = 0;
      /* find pings & pongs! */
      while (pos + sizeof (MESSAGE_HEADER) < size)
        {
          MESSAGE_HEADER *hdr;

          hdr = (MESSAGE_HEADER *) & plaintext[pos];
          if (htons (hdr->size) + pos > size)
            {
              GE_LOG (ectx,
                      GE_WARNING | GE_DEVELOPER | GE_USER | GE_BULK,
                      _("Error parsing encrypted session key from `%s', "
                        "given message part size is invalid.\n"), &enc);
              break;
            }
          if (htons (hdr->type) == p2p_PROTO_PING)
            ping = hdr;
          else if (htons (hdr->type) == p2p_PROTO_PONG)
            pong = hdr;
          else
            GE_LOG (ectx,
                    GE_WARNING | GE_DEVELOPER | GE_USER | GE_BULK,
                    _
                    ("Unknown type in embedded message from `%s': %u (size: %u)\n"),
                    &enc, htons (hdr->type), htons (hdr->size));
          pos += ntohs (hdr->size);
        }
    }
  if (pong != NULL)
    {
      /* we initiated, this is the response */
      /* notify ourselves about encapsulated pong */
#if DEBUG_SESSION
      GE_LOG (ectx,
              GE_DEBUG | GE_USER | GE_REQUEST,
              "Received PONG in session key from `%s', injecting!\n", &enc);
#endif
      coreAPI->injectMessage (sender,
                              (char *) pong,
                              ntohs (pong->size), YES, tsession);
      if (ping != NULL)
        {                       /* should always be true for well-behaved peers */
          /* pong can go out over ordinary channels */
#if DEBUG_SESSION
          GE_LOG (ectx,
                  GE_DEBUG | GE_USER | GE_REQUEST,
                  "Received PING in session key from `%s', "
                  "sending PONG over normal encrypted session!\n", &enc);
#endif
          ping->type = htons (p2p_PROTO_PONG);
          if (stats != NULL)
            stats->change (stat_pongSent, 1);
          coreAPI->unicast (sender, ping, EXTREME_PRIORITY, 0);
        }
    }
  else
    {
      if (ping != NULL)
        {
#if DEBUG_SESSION
          GE_LOG (ectx,
                  GE_DEBUG | GE_USER | GE_REQUEST,
                  "Received ping in session key from `%s', "
                  "sending pong together with my session key!\n", &enc);
#endif
          ping->type = htons (p2p_PROTO_PONG);
          if (stats != NULL)
            stats->change (stat_pongSent, 1);
          exchangeKey (sender, tsession, ping); /* ping is now pong */
        }
      else
        {
          GE_BREAK_OP (ectx, 0);
          /* PING not included in SKEY - bug (in other peer!?) */
        }
    }
  FREENONNULL (plaintext);
  return OK;
}

/**
 * Try to connect to the given peer.
 *
 * @return SYSERR if that is impossible,
 *         YES if a connection is established upon return,
 *         NO if we're going to try to establish one asynchronously
 */
static int
tryConnect (const PeerIdentity * peer)
{
#if DEBUG_SESSION
  EncName enc;

  IF_GELOG (ectx,
            GE_DEBUG | GE_USER | GE_REQUEST,
            hash2enc (&peer->hashPubKey, &enc));
#endif
  if ((topology != NULL) && (topology->allowConnectionFrom (peer) == SYSERR))
    {
#if DEBUG_SESSION
      GE_LOG (ectx,
              GE_DEBUG | GE_USER | GE_REQUEST,
              "Topology rejected connecting to `%s'.\n", &enc);
#endif
      return SYSERR;
    }
  if (coreAPI->queryPeerStatus (peer, NULL, NULL) == OK)
    {
#if DEBUG_SESSION
      GE_LOG (ectx,
              GE_DEBUG | GE_USER | GE_REQUEST,
              "Connection to `%s' already up\n", &enc);
#endif
      return YES;               /* trivial case */
    }
#if DEBUG_SESSION
  GE_LOG (ectx,
          GE_DEBUG | GE_USER | GE_REQUEST,
          "Trying to exchange key with `%s'.\n", &enc);
#endif
  if (YES == identity->isBlacklisted (peer, NO))
    return NO;                  /* not allowed right now! */
  if (OK == exchangeKey (peer, NULL, NULL))
    return NO;
  return SYSERR;
}

/**
 * We have received an (encrypted) setkey message.
 * The reaction is to update our key to the new
 * value.  (Rekeying).
 */
static int
acceptSessionKeyUpdate (const PeerIdentity * sender,
                        const MESSAGE_HEADER * msg)
{
  acceptSessionKey (sender, msg, NULL);
  return OK;
}


/**
 * Initialize the module.
 */
Session_ServiceAPI *
provide_module_session (CoreAPIForApplication * capi)
{
  static Session_ServiceAPI ret;

  ectx = capi->ectx;
  GE_ASSERT (ectx, sizeof (P2P_setkey_MESSAGE) == 520);
  coreAPI = capi;
  identity = capi->requestService ("identity");
  if (identity == NULL)
    {
      GE_BREAK (ectx, 0);
      return NULL;
    }
  transport = capi->requestService ("transport");
  if (transport == NULL)
    {
      GE_BREAK (ectx, 0);
      coreAPI->releaseService (identity);
      identity = NULL;
      return NULL;
    }
  pingpong = capi->requestService ("pingpong");
  if (pingpong == NULL)
    {
      GE_BREAK (ectx, 0);
      coreAPI->releaseService (transport);
      transport = NULL;
      coreAPI->releaseService (identity);
      identity = NULL;
      return NULL;
    }
  topology = capi->requestService ("topology");
  stats = capi->requestService ("stats");
  if (stats != NULL)
    {
      stat_skeySent = stats->create (gettext_noop ("# session keys sent"));
      stat_skeyRejected
        = stats->create (gettext_noop ("# session keys rejected"));
      stat_skeyAccepted
        = stats->create (gettext_noop ("# session keys accepted"));
      stat_sessionEstablished
        = stats->create (gettext_noop ("# sessions established"));
      stat_pingSent
        = stats->create (gettext_noop ("# encrypted PING messages sent"));
      stat_pongSent
        = stats->create (gettext_noop ("# encrypted PONG messages sent"));
    }

  GE_LOG (ectx,
          GE_INFO | GE_USER | GE_REQUEST,
          _("`%s' registering handler %d (plaintext and ciphertext)\n"),
          "session", P2P_PROTO_setkey);
  coreAPI->registerPlaintextHandler (P2P_PROTO_setkey, &acceptSessionKey);
  coreAPI->registerHandler (P2P_PROTO_setkey, &acceptSessionKeyUpdate);
  ret.tryConnect = &tryConnect;
  return &ret;
}

/**
 * Shutdown the module.
 */
int
release_module_session ()
{
  coreAPI->unregisterPlaintextHandler (P2P_PROTO_setkey, &acceptSessionKey);
  coreAPI->unregisterHandler (P2P_PROTO_setkey, &acceptSessionKeyUpdate);
  if (topology != NULL)
    {
      coreAPI->releaseService (topology);
      topology = NULL;
    }
  coreAPI->releaseService (stats);
  stats = NULL;
  coreAPI->releaseService (identity);
  identity = NULL;
  coreAPI->releaseService (transport);
  transport = NULL;
  coreAPI->releaseService (pingpong);
  pingpong = NULL;
  coreAPI = NULL;
  return OK;
}

/* end of connect.c */
