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

#define DEBUG_SESSION GNUNET_NO

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Identity_ServiceAPI *identity;

static GNUNET_Transport_ServiceAPI *transport;

static GNUNET_Pingpong_ServiceAPI *pingpong;

static GNUNET_Topology_ServiceAPI *topology;

static GNUNET_Stats_ServiceAPI *stats;

static struct GNUNET_GE_Context *ectx;

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
  GNUNET_MessageHeader header;
  /**
   * time when this key was created  (network byte order)
   * Must be the first field after the header since
   * the signature starts at this offset.
   */
  GNUNET_Int32Time creationTime;

  /**
   * The encrypted session key.  May ALSO contain
   * encrypted PINGs and PONGs.
   */
  GNUNET_RSA_EncryptedData key;

  /**
   * GNUNET_RSA_Signature of the stuff above.
   */
  GNUNET_RSA_Signature signature;

} P2P_setkey_MESSAGE;

/**
 * @brief message for session key exchange.
 */
typedef struct
{
  GNUNET_MessageHeader header;
  /**
   * time when this key was created  (network byte order)
   * Must be the first field after the header since
   * the signature starts at this offset.
   */
  GNUNET_Int32Time creationTime;

  /**
   * The encrypted session key.  May ALSO contain
   * encrypted PINGs and PONGs.
   */
  GNUNET_RSA_EncryptedData key;

  /**
   * Who is the intended recipient?
   */
  GNUNET_PeerIdentity target;

  /**
   * GNUNET_RSA_Signature of the stuff above.
   */
  GNUNET_RSA_Signature signature;

} P2P_new_setkey_MESSAGE;


#if DEBUG_SESSION
/**
 * Not thread-safe, only use for debugging!
 */
static const char *
printSKEY (const GNUNET_AES_SessionKey * sk)
{
  static char r[512];
  static char t[12];
  int i;

  strcpy (r, "");
  for (i = 0; i < GNUNET_SESSIONKEY_LEN; i++)
    {
      GNUNET_snprintf (t, 12, "%02x", sk->key[i]);
      strcat (r, t);
    }
  return r;
}
#endif

/**
 * We received a GNUNET_RSA_sign of life from this host.
 *
 * @param hostId the peer that gave a GNUNET_RSA_sign of live
 */
static void
notifyPONG (void *arg)
{
  GNUNET_PeerIdentity *hostId = arg;
#if DEBUG_SESSION
  GNUNET_EncName enc;
#endif

  GNUNET_GE_ASSERT (ectx, hostId != NULL);
#if DEBUG_SESSION
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
            GNUNET_hash_to_enc (&hostId->hashPubKey, &enc));
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 "Received `%s' from `%s', marking session as up.\n", "PONG",
                 &enc);
#endif
  GNUNET_GE_ASSERT (ectx, hostId != NULL);
  if (stats != NULL)
    stats->change (stat_sessionEstablished, 1);
  coreAPI->connection_mark_session_as_confirmed (hostId);
  GNUNET_free (hostId);
}


/**
 * Check if the received session key is properly signed
 * and if connections to this peer are allowed according
 * to policy.
 *
 * @param hostId the sender of the key
 * @param sks the session key message
 * @return GNUNET_SYSERR if invalid, GNUNET_OK if valid, GNUNET_NO if
 *  connections are disallowed
 */
static int
verifySKS (const GNUNET_PeerIdentity * hostId,
           const P2P_setkey_MESSAGE * sks,
           const GNUNET_RSA_Signature * signature)
{
  char *limited;
  GNUNET_EncName enc;
  unsigned int rsize;

  if ((sks == NULL) || (hostId == NULL))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  /* check if we are allowed to accept connections
     from that peer */
  limited = NULL;
  GNUNET_GC_get_configuration_value_string (coreAPI->cfg,
                                            "GNUNETD", "LIMIT-ALLOW", "",
                                            &limited);
  if (strlen (limited) > 0)
    {
      GNUNET_hash_to_enc (&hostId->hashPubKey, &enc);
      if (NULL == strstr (limited, (char *) &enc))
        {
#if DEBUG_SESSION
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                         "Connection from peer `%s' was rejected (not allowed).\n",
                         &enc);
#endif
          GNUNET_free (limited);
          return GNUNET_NO;
        }
    }
  GNUNET_free (limited);
  limited = NULL;
  GNUNET_GC_get_configuration_value_string (coreAPI->cfg,
                                            "GNUNETD", "LIMIT-DENY", "",
                                            &limited);
  if (strlen (limited) > 0)
    {
      GNUNET_hash_to_enc (&hostId->hashPubKey, &enc);
      if (NULL != strstr (limited, (char *) &enc))
        {
#if DEBUG_SESSION
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                         "Connection from peer `%s' was rejected (explicitly denied).\n",
                         &enc);
#endif
          GNUNET_free (limited);
          return GNUNET_NO;
        }
    }
  GNUNET_free (limited);

  rsize = ntohs (sks->header.size);
  while (rsize > sizeof (P2P_new_setkey_MESSAGE))
    rsize -= pingpong->ping_size;
  if (rsize < sizeof (P2P_setkey_MESSAGE))
    {
      GNUNET_EncName enc;

      GNUNET_GE_BREAK_OP (ectx, 0);
      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                GNUNET_hash_to_enc (&hostId->hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     _("Session key from peer `%s' could not be verified.\n"),
                     &enc);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK != identity->verifyPeerSignature (hostId,
                                                  sks,
                                                  rsize -
                                                  sizeof
                                                  (GNUNET_RSA_Signature),
                                                  signature))
    {
#if DEBUG_SESSION
      GNUNET_EncName enc;

      IF_GELOG (ectx,
                GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                GNUNET_hash_to_enc (&hostId->hashPubKey, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     _("Session key from peer `%s' could not be verified.\n"),
                     &enc);
#endif
      return GNUNET_SYSERR;     /*reject! */
    }
  return GNUNET_OK;             /* ok */
}

/**
 * Force creation of a new Session key for the given host.
 *
 * @param hostId the identity of the other host
 * @param sk the GNUNET_AES_SessionKey to use
 * @param created the timestamp to use
 * @param ping optional PING to include (otherwise NULL)
 * @param pong optional PONG to include (otherwise NULL)
 * @param ret the address where to write the signed
 *        session key message
 * @return message on success, NULL on failure
 */
static P2P_new_setkey_MESSAGE *
makeSessionKeySigned (const GNUNET_PeerIdentity * hostId,
                      const GNUNET_AES_SessionKey * sk,
                      GNUNET_Int32Time created,
                      const GNUNET_MessageHeader * ping,
                      const GNUNET_MessageHeader * pong)
{
  GNUNET_MessageHello *foreignHello;
  int size;
  P2P_new_setkey_MESSAGE *msg;
  char *pt;
  GNUNET_EncName enc;
  GNUNET_PeerIdentity hc;

  GNUNET_GE_ASSERT (ectx, sk != NULL);
  foreignHello =
    identity->identity2Hello (hostId, GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY,
                              GNUNET_YES);
  /* create and encrypt sessionkey */
  if (NULL == foreignHello)
    {
      GNUNET_hash_to_enc (&hostId->hashPubKey, &enc);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     _("Cannot encrypt sessionkey, peer `%s' not known!\n"),
                     &enc);
      return NULL;              /* other host not known */
    }
  identity->getPeerIdentity (&foreignHello->publicKey, &hc);
  if ((0 != memcmp (&hc,
                    hostId,
                    sizeof (GNUNET_PeerIdentity))) ||
      (0 != memcmp (&hc,
                    &foreignHello->senderIdentity,
                    sizeof (GNUNET_PeerIdentity))))
    {
      GNUNET_GE_BREAK_OP (NULL,
                          0 == memcmp (&hc,
                                       &foreignHello->senderIdentity,
                                       sizeof (GNUNET_PeerIdentity)));
      GNUNET_GE_BREAK_OP (NULL,
                          0 == memcmp (&hc, hostId,
                                       sizeof (GNUNET_PeerIdentity)));
      GNUNET_GE_BREAK_OP (NULL, 0);
      GNUNET_free (foreignHello);
      return NULL;
    }


  size = sizeof (P2P_new_setkey_MESSAGE);
  if (ping != NULL)
    size += ntohs (ping->size);
  if (pong != NULL)
    size += ntohs (pong->size);
  msg = GNUNET_malloc (size);
  msg->target = *hostId;
  if (GNUNET_SYSERR == GNUNET_RSA_encrypt (sk,
                                           sizeof (GNUNET_AES_SessionKey),
                                           &foreignHello->publicKey,
                                           &msg->key))
    {
      GNUNET_GE_BREAK_OP (ectx, 0);
      GNUNET_free (foreignHello);
      GNUNET_free (msg);
      return NULL;              /* encrypt failed */
    }
  GNUNET_free (foreignHello);

  /* complete header */
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_P2P_PROTO_SET_KEY);
  msg->creationTime = htonl (created);
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    identity->signData (msg,
                                        sizeof (P2P_new_setkey_MESSAGE)
                                        - sizeof (GNUNET_RSA_Signature),
                                        &msg->signature));
#if EXTRA_CHECKS
  /* verify signature/SKS */
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR != verifySKS (coreAPI->myIdentity,
                                                (const P2P_setkey_MESSAGE *)
                                                msg, &msg->signature));
#endif

  size = 0;
  if (ping != NULL)
    size += ntohs (ping->size);
  if (pong != NULL)
    size += ntohs (pong->size);
  if (size > 0)
    {
      pt = GNUNET_malloc (size);
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
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     "Encrypting %d bytes of PINGPONG with key %s and IV %u\n",
                     size, printSKEY (sk), *(int *) &msg->signature);
#endif
      GNUNET_GE_ASSERT (ectx,
                        -1 != GNUNET_AES_encrypt (pt,
                                                  size,
                                                  sk,
                                                  (const
                                                   GNUNET_AES_InitializationVector
                                                   *) &msg->signature,
                                                  (char *) &msg[1]));
      GNUNET_free (pt);
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
exchangeKey (const GNUNET_PeerIdentity * receiver,
             GNUNET_TSession * tsession, GNUNET_MessageHeader * pong)
{
  GNUNET_MessageHello *hello;
  P2P_new_setkey_MESSAGE *skey;
  GNUNET_AES_SessionKey sk;
  GNUNET_Int32Time age;
  GNUNET_MessageHeader *ping;
  GNUNET_PeerIdentity *sndr;
  GNUNET_EncName enc;

  GNUNET_GE_ASSERT (ectx, receiver != NULL);
  if ((tsession != NULL) &&
      (0 != memcmp (&tsession->peer, receiver, sizeof (GNUNET_PeerIdentity))))
    {
      GNUNET_GE_BREAK (ectx, 0);
      tsession = NULL;
    }
  if ((topology != NULL) &&
      (topology->allowConnectionFrom (receiver) == GNUNET_SYSERR))
    return GNUNET_SYSERR;
  GNUNET_hash_to_enc (&receiver->hashPubKey, &enc);
  /* then try to connect on the transport level */
  if ((tsession == NULL)
      || (transport->associate (tsession, __FILE__) == GNUNET_SYSERR))
    tsession = transport->connectFreely (receiver, GNUNET_YES, __FILE__);
  if (tsession == NULL)
    {
#if DEBUG_SESSION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     "Key exchange with `%s' failed: could not connect.\n",
                     &enc);
#endif
      return GNUNET_SYSERR;     /* failed to connect */
    }

  /* create our ping */
  sndr = GNUNET_malloc (sizeof (GNUNET_PeerIdentity));
  *sndr = *receiver;
  ping = pingpong->pingUser (receiver, &notifyPONG, sndr, GNUNET_NO, rand ());
  if (ping == NULL)
    {
      GNUNET_free (sndr);
      transport->disconnect (tsession, __FILE__);
      return GNUNET_SYSERR;
    }

  /* get or create our session key */
  if (GNUNET_OK !=
      coreAPI->connection_get_session_key_of_peer (receiver, &sk,
                                                   &age, GNUNET_YES))
    {
      age = GNUNET_get_time_int32 (NULL);
      GNUNET_AES_create_session_key (&sk);
#if DEBUG_SESSION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     "Created fresh sessionkey `%s' for peer `%s'.\n",
                     printSKEY (&sk), &enc);
#endif
    }

  /* build SKEY message */
  skey = makeSessionKeySigned (receiver, &sk, age, ping, pong);
  GNUNET_free (ping);
  if (skey == NULL)
    {
      transport->disconnect (tsession, __FILE__);
      return GNUNET_SYSERR;
    }

  /* create hello */
  hello = transport->createhello (tsession->ttype);
  if (NULL == hello)
    hello = transport->createhello (GNUNET_TRANSPORT_PROTOCOL_NUMBER_ANY);
  if (NULL == hello)
    {
      char *tports;

      tports = NULL;
      GNUNET_GC_get_configuration_value_string (coreAPI->cfg,
                                                "GNUNETD",
                                                "TRANSPORTS", NULL, &tports);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                     _
                     ("Could not create any HELLO for myself (have transports `%s')!\n"),
                     tports);
      GNUNET_free_non_null (tports);
    }
#if DEBUG_SESSION
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
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
      coreAPI->connection_send_plaintext (tsession,
                                          (const char *) hello,
                                          GNUNET_sizeof_hello (hello));
      GNUNET_free (hello);
      hello = NULL;
      coreAPI->connection_send_plaintext (tsession,
                                          (const char *) skey,
                                          ntohs (skey->header.size));
    }
  GNUNET_free (skey);
  if (0 != memcmp (receiver, &tsession->peer, sizeof (GNUNET_PeerIdentity)))
    {
      GNUNET_GE_BREAK (NULL, 0);
    }
  else
    {
      coreAPI->offerTSessionFor (receiver, tsession);
    }
  transport->disconnect (tsession, __FILE__);
  coreAPI->connection_assign_session_key_to_peer (&sk, receiver,
                                                  age, GNUNET_YES);
  return GNUNET_OK;
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
 * @return GNUNET_SYSERR or GNUNET_OK
 */
static int
acceptSessionKey (const GNUNET_PeerIdentity * sender,
                  const GNUNET_MessageHeader * msg,
                  GNUNET_TSession * tsession)
{
  GNUNET_AES_SessionKey key;
  GNUNET_MessageHeader *ping;
  GNUNET_MessageHeader *pong;
  const P2P_setkey_MESSAGE *sessionkeySigned;
  int size;
  int pos;
  char *plaintext;
  GNUNET_EncName enc;
  int ret;
  const GNUNET_RSA_Signature *sig;
  const P2P_new_setkey_MESSAGE *newMsg;
  const void *end;

  if (sender == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_hash_to_enc (&sender->hashPubKey, &enc);
  if ((topology != NULL) &&
      (topology->allowConnectionFrom (sender) == GNUNET_SYSERR))
    {
#if DEBUG_SESSION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     "Topology rejected session key from peer `%s'.\n", &enc);
#endif
      return GNUNET_SYSERR;
    }
  if (0 == memcmp (&sender->hashPubKey,
                   &coreAPI->myIdentity->hashPubKey,
                   sizeof (GNUNET_HashCode)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
#if DEBUG_SESSION
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 "Received session key from peer `%s'.\n", &enc);
#endif

  if (ntohs (msg->size) < sizeof (P2P_setkey_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER | GNUNET_GE_USER
                     | GNUNET_GE_BULK,
                     _
                     ("Session key received from peer `%s' has invalid format (discarded).\n"),
                     &enc);
      return GNUNET_SYSERR;
    }
  if ((GNUNET_OK !=
       coreAPI->connection_get_session_key_of_peer (sender, NULL,
                                                    NULL,
                                                    GNUNET_YES))
      && ((GNUNET_YES == identity->isBlacklisted (sender, GNUNET_NO))
          || ((coreAPI->forAllConnectedNodes (NULL, NULL) >= 3)
              && (GNUNET_cpu_get_load (ectx, coreAPI->cfg) >
                  GNUNET_IDLE_LOAD_THRESHOLD))))
    return GNUNET_SYSERR;       /* other peer initiated but is
                                   listed as not allowed => discard */

  sessionkeySigned = (const P2P_setkey_MESSAGE *) msg;

  if ((ntohs (msg->size) == sizeof (P2P_new_setkey_MESSAGE)) ||
      (ntohs (msg->size) ==
       sizeof (P2P_new_setkey_MESSAGE) + pingpong->ping_size)
      || (ntohs (msg->size) ==
          sizeof (P2P_new_setkey_MESSAGE) + pingpong->ping_size * 2))
    {
      newMsg = (const P2P_new_setkey_MESSAGE *) msg;

      if (0 != memcmp (&coreAPI->myIdentity->hashPubKey,
                       &newMsg->target.hashPubKey, sizeof (GNUNET_HashCode)))
        {
          GNUNET_EncName ta;
          GNUNET_hash_to_enc (&newMsg->target.hashPubKey, &ta);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER |
                         GNUNET_GE_USER | GNUNET_GE_BULK,
                         _
                         ("Session key received from peer `%s' is for `%s' and not for me!\n"),
                         &enc, &ta);
          return GNUNET_SYSERR; /* not for us! */
        }
      sig = &newMsg->signature;
    }
  else
    {
      sig = &sessionkeySigned->signature;
      newMsg = NULL;
    }
  ret = verifySKS (sender, sessionkeySigned, sig);
  if (GNUNET_OK != ret)
    {
#if DEBUG_SESSION
      if (ret == GNUNET_SYSERR)
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST |
                       GNUNET_GE_DEVELOPER,
                       "Signature of session key from `%s' failed"
                       " verification (discarded).\n", &enc);
#endif
      if (stats != NULL)
        stats->change (stat_skeyRejected, 1);
      return GNUNET_SYSERR;     /* rejected */
    }
  memset (&key, 0, sizeof (GNUNET_AES_SessionKey));
  size = identity->decryptData (&sessionkeySigned->key,
                                &key, sizeof (GNUNET_AES_SessionKey));
  if (size != sizeof (GNUNET_AES_SessionKey))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER | GNUNET_GE_USER
                     | GNUNET_GE_BULK,
                     _("Invalid `%s' message received from peer `%s'.\n"),
                     "setkey", &enc);
      return GNUNET_SYSERR;
    }
  if (key.crc32 != htonl (GNUNET_crc32_n (&key, GNUNET_SESSIONKEY_LEN)))
    {
#if DEBUG_SESSION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER | GNUNET_GE_USER
                     | GNUNET_GE_BULK,
                     _
                     ("setkey `%s' from `%s' fails CRC check (have: %u, want %u).\n"),
                     printSKEY (&key), &enc, ntohl (key.crc32),
                     GNUNET_crc32_n (&key, GNUNET_SESSIONKEY_LEN));
#endif
      GNUNET_GE_BREAK_OP (ectx, 0);
      stats->change (stat_skeyRejected, 1);
      return GNUNET_SYSERR;
    }

#if DEBUG_SESSION
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 "Received setkey message from `%s' with %u bytes of data and key `%s'.\n",
                 &enc, ntohs (sessionkeySigned->header.size),
                 printSKEY (&key));
#endif
  if (stats != NULL)
    stats->change (stat_skeyAccepted, 1);
  /* notify core about session key */
  coreAPI->connection_assign_session_key_to_peer (&key,
                                                  sender,
                                                  ntohl
                                                  (sessionkeySigned->
                                                   creationTime), GNUNET_NO);
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
      plaintext = GNUNET_malloc (size);
#if DEBUG_SESSION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     "Decrypting %d bytes of PINGPONG from `%s' with key `%s' and IV %u\n",
                     size, &enc, printSKEY (&key), *(int *) sig);
#endif
      GNUNET_GE_ASSERT (ectx,
                        -1 != GNUNET_AES_decrypt (&key,
                                                  end,
                                                  size,
                                                  (const
                                                   GNUNET_AES_InitializationVector
                                                   *) sig, plaintext));
      pos = 0;
      /* find pings & pongs! */
      while (pos + sizeof (GNUNET_MessageHeader) < size)
        {
          GNUNET_MessageHeader *hdr;

          hdr = (GNUNET_MessageHeader *) & plaintext[pos];
          if (htons (hdr->size) + pos > size)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER |
                             GNUNET_GE_USER | GNUNET_GE_BULK,
                             _
                             ("Error parsing encrypted session key from `%s', "
                              "given message part size is invalid.\n"), &enc);
              break;
            }
          if (htons (hdr->type) == GNUNET_P2P_PROTO_PING)
            ping = hdr;
          else if (htons (hdr->type) == GNUNET_P2P_PROTO_PONG)
            pong = hdr;
          else
            GNUNET_GE_LOG (ectx,
                           GNUNET_GE_WARNING | GNUNET_GE_DEVELOPER |
                           GNUNET_GE_USER | GNUNET_GE_BULK,
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
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     "Received PONG in session key from `%s', injecting!\n",
                     &enc);
#endif
      coreAPI->p2p_inject_message (sender,
                                   (char *) pong,
                                   ntohs (pong->size), GNUNET_YES, tsession);
      if (ping != NULL)
        {                       /* should always be true for well-behaved peers */
          /* pong can go out over ordinary channels */
#if DEBUG_SESSION
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                         "Received PING in session key from `%s', "
                         "sending PONG over normal encrypted session!\n",
                         &enc);
#endif
          ping->type = htons (GNUNET_P2P_PROTO_PONG);
          if (stats != NULL)
            stats->change (stat_pongSent, 1);
          coreAPI->unicast (sender, ping, GNUNET_EXTREME_PRIORITY, 0);
        }
    }
  else
    {
      if (ping != NULL)
        {
#if DEBUG_SESSION
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                         "Received ping in session key from `%s', "
                         "sending pong together with my session key!\n",
                         &enc);
#endif
          ping->type = htons (GNUNET_P2P_PROTO_PONG);
          if (stats != NULL)
            stats->change (stat_pongSent, 1);
          exchangeKey (sender, tsession, ping); /* ping is now pong */
        }
      else
        {
          GNUNET_GE_BREAK_OP (ectx, 0);
          /* PING not included in SKEY - bug (in other peer!?) */
        }
    }
  GNUNET_free_non_null (plaintext);
  return GNUNET_OK;
}

/**
 * Try to connect to the given peer.
 *
 * @return GNUNET_SYSERR if that is impossible,
 *         GNUNET_YES if a connection is established upon return,
 *         GNUNET_NO if we're going to try to establish one asynchronously
 */
static int
tryConnect (const GNUNET_PeerIdentity * peer)
{
#if DEBUG_SESSION
  GNUNET_EncName enc;

  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
            GNUNET_hash_to_enc (&peer->hashPubKey, &enc));
#endif
  if ((topology != NULL)
      && (topology->allowConnectionFrom (peer) == GNUNET_SYSERR))
    {
#if DEBUG_SESSION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     "Topology rejected connecting to `%s'.\n", &enc);
#endif
      return GNUNET_SYSERR;
    }
  if (coreAPI->queryPeerStatus (peer, NULL, NULL) == GNUNET_OK)
    {
#if DEBUG_SESSION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     "Connection to `%s' already up\n", &enc);
#endif
      return GNUNET_YES;        /* trivial case */
    }
  if (GNUNET_YES == identity->isBlacklisted (peer, GNUNET_NO))
    {
#if DEBUG_SESSION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                     "Peer `%s' blacklisted, cannot connect right now\n",
                     &enc);
#endif
      return GNUNET_NO;         /* not allowed right now! */
    }
#if DEBUG_SESSION
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 "Trying to exchange key with `%s'.\n", &enc);
#endif
  if (GNUNET_OK == exchangeKey (peer, NULL, NULL))
    return GNUNET_NO;
  return GNUNET_SYSERR;
}

/**
 * We have received an (encrypted) setkey message.
 * The reaction is to update our key to the new
 * value.  (Rekeying).
 */
static int
acceptSessionKeyUpdate (const GNUNET_PeerIdentity * sender,
                        const GNUNET_MessageHeader * msg)
{
  acceptSessionKey (sender, msg, NULL);
  return GNUNET_OK;
}


/**
 * Initialize the module.
 */
GNUNET_Session_ServiceAPI *
provide_module_session (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Session_ServiceAPI ret;

  ectx = capi->ectx;
  GNUNET_GE_ASSERT (ectx, sizeof (P2P_setkey_MESSAGE) == 520);
  coreAPI = capi;
  identity = capi->request_service ("identity");
  if (identity == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  transport = capi->request_service ("transport");
  if (transport == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      coreAPI->release_service (identity);
      identity = NULL;
      return NULL;
    }
  pingpong = capi->request_service ("pingpong");
  if (pingpong == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      coreAPI->release_service (transport);
      transport = NULL;
      coreAPI->release_service (identity);
      identity = NULL;
      return NULL;
    }
  topology = capi->request_service ("topology");
  stats = capi->request_service ("stats");
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

  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 _
                 ("`%s' registering handler %d (plaintext and ciphertext)\n"),
                 "session", GNUNET_P2P_PROTO_SET_KEY);
  coreAPI->plaintext_register_handler (GNUNET_P2P_PROTO_SET_KEY,
                                       &acceptSessionKey);
  coreAPI->registerHandler (GNUNET_P2P_PROTO_SET_KEY,
                            &acceptSessionKeyUpdate);
  ret.tryConnect = &tryConnect;
  return &ret;
}

/**
 * Shutdown the module.
 */
int
release_module_session ()
{
  coreAPI->plaintext_unregister_handler (GNUNET_P2P_PROTO_SET_KEY,
                                         &acceptSessionKey);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_SET_KEY,
                              &acceptSessionKeyUpdate);
  if (topology != NULL)
    {
      coreAPI->release_service (topology);
      topology = NULL;
    }
  coreAPI->release_service (stats);
  stats = NULL;
  coreAPI->release_service (identity);
  identity = NULL;
  coreAPI->release_service (transport);
  transport = NULL;
  coreAPI->release_service (pingpong);
  pingpong = NULL;
  coreAPI = NULL;
  return GNUNET_OK;
}

/* end of connect.c */
