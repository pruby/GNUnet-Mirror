/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file server/pingpong.c
 * @brief Pings a host and triggers an action if a reply is received.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_pingpong_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_transport_service.h"

/**
 * Ping message (test if address actually corresponds to
 * the advertised GNUnet host. The receiver responds with
 * exactly the same message, except that it is now a pong.
 * This message can be send in plaintext and without padding
 * and typically does make little sense (except keepalive)
 * for an encrypted (authenticated) tunnel.
 * <br>
 * There is also no proof that the other side actually
 * has the acclaimed identity, the only thing that is
 * proved is that the other side can be reached via
 * the underlying protocol and that it is a GNUnet node.
 * <br>
 * The challenge prevents an inept adversary from sending
 * us a hello and then an arbitrary PONG reply (adversary
 * must at least be able to sniff our outbound traffic).
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Which peer is the target of the ping? This is important since for
   * plaintext-pings, we need to catch faulty advertisements that
   * advertise a correct address but with the wrong public key.
   */
  GNUNET_PeerIdentity receiver;

  /**
   * The challenge is a (pseudo) random number that an adversary that
   * wants to fake a pong message would have to guess. Since even if
   * the number is guessed, the security impact is at most some wasted
   * resources, 32 bit are more than enough.
   */
  int challenge;

} P2P_pingpong_MESSAGE;

#define DEBUG_PINGPONG GNUNET_NO

#define MAX_PING_PONG 256

typedef struct
{
  GNUNET_PeerIdentity receiverIdentity;
  int challenge;
  int plaintext;
  GNUNET_CronJob method;
  void *data;
  GNUNET_Int32Time sendTime;
} PingPongEntry;

static PingPongEntry *pingPongs;

static struct GNUNET_Mutex *pingPongLock;

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Transport_ServiceAPI *transport;

static GNUNET_Identity_ServiceAPI *identity;

static GNUNET_Stats_ServiceAPI *stats;

static struct GNUNET_GE_Context *ectx;

static int stat_encryptedPongReceived;

static int stat_plaintextPongReceived;

static int stat_pingReceived;

static int stat_pingCreated;

static int stat_pongSent;

static int stat_plaintextPongSent;

static int stat_plaintextPongFailed;

static int stat_plaintextPingSent;

static int stat_ciphertextPingSent;

/**
 * We received a PING message, send the PONG reply.
 */
static int
pingReceived (const GNUNET_PeerIdentity * sender,
              const GNUNET_MessageHeader * msg)
{
  const P2P_pingpong_MESSAGE *pmsg;
  P2P_pingpong_MESSAGE pong;

  if (ntohs (msg->size) != sizeof (P2P_pingpong_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER |
                     GNUNET_GE_DEVELOPER,
                     _("Received malformed `%s' message. Dropping.\n"),
                     "ping");
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_pingReceived, 1);
  pmsg = (const P2P_pingpong_MESSAGE *) msg;
  if (0 != memcmp (coreAPI->myIdentity,
                   &pmsg->receiver, sizeof (GNUNET_PeerIdentity)))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                     _("Received ping for another peer. Dropping.\n"));
      return GNUNET_SYSERR;     /* not for us */
    }

#if DEBUG_PINGPONG
  GNUNET_EncName enc;

  GNUNET_hash_to_enc (&sender->hashPubKey, &enc);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received ping from peer %s.\n", &enc);
#endif
  pong = *pmsg;
  pong.header.type = htons (GNUNET_P2P_PROTO_PONG);
  if (stats != NULL)
    stats->change (stat_pingReceived, 1);
  coreAPI->unicast (sender, &pong.header, GNUNET_EXTREME_PRIORITY, 0);  /* send now! */
  if (stats != NULL)
    stats->change (stat_pongSent, 1);
  return GNUNET_OK;
}

static int
connection_send_plaintext (const GNUNET_PeerIdentity * peer,
                           const P2P_pingpong_MESSAGE * msg)
{
  GNUNET_TSession *mytsession;
  int ret;

  mytsession = transport->connectFreely (peer, GNUNET_YES, __FILE__);
  if (mytsession == NULL)
    return GNUNET_SYSERR;
  ret = coreAPI->connection_send_plaintext (mytsession,
                                            (char *) msg,
                                            sizeof (P2P_pingpong_MESSAGE));
  transport->disconnect (mytsession, __FILE__);
  return ret;
}

/**
 * We received a PING message, send the PONG reply and notify the
 * connection module that the session is still life.
 */
static int
plaintextPingReceived (const GNUNET_PeerIdentity * sender,
                       const GNUNET_MessageHeader * hmsg,
                       GNUNET_TSession * tsession)
{
  GNUNET_EncName enc;
  const P2P_pingpong_MESSAGE *pmsg;
  P2P_pingpong_MESSAGE pong;
  int ret;

  if (ntohs (hmsg->size) != sizeof (P2P_pingpong_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER |
                     GNUNET_GE_DEVELOPER,
                     _("Received malformed `%s' message. Dropping.\n"),
                     "ping");
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_SYSERR;
    }
  pmsg = (const P2P_pingpong_MESSAGE *) hmsg;
  if (0 != memcmp (coreAPI->myIdentity,
                   &pmsg->receiver, sizeof (GNUNET_PeerIdentity)))
    {
      GNUNET_hash_to_enc (&sender->hashPubKey, &enc);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_ADMIN,
                     _("Received PING from `%s' not destined for us!\n"),
                     &enc);
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_SYSERR;     /* not for us */
    }

#if DEBUG_PINGPONG
  GNUNET_hash_to_enc (&sender->hashPubKey, &enc);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received plaintext ping from peer %s.\n", &enc);
#endif
  pong = *pmsg;
  pong.header.type = htons (GNUNET_P2P_PROTO_PONG);
  /* allow using a different transport for sending the reply, the
     transport may have been uni-directional! */
  ret = GNUNET_SYSERR;
  if (tsession != NULL)
    ret = coreAPI->connection_send_plaintext (tsession,
                                              (char *) &pong,
                                              sizeof (P2P_pingpong_MESSAGE));
  if (ret != GNUNET_OK)
    ret = connection_send_plaintext (sender, &pong);
  if (ret == GNUNET_OK)
    {
      if (stats != NULL)
        stats->change (stat_plaintextPongSent, 1);
    }
  else
    {
      if (stats != NULL)
        stats->change (stat_plaintextPongFailed, 1);
    }
  return ret;
}

/**
 * Handler for a pong.
 */
static int
pongReceived (const GNUNET_PeerIdentity * sender,
              const GNUNET_MessageHeader * msg)
{
  int i;
  const P2P_pingpong_MESSAGE *pmsg;
  PingPongEntry *entry;
  int matched;
#if DEBUG_PINGPONG
  GNUNET_EncName enc;
#endif

  pmsg = (const P2P_pingpong_MESSAGE *) msg;
  if ((ntohs (msg->size) != sizeof (P2P_pingpong_MESSAGE)) ||
      (0 != memcmp (sender, &pmsg->receiver, sizeof (GNUNET_PeerIdentity))))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER |
                     GNUNET_GE_DEVELOPER,
                     _("Received malformed `%s' message. Dropping.\n"),
                     "pong");
      return GNUNET_SYSERR;     /* bad pong */
    }
#if DEBUG_PINGPONG
  GNUNET_hash_to_enc (&sender->hashPubKey, &enc);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received PONG from `%s'.\n", &enc);
#endif
  matched = 0;
  if (stats != NULL)
    stats->change (stat_encryptedPongReceived, 1);
  GNUNET_mutex_lock (pingPongLock);
  for (i = 0; i < MAX_PING_PONG; i++)
    {
      entry = &pingPongs[i];
      if (((int) ntohl (pmsg->challenge) == entry->challenge) &&
          (0 == memcmp (sender,
                        &entry->receiverIdentity,
                        sizeof (GNUNET_PeerIdentity)))
          && (entry->plaintext == GNUNET_NO))
        {
          entry->method (entry->data);
          /* entry was valid for one time only */
          memset (entry, 0, sizeof (PingPongEntry));
          matched++;
        }
    }
  GNUNET_mutex_unlock (pingPongLock);
#if DEBUG_PINGPONG
  GNUNET_hash_to_enc (&sender->hashPubKey, &enc);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received PONG from `%s' matched %u peers.\n", &enc,
                 matched);
#endif
  if (matched == 0)
    {
#if DEBUG_PINGPONG
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                     _("Could not match PONG against any PING. "
                       "Try increasing MAX_PING_PONG constant.\n"));
#endif
    }
  return GNUNET_OK;
}

/**
 * Handler for a pong.
 */
static int
plaintextPongReceived (const GNUNET_PeerIdentity * sender,
                       const GNUNET_MessageHeader * msg,
                       GNUNET_TSession * session)
{
  int i;
  const P2P_pingpong_MESSAGE *pmsg;
  PingPongEntry *entry;
  int matched;
#if DEBUG_PINGPONG
  GNUNET_EncName enc;
#endif

  pmsg = (const P2P_pingpong_MESSAGE *) msg;
  if ((ntohs (msg->size) != sizeof (P2P_pingpong_MESSAGE)) ||
      (0 != memcmp (sender, &pmsg->receiver, sizeof (GNUNET_PeerIdentity))))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER |
                     GNUNET_GE_DEVELOPER,
                     _("Received malformed `%s' message. Dropping.\n"),
                     "pong");
      return GNUNET_SYSERR;     /* bad pong */
    }
  if (stats != NULL)
    stats->change (stat_plaintextPongReceived, 1);
  matched = 0;
  GNUNET_mutex_lock (pingPongLock);
  for (i = 0; i < MAX_PING_PONG; i++)
    {
      entry = &pingPongs[i];
      if (((int) ntohl (pmsg->challenge) == entry->challenge) &&
          (0 == memcmp (sender,
                        &entry->receiverIdentity,
                        sizeof (GNUNET_PeerIdentity)))
          && (entry->plaintext == GNUNET_YES))
        {
          entry->method (entry->data);
          /* entry was valid for one time only */
          memset (entry, 0, sizeof (PingPongEntry));
          matched++;
        }
    }
  GNUNET_mutex_unlock (pingPongLock);
#if DEBUG_PINGPONG
  GNUNET_hash_to_enc (&sender->hashPubKey, &enc);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received plaintext PONG from `%s' matched %u peers.\n",
                 &enc, matched);
#endif
  if (matched == 0)
    {
#if DEBUG_PINGPONG
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                     _("Could not match PONG against any PING. "
                       "Try increasing MAX_PING_PONG constant.\n"));
#endif
    }
  return GNUNET_OK;
}

/**
 * Create a ping a host an call a method if a reply comes back.
 * Does  NOT send the ping message but rather returns it
 * to the caller.  The caller is responsible for both sending
 * and freeing the message.
 *
 * @param receiver the peer that should be PINGed
 * @param method the method to call if a PONG comes back
 * @param data an argument to pass to the method.
 * @param plaintext is the PONG expected to be in plaintext (GNUNET_YES/GNUNET_NO)
 * @returns NULL on error, otherwise the PING message
 */
static GNUNET_MessageHeader *
createPing (const GNUNET_PeerIdentity * receiver,
            GNUNET_CronJob method, void *data, int plaintext, int challenge)
{
  int i;
  int j;
  GNUNET_Int32Time min;
  PingPongEntry *entry;
  GNUNET_Int32Time now;
  P2P_pingpong_MESSAGE *pmsg;

  GNUNET_mutex_lock (pingPongLock);
  now = GNUNET_get_time_int32 (&min);   /* set both, tricky... */

  j = -1;
  for (i = 0; i < MAX_PING_PONG; i++)
    if (min > pingPongs[i].sendTime)
      {
        min = pingPongs[i].sendTime;
        j = i;
      }
  if (j == -1)
    {                           /* all send this second!? */
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_ADMIN,
                     _("Cannot create PING, table full. "
                       "Try increasing MAX_PING_PONG.\n"));
      GNUNET_mutex_unlock (pingPongLock);
      return NULL;
    }
  entry = &pingPongs[j];
  entry->sendTime = now;
  entry->method = method;
  entry->plaintext = plaintext;
  GNUNET_free_non_null (entry->data);
  entry->data = data;
  entry->receiverIdentity = *receiver;
  pmsg = GNUNET_malloc (sizeof (P2P_pingpong_MESSAGE));
  pmsg->header.size = htons (sizeof (P2P_pingpong_MESSAGE));
  pmsg->header.type = htons (GNUNET_P2P_PROTO_PING);
  pmsg->receiver = *receiver;
  entry->challenge = challenge;
  pmsg->challenge = htonl (challenge);
  GNUNET_mutex_unlock (pingPongLock);
  if (stats != NULL)
    stats->change (stat_pingCreated, 1);
  return &pmsg->header;
}

/**
 * Ping a host an call a method if a reply comes back.
 *
 * @param receiver the peer that should be PINGed
 * @param usePlaintext send the PING in plaintext (GNUNET_YES/GNUNET_NO)
 * @param method the method to call if a PONG comes back
 * @param data an argument to pass to the method.
 * @returns GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
initiatePing (const GNUNET_PeerIdentity * receiver,
              GNUNET_CronJob method, void *data, int usePlaintext,
              int challenge)
{
  GNUNET_MessageHeader *pmsg;

  pmsg = createPing (receiver, method, data, usePlaintext, challenge);
  if (pmsg == NULL)
    return GNUNET_SYSERR;
  if (usePlaintext == GNUNET_YES)
    {
      if (GNUNET_OK !=
          connection_send_plaintext (receiver,
                                     (const P2P_pingpong_MESSAGE *) pmsg))
        {
          GNUNET_free (pmsg);
          return GNUNET_SYSERR;
        }
      if (stats != NULL)
        stats->change (stat_plaintextPingSent, 1);
    }
  else
    {
      coreAPI->unicast (receiver, pmsg, GNUNET_EXTREME_PRIORITY, 0);
      if (stats != NULL)
        stats->change (stat_ciphertextPingSent, 1);
    }
  GNUNET_free (pmsg);
  return GNUNET_OK;
}

/**
 * Initialize the pingpong module.
 */
GNUNET_Pingpong_ServiceAPI *
provide_module_pingpong (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Pingpong_ServiceAPI ret;

  ectx = capi->ectx;
  GNUNET_GE_ASSERT (ectx, sizeof (P2P_pingpong_MESSAGE) == 72);
  coreAPI = capi;
  identity = capi->request_service ("identity");
  if (identity == NULL)
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      return NULL;
    }
  transport = capi->request_service ("transport");
  if (transport == NULL)
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      capi->release_service (identity);
      return NULL;
    }
  stats = capi->request_service ("stats");
  if (stats != NULL)
    {
      stat_encryptedPongReceived
        = stats->create (gettext_noop ("# encrypted PONG messages received"));
      stat_plaintextPongReceived
        = stats->create (gettext_noop ("# plaintext PONG messages received"));
      stat_pingReceived
        = stats->create (gettext_noop ("# encrypted PING messages received"));
      stat_pingCreated
        = stats->create (gettext_noop ("# PING messages created"));
      stat_pongSent
        = stats->create (gettext_noop ("# encrypted PONG messages sent"));
      stat_plaintextPingSent
        = stats->create (gettext_noop ("# plaintext PING messages sent"));
      stat_ciphertextPingSent
        = stats->create (gettext_noop ("# encrypted PING messages sent"));
      stat_plaintextPongSent
        = stats->create (gettext_noop ("# plaintext PONG messages sent"));
      stat_plaintextPongFailed
        =
        stats->
        create (gettext_noop ("# plaintext PONG transmissions failed"));

    }
  pingPongLock = capi->connection_get_lock ();
  pingPongs =
    (PingPongEntry *) GNUNET_malloc (sizeof (PingPongEntry) * MAX_PING_PONG);
  memset (pingPongs, 0, sizeof (PingPongEntry) * MAX_PING_PONG);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_USER | GNUNET_GE_REQUEST,
                 _
                 ("`%s' registering handlers %d %d (plaintext and ciphertext)\n"),
                 "pingpong", GNUNET_P2P_PROTO_PING, GNUNET_P2P_PROTO_PONG);
  capi->registerHandler (GNUNET_P2P_PROTO_PING, &pingReceived);
  capi->registerHandler (GNUNET_P2P_PROTO_PONG, &pongReceived);
  capi->plaintext_register_handler (GNUNET_P2P_PROTO_PING,
                                    &plaintextPingReceived);
  capi->plaintext_register_handler (GNUNET_P2P_PROTO_PONG,
                                    &plaintextPongReceived);
  ret.ping = &initiatePing;
  ret.pingUser = &createPing;
  ret.ping_size = sizeof (P2P_pingpong_MESSAGE);
  return &ret;
}

/**
 * Shutdown the pingpong module.
 */
int
release_module_pingpong ()
{
  int i;

  coreAPI->release_service (stats);
  stats = NULL;
  coreAPI->release_service (transport);
  transport = NULL;
  coreAPI->release_service (identity);
  identity = NULL;
  for (i = 0; i < MAX_PING_PONG; i++)
    GNUNET_free_non_null (pingPongs[i].data);
  GNUNET_free (pingPongs);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_PING, &pingReceived);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_PONG, &pongReceived);
  coreAPI->plaintext_unregister_handler (GNUNET_P2P_PROTO_PING,
                                         &plaintextPingReceived);
  coreAPI->plaintext_unregister_handler (GNUNET_P2P_PROTO_PONG,
                                         &plaintextPongReceived);
  coreAPI = NULL;
  return GNUNET_OK;
}

/* end of pingpong.c */
