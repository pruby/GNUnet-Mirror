/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/tracekit/tracekit.c
 * @brief implementation of the tracekit protocol
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "tracekit.h"

/**
 * Maximum number of tracekit requests that we're willing
 * to route at the same time.
 */
#define MAXROUTE 64

#define DEBUG_TRACEKIT GNUNET_NO


static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_Mutex *lock;

static unsigned int clientCount;

static struct GNUNET_ClientHandle **clients;

/**
 * An entry in the tracekit's routing table.
 */
struct RTE
{
  GNUNET_PeerIdentity initiator;
  GNUNET_PeerIdentity replyTo;
  unsigned int timestamp;
  unsigned int priority;
};

static struct RTE routeTable[MAXROUTE];

static int
handlep2pReply (const GNUNET_PeerIdentity * sender,
                const GNUNET_MessageHeader * message)
{
  struct RTE *rte;
  unsigned int i;
  unsigned int hostCount;
  const P2P_tracekit_reply_MESSAGE *reply;
#if DEBUG_TRACEKIT
  GNUNET_EncName enc;
#endif
  unsigned int idx;
  CS_tracekit_reply_MESSAGE *csReply;

  hostCount =
    (ntohs (message->size) -
     sizeof (P2P_tracekit_reply_MESSAGE)) / sizeof (GNUNET_PeerIdentity);
  if (ntohs (message->size) !=
      sizeof (P2P_tracekit_reply_MESSAGE) +
      hostCount * sizeof (GNUNET_PeerIdentity))
    {
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_SYSERR;
    }
  reply = (const P2P_tracekit_reply_MESSAGE *) message;
#if DEBUG_TRACEKIT
  GNUNET_hash_to_enc (&reply->initiatorId.hashPubKey, &enc);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT: Sending reply back to initiator `%s'.\n", &enc);
#endif
  GNUNET_mutex_lock (lock);
  for (i = 0; i < MAXROUTE; i++)
    {
      rte = &routeTable[i];
      if ((rte->timestamp ==
           (GNUNET_Int32Time) ntohl (reply->initiatorTimestamp))
          && (0 ==
              memcmp (&rte->initiator,
                      &reply->initiatorId, sizeof (GNUNET_HashCode))))
        {
#if DEBUG_TRACEKIT
          GNUNET_GE_LOG (coreAPI->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "TRACEKIT: found matching entry in routing table\n");
#endif
          if (0 == memcmp (coreAPI->my_identity,
                           &rte->replyTo, sizeof (GNUNET_HashCode)))
            {
              idx = ntohl (reply->clientId);
              if ((idx >= clientCount) || (clients[idx] == NULL))
                continue;
#if DEBUG_TRACEKIT
              GNUNET_GE_LOG (coreAPI->ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "TRACEKIT: I am initiator, sending to client %u.\n",
                             idx);
#endif
              csReply =
                GNUNET_malloc (sizeof (CS_tracekit_reply_MESSAGE) +
                               hostCount * sizeof (GNUNET_PeerIdentity));
              csReply->header.size
                = htons (sizeof (CS_tracekit_reply_MESSAGE) +
                         hostCount * sizeof (GNUNET_PeerIdentity));
              csReply->header.type = htons (GNUNET_CS_PROTO_TRACEKIT_REPLY);
              csReply->responderId = reply->responderId;
              memcpy (&csReply[1],
                      &reply[1], hostCount * sizeof (GNUNET_PeerIdentity));
              coreAPI->cs_send_message (clients[idx],
                                        &csReply->header, GNUNET_YES);
              GNUNET_free (csReply);
            }
          else
            {
#if DEBUG_TRACEKIT
              GNUNET_hash_to_enc (&rte->replyTo.hashPubKey, &enc);
              GNUNET_GE_LOG (coreAPI->ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "TRACEKIT: forwarding to next hop `%s'\n", &enc);
#endif
              coreAPI->ciphertext_send (&rte->replyTo, message, rte->priority,
                                        0);
            }
        }
    }
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

typedef struct
{
  const P2P_tracekit_probe_MESSAGE *pro;

  const GNUNET_PeerIdentity *sender;

} Transmit_Trace_Closure;

/**
 * Callback used for forwarding the request to
 * our neighbors (excluding the initiator and
 * our predecessor)
 */
static void
transmit (const GNUNET_PeerIdentity * id, void *cls)
{
  const Transmit_Trace_Closure *ttc = cls;

  if ((0 != memcmp (id, &ttc->pro->initiatorId, sizeof (GNUNET_PeerIdentity)))
      && (0 != memcmp (id, &ttc->sender, sizeof (GNUNET_PeerIdentity))))
    coreAPI->ciphertext_send (id, &ttc->pro->header,
                              ntohl (ttc->pro->priority), 0);
}

typedef struct
{
  GNUNET_PeerIdentity *peers;

  unsigned int max;

  unsigned int pos;

} Tracekit_Collect_Trace_Closure;

/**
 * Get a list of the peers that we are connected
 * to (as one big array).
 */
static void
getPeerCallback (const GNUNET_PeerIdentity * id, void *cls)
{
  Tracekit_Collect_Trace_Closure *closure = cls;

  if (closure->pos == closure->max)
    GNUNET_array_grow (closure->peers, closure->max, closure->max + 32);
  closure->peers[closure->pos++] = *id;
}

static int
handlep2pProbe (const GNUNET_PeerIdentity * sender,
                const GNUNET_MessageHeader * message)
{
  const P2P_tracekit_probe_MESSAGE *msg;
  P2P_tracekit_probe_MESSAGE amsg;
  P2P_tracekit_reply_MESSAGE *reply;
  Tracekit_Collect_Trace_Closure closure;
  Transmit_Trace_Closure ttc;
  unsigned int i;
  int sel;
  unsigned int hops;
  GNUNET_Int32Time oldest;
  unsigned int count;
  unsigned int size;
  GNUNET_Int32Time now;
  struct RTE *rte;

  if (ntohs (message->size) != sizeof (P2P_tracekit_probe_MESSAGE))
    {
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_SYSERR;
    }
  msg = (const P2P_tracekit_probe_MESSAGE *) message;
#if DEBUG_TRACEKIT
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT: received probe\n");
#endif
  GNUNET_get_time_int32 (&now);
  if (ntohl (msg->timestamp) > 3600 + now)
    {
#if DEBUG_TRACEKIT
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "TRACEKIT: probe has timestamp in the far future (%u > %u), dropping\n",
                     ntohl (msg->timestamp), 3600 + now);
#endif
      return GNUNET_SYSERR;     /* Timestamp is more than 1h in the future. Invalid! */
    }
  GNUNET_mutex_lock (lock);
  /* test if already processed */
  for (i = 0; i < MAXROUTE; i++)
    {
      rte = &routeTable[i];
      if ((rte->timestamp == ntohl (msg->timestamp))
          && 0 == memcmp (&rte->initiator,
                          &msg->initiatorId, sizeof (GNUNET_HashCode)))
        {
          /* received twice => ignore */
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
    }
  /* no, find and kill oldest entry */
  oldest = ntohl (msg->timestamp);
  sel = -1;
  for (i = 0; i < MAXROUTE; i++)
    {
      rte = &routeTable[i];
      if (oldest > rte->timestamp)
        {
          oldest = rte->timestamp;
          sel = i;
        }
    }
  if (sel == -1)
    {
      GNUNET_mutex_unlock (lock);
#if DEBUG_TRACEKIT
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "TRACEKIT: routing table full, trace request dropped\n");
#endif
      return GNUNET_OK;
    }
  rte = &routeTable[sel];
  rte->timestamp = ntohl (msg->timestamp);
  rte->priority = ntohl (msg->priority);
  rte->initiator = msg->initiatorId;
  rte->replyTo = *sender;
  hops = ntohl (msg->hopsToGo);
  GNUNET_mutex_unlock (lock);
  /* forward? */
  if (hops > 0)
    {
      memcpy (&amsg, msg, sizeof (P2P_tracekit_probe_MESSAGE));
      amsg.hopsToGo = htonl (hops - 1);
      ttc.pro = &amsg;
      ttc.sender = sender;
      coreAPI->p2p_connections_iterate (&transmit, &ttc);
    }
  /* build local reply */
  closure.peers = NULL;
  closure.max = 0;
  closure.pos = 0;
  coreAPI->p2p_connections_iterate (&getPeerCallback, &closure);
  while (closure.pos > 0)
    {
      count = closure.pos;
      if (count > 60000 / sizeof (GNUNET_PeerIdentity))
        count = 60000 / sizeof (GNUNET_PeerIdentity);
      size =
        sizeof (P2P_tracekit_reply_MESSAGE) +
        count * sizeof (GNUNET_PeerIdentity);
      reply = GNUNET_malloc (size);
      reply->header.size = htons (size);
      reply->header.type = htons (GNUNET_P2P_PROTO_TRACEKIT_REPLY);
      reply->initiatorId = msg->initiatorId;
      reply->responderId = *(coreAPI->my_identity);
      reply->initiatorTimestamp = msg->timestamp;
      reply->clientId = msg->clientId;
      memcpy (&reply[1],
              &closure.peers[closure.pos - count],
              count * sizeof (GNUNET_PeerIdentity));
      if (0 == memcmp (&coreAPI->my_identity->hashPubKey,
                       &sender->hashPubKey, sizeof (GNUNET_HashCode)))
        handlep2pReply (coreAPI->my_identity, &reply->header);
      else
        coreAPI->ciphertext_send (sender, &reply->header,
                                  ntohl (msg->priority), 0);
      closure.pos -= count;
      GNUNET_free (reply);
    }
  GNUNET_array_grow (closure.peers, closure.max, 0);
  return GNUNET_OK;
}

static int
csHandle (struct GNUNET_ClientHandle *client,
          const GNUNET_MessageHeader * message)
{
  const CS_tracekit_probe_MESSAGE *csProbe;
  unsigned int i;
  int idx;
  P2P_tracekit_probe_MESSAGE p2pProbe;

  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT: client sends probe request\n");

  /* build probe, broadcast */
  csProbe = (const CS_tracekit_probe_MESSAGE *) message;
  if (ntohs (csProbe->header.size) != sizeof (CS_tracekit_probe_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_lock (lock);
  idx = -1;
  for (i = 0; i < clientCount; i++)
    {
      if (clients[i] == client)
        {
          idx = i;
          break;
        }
      if (clients[i] == NULL)
        idx = i;
    }
  if (idx == -1)
    {
      GNUNET_array_grow (clients, clientCount, clientCount + 1);
      idx = clientCount - 1;
    }
  clients[idx] = client;
  GNUNET_mutex_unlock (lock);
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT: client joins in slot %u.\n", idx);
  p2pProbe.header.size = htons (sizeof (P2P_tracekit_probe_MESSAGE));
  p2pProbe.header.type = htons (GNUNET_P2P_PROTO_TRACEKIT_PROBE);
  p2pProbe.clientId = htonl (idx);
  p2pProbe.hopsToGo = csProbe->hops;
  p2pProbe.timestamp = htonl (GNUNET_get_time_int32 (NULL));
  p2pProbe.priority = csProbe->priority;
  memcpy (&p2pProbe.initiatorId, coreAPI->my_identity,
          sizeof (GNUNET_PeerIdentity));
  handlep2pProbe (coreAPI->my_identity, &p2pProbe.header);      /* FIRST send to myself! */
  return GNUNET_OK;
}

static void
clientExitHandler (struct GNUNET_ClientHandle *c)
{
  int i;

  GNUNET_mutex_lock (lock);
  for (i = 0; i < clientCount; i++)
    {
      if (clients[i] == c)
        {
          clients[i] = NULL;
          break;
        }
    }
  i = clientCount - 1;
  while ((i >= 0) && (clients[i] == NULL))
    i--;
  i++;
  if (i != clientCount)
    GNUNET_array_grow (clients, clientCount, i);
  GNUNET_mutex_unlock (lock);
}

int
initialize_module_tracekit (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;

  lock = GNUNET_mutex_create (GNUNET_NO);
  coreAPI = capi;
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT registering handlers %d %d and %d\n",
                 GNUNET_P2P_PROTO_TRACEKIT_PROBE,
                 GNUNET_P2P_PROTO_TRACEKIT_REPLY,
                 GNUNET_CS_PROTO_TRACEKIT_PROBE);
  if (GNUNET_SYSERR ==
      capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_TRACEKIT_PROBE,
                                             &handlep2pProbe))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->p2p_ciphertext_handler_register (GNUNET_P2P_PROTO_TRACEKIT_REPLY,
                                             &handlep2pReply))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->cs_disconnect_handler_register (&clientExitHandler))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->cs_handler_register (GNUNET_CS_PROTO_TRACEKIT_PROBE,
                                 (GNUNET_ClientRequestHandler) & csHandle))
    ok = GNUNET_SYSERR;
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "tracekit",
                                                                   gettext_noop
                                                                   ("allows mapping of the network topology")));
  return ok;
}

void
done_module_tracekit ()
{
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_TRACEKIT_PROBE,
                                              &handlep2pProbe);
  coreAPI->p2p_ciphertext_handler_unregister (GNUNET_P2P_PROTO_TRACEKIT_REPLY,
                                              &handlep2pReply);
  coreAPI->cs_disconnect_handler_unregister (&clientExitHandler);
  coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_TRACEKIT_PROBE, &csHandle);
  GNUNET_array_grow (clients, clientCount, 0);
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  coreAPI = NULL;
}

/* end of tracekit.c */
