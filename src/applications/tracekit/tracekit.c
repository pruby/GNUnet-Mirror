/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_Mutex *lock;

static unsigned int clientCount;

static struct GNUNET_ClientHandle **clients;

static struct GNUNET_GE_Context *ectx;

typedef struct
{
  GNUNET_PeerIdentity initiator;
  GNUNET_PeerIdentity replyTo;
  GNUNET_Int32Time timestamp;
  unsigned int priority;
} RTE;

#define MAXROUTE 64

static RTE *routeTable[MAXROUTE];

static int
handlep2pReply (const GNUNET_PeerIdentity * sender,
                const GNUNET_MessageHeader * message)
{
  unsigned int i;
  unsigned int hostCount;
  P2P_tracekit_reply_MESSAGE *reply;
  GNUNET_EncName initiator;
  GNUNET_EncName sen;

  GNUNET_hash_to_enc (&sender->hashPubKey, &sen);
  hostCount =
    (ntohs (message->size) -
     sizeof (P2P_tracekit_reply_MESSAGE)) / sizeof (GNUNET_PeerIdentity);
  if (ntohs (message->size) !=
      sizeof (P2P_tracekit_reply_MESSAGE) +
      hostCount * sizeof (GNUNET_PeerIdentity))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Received invalid `%s' message from `%s'.\n"),
                     "P2P_tracekit_probe_MESSAGE", &sen);
      return GNUNET_SYSERR;
    }
  reply = (P2P_tracekit_reply_MESSAGE *) message;
  GNUNET_hash_to_enc (&reply->initiatorId.hashPubKey, &initiator);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT: Sending reply back to initiator `%s'.\n",
                 &initiator);
  GNUNET_mutex_lock (lock);
  for (i = 0; i < MAXROUTE; i++)
    {
      if (routeTable[i] == NULL)
        continue;
      if ((routeTable[i]->timestamp ==
           (GNUNET_Int32Time) ntohl (reply->initiatorTimestamp))
          && (0 ==
              memcmp (&routeTable[i]->initiator.hashPubKey,
                      &reply->initiatorId.hashPubKey,
                      sizeof (GNUNET_HashCode))))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "TRACEKIT: found matching entry in routing table\n");
          if (0 == memcmp (&coreAPI->myIdentity->hashPubKey,
                           &routeTable[i]->replyTo.hashPubKey,
                           sizeof (GNUNET_HashCode)))
            {
              unsigned int idx;
              CS_tracekit_reply_MESSAGE *csReply;

              idx = ntohl (reply->clientId);
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "TRACEKIT: I am initiator, sending to client.\n");
              if (idx >= clientCount)
                {
                  GNUNET_GE_BREAK (ectx, 0);
                  continue;     /* discard */
                }
              if (clients[idx] == NULL)
                {
                  GNUNET_GE_LOG (ectx,
                                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                                 GNUNET_GE_USER,
                                 "TRACEKIT: received response on slot %u, but client already exited.\n",
                                 idx);
                  continue;     /* discard */
                }

              csReply =
                GNUNET_malloc (sizeof (CS_tracekit_reply_MESSAGE) +
                               hostCount * sizeof (GNUNET_PeerIdentity));
              /* build msg */
              csReply->header.size
                =
                htons (sizeof (CS_tracekit_reply_MESSAGE) +
                       hostCount * sizeof (GNUNET_PeerIdentity));
              csReply->header.type = htons (GNUNET_CS_PROTO_TRACEKIT_REPLY);
              csReply->responderId = reply->responderId;
              memcpy (&
                      ((CS_tracekit_reply_MESSAGE_GENERIC *) csReply)->
                      peerList[0],
                      &((P2P_tracekit_reply_MESSAGE_GENERIC *) reply)->
                      peerList[0], hostCount * sizeof (GNUNET_PeerIdentity));
              coreAPI->sendToClient (clients[idx], &csReply->header,
                                     GNUNET_YES);
              GNUNET_free (csReply);
            }
          else
            {
              GNUNET_EncName hop;

              GNUNET_hash_to_enc (&routeTable[i]->replyTo.hashPubKey, &hop);
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                             GNUNET_GE_USER,
                             "TRACEKIT: forwarding to next hop `%s'\n", &hop);
              coreAPI->unicast (&routeTable[i]->replyTo, message,
                                routeTable[i]->priority, 0);
            }
        }
    }
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}


typedef struct
{
  GNUNET_PeerIdentity *peers;
  unsigned int max;
  int pos;
} Tracekit_Collect_Trace_Closure;

static void
getPeerCallback (const GNUNET_PeerIdentity * id, void *cls)
{
  Tracekit_Collect_Trace_Closure *closure = cls;
  if (closure->pos == closure->max)
    {
      GNUNET_array_grow (closure->peers, closure->max, closure->max + 32);
    }
  if (closure->pos < closure->max)
    {
      /* check needed since #connections may change anytime! */
      closure->peers[closure->pos++] = *id;
    }
}

static void
transmit (const GNUNET_PeerIdentity * id, void *cls)
{
  P2P_tracekit_probe_MESSAGE *pro = cls;
  if (0 != memcmp (id, &pro->initiatorId, sizeof (GNUNET_PeerIdentity)))
    coreAPI->unicast (id, &pro->header, ntohl (pro->priority), 0);
}

static int
handlep2pProbe (const GNUNET_PeerIdentity * sender,
                const GNUNET_MessageHeader * message)
{
  P2P_tracekit_reply_MESSAGE *reply;
  P2P_tracekit_probe_MESSAGE *msg;
  Tracekit_Collect_Trace_Closure closure;
  int i;
  int sel;
  int hops;
  GNUNET_Int32Time oldest;
  int count;
  unsigned int size;
  GNUNET_EncName init;
  GNUNET_EncName sen;
  GNUNET_Int32Time now;

  GNUNET_hash_to_enc (&sender->hashPubKey, &sen);
  if (ntohs (message->size) != sizeof (P2P_tracekit_probe_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Received invalid `%s' message from `%s'.\n"),
                     "P2P_tracekit_probe_MESSAGE", &sen);
      return GNUNET_SYSERR;
    }
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT: received probe\n");
  GNUNET_get_time_int32 (&now);
  msg = (P2P_tracekit_probe_MESSAGE *) message;
  if ((GNUNET_Int32Time) ntohl (msg->timestamp) > 3600 + now)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "TRACEKIT: probe has timestamp in the far future (%d > %d), dropping\n",
                     ntohl (msg->timestamp), 3600 + now);
      return GNUNET_SYSERR;     /* Timestamp is more than 1h in the future. Invalid! */
    }
  GNUNET_hash_to_enc (&msg->initiatorId.hashPubKey, &init);
  GNUNET_mutex_lock (lock);
  /* test if already processed */
  for (i = 0; i < MAXROUTE; i++)
    {
      if (routeTable[i] == NULL)
        continue;
      if ((routeTable[i]->timestamp ==
           (GNUNET_Int32Time) ntohl (msg->timestamp))
          && 0 == memcmp (&routeTable[i]->initiator.hashPubKey,
                          &msg->initiatorId.hashPubKey,
                          sizeof (GNUNET_HashCode)))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "TRACEKIT-PROBE %d from `%s' received twice (slot %d), ignored\n",
                         ntohl (msg->timestamp), &init, i);
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
    }
  /* no, find and kill oldest entry */
  oldest = ntohl (msg->timestamp);
  sel = -1;
  for (i = 0; i < MAXROUTE; i++)
    {
      if (routeTable[i] == NULL)
        {
          sel = i;
          oldest = 0;
          continue;
        }
      if (oldest > routeTable[i]->timestamp)
        {
          oldest = routeTable[i]->timestamp;
          sel = i;
        }
      if (routeTable[i]->timestamp < now - 3600)
        {
          /* side-effect: drop very old entries */
          GNUNET_free (routeTable[i]);
          routeTable[i] = NULL;
        }
    }
  if (sel == -1)
    {
      GNUNET_mutex_unlock (lock);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     _
                     ("TRACEKIT: routing table full, trace request dropped\n"));
      return GNUNET_OK;
    }
  if (routeTable[sel] == NULL)
    routeTable[sel] = GNUNET_malloc (sizeof (RTE));
  routeTable[sel]->timestamp = ntohl (msg->timestamp);
  routeTable[sel]->priority = ntohl (msg->priority);
  routeTable[sel]->initiator = msg->initiatorId;
  routeTable[sel]->replyTo = *sender;
  GNUNET_mutex_unlock (lock);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT-PROBE started at %d by peer `%s' received, processing in slot %d with %u hops\n",
                 ntohl (msg->timestamp), &init, sel, ntohl (msg->hopsToGo));
  hops = ntohl (msg->hopsToGo);
  /* forward? */
  if (hops > 0)
    {
      msg->hopsToGo = htonl (hops - 1);
      coreAPI->forAllConnectedNodes (&transmit, msg);
    }
  closure.peers = NULL;
  closure.max = 0;
  closure.pos = 0;
  coreAPI->forAllConnectedNodes (&getPeerCallback, &closure);
  /* build local reply */
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
      reply->responderId = *(coreAPI->myIdentity);
      reply->initiatorTimestamp = msg->timestamp;
      reply->clientId = msg->clientId;
      memcpy (&reply[1],
              &closure.peers[closure.pos - count],
              count * sizeof (GNUNET_PeerIdentity));
      if (0 == memcmp (&coreAPI->myIdentity->hashPubKey,
                       &sender->hashPubKey, sizeof (GNUNET_HashCode)))
        {
          handlep2pReply (coreAPI->myIdentity, &reply->header);
        }
      else
        {
          coreAPI->unicast (sender, &reply->header, ntohl (msg->priority), 0);
        }
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
  int i;
  int idx;
  CS_tracekit_probe_MESSAGE *csProbe;
  P2P_tracekit_probe_MESSAGE p2pProbe;

  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT: client sends probe request\n");

  /* build probe, broadcast */
  csProbe = (CS_tracekit_probe_MESSAGE *) message;
  if (ntohs (csProbe->header.size) != sizeof (CS_tracekit_probe_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("TRACEKIT: received invalid `%s' message\n"),
                     "CS_tracekit_probe_MESSAGE");
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
      if ((clients[i] == NULL) && (idx == -1))
        {
          idx = i;
          break;
        }
    }
  if (idx == -1)
    {
      GNUNET_array_grow (clients, clientCount, clientCount + 1);
      idx = clientCount - 1;
    }
  clients[idx] = client;
  GNUNET_mutex_unlock (lock);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT: client joins in slot %u.\n", idx);

  p2pProbe.header.size = htons (sizeof (P2P_tracekit_probe_MESSAGE));
  p2pProbe.header.type = htons (GNUNET_P2P_PROTO_TRACEKIT_PROBE);
  p2pProbe.clientId = htonl (idx);
  p2pProbe.hopsToGo = csProbe->hops;
  p2pProbe.timestamp = htonl (GNUNET_get_time_int32 (NULL));
  p2pProbe.priority = csProbe->priority;
  memcpy (&p2pProbe.initiatorId, coreAPI->myIdentity,
          sizeof (GNUNET_PeerIdentity));
  handlep2pProbe (coreAPI->myIdentity, &p2pProbe.header);       /* FIRST send to myself! */
  return GNUNET_OK;
}

static void
clientExitHandler (struct GNUNET_ClientHandle *c)
{
  int i;

  GNUNET_mutex_lock (lock);
  for (i = 0; i < clientCount; i++)
    if (clients[i] == c)
      {
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                       "TRACEKIT: client in slot %u exits.\n", i);
        clients[i] = NULL;
        break;
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

  ectx = capi->ectx;
  lock = GNUNET_mutex_create (GNUNET_NO);
  coreAPI = capi;
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "TRACEKIT registering handlers %d %d and %d\n",
                 GNUNET_P2P_PROTO_TRACEKIT_PROBE,
                 GNUNET_P2P_PROTO_TRACEKIT_REPLY,
                 GNUNET_CS_PROTO_TRACEKIT_PROBE);
  memset (routeTable, 0, MAXROUTE * sizeof (RTE *));
  if (GNUNET_SYSERR == capi->registerHandler (GNUNET_P2P_PROTO_TRACEKIT_PROBE,
                                              &handlep2pProbe))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR == capi->registerHandler (GNUNET_P2P_PROTO_TRACEKIT_REPLY,
                                              &handlep2pReply))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR == capi->registerClientExitHandler (&clientExitHandler))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_TRACEKIT_PROBE,
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
  int i;

  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_TRACEKIT_PROBE,
                              &handlep2pProbe);
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_TRACEKIT_REPLY,
                              &handlep2pReply);
  coreAPI->unregisterClientExitHandler (&clientExitHandler);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_TRACEKIT_PROBE,
                                    &csHandle);
  for (i = 0; i < MAXROUTE; i++)
    {
      GNUNET_free_non_null (routeTable[i]);
      routeTable[i] = NULL;
    }
  GNUNET_array_grow (clients, clientCount, 0);
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  coreAPI = NULL;
}

/* end of tracekit.c */
