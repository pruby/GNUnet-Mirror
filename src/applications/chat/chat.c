/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * CHAT CORE. This is the code that is plugged
 * into the GNUnet core to enable chatting.
 *
 * @author Christian Grothoff
 * @file applications/chat/chat.c
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "chat.h"

static GNUNET_CoreAPIForPlugins *coreAPI;

#define MAX_LAST_MESSAGES 12
#define MAX_CLIENTS 4

static struct GNUNET_ClientHandle **clients;
static int clientCount;
static struct GNUNET_HashCode **lastMsgs;
static int ringIndex;
static struct GNUNET_Mutex *chatMutex;
static struct GNUNET_GE_Context *ectx;
static struct GNUNET_GC_Configuration *cfg;

static void
markSeen (GNUNET_HashCode * hc)
{
  if (++ringIndex >= MAX_LAST_MESSAGES)
    ringIndex = 0;
  memcpy (&lastMsgs[ringIndex], hc, sizeof (GNUNET_HashCode));
}

typedef struct
{
  const GNUNET_MessageHeader *message;
  unsigned int prio;
  unsigned int delay;
} BCC;

static void
bccHelper (const GNUNET_PeerIdentity * peer, BCC * bcc)
{
  coreAPI->unicast (peer, bcc->message, bcc->prio, bcc->delay);
}

static void
broadcastToConnected (const GNUNET_MessageHeader * message,
                      unsigned int prio, unsigned int delay)
{
  BCC bcc;
  bcc.message = message;
  bcc.prio = prio;
  bcc.delay = delay;
  coreAPI->forAllConnectedNodes ((GNUNET_NodeIteratorCallback) bccHelper,
                                 &bcc);
}

static int
handleChatMSG (const GNUNET_PeerIdentity * sender,
               const GNUNET_MessageHeader * message)
{
  int i;
  int j;
  CS_chat_MESSAGE *cmsg;

  GNUNET_HashCode hc;
  
  char *nick;
  char *message_content;
  char *room_name;
  
  int header_size;
  unsigned long nick_len;
  unsigned long msg_len;
  unsigned long room_size;

  cmsg = (CS_chat_MESSAGE *) message;

   if (ntohs (message->size) < sizeof (CS_chat_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Message received from client is invalid\n"));
      return GNUNET_SYSERR;    /* invalid message */
 
    }
  

  header_size = ntohs(cmsg->header.size);
  nick_len = ntohl(cmsg->nick_len);
  msg_len = ntohl(cmsg->msg_len);
  room_size = ntohl(cmsg->nick_len);
  
  nick = GNUNET_malloc(nick_len + 1);
  message_content = GNUNET_malloc(msg_len + 1);
  room_name = GNUNET_malloc(room_size + 1);
    
  memcpy(nick,&cmsg->nick[0],nick_len);
  memcpy(message_content,&cmsg->nick[sizeof(nick)],msg_len);
  memcpy(room_name,&cmsg->nick[sizeof(nick) + sizeof(message_content)],msg_len);  
  
  nick[nick_len] = '\0';
  message_content[msg_len] = '\0';
  room_name[room_size] = '\0';
      
  
  GNUNET_hash (cmsg, header_size, &hc);
  /* check if we have seen this message already */

  j = -1;
  GNUNET_mutex_lock (chatMutex);
  for (i = 0; i < MAX_LAST_MESSAGES; i++)
    if (0 == memcmp (&hc, &lastMsgs[i], sizeof (GNUNET_HashCode)))
      j = i;
  if (j == -1)
    {
      /* we have not seen it before, send to all TCP clients
         and broadcast to all peers */
      markSeen (&hc);
      broadcastToConnected (message, 5, 1);
      cmsg->header.type = htons (GNUNET_CS_PROTO_CHAT_MSG);
      for (j = 0; j < clientCount; j++)
        coreAPI->cs_send_to_client (clients[j], &cmsg->header,GNUNET_YES);
      /*pmsg->nick[CHAT_NICK_LENGTH - 1] = '\0';
      pmsg->message[CHAT_MSG_LENGTH - 1] = '\0';*/
      
      /*
         GNUNET_GE_LOG(ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
         " CHAT: received new message from %s: %s\n",
         &pmsg->nick[0],
         &pmsg->message[0]);
       */
    }
  GNUNET_mutex_unlock (chatMutex);
  return GNUNET_OK;
}

static int
csHandleChatRequest (struct GNUNET_ClientHandle *client,
                     const GNUNET_MessageHeader * message)
{
  int i;
  int j;
  CS_chat_MESSAGE *cmsg;
  P2P_chat_MESSAGE *pmsg;
  GNUNET_HashCode hc;
  char *nick;
  char *message_content;
  char *room_name;
  
  int header_size;
  unsigned long nick_len;
  unsigned long msg_len;
  unsigned long room_size;
  
  pmsg = (P2P_chat_MESSAGE *) message;
  cmsg = (CS_chat_MESSAGE *) message;

  if (ntohs (cmsg->header.size) < sizeof (CS_chat_MESSAGE))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Message received from client is invalid\n"));
      return GNUNET_SYSERR;  /* invalid message */
 
    }
   
  header_size = ntohs(cmsg->header.size);
  nick_len = ntohl(cmsg->nick_len);
  msg_len = ntohl(cmsg->msg_len);
  room_size = ntohl(cmsg->nick_len);
  
  nick = GNUNET_malloc(nick_len + 1);
  message_content = GNUNET_malloc(msg_len + 1);
  room_name = GNUNET_malloc(room_size + 1);
    
  memcpy(nick,&cmsg->nick[0],nick_len);
  memcpy(message_content,&cmsg->nick[sizeof(nick)],msg_len);
  memcpy(room_name,&cmsg->nick[sizeof(nick) + sizeof(message_content)],msg_len);  
  
  nick[nick_len] = '\0';
  message_content[msg_len] = '\0';
  room_name[room_size] = '\0';  
  
  GNUNET_hash (pmsg, header_size, &hc);
  GNUNET_mutex_lock (chatMutex);
  markSeen (&hc);

  /* forward to all other TCP chat clients */
  j = -1;                       /* marker to check if this is a new client */
  for (i = 0; i < clientCount; i++)
    if (clients[i] == client)
      j = i;
    else
      coreAPI->cs_send_to_client (clients[i], message,GNUNET_YES);
  if (j == -1)
    {
      if (clientCount == MAX_CLIENTS)
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                       _("Maximum number of chat clients reached.\n"));
      else
        {
          clients[clientCount++] = client;
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         _("Now %d of %d chat clients at this node.\n"),
                         clientCount, MAX_CLIENTS);
        }
    }
  /* forward to all other nodes in the network */
  pmsg->header.type = htons (GNUNET_P2P_PROTO_CHAT_MSG);
  broadcastToConnected (&pmsg->header, 5, 1);
  GNUNET_mutex_unlock (chatMutex);
  return GNUNET_OK;
}

static void
chatClientExitHandler (struct GNUNET_ClientHandle *client)
{
  int i;
  GNUNET_mutex_lock (chatMutex);
  for (i = 0; i < clientCount; i++)
    if (clients[i] == client)
      {
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                       "Chat client exits.\n");
        clients[i] = clients[--clientCount];
        break;
      }
  GNUNET_mutex_unlock (chatMutex);
}


int
initialize_module_chat (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;

  GNUNET_GE_ASSERT (ectx,
                    sizeof (P2P_chat_MESSAGE) == sizeof (CS_chat_MESSAGE));
  chatMutex = GNUNET_mutex_create (GNUNET_NO);
  clientCount = 0;
  coreAPI = capi;
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering handlers %d and %d\n"),
                 "chat", GNUNET_P2P_PROTO_CHAT_MSG, GNUNET_CS_PROTO_CHAT_MSG);

  if (GNUNET_SYSERR ==
      capi->registerHandler (GNUNET_P2P_PROTO_CHAT_MSG, &handleChatMSG))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->cs_exit_handler_register (&chatClientExitHandler))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR == capi->registerClientHandler (GNUNET_CS_PROTO_CHAT_MSG,
                                                    &csHandleChatRequest))
    ok = GNUNET_SYSERR;

  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "chat",
                                                                   _
                                                                   ("enables P2P-chat (incomplete)")));
  return ok;
}

void
done_module_chat ()
{
  coreAPI->unregisterHandler (GNUNET_P2P_PROTO_CHAT_MSG, &handleChatMSG);
  coreAPI->cs_exit_handler_unregister (&chatClientExitHandler);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_CHAT_MSG,
                                    &csHandleChatRequest);
  GNUNET_mutex_destroy (chatMutex);
  coreAPI = NULL;
}

/* end of chat.c */
