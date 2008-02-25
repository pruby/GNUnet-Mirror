/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @author Nathan Evans
 * @file applications/chat/chat.c
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_core.h"
#include "chat.h"

static GNUNET_CoreAPIForPlugins *coreAPI;

#define MAX_LAST_MESSAGES 12

static struct GNUNET_Mutex *chatMutex;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

struct GNUNET_CS_chat_client
{
  struct GNUNET_ClientHandle *client;
  struct GNUNET_CS_chat_client *next;
  struct GNUNET_CS_chat_client *prev;
  GNUNET_HashCode room_name_hash;

};

static struct GNUNET_CS_chat_client *client_list_head;

static int
csHandleChatMSG (struct GNUNET_ClientHandle *client,
                 const GNUNET_MessageHeader * message)
{
  CS_chat_MESSAGE *cmsg;

  struct GNUNET_CS_chat_client *tempClient;

  GNUNET_HashCode hc;
  GNUNET_HashCode room_name_hash;

  char *nick;
  char *message_content;
  char *room_name;

  int header_size;
  unsigned long nick_len;
  unsigned long msg_len;
  unsigned long room_name_len;

  cmsg = (CS_chat_MESSAGE *) message;
  if (ntohs (cmsg->header.size) < sizeof (CS_chat_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;     /* invalid message */
    }


  header_size = ntohs (cmsg->header.size);
  nick_len = ntohl (cmsg->nick_len);
  msg_len = ntohl (cmsg->msg_len);
  room_name_len = ntohl (cmsg->room_name_len);

  nick = GNUNET_malloc (nick_len + 1);
  message_content = GNUNET_malloc (msg_len + 1);
  room_name = GNUNET_malloc (room_name_len + 1);

  /* BUFFER OVERFLOWS! */
  memcpy (nick, &cmsg->nick[0], nick_len);
  memcpy (message_content, &cmsg->nick[nick_len], msg_len);
  memcpy (room_name, &cmsg->nick[nick_len + msg_len], room_name_len);

  nick[nick_len] = '\0';
  message_content[msg_len] = '\0';
  room_name[room_name_len] = '\0';

  GNUNET_hash (room_name, strlen (room_name), &room_name_hash);

  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                 "Received chat message from client.\n Message is `%s'\n from `%s'\n intended for room `%s'\n",
                 message_content, nick, room_name);

  GNUNET_hash (cmsg, header_size, &hc);
  /* check if we have seen this message already */

  GNUNET_mutex_lock (chatMutex);

  /*TODO: we have received a message intended for some room, check current client contexts for matching room and send to those clients */
  /*TODO: p2p messages will need to be sent as well at some point */

  tempClient = client_list_head;
  while ((tempClient != NULL) && (tempClient->client != NULL))
    {
      if (memcmp
          (&room_name_hash, &tempClient->room_name_hash,
           sizeof (GNUNET_HashCode)) == 0)
        {
          fprintf (stderr,
                   "room names match, must send message to others!!\n");
          coreAPI->cs_send_to_client (tempClient->client, message,
                                      GNUNET_YES);
        }

      tempClient = tempClient->next;
    }
  GNUNET_mutex_unlock (chatMutex);

  GNUNET_free (room_name);
  GNUNET_free (nick);
  GNUNET_free (message_content);

  return GNUNET_OK;
}

static int
csHandleChatJoinRequest (struct GNUNET_ClientHandle *client,
                         const GNUNET_MessageHeader * message)
{
  const CS_chat_JOIN_MESSAGE *cmsg;
  P2P_chat_MESSAGE *pmsg;
  GNUNET_HashCode hc;
  GNUNET_HashCode room_name_hash;

  char *nick;
  GNUNET_RSA_PublicKey *client_key;
  char *room_name;

  int header_size;
  int tempCount;
  unsigned long nick_len;
  unsigned long pubkey_len;
  unsigned long room_name_len;
  struct GNUNET_CS_chat_client *tempClient;

  pmsg = (P2P_chat_MESSAGE *) message;
  cmsg = (CS_chat_JOIN_MESSAGE *) message;

  if (ntohs (cmsg->header.size) < sizeof (CS_chat_JOIN_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;     /* invalid message */
    }

  header_size = ntohs (cmsg->header.size);
  nick_len = ntohl (cmsg->nick_len);
  pubkey_len = ntohl (cmsg->pubkey_len);
  room_name_len = ntohl (cmsg->room_name_len);

  nick = GNUNET_malloc (nick_len + 1);
  client_key = GNUNET_malloc (sizeof (GNUNET_RSA_PublicKey));
  room_name = GNUNET_malloc (room_name_len + 1);

  /* BUFFER OVERFLOWS */
  memcpy (nick, &cmsg->nick[0], nick_len);
  memcpy (client_key, &cmsg->nick[nick_len], pubkey_len);
  memcpy (room_name, &cmsg->nick[nick_len + pubkey_len], room_name_len);

  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "Received join chat room message from client.\n From `%s'\n for room `%s'\n",
                 nick, room_name);

  nick[nick_len] = '\0';
  room_name[room_name_len] = '\0';
  GNUNET_hash (cmsg, header_size, &hc);
  GNUNET_hash (room_name, strlen (room_name), &room_name_hash);
  GNUNET_mutex_lock (chatMutex);

  /*TODO: create client context on the server, very simple as of now */
#if EXTRA_CHECKS
  tempClient = client_list;
  while ((tempClient->client != client) && (tempClient != NULL))
    tempClient = tempClient->next;
  if (tempClient != NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_free (nick);
      GNUNET_free (client_key);
      GNUNET_free (room_name);
      GNUNET_mutex_unlock (chatMutex);
      return GNUNET_SYSERR;
    }
#endif
  tempClient = GNUNET_malloc (sizeof (struct GNUNET_CS_chat_client));
  memset (tempClient, 0, sizeof (struct GNUNET_CS_chat_client));
  tempClient->next = client_list_head;
  if (client_list_head != NULL)
    client_list_head->prev = tempClient;
  client_list_head = tempClient;
  tempClient->client = client;
  memcpy (&tempClient->room_name_hash, &room_name_hash,
          sizeof (GNUNET_HashCode));
  tempCount = 0;

  while (tempClient != NULL)
    {
      tempCount++;
      tempClient = tempClient->next;
    }

  fprintf (stderr, "Number of clients currently is... %d\n", tempCount);


  /* forward to all other TCP chat clients */
  /* marker to check if this is a new client */
  /*
     j = -1;
     for (i = 0; i < clientCount; i++)
     if (clients[i] == client)
     j = i;
     else
     coreAPI->cs_send_to_client (clients[i], message, GNUNET_YES);
     if (j == -1)
     {
     if (clientCount == MAX_CLIENTS)
     GNUNET_GE_LOG (ectx,
     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
     _("Maximum number of chat clients reached.\n"));
     else
     {
     GNUNET_array_grow (clients, clientCount, clientCount + 1);
     clients[clientCount] = client;
     ++clientCount;
     GNUNET_GE_LOG (ectx,
     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
     _("Now %d of %d chat clients at this node.\n"),
     clientCount, MAX_CLIENTS);
     }
     }
   */

  /* forward to all other nodes in the network */

  GNUNET_free (nick);
  GNUNET_free (client_key);
  GNUNET_free (room_name);

  GNUNET_mutex_unlock (chatMutex);
  fprintf (stderr, "End of handleChatRequest\n");
  return GNUNET_OK;
}


static void
chatClientExitHandler (struct GNUNET_ClientHandle *client)
{
  int tempCount;

  struct GNUNET_CS_chat_client *tempClient;
  struct GNUNET_CS_chat_client *pos;
  struct GNUNET_CS_chat_client *prev;

  /*client_key = GNUNET_malloc (sizeof (GNUNET_RSA_PublicKey));
     memcpy (client_key, &cmsg->nick[nick_len], pubkey_len); */

  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_DEVELOPER,
                 "Received leave chat room message from client.\n");


  GNUNET_mutex_lock (chatMutex);

  /*TODO: delete client context on the server */
  pos = client_list_head;
  prev = NULL;
  while ((pos != NULL) && (pos->client != client))
    {
      prev = pos;
      pos = pos->next;
    }
  if (pos != NULL)
    {
      if (prev == NULL)
        client_list_head = pos->next;
      else
        prev->next = pos->next;
      if (pos->next != NULL)
        pos->next->prev = pos->prev;
      GNUNET_free (pos);
    }
  /*Count the number of current clients, will be removed */

  tempClient = client_list_head;
  tempCount = 0;
  while (tempClient != NULL)
    {
      tempCount++;
      tempClient = tempClient->next;
    }
  fprintf (stderr, "Number of clients currently is... %d\n", tempCount);


  GNUNET_mutex_unlock (chatMutex);
  fprintf (stderr, "End of handleChatLeave\n");
  return;
}


int
initialize_module_chat (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;

  GNUNET_GE_ASSERT (ectx,
                    sizeof (P2P_chat_MESSAGE) == sizeof (CS_chat_MESSAGE));
  chatMutex = GNUNET_mutex_create (GNUNET_NO);

  coreAPI = capi;
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering handlers %d and %d\n"),
                 "chat", GNUNET_P2P_PROTO_CHAT_MSG, GNUNET_CS_PROTO_CHAT_MSG);

  /*if (GNUNET_SYSERR ==
     capi->registerHandler (GNUNET_P2P_PROTO_CHAT_MSG, &handleChatMSG))
     ok = GNUNET_SYSERR; */
  if (GNUNET_SYSERR ==
      capi->cs_exit_handler_register (&chatClientExitHandler))
    ok = GNUNET_SYSERR;

  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_CHAT_JOIN_MSG,
                                   &csHandleChatJoinRequest))
    ok = GNUNET_SYSERR;

  if (GNUNET_SYSERR == capi->registerClientHandler (GNUNET_CS_PROTO_CHAT_MSG,
                                                    &csHandleChatMSG))
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
  /*coreAPI->unregisterHandler (GNUNET_P2P_PROTO_CHAT_MSG, &handleChatMSG); */
  coreAPI->cs_exit_handler_unregister (&chatClientExitHandler);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_CHAT_MSG,
                                    &csHandleChatMSG);
  coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_CHAT_JOIN_MSG,
                                    &csHandleChatJoinRequest);

  GNUNET_mutex_destroy (chatMutex);
  coreAPI = NULL;
}


/* end of chat.c */
