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

/**
 * Linked list of our current clients.
 */
struct GNUNET_CS_chat_client
{
  struct GNUNET_CS_chat_client *next;

  struct GNUNET_ClientHandle *client;

  char *nick;

  char *room;
};

static struct GNUNET_CS_chat_client *client_list_head;

static GNUNET_CoreAPIForPlugins *coreAPI;

static struct GNUNET_Mutex *chatMutex;

/**
 * Tell clients about change in chat room members
 * 
 * @param has_joined GNUNET_YES if the member joined,
 *                   GNUNET_NO if the member left
 */
static void
update_client_members (const char * room_name,
		       const char * nick,
		       int has_joined)
{
  struct GNUNET_CS_chat_client *pos;
  struct GNUNET_CS_chat_client *compare_pos;
  CS_chat_ROOM_MEMBER_MESSAGE *message;
  unsigned int message_size;

  message_size =
    sizeof (CS_chat_ROOM_MEMBER_MESSAGE) +
    strlen (nick);
  message = GNUNET_malloc (message_size);
  message->header.size = htons (message_size);
  message->header.type =
    htons (GNUNET_CS_PROTO_CHAT_ROOM_MEMBER_MESSAGE);
  message->nick_len = htons (strlen (nick));
  memcpy (&message[1],
	  nick,
	  strlen (nick));
  GNUNET_mutex_lock (chatMutex);
  pos = client_list_head;
  while (pos != NULL)
    {
      if (0 != strcmp(pos->room,
		      room_name))
	{
	  pos = pos->next;
	  continue;
	}
      coreAPI->cs_send_message (pos->client, &message->header,
				GNUNET_YES);      
      pos = pos->next;
    }
  GNUNET_mutex_unlock (chatMutex);
  GNUNET_free(message);  
}


static int
csHandleChatMSG (struct GNUNET_ClientHandle *client,
                 const GNUNET_MessageHeader * message)
{
  const CS_chat_MESSAGE *cmsg;
  struct GNUNET_CS_chat_client *pos;
  const char *nick;
  const char *room;
  unsigned short header_size;
  unsigned long msg_len;

  if (ntohs (message->size) < sizeof (CS_chat_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;     /* invalid message */
    }
  cmsg = (const CS_chat_MESSAGE *) message;
  GNUNET_mutex_lock (chatMutex);

  pos = client_list_head;
  while ((pos != NULL) && (pos->client != client))
    pos = pos->next;
  if (pos == NULL)
    {
      GNUNET_mutex_unlock (chatMutex);
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;     /* not member of chat room! */
    }
  room = pos->room;
  nick = pos->nick;
  pos = client_list_head;
  while (pos != NULL) 
    {
      if (0 == strcmp(room,
		      pos->room))
	coreAPI->cs_send_message (pos->client, message, GNUNET_YES);
      pos = pos->next;
    }
  GNUNET_mutex_unlock (chatMutex);
  return GNUNET_OK;
}

static int
csHandleChatJoinRequest (struct GNUNET_ClientHandle *client,
                         const GNUNET_MessageHeader * message)
{
  const CS_chat_JOIN_MESSAGE *cmsg;
  char *nick;
  char *room_name;
  int header_size;
  int nick_len;
  int room_name_len;
  struct GNUNET_CS_chat_client *entry;

  if (ntohs (message.size) < sizeof (CS_chat_JOIN_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;     /* invalid message */
    }
  cmsg = (const CS_chat_JOIN_MESSAGE *) message;
  header_size = ntohs (cmsg->header.size);
  nick_len = ntohs (cmsg->nick_len);
  if (header_size - sizeof (CS_chat_JOIN_MESSAGE) <= nick_len)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  room_name_len = header_size - sizeof (CS_chat_JOIN_MESSAGE) - nick_len;
  nick = GNUNET_malloc (nick_len + 1);
  memcpy (nick, &cmsg->nick[0], nick_len);
  nick[nick_len] = '\0';
  room_name = GNUNET_malloc (room_name_len + 1);
  memcpy (room_name, &cmsg->nick[nick_len], room_name_len);
  room_name[room_name_len] = '\0';
  entry = GNUNET_malloc (sizeof (struct GNUNET_CS_chat_client));
  memset (entry, 0, sizeof (struct GNUNET_CS_chat_client));
  entry->client = client;
  entry->nick = nick;
  entry->room = room_name; 
  GNUNET_mutex_lock (chatMutex);
  entry->next = client_list_head;
  client_list_head = entry;
  GNUNET_mutex_unlock (chatMutex);
  update_client_members (room_name, nick, GNUNET_YES);
  return GNUNET_OK;
}


static void
chatClientExitHandler (struct GNUNET_ClientHandle *client)
{
  int tempCount;
  int message_size;
  struct GNUNET_CS_chat_client *entry;
  struct GNUNET_CS_chat_client *pos;
  struct GNUNET_CS_chat_client *prev;
  char *nick_to_remove;
  CS_chat_ROOM_MEMBER_MESSAGE *message;

  GNUNET_mutex_lock (chatMutex);
  pos = client_list_head;
  prev = NULL;
  while ((pos != NULL) && (pos->client != client))
    {
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      GNUNET_mutex_unlock (chatMutex);
      return; /* nothing to do */
    }
  if (prev == NULL)
    client_list_head = pos->next;
  else
    prev->next = pos->next;
  GNUNET_mutex_unlock (chatMutex);
  update_client_members(pos->room,
			pos->nick,
			GNUNET_NO);
  GNUNET_free (pos->room);
  GNUNET_free (pos->nick);
  GNUNET_free (pos);
}

int
initialize_module_chat (GNUNET_CoreAPIForPlugins * capi)
{
  int ok = GNUNET_OK;

  coreAPI = capi;
  GNUNET_GE_LOG (capi->ectx, 
		 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering CS handlers %d and %d\n"),
                 "chat", 
		 GNUNET_CS_PROTO_CHAT_JOIN_MSG, GNUNET_CS_PROTO_CHAT_MSG);

  if (GNUNET_SYSERR ==
      capi->cs_disconnect_handler_register (&chatClientExitHandler))
    ok = GNUNET_SYSERR;  
  if (GNUNET_SYSERR ==
      capi->cs_handler_register (GNUNET_CS_PROTO_CHAT_JOIN_MSG,
                                 &csHandleChatJoinRequest))
    ok = GNUNET_SYSERR;
  if (GNUNET_SYSERR == capi->cs_handler_register (GNUNET_CS_PROTO_CHAT_MSG,
                                                  &csHandleChatMSG))
    ok = GNUNET_SYSERR;
  GNUNET_GE_ASSERT (capi->coreAPI->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "chat",
                                                                   _
                                                                   ("enables P2P-chat (incomplete)")));
  chatMutex = GNUNET_mutex_create (GNUNET_NO);
  return ok;
}

void
done_module_chat ()
{
  coreAPI->cs_disconnect_handler_unregister (&chatClientExitHandler);
  coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_CHAT_MSG, &csHandleChatMSG);
  coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_CHAT_JOIN_MSG,
                                  &csHandleChatJoinRequest);
  GNUNET_mutex_destroy (chatMutex);
  coreAPI = NULL;
}


/* end of chat.c */
