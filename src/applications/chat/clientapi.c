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
 * @file applications/chat/clientapi.c
 * @brief convenience API to the chat application
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_chat_lib.h"
#include "chat.h"

/**
 * Listen for incoming messages on this chat room.  When received,
 * call the client callback.  Also, support servers going away/coming
 * back (i.e. rejoin chat room to keep server state up to date)...
 */
static void *
poll_thread (void *rcls)
{
  struct GNUNET_CHAT_Room *room = rcls;
  GNUNET_MessageHeader *reply;
  CS_chat_MESSAGE *received_msg;
  unsigned int size;
  unsigned int nick_len;
  unsigned int msg_len;
  unsigned int room_name_len;
  char *nick;
  char *message_content;
  int disconnected;
  int ret;

  disconnected = GNUNET_NO;
  ret = GNUNET_OK;
  while ( (ret == GNUNET_OK) &&
	  (room->shutdown_flag != GNUNET_YES) )
    {
      if (disconnected)
        {
          GNUNET_thread_sleep (15 * GNUNET_CRON_SECONDS);
          if (GNUNET_client_connection_ensure_connected (room->sock) ==
              GNUNET_OK)
            {
              /* send join! */
              disconnected = GNUNET_NO;
              GNUNET_CHAT_rejoin_room (room);
              continue;
            }
          else
            break;
        }
      reply = NULL;
      if (GNUNET_OK != GNUNET_client_connection_read (room->sock, &reply))
        {
          disconnected = GNUNET_YES;
          continue;
        }

      if ((reply->size <
           ntohs (sizeof (CS_chat_MESSAGE)))
          || (reply->type != ntohs (GNUNET_CS_PROTO_CHAT_MSG)))
        {
          GNUNET_GE_BREAK (NULL, 0);
          GNUNET_client_connection_close_temporarily (room->sock);
          disconnected = GNUNET_YES;
          continue;
        }
      size = ntohs (reply->size);
      received_msg = (CS_chat_MESSAGE *) reply;
      nick_len = ntohs (received_msg->nick_len);
      msg_len = ntohs (received_msg->msg_len);
      /* NO NEED TO SEND ROOM! */
      room_name_len = size - nick_len - msg_len - sizeof (CS_chat_MESSAGE);
      if (size < (nick_len + msg_len + room_name_len))
        {
          GNUNET_GE_BREAK (NULL, 0);
          GNUNET_client_connection_close_temporarily (room->sock);
	  disconnected = GNUNET_YES;
	  continue;
        }
      nick = GNUNET_malloc (nick_len + 1);
      memcpy (nick, &received_msg->nick[0], nick_len);
      nick[nick_len] = '\0';
      message_content = GNUNET_malloc (msg_len + 1);
      memcpy (message_content, &received_msg->nick[nick_len], msg_len);
      message_content[msg_len] = '\0';
      if (GNUNET_OK !=
          room->callback (room->callback_cls, room, nick, message_content,
                          GNUNET_get_time (), 0))
	ret = GNUNET_SYSERR;
      GNUNET_free(nick);
      GNUNET_free(message_content);
    }
  return NULL;
}


/**
 * List all of the (publically visible) chat rooms.
 * @return number of rooms on success, GNUNET_SYSERR if iterator aborted
 */
int
GNUNET_CHAT_list_rooms (struct GNUNET_GE_Context *ectx,
                        struct GNUNET_GC_Configuration *cfg,
                        GNUNET_CHAT_RoomIterator it, void *cls)
{
  return GNUNET_SYSERR;
}

/**
 * Join a chat room.
 *
 * @param nickname the nick you want to use
 * @param memberInfo public information about you
 * @param callback which function to call if a message has
 *        been received?
 * @param cls argument to callback
 * @return NULL on error
 */
struct GNUNET_CHAT_Room *
GNUNET_CHAT_join_room (struct GNUNET_GE_Context *ectx,
                       struct GNUNET_GC_Configuration *cfg,
                       const char *nickname,
                       const char *room_name,
                       const GNUNET_RSA_PublicKey * me,
                       const struct GNUNET_RSA_PrivateKey *key,
                       const char *memberInfo,
                       GNUNET_CHAT_MessageCallback callback, void *cls)
{
  CS_chat_JOIN_MESSAGE *join_msg;
  GNUNET_HashCode hash_of_me;
  GNUNET_HashCode hash_of_room_name;
  struct GNUNET_CHAT_Room *chat_room;
  struct GNUNET_ClientServerConnection *sock;
  int size_of_join;

  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
      return NULL;
    }

  GNUNET_hash (me, sizeof (GNUNET_RSA_PublicKey), &hash_of_me);
  GNUNET_hash (room_name, strlen (room_name), &hash_of_room_name);
  size_of_join =
    sizeof (CS_chat_JOIN_MESSAGE) + strlen (nickname) +
    sizeof (GNUNET_RSA_PublicKey) + strlen (room_name);
  join_msg = GNUNET_malloc (size_of_join);
  join_msg->header.size = htons (size_of_join);
  join_msg->header.type = htons (GNUNET_CS_PROTO_CHAT_JOIN_MSG);
  join_msg->nick_len = htons (strlen (nickname));
  join_msg->pubkey_len = htons (sizeof (GNUNET_RSA_PublicKey));
  memcpy (&join_msg->nick[0], nickname, strlen (nickname));
  memcpy (&join_msg->nick[strlen (nickname)], me,
          sizeof (GNUNET_RSA_PublicKey));
  memcpy (&join_msg->nick[strlen (nickname) + sizeof (GNUNET_RSA_PublicKey)],
          room_name, strlen (room_name));
  if (GNUNET_SYSERR ==
      GNUNET_client_connection_write (sock, &join_msg->header))
    {
      /* ALREADY LOGGED */
      fprintf (stderr, _("Error writing to socket.\n"));
      GNUNET_client_connection_destroy(sock);
      GNUNET_free (join_msg);
      return NULL;
    }
  GNUNET_free (join_msg);
  chat_room = GNUNET_malloc (sizeof (struct GNUNET_CHAT_Room));
  chat_room->nickname = GNUNET_strdup(nickname);
  chat_room->room_name = GNUNET_strdup(room_name);
  chat_room->room_name_hash = hash_of_room_name;
  chat_room->my_public_key = me;
  chat_room->my_public_key_hash = hash_of_me;
  chat_room->my_private_key = key;
  chat_room->callback = callback;
  chat_room->callback_cls = cls;
  chat_room->ectx = ectx;
  chat_room->cfg = cfg;
  chat_room->memberInfo = GNUNET_strdup(memberInfo);
  chat_room->sock = sock;
  chat_room->listen_thread =
    GNUNET_thread_create (&poll_thread, chat_room, 1024 * 2);
  return chat_room;
}

int
GNUNET_CHAT_rejoin_room (struct GNUNET_CHAT_Room *chat_room)
{
  CS_chat_JOIN_MESSAGE *join_msg;
  GNUNET_MessageHeader csHdr;
  GNUNET_HashCode hash_of_me;
  GNUNET_HashCode hash_of_room_name;
  int size_of_join;

  csHdr.size = htons (sizeof (CS_chat_JOIN_MESSAGE));
  csHdr.type = htons (GNUNET_CS_PROTO_CHAT_JOIN_MSG);

  GNUNET_hash (chat_room->my_public_key, sizeof (GNUNET_RSA_PublicKey),
               &hash_of_me);
  GNUNET_hash (chat_room->room_name, strlen (chat_room->room_name),
               &hash_of_room_name);
  size_of_join =
    sizeof (CS_chat_JOIN_MESSAGE) + strlen (chat_room->nickname) +
    sizeof (GNUNET_RSA_PublicKey) + strlen (chat_room->room_name);
  join_msg = GNUNET_malloc (size_of_join);
  join_msg->nick_len = htons (strlen (chat_room->nickname));
  join_msg->pubkey_len = htons (sizeof (GNUNET_RSA_PublicKey));
  memcpy (&join_msg->nick[0], chat_room->nickname,
          strlen (chat_room->nickname));
  memcpy (&join_msg->nick[strlen (chat_room->nickname)],
          chat_room->my_public_key, sizeof (GNUNET_RSA_PublicKey));
  memcpy (&join_msg->
          nick[strlen (chat_room->nickname) + sizeof (GNUNET_RSA_PublicKey)],
          chat_room->room_name, strlen (chat_room->room_name));
  join_msg->header = csHdr;
  join_msg->header.size = htons (size_of_join);
  if (GNUNET_SYSERR ==
      GNUNET_client_connection_write (chat_room->sock, &join_msg->header))
    {
      GNUNET_free (join_msg);
      return GNUNET_SYSERR;
    }

  GNUNET_free (join_msg);
  return GNUNET_OK;
}

/**
 * Leave a chat room.
 */
void
GNUNET_CHAT_leave_room (struct GNUNET_CHAT_Room *chat_room)
{
  void *unused;
  chat_room->shutdown_flag = GNUNET_YES;
  GNUNET_client_connection_close_forever (chat_room->sock);
  GNUNET_thread_stop_sleep (chat_room->listen_thread);
  GNUNET_thread_join (chat_room->listen_thread, &unused);
  GNUNET_free (chat_room->room_name);
  GNUNET_free (chat_room->nickname);
  GNUNET_free (chat_room->memberInfo);
  GNUNET_client_connection_destroy (chat_room->sock);
  GNUNET_free (chat_room);
}

/**
 * Send a message.
 *
 * @param receiver use NULL to send to everyone in the room
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CHAT_send_message (struct GNUNET_CHAT_Room *room,
                          const char *message,
                          GNUNET_CHAT_MessageConfirmation callback,
                          void *cls,
                          GNUNET_CHAT_MSG_OPTIONS options,
                          const GNUNET_RSA_PublicKey * receiver)
{
  int ret = GNUNET_OK;
  GNUNET_MessageHeader cs_msg_hdr;
  CS_chat_MESSAGE *msg_to_send;

  cs_msg_hdr.size =
    htons (sizeof (CS_chat_MESSAGE) +
           strlen (room->nickname) + strlen (message) +
           strlen (room->room_name));
  cs_msg_hdr.type = htons (GNUNET_CS_PROTO_CHAT_MSG);
  msg_to_send = GNUNET_malloc (ntohs (cs_msg_hdr.size));
  msg_to_send->nick_len = htons (strlen (room->nickname));
  msg_to_send->msg_len = htons (strlen (message));
  memcpy (&msg_to_send->nick[0], room->nickname, strlen (room->nickname));
  memcpy (&msg_to_send->nick[strlen (room->nickname)], message,
          strlen (message));
  memcpy (&msg_to_send->nick[strlen (room->nickname) + strlen (message)],
          room->room_name, strlen (room->room_name));
  msg_to_send->header = cs_msg_hdr;
  if (GNUNET_SYSERR ==
      GNUNET_client_connection_write (room->sock, &msg_to_send->header))
    {
      fprintf (stderr, _("Error writing to socket.\n"));
      ret = GNUNET_SYSERR;
    }

  return ret;
}

/**
 * List all of the (known) chat members.
 * @return number of rooms on success, GNUNET_SYSERR if iterator aborted
 */
int
GNUNET_CHAT_list_members (struct GNUNET_CHAT_Room *room,
                          GNUNET_CHAT_MemberIterator it, void *cls)
{
  return GNUNET_SYSERR;
}

/* end of clientapi.c */
