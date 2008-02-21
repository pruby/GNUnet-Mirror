/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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

#define MAX_RETRIES 5

/**
 * Handle for a (joined) chat room.
 */
struct GNUNET_CHAT_Room
{
  struct GNUNET_ClientServerConnection *sock;

  struct GNUNET_ThreadHandle *listen_thread;

  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  char *nickname;

  char *room_name;

  GNUNET_HashCode room_name_hash;

  const GNUNET_RSA_PublicKey *my_public_key;

  GNUNET_HashCode my_public_key_hash;

  const struct GNUNET_RSA_PrivateKey *my_private_key;

  char *memberInfo;

  GNUNET_CHAT_MessageCallback callback;

  void *callback_cls;

};

/**
 * Listen for incoming messages on this chat room.  When received, call the client callback.
 * Also, support servers going away/coming back (i.e. rejoin chat room to keep server state up to date)... 
 */
static void *
poll_thread (void *rcls)
{
  struct GNUNET_CHAT_Room *room = rcls;
  int ret;
  GNUNET_MessageHeader *reply;
  CS_chat_MESSAGE *received_msg;
  unsigned int size;
  unsigned int nick_len;
  unsigned int msg_len;
  unsigned int room_name_len;
  unsigned int retries;
  char *nick;
  char *message_content;
  char *room_name;

  ret = GNUNET_OK;
  /* CHECK FOR SHUTDOWN! */
  while (room->shutdown_flag != GNUNET_YES)
    {
      if (disconnected)
	{
	  if (GNUNET_client_connection_ensure_connected (room->sock) == GNUNET_OK)
	    {
	      disconnected = 0;
	      /* send join! */
	    }
	  else
	    {
	      GNUNET_thread_sleep(5 * GNUNET_CRON_SECONDS);
	      continue;
            }
        }

      reply = NULL;

      if (GNUNET_OK != GNUNET_client_connection_read (room->sock, &reply))
	{
	  disconnected = GNUNET_YES;
	  continue;
	}

      if ((reply->size <
           ntohs (sizeof (GNUNET_MessageHeader) + sizeof (CS_chat_MESSAGE)))
          || (reply->type != ntohs (GNUNET_CS_PROTO_CHAT_MSG)))
	{
	  GNUNET_GE_BREAK(NULL, 0);
	  GNUNET_client_connection_close_temporarily(room->sock);
	  disconnected = GNUNET_YES;
	  continue;
	}

      size = ntohs (reply->size);

      received_msg = (CS_chat_MESSAGE *) reply;

      nick_len = ntohl (received_msg->nick_len);
      msg_len = ntohl (received_msg->msg_len);
      /* NO NEED TO SEND ROOM! */
      room_name_len = ntohl (received_msg->room_name_len);

      nick = GNUNET_malloc (nick_len + 1);
      message_content = GNUNET_malloc (msg_len + 1);
      room_name = GNUNET_malloc (room_name_len + 1);

      /* BUFFER OVERFLOWS! */
      memcpy (nick, &received_msg->nick[0], nick_len);
      memcpy (message_content, &received_msg->nick[nick_len], msg_len);
      memcpy (room_name, &received_msg->nick[nick_len + msg_len],
              room_name_len);

      nick[nick_len] = '\0';
      message_content[msg_len] = '\0';
      room_name[room_name_len] = '\0';

      if (GNUNET_OK !=
          room->callback (room->callback_cls, room, nick, message_content,
                          GNUNET_get_time (), 0))
        {
          ret = GNUNET_SYSERR;
        }

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
  GNUNET_MessageHeader csHdr;

  GNUNET_HashCode hash_of_me;
  GNUNET_HashCode hash_of_room_name;

  struct GNUNET_CHAT_Room *chat_room;
  struct GNUNET_ClientServerConnection *sock;

  int size_of_join;

  csHdr.size = htons (sizeof (CS_chat_JOIN_MESSAGE));
  csHdr.type = htons (GNUNET_CS_PROTO_CHAT_JOIN_MSG);

  sock = GNUNET_client_connection_create (ectx, cfg);

  if (sock == NULL)
    {
      fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
      return NULL;
    }

  // connect
  GNUNET_hash (me, sizeof (GNUNET_RSA_PublicKey), &hash_of_me);
  GNUNET_hash (room_name, strlen (room_name), &hash_of_room_name);

  size_of_join =
    sizeof (CS_chat_JOIN_MESSAGE) + strlen (nickname) +
    sizeof (GNUNET_RSA_PublicKey) + strlen (room_name);
  join_msg = GNUNET_malloc (size_of_join);

  join_msg->nick_len = htonl (strlen (nickname));
  join_msg->pubkey_len = htonl (sizeof (GNUNET_RSA_PublicKey));
  join_msg->room_name_len = htonl (strlen (room_name));


  memcpy (&join_msg->nick[0], nickname, strlen (nickname));
  memcpy (&join_msg->nick[strlen (nickname)], me,
          sizeof (GNUNET_RSA_PublicKey));
  memcpy (&join_msg->nick[strlen (nickname) + sizeof (GNUNET_RSA_PublicKey)],
          room_name, strlen (room_name));

  join_msg->header = csHdr;
  join_msg->header.size = htons (size_of_join);

  if (GNUNET_SYSERR ==
      GNUNET_client_connection_write (sock, &join_msg->header))
    {
      /* ALREADY LOGGED */
      fprintf (stderr, _("Error writing to socket.\n"));
      GNUNET_free(join_msg);
      return NULL;
    }

  GNUNET_free (join_msg);

  // allocate & init room struct
  chat_room = GNUNET_malloc (sizeof (struct GNUNET_CHAT_Room));
  chat_room->nickname = GNUNET_malloc (strlen (nickname) + 1);
  strncpy (chat_room->nickname, nickname, strlen (nickname) + 1);

  chat_room->room_name = GNUNET_malloc (strlen (room_name) + 1);
  strncpy (chat_room->room_name, room_name, strlen (room_name) + 1);

  chat_room->room_name_hash = hash_of_room_name;
  chat_room->my_public_key = me;
  chat_room->my_public_key_hash = hash_of_me;
  chat_room->my_private_key = key;
  chat_room->callback = callback;
  chat_room->callback_cls = cls;
  chat_room->ectx = ectx;
  chat_room->cfg = cfg;
  chat_room->memberInfo = GNUNET_malloc (strlen (memberInfo) + 1);
  strncpy (chat_room->memberInfo, memberInfo, strlen (memberInfo) + 1);
  chat_room->sock = sock;

  // create pthread
  chat_room->listen_thread =
    GNUNET_thread_create (&poll_thread, chat_room, 1024 * 2);

  return chat_room;
}

/**
 * Leave a chat room.
 */
void
GNUNET_CHAT_leave_room (struct GNUNET_CHAT_Room *chat_room)
{
  void * unused;
  chat_room->shutdown_flag = GNUNET_YES;
  GNUNET_client_connection_close_forever (chat_room->sock);
  GNUNET_stop_sleep(room->listen_thread);
  GNUNET_pthread_join(room->listen_thread, &unused);
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
    htons (sizeof (GNUNET_MessageHeader) + sizeof (CS_chat_MESSAGE) +
           strlen (room->nickname) + strlen (message) +
           strlen (room->room_name));
  cs_msg_hdr.type = htons (GNUNET_CS_PROTO_CHAT_MSG);

  msg_to_send = GNUNET_malloc (ntohl (cs_msg_hdr.size));

  msg_to_send->nick_len = htonl (strlen (room->nickname));
  msg_to_send->msg_len = htonl (strlen (message));
  msg_to_send->room_name_len = htonl (strlen (room->room_name));

  memcpy (&msg_to_send->nick[0], room->nickname, strlen (room->nickname));
  memcpy (&msg_to_send->nick[strlen (room->nickname)], message,
          strlen (message));
  memcpy (&msg_to_send->nick[strlen (room->nickname) + strlen (message)],
          room->room_name, strlen (room->room_name));

  /*fprintf(stderr,"sending message ---\n");
     fprintf(stderr,"nick: %s\nmessage:%s\nroom:%s\n",room->nickname,message,room->room_name); */

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
