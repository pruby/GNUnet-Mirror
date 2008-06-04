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
 * @file applications/chat/lib/messaging.c
 * @brief convenience API for sending and receiving chat messages
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_chat_lib.h"
#include "gnunet_directories.h"
#include "chat.h"

#define NICK_IDENTITY_PREFIX ".chat_identity_"

/**
 * Handle for a (joined) chat room.
 */
struct GNUNET_CHAT_Room
{
  struct GNUNET_ClientServerConnection *sock;

  struct GNUNET_ThreadHandle *listen_thread;

  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  struct GNUNET_MetaData *member_info;

  char *room_name;

  GNUNET_RSA_PrivateKeyEncoded *my_private_key;

  GNUNET_CHAT_MessageCallback message_callback;

  void *message_callback_cls;

  GNUNET_CHAT_MemberListCallback member_list_callback;

  void *member_list_callback_cls;

  GNUNET_CHAT_MessageConfirmation confirmation_callback;

  void *confirmation_cls;

  int shutdown_flag;

  unsigned int sequence_number;

  unsigned int msg_options;

};

/**
 * Linked list of members in the chat room.
 */
struct MemberList
{
  struct MemberList *next;

  /**
   * Description of the member.
   */
  struct GNUNET_MetaData *meta;

  /**
   * Member ID (pseudonym).
   */
  GNUNET_HashCode id;

};

static int
GNUNET_CHAT_rejoin_room (struct GNUNET_CHAT_Room *chat_room)
{
  CS_chat_MESSAGE_JoinRequest *join_msg;
  unsigned int size_of_join;
  unsigned int room_len;
  unsigned int meta_len;
  char *room;

  meta_len =
    GNUNET_meta_data_get_serialized_size (chat_room->member_info, GNUNET_YES);
  room_len = strlen (chat_room->room_name);
  size_of_join = sizeof (CS_chat_MESSAGE_JoinRequest) + meta_len
    + room_len + ntohs (chat_room->my_private_key->len) -
    sizeof (GNUNET_RSA_PrivateKeyEncoded);
  if (size_of_join >= GNUNET_MAX_BUFFER_SIZE - 8)
    return GNUNET_SYSERR;
  join_msg = GNUNET_malloc (size_of_join);
  join_msg->header.size = htons (size_of_join);
  join_msg->header.type = htons (GNUNET_CS_PROTO_CHAT_JOIN_REQUEST);
  join_msg->msg_options = htonl (chat_room->msg_options);
  join_msg->room_name_len = htons (room_len);
  join_msg->reserved = htons (0);
  memcpy (&join_msg->private_key,
          chat_room->my_private_key, ntohs (chat_room->my_private_key->len));
  room = (char *) &join_msg[1];
  room +=
    ntohs (chat_room->my_private_key->len) -
    sizeof (GNUNET_RSA_PrivateKeyEncoded);
  memcpy (room, chat_room->room_name, room_len);
  if (GNUNET_SYSERR ==
      GNUNET_meta_data_serialize (chat_room->ectx,
                                  chat_room->member_info,
                                  &room[room_len], meta_len, GNUNET_YES))
    {
      GNUNET_free (join_msg);
      return GNUNET_SYSERR;
    }
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
 * Listen for incoming messages on this chat room.  When received,
 * call the proper client callback.  Also, support servers going
 * away/coming back (i.e. rejoin chat room to keep server state up to
 * date)...
 */
static void *
poll_thread (void *rcls)
{
  struct GNUNET_CHAT_Room *room = rcls;
  GNUNET_MessageHeader *reply;
  CS_chat_MESSAGE_ConfirmationReceipt *receipt;
  CS_chat_MESSAGE_LeaveNotification *leave_msg;
  CS_chat_MESSAGE_JoinNotification *join_msg;
  CS_chat_MESSAGE_ReceiveNotification *received_msg;
  GNUNET_HashCode id;
  struct GNUNET_MetaData *meta;
  struct MemberList *members;
  struct MemberList *pos;
  struct MemberList *prev;
  unsigned int size;
  unsigned int meta_len;
  unsigned int msg_len;
  char *message_content;
  int disconnected;
  int malformed;
  int ret;

  disconnected = GNUNET_NO;
  malformed = GNUNET_NO;
  ret = GNUNET_OK;
  reply = NULL;
  members = NULL;
  while ((ret == GNUNET_OK) && (room->shutdown_flag != GNUNET_YES))
    {
      if (malformed)
        {
          GNUNET_GE_BREAK (NULL, 0);
          GNUNET_client_connection_close_temporarily (room->sock);
          disconnected = GNUNET_YES;
          malformed = GNUNET_NO;
        }
      if (reply != NULL)
        {
          GNUNET_free (reply);
          reply = NULL;
        }
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
      size = ntohs (reply->size);
      switch (ntohs (reply->type))
        {
        case GNUNET_CS_PROTO_CHAT_JOIN_NOTIFICATION:
          if (size < sizeof (CS_chat_MESSAGE_JoinNotification))
            {
              malformed = GNUNET_YES;
              continue;
            }
          join_msg = (CS_chat_MESSAGE_JoinNotification *) reply;
          meta_len = size - sizeof (CS_chat_MESSAGE_JoinNotification);
          meta = GNUNET_meta_data_deserialize (room->ectx,
                                               (const char *)
                                               &join_msg[1], meta_len);
          if (meta == NULL)
            {
              malformed = GNUNET_YES;
              continue;
            }
          pos = GNUNET_malloc (sizeof (struct MemberList));
          pos->meta = meta;
          GNUNET_hash (&join_msg->public_key,
                       sizeof (GNUNET_RSA_PublicKey), &pos->id);
          GNUNET_pseudonym_add (room->ectx, room->cfg, &pos->id, meta);
          room->member_list_callback (room->member_list_callback_cls,
                                      meta, &join_msg->public_key,
                                      ntohl (join_msg->msg_options));
          pos->next = members;
          members = pos;
          break;
        case GNUNET_CS_PROTO_CHAT_LEAVE_NOTIFICATION:
          if (size < sizeof (CS_chat_MESSAGE_LeaveNotification))
            {
              malformed = GNUNET_YES;
              continue;
            }
          leave_msg = (CS_chat_MESSAGE_LeaveNotification *) reply;
          room->member_list_callback (room->member_list_callback_cls,
                                      NULL, &leave_msg->user,
                                      GNUNET_CHAT_MSG_OPTION_NONE);
          GNUNET_hash (&leave_msg->user, sizeof (GNUNET_RSA_PublicKey), &id);
          prev = NULL;
          pos = members;
          while ((pos != NULL) &&
                 (0 != memcmp (&pos->id, &id, sizeof (GNUNET_HashCode))))
            {
              prev = pos;
              pos = pos->next;
            }
          GNUNET_GE_ASSERT (NULL, pos != NULL);
          if (prev == NULL)
            members = pos->next;
          else
            prev->next = pos->next;
          GNUNET_meta_data_destroy (pos->meta);
          GNUNET_free (pos);
          break;
        case GNUNET_CS_PROTO_CHAT_MESSAGE_NOTIFICATION:
          if (size < sizeof (CS_chat_MESSAGE_ReceiveNotification))
            {
              malformed = GNUNET_YES;
              continue;
            }
          received_msg = (CS_chat_MESSAGE_ReceiveNotification *) reply;
          msg_len = size - sizeof (CS_chat_MESSAGE_ReceiveNotification);
          message_content = GNUNET_malloc (msg_len + 1);
          memcpy (message_content, &received_msg[1], msg_len);
          message_content[msg_len] = '\0';
          pos = members;
          while ((pos != NULL) &&
                 (0 != memcmp (&pos->id,
                               &received_msg->sender,
                               sizeof (GNUNET_HashCode))))
            pos = pos->next;
          GNUNET_GE_ASSERT (NULL, pos != NULL);
          room->message_callback (room->message_callback_cls,
                                  room,
                                  &received_msg->sender,
                                  pos->meta,
                                  message_content,
                                  ntohl (received_msg->msg_options));
          GNUNET_free (message_content);
          break;
        case GNUNET_CS_PROTO_CHAT_CONFIRMATION_RECEIPT:
          if (size < sizeof (CS_chat_MESSAGE_ConfirmationReceipt))
            {
              malformed = GNUNET_YES;
              continue;
            }
          receipt = (CS_chat_MESSAGE_ConfirmationReceipt *) reply;
          if (room->confirmation_callback != NULL)
            room->confirmation_callback (room->confirmation_cls,
                                         room,
                                         ntohl (receipt->sequence_number),
                                         GNUNET_ntohll (receipt->timestamp),
                                         &receipt->target,
                                         &receipt->content,
                                         &receipt->signature);
          break;
        default:
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
    }
  GNUNET_free_non_null (reply);
  while (members != NULL)
    {
      pos = members;
      members = pos->next;
      GNUNET_meta_data_destroy (pos->meta);
      GNUNET_free (pos);
    }
  return NULL;
}

/**
 * Returns the private key on success,
 * NULL on error.
 */
static GNUNET_RSA_PrivateKeyEncoded *
GNUNET_CHAT_initPrivateKey (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg,
                            const char *nick_name)
{
  char *gnHome;
  char *keyfile;
  GNUNET_RSA_PrivateKeyEncoded *encPrivateKey;
  struct GNUNET_RSA_PrivateKey *privKey;
  unsigned short len;
  int res;

  if (-1 == GNUNET_GC_get_configuration_value_filename (cfg,
                                                        "PATHS",
                                                        "GNUNET_HOME",
                                                        GNUNET_DEFAULT_HOME_DIRECTORY,
                                                        &gnHome))
    return NULL;
  GNUNET_disk_directory_create (ectx, gnHome);
  if (GNUNET_YES != GNUNET_disk_directory_test (ectx, gnHome))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_FATAL | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_IMMEDIATE,
                     _("Failed to access GNUnet home directory `%s'\n"),
                     gnHome);
      GNUNET_free (gnHome);
      return NULL;
    }

  /* read or create public key */
  keyfile =
    GNUNET_malloc (strlen (gnHome) + strlen (NICK_IDENTITY_PREFIX) +
                   strlen (nick_name) + 2);
  strcpy (keyfile, gnHome);
  GNUNET_free (gnHome);
  if (keyfile[strlen (keyfile) - 1] != DIR_SEPARATOR)
    strcat (keyfile, DIR_SEPARATOR_STR);
  strcat (keyfile, NICK_IDENTITY_PREFIX);
  strcat (keyfile, nick_name);

  res = 0;
  if (GNUNET_YES == GNUNET_disk_file_test (ectx, keyfile))
    {
      res =
        GNUNET_disk_file_read (ectx, keyfile, sizeof (unsigned short), &len);
    }
  encPrivateKey = NULL;
  if (res == sizeof (unsigned short))
    {
      encPrivateKey =
        (GNUNET_RSA_PrivateKeyEncoded *) GNUNET_malloc (ntohs (len));
      if (ntohs (len) !=
          GNUNET_disk_file_read (ectx, keyfile, ntohs (len), encPrivateKey))
        {
          GNUNET_free (encPrivateKey);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER |
                         GNUNET_GE_IMMEDIATE | GNUNET_GE_ADMIN,
                         _
                         ("Existing key in file `%s' failed format check, creating new key.\n"),
                         keyfile);
          encPrivateKey = NULL;
        }
    }
  if (encPrivateKey == NULL)
    {                           /* make new hostkey */
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _
                     ("Creating new key for this nickname (this may take a while).\n"));
      privKey = GNUNET_RSA_create_key ();
      GNUNET_GE_ASSERT (ectx, privKey != NULL);
      encPrivateKey = GNUNET_RSA_encode_key (privKey);
      GNUNET_GE_ASSERT (ectx, encPrivateKey != NULL);
      GNUNET_disk_file_write (ectx,
                              keyfile,
                              encPrivateKey, ntohs (encPrivateKey->len),
                              "600");
      GNUNET_RSA_free_key (privKey);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                     _("Done creating key.\n"));
    }
  GNUNET_free (keyfile);
  GNUNET_GE_ASSERT (ectx, encPrivateKey != NULL);
  return encPrivateKey;
}

/**
 * Join a chat room.
 *
 * @param nick_name nickname of the user joining (used to
 *                  determine which public key to use);
 *                  the nickname should probably also
 *                  be used in the member_info (as "EXTRACTOR_TITLE")
 * @param member_info information about the joining member
 * @param memberInfo public information about you
 * @param messageCallback which function to call if a message has
 *        been received?
 * @param message_cls argument to callback
 * @param memberCallback which function to call for join/leave notifications
 * @param confirmationCallback which function to call for confirmations (maybe NULL)
 * @return NULL on error
 */
struct GNUNET_CHAT_Room *
GNUNET_CHAT_join_room (struct GNUNET_GE_Context *ectx,
                       struct GNUNET_GC_Configuration *cfg,
                       const char *nick_name,
                       struct GNUNET_MetaData *member_info,
                       const char *room_name,
                       GNUNET_CHAT_MSG_OPTIONS msg_options,
                       GNUNET_CHAT_MessageCallback messageCallback,
                       void *message_cls,
                       GNUNET_CHAT_MemberListCallback memberCallback,
                       void *member_cls,
                       GNUNET_CHAT_MessageConfirmation confirmationCallback,
                       void *confirmation_cls, GNUNET_HashCode * me)
{
  struct GNUNET_CHAT_Room *chat_room;
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_RSA_PrivateKeyEncoded *key;
  struct GNUNET_RSA_PrivateKey *priv_key;
  GNUNET_RSA_PublicKey pub_key;

  key = GNUNET_CHAT_initPrivateKey (ectx, cfg, nick_name);
  if (key == NULL)
    return NULL;
  priv_key = GNUNET_RSA_decode_key (key);
  GNUNET_RSA_get_public_key (priv_key, &pub_key);
  GNUNET_hash (&pub_key, sizeof (GNUNET_RSA_PublicKey), me);
  GNUNET_pseudonym_add (ectx, cfg, me, member_info);
  GNUNET_RSA_free_key (priv_key);
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      GNUNET_free (key);
      return NULL;
    }
  chat_room = GNUNET_malloc (sizeof (struct GNUNET_CHAT_Room));
  chat_room->msg_options = msg_options;
  chat_room->room_name = GNUNET_strdup (room_name);
  chat_room->member_info = GNUNET_meta_data_duplicate (member_info);
  chat_room->my_private_key = key;
  chat_room->message_callback = messageCallback;
  chat_room->message_callback_cls = message_cls;
  chat_room->member_list_callback = memberCallback;
  chat_room->member_list_callback_cls = member_cls;
  chat_room->confirmation_callback = confirmationCallback;
  chat_room->confirmation_cls = confirmation_cls;
  chat_room->ectx = ectx;
  chat_room->cfg = cfg;
  chat_room->sock = sock;
  chat_room->listen_thread =
    GNUNET_thread_create (&poll_thread, chat_room, 1024 * 2);
  if (chat_room->listen_thread == NULL)
    {
      GNUNET_free (chat_room->room_name);
      GNUNET_client_connection_destroy (chat_room->sock);
      GNUNET_meta_data_destroy (chat_room->member_info);
      GNUNET_free (chat_room);
      GNUNET_free (key);
      return NULL;
    }
  if (GNUNET_SYSERR == GNUNET_CHAT_rejoin_room (chat_room))
    {
      GNUNET_CHAT_leave_room (chat_room);
      return NULL;
    }
  return chat_room;
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
  GNUNET_meta_data_destroy (chat_room->member_info);
  GNUNET_client_connection_destroy (chat_room->sock);
  GNUNET_free (chat_room->my_private_key);
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
                          GNUNET_CHAT_MSG_OPTIONS options,
                          const GNUNET_RSA_PublicKey * receiver,
                          unsigned int *sequence_number)
{
  int ret = GNUNET_OK;
  CS_chat_MESSAGE_TransmitRequest *msg_to_send;
  unsigned int msg_size;

  msg_size = strlen (message) + sizeof (CS_chat_MESSAGE_TransmitRequest);
  if (msg_size > GNUNET_MAX_BUFFER_SIZE - 8)
    return GNUNET_SYSERR;
  msg_to_send = GNUNET_malloc (msg_size);
  msg_to_send->header.size = htons (msg_size);
  msg_to_send->header.type = htons (GNUNET_CS_PROTO_CHAT_TRANSMIT_REQUEST);
  msg_to_send->msg_options = htonl (options);
  *sequence_number = room->sequence_number++;
  msg_to_send->sequence_number = htonl (*sequence_number);
  msg_to_send->reserved = htonl (0);
  if (receiver == NULL)
    memset (&msg_to_send->target, 0, sizeof (GNUNET_HashCode));
  else
    GNUNET_hash (receiver,
                 sizeof (GNUNET_RSA_PublicKey), &msg_to_send->target);
  memcpy (&msg_to_send[1], message, strlen (message));
  ret = GNUNET_client_connection_write (room->sock, &msg_to_send->header);
  GNUNET_free (msg_to_send);
  return ret;
}

/* end of messaging.c */
