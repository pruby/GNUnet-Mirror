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
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_chat_lib.h"
#include "chat.h"

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

  const GNUNET_RSA_PublicKey *my_public_key;

  const struct GNUNET_RSA_PrivateKey *my_private_key;

  char *memberInfo;

  GNUNET_CHAT_MessageCallback callback;

  void *callback_cls;

};

static void *
thread_main (void *rcls)
{
  struct GNUNET_CHAT_Room *room = rcls;
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
                       const GNUNET_RSA_PublicKey * me,
                       const struct GNUNET_RSA_PrivateKey *key,
                       const char *memberInfo,
                       GNUNET_CHAT_MessageCallback callback, void *cls)
{
  CS_chat_MESSAGE *chat_msg;	 
  GNUNET_MessageHeader csHdr;
  struct GNUNET_CHAT_Room *chat_room;
  struct GNUNET_ClientServerConnection *sock;
  
  int ret;

  ret = GNUNET_OK;
  csHdr.size = htons (sizeof (GNUNET_MessageHeader));
  csHdr.type = htons (GNUNET_CS_PROTO_CHAT_MSG);
  
  sock = GNUNET_client_connection_create(ectx,cfg);
  
  if (sock == NULL)
  {
    fprintf (stderr, _("Error establishing connection with gnunetd.\n"));
    ret = GNUNET_SYSERR;
  }

  if (GNUNET_SYSERR == GNUNET_client_connection_write (sock, &csHdr))
  {
  	fprintf (stderr, _("Error writing to socket.\n"));
    ret = GNUNET_SYSERR;
  }
    
  chat_msg = GNUNET_malloc (sizeof (CS_chat_MESSAGE));
  
  // connect

  // allocate & init room struct
  chat_room = GNUNET_malloc(sizeof(struct GNUNET_CHAT_Room));
  chat_room->nickname = GNUNET_malloc(sizeof(nickname));
  strncpy(chat_room->nickname,nickname,sizeof(nickname));
  chat_room->my_public_key = me;
  chat_room->my_private_key = key;
  chat_room->callback = callback;
  chat_room->callback_cls = cls;
  chat_room->ectx = ectx;
  chat_room->cfg = cfg;
  chat_room->memberInfo = GNUNET_malloc(sizeof(memberInfo));
  strncpy(chat_room->memberInfo,memberInfo,sizeof(memberInfo));
  chat_room->sock = sock;

  // create pthread

  // return room struct
  if (ret != GNUNET_OK)
  	return NULL;
  	
  return chat_room;
}

/**
 * Leave a chat room.
 */
void
GNUNET_CHAT_leave_room (struct GNUNET_CHAT_Room *room)
{
  // stop thread
  // join thread
  // free room struct
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
  return GNUNET_SYSERR;
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
