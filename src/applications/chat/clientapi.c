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
  struct ClientServerConnection *sock;

  struct PTHREAD *listen_thread;

  struct GE_Context *ectx;

  struct GC_Configuration *cfg;

  char *nickname;

  const PublicKey *my_public_key;

  const struct PrivateKey *my_private_key;

  char *memberInfo;

  GNUNET_CHAT_Message_Callback callback;

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
 * @return number of rooms on success, SYSERR if iterator aborted
 */
int
GNUNET_CHAT_list_rooms (struct GE_Context *ectx,
                        struct GC_Configuration *cfg,
                        GNUNET_CHAT_Room_Iterator it, void *cls)
{
  return SYSERR;
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
GNUNET_CHAT_join_room (struct GE_Context *ectx,
                       struct GC_Configuration *cfg,
                       const char *nickname,
                       const PublicKey * me,
                       const struct PrivateKey *key,
                       const char *memberInfo,
                       GNUNET_CHAT_Message_Callback callback, void *cls)
{
  // connect

  // allocate & init room struct

  // create pthread

  // return room struct
  return NULL;
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
 * @return OK on success, SYSERR on error
 */
int
GNUNET_CHAT_send_message (struct GNUNET_CHAT_Room *room,
                          const char *message,
                          GNUNET_CHAT_Message_Confirmation callback,
                          void *cls,
                          GNUNET_CHAT_MSG_OPTIONS options,
                          const PublicKey * receiver)
{
  return SYSERR;
}

/**
 * List all of the (known) chat members.
 * @return number of rooms on success, SYSERR if iterator aborted
 */
int
GNUNET_CHAT_list_members (struct GNUNET_CHAT_Room *room,
                          GNUNET_CHAT_Member_Iterator it, void *cls)
{
  return SYSERR;
}


/* end of clientapi.c */
