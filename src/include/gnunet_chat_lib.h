/*
     This file is part of GNUnet
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
 * @file include/gnunet_chat_lib.h
 * @brief support for chat
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#ifndef GNUNET_CHAT_LIB_H
#define GNUNET_CHAT_LIB_H

#include "gnunet_util_core.h"
#include "gnunet_ecrs_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Version number.
 */
#define GNUNET_CHAT_VERSION "0.0.2"

typedef enum
{
  /**
   * No special options.
   */
  GNUNET_CHAT_MSG_OPTION_NONE = 0,

  /**
   * Encrypt the message so that only the
   * receiver can decrypt it.
   */
  GNUNET_CHAT_MSG_PRIVATE = 1,

  /**
   * Hide the identity of the sender.
   */
  GNUNET_CHAT_MSG_ANONYMOUS = 2,

  /**
   * Sign the content, authenticating the
   * sender (using the provided private
   * key, which may represent a pseudonym).
   */
  GNUNET_CHAT_MSG_AUTHENTICATED = 4,

  /**
   * Require signed acknowledgement before
   * completing delivery (and of course, only
   * acknowledge if delivery is guaranteed).
   */
  GNUNET_CHAT_MSG_ACKNOWLEDGED = 8,

  /**
   * Authenticate for the receiver, but
   * ensure that receiver cannot prove
   * authenticity to third parties later.
   * (not yet implemented)
   */
  GNUNET_CHAT_MSG_OFF_THE_RECORD = 16,

} GNUNET_CHAT_MSG_OPTIONS;

/**
 * Handle for a (joined) chat room.
 */
struct GNUNET_CHAT_Room;

/**
 * A message was sent in the chat to us.
 *
 * @param timestamp when was the message sent?
 * @param sender what is the ID of the sender? (maybe NULL)
 * @param message the message (maybe NULL, especially if confirmation
 *        is requested before delivery; the protocol will ensure
 *        that this function is called again with the full message
 *        if a confirmation is transmitted; if the message is NULL,
 *        the user is merely asked if engaging in the exchange is ok
 * @param room in which room was the message received?
 * @param options options for the message
 * @return GNUNET_OK to accept the message now, GNUNET_NO to
 *         accept (but user is away), GNUNET_SYSERR to signal denied delivery
 */
typedef int (*GNUNET_CHAT_MessageCallback) (void *cls,
                                            struct GNUNET_CHAT_Room * room,
                                            const GNUNET_HashCode * sender,
                                            const struct GNUNET_MetaData
                                            * member_info,
                                            const char *message,
                                            GNUNET_CHAT_MSG_OPTIONS options);

/**
 * @param member_info will be non-null if the member is joining, NULL if he is leaving
 * @param member_id hash of public key of the user (for unique identification)
 * @param options what types of messages is this member willing to receive?
 */
typedef int (*GNUNET_CHAT_MemberListCallback) (void *cls,
                                               const struct
                                               GNUNET_MetaData *
                                               member_info,
                                               const GNUNET_RSA_PublicKey *
                                               member_id,
                                               GNUNET_CHAT_MSG_OPTIONS
                                               options);


/**
 * Callback used for message delivery confirmations.
 *
 * @param timestamp when was the message received?
 * @param msg_hash hash fo the original message
 * @param room in which room was the message received?
 * @param receipt signature confirming delivery
 * @return GNUNET_OK
 */
typedef int (*GNUNET_CHAT_MessageConfirmation) (void *cls,
                                                struct GNUNET_CHAT_Room *
                                                room,
                                                unsigned int orig_seq_number,
                                                GNUNET_CronTime timestamp,
                                                const GNUNET_HashCode *
                                                receiver,
                                                const GNUNET_HashCode *
                                                msg_hash,
                                                const GNUNET_RSA_Signature *
                                                receipt);



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
 * @param pid set to the pseudonym ID of ourselves
 *
 * @return NULL on error
 */
struct GNUNET_CHAT_Room *GNUNET_CHAT_join_room (struct GNUNET_GE_Context
                                                *ectx,
                                                struct GNUNET_GC_Configuration
                                                *cfg, const char *nick_name,
                                                struct GNUNET_MetaData
                                                *member_info,
                                                const char *room_name,
                                                GNUNET_CHAT_MSG_OPTIONS
                                                msg_options,
                                                GNUNET_CHAT_MessageCallback
                                                messageCallback,
                                                void *message_cls,
                                                GNUNET_CHAT_MemberListCallback
                                                memberCallback,
                                                void *member_cls,
                                                GNUNET_CHAT_MessageConfirmation
                                                confirmationCallback,
                                                void *confirmation_cls,
                                                GNUNET_HashCode * pid);

/**
 * Leave a chat room.
 */
void GNUNET_CHAT_leave_room (struct GNUNET_CHAT_Room *room);

/**
 * Send a message to the chat room.
 *
 * @param message 0-terminated Utf-8 string describing the message
 *                (may not be longer than ~63k)
 * @param receiver use NULL to send to everyone in the room
 * @param sequence_number set to the sequence number that was
 *        assigned to the message
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CHAT_send_message (struct GNUNET_CHAT_Room *room,
                          const char *message,
                          GNUNET_CHAT_MSG_OPTIONS options,
                          const GNUNET_RSA_PublicKey * receiver,
                          unsigned int *sequence_number);




#if 0
/* these are not yet implemented / supported */
/**
 * Callback function to iterate over rooms.
 *
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
typedef int (*GNUNET_CHAT_RoomIterator) (const char *room,
                                         const char *topic, void *cls);

/**
 * List all of the (publically visible) chat rooms.
 * @return number of rooms on success, GNUNET_SYSERR if iterator aborted
 */
int GNUNET_CHAT_list_rooms (struct GNUNET_GE_Context *ectx,
                            struct GNUNET_GC_Configuration *cfg,
                            GNUNET_CHAT_RoomIterator it, void *cls);
#endif


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/* end of gnunet_chat_lib.h */
