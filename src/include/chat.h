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
 * @author Christian Grothoff
 * @author Nathan Evans
 * @file chat.h
 */
#ifndef CHAT_H
#define CHAT_H

#include "gnunet_core.h"
#include "gnunet_chat_lib.h"

/**
 * We have received a chat message (server to client).  After this
 * struct, the remaining bytes are the actual message in plaintext.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Message options, see GNUNET_CHAT_MSG_OPTIONS.
   */
  unsigned int msg_options;

  /**
   * Hash of the public key of the pseudonym of the
   * sender of the message (all zeros for anonymous).
   */
  GNUNET_HashCode sender;

} CS_chat_MESSAGE_ReceiveNotification;

/**
 * Send a chat message (client to server).  After this struct, the
 * remaining bytes are the actual message in plaintext.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Desired message options, see GNUNET_CHAT_MSG_OPTIONS.
   */
  unsigned int msg_options;

  /**
   * Sequence number of the message (unique per sender).
   */
  unsigned int sequence_number;

  /**
   * Reserved (for alignment).
   */
  unsigned int reserved;

  /**
   * Who should receive this message?  Set to all zeros
   * for "everyone".
   */
  GNUNET_HashCode target;

} CS_chat_MESSAGE_TransmitRequest;

/**
 * Confirm receipt of a chat message (this is the receipt
 * send from the daemon to the original sender; clients
 * do not have to ever generate receipts on their own).
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Sequence number of the original message.
   */
  unsigned int sequence_number;

  /**
   * Time of receipt.
   */
  GNUNET_CronTime timestamp;

  /**
   * Who is confirming the receipt?
   */
  GNUNET_HashCode target;

  /**
   * Hash of the (possibly encrypted) content.
   */
  GNUNET_HashCode content;

  /**
   * Signature confirming receipt.  Signature
   * covers everything from header through content.
   */
  GNUNET_RSA_Signature signature;

} CS_chat_MESSAGE_ConfirmationReceipt;

/**
 * Message send from client to daemon to join a chat room.
 * This struct is followed by the room name and then
 * the serialized ECRS meta data describing the new member.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Options.  Set all options that this client is willing to receive.
   * For example, if the client does not want to receive anonymous or
   * OTR messages but is willing to generate acknowledgements and
   * receive private messages, this should be set to
   * GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ACKNOWLEDGED.
   */
  unsigned int msg_options;

  /**
   * Length of the room name.
   */
  unsigned short room_name_len;

  /**
   * Reserved (should be zero).
   */
  unsigned short reserved;

  /**
   * Private key of the joining member.
   */
  GNUNET_RSA_PrivateKeyEncoded private_key;

} CS_chat_MESSAGE_JoinRequest;

/**
 * Message send by server to client to indicate joining
 * or leaving of another room member.  This struct is
 * followed by the serialized ECRS MetaData describing
 * the new member.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Options.  Set to all options that the new user is willing to
   * process.  For example, if the client does not want to receive
   * anonymous or OTR messages but is willing to generate
   * acknowledgements and receive private messages, this should be set
   * to GNUNET_CHAT_MSG_PRIVATE | GNUNET_CHAT_MSG_ACKNOWLEDGED.
   */
  unsigned int msg_options;

  /**
   * Public key of the new user.
   */
  GNUNET_RSA_PublicKey public_key;

} CS_chat_MESSAGE_JoinNotification;


/**
 * Message send by server to client to indicate
 * leaving of another room member.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * Reserved (for alignment).
   */
  unsigned int reserved;

  /**
   * Who is leaving?
   */
  GNUNET_RSA_PublicKey user;

} CS_chat_MESSAGE_LeaveNotification;


#endif

/* end of chat.h */
