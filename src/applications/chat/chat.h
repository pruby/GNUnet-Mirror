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
 * @file applications/chat/chat.h
 **/
#ifndef CHAT_CHAT_H
#define CHAT_CHAT_H

#include "gnunet_core.h"
#include "gnunet_chat_lib.h"

typedef struct
{
  GNUNET_MessageHeader header;

  unsigned short nick_len;

  unsigned short msg_len;

  /*int room_name_len; */

  char nick[1];

} CS_chat_MESSAGE;

typedef struct
{
  GNUNET_MessageHeader header;

  GNUNET_RSA_PublicKey pkey;

  unsigned short nick_len;

  char nick[1];

} CS_chat_JOIN_MESSAGE;

typedef struct
{
  GNUNET_MessageHeader header;

  unsigned short nick_len;

  char nick[1];

} CS_chat_ROOM_MEMBER_MESSAGE;


#endif

/* end of chat.h */
