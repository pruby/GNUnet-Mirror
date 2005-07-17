/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * @file applications/chat/chat.h
 **/
#ifndef CHAT_CHAT_H
#define CHAT_CHAT_H

#include "gnunet_core.h"

#define CHAT_NICK_LENGTH 32
#define CHAT_MSG_LENGTH 1024

typedef struct {
  P2P_MESSAGE_HEADER header;
  char nick[CHAT_NICK_LENGTH];
  char message[CHAT_MSG_LENGTH];
} P2P_chat_MESSAGE;

typedef struct {
  CS_MESSAGE_HEADER header;
  char nick[CHAT_NICK_LENGTH];
  char message[CHAT_MSG_LENGTH];
} CS_chat_MESSAGE;



#endif
