/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/stats/statistics.h
 */
#ifndef CHAT_CHAT_H
#define CHAT_CHAT_H

#include "gnunet_util.h"

/**
 * Statistics message. Contains the timestamp and an aribtrary
 * (bounded by the maximum CS message size!) number of statistical
 * numbers. If needed, several messages are used.
 *
 * The struct is followed by statCounters 64-bit 
 * integers which are then followed by 0-terminated
 * strings.
 */
typedef struct
{
  GNUNET_MessageHeader header;
  /**
   * For 64-bit alignment...
   */
  int reserved GNUNET_PACKED;

  /**
   * timestamp  (network byte order) 
   */
  GNUNET_CronTime startTime GNUNET_PACKED;

  /**
   * total number of statistical counters 
   */
  unsigned int totalCounters GNUNET_PACKED;

  /**
   * number of statistical counters in this message 
   */
  unsigned int statCounters GNUNET_PACKED;

} CS_stats_reply_MESSAGE;

/**
 * Query protocol supported message.  Contains the type of
 * the message we are requesting the status of.
 */
typedef struct
{
  GNUNET_MessageHeader header;

  /**
   * The type of the message (XX_CS_PROTO_XXXX)
   * we want to know the status of.
   */
  unsigned short type GNUNET_PACKED;

  /**
   * 0 for plaintext P2P,
   * 1 for ciphertext P2P,
   * 2 for either plaintext or ciphertext P2P,
   * 3 for client-server
   */
  unsigned short handlerType GNUNET_PACKED;

} CS_stats_get_supported_MESSAGE;

#endif
