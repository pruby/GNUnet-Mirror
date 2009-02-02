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
 * @file applications/tbench/tbench.h
 * @author Christian Grothoff
 */
#ifndef TBENCH_TBENCH_H
#define TBENCH_TBENCH_H

#include "gnunet_core.h"

/**
 * Client requests peer to perform some profiling.
 */
typedef struct
{
  GNUNET_MessageHeader header;
  /**
   * How big is each message (plus headers).
   * Note that GNUnet is limited to 64k messages.
   */
  unsigned int msgSize GNUNET_PACKED;
  /**
   * How many messages should be transmitted in
   * each iteration?
   */
  unsigned int msgCnt GNUNET_PACKED;
  /**
   * How many iterations should be performed?
   */
  unsigned int iterations GNUNET_PACKED;
  /**
   * Which peer should receive the messages?
   */
  GNUNET_PeerIdentity receiverId;
  /**
   * Inter packet space in milliseconds (delay
   * introduced when sending messages).
   */
  GNUNET_CronTime intPktSpace GNUNET_PACKED;
  /**
   * Time to wait for the arrival of all repies
   * in one iteration.
   */
  GNUNET_CronTime timeOut GNUNET_PACKED;
  /**
   * intPktSpace delay is only introduced every
   * trainSize messages.
   */
  unsigned int trainSize GNUNET_PACKED;
  /**
   * Which priority should be used?
   */
  unsigned int priority GNUNET_PACKED;
} CS_tbench_request_MESSAGE;

/**
 * Response from server with statistics.
 */
typedef struct
{
  GNUNET_MessageHeader header;
  unsigned int max_loss GNUNET_PACKED;
  unsigned int min_loss GNUNET_PACKED;
  float mean_loss GNUNET_PACKED;
  float variance_loss GNUNET_PACKED;

  GNUNET_CronTime max_time GNUNET_PACKED;
  GNUNET_CronTime min_time GNUNET_PACKED;
  float mean_time GNUNET_PACKED;
  float variance_time GNUNET_PACKED;
} CS_tbench_reply_MESSAGE;

#endif
