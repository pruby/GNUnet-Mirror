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
 */
typedef struct {
  CS_HEADER header;
  /**
   * For 64-bit alignment...
   */
  int reserved;
  /* timestamp  (network byte order)*/
  cron_t startTime;
  /* total number of statistical counters */
  int totalCounters;
  /* number of statistical counters in this message */
  int statCounters;

} STATS_CS_MESSAGE;

/**
 * Generic version of STATS_CS_MESSAGE with field for finding the end
 * of the struct. Use the other version for allocation.
 */
typedef struct {
  STATS_CS_MESSAGE stats_cs_message;

  /* values[statCounters] */
  unsigned long long values[1];

  /* description for each of the values,
     separated by '\0'-terminators; the
     last description is also terminated
     by a '\0'; again statCounters entries */
  /* char descriptions[0]; */
} STATS_CS_MESSAGE_GENERIC;

/**
 * Query protocol supported message.  Contains the type of
 * the message we are requesting the status of.
 */
typedef struct {
  CS_HEADER header;

  /**
   * The type of the message (XX_CS_PROTO_XXXX)
   * we want to know the status of.
   */
  unsigned short type;

  /**
   * For 64-bit alignment...
   */
  unsigned short reserved;

} STATS_CS_GET_MESSAGE_SUPPORTED;

#endif
