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
 * @file traffic/traffic.h
 * @author Christian Grothoff
 *
 * @brief Module to keep track of recent amounts of p2p traffic
 * on the local GNUnet node.
 */
#ifndef TRAFFIC_H
#define TRAFFIC_H

/**
 * Counter for traffic.
 */
typedef struct
{

  /**
   * Flags. See TC_XXXX definitions.
   */
  unsigned short flags;

  /**
   * What is the message type that this counter is concerned with?
   */
  unsigned short type;

  /**
   * What was the number of messages of this type that the peer
   * processed in the last n time units?
   */
  unsigned int count;

  /**
   * What is the average size of the last "count" messages that
   * the peer processed?
   */
  unsigned int avrg_size;

  /**
   * In which of the last 32 time units did the peer receive or send a
   * message of this type? The lowest bit (1) corresponds to -31
   * seconds ago, the highest bit (2^31) corresponds to the current
   * second.
   */
  unsigned int time_slots;
} TRAFFIC_COUNTER;


/**
 * Format of the reply-message to a CS_TRAFFIC_QUERY.
 * A message of this format is send back to the client
 * if it sends a CS_TRAFFIC_QUERY to gnunetd.
 */
typedef struct
{
  MESSAGE_HEADER header;

  /**
   * The number of different message types we have seen
   * in the last time.
   */
  unsigned int count;

} CS_traffic_info_MESSAGE;

/**
 * Generic version of CS_traffic_info_MESSAGE with field for accessing end of struct
 * (use the other version for allocation).
 */
typedef struct
{
  CS_traffic_info_MESSAGE cs_traffic_info;

  /**
   * "count" traffic counters.
   */
  TRAFFIC_COUNTER counters[1];

} CS_traffic_info_MESSAGE_GENERIC;

/**
 * Request for CS_traffic_info_MESSAGE.
 */
typedef struct
{
  MESSAGE_HEADER header;

  /**
   * How many time units back should the statistics returned contain?
   * (in network byte order) Must be smaller or equal to HISTORY_SIZE.
   */
  unsigned int timePeriod;

} CS_traffic_request_MESSAGE;


#endif
