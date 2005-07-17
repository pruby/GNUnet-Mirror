/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004 Christian Grothoff (and other contributing authors)

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
 * @file traffic/clientapi.c
 * @author Christian Grothoff
 * @brief API for clients to obtain traffic statistics
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_util.h"
#include "gnunet_traffic_lib.h"
#include "traffic.h"


/**
 * Poll gnunetd via TCP about traffic information.
 *
 * @param sock socket to query gnunetd over
 * @param timeframe what time interval should be considered
 * @param type what type of message do we care about?
 * @param direction TC_RECEIVED of TC_SEND?
 * @param count set to number of messages
 * @param avg_size set to average size
 * @param peers set to number of peers involved
 * @return OK on success, SYSERR on error
 */
int pollSocket(GNUNET_TCP_SOCKET * sock,
	       unsigned int timeframe,
	       unsigned short type,
	       unsigned short direction,
	       unsigned int * count,
	       unsigned int * avg_size,
	       unsigned int * peers,
	       unsigned int * time) {
  CS_traffic_info_MESSAGE * info;
  CS_traffic_request_MESSAGE req;
  int i;

  req.header.size
    = htons(sizeof(CS_traffic_request_MESSAGE));
  req.header.type
    = htons(CS_PROTO_traffic_QUERY);
  req.timePeriod
    = htonl(timeframe);
  if (SYSERR == writeToSocket(sock,
			      &req.header)) {
    LOG(LOG_WARNING,
	_("Failed to query gnunetd about traffic conditions.\n"));
    return SYSERR;
  }
  info = NULL;
  if (SYSERR == readFromSocket(sock,
			       (CS_MESSAGE_HEADER**)&info)) {
    LOG(LOG_WARNING,
	_("Did not receive reply from gnunetd about traffic conditions.\n"));
    return SYSERR;
  }
  if ( (ntohs(info->header.type) !=
	CS_PROTO_traffic_INFO) ||
       (ntohs(info->header.size) !=
	sizeof(CS_traffic_info_MESSAGE) + ntohl(info->count)*sizeof(TRAFFIC_COUNTER)) ) {
    BREAK();
    return SYSERR;
  }

  for (i=ntohl(info->count)-1;i>=0;i--) {
    TRAFFIC_COUNTER * tc = &((CS_traffic_info_MESSAGE_GENERIC*)info)->counters[i];
    if ((tc->flags & TC_TYPE_MASK) == direction) {
      *count = ntohl(tc->count);
      *avg_size = ntohl(tc->avrg_size);
      *peers = ntohs(tc->flags) & TC_DIVERSITY_MASK;
      *time = ntohl(tc->time_slots);
    } /* end if received */
  } /* end for all counters */
  FREE(info);
  return OK;
}

/* end of clientapi.c */
