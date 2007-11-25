/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_traffic_lib.h
 * @brief convenience API to the TRAFFIC service
 * @author Christian Grothoff
 */

#ifndef GNUNET_TRAFFIC_LIB_H
#define GNUNET_TRAFFIC_LIB_H

#include "gnunet_util.h"
#include "gnunet_util_network_client.h"
#include "gnunet_traffic_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Poll gnunetd via TCP about traffic information.
 *
 * @param sock socket to query gnunetd over
 * @param timeframe what time interval should be considered
 * @param type what type of message do we care about?
 * @param direction GNUNET_TRAFFIC_TYPE_RECEIVED of TC_SEND?
 * @param count set to number of messages
 * @param avg_size set to average size
 * @param peers set to number of peers involved
 * @param time set to the time distribution
 *        bit-vector giving times of interactions,
 *        highest bit is current time-unit, bit 1 is 32 time-units ago (set)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_traffic_poll (struct GNUNET_ClientServerConnection *sock,
                         unsigned int timeframe,
                         unsigned short type,
                         unsigned short direction,
                         unsigned int *count,
                         unsigned int *avg_size,
                         unsigned int *peers, unsigned int *time);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
