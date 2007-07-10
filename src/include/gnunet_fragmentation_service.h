/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_fragmentation_service.h
 * @brief module to do fragmentation
 * @author Christian Grothoff
 */

#ifndef GNUNET_FRAGMENTATION_SERVICE_H
#define GNUNET_FRAGMENTATION_SERVICE_H

#include "gnunet_util.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * @brief Definition of the fragmentation API.
 */
typedef struct
{

  /**
   * Fragment an over-sized message.
   *
   * @param peer the recipient of the message
   * @param mtu maximum size of a fragment
   * @param prio priority of the message
   * @param targetTime desired transmission time
   * @param len size of the message
   * @param bmc callback to construct the message
   * @param bmcClosure argument to bmc
   */
  void (*fragment) (const PeerIdentity * peer,
                    unsigned int mtu,
                    unsigned int prio,
                    unsigned int targetTime,
                    unsigned int len,
                    BuildMessageCallback bmc, void *bmcClosure);

} Fragmentation_ServiceAPI;


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_fragmentation_service.h */
#endif
