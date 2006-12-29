/*
     This file is part of GNUnet
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_upnp_service.h
 * @brief API for UPnP access
 * @author Christian Grothoff
 */

#ifndef GNUNET_UPNP_SERVICE_H
#define GNUNET_UPNP_SERVICE_H

#include "gnunet_util.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * @brief UPNP API
 */
typedef struct {

  /**
   * Get the external IP address for the local machine.
   * @param protocol "UDP" or "TCP".
   *
   * @return SYSERR on error, OK on success
   */
  int (*get_ip)(unsigned short port,
		const char * protocol,
		IPaddr * address);

} UPnP_ServiceAPI;


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
