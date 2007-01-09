/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file transports/ip.c
 * @brief code to determine the IP of the local machine
 *
 * @author Christian Grothoff
 * @author Tzvetan Horozov
 * @author Heikki Lindholm
 */

#include <stdlib.h>
#include "platform.h"
#include "gnunet_util.h"
#include "ip.h"

/**
 * Get the IP address for the local machine.
 * @return SYSERR on error, OK on success
 */
int getPublicIPAddress(struct GC_Configuration * cfg,
		       struct GE_Context * ectx,
		       IPaddr * address) {
  static IPaddr myAddress;
  static cron_t last;
  static cron_t lastError;
  cron_t now;
  char * ips;

  now = get_time();
  if (last + cronMINUTES < now) {
    if (lastError + 30 * cronSECONDS > now)
      return SYSERR;
    ips = network_get_local_ip(cfg,
			       ectx,			       
			       &myAddress);
    if (ips == NULL) {
      GE_LOG(ectx,
	     GE_WARNING | GE_USER | GE_BULK,
	     _("Failed to obtain my (external) %s address!\n"),
	     "IP");
      lastError = now;
      return SYSERR;
    }
    FREE(ips);
    last = now;
  }
  memcpy(address,
	 &myAddress,
	 sizeof(IPaddr));
  return OK;
}

/* end of ip.c */
