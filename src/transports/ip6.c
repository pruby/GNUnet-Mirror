/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file transports/ip6.c
 * @brief code to determine the IP(v6) of the local machine
 *
 * Todo:
 * * scanning of network devices for IPv6 (first: find good
 *   API to do it, doesn't seem to exist!)
 *
 * @author Christian Grothoff
 * @author Tzvetan Horozov
 */

#include <stdlib.h>
#include "platform.h"
#include "gnunet_util.h"
#include "ip6.h"

/**
 * Obtain the identity information for the current node
 * (connection information), conInfo.
 * @return SYSERR on failure, OK on success
 */
static int getAddress6FromHostname(IP6addr * identity) {
  char * hostname;
  struct hostent * ip;
  
  hostname = MALLOC(1024);
  if (0 != gethostname(hostname, 1024)) {
    LOG_STRERROR(LOG_ERROR, "gethostname");
    FREE(hostname);
    return SYSERR;
  }
  /* LOG(LOG_DEBUG,
      " looking up $HOSTNAME (%s) to obtain local IP\n",
      hostname); */

  ip = gethostbyname2(hostname, AF_INET6);
  if (ip == NULL) {
    LOG(LOG_ERROR,
	_("Could not find IP of host `%s': %s\n"),
	hostname, 
	hstrerror(h_errno));
    FREE(hostname);
    return SYSERR;
  }
  FREE(hostname);
  if (ip->h_addrtype != AF_INET6) {
    BREAK();
    return SYSERR;
  }
  GNUNET_ASSERT(sizeof(struct in6_addr) == sizeof(identity->addr));
  memcpy(&identity->addr[0],
	 ip->h_addr_list[0],
	 sizeof(struct in6_addr));
  return OK;
}

/**
 * Get the IP address for the local machine.
 * @return SYSERR on error, OK on success
 */
static int getAddress6(IP6addr  * address){
  char * ipString;
  int retval;
  struct hostent * ip; /* for the lookup of the IP in gnunet.conf */

  retval = SYSERR;
  ipString = getConfigurationString("NETWORK",
				    "IP6");
  if (ipString == NULL) {
    retval = getAddress6FromHostname(address);
  } else {
    /* LOG(LOG_DEBUG,
	" obtaining local IP address from hostname %s\n",
	ipString); */
    ip = gethostbyname2(ipString,
			AF_INET6);
    if (ip == NULL) {
      LOG(LOG_ERROR,
	  _("Could not resolve `%s': %s\n"),
	  ipString, 
	  hstrerror(h_errno));
      retval = SYSERR;
    } else {
      if (ip->h_addrtype != AF_INET6) {
	BREAK();
	retval = SYSERR;
      } else {
	GNUNET_ASSERT(sizeof(struct in6_addr) == sizeof(address->addr));
	memcpy(&address->addr[0],
	       ip->h_addr_list[0],
	       sizeof(struct in6_addr));
	retval = OK;
      }
    }
    FREE(ipString);
  }
  return retval;
}

/**
 * Get the IPv6 address for the local machine.
 * @return SYSERR on error, OK on success
 */
int getPublicIP6Address(IP6addr * address) {
  static IP6addr myAddress;
  static cron_t last;
  static cron_t lastError;
  cron_t now;

  cronTime(&now);
  if (last + cronMINUTES < now) {
    if (lastError + 30 * cronSECONDS > now)
      return SYSERR;
    if (SYSERR == getAddress6(&myAddress)) {
      lastError = now;
      LOG(LOG_WARNING,
	  _("Failed to obtain my (external) IPv6 address!\n"));
      return SYSERR;
    }
    last = now;
  }
  memcpy(address,
	 &myAddress,
	 sizeof(IP6addr));
  return OK;
}

/* end of ip6.c */
