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
 * @file transports/ip6.c
 * @brief code to determine the IP(v6) of the local machine
 *
 * Todo:
 * * scanning of network devices for IPv6 (first: find good
 *   API to do it, doesn't seem to exist!)
 *
 * @author Christian Grothoff
 * @author Tzvetan Horozov
 * @author Heikki Lindholm
 */

#include <stdlib.h>
#include "platform.h"
#include "gnunet_util.h"
#include "ip6.h"
#if HAVE_IFADDRS_H
#if HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <ifaddrs.h>
#endif

/* maximum length of hostname */
#define MAX_HOSTNAME 1024

/**
 * Obtain the identity information for the current node
 * (connection information), conInfo.
 * @return GNUNET_SYSERR on failure, GNUNET_OK on success
 */
static int
getAddress6FromHostname (struct GNUNET_GE_Context *ectx,
                         GNUNET_IPv6Address * identity)
{
  char hostname[MAX_HOSTNAME];
  struct hostent *ip;

  if (0 != gethostname (hostname, MAX_HOSTNAME))
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_USER | GNUNET_GE_BULK, "gethostname");
      return GNUNET_SYSERR;
    }
  /* GNUNET_GE_LOG(ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
     " looking up $HOSTNAME (%s) to obtain local IP\n",
     hostname); */

  ip = gethostbyname2 (hostname, AF_INET6);
  if (ip == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     _("Could not find IP of host `%s': %s\n"), hostname,
                     hstrerror (h_errno));
      return GNUNET_SYSERR;
    }
  if (ip->h_addrtype != AF_INET6)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_GE_ASSERT (ectx,
                    sizeof (struct in6_addr) == sizeof (identity->addr));
  memcpy (&identity->addr[0], ip->h_addr_list[0], sizeof (struct in6_addr));
  return GNUNET_OK;
}

#if HAVE_GETIFADDRS && HAVE_GNUNET_freeIFADDRS
static int
getAddress6FromGetIfAddrs (struct GNUNET_GC_Configuration *cfg,
                           struct GNUNET_GE_Context *ectx,
                           GNUNET_IPv6Address * identity)
{
  char *interfaces;
  struct ifaddrs *ifa_first;

  if (-1 == GNUNET_GC_get_configuration_value_string (cfg,
                                                      "NETWORK",
                                                      "INTERFACE",
                                                      GNUNET_DEFAULT_INTERFACE,
                                                      &interfaces))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("No interface specified in section `%s' under `%s'!\n"),
                     "NETWORK", "INTERFACE");
      return GNUNET_SYSERR;     /* that won't work! */
    }

  if (getifaddrs (&ifa_first) == 0)
    {
      struct ifaddrs *ifa_ptr;

      ifa_ptr = ifa_first;
      for (ifa_ptr = ifa_first; ifa_ptr != NULL; ifa_ptr = ifa_ptr->ifa_next)
        {
          if (ifa_ptr->ifa_name != NULL &&
              ifa_ptr->ifa_addr != NULL && (ifa_ptr->ifa_flags & IFF_UP) != 0)
            {
              if (strcmp (interfaces, (char *) ifa_ptr->ifa_name) != 0)
                continue;
              if (ifa_ptr->ifa_addr->sa_family != AF_INET6)
                continue;
              memcpy (identity,
                      &(((struct sockaddr_in6 *) ifa_ptr->ifa_addr)->
                        sin6_addr), sizeof (struct in6_addr));
              freeifaddrs (ifa_first);
              GNUNET_free (interfaces);
              return GNUNET_OK;
            }
        }
      freeifaddrs (ifa_first);
    }
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                 _("Could not obtain IP for interface `%s' using `%s'.\n"),
                 interfaces, "getifaddrs");
  GNUNET_free (interfaces);
  return GNUNET_SYSERR;
}
#endif

/**
 * Get the IP address for the local machine.
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
getAddress6 (struct GNUNET_GC_Configuration *cfg,
             struct GNUNET_GE_Context *ectx, GNUNET_IPv6Address * address)
{
  char *ipString;
  int retval;
  struct hostent *ip;           /* for the lookup of the IP in gnunet.conf */

  retval = GNUNET_SYSERR;
  if (GNUNET_GC_have_configuration_value (cfg, "NETWORK", "IP6"))
    {
      ipString = NULL;
      GNUNET_GC_get_configuration_value_string (cfg,
                                                "NETWORK", "IP6", "",
                                                &ipString);
      if (strlen (ipString) > 0)
        {
          ip = gethostbyname2 (ipString, AF_INET6);
          if (ip == NULL)
            {
              GNUNET_GE_LOG (ectx,
                             GNUNET_GE_ERROR | GNUNET_GE_USER |
                             GNUNET_GE_BULK,
                             _("Could not resolve `%s': %s\n"), ipString,
                             hstrerror (h_errno));
            }
          else if (ip->h_addrtype != AF_INET6)
            {
              GNUNET_GE_ASSERT (ectx, 0);
              retval = GNUNET_SYSERR;
            }
          else
            {
              GNUNET_GE_ASSERT (ectx,
                                sizeof (struct in6_addr) ==
                                sizeof (address->addr));
              memcpy (&address->addr[0], ip->h_addr_list[0],
                      sizeof (struct in6_addr));
              retval = GNUNET_OK;
            }
        }
      GNUNET_free (ipString);
    }
#if HAVE_GETIFADDRS && HAVE_GNUNET_freeIFADDRS
  if (retval == GNUNET_SYSERR)
    if (GNUNET_OK == getAddress6FromGetIfAddrs (cfg, ectx, address))
      retval = GNUNET_OK;
#endif
  if (retval == GNUNET_SYSERR)
    retval = getAddress6FromHostname (ectx, address);
  return retval;
}

/**
 * Get the IPv6 address for the local machine.
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
getPublicIP6Address (struct GNUNET_GC_Configuration *cfg,
                     struct GNUNET_GE_Context *ectx,
                     GNUNET_IPv6Address * address)
{
  static GNUNET_IPv6Address myAddress;
  static GNUNET_CronTime last;
  static GNUNET_CronTime lastError;
  GNUNET_CronTime now;

  now = GNUNET_get_time ();
  if (last + GNUNET_CRON_MINUTES < now)
    {
      if (lastError + 30 * GNUNET_CRON_SECONDS > now)
        return GNUNET_SYSERR;
      if (GNUNET_SYSERR == getAddress6 (cfg, ectx, &myAddress))
        {
          lastError = now;
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Failed to obtain my (external) %s address!\n"),
                         "IPv6");
          return GNUNET_SYSERR;
        }
      last = now;
    }
  memcpy (address, &myAddress, sizeof (GNUNET_IPv6Address));
  return GNUNET_OK;
}

/* end of ip6.c */
