/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file util/network/ip.c
 * @brief code to determine the IP of the local machine
 *
 *
 * Determine the IP of the local machine. We have many
 * ways to get that IP:
 * a) from the interface (ifconfig)
 * b) via DNS from our HOSTNAME (environment)
 * c) from the configuration (HOSTNAME specification or static IP)
 *
 * Which way applies depends on the OS, the configuration
 * (dynDNS? static IP? NAT?) and at the end what the user
 * needs.
 *
 * @author Christian Grothoff
 * @author Tzvetan Horozov
 */

#include <stdlib.h>
#include "platform.h"
#include "gnunet_util_network.h"

/* maximum length of hostname */
#define MAX_HOSTNAME 1024

/**
 * Obtain the identity information for the current node
 * (connection information), conInfo.
 * @return SYSERR on failure, OK on success
 */
static int
getAddressFromHostname (struct GE_Context *ectx, IPaddr * identity)
{
  char hostname[MAX_HOSTNAME];
  int ret;

  if (0 != gethostname (hostname, MAX_HOSTNAME))
    {
      GE_LOG_STRERROR (ectx,
                       GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
                       "gethostname");
      return SYSERR;
    }
  ret = get_host_by_name (ectx, hostname, identity);
  return ret;
}

#if HAVE_GETIFADDRS && HAVE_FREEIFADDRS
static int
getAddressFromGetIfAddrs (struct GC_Configuration *cfg,
                          struct GE_Context *ectx, IPaddr * identity)
{
  char *interfaces;
  struct ifaddrs *ifa_first;

  if (-1 == GC_get_configuration_value_string (cfg,
                                               "NETWORK",
                                               "INTERFACE",
                                               "eth0", &interfaces))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("No interface specified in section `%s' under `%s'!\n"),
              "NETWORK", "INTERFACE");
      return SYSERR;            /* that won't work! */
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
              if (ifa_ptr->ifa_addr->sa_family != AF_INET)
                continue;
              memcpy (identity,
                      &(((struct sockaddr_in *) ifa_ptr->ifa_addr)->sin_addr),
                      sizeof (struct in_addr));
              freeifaddrs (ifa_first);
              FREE (interfaces);
              return OK;
            }
        }
      freeifaddrs (ifa_first);
    }
  GE_LOG (ectx,
          GE_WARNING | GE_USER | GE_BULK,
          _("Could not obtain IP for interface `%s' using `%s'.\n"),
          interfaces, "getifaddrs");
  FREE (interfaces);
  return SYSERR;
}
#endif


#if LINUX || SOMEBSD || MINGW
#define MAX_INTERFACES 16
static int
getAddressFromIOCTL (struct GC_Configuration *cfg,
                     struct GE_Context *ectx, IPaddr * identity)
{
  char *interfaces;
#ifndef MINGW
  struct ifreq ifr[MAX_INTERFACES];
  struct ifconf ifc;
  int sockfd, ifCount;
#else
  DWORD dwIP;
#endif
  int i;

  if (-1 == GC_get_configuration_value_string (cfg,
                                               "NETWORK",
                                               "INTERFACE",
                                               "eth0", &interfaces))
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _("No interface specified in section `%s' under `%s'!\n"),
              "NETWORK", "INTERFACE");
      return SYSERR;            /* that won't work! */
    }
#ifndef MINGW
  sockfd = SOCKET (PF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1)
    {
      FREE (interfaces);
      GE_LOG_STRERROR (ectx,
                       GE_ERROR | GE_ADMIN | GE_USER | GE_BULK, "socket");
      return SYSERR;
    }
  memset (&ifc, 0, sizeof (struct ifconf));
  ifc.ifc_len = sizeof (ifr);
  ifc.ifc_buf = (char *) &ifr;

  if (ioctl (sockfd, SIOCGIFCONF, &ifc) == -1)
    {
      GE_LOG_STRERROR (ectx,
                       GE_WARNING | GE_ADMIN | GE_USER | GE_BULK, "ioctl");
      if (0 != CLOSE (sockfd))
        GE_LOG_STRERROR (ectx, GE_WARNING | GE_ADMIN | GE_BULK, "close");
      FREE (interfaces);
      return SYSERR;
    }
  ifCount = ifc.ifc_len / sizeof (struct ifreq);

  /* first, try to find exatly matching interface */
  for (i = 0; i < ifCount; i++)
    {
      if (ioctl (sockfd, SIOCGIFADDR, &ifr[i]) != 0)
        continue;
      if (ioctl (sockfd, SIOCGIFFLAGS, &ifr[i]) != 0)
        continue;
      if (!(ifr[i].ifr_flags & IFF_UP))
        continue;
      if (strcmp ((char *) interfaces, (char *) ifr[i].ifr_name) != 0)
        continue;
      memcpy (identity,
              &(((struct sockaddr_in *) &ifr[i].ifr_addr)->sin_addr),
              sizeof (struct in_addr));
      if (0 != CLOSE (sockfd))
        GE_LOG_STRERROR (ectx, GE_WARNING | GE_ADMIN | GE_BULK, "close");
      FREE (interfaces);
      return OK;
    }
  GE_LOG (ectx,
          GE_WARNING | GE_ADMIN | GE_USER | GE_BULK,
          _("Could not find interface `%s' using `%s', "
            "trying to find another interface.\n"), interfaces, "ioctl");
  /* if no such interface exists, take any interface but loopback */
  for (i = 0; i < ifCount; i++)
    {
      if (ioctl (sockfd, SIOCGIFADDR, &ifr[i]) != 0)
        continue;
      if (ioctl (sockfd, SIOCGIFFLAGS, &ifr[i]) != 0)
        continue;
      if (!(ifr[i].ifr_flags & IFF_UP))
        continue;
      if (strncmp ("lo", (char *) ifr[i].ifr_name, 2) == 0)
        continue;
      memcpy (identity,
              &(((struct sockaddr_in *) &ifr[i].ifr_addr)->sin_addr),
              sizeof (struct in_addr));
      if (0 != CLOSE (sockfd))
        GE_LOG_STRERROR (ectx, GE_WARNING | GE_ADMIN | GE_BULK, "close");
      FREE (interfaces);
      return OK;
    }

  if (0 != CLOSE (sockfd))
    GE_LOG_STRERROR (ectx, GE_WARNING | GE_ADMIN | GE_BULK, "close");
  GE_LOG (ectx,
          GE_WARNING | GE_USER | GE_BULK,
          _("Could not obtain IP for interface `%s' using `%s'.\n"),
          interfaces, "ioctl");
  FREE (interfaces);
  return SYSERR;
#else /* MinGW */

  /* Win 98 or Win NT SP 4 */
  if (GNGetIpAddrTable)
    {
      PMIB_IFTABLE pTable;
      PMIB_IPADDRTABLE pAddrTable;
      DWORD dwIfIdx;
      unsigned int iAddrCount = 0;

      dwIP = 0;

      EnumNICs (&pTable, &pAddrTable);

      for (dwIfIdx = 0; dwIfIdx < pTable->dwNumEntries; dwIfIdx++)
        {
          unsigned long long l;
          BYTE bPhysAddr[MAXLEN_PHYSADDR];

          l = _atoi64 (interfaces);

          memset (bPhysAddr, 0, MAXLEN_PHYSADDR);
          memcpy (bPhysAddr,
                  pTable->table[dwIfIdx].bPhysAddr,
                  pTable->table[dwIfIdx].dwPhysAddrLen);

          if (memcmp (bPhysAddr, &l, sizeof (l)) == 0)
            {
              for (i = 0; i < pAddrTable->dwNumEntries; i++)
                {
                  if (pAddrTable->table[i].dwIndex
                      == pTable->table[dwIfIdx].dwIndex)
                    {
                      iAddrCount++;
                      dwIP = pAddrTable->table[i].dwAddr;
                    }
                }
            }
        }

      if (!iAddrCount)
        {
          GE_LOG (ectx, GE_WARNING | GE_BULK | GE_USER,
                  _("Could not find an IP address for "
                    "interface `%s'.\n"), interfaces);

          GlobalFree (pTable);
          GlobalFree (pAddrTable);
          return SYSERR;
        }
      else if (iAddrCount > 1)
        GE_LOG (ectx, GE_WARNING | GE_BULK | GE_USER,
                _("There is more than one IP address specified"
                  " for interface `%s'.\nGNUnet will "
                  "use %u.%u.%u.%u.\n"), interfaces, PRIP (ntohl (dwIP)));

      identity->addr = dwIP;

      GlobalFree (pTable);
      GlobalFree (pAddrTable);
    }
  else                          /* Win 95 */
    {
      SOCKET s;
      HOSTENT *pHost;
      SOCKADDR_IN theHost;

      s = SOCKET (PF_INET, SOCK_STREAM, 0);
      pHost = GETHOSTBYNAME ("www.example.com");
      if (!pHost)
        {
          GE_LOG (ectx, GE_ERROR | GE_BULK | GE_USER,
                  _("Could not resolve `%s' to "
                    "determine our IP address: %s\n"),
                  "www.example.com", STRERROR (errno));
          return SYSERR;
        }

      theHost.sin_family = AF_INET;
      theHost.sin_port = htons (80);
      theHost.sin_addr.S_un.S_addr
        = *((unsigned long *) pHost->h_addr_list[0]);
      if (CONNECT (s,
                   (SOCKADDR *) & theHost,
                   sizeof (theHost)) == SOCKET_ERROR && errno != EWOULDBLOCK)
        {
          GE_LOG_STRERROR (ectx, GE_ERROR | GE_BULK | GE_USER, "connect");
          return SYSERR;
        }

      i = sizeof (theHost);
      if (GETSOCKNAME (s, (SOCKADDR *) & theHost, &i) == SOCKET_ERROR)
        {
          GE_LOG_STRERROR (ectx, GE_ERROR | GE_BULK | GE_USER, "getsockname");
          return SYSERR;
        }
      closesocket (s);
      identity->addr = theHost.sin_addr.S_un.S_addr;
    }

  GE_LOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER,
          _("GNUnet now uses the IP address %u.%u.%u.%u.\n"),
          PRIP (ntohl (identity->addr)));

  return OK;
#endif
}

#endif

/**
 * Get the IP address for the local machine.
 * @return NULL on error, IP as string otherwise
 */
char *
network_get_local_ip (struct GC_Configuration *cfg,
                      struct GE_Context *ectx, IPaddr * addr)
{
  IPaddr address;
  char *ipString;
  int retval;
  char buf[65];

  retval = SYSERR;
  if (GC_have_configuration_value (cfg, "NETWORK", "IP"))
    {
      ipString = NULL;
      GC_get_configuration_value_string (cfg, "NETWORK", "IP", "", &ipString);
      if (strlen (ipString) > 0)
        {
          retval = get_host_by_name (ectx, ipString, &address);
        }
      FREE (ipString);
    }
#if LINUX || SOMEBSD || MINGW
  if (retval == SYSERR)
    if (OK == getAddressFromIOCTL (cfg, ectx, &address))
      retval = OK;
#endif
#if HAVE_GETIFADDRS && HAVE_FREEIFADDRS
  if (retval == SYSERR)
    if (OK == getAddressFromGetIfAddrs (cfg, ectx, &address))
      retval = OK;
#endif
  if (retval == SYSERR)
    retval = getAddressFromHostname (ectx, &address);
  if (retval == SYSERR)
    return NULL;
  SNPRINTF (buf, 64, "%u.%u.%u.%u", PRIP (ntohl (*(int *) &address)));
  if (addr != NULL)
    *addr = address;
  return STRDUP (buf);
}


/* end of ip.c */
