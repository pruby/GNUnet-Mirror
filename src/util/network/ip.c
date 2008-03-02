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
 * @return GNUNET_SYSERR on failure, GNUNET_OK on success
 */
static int
getAddressFromHostname (struct GNUNET_GE_Context *ectx,
                        struct in_addr *identity)
{
  char hostname[MAX_HOSTNAME];
  int ret;
  struct sockaddr *my_addr;
  struct sockaddr_in a4;
  socklen_t socklen;

  if (0 != gethostname (hostname, MAX_HOSTNAME))
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_USER | GNUNET_GE_BULK, "gethostname");
      return GNUNET_SYSERR;
    }
  socklen = sizeof (struct sockaddr_in);
  my_addr = (struct sockaddr *) &a4;
  ret =
    GNUNET_get_ip_from_hostname (ectx, hostname, AF_INET, &my_addr, &socklen);
  if (ret == GNUNET_OK)
    *identity = a4.sin_addr;
  return ret;
}

#if HAVE_GETIFADDRS && HAVE_GNUNET_freeIFADDRS
static int
getAddressFromGetIfAddrs (struct GNUNET_GC_Configuration *cfg,
                          struct GNUNET_GE_Context *ectx,
                          struct in_addr *identity)
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
              if (ifa_ptr->ifa_addr->sa_family != AF_INET)
                continue;
              memcpy (identity,
                      &(((struct sockaddr_in *) ifa_ptr->ifa_addr)->sin_addr),
                      sizeof (struct in_addr));
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


#if LINUX || SOMEBSD || MINGW
#define MAX_INTERFACES 16
static int
getAddressFromIOCTL (struct GNUNET_GC_Configuration *cfg,
                     struct GNUNET_GE_Context *ectx, struct in_addr *identity)
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
#ifndef MINGW
  sockfd = SOCKET (PF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1)
    {
      GNUNET_free (interfaces);
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_USER | GNUNET_GE_BULK, "socket");
      return GNUNET_SYSERR;
    }
  memset (&ifc, 0, sizeof (struct ifconf));
  ifc.ifc_len = sizeof (ifr);
  ifc.ifc_buf = (char *) &ifr;

  if (ioctl (sockfd, SIOCGIFCONF, &ifc) == -1)
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                              GNUNET_GE_USER | GNUNET_GE_BULK, "ioctl");
      if (0 != CLOSE (sockfd))
        GNUNET_GE_LOG_STRERROR (ectx,
                                GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                GNUNET_GE_BULK, "close");
      GNUNET_free (interfaces);
      return GNUNET_SYSERR;
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
        GNUNET_GE_LOG_STRERROR (ectx,
                                GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                GNUNET_GE_BULK, "close");
      GNUNET_free (interfaces);
      return GNUNET_OK;
    }
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 _("Could not find interface `%s' using `%s', "
                   "trying to find another interface.\n"), interfaces,
                 "ioctl");
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
        GNUNET_GE_LOG_STRERROR (ectx,
                                GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                                GNUNET_GE_BULK, "close");
      GNUNET_free (interfaces);
      return GNUNET_OK;
    }

  if (0 != CLOSE (sockfd))
    GNUNET_GE_LOG_STRERROR (ectx,
                            GNUNET_GE_WARNING | GNUNET_GE_ADMIN |
                            GNUNET_GE_BULK, "close");
  GNUNET_GE_LOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                 _("Could not obtain IP for interface `%s' using `%s'.\n"),
                 interfaces, "ioctl");
  GNUNET_free (interfaces);
  return GNUNET_SYSERR;
#else /* MinGW */
  char ntop_buf[INET_ADDRSTRLEN];

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
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("Could not find an IP address for "
                           "interface `%s'.\n"), interfaces);

          GlobalFree (pTable);
          GlobalFree (pAddrTable);
          return GNUNET_SYSERR;
        }
      else if (iAddrCount > 1)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("There is more than one IP address specified"
                           " for interface `%s'.\nGNUnet will "
                           "use %s.\n"), interfaces,
                         inet_ntop (AF_INET, &dwIP, ntop_buf,
                                    INET_ADDRSTRLEN));
        }

      identity->S_un.S_addr = dwIP;

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
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("Could not resolve `%s' to "
                           "determine our IP address: %s\n"),
                         "www.example.com", STRERROR (errno));
          return GNUNET_SYSERR;
        }

      theHost.sin_family = AF_INET;
      theHost.sin_port = htons (80);
      theHost.sin_addr.S_un.S_addr
        = *((unsigned long *) pHost->h_addr_list[0]);
      if (CONNECT (s,
                   (SOCKADDR *) & theHost,
                   sizeof (theHost)) == SOCKET_ERROR && errno != EWOULDBLOCK)
        {
          GNUNET_GE_LOG_STRERROR (ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                  GNUNET_GE_USER, "connect");
          return GNUNET_SYSERR;
        }

      i = sizeof (theHost);
      if (GETSOCKNAME (s, (SOCKADDR *) & theHost, &i) == SOCKET_ERROR)
        {
          GNUNET_GE_LOG_STRERROR (ectx,
                                  GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                  GNUNET_GE_USER, "getsockname");
          return GNUNET_SYSERR;
        }
      closesocket (s);
      *identity = theHost.sin_addr;
    }

  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("GNUnet now uses the IP address %s.\n"),
                 inet_ntop (AF_INET, identity, ntop_buf, INET_ADDRSTRLEN));
  return GNUNET_OK;
#endif
}

#endif

/**
 * Get the IP address for the local machine.
 * @return NULL on error, IP as string otherwise
 */
char *
GNUNET_get_local_ip (struct GNUNET_GC_Configuration *cfg,
                     struct GNUNET_GE_Context *ectx, struct in_addr *addr)
{
  struct in_addr address;
  struct sockaddr *my_addr;
  struct sockaddr_in a4;
  char *ipString;
  int retval;
  char buf[INET_ADDRSTRLEN];
  socklen_t socklen;

  retval = GNUNET_SYSERR;
  if (GNUNET_GC_have_configuration_value (cfg, "NETWORK", "IP"))
    {
      ipString = NULL;
      GNUNET_GC_get_configuration_value_string (cfg, "NETWORK", "IP", "",
                                                &ipString);
      if (strlen (ipString) > 0)
        {
          socklen = sizeof (struct sockaddr_in);
          my_addr = (struct sockaddr *) &a4;
          retval =
            GNUNET_get_ip_from_hostname (ectx, ipString, AF_INET, &my_addr,
                                         &socklen);
          if (retval == GNUNET_OK)
            address = a4.sin_addr;
        }
      GNUNET_free (ipString);
    }
#if LINUX || SOMEBSD || MINGW
  if (retval == GNUNET_SYSERR)
    if (GNUNET_OK == getAddressFromIOCTL (cfg, ectx, &address))
      retval = GNUNET_OK;
#endif
#if HAVE_GETIFADDRS && HAVE_GNUNET_freeIFADDRS
  if (retval == GNUNET_SYSERR)
    if (GNUNET_OK == getAddressFromGetIfAddrs (cfg, ectx, &address))
      retval = GNUNET_OK;
#endif
  if (retval == GNUNET_SYSERR)
    retval = getAddressFromHostname (ectx, &address);
  if (retval == GNUNET_SYSERR)
    return NULL;
  if (NULL == inet_ntop (AF_INET, &address, buf, INET_ADDRSTRLEN))
    return NULL;
  if (addr != NULL)
    *addr = address;
  return GNUNET_strdup (buf);
}


/* end of ip.c */
