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
 * @file util/identity.c
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

/**
 * @brief our current IPv4 address.
 */
static IPaddr myAddress;

static int ipv4_init = NO;

#if USE_IPV6
static IP6addr myAddress6;

static int ipv6_init = NO;
#endif

/**
 * Obtain the identity information for the current node
 * (connection information), conInfo.
 * @return SYSERR on failure, OK on success
 */
static int getAddressFromHostname(IPaddr * identity) {
  char * hostname;
  struct hostent * ip;

  hostname = MALLOC(1024);
  if (0 != gethostname(hostname, 1024)) {
    FREE(hostname);
    LOG_STRERROR(LOG_ERROR, "gethostname");
    return SYSERR;
  }
  /* LOG(LOG_DEBUG,
      " looking up $HOSTNAME (%s) to obtain local IP\n",
      hostname); */

  ip = GETHOSTBYNAME(hostname);
  if (ip == NULL) {    
    LOG(LOG_ERROR,
	_("Could not find IP of host '%s': %s\n"),
	hostname, 
	hstrerror(h_errno));
    FREE(hostname);
    return SYSERR;
  }
  FREE(hostname);
  if (ip->h_addrtype != AF_INET) {
    BREAK();
    return SYSERR;
  }
  memcpy(identity,
	 &((struct in_addr*)ip->h_addr_list[0])->s_addr,
	 sizeof(struct in_addr));
  return OK;
}

#if USE_IPV6
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
	_("Could not find IP of host '%s': %s\n"),
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
#endif

#if LINUX || SOMEBSD || MINGW
#define MAX_INTERFACES 16
static int getAddressFromIOCTL(IPaddr * identity) {
  char * interfaces;
#ifndef MINGW
  struct ifreq ifr[MAX_INTERFACES];
  struct ifconf ifc;
  int sockfd,ifCount;
#else
  DWORD dwIP;
#endif
  int i;

  interfaces = getConfigurationString("NETWORK",
				      "INTERFACE");
  if (interfaces == NULL) {
    LOG(LOG_ERROR,
	"No interface specified in section NETWORK under INTERFACE!\n");
    return SYSERR; /* that won't work! */
  }
#ifndef MINGW
  sockfd = SOCKET(PF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1) {
    FREE(interfaces);
    LOG_STRERROR(LOG_ERROR, "socket");
    return SYSERR;
  }
  ifc.ifc_len = sizeof(ifr);
  ifc.ifc_buf = (char*)&ifr;
  
  if (ioctl(sockfd, SIOCGIFCONF, &ifc) == -1) {
    LOG_STRERROR(LOG_WARNING, "ioctl");
    CLOSE(sockfd);
    FREE(interfaces);
    return SYSERR;
  }
  ifCount = ifc.ifc_len / sizeof(struct ifreq);
  
  /* first, try to find exatly matching interface */
  for(i=0;i<ifCount;i++){
    if (ioctl(sockfd, SIOCGIFADDR, &ifr[i]) != 0)
       continue;
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr[i]) != 0)
       continue;
    if (!(ifr[i].ifr_flags & IFF_UP))
       continue; 
    if (strcmp((char*) interfaces,
	       (char*) ifr[i].ifr_name) != 0)
      continue;
    memcpy(identity,
	   &(((struct sockaddr_in *)&ifr[i].ifr_addr)->sin_addr),
	   sizeof(struct in_addr));
    CLOSE(sockfd);
    FREE(interfaces);
    return OK;
  }
  LOG(LOG_WARNING,
      _("Could not find interface '%s' in '%s', trying to find another interface.\n"),
      "ioctl",
      interfaces);
  /* if no such interface exists, take any interface but loopback */
  for(i=0;i<ifCount;i++){
    if (ioctl(sockfd, SIOCGIFADDR, &ifr[i]) != 0)
       continue;
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr[i]) != 0)
       continue;
    if (!(ifr[i].ifr_flags & IFF_UP))
       continue;
    if (strncmp("lo", 
		(char*) ifr[i].ifr_name, 2) == 0)
      continue;
    memcpy(identity,
	   &(((struct sockaddr_in *)&ifr[i].ifr_addr)->sin_addr),
	   sizeof(struct in_addr));
    CLOSE(sockfd);
    FREE(interfaces);
    return OK;
  }

  CLOSE(sockfd);
  LOG(LOG_WARNING,
      _("Could not obtain IP for interface '%s' using '%s'.\n"),
      "ioctl",
      interfaces);
  FREE(interfaces);
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
    
    EnumNICs(&pTable, &pAddrTable);
    
    for(dwIfIdx=0; dwIfIdx < pTable->dwNumEntries; dwIfIdx++) {
      unsigned long long l;
      BYTE bPhysAddr[MAXLEN_PHYSADDR];

      l = _atoi64(interfaces);

      memset(bPhysAddr, 0, MAXLEN_PHYSADDR);      
      memcpy(bPhysAddr,
        pTable->table[dwIfIdx].bPhysAddr,
        pTable->table[dwIfIdx].dwPhysAddrLen);

      if (memcmp(bPhysAddr, &l, sizeof(l)) == 0) {
        for(i = 0; i < pAddrTable->dwNumEntries; i++) {  
          if (pAddrTable->table[i].dwIndex == pTable->table[dwIfIdx].dwIndex) {
            iAddrCount++;
            dwIP = pAddrTable->table[i].dwAddr;
          }
        }
      }
    }

    if (! iAddrCount)
      {
      LOG(LOG_WARNING,
	  _("Could not find an IP address for "
	    "interface '%s'.\n"), 
	  interfaces);
      
      return SYSERR;
    }
    else if (iAddrCount > 1)
      LOG(LOG_WARNING, 
	  _("There is more than one IP address specified"
	    " for interface '%s'.\nGNUnet will "
	    "use %u.%u.%u.%u.\n"), 
	  interfaces, 
	  PRIP(ntohl(dwIP)));
    else
      LOG(LOG_DEBUG, _("GNUnet now uses the IP address %u.%u.%u.%u.\n"),
        PRIP(ntohl(dwIP)));

    identity->addr = dwIP;
  }
  else /* Win 95 */
  {
    SOCKET s;
    HOSTENT *pHost;
    SOCKADDR_IN theHost;

    s = SOCKET(PF_INET, SOCK_STREAM, 0);
    pHost = GETHOSTBYNAME("www.example.com");
    if (! pHost) {
      LOG(LOG_ERROR, 
	  _("Could not resolve '%s' to "
	    "determine our IP address: %s\n"), 
	  "www.example.com",
	  STRERROR(errno));
        
      return SYSERR;
    }
    
    theHost.sin_family = AF_INET;
    theHost.sin_port = htons(80);
    theHost.sin_addr.S_un.S_addr = *((unsigned long *) pHost->h_addr_list[0]);
    if (CONNECT(s, (SOCKADDR *) &theHost, sizeof(theHost)) == SOCKET_ERROR) {
      LOG_STRERROR(LOG_ERROR, "connect");
      return SYSERR;
    }
    
    i = sizeof(theHost);
    if (GETSOCKNAME(s, (SOCKADDR *) &theHost, &i) == SOCKET_ERROR) {
      LOG_STRERROR(LOG_ERROR, "getsockname");
      return SYSERR;
    }    
    closesocket(s);    
    identity->addr = theHost.sin_addr.S_un.S_addr;
  }
  
  return OK;
#endif
}

#endif

/**
 * Get the IP address for the local machine.
 * @return SYSERR on error, OK on success
 */
static int getAddress(IPaddr  * address){
  char * ipString;
  int retval;
  struct hostent * ip; /* for the lookup of the IP in gnunet.conf */

  retval = SYSERR;
  ipString = getConfigurationString("NETWORK",
				    "IP");
  if (ipString == NULL || !ipString[0]) {
#if LINUX || SOMEBSD || MINGW
    if (OK == getAddressFromIOCTL(address))
      retval = OK;
    else 
#endif
      retval = getAddressFromHostname(address);
  } else {
    /* LOG(LOG_DEBUG,
        "obtaining local IP address from hostname %s\n",
	ipString); */
    ip = GETHOSTBYNAME(ipString);
    if (ip == NULL) {     
      LOG(LOG_ERROR,
	  _("Could not resolve '%s': %s\n"),
	  ipString, hstrerror(h_errno));
      retval = SYSERR;
    } else {
      if (ip->h_addrtype != AF_INET) {
	BREAK();
	retval = SYSERR;
      } else {
	memcpy (address,
		&((struct in_addr*) ip->h_addr_list[0])->s_addr,
		sizeof(struct in_addr));
	retval = OK;
      }
    }
    FREE(ipString);
  }
  return retval;
}

#if USE_IPV6
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
	  _("Could not resolve '%s': %s\n"),
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
#endif

static void cronRefreshAddress(void * unused) {
  LOG(LOG_CRON,
      "enter cronRefreshAddress\n");
  if (SYSERR == getAddress(&myAddress))
    LOG(LOG_FAILURE,
	_("Could not determine IP address of the local machine!\n"));
  LOG(LOG_CRON,
      "exit cronRefreshAddress\n");
}

#if USE_IPV6
static void cronRefreshAddress6(void * unused) {
  LOG(LOG_CRON,
      "enter cronRefreshAddress6\n");
  if (SYSERR == getAddress6(&myAddress6))
    LOG(LOG_FAILURE,
	_("Could not determine IP(v6) address of the local machine!\n"));
  LOG(LOG_CRON,
      "exit cronRefreshAddress6\n");
}
#endif

/** 
 * Initialize identity module. Requires configuration.
 */
int initAddress() {
  if (SYSERR == getAddress(&myAddress)) {
    LOG(LOG_ERROR,
	_("Could not find IP(v4) for this host. Please provide the IP in the configuration file.\n"));  
    ipv4_init = NO;
  } else {
    ipv4_init = YES;
    addCronJob(&cronRefreshAddress, 
	       2 * cronMINUTES,
	       2 * cronMINUTES,
	       NULL);
  }
#if USE_IPV6
  if (SYSERR == getAddress6(&myAddress6)) {
    LOG(LOG_ERROR,
	_("Could not find IP(v6) for this host. Please provide the IP in the configuration file.\n"));
    ipv6_init = NO;
  } else {
    addCronJob(&cronRefreshAddress6, 
	       2 * cronMINUTES,
	       2 * cronMINUTES,
	       NULL);
    ipv6_init = YES;
  }
#endif
  return OK;
}

/** 
 * Shutdown identity module.
 */
void doneAddress() {
  if (ipv4_init == YES) {
    delCronJob(&cronRefreshAddress, 
	       2 * cronMINUTES,
	       NULL);  
    ipv4_init = NO;
  }
#if USE_IPV6
  if (ipv6_init == YES) {
    delCronJob(&cronRefreshAddress6, 
	       2 * cronMINUTES,
	       NULL);
    ipv6_init = NO;
  }
#endif
 
}

/**
 * Get the IP address for the local machine.
 * @return SYSERR on error, OK on success
 */
int getPublicIPAddress(IPaddr * address) {
  if (ipv4_init == NO)
    return SYSERR;
  *address = myAddress;
  return OK;
}

/**
 * Get the IPv6 address for the local machine.
 * @return SYSERR on error, OK on success
 */
int getPublicIP6Address(IP6addr * address) {
#if USE_IPV6
  if (ipv6_init == NO)
    return SYSERR;
  *address = myAddress6;
  return OK;
#else
  return SYSERR;
#endif
}

/* end of identity.c */
