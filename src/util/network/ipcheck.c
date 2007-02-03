/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/network/ipcheck.c
 * @brief test if an IP matches a given subnet
 * @author Christian Grothoff
 */

#include "gnunet_util_network.h"
#include "gnunet_util_string.h"
#include "gnunet_util_error.h"
#include "platform.h"

/**
 * @brief IPV4 network in CIDR notation.
 */
typedef struct CIDRNetwork {
  IPaddr network;
  IPaddr netmask;
} CIDRNetwork;

/**
 * @brief network in CIDR notation for IPV6.
 */
typedef struct CIDR6Network {
  IP6addr network;
  IP6addr netmask;
} CIDR6Network;


/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in dotted-decimal
 * notation. The netmask can be given in CIDR notation (/16) or
 * in dotted-decimal (/255.255.0.0).
 * <p>
 * @param routeList a string specifying the forbidden networks
 * @return the converted list, NULL if the synatx is flawed
 */
CIDRNetwork * parse_ipv4_network_specification(struct GE_Context * ectx,
					       const char * routeList) {
  unsigned int count;
  unsigned int i;
  unsigned int j;
  unsigned int len;
  int cnt;
  unsigned int pos;
  unsigned int temps[8];
  int slash;
  CIDRNetwork * result;

  if (routeList == NULL)
    return NULL;
  len = strlen(routeList);
  if (len == 0)
    return NULL;
  count = 0;
  for (i=0;i<len;i++)
    if (routeList[i] == ';')
      count++;
  result = MALLOC(sizeof(CIDRNetwork) * (count+1));
  /* add termination */
  memset(result,
	 0,
	 sizeof(CIDRNetwork)*(count+1));
  i=0;
  pos = 0;
  while (i < count) {
    cnt = sscanf(&routeList[pos],
		 "%u.%u.%u.%u/%u.%u.%u.%u;",
		 &temps[0],
		 &temps[1],
		 &temps[2],
		 &temps[3],
		 &temps[4],
		 &temps[5],
		 &temps[6],
		 &temps[7]);
    if (cnt == 8) {
      for (j=0;j<8;j++)
	if (temps[j] > 0xFF) {
	  GE_LOG(ectx,
		 GE_ERROR | GE_USER | GE_IMMEDIATE,
		 _("Invalid format for IP: `%s'\n"),
		 &routeList[pos]);
	  FREE(result);
	  return NULL;
	}
      result[i].network.addr
	= htonl((temps[0] << 24) + (temps[1] << 16) + (temps[2] << 8) + temps[3]);
      result[i].netmask.addr
	= htonl((temps[4] << 24) + (temps[5] << 16) + (temps[6] << 8) + temps[7]);
      while (routeList[pos] != ';')
	pos++;
      pos++;
      i++;
      continue;
    }
    /* try second notation */
    cnt = sscanf(&routeList[pos],
		 "%u.%u.%u.%u/%u;",
		 &temps[0],
		 &temps[1],
		 &temps[2],
		 &temps[3],
		 &slash);
    if (cnt == 5) {
      for (j=0;j<4;j++)
	if (temps[j] > 0xFF) {
	  GE_LOG(ectx,
		 GE_ERROR | GE_USER | GE_IMMEDIATE,
		 _("Invalid format for IP: `%s'\n"),
		 &routeList[pos]);
	  FREE(result);
	  return NULL;
	}
      result[i].network.addr
	= htonl((temps[0] << 24) + (temps[1] << 16) + (temps[2] << 8) + temps[3]);
      if ( (slash <= 32) && (slash > 0) ) {
	result[i].netmask.addr = 0;
	while (slash > 0) {
	  result[i].netmask.addr
	    = (result[i].netmask.addr >> 1) + 0x80000000;
	  slash--;
	}
	result[i].netmask.addr
	  = htonl(result[i].netmask.addr);
	while (routeList[pos] != ';')
	  pos++;
	pos++;
 	i++;
	continue;
      } else {
	GE_LOG(ectx,
	       GE_ERROR | GE_USER | GE_IMMEDIATE,
	       _("Invalid network notation ('/%d' is not legal in IPv4 CIDR)."),
	       slash);
	FREE(result);
	return NULL; /* error */
      }
    }
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_IMMEDIATE,
	   _("Invalid format for IP: `%s'\n"),
	   &routeList[pos]);
    FREE(result);
    return NULL; /* error */
  }
  if (pos < strlen(routeList)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_IMMEDIATE,
	   _("Invalid format for IP: `%s'\n"),
	   &routeList[pos]);
    FREE(result);
    return NULL; /* oops */
  }
  return result; /* ok */
}


/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in colon-hex
 * notation.  The netmask must be given in CIDR notation (/16) or
 * can be omitted to specify a single host.
 * <p>
 * @param routeList a string specifying the forbidden networks
 * @return the converted list, NULL if the synatx is flawed
 */
CIDR6Network * parse_ipv6_network_specification(struct GE_Context * ectx,
						const char * routeListX) {
  unsigned int count;
  unsigned int i;
  unsigned int len;
  unsigned int pos;
  int start;
  int slash;
  int ret;
  char * routeList;
  CIDR6Network * result;

  if (routeListX == NULL)
    return NULL;
  len = strlen(routeListX);
  if (len == 0)
    return NULL;
  routeList = STRDUP(routeListX);
  count = 0;
  for (i=0;i<len;i++)
    if (routeList[i] == ';')
      count++;
  if (routeList[len-1] != ';') {
    GE_LOG(ectx,
	   GE_ERROR | GE_USER | GE_IMMEDIATE,
	   _("Invalid network notation (does not end with ';': `%s')\n"),
	   routeList);
    FREE(routeList);
    return NULL;
  }

  result = MALLOC(sizeof(CIDR6Network) * (count+1));
  memset(result,
	 0,
	 sizeof(CIDR6Network) * (count+1));
  i=0;
  pos = 0;
  while (i < count) {
    start = pos;
    while (routeList[pos] != ';')
      pos++;
    slash = pos;
    while ( (slash >= start) &&
	    (routeList[slash] != '/') )
      slash--;
    if (slash < start) {
      memset(&result[i].netmask,
	     0xFF,
	     sizeof(IP6addr));	
      slash = pos;
    } else {
      routeList[pos] = '\0';
      ret = inet_pton(AF_INET6,
		      &routeList[slash+1],
		      &result[i].netmask);
      if (ret <= 0) {
	GE_LOG(ectx,
	       GE_ERROR | GE_USER | GE_IMMEDIATE,
	       _("Wrong format `%s' for netmask: %s\n"),
	       &routeList[slash+1],
	       STRERROR(errno));
	FREE(result);
	FREE(routeList);
	return NULL;
      }
    }
    routeList[slash] = '\0';
    ret = inet_pton(AF_INET6,
		    &routeList[start],
		    &result[i].network);
    if (ret <= 0) {
      GE_LOG(ectx,
	     GE_ERROR | GE_USER | GE_IMMEDIATE,
	     _("Wrong format `%s' for network: %s\n"),
	     &routeList[slash+1],
	       STRERROR(errno));
      FREE(result);
      FREE(routeList);
      return NULL;
    }
    pos++;
  }
  FREE(routeList);
  return result;
}


/**
 * Check if the given IP address is in the list of IP addresses.
 *
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return NO if the IP is not in the list, YES if it it is
 */
int check_ipv4_listed(const CIDRNetwork * list,
		      IPaddr ip) {
  int i;
  IPaddr add;

  add = ip;
  i=0;
  if (list == NULL)
    return NO;

  while ( (list[i].network.addr != 0) ||
	  (list[i].netmask.addr != 0) ) {
    if ( (add.addr & list[i].netmask.addr) ==
	 (list[i].network.addr & list[i].netmask.addr) )
      return YES;
    i++;
  }
  return NO;
}

/**
 * Check if the given IP address is in the list of IP addresses.
 *
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return NO if the IP is not in the list, YES if it it is
 */
int check_ipv6_listed(const CIDR6Network * list,
		      IP6addr ip) {
  unsigned int i;
  unsigned int j;
  struct in6_addr zero;

  i=0;
  if (list == NULL)
    return NO;

  memset(&zero, 0, sizeof(struct in6_addr));
  while ( (memcmp(&zero, &list[i].network, sizeof(struct in6_addr)) != 0) ||
	  (memcmp(&zero, &list[i].netmask, sizeof(struct in6_addr)) != 0) ) {
    for (j=0;j<sizeof(struct in6_addr)/sizeof(int);j++)
      if ( ((((int*)&ip)[j] & ((int*)&list[i].netmask)[j])) !=
	   (((int*)&list[i].network)[j] & ((int*)&list[i].netmask)[j]) ) {
      i++;
      continue;
    }
    return YES;
  }
  return NO;
}

/* end of ipcheck.c */
