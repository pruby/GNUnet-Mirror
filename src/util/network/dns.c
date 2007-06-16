/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file util/network/dns.c
 * @brief code to do DNS resolution
 *
 * @author Christian Grothoff
 */

#include <stdlib.h>
#include "platform.h"
#include "gnunet_util_network.h"


/**
 * Disable DNS resolutions.  The existing DNS resolution
 * code is synchronous and introduces ~500ms delays while
 * holding an important lock.  As a result, it makes
 * GNUnet laggy.  This should be fixed in the future.
 */
#define NO_RESOLVE YES


struct IPCache {
  struct IPCache * next;
  char * addr;
  struct sockaddr * sa;
  cron_t last_refresh;
  cron_t last_request;
  unsigned int salen;
};

static struct IPCache * head;

static struct MUTEX * lock;

static void cache_resolve(struct IPCache * cache) {
#if NO_RESOLVE
  if (cache->sa->sa_family == AF_INET) {
    cache->addr = STRDUP("255.255.255.255");
    SNPRINTF(cache->addr,
	     strlen("255.255.255.255")+1,
	     "%u.%u.%u.%u",
	     PRIP(ntohl(*(int*)&((struct sockaddr_in*) cache->sa)->sin_addr)));
  } else {
    cache->addr = STRDUP("IPv6");
  }
#else
#if HAVE_GETNAMEINFO
  char hostname[256];

  if (0 == getnameinfo(cache->sa,
		       cache->salen,
		       hostname,
		       255,
		       NULL, 0,
		       0))
    cache->addr = STRDUP(hostname);
#else
#if HAVE_GETHOSTBYADDR
  struct hostent * ent;
  
  switch (cache->sa->sa_family) {
  case AF_INET:
    ent = gethostbyaddr(&((struct sockaddr_in*) cache->sa)->sin_addr,
			sizeof(IPaddr),
			AF_INET);
    break;
  case AF_INET6:
    ent = gethostbyaddr(&((struct sockaddr_in6*) cache->sa)->sin6_addr,
			sizeof(IPaddr6),
			AF_INET6);
    break;
  default:
    ent = NULL;
  }
  if (ent != NULL)
    cache->addr = STRDUP(ent->h_name); 
#endif
#endif
#endif
}

static struct IPCache * 
resolve(const struct sockaddr * sa,
	unsigned int salen) {
  struct IPCache * ret;

  ret = MALLOC(sizeof(struct IPCache));
  ret->next = head;
  ret->salen = salen;
  ret->sa = salen == 0 ? NULL : MALLOC(salen);
  memcpy(ret->sa,
	 sa,
	 salen);
  ret->last_request = get_time();
  ret->last_refresh = get_time();
  ret->addr = NULL;
  cache_resolve(ret);
  head = ret;
  return ret;
}

#if IPV6_STUFF
  char * ret;
  char inet6[INET6_ADDRSTRLEN];
  const Host6Address * haddr = (const Host6Address*) &hello[1];
  char * hn;
  size_t n;
  struct sockaddr_in6 serverAddr;

  if (do_resolve) {
    memset((char *) &serverAddr,
	   0,
	   sizeof(serverAddr));
    serverAddr.sin6_family   = AF_INET6;
    memcpy(&serverAddr.sin6_addr,
	   haddr,
	   sizeof(IP6addr));
    serverAddr.sin6_port = haddr->port;
    hn = getIPaddressAsString((const struct sockaddr*) &serverAddr,
			      sizeof(struct sockaddr_in));
  } else
    hn = NULL;
  n = INET6_ADDRSTRLEN + 16 +  (hn == NULL ? 0 : strlen(hn)) + 10;
  ret = MALLOC(n);
  if (hn != NULL) {
    SNPRINTF(ret,
	     n,
	     "%s (%s) TCP6 (%u)",
	     hn,
	     inet_ntop(AF_INET6,
		       haddr,
		       inet6,
		       INET6_ADDRSTRLEN),
	     ntohs(haddr->port));
  } else {
    SNPRINTF(ret,
	     n,
	     "%s TCP6 (%u)",
	     inet_ntop(AF_INET6,
		       haddr,
		       inet6,
		       INET6_ADDRSTRLEN),
	     ntohs(haddr->port));
  }
  FREENONNULL(hn);
  return ret;
}
#endif


/**
 * Get an IP address as a string (works for both IPv4 and IPv6).  Note
 * that the resolution happens asynchronously and that the first call
 * may not immediately result in the FQN (but instead in a
 * human-readable IP address).
 *
 * @param sa should be of type "struct sockaddr*"
 */ 
char * network_get_ip_as_string(const void * sav,
				unsigned int salen,
				int do_resolve) {
  const struct sockaddr * sa = sav;
  char * ret;
  struct IPCache * cache; 
  struct IPCache * prev;
  cron_t now;

  now = get_time();  
  MUTEX_LOCK(lock);
  cache = head;
  prev = NULL;
  while ( (cache != NULL) &&
	  ( (cache->salen != salen) ||
	    (0 != memcmp(cache->sa,
			 sa,
			 salen) ) ) ) {
    if (cache->last_request + 60 * cronMINUTES < now) {
      if (prev != NULL) {
	prev->next = cache->next;
	FREENONNULL(cache->addr);
	FREE(cache->sa);
	FREE(cache);      
	cache = prev->next;
      } else {
	head = cache->next;
	FREENONNULL(cache->addr);
	FREE(cache->sa);
	FREE(cache);      
	cache = head;	
      }
      continue;
    }    
    prev = cache;
    cache = cache->next;
  }
  if (cache != NULL) {
    cache->last_request = now;
    if (cache->last_refresh + 12 * cronHOURS < now) {
      FREENONNULL(cache->addr);
      cache->addr = NULL;
      cache_resolve(cache);
    }
  } else
    cache = resolve(sa, salen);  
  ret = (cache->addr == NULL) ? NULL : STRDUP(cache->addr);
  MUTEX_UNLOCK(lock);
  return ret;
}




void __attribute__ ((constructor)) gnunet_dns_ltdl_init() {
  lock = MUTEX_CREATE(YES);
}

void __attribute__ ((destructor)) gnunet_dns_ltdl_fini() {
  struct IPCache * pos;
  MUTEX_DESTROY(lock);
  while (head != NULL) {
    pos = head->next;
    FREENONNULL(head->addr);
    FREE(head->sa);
    FREE(head);
    head = pos;
  }
}
