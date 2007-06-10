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
 * @file transports/ip.c
 * @brief code to determine thep IP of the local machine
 *        and to do DNS resolution (with caching)
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
#if HAVE_GETNAMEINFO
  char hostname[256];

  if (0 == getnameinfo(cache->sa,
		       cache->salen,
		       hostname,
		       255,
		       NULL, 0,
		       NI_NAMEREQD))
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
}

static struct IPCache * resolve(const struct sockaddr * sa,
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
  cache_resolve(ret);
  head = ret;
  return ret;
}


/**
 * Get an IP address as a string
 * (works for both IPv4 and IPv6).
 */ 
char * getIPaddressAsString(const void * sav,
			    unsigned int salen) {
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

struct PICache {
  struct PICache * next;
  char * address;
  PeerIdentity peer;
  cron_t expire;
};

static struct PICache * pi_head;

static void expirePICache() {
  struct PICache * pos; 
  struct PICache * next; 
  struct PICache * prev; 
  cron_t now;
  
  now = get_time();
  pos = pi_head;
  prev = NULL;
  while (pos != NULL) {
    next = pos->next;
    if (pos->expire < now) {
      FREE(pos->address);
      FREE(pos);
      if (prev == NULL)
	pi_head = next;
      else
	prev->next = next;
    }
    prev = pos;
    pos = next;
  }
}

/**
 * We only have the PeerIdentity.  Do we have any
 * clue about the address (as a string) based on 
 * the "accept" of the connection?  Note that the
 * response is just the best guess.
 */
char * getIPaddressFromPID(const PeerIdentity * peer) {
  char * ret;
  struct PICache * cache; 

  ret = NULL;
  MUTEX_LOCK(lock);
  expirePICache();
  cache = pi_head;
  while (cache != NULL) {
    if (0 == memcmp(peer,
		    &cache->peer,
		    sizeof(PeerIdentity))) {      
      ret = STRDUP(cache->address);
      break;
    }
    cache = cache->next;
  }
  MUTEX_UNLOCK(lock);
  return ret;
}

/**
 * We have accepted a connection from a particular
 * address (here given as a string) and received
 * a welcome message that claims that this connection
 * came from a particular peer.  This information is
 * NOT validated (and it may well be impossible for
 * us to validate the address).  
 */
void setIPaddressFromPID(const PeerIdentity * peer,
			 const char * address) {
  struct PICache * next;

  MUTEX_LOCK(lock);
  next = pi_head;
  while (next != NULL) {
    if (0 == memcmp(peer,
		    &next->peer,
		    sizeof(PeerIdentity))) {
      next->expire = get_time() + 12 * cronHOURS;
      if (0 == strcmp(address,
		      next->address)) {
	MUTEX_UNLOCK(lock);  
	return;
      }
      FREE(next->address);
      next->address = STRDUP(address);
      MUTEX_UNLOCK(lock);  
      return;      
    }
    next = next->next;
  }
  next = MALLOC(sizeof(struct PICache));
  next->peer = *peer;
  next->address = STRDUP(address);
  next->expire = get_time() + 12 * cronHOURS;
  expirePICache();
  next->next = pi_head;  
  pi_head = next;
  MUTEX_UNLOCK(lock);  
  
}



void __attribute__ ((constructor)) gnunet_ip_ltdl_init() {
  lock = MUTEX_CREATE(YES);
}

void __attribute__ ((destructor)) gnunet_ip_ltdl_fini() {
  struct IPCache * pos;
  struct PICache * ppos;
  MUTEX_DESTROY(lock);
  while (head != NULL) {
    pos = head->next;
    FREENONNULL(head->addr);
    FREE(head->sa);
    FREE(head);
    head = pos;
  }
  while (pi_head != NULL) {
    ppos = pi_head->next;
    FREE(pi_head->address);
    FREE(pi_head);
    pi_head = ppos;
  }
}


/* end of ip.c */
