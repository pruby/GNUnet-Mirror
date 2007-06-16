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

struct PICache {
  struct PICache * next;
  void * address;
  unsigned int len;
  PeerIdentity peer;
  cron_t expire;
};

static struct PICache * pi_head;

static struct MUTEX * lock;

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
    } else
      prev = pos;
    pos = next;
  }
}


/**
 * We only have the PeerIdentity.  Do we have any
 * clue about the address based on 
 * the "accept" of the connection?  Note that the
 * response is just the best guess.
 * 
 * @param sa set to the address
 * @return OK if we found an address, SYSERR if not
 */
int getIPaddressFromPID(const PeerIdentity * peer,
			void ** sa,
			unsigned int * salen) {
  struct PICache * cache; 

  MUTEX_LOCK(lock);
  expirePICache();
  cache = pi_head;
  while (cache != NULL) {
    if (0 == memcmp(peer,
		    &cache->peer,
		    sizeof(PeerIdentity))) {      
      *salen = cache->len;
      *sa = MALLOC(cache->len);
      memcpy(*sa,
	     cache->address,
	     cache->len);
      MUTEX_UNLOCK(lock);
      return OK;
    }
    cache = cache->next;
  }
  MUTEX_UNLOCK(lock);
  return SYSERR;
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
			 const void * sa,
			 unsigned int salen) {
  struct PICache * next;

  MUTEX_LOCK(lock);
  next = pi_head;
  while (next != NULL) {
    if (0 == memcmp(peer,
		    &next->peer,
		    sizeof(PeerIdentity))) {
      next->expire = get_time() + 12 * cronHOURS;
      if ( (salen == next->len) &&
	   (0 == memcmp(sa,
			next->address,
			salen)) )  {
	MUTEX_UNLOCK(lock);  
	return;
      }
      FREE(next->address);
      next->address = MALLOC(salen);
      next->len = salen;
      memcpy(next->address,
	     sa,
	     salen);
      MUTEX_UNLOCK(lock);  
      return;      
    }
    next = next->next;
  }
  next = MALLOC(sizeof(struct PICache));
  next->peer = *peer;
  next->address = MALLOC(salen);
  memcpy(next->address,
	 sa,
	 salen);
  next->len = salen;
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
  struct PICache * ppos;
  MUTEX_DESTROY(lock);
  while (pi_head != NULL) {
    ppos = pi_head->next;
    FREE(pi_head->address);
    FREE(pi_head);
    pi_head = ppos;
  }
}


/* end of ip.c */
