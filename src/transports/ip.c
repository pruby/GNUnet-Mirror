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
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_IP_get_public_ipv4_address (struct GNUNET_GC_Configuration *cfg,
                                   struct GNUNET_GE_Context *ectx,
                                   GNUNET_IPv4Address * address)
{
  static GNUNET_IPv4Address myAddress;
  static GNUNET_CronTime last;
  static GNUNET_CronTime lastError;
  GNUNET_CronTime now;
  char *ips;

  now = GNUNET_get_time ();
  if (last + GNUNET_CRON_MINUTES < now)
    {
      if (lastError + 30 * GNUNET_CRON_SECONDS > now)
        return GNUNET_SYSERR;
      ips = GNUNET_get_local_ip (cfg, ectx, &myAddress);
      if (ips == NULL)
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_WARNING | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Failed to obtain my (external) %s address!\n"),
                         "IP");
          lastError = now;
          return GNUNET_SYSERR;
        }
      GNUNET_free (ips);
      last = now;
    }
  memcpy (address, &myAddress, sizeof (GNUNET_IPv4Address));
  return GNUNET_OK;
}

struct PICache
{
  struct PICache *next;
  void *address;
  unsigned int len;
  GNUNET_PeerIdentity peer;
  GNUNET_CronTime expire;
};

static struct PICache *pi_head;

static struct GNUNET_Mutex *lock;

static void
expirePICache ()
{
  struct PICache *pos;
  struct PICache *next;
  struct PICache *prev;
  GNUNET_CronTime now;

  now = GNUNET_get_time ();
  pos = pi_head;
  prev = NULL;
  while (pos != NULL)
    {
      next = pos->next;
      if (pos->expire < now)
        {
          GNUNET_free (pos->address);
          GNUNET_free (pos);
          if (prev == NULL)
            pi_head = next;
          else
            prev->next = next;
        }
      else
        prev = pos;
      pos = next;
    }
}


/**
 * We only have the GNUNET_PeerIdentity.  Do we have any
 * clue about the address based on
 * the "accept" of the connection?  Note that the
 * response is just the best guess.
 *
 * @param sa set to the address
 * @return GNUNET_OK if we found an address, GNUNET_SYSERR if not
 */
int
GNUNET_IP_get_address_from_peer_identity (const GNUNET_PeerIdentity * peer,
                                          void **sa, unsigned int *salen)
{
  struct PICache *cache;

  GNUNET_mutex_lock (lock);
  expirePICache ();
  cache = pi_head;
  while (cache != NULL)
    {
      if (0 == memcmp (peer, &cache->peer, sizeof (GNUNET_PeerIdentity)))
        {
          *salen = cache->len;
          *sa = GNUNET_malloc (cache->len);
          memcpy (*sa, cache->address, cache->len);
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
      cache = cache->next;
    }
  GNUNET_mutex_unlock (lock);
  return GNUNET_SYSERR;
}

/**
 * We have accepted a connection from a particular
 * address (here given as a string) and received
 * a welcome message that claims that this connection
 * came from a particular peer.  This information is
 * NOT validated (and it may well be impossible for
 * us to validate the address).
 */
void
GNUNET_IP_set_address_for_peer_identity (const GNUNET_PeerIdentity * peer,
                                         const void *sa, unsigned int salen)
{
  struct PICache *next;

  GNUNET_mutex_lock (lock);
  next = pi_head;
  while (next != NULL)
    {
      if (0 == memcmp (peer, &next->peer, sizeof (GNUNET_PeerIdentity)))
        {
          next->expire = GNUNET_get_time () + 12 * GNUNET_CRON_HOURS;
          if ((salen == next->len) &&
              (0 == memcmp (sa, next->address, salen)))
            {
              GNUNET_mutex_unlock (lock);
              return;
            }
          GNUNET_free (next->address);
          next->address = GNUNET_malloc (salen);
          next->len = salen;
          memcpy (next->address, sa, salen);
          GNUNET_mutex_unlock (lock);
          return;
        }
      next = next->next;
    }
  next = GNUNET_malloc (sizeof (struct PICache));
  next->peer = *peer;
  next->address = GNUNET_malloc (salen);
  memcpy (next->address, sa, salen);
  next->len = salen;
  next->expire = GNUNET_get_time () + 12 * GNUNET_CRON_HOURS;
  expirePICache ();
  next->next = pi_head;
  pi_head = next;
  GNUNET_mutex_unlock (lock);

}



void __attribute__ ((constructor)) GNUNET_IP_ltdl_init ()
{
  lock = GNUNET_mutex_create (GNUNET_YES);
}

void __attribute__ ((destructor)) GNUNET_IP_ltdl_fini ()
{
  struct PICache *ppos;
  GNUNET_mutex_destroy (lock);
  while (pi_head != NULL)
    {
      ppos = pi_head->next;
      GNUNET_free (pi_head->address);
      GNUNET_free (pi_head);
      pi_head = ppos;
    }
}


/* end of ip.c */
