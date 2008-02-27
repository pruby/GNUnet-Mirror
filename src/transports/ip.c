/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
#if HAVE_IFADDRS_H
#if HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <ifaddrs.h>
#endif

/* maximum length of hostname */
#define MAX_HOSTNAME 1024

/**
 * Get the IP address for the local machine.
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_IP_get_public_ipv4_address (struct GNUNET_GC_Configuration *cfg,
                                   struct GNUNET_GE_Context *ectx,
                                   struct in_addr *address)
{
  static struct in_addr myAddress;
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
                         GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Failed to obtain my (external) %s address!\n"),
                         "IP");
          lastError = now;
          return GNUNET_SYSERR;
        }
      GNUNET_free (ips);
      last = now;
    }
  memcpy (address, &myAddress, sizeof (struct in_addr));
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


/**
 * Obtain the identity information for the current node
 * (connection information), conInfo.
 * @return GNUNET_SYSERR on failure, GNUNET_OK on success
 */
static int
getAddress6FromHostname (struct GNUNET_GE_Context *ectx,
                         struct in6_addr *identity)
{
  char hostname[MAX_HOSTNAME];
  struct sockaddr_in6 addr;
  struct sockaddr *sa;
  socklen_t salen;

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
  salen = sizeof (struct sockaddr_in);
  sa = (struct sockaddr *) &addr;
  if (GNUNET_OK !=
      GNUNET_get_ip_from_hostname (ectx, hostname, AF_INET6, &sa, &salen))
    return GNUNET_SYSERR;
  *identity = addr.sin6_addr;
  return GNUNET_OK;
}

#if HAVE_GETIFADDRS && HAVE_FREEIFADDRS
static int
getAddress6FromGetIfAddrs (struct GNUNET_GC_Configuration *cfg,
                           struct GNUNET_GE_Context *ectx,
                           struct in6_addr *identity)
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
                      &((struct sockaddr_in6 *) ifa_ptr->ifa_addr)->sin6_addr,
                      sizeof (struct in6_addr));
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
             struct GNUNET_GE_Context *ectx, struct in6_addr *address)
{
  char *ipString;
  int retval;
  socklen_t sa_len;
  struct sockaddr *sa;
  struct sockaddr_in6 sa6;

  retval = GNUNET_SYSERR;
  if (GNUNET_GC_have_configuration_value (cfg, "NETWORK", "IP6"))
    {
      ipString = NULL;
      GNUNET_GC_get_configuration_value_string (cfg,
                                                "NETWORK", "IP6", "",
                                                &ipString);
      sa_len = sizeof (struct sockaddr_in6);
      sa = (struct sockaddr *) &sa6;
      if ((strlen (ipString) > 0) &&
          (GNUNET_OK ==
           GNUNET_get_ip_from_hostname (ectx,
                                        ipString, AF_INET6, &sa, &sa_len)))
        {
          *address = sa6.sin6_addr;
          retval = GNUNET_OK;
        }
      GNUNET_free (ipString);
    }
#if HAVE_GETIFADDRS && HAVE_FREEIFADDRS
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
GNUNET_IP_get_public_ipv6_address (struct GNUNET_GC_Configuration *cfg,
                                   struct GNUNET_GE_Context *ectx,
                                   struct in6_addr *address)
{
  static struct in6_addr myAddress;
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
                         GNUNET_GE_INFO | GNUNET_GE_USER | GNUNET_GE_BULK,
                         _("Failed to obtain my (external) %s address!\n"),
                         "IPv6");
          return GNUNET_SYSERR;
        }
      last = now;
    }
  memcpy (address, &myAddress, sizeof (struct in6_addr));
  return GNUNET_OK;
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
