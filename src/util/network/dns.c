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

#if HAVE_ADNS
#include <adns.h>
#endif


struct IPCache
{
  struct IPCache *next;
  char *addr;
  struct sockaddr *sa;
  cron_t last_refresh;
  cron_t last_request;
  unsigned int salen;
#if HAVE_ADNS
  int posted;
  adns_query query;
#endif
};

static struct IPCache *head;

static struct MUTEX *lock;

#if HAVE_ADNS
static int a_init;

static adns_state a_state;
#endif

static void
cache_resolve (struct IPCache *cache)
{
#if HAVE_ADNS
  adns_answer *answer;
  adns_status ret;
  struct IPCache *rec;
  int reti;

  if (a_init == 0)
    {
      a_init = 1;
      adns_init (&a_state, adns_if_noerrprint, NULL);
    }
  if (cache->posted == NO)
    {
      ret = adns_submit_reverse (a_state, cache->sa, adns_r_ptr,
#ifdef adns_qf_none
                                 adns_qf_none,
#else
                                 0,
#endif
                                 cache, &cache->query);
      if (adns_s_ok == ret)
        cache->posted = YES;
    }
  adns_processany (a_state);
  answer = NULL;
  reti = adns_check (a_state, &cache->query, &answer, (void **) &rec);
  if (reti == 0)
    {
      if (answer != NULL)
        {
          if ((answer->rrs.str != NULL) && (*(answer->rrs.str) != NULL))
            cache->addr = STRDUP (*(answer->rrs.str));
          free (answer);
        }
      cache->posted = NO;
    }
#else
#if HAVE_GETNAMEINFO
  char hostname[256];

  if (0 == getnameinfo (cache->sa, cache->salen, hostname, 255, NULL, 0, 0))
    cache->addr = STRDUP (hostname);
#else
#if HAVE_GETHOSTBYADDR
  struct hostent *ent;

  switch (cache->sa->sa_family)
    {
    case AF_INET:
      ent = gethostbyaddr (&((struct sockaddr_in *) cache->sa)->sin_addr,
                           sizeof (IPaddr), AF_INET);
      break;
    case AF_INET6:
      ent = gethostbyaddr (&((struct sockaddr_in6 *) cache->sa)->sin6_addr,
                           sizeof (IPaddr6), AF_INET6);
      break;
    default:
      ent = NULL;
    }
  if (ent != NULL)
    cache->addr = STRDUP (ent->h_name);
#endif
#endif
#endif
}

static struct IPCache *
resolve (const struct sockaddr *sa, unsigned int salen)
{
  struct IPCache *ret;

  ret = MALLOC (sizeof (struct IPCache));
#if HAVE_ADNS
  ret->posted = NO;
#endif
  ret->next = head;
  ret->salen = salen;
  ret->sa = salen == 0 ? NULL : MALLOC (salen);
  memcpy (ret->sa, sa, salen);
  ret->last_request = get_time ();
  ret->last_refresh = get_time ();
  ret->addr = NULL;
  cache_resolve (ret);
  head = ret;
  return ret;
}

static char *
no_resolve (const struct sockaddr *sa, unsigned int salen)
{
  char *ret;
  char inet6[INET6_ADDRSTRLEN];

  if (salen < sizeof (struct sockaddr))
    return NULL;
  switch (sa->sa_family)
    {
    case AF_INET:
      if (salen != sizeof (struct sockaddr_in))
        return NULL;
      ret = STRDUP ("255.255.255.255");
      SNPRINTF (ret,
                strlen ("255.255.255.255") + 1,
                "%u.%u.%u.%u",
                PRIP (ntohl
                      (*(int *) &((struct sockaddr_in *) sa)->sin_addr)));
      break;
    case AF_INET6:
      if (salen != sizeof (struct sockaddr_in6))
        return NULL;
      inet_ntop (AF_INET6,
                 &((struct sockaddr_in6 *) sa)->sin6_addr,
                 inet6, INET6_ADDRSTRLEN);
      ret = STRDUP (inet6);
      break;
    default:
      ret = NULL;
      break;
    }
  return ret;
}

/**
 * Get an IP address as a string (works for both IPv4 and IPv6).  Note
 * that the resolution happens asynchronously and that the first call
 * may not immediately result in the FQN (but instead in a
 * human-readable IP address).
 *
 * @param sa should be of type "struct sockaddr*"
 */
char *
network_get_ip_as_string (const void *sav, unsigned int salen, int do_resolve)
{
  const struct sockaddr *sa = sav;
  char *ret;
  struct IPCache *cache;
  struct IPCache *prev;
  cron_t now;

  if (salen < sizeof (struct sockaddr))
    return NULL;
  now = get_time ();
  MUTEX_LOCK (lock);
  cache = head;
  prev = NULL;
  while ((cache != NULL) &&
         ((cache->salen != salen) || (0 != memcmp (cache->sa, sa, salen))))
    {
      if (cache->last_request + 60 * cronMINUTES < now)
        {
#if HAVE_ADNS
          if (cache->posted == YES)
            {
              adns_cancel (cache->query);
              cache->posted = NO;
            }
#endif
          if (prev != NULL)
            {
              prev->next = cache->next;
              FREENONNULL (cache->addr);
              FREE (cache->sa);
              FREE (cache);
              cache = prev->next;
            }
          else
            {
              head = cache->next;
              FREENONNULL (cache->addr);
              FREE (cache->sa);
              FREE (cache);
              cache = head;
            }
          continue;
        }
      prev = cache;
      cache = cache->next;
    }
  if (cache != NULL)
    {
      cache->last_request = now;
      if (cache->last_refresh + 12 * cronHOURS < now)
        {
          FREENONNULL (cache->addr);
          cache->addr = NULL;
          cache->salen = 0;
          cache_resolve (cache);
        }
#if HAVE_ADNS
      if (cache->posted == YES)
        {
          cache_resolve (cache);
        }
#endif
    }
  else if (do_resolve == NO)
    {
      MUTEX_UNLOCK (lock);
      return no_resolve (sav, salen);
    }
  else
    cache = resolve (sa, salen);
  ret = (cache->addr == NULL) ? NULL : STRDUP (cache->addr);
  if (ret == NULL)
    ret = no_resolve (sa, salen);
  MUTEX_UNLOCK (lock);
  return ret;
}




void __attribute__ ((constructor)) gnunet_dns_ltdl_init ()
{
  lock = MUTEX_CREATE (YES);
}

void __attribute__ ((destructor)) gnunet_dns_ltdl_fini ()
{
  struct IPCache *pos;
  MUTEX_DESTROY (lock);
  while (head != NULL)
    {
      pos = head->next;
#if HAVE_ADNS
      if (head->posted == YES)
        {
          adns_cancel (head->query);
          head->posted = NO;
        }
#endif
      FREENONNULL (head->addr);
      FREE (head->sa);
      FREE (head);
      head = pos;
    }
#if HAVE_ADNS
  if (a_init != 0)
    {
      a_init = 0;
      adns_finish (a_state);
    }
#endif
}
