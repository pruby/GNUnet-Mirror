/*
     This file is part of GNUnet.
     (C) 2007, 2008 Christian Grothoff (and other contributing authors)

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
  GNUNET_CronTime last_refresh;
  GNUNET_CronTime last_request;
  unsigned int salen;
#if HAVE_ADNS
  int posted;
  adns_query query;
#endif
};

static struct IPCache *head;

static struct GNUNET_Mutex *lock;

#if HAVE_ADNS
static int a_init;

static adns_state a_state;
#endif

#if HAVE_ADNS
static void
adns_resolve (struct IPCache *cache)
{
  adns_answer *answer;
  adns_status ret;
  struct IPCache *rec;
  int reti;

  if (a_init == 0)
    {
      a_init = 1;
      adns_init (&a_state, adns_if_noerrprint, NULL);
    }
  if (cache->posted == GNUNET_NO)
    {
      ret = adns_submit_reverse (a_state, cache->sa, adns_r_ptr,
#ifdef adns_qf_none
                                 adns_qf_none,
#else
                                 0,
#endif
                                 cache, &cache->query);
      if (adns_s_ok == ret)
        cache->posted = GNUNET_YES;
    }
  adns_processany (a_state);
  answer = NULL;
  reti = adns_check (a_state, &cache->query, &answer, (void **) &rec);
  if (reti == 0)
    {
      if (answer != NULL)
        {
          if ((answer->rrs.str != NULL) && (*(answer->rrs.str) != NULL))
            cache->addr = GNUNET_strdup (*(answer->rrs.str));
          free (answer);
        }
      cache->posted = GNUNET_NO;
    }
}
#endif

#if HAVE_GETNAMEINFO
static void
getnameinfo_resolve (struct IPCache *cache)
{
  char hostname[256];

  if (0 == getnameinfo (cache->sa, cache->salen, hostname, 255, NULL, 0, 0))
    cache->addr = GNUNET_strdup (hostname);
}
#endif

#if HAVE_GETHOSTBYADDR
static void
gethostbyaddr_resolve (struct IPCache *cache)
{
  struct hostent *ent;

  switch (cache->sa->sa_family)
    {
    case AF_INET:
      ent = gethostbyaddr (&((struct sockaddr_in *) cache->sa)->sin_addr,
                           sizeof (struct in_addr), AF_INET);
      break;
    case AF_INET6:
      ent = gethostbyaddr (&((struct sockaddr_in6 *) cache->sa)->sin6_addr,
                           sizeof (struct in6_addr), AF_INET6);
      break;
    default:
      ent = NULL;
    }
  if (ent != NULL)
    cache->addr = GNUNET_strdup (ent->h_name);
}
#endif

static void
cache_resolve (struct IPCache *cache)
{
#if HAVE_ADNS
  if (cache->sa->sa_family == AF_INET)
    {
      adns_resolve (cache);
      return;
    }
#endif
#if HAVE_GETNAMEINFO
  if (cache->addr == NULL)
    getnameinfo_resolve (cache);
#endif
#if HAVE_GETHOSTBYADDR
  if (cache->addr == NULL)
    gethostbyaddr_resolve (cache);
#endif
}

static struct IPCache *
resolve (const struct sockaddr *sa, unsigned int salen)
{
  struct IPCache *ret;

  ret = GNUNET_malloc (sizeof (struct IPCache));
#if HAVE_ADNS
  ret->posted = GNUNET_NO;
#endif
  ret->next = head;
  ret->salen = salen;
  ret->sa = salen == 0 ? NULL : GNUNET_malloc (salen);
  memcpy (ret->sa, sa, salen);
  ret->last_request = GNUNET_get_time ();
  ret->last_refresh = GNUNET_get_time ();
  ret->addr = NULL;
  cache_resolve (ret);
  head = ret;
  return ret;
}

static char *
no_resolve (const struct sockaddr *sa, unsigned int salen)
{
  char *ret;
  char inet4[INET_ADDRSTRLEN];
  char inet6[INET6_ADDRSTRLEN];

  if (salen < sizeof (struct sockaddr))
    return NULL;
  switch (sa->sa_family)
    {
    case AF_INET:
      if (salen != sizeof (struct sockaddr_in))
        return NULL;
      inet_ntop (AF_INET,
                 &((struct sockaddr_in *) sa)->sin_addr,
                 inet4, INET_ADDRSTRLEN);
      ret = GNUNET_strdup (inet4);
      break;
    case AF_INET6:
      if (salen != sizeof (struct sockaddr_in6))
        return NULL;
      inet_ntop (AF_INET6,
                 &((struct sockaddr_in6 *) sa)->sin6_addr,
                 inet6, INET6_ADDRSTRLEN);
      ret = GNUNET_strdup (inet6);
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
GNUNET_get_ip_as_string (const void *sav, unsigned int salen, int do_resolve)
{
  const struct sockaddr *sa = sav;
  char *ret;
  struct IPCache *cache;
  struct IPCache *prev;
  GNUNET_CronTime now;

  if (salen < sizeof (struct sockaddr))
    return NULL;
  now = GNUNET_get_time ();
  GNUNET_mutex_lock (lock);
  cache = head;
  prev = NULL;
  while ((cache != NULL) &&
         ((cache->salen != salen) || (0 != memcmp (cache->sa, sa, salen))))
    {
      if (cache->last_request + 60 * GNUNET_CRON_MINUTES < now)
        {
#if HAVE_ADNS
          if (cache->posted == GNUNET_YES)
            {
              adns_cancel (cache->query);
              cache->posted = GNUNET_NO;
            }
#endif
          if (prev != NULL)
            {
              prev->next = cache->next;
              GNUNET_free_non_null (cache->addr);
              GNUNET_free (cache->sa);
              GNUNET_free (cache);
              cache = prev->next;
            }
          else
            {
              head = cache->next;
              GNUNET_free_non_null (cache->addr);
              GNUNET_free (cache->sa);
              GNUNET_free (cache);
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
      if (cache->last_refresh + 12 * GNUNET_CRON_HOURS < now)
        {
          GNUNET_free_non_null (cache->addr);
          cache->addr = NULL;
          cache->salen = 0;
          cache_resolve (cache);
        }
#if HAVE_ADNS
      if (cache->posted == GNUNET_YES)
        {
          cache_resolve (cache);
        }
#endif
    }
  else if (do_resolve == GNUNET_NO)
    {
      GNUNET_mutex_unlock (lock);
      return no_resolve (sav, salen);
    }
  else
    cache = resolve (sa, salen);
  ret = (cache->addr == NULL) ? NULL : GNUNET_strdup (cache->addr);
  if (ret == NULL)
    ret = no_resolve (sa, salen);
  GNUNET_mutex_unlock (lock);
  return ret;
}

#if HAVE_GETHOSTBYNAME
static int
gethostbyname_resolve (struct GNUNET_GE_Context *ectx,
                       const char *hostname,
                       struct sockaddr **sa, socklen_t * socklen)
{
  struct hostent *hp;
  struct sockaddr_in *addr;

  hp = GETHOSTBYNAME (hostname);
  if (hp == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _("Could not find IP of host `%s': %s\n"),
                     hostname, hstrerror (h_errno));
      return GNUNET_SYSERR;
    }
  if (hp->h_addrtype != AF_INET)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_GE_ASSERT (NULL, hp->h_length == sizeof (struct in_addr));
  if (NULL == *sa)
    {
      *sa = GNUNET_malloc (sizeof (struct sockaddr_in));
      memset (*sa, 0, sizeof (struct sockaddr_in));
      *socklen = sizeof (struct sockaddr_in);
    }
  else
    {
      if (sizeof (struct sockaddr_in) > *socklen)
        return GNUNET_SYSERR;
      *socklen = sizeof (struct sockaddr_in);
    }
  addr = (struct sockaddr_in *) *sa;
  memset (addr, 0, sizeof (struct sockaddr_in));
  addr->sin_family = AF_INET;
  memcpy (&addr->sin_addr, hp->h_addr_list[0], hp->h_length);
  return GNUNET_OK;
}
#endif

#if HAVE_GETHOSTBYNAME2
static int
gethostbyname2_resolve (struct GNUNET_GE_Context *ectx,
                        const char *hostname,
                        int domain, struct sockaddr **sa, socklen_t * socklen)
{
  struct hostent *hp;

  if (domain == AF_UNSPEC)
    {
      hp = gethostbyname2 (hostname, AF_INET);
      if (hp == NULL)
        hp = gethostbyname2 (hostname, AF_INET6);
    }
  else
    {
      hp = gethostbyname2 (hostname, domain);
    }
  if (hp == NULL)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_BULK,
                     _("Could not find IP of host `%s': %s\n"),
                     hostname, hstrerror (h_errno));
      return GNUNET_SYSERR;
    }
  if ((hp->h_addrtype != domain) && (domain != 0))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  domain = hp->haddrtype;
  if (domain == AF_INET)
    {
      GNUNET_GE_ASSERT (NULL, hp->h_length == sizeof (struct in_addr));
      if (NULL == *sa)
        {
          *sa = GNUNET_malloc (sizeof (struct sockaddr_in));
          memset (*sa, 0, sizeof (struct sockaddr_in));
          *socklen = sizeof (struct sockaddr_in);
        }
      else
        {
          if (sizeof (struct sockaddr_in) > *socklen)
            return GNUNET_SYSERR;
          *socklen = sizeof (struct sockaddr_in);
        }
      memset (*sa, 0, sizeof (struct sockaddr_in));
      (*sa)->sa_family = AF_INET;
      memcpy (&((struct sockaddr_in *) (*sa))->sin_addr,
              hp->h_addr_list[0], hp->h_length);
    }
  else
    {
      GNUNET_GE_ASSERT (NULL, hp->h_length == sizeof (struct in_addr6));
      if (NULL == *sa)
        {
          *sa = GNUNET_malloc (sizeof (struct sockaddr_in6));
          memset (*sa, 0, sizeof (struct sockaddr_in6));
          *socklen = sizeof (struct sockaddr_in6);
        }
      else
        {
          if (sizeof (struct sockaddr_in6) > *socklen)
            return GNUNET_SYSERR;
          *socklen = sizeof (struct sockaddr_in6);
        }
      memset (*sa, 0, sizeof (struct sockaddr_in6));
      (*sa)->sa_family = AF_INET6;
      memcpy (&((struct sockaddr_in6 *) (*sa))->sin6_addr,
              hp->h_addr_list[0], hp->h_length);
    }
  return GNUNET_OK;
}
#endif

#if HAVE_GETADDRINFO
int
getaddrinfo_resolve (struct GNUNET_GE_Context *ectx,
                     const char *hostname,
                     int domain, struct sockaddr **sa, socklen_t * socklen)
{
  int s;
  struct addrinfo hints;
  struct addrinfo *result;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = domain;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;        /* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  if (0 != (s = getaddrinfo (hostname, NULL, &hints, &result)))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     _("Could not resolve `%s': %s\n"), hostname,
                     gai_strerror (s));
      return GNUNET_SYSERR;
    }
  if (result == NULL)
    return GNUNET_SYSERR;
  if (NULL == *sa)
    {
      *sa = GNUNET_malloc (result->ai_addrlen);
      *socklen = result->ai_addrlen;
      memcpy (*sa, result->ai_addr, result->ai_addrlen);
      freeaddrinfo (result);
      return GNUNET_OK;
    }
  if (result->ai_addrlen > *socklen)
    {
      freeaddrinfo (result);
      return GNUNET_SYSERR;
    }
  *socklen = result->ai_addrlen;
  memcpy (*sa, result->ai_addr, result->ai_addrlen);
  freeaddrinfo (result);
  return GNUNET_OK;
}
#endif


/**
 * Convert a string to an IP address.
 *
 * @param hostname the hostname to resolve
 * @param domain AF_INET or AF_INET6; use AF_UNSPEC for "any"
 * @param *sa should be of type "struct sockaddr*" and
 *        will be set to the IP address on success;
 *        if *sa is NULL, sufficient space will be
 *        allocated.
 * @param socklen will be set to the length of *sa.
 *        If *sa is not NULL, socklen will be checked
 *        to see if sufficient space is provided and
 *        updated to the amount of space actually
 *        required/used.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_get_ip_from_hostname (struct GNUNET_GE_Context *ectx,
                             const char *hostname,
                             int domain,
                             struct sockaddr **sa, unsigned int *socklen)
{
  int ret;

  ret = GNUNET_NO;              /* NO: continue trying, OK: success, SYSERR: failure */
  GNUNET_mutex_lock (lock);
#if HAVE_GETADDRINFO
  if (ret == GNUNET_NO)
    ret = getaddrinfo_resolve (ectx, hostname, domain, sa, socklen);
#endif
#if HAVE_GETHOSTBYNAME2
  if (ret == GNUNET_NO)
    ret = gethostbyname2_resolve (ectx, hostname, domain, sa, socklen);
#endif
#if HAVE_GETHOSTBYNAME
  if ((ret == GNUNET_NO) && ((domain == AF_UNSPEC) || (domain == PF_INET)))
    ret = gethostbyname_resolve (ectx, hostname, sa, socklen);
#endif
  GNUNET_mutex_unlock (lock);
  if (ret == GNUNET_NO)
    ret = GNUNET_SYSERR;        /* no further options */
  return ret;
}

void __attribute__ ((constructor)) GNUNET_dns_ltdl_init ()
{
  lock = GNUNET_mutex_create (GNUNET_YES);
}

void __attribute__ ((destructor)) GNUNET_dns_ltdl_fini ()
{
  struct IPCache *pos;
  GNUNET_mutex_destroy (lock);
  while (head != NULL)
    {
      pos = head->next;
#if HAVE_ADNS
      if (head->posted == GNUNET_YES)
        {
          adns_cancel (head->query);
          head->posted = GNUNET_NO;
        }
#endif
      GNUNET_free_non_null (head->addr);
      GNUNET_free (head->sa);
      GNUNET_free (head);
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
