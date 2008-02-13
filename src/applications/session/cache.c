/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file session/cache.c
 * @brief module responsible for caching
 *   sessionkey exchange requests
 * @author Christian Grothoff
 *
 * TODO: add code to evict very old entries from the cache!
 */
#include "platform.h"
#include "cache.h"

#define MAX_CACHE_ENTRIES 8

struct Entry
{
  struct Entry *next;
  GNUNET_MessageHeader *msg;
  GNUNET_PeerIdentity peer;
  GNUNET_AES_SessionKey key;
  GNUNET_Int32Time time_limit;
};

static unsigned int count;

static struct Entry *cache;

static struct GNUNET_Mutex *lock;

static void
expire_oldest_entries ()
{
  struct Entry *e;
  struct Entry *prev;
  GNUNET_Int32Time oldest;

  oldest = -1;                  /* infinity */
  e = cache;
  while (e != NULL)
    {
      if (e->time_limit < oldest)
        oldest = e->time_limit;
      e = e->next;
    }
  e = cache;
  prev = NULL;
  while (e != NULL)
    {
      if (e->time_limit == oldest)
        {
          if (prev == NULL)
            cache = e->next;
          else
            prev->next = e->next;
          GNUNET_free (e->msg);
          GNUNET_free (e);
          count--;
          return;
        }
      prev = e;
      e = e->next;
    }
}

/**
 * Query the cache, obtain a cached key exchange message
 * if possible.
 *
 * @param peer for the key
 * @param msg set to key exchange message
 * @return GNUNET_OK on success
 */
int
GNUNET_session_cache_get (const GNUNET_PeerIdentity * peer,
                          GNUNET_Int32Time time_limit,
                          const GNUNET_AES_SessionKey * key,
                          unsigned short size, GNUNET_MessageHeader ** msg)
{
  struct Entry *e;

  GNUNET_mutex_lock (lock);
  e = cache;
  while (e != NULL)
    {
      if ((0 == memcmp (&e->peer,
                        peer,
                        sizeof (GNUNET_PeerIdentity))) &&
          (0 == memcmp (&e->key,
                        key,
                        sizeof (GNUNET_AES_SessionKey))) &&
          (e->time_limit == time_limit) && (ntohs (e->msg->size) == size))
        {
          *msg = GNUNET_malloc (ntohs (e->msg->size));
          memcpy (*msg, e->msg, ntohs (e->msg->size));
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
      e = e->next;
    }
  GNUNET_mutex_unlock (lock);
  return GNUNET_SYSERR;
}

/**
 * Store a message in the cache.
 *
 * @param peer for the key
 * @param msg the key exchange message
 * @return GNUNET_OK on success
 */
void
GNUNET_session_cache_put (const GNUNET_PeerIdentity * peer,
                          GNUNET_Int32Time time_limit,
                          const GNUNET_AES_SessionKey * key,
                          const GNUNET_MessageHeader * msg)
{
  struct Entry *e;

  GNUNET_mutex_lock (lock);
  e = cache;
  while (e != NULL)
    {
      if (0 == memcmp (&e->peer, peer, sizeof (GNUNET_PeerIdentity)))
        break;
      e = e->next;
    }
  if (e == NULL)
    {
      e = GNUNET_malloc (sizeof (struct Entry));
      e->msg = NULL;
      e->peer = *peer;
      e->next = cache;
      cache = e;
      count++;
    }
  GNUNET_free_non_null (e->msg);
  e->key = *key;
  e->time_limit = time_limit;
  e->msg = GNUNET_malloc (ntohs (msg->size));
  memcpy (e->msg, msg, ntohs (msg->size));
  if (count > MAX_CACHE_ENTRIES)
    expire_oldest_entries ();
  GNUNET_mutex_unlock (lock);
}

void __attribute__ ((constructor)) GNUNET_session_cache_ltdl_init ()
{
  lock = GNUNET_mutex_create (GNUNET_NO);
}

void __attribute__ ((destructor)) GNUNET_session_cache_ltdl_fini ()
{
  struct Entry *e;
  while (cache != NULL)
    {
      e = cache;
      cache = e->next;
      GNUNET_free (e->msg);
      GNUNET_free (e);
    }
  GNUNET_mutex_destroy (lock);
  lock = NULL;
}
