/*
     This file is part of GNUnet
     (C) 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/pseudonym/pseudonym_notification.c
 * @brief implementation of the notification mechanism
 * @author Christian Grothoff
 */


#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_pseudonym_lib.h"
#include "gnunet_util.h"

struct DiscoveryCallback
{
  struct DiscoveryCallback *next;
  GNUNET_PSEUDO_PseudonymIterator callback;
  void *closure;
};

static struct DiscoveryCallback *head;

static struct GNUNET_Mutex *lock;

/**
 * Internal notification about new tracked URI.
 */
void
GNUNET_PSEUDO_internal_notify_ (const GNUNET_HashCode * id,
                                const struct GNUNET_ECRS_MetaData *md,
                                int rating)
{
  struct DiscoveryCallback *pos;

  GNUNET_mutex_lock (lock);
  pos = head;
  while (pos != NULL)
    {
      pos->callback (pos->closure, id, md, rating);
      pos = pos->next;
    }
  GNUNET_mutex_unlock (lock);
}



/**
 * Register callback to be invoked whenever we discover
 * a new pseudonym.
 */
int
GNUNET_PSEUDO_register_discovery_callback (struct GNUNET_GE_Context *ectx,
                                           struct GNUNET_GC_Configuration
                                           *cfg,
                                           GNUNET_PSEUDO_PseudonymIterator
                                           iterator, void *closure)
{
  struct DiscoveryCallback *list;

  list = GNUNET_malloc (sizeof (struct DiscoveryCallback));
  list->callback = iterator;
  list->closure = closure;
  GNUNET_mutex_lock (lock);
  list->next = head;
  head = list;
  GNUNET_PSEUDO_list_all (ectx, cfg, iterator, closure);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Unregister pseudonym discovery callback.
 */
int
GNUNET_PSEUDO_unregister_discovery_callback (GNUNET_PSEUDO_PseudonymIterator
                                             iterator, void *closure)
{
  struct DiscoveryCallback *prev;
  struct DiscoveryCallback *pos;

  prev = NULL;
  GNUNET_mutex_lock (lock);
  pos = head;
  while ((pos != NULL) &&
         ((pos->callback != iterator) || (pos->closure != closure)))
    {
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  if (prev == NULL)
    head = pos->next;
  else
    prev->next = pos->next;
  GNUNET_free (pos);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}



void __attribute__ ((constructor)) GNUNET_PSEUDO_ltdl_init ()
{
  lock = GNUNET_mutex_create (GNUNET_NO);
}

void __attribute__ ((destructor)) GNUNET_PSEUDO_ltdl_fini ()
{
  GNUNET_mutex_destroy (lock);
  lock = NULL;
}


/* end of notification.c */
