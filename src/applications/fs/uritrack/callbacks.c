/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/uritrack/callbacks.c
 * @brief callbacks for URI tracking
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "gnunet_uritrack_lib.h"

/**
 * @brief Struct for URITRACK callback.
 */
typedef struct
{
  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  GNUNET_ECRS_SearchResultProcessor iterator;

  void *closure;

  struct GNUNET_ThreadHandle *init;

  int abort_init;
} Callback;

static struct GNUNET_Mutex *lock;

static Callback **callbacks;

static unsigned int callbacks_size;

static int
init_iterator (const GNUNET_ECRS_FileInfo * fi,
               const GNUNET_HashCode * key, int isRoot, void *closure)
{
  Callback *c = closure;

  c->iterator (fi, key, isRoot, c->closure);
  if (c->abort_init)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

static void *
init_thread (void *arg)
{
  Callback *c = arg;
  GNUNET_URITRACK_list (c->ectx, c->cfg, GNUNET_YES, &init_iterator, arg);
  return NULL;
}

/**
 * Register a handler that is called whenever
 * a URI is tracked.  If URIs are already in
 * the database, the callback will be called
 * for all existing URIs as well.
 */
int
GNUNET_URITRACK_register_track_callback (struct GNUNET_GE_Context *ectx,
                                         struct GNUNET_GC_Configuration *cfg,
                                         GNUNET_ECRS_SearchResultProcessor
                                         iterator, void *closure)
{
  Callback *c;

  c = GNUNET_malloc (sizeof (Callback));
  c->ectx = ectx;
  c->cfg = cfg;
  c->iterator = iterator;
  c->closure = closure;
  c->abort_init = GNUNET_NO;
  c->init = GNUNET_thread_create (&init_thread, c, 16 * 1024);
  GNUNET_mutex_lock (lock);
  GNUNET_array_grow (callbacks, callbacks_size, callbacks_size + 1);
  callbacks[callbacks_size - 1] = c;
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * Unregister a URI callback.
 */
int
GNUNET_URITRACK_unregister_track_callback (GNUNET_ECRS_SearchResultProcessor
                                           iterator, void *closure)
{
  int i;
  void *unused;
  Callback *c;

  GNUNET_mutex_lock (lock);
  for (i = 0; i < callbacks_size; i++)
    {
      c = callbacks[i];
      if ((c->iterator == iterator) && (c->closure == closure))
        {
          c->abort_init = GNUNET_YES;
          GNUNET_thread_join (c->init, &unused);
          callbacks[i] = callbacks[callbacks_size - 1];
          GNUNET_array_grow (callbacks, callbacks_size, callbacks_size - 1);
          GNUNET_free (c);
          GNUNET_mutex_unlock (lock);
          return GNUNET_OK;
        }
    }
  GNUNET_mutex_unlock (lock);
  return GNUNET_SYSERR;
}

/**
 * Internal notification about new tracked URI.
 */
void
GNUNET_URITRACK_internal_notify (const GNUNET_ECRS_FileInfo * fi)
{
  int i;

  GNUNET_mutex_lock (lock);
  for (i = 0; i < callbacks_size; i++)
    callbacks[i]->iterator (fi, NULL, GNUNET_NO, callbacks[i]->closure);
  GNUNET_mutex_unlock (lock);
}

void __attribute__ ((constructor)) GNUNET_URITRACK_ltdl_init ()
{
  lock = GNUNET_mutex_create (GNUNET_NO);
}

void __attribute__ ((destructor)) GNUNET_URITRACK_ltdl_fini ()
{
  GNUNET_mutex_destroy (lock);
  lock = NULL;
}

/* end of callbacks.c */
