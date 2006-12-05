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

#include "gnunet_directories.h"
#include "gnunet_util.h"
#include "gnunet_uritrack_lib.h"
#include "platform.h"

/**
 * @brief Struct for URITRACK callback.
 */
typedef struct {
  struct GE_Context * ectx;

  struct GC_Configuration * cfg;
		
  ECRS_SearchProgressCallback iterator;

  void * closure;

  struct PTHREAD * init;

  int abort_init;
} Callback;

static struct MUTEX * lock;

static Callback ** callbacks;

static unsigned int callbacks_size;

static int init_iterator(const ECRS_FileInfo * fi,
			 const HashCode512 * key,
			 int isRoot,
			 void * closure) {
 Callback * c = closure;

 c->iterator(fi,
	     key,
	     isRoot,
	     c->closure);
 if (c->abort_init)
   return SYSERR;
 return OK;
}

static void * init_thread(void * arg) {
  Callback * c = arg;
  URITRACK_listURIs(c->ectx,
		    c->cfg,
		    YES,
		    &init_iterator,
		    arg);
  return NULL;
}

/**
 * Register a handler that is called whenever
 * a URI is tracked.  If URIs are already in
 * the database, the callback will be called
 * for all existing URIs as well.
 */
int URITRACK_registerTrackCallback(struct GE_Context * ectx,
				   struct GC_Configuration * cfg,
				   ECRS_SearchProgressCallback iterator,
				   void * closure) {
  Callback * c;

  c = MALLOC(sizeof(Callback));
  c->ectx = ectx;
  c->cfg = cfg;
  c->iterator = iterator;
  c->closure = closure;
  c->abort_init = NO;
  c->init = PTHREAD_CREATE(&init_thread,
			   c,
			   16 * 1024);
  MUTEX_LOCK(lock);
  GROW(callbacks,
       callbacks_size,
       callbacks_size + 1);
  callbacks[callbacks_size-1] = c;
  MUTEX_UNLOCK(lock);
  return OK;
}

/**
 * Unregister a URI callback.
 */
int URITRACK_unregisterTrackCallback(ECRS_SearchProgressCallback iterator,
				     void * closure) {
  int i;
  void * unused;
  Callback * c;

  MUTEX_LOCK(lock);
  for (i=0;i<callbacks_size;i++) {
    c = callbacks[i];
    if ( (c->iterator == iterator) &&
	 (c->closure == closure) ) {
      c->abort_init = YES;
      PTHREAD_JOIN(c->init, &unused);
      callbacks[i] = callbacks[callbacks_size-1];
      GROW(callbacks,
	   callbacks_size,
	   callbacks_size - 1);
      FREE(c);
      MUTEX_UNLOCK(lock);
      return OK;
    }
  }
  MUTEX_UNLOCK(lock);
  return SYSERR;
}

/**
 * Internal notification about new tracked URI.
 */
void URITRACK_internal_notify(const ECRS_FileInfo * fi) {
  int i;

  MUTEX_LOCK(lock);
  for (i=0;i<callbacks_size;i++)
    callbacks[i]->iterator(fi,
			   NULL,
			   NO,
			   callbacks[i]->closure);
  MUTEX_UNLOCK(lock);
}

void __attribute__ ((constructor)) gnunet_uritrack_ltdl_init() {
  lock = MUTEX_CREATE(NO);
}

void __attribute__ ((destructor)) gnunet_uritrack_ltdl_fini() {
  MUTEX_DESTROY(lock);
  lock = NULL;
}

/* end of callbacks.c */
