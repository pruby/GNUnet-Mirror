/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/fsui.c
 * @brief main FSUI functions
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

/**
 * Start FSUI manager.  Use the given progress callback to notify the
 * UI about events.  Start processing pending activities that were
 * running when FSUI_stop was called previously.
 *
 * @return NULL on error
 */
struct FSUI_Context * FSUI_start(FSUI_EventCallback cb,
				 void * closure) {
  FSUI_Context * ret;

  ret = MALLOC(sizeof(FSUI_Context));
  memset(ret, 0, sizeof(FSUI_Context));
  MUTEX_CREATE_RECURSIVE(&ret->lock);
  ret->ecb = cb;
  ret->ecbClosure = closure;

  return ret;
}

/**
 * Stop all processes under FSUI control (serialize state, continue
 * later if possible).
 */
void FSUI_stop(struct FSUI_Context * ctx) {
  MUTEX_DESTROY(&ctx->lock);
  FREE(ctx);
}

/**
 * Set the anonymity level in this FSUI context for
 * all actions that are started from now on (until
 * the next call to setAnonymityLevel).
 */
void FSUI_setAnonymityLevel(struct FSUI_Context * ctx,
			    unsigned int anonymityLevel) {
  ctx->anonymityLevel = anonymityLevel;
}

/**
 * Get the anonymity level that is currently used
 * by this FSUI context.
 */
unsigned int FSUI_getAnonymityLevel(const struct FSUI_Context * ctx) {
  return ctx->anonymityLevel;
}


/* *************** internal helper functions *********** */


void cleanupFSUIThreadList(FSUI_Context * ctx) {
  FSUI_ThreadList * pos;
  FSUI_ThreadList * tmp;
  FSUI_ThreadList * prev;
  FSUI_DownloadList * dpos;
  FSUI_DownloadList * dprev;
  FSUI_DownloadList * dtmp;
  void * unused;
  int i;
  
  prev = NULL;
  MUTEX_LOCK(&ctx->lock);
  pos = ctx->activeThreads;
  while (pos != NULL) {
    if (YES == pos->isDone) {
      PTHREAD_JOIN(&pos->handle,
		   &unused);
      tmp = pos->next;
      FREE(pos);
      if (prev != NULL)
	prev->next = tmp;
      else
	ctx->activeThreads = tmp;
      pos = tmp;
    } else {
      prev = pos;
      pos = pos->next;
    }
  }

  dpos = ctx->activeDownloads;
  dprev = NULL;
  while (dpos != NULL) {
    if (YES == dpos->signalTerminate) {
      PTHREAD_JOIN(&dpos->handle,
		   &unused);
      dtmp = dpos->next;
      ECRS_freeUri(dpos->uri);
      FREE(dpos->filename);
      for (i=0;i<dpos->completedDownloadsCount;i++)
	ECRS_freeUri(dpos->completedDownloads[i]);
      GROW(dpos->completedDownloads,
	   dpos->completedDownloadsCount,
	   0);      
      FREE(dpos);
      if (dprev != NULL)
	dprev->next = dtmp;
      else
	ctx->activeDownloads = dtmp;
      dpos = dtmp;
    } else {
      dprev = dpos;
      dpos = dpos->next;
    }
  }


  MUTEX_UNLOCK(&ctx->lock);
}


/* end of fsui.c */
