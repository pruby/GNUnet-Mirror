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
  char * fn;
  char * gh;

  ret = MALLOC(sizeof(FSUI_Context));
  memset(ret, 0, sizeof(FSUI_Context));
  fn = getConfigurationString("",
			      "GNUNET_HOME");
  gh = expandFileName(fn);
  FREE(fn);
  fn = MALLOC(strlen(gh) + strlen("fsui-lock") + 2);
  strcpy(fn, gh);
  FREE(gh);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, "fsui-lock");
  ret->ipc = IPC_SEMAPHORE_NEW(fn,
			       1);
  LOG(LOG_INFO,
      "Getting IPC lock for FSUI (%s).\n",
      fn);
  FREE(fn);
  IPC_SEMAPHORE_DOWN(ret->ipc);
  LOG(LOG_INFO,
      "Aquired IPC lock.\n");
  MUTEX_CREATE_RECURSIVE(&ret->lock);
  ret->ecb = cb;
  ret->ecbClosure = closure;

  return ret;
}

static void freeDownloadList(FSUI_DownloadList * list) {
  FSUI_DownloadList * dpos;
  int i;
  void * unused;

  while (list != NULL) {
    dpos = list;
    list = dpos->next;
    freeDownloadList(dpos->subDownloads);
    freeDownloadList(dpos->subDownloadsNext);
    dpos->signalTerminate = YES;
    PTHREAD_JOIN(&dpos->handle, &unused);
    ECRS_freeUri(dpos->uri);
    FREE(dpos->filename);
    for (i=dpos->completedDownloadsCount-1;i>=0;i--)
      ECRS_freeUri(dpos->completedDownloads[i]);    
    GROW(dpos->completedDownloads,
	 dpos->completedDownloadsCount,
	 0);
    FREE(dpos);
  }
}

/**
 * Stop all processes under FSUI control (serialize state, continue
 * later if possible).
 */
void FSUI_stop(struct FSUI_Context * ctx) {
  FSUI_ThreadList * tpos;
  FSUI_SearchList * spos;
  void * unused;
  int i;

  LOG(LOG_INFO,
      "FSUI shutdown.  This may take a while.\n");
  while (ctx->activeThreads != NULL) {
    tpos = ctx->activeThreads;
    ctx->activeThreads = tpos->next;
    PTHREAD_JOIN(&tpos->handle, &unused);
    FREE(tpos);
  }
  
  while (ctx->activeSearches != NULL) {
    spos = ctx->activeSearches;
    ctx->activeSearches = spos->next;

    spos->signalTerminate = YES;
    PTHREAD_JOIN(&spos->handle, &unused);
    /* FIXME: serialize spos state! */

    ECRS_freeUri(spos->uri);
    for (i=spos->sizeResultsReceived-1;i>=0;i--) {
      ECRS_FileInfo * fi;
      fi = &spos->resultsReceived[i];
      ECRS_freeMetaData(fi->meta);
      ECRS_freeUri(fi->uri);
    }
    GROW(spos->resultsReceived,
	 spos->sizeResultsReceived,
	 0);
    for (i=spos->sizeUnmatchedResultsReceived-1;i>=0;i--) {
      ResultPending * rp = &spos->unmatchedResultsReceived[i];
      GROW(rp->matchingKeys,
	   rp->matchingKeyCount,
	   0);
      ECRS_freeMetaData(rp->fi.meta);
      ECRS_freeUri(rp->fi.uri);
    }
    GROW(spos->unmatchedResultsReceived,
	 spos->sizeUnmatchedResultsReceived,
	 0);
    FREE(spos);
  }

  /* FIXME: serialize dpos state! */
  freeDownloadList(ctx->activeDownloads);
  ctx->activeDownloads = NULL;

  IPC_SEMAPHORE_UP(ctx->ipc);
  IPC_SEMAPHORE_FREE(ctx->ipc);
  MUTEX_DESTROY(&ctx->lock);
  FREE(ctx);
  LOG(LOG_INFO,
      "FSUI shutdown complete.\n");
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
