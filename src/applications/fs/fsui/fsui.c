/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_directories.h"
#include "fsui.h"

#define DEBUG_PERSISTENCE NO

/* ***************** CRON code ***************** */

#define FSUI_UDT_FREQUENCY (2 * cronSECONDS)

/**
 * Cron job for download load management.
 */
static void updateDownloadThreads(void * c) {
  FSUI_Context * ctx = c;
  FSUI_DownloadList * dpos;

  MUTEX_LOCK(ctx->lock);
  dpos = ctx->activeDownloads.child;
#if DEBUG_PERSISTENCE
  if (dpos != NULL)
    GE_LOG(ctx->ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Download thread manager schedules pending downloads...\n");
#endif
  while (dpos != NULL) {
    FSUI_updateDownloadThread(dpos);
    dpos = dpos->next;
  }
  MUTEX_UNLOCK(ctx->lock);
}

/* ******************* START code *********************** */

static void signalDownloadResume(struct FSUI_DownloadList * ret,
				 FSUI_Context * ctx) {
  FSUI_Event event;
  cron_t now;
  cron_t eta;

  while (ret != NULL) {
    event.type = FSUI_download_resumed;
    event.data.DownloadResumed.dc.pos = ret;
    event.data.DownloadResumed.dc.cctx = ret->cctx;
    event.data.DownloadResumed.dc.ppos = ret->parent == &ctx->activeDownloads ? NULL : ret->parent;
    event.data.DownloadResumed.dc.pcctx = ret->parent->cctx;
    event.data.DownloadResumed.dc.spos = ret->search;
    event.data.DownloadResumed.dc.sctx = ret->search == NULL ? NULL : ret->search->cctx;
    event.data.DownloadResumed.completed = ret->completed;
    event.data.DownloadResumed.total = ret->total;
    event.data.DownloadResumed.state = ret->state;
    now = get_time();
    if ( (ret->total == 0) || (ret->completed == 0) ) {
      eta = now;
    } else {
      eta = (cron_t) (now - ret->runTime +
		      (((double)(ret->runTime)/(double)ret->completed))
		      * (double)ret->total);
      if (eta < now)
	eta = now;
    }
    event.data.DownloadResumed.eta = eta;
    event.data.DownloadResumed.filename = ret->filename;
    event.data.DownloadResumed.fi.uri = ret->fi.uri;
    event.data.DownloadResumed.fi.meta = ret->fi.meta;
    event.data.DownloadResumed.anonymityLevel = ret->anonymityLevel;
    ret->cctx = ctx->ecb(ctx->ecbClosure, &event);
    if (ret->child != NULL)
      signalDownloadResume(ret->child,
			   ctx);
    ret = ret->next;
  }
}

static void signalUploadResume(struct FSUI_UploadList * ret,
			       FSUI_Context * ctx) {
  FSUI_Event event;
  cron_t now;
  cron_t eta;

  while (ret != NULL) {
    event.type = FSUI_upload_resumed;
    event.data.UploadResumed.uc.pos = ret;
    event.data.UploadResumed.uc.cctx = NULL;
    event.data.UploadResumed.uc.ppos = ret->parent;
    event.data.UploadResumed.uc.pcctx = ret->parent->cctx;
    event.data.UploadResumed.completed = ret->completed;
    event.data.UploadResumed.total = ret->total;
    event.data.UploadResumed.uri = ret->uri;
    event.data.UploadResumed.state = ret->state;
    now = get_time();
    if ( (ret->total == 0) || (ret->completed == 0) ) {
      eta = now;
    } else {
      eta = (cron_t) (ret->start_time +
		      (((double)(now - ret->start_time)/(double)ret->completed))
		      * (double)ret->total);
      if (eta < now)
	eta = now;
    }
    event.data.UploadResumed.eta = eta;
    event.data.UploadResumed.anonymityLevel = ret->shared->anonymityLevel;
    event.data.UploadResumed.filename = ret->filename;
    ret->cctx = ctx->ecb(ctx->ecbClosure, &event);
    if (ret->child != NULL)
      signalUploadResume(ret->child,
			 ctx);
    ret = ret->next;
  }
}

/**
 * Resume uploads.
 * Only re-starts top-level upload threads;
 * threads below are controlled by the parent.
 */
static void doResumeUploads(struct FSUI_UploadList * ret,
			    FSUI_Context * ctx) {
  while (ret != NULL) {
    if (ret->state == FSUI_ACTIVE) {
      ret->shared->handle = PTHREAD_CREATE(&FSUI_uploadThread,
					   ret,
					   128 * 1024);
      if (ret->shared->handle == NULL)
	GE_DIE_STRERROR(ctx->ectx,
			GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
			"pthread_create");
    }
    ret = ret->next;
  }
}

/**
 * Start FSUI manager.  Use the given progress callback to notify the
 * UI about events.  Start processing pending activities that were
 * running when FSUI_stop was called previously.
 *
 * @param name name of the context, must not be NULL
 * @return NULL on error
 */
struct FSUI_Context * FSUI_start(struct GE_Context * ectx,
				 struct GC_Configuration * cfg,
				 const char * name,
				 unsigned int threadPoolSize,
				 int doResume,
				 FSUI_EventCallback cb,
				 void * closure) {
  FSUI_Event event;
  FSUI_Context * ret;
  FSUI_SearchList * list;
  FSUI_UnindexList * xlist;
  char * fn;
  char * gh;
  unsigned long long size;

  GE_ASSERT(ectx, cfg != NULL);
  ret = MALLOC(sizeof(FSUI_Context));
  memset(ret,
	 0,
	 sizeof(FSUI_Context));
  ret->activeDownloads.state
    = FSUI_PENDING; /* !? */
  ret->activeDownloads.ctx = ret;
  ret->cfg = cfg;
  ret->ecb = cb;
  ret->ecbClosure = closure;
  ret->threadPoolSize = threadPoolSize;
  if (ret->threadPoolSize == 0)
    ret->threadPoolSize = 32;
  ret->activeDownloadThreads = 0;

  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &gh);
  disk_directory_create(ectx, gh);
  fn = MALLOC(strlen(gh) + strlen(name) + 2 + 5);
  strcpy(fn, gh);
  FREE(gh);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, name);
  ret->name = fn;

  /* 1) read state  in */
  if (doResume) {
    ret->ipc = IPC_SEMAPHORE_CREATE(ectx,
				    fn,
				    1);
#if DEBUG_PERSISTENCE
    GE_LOG(ectx,
	   GE_INFO | GE_REQUEST | GE_USER,
	   "Getting IPC lock for FSUI (%s).\n",
	   fn);
#endif
    IPC_SEMAPHORE_DOWN(ret->ipc, YES);
#if DEBUG_PERSISTENCE
    GE_LOG(ectx,
	   GE_INFO | GE_REQUEST | GE_USER,
	   "Aquired IPC lock.\n");
#endif
    strcat(fn, ".res");
    FSUI_deserialize(ret);
  } else {
    ret->ipc = NULL;
  }
  ret->lock = MUTEX_CREATE(YES);

  /* 2) do resume events */
  /* 2a) signal download restarts */
  signalDownloadResume(ret->activeDownloads.child,
		       ret);
  /* 2b) signal search restarts */
  list = ret->activeSearches;
  while (list != NULL) {
    event.type = FSUI_search_resumed;
    event.data.SearchResumed.sc.pos = list;
    event.data.SearchResumed.sc.cctx = NULL;
    event.data.SearchResumed.fis = list->resultsReceived;
    event.data.SearchResumed.fisSize = list->sizeResultsReceived;
    event.data.SearchResumed.anonymityLevel = list->anonymityLevel;
    event.data.SearchResumed.searchURI = list->uri;
    event.data.SearchResumed.state = list->state;
    list->cctx = cb(closure, &event);
    list = list->next;
  }
  /* 2c) signal upload restarts */
  signalUploadResume(ret->activeUploads.child,
		     ret);
  /* 2d) signal unindex restarts */
  xlist = ret->unindexOperations;
  while (xlist != NULL) {
    if (OK != disk_file_size(ectx,
			     xlist->filename,
			     &size,
			     YES))
      size = 0;
    event.type = FSUI_unindex_resumed;
    event.data.UnindexResumed.uc.pos = xlist;
    event.data.UnindexResumed.uc.cctx = NULL;
    event.data.UnindexResumed.completed = (xlist->state == FSUI_COMPLETED_JOINED) ? size : 0;
    event.data.UnindexResumed.total = size;
    event.data.UnindexResumed.eta = get_time();
    event.data.UnindexResumed.filename = xlist->filename;
    event.data.UnindexResumed.state = xlist->state;
    xlist->cctx = cb(closure, &event);	
    xlist = xlist->next;
  }

  /* 3) restart processing */
  ret->cron = cron_create(ectx);
  /* 3a) resume downloads */
  cron_add_job(ret->cron,
	       &updateDownloadThreads,
	       0,
	       FSUI_UDT_FREQUENCY,
	       ret);
  cron_start(ret->cron);
  /* 3b) resume uploads */
  doResumeUploads(ret->activeUploads.child,
		  ret);
  /* 3c) resume unindexing */
  xlist = ret->unindexOperations;
  while (xlist != NULL) {
    if (xlist->state == FSUI_PENDING) {
      xlist->state = FSUI_ACTIVE;
      xlist->handle = PTHREAD_CREATE(&FSUI_unindexThread,
				     xlist,
				     32 * 1024);
      if (xlist->handle == NULL)
	GE_DIE_STRERROR(ectx,
			GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
			"pthread_create");
    }
    xlist = xlist->next;
  }
  /* 3d) resume searching */
  list = ret->activeSearches;
  while (list != NULL) {
    if (list->state == FSUI_PENDING) {
      list->state = FSUI_ACTIVE;
      list->handle = PTHREAD_CREATE(&FSUI_searchThread,
				    list,
				    32 * 1024);
      if (list->handle == NULL)
	GE_DIE_STRERROR(ectx,
			GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
			"pthread_create");
    }
    list = list->next;
  }

  return ret;
}

/* ******************* STOP code *********************** */

/**
 * (recursively) signal download suspension.
 */
static void signalDownloadSuspend(struct GE_Context * ectx,
				  FSUI_Context * ctx,
				  FSUI_DownloadList * list) {
  FSUI_Event event;
  while (list != NULL) {
    signalDownloadSuspend(ectx,
			  ctx,
			  list->child);
    event.type = FSUI_download_suspended;
    event.data.DownloadSuspended.dc.pos = list;
    event.data.DownloadSuspended.dc.cctx = list->cctx;
    event.data.DownloadSuspended.dc.ppos = list->parent == &ctx->activeDownloads ? NULL : list->parent;
    event.data.DownloadSuspended.dc.pcctx = list->parent->cctx;
    event.data.DownloadSuspended.dc.spos = list->search;
    event.data.DownloadSuspended.dc.sctx = list->search == NULL ? NULL : list->search->cctx;
    ctx->ecb(ctx->ecbClosure, &event);
    list = list->next;
  }
}

/**
 * (recursively) signal upload suspension.
 */
static void signalUploadSuspend(struct GE_Context * ectx,
				FSUI_Context * ctx,
				FSUI_UploadList * upos) {
  FSUI_Event event;
  while (upos != NULL) {
    signalUploadSuspend(ectx,
			ctx,
			upos->child);
    event.type = FSUI_upload_suspended;
    event.data.UploadSuspended.uc.pos = upos;
    event.data.UploadSuspended.uc.cctx = upos->cctx;
    event.data.UploadSuspended.uc.ppos = upos->parent;
    event.data.UploadSuspended.uc.pcctx = upos->parent->cctx;
    ctx->ecb(ctx->ecbClosure, &event);
    upos = upos->next;
  }
}

/**
 * (recursively) free download list
 */
static void freeDownloadList(FSUI_DownloadList * list) {
  FSUI_DownloadList *  next;
  int i;

  while (list != NULL) {
    freeDownloadList(list->child);
    ECRS_freeUri(list->fi.uri);
    ECRS_freeMetaData(list->fi.meta);
    FREE(list->filename);
    for (i=0;i<list->completedDownloadsCount;i++)
      ECRS_freeUri(list->completedDownloads[i]);
    GROW(list->completedDownloads,
	 list->completedDownloadsCount,
	 0);
    next = list->next;
    FREE(list);
    list = next;
  }
}

/**
 * (recursively) free upload list
 */
static void freeUploadList(struct FSUI_Context * ctx,
			   FSUI_UploadList * list) {
  FSUI_UploadList *  next;
  FSUI_UploadShared * shared;

  while (list != NULL) {
    freeUploadList(ctx, list->child);
    next = list->next;
    FREE(list->filename);
    if (list->meta != NULL)
      ECRS_freeMetaData(list->meta);
    if (list->keywords != NULL)
      ECRS_freeUri(list->keywords);
    if (list->uri != NULL)
      ECRS_freeUri(list->uri);
    if (list->parent == &ctx->activeUploads) {
      shared = list->shared;
      EXTRACTOR_removeAll(shared->extractors);
      if (shared->global_keywords != NULL)
	ECRS_freeUri(shared->global_keywords);
      FREENONNULL(shared->extractor_config);
      FREE(shared);
    }
    FREE(list);
    list = next;
  }
}

/**
 * Stop all processes under FSUI control (serialize state, continue
 * later if possible).
 */
void FSUI_stop(struct FSUI_Context * ctx) {
  struct GE_Context * ectx;
  FSUI_SearchList * spos;
  FSUI_DownloadList * dpos;
  FSUI_UnindexList * xpos;
  FSUI_UploadList * upos;
  FSUI_Event event;
  void * unused;
  int i;

  ectx = ctx->ectx;
  if (ctx->ipc != NULL)
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "FSUI shutdown.  This may take a while.\n");

  /* 1) stop everything */
  cron_stop(ctx->cron);
  cron_del_job(ctx->cron,
	       &updateDownloadThreads,
	       FSUI_UDT_FREQUENCY,
	       ctx);
  cron_destroy(ctx->cron);

  /* 1a) stop downloading */
  ctx->threadPoolSize = 0;
  dpos = ctx->activeDownloads.child;
  while (dpos != NULL) {
    FSUI_updateDownloadThread(dpos);
    dpos = dpos->next;
  }
  /* 1b) stop searching */
  spos = ctx->activeSearches;
  while (spos != NULL) {
    if ( (spos->state == FSUI_ACTIVE) ||
	 (spos->state == FSUI_ABORTED) ||
	 (spos->state == FSUI_ERROR) ||
	 (spos->state == FSUI_COMPLETED) ) {
      if (spos->state == FSUI_ACTIVE)
	spos->state = FSUI_PENDING;
      PTHREAD_STOP_SLEEP(spos->handle);
      PTHREAD_JOIN(spos->handle, &unused);
      if (spos->state != FSUI_PENDING)
	spos->state++; /* _JOINED */
    }
    spos = spos->next;
  }
  /* 1c) stop unindexing */
  xpos = ctx->unindexOperations;
  while (xpos != NULL) {
    if ( (xpos->state == FSUI_ACTIVE) ||
	 (xpos->state == FSUI_ABORTED) ||
	 (xpos->state == FSUI_ERROR) ||
	 (xpos->state == FSUI_COMPLETED) ) {
      if (xpos->state == FSUI_ACTIVE)
	xpos->state = FSUI_PENDING;
      PTHREAD_STOP_SLEEP(xpos->handle);
      PTHREAD_JOIN(xpos->handle, &unused);
      if (xpos->state != FSUI_PENDING)
	xpos->state++; /* _JOINED */
    }
    xpos = xpos->next;
  }
  /* 1d) stop uploading */
  upos = ctx->activeUploads.child;
  while (upos != NULL) {
    if ( (upos->state == FSUI_ACTIVE) ||
	 (upos->state == FSUI_ABORTED) ||
	 (upos->state == FSUI_ERROR) ||
	 (upos->state == FSUI_COMPLETED) ) {
      /* NOTE: will force transitive termination
	 of rest of tree! */
      if (upos->state == FSUI_ACTIVE)
	upos->state = FSUI_PENDING;
      PTHREAD_STOP_SLEEP(upos->shared->handle);
      PTHREAD_JOIN(upos->shared->handle, &unused);
      if (upos->state != FSUI_PENDING)
	upos->state++; /* _JOINED */
    }
    upos = upos->next;
  }

  /* 2) signal suspension events */
  /* 2a) signal search suspension */
  spos = ctx->activeSearches;
  while (spos != NULL) {
    event.type = FSUI_search_suspended;
    event.data.SearchSuspended.sc.pos = spos;
    event.data.SearchSuspended.sc.cctx = spos->cctx;
    ctx->ecb(ctx->ecbClosure, &event);
    spos = spos->next;
  }
  /* 2b) signal uploads suspension */
  signalUploadSuspend(ectx,
		      ctx,
		      ctx->activeUploads.child);
  /* 2c) signal downloads suspension */
  signalDownloadSuspend(ectx,
			ctx,
			ctx->activeDownloads.child);
  /* 2d) signal unindex suspension */
  xpos = ctx->unindexOperations;
  while (xpos != NULL) {
    event.type = FSUI_unindex_suspended;
    event.data.UnindexSuspended.uc.pos = xpos;
    event.data.UnindexSuspended.uc.cctx = xpos->cctx;
    ctx->ecb(ctx->ecbClosure, &event);
    xpos = xpos->next;
  }

  /* 3) serialize all of the FSUI state */
  if (ctx->ipc != NULL)
    FSUI_serialize(ctx);

  /* 4) finally, free memory */
  /* 4a) free search memory */
  while (ctx->activeSearches != NULL) {
    spos = ctx->activeSearches;
    ctx->activeSearches = spos->next;
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
      ResultPending * rp;

      rp = &spos->unmatchedResultsReceived[i];
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
  /* 4b) free unindex memory */
  while (ctx->unindexOperations != NULL) {
    xpos = ctx->unindexOperations;
    ctx->unindexOperations = xpos->next;
    FREE(xpos->filename);
    FREE(xpos);
  }
  /* 4c) free upload memory */
  freeUploadList(ctx,
		 ctx->activeUploads.child);
  /* 4d) free download memory */
  freeDownloadList(ctx->activeDownloads.child);

  /* 5) finish FSUI Context */
  if (ctx->ipc != NULL) {
    IPC_SEMAPHORE_UP(ctx->ipc);
    IPC_SEMAPHORE_DESTROY(ctx->ipc);
  }
  MUTEX_DESTROY(ctx->lock);
  FREE(ctx->name);
  if (ctx->ipc != NULL)
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "FSUI shutdown complete.\n");
  FREE(ctx);
}


/* end of fsui.c */
