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
 *
 * TODO:
 * - upload tree representation (currently flat list!)
 * - download tree free memory
 * - resume signaling: some minor fields uninitialized
 * - better ETA calculation for download resume
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

  while (ret != NULL) {
    event.type = FSUI_download_resumed;
    event.data.DownloadResumed.dc.pos = ret;
    event.data.DownloadResumed.dc.cctx = ret->cctx;
    event.data.DownloadResumed.dc.ppos = ret->parent;
    event.data.DownloadResumed.dc.pcctx = ret->parent->cctx;
    event.data.DownloadResumed.eta = get_time(); /* FIXME: can do better here! */
    event.data.DownloadResumed.total = ret->total;
    event.data.DownloadResumed.completed = ret->completed;
    event.data.DownloadResumed.anonymityLevel = ret->anonymityLevel;
    event.data.DownloadResumed.uri = ret->uri;
    ret->cctx = ctx->ecb(ctx->ecbClosure, &event);
    if (ret->child != NULL)
      signalDownloadResume(ret->child,
			   ctx);
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
  FSUI_UploadList * ulist;
  FSUI_UnindexList * xlist;
  char * fn;
  char * gh;

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
    list->cctx = cb(closure, &event);	
    list = list->next;
  }
  /* 2c) signal upload restarts */
  ulist = ret->activeUploads;
  while (ulist != NULL) {
    event.type = FSUI_upload_resumed;
    event.data.UploadResumed.uc.pos = ulist;
    event.data.UploadResumed.uc.cctx = NULL;
    event.data.UploadResumed.completed = ulist->main_completed;
    event.data.UploadResumed.total = ulist->main_total;
    event.data.UploadResumed.anonymityLevel = ulist->anonymityLevel;
    event.data.UploadResumed.eta = 0; /* FIXME: use start_time for estimate! */
    event.data.UploadResumed.filename = ulist->filename;
    ulist->cctx = cb(closure, &event);	
    ulist = ulist->next;
  }
  /* 2d) signal unindex restarts */
  xlist = ret->unindexOperations;
  while (xlist != NULL) {
    event.type = FSUI_unindex_resumed;
    event.data.UnindexResumed.uc.pos = xlist;
    event.data.UnindexResumed.uc.cctx = NULL;
    event.data.UnindexResumed.completed = 0; /* FIXME */
    event.data.UnindexResumed.total = 0; /* FIXME */
    event.data.UnindexResumed.eta = 0; /* FIXME: use start_time for estimate! */
    event.data.UnindexResumed.filename = xlist->filename;
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
  ulist = ret->activeUploads;
  while (ulist != NULL) {
    if ( (ulist->state != FSUI_ABORTED_JOINED) &&
	 (ulist->state != FSUI_COMPLETED_JOINED) &&
	 (ulist->state != FSUI_ERROR_JOINED) ) {
      ulist->state = FSUI_ACTIVE;
      ulist->handle = PTHREAD_CREATE(&FSUI_uploadThread,
				     ulist,
				     32 * 1024);
      if (ulist->handle == NULL)
	GE_DIE_STRERROR(ectx,
			GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
			"pthread_create");
    }     
    ulist = ulist->next;
  }
  /* 3c) resume unindexing */
  xlist = ret->unindexOperations;
  while (xlist != NULL) {
    if ( (xlist->state != FSUI_ABORTED_JOINED) &&
	 (xlist->state != FSUI_COMPLETED_JOINED) &&
	 (xlist->state != FSUI_ERROR_JOINED) ) {
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
    if ( (list->state != FSUI_ABORTED_JOINED) &&
	 (list->state != FSUI_COMPLETED_JOINED) &&
	 (list->state != FSUI_ERROR_JOINED) ) {
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
    event.data.DownloadSuspended.dc.ppos = list->parent;
    event.data.DownloadSuspended.dc.pcctx = list->parent->cctx; 
    ctx->ecb(ctx->ecbClosure, &event);
    list = list->next;
  }
}

/**
 * (recursively) free download list
 */
static void freeDownloadList(FSUI_DownloadList * list) {
  FSUI_DownloadList *  next;
  
  while (list != NULL) {
    freeDownloadList(list->child);
    /* FIXME: free memory! */
    next = list->next;
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
	   GE_INFO | GE_REQUEST | GE_USER,
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
    spos->signalTerminate = YES;
    PTHREAD_STOP_SLEEP(spos->handle);
    PTHREAD_JOIN(spos->handle, &unused);
    spos = spos->next;
  }
  /* 1c) stop unindexing */
  xpos = ctx->unindexOperations;
  while (xpos != NULL) {
    xpos->force_termination = YES;
    PTHREAD_STOP_SLEEP(xpos->handle);
    PTHREAD_JOIN(xpos->handle, &unused);    
    xpos = xpos->next;    
  }
  /* 1d) stop uploading */
  upos = ctx->activeUploads;
  while (upos != NULL) {
    upos->force_termination = YES;
    PTHREAD_STOP_SLEEP(upos->handle);
    PTHREAD_JOIN(upos->handle, &unused);
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
  upos = ctx->activeUploads;
  while (upos != NULL) {
    event.type = FSUI_upload_suspended;
    event.data.UploadSuspended.uc.pos = upos;
    event.data.UploadSuspended.uc.cctx = upos->cctx;
    event.data.UploadSuspended.uc.ppos = NULL; /* FIXME */
    event.data.UploadSuspended.uc.pcctx = NULL; /* FIXME */
    ctx->ecb(ctx->ecbClosure, &event);
    upos = upos->next;
  }
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
  while (ctx->activeUploads != NULL) {
    upos = ctx->activeUploads;
    ctx->activeUploads = upos->next;
    FREE(upos->filename);
    FREENONNULL(upos->main_filename);
    ECRS_freeMetaData(upos->meta);
    ECRS_freeUri(upos->uri);
    if (upos->globalUri != NULL)
      ECRS_freeUri(upos->globalUri);
    EXTRACTOR_removeAll(upos->extractors);
    FREE(upos);
  }
  /* 4d) free download memory */
  freeDownloadList(ctx->activeDownloads.child);

  /* 5) finish FSUI Context */
  if (ctx->ipc != NULL) {
    IPC_SEMAPHORE_UP(ctx->ipc);
    IPC_SEMAPHORE_DESTROY(ctx->ipc);
  }
  MUTEX_DESTROY(ctx->lock);
  FREE(ctx->name);
  FREE(ctx);
  if (ctx->ipc != NULL)
    GE_LOG(ectx,
	   GE_INFO | GE_REQUEST | GE_USER,
	   "FSUI shutdown complete.\n");
}


/* end of fsui.c */
