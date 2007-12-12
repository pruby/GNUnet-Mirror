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

#define DEBUG_PERSISTENCE GNUNET_NO

/* ***************** CRON code ***************** */

#define GNUNET_FSUI_UDT_FREQUENCY (2 * GNUNET_CRON_SECONDS)

/**
 * Cron job for download load management.
 */
static void
updateDownloadThreads (void *c)
{
  GNUNET_FSUI_Context *ctx = c;
  GNUNET_FSUI_DownloadList *dpos;

  GNUNET_mutex_lock (ctx->lock);
  dpos = ctx->activeDownloads.child;
#if DEBUG_PERSISTENCE
  if (dpos != NULL)
    GNUNET_GE_LOG (ctx->ectx,
                   GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                   "Download thread manager schedules pending downloads...\n");
#endif
  while (dpos != NULL)
    {
      GNUNET_FSUI_updateDownloadThread (dpos);
      dpos = dpos->next;
    }
  GNUNET_mutex_unlock (ctx->lock);
}

/* ******************* START code *********************** */

static void
signalDownloadResume (struct GNUNET_FSUI_DownloadList *ret,
                      GNUNET_FSUI_Context * ctx)
{
  GNUNET_FSUI_Event event;
  GNUNET_CronTime now;
  GNUNET_CronTime eta;

  while (ret != NULL)
    {
      event.type = GNUNET_FSUI_download_resumed;
      event.data.DownloadResumed.dc.pos = ret;
      event.data.DownloadResumed.dc.cctx = ret->cctx;
      event.data.DownloadResumed.dc.ppos =
        ret->parent == &ctx->activeDownloads ? NULL : ret->parent;
      event.data.DownloadResumed.dc.pcctx = ret->parent->cctx;
      event.data.DownloadResumed.dc.spos = ret->search;
      event.data.DownloadResumed.dc.sctx =
        ret->search == NULL ? NULL : ret->search->cctx;
      event.data.DownloadResumed.completed = ret->completed;
      event.data.DownloadResumed.total = ret->total;
      event.data.DownloadResumed.state = ret->state;
      now = GNUNET_get_time ();
      if ((ret->total == 0) || (ret->completed == 0))
        {
          eta = now;
        }
      else
        {
          eta = (GNUNET_CronTime) (now - ret->runTime +
                                   (((double) (ret->runTime) /
                                     (double) ret->completed)) *
                                   (double) ret->total);
          if (eta < now)
            eta = now;
        }
      event.data.DownloadResumed.eta = eta;
      event.data.DownloadResumed.filename = ret->filename;
      event.data.DownloadResumed.fi.uri = ret->fi.uri;
      event.data.DownloadResumed.fi.meta = ret->fi.meta;
      event.data.DownloadResumed.anonymityLevel = ret->anonymityLevel;
      ret->cctx = ctx->ecb (ctx->ecbClosure, &event);
      if (ret->child != NULL)
        signalDownloadResume (ret->child, ctx);
      ret = ret->next;
    }
}

static void
signalUploadResume (struct GNUNET_FSUI_UploadList *ret,
                    GNUNET_FSUI_Context * ctx)
{
  GNUNET_FSUI_Event event;
  GNUNET_CronTime now;
  GNUNET_CronTime eta;

  while (ret != NULL)
    {
      event.type = GNUNET_FSUI_upload_resumed;
      event.data.UploadResumed.uc.pos = ret;
      event.data.UploadResumed.uc.cctx = NULL;
      event.data.UploadResumed.uc.ppos = ret->parent;
      event.data.UploadResumed.uc.pcctx = ret->parent->cctx;
      event.data.UploadResumed.completed = ret->completed;
      event.data.UploadResumed.total = ret->total;
      event.data.UploadResumed.uri = ret->uri;
      event.data.UploadResumed.state = ret->state;
      now = GNUNET_get_time ();
      if ((ret->total == 0) || (ret->completed == 0))
        {
          eta = now;
        }
      else
        {
          eta = (GNUNET_CronTime) (ret->start_time +
                                   (((double) (now - ret->start_time) /
                                     (double) ret->completed)) *
                                   (double) ret->total);
          if (eta < now)
            eta = now;
        }
      event.data.UploadResumed.eta = eta;
      event.data.UploadResumed.anonymityLevel = ret->shared->anonymityLevel;
      event.data.UploadResumed.filename = ret->filename;
      ret->cctx = ctx->ecb (ctx->ecbClosure, &event);
      if (ret->child != NULL)
        signalUploadResume (ret->child, ctx);
      ret = ret->next;
    }
}

/**
 * Resume uploads.
 * Only re-starts top-level upload threads;
 * threads below are controlled by the parent.
 */
static void
doResumeUploads (struct GNUNET_FSUI_UploadList *ret,
                 GNUNET_FSUI_Context * ctx)
{
  while (ret != NULL)
    {
      if (ret->state == GNUNET_FSUI_ACTIVE)
        {
          ret->shared->handle =
            GNUNET_thread_create (&GNUNET_FSUI_uploadThread, ret, 128 * 1024);
          if (ret->shared->handle == NULL)
            GNUNET_GE_DIE_STRERROR (ctx->ectx,
                                    GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                    GNUNET_GE_IMMEDIATE, "pthread_create");
        }
      ret = ret->next;
    }
}

/**
 * Start FSUI manager.  Use the given progress callback to notify the
 * UI about events.  Start processing pending activities that were
 * running when GNUNET_FSUI_stop was called previously.
 *
 * @param name name of the context, must not be NULL
 * @return NULL on error
 */
struct GNUNET_FSUI_Context *
GNUNET_FSUI_start (struct GNUNET_GE_Context *ectx,
                   struct GNUNET_GC_Configuration *cfg,
                   const char *name,
                   unsigned int threadPoolSize,
                   int doResume, GNUNET_FSUI_EventProcessor cb, void *closure)
{
  GNUNET_FSUI_Event event;
  GNUNET_FSUI_Context *ret;
  GNUNET_FSUI_SearchList *list;
  GNUNET_FSUI_UnindexList *xlist;
  char *fn;
  char *gh;
  unsigned long long size;

  GNUNET_GE_ASSERT (ectx, cfg != NULL);
  ret = GNUNET_malloc (sizeof (GNUNET_FSUI_Context));
  memset (ret, 0, sizeof (GNUNET_FSUI_Context));
  ret->activeDownloads.state = GNUNET_FSUI_PENDING;     /* !? */
  ret->activeDownloads.ctx = ret;
  ret->cfg = cfg;
  ret->ecb = cb;
  ret->ecbClosure = closure;
  ret->threadPoolSize = threadPoolSize;
  if (ret->threadPoolSize == 0)
    ret->threadPoolSize = 32;
  ret->activeDownloadThreads = 0;

  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "GNUNET",
                                              "GNUNET_HOME",
                                              GNUNET_DEFAULT_HOME_DIRECTORY,
                                              &gh);
  GNUNET_disk_directory_create (ectx, gh);
  fn = GNUNET_malloc (strlen (gh) + strlen (name) + 2 + 5);
  strcpy (fn, gh);
  GNUNET_free (gh);
  strcat (fn, DIR_SEPARATOR_STR);
  strcat (fn, name);
  ret->name = fn;

  /* 1) read state  in */
  if (doResume)
    {
      ret->ipc = GNUNET_IPC_semaphore_create (ectx, fn, 1);
#if DEBUG_PERSISTENCE
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Getting IPC lock for FSUI (%s).\n", fn);
#endif
      GNUNET_IPC_semaphore_down (ret->ipc, GNUNET_YES);
#if DEBUG_PERSISTENCE
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_INFO | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Aquired IPC lock.\n");
#endif
      strcat (fn, ".res");
      GNUNET_FSUI_deserialize (ret);
    }
  else
    {
      ret->ipc = NULL;
    }
  ret->lock = GNUNET_mutex_create (GNUNET_YES);

  /* 2) do resume events */
  /* 2a) signal download restarts */
  signalDownloadResume (ret->activeDownloads.child, ret);
  /* 2b) signal search restarts */
  list = ret->activeSearches;
  while (list != NULL)
    {
      event.type = GNUNET_FSUI_search_resumed;
      event.data.SearchResumed.sc.pos = list;
      event.data.SearchResumed.sc.cctx = NULL;
      event.data.SearchResumed.fis = list->resultsReceived;
      event.data.SearchResumed.fisSize = list->sizeResultsReceived;
      event.data.SearchResumed.anonymityLevel = list->anonymityLevel;
      event.data.SearchResumed.searchURI = list->uri;
      event.data.SearchResumed.state = list->state;
      list->cctx = cb (closure, &event);
      list = list->next;
    }
  /* 2c) signal upload restarts */
  signalUploadResume (ret->activeUploads.child, ret);
  /* 2d) signal unindex restarts */
  xlist = ret->unindexOperations;
  while (xlist != NULL)
    {
      if (GNUNET_OK !=
          GNUNET_disk_file_size (ectx, xlist->filename, &size, GNUNET_YES))
        size = 0;
      event.type = GNUNET_FSUI_unindex_resumed;
      event.data.UnindexResumed.uc.pos = xlist;
      event.data.UnindexResumed.uc.cctx = NULL;
      event.data.UnindexResumed.completed =
        (xlist->state == GNUNET_FSUI_COMPLETED_JOINED) ? size : 0;
      event.data.UnindexResumed.total = size;
      event.data.UnindexResumed.eta = GNUNET_get_time ();
      event.data.UnindexResumed.filename = xlist->filename;
      event.data.UnindexResumed.state = xlist->state;
      xlist->cctx = cb (closure, &event);
      xlist = xlist->next;
    }

  /* 3) restart processing */
  ret->cron = GNUNET_cron_create (ectx);
  /* 3a) resume downloads */
  GNUNET_cron_add_job (ret->cron,
                       &updateDownloadThreads, 0, GNUNET_FSUI_UDT_FREQUENCY,
                       ret);
  GNUNET_cron_start (ret->cron);
  /* 3b) resume uploads */
  doResumeUploads (ret->activeUploads.child, ret);
  /* 3c) resume unindexing */
  xlist = ret->unindexOperations;
  while (xlist != NULL)
    {
      if (xlist->state == GNUNET_FSUI_PENDING)
        {
          xlist->state = GNUNET_FSUI_ACTIVE;
          xlist->handle = GNUNET_thread_create (&GNUNET_FSUI_unindexThread,
                                                xlist, 32 * 1024);
          if (xlist->handle == NULL)
            GNUNET_GE_DIE_STRERROR (ectx,
                                    GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                    GNUNET_GE_IMMEDIATE, "pthread_create");
        }
      xlist = xlist->next;
    }
  /* 3d) resume searching */
  list = ret->activeSearches;
  while (list != NULL)
    {
      if (list->state == GNUNET_FSUI_PENDING)
        {
          list->state = GNUNET_FSUI_ACTIVE;
          list->handle =
            GNUNET_thread_create (&GNUNET_FSUI_searchThread, list, 32 * 1024);
          if (list->handle == NULL)
            GNUNET_GE_DIE_STRERROR (ectx,
                                    GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                    GNUNET_GE_IMMEDIATE, "pthread_create");
        }
      list = list->next;
    }

  return ret;
}

/* ******************* STOP code *********************** */

/**
 * (recursively) signal download suspension.
 */
static void
signalDownloadSuspend (struct GNUNET_GE_Context *ectx,
                       GNUNET_FSUI_Context * ctx,
                       GNUNET_FSUI_DownloadList * list)
{
  GNUNET_FSUI_Event event;
  while (list != NULL)
    {
      signalDownloadSuspend (ectx, ctx, list->child);
      event.type = GNUNET_FSUI_download_suspended;
      event.data.DownloadSuspended.dc.pos = list;
      event.data.DownloadSuspended.dc.cctx = list->cctx;
      event.data.DownloadSuspended.dc.ppos =
        list->parent == &ctx->activeDownloads ? NULL : list->parent;
      event.data.DownloadSuspended.dc.pcctx = list->parent->cctx;
      event.data.DownloadSuspended.dc.spos = list->search;
      event.data.DownloadSuspended.dc.sctx =
        list->search == NULL ? NULL : list->search->cctx;
      ctx->ecb (ctx->ecbClosure, &event);
      list = list->next;
    }
}

/**
 * (recursively) signal upload suspension.
 */
static void
signalUploadSuspend (struct GNUNET_GE_Context *ectx,
                     GNUNET_FSUI_Context * ctx, GNUNET_FSUI_UploadList * upos)
{
  GNUNET_FSUI_Event event;
  while (upos != NULL)
    {
      signalUploadSuspend (ectx, ctx, upos->child);
      event.type = GNUNET_FSUI_upload_suspended;
      event.data.UploadSuspended.uc.pos = upos;
      event.data.UploadSuspended.uc.cctx = upos->cctx;
      event.data.UploadSuspended.uc.ppos = upos->parent;
      event.data.UploadSuspended.uc.pcctx = upos->parent->cctx;
      ctx->ecb (ctx->ecbClosure, &event);
      upos = upos->next;
    }
}

/**
 * (recursively) free download list
 */
static void
freeDownloadList (GNUNET_FSUI_DownloadList * list)
{
  GNUNET_FSUI_DownloadList *next;
  int i;

  while (list != NULL)
    {
      freeDownloadList (list->child);
      GNUNET_ECRS_uri_destroy (list->fi.uri);
      GNUNET_ECRS_meta_data_destroy (list->fi.meta);
      GNUNET_free (list->filename);
      for (i = 0; i < list->completedDownloadsCount; i++)
        GNUNET_ECRS_uri_destroy (list->completedDownloads[i]);
      GNUNET_array_grow (list->completedDownloads,
                         list->completedDownloadsCount, 0);
      next = list->next;
      GNUNET_free (list);
      list = next;
    }
}

/**
 * (recursively) free upload list
 */
static void
freeUploadList (struct GNUNET_FSUI_Context *ctx,
                GNUNET_FSUI_UploadList * list)
{
  GNUNET_FSUI_UploadList *next;
  GNUNET_FSUI_UploadShared *shared;

  while (list != NULL)
    {
      freeUploadList (ctx, list->child);
      next = list->next;
      GNUNET_free (list->filename);
      if (list->meta != NULL)
        GNUNET_ECRS_meta_data_destroy (list->meta);
      if (list->keywords != NULL)
        GNUNET_ECRS_uri_destroy (list->keywords);
      if (list->uri != NULL)
        GNUNET_ECRS_uri_destroy (list->uri);
      if (list->parent == &ctx->activeUploads)
        {
          shared = list->shared;
          EXTRACTOR_removeAll (shared->extractors);
          if (shared->global_keywords != NULL)
            GNUNET_ECRS_uri_destroy (shared->global_keywords);
          GNUNET_free_non_null (shared->extractor_config);
          GNUNET_free (shared);
        }
      GNUNET_free (list);
      list = next;
    }
}

/**
 * Stop all processes under FSUI control (serialize state, continue
 * later if possible).
 */
void
GNUNET_FSUI_stop (struct GNUNET_FSUI_Context *ctx)
{
  struct GNUNET_GE_Context *ectx;
  GNUNET_FSUI_SearchList *spos;
  GNUNET_FSUI_DownloadList *dpos;
  GNUNET_FSUI_UnindexList *xpos;
  GNUNET_FSUI_UploadList *upos;
  GNUNET_FSUI_Event event;
  void *unused;
  int i;

  ectx = ctx->ectx;
  if (ctx->ipc != NULL)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                   "FSUI shutdown.  This may take a while.\n");

  /* 1) stop everything */
  GNUNET_cron_stop (ctx->cron);
  GNUNET_cron_del_job (ctx->cron, &updateDownloadThreads,
                       GNUNET_FSUI_UDT_FREQUENCY, ctx);
  GNUNET_cron_destroy (ctx->cron);

  /* 1a) stop downloading */
  ctx->threadPoolSize = 0;
  dpos = ctx->activeDownloads.child;
  while (dpos != NULL)
    {
      GNUNET_FSUI_updateDownloadThread (dpos);
      dpos = dpos->next;
    }
  /* 1b) stop searching */
  spos = ctx->activeSearches;
  while (spos != NULL)
    {
      if ((spos->state == GNUNET_FSUI_ACTIVE) ||
          (spos->state == GNUNET_FSUI_ABORTED) ||
          (spos->state == GNUNET_FSUI_ERROR)
          || (spos->state == GNUNET_FSUI_COMPLETED))
        {
          if (spos->state == GNUNET_FSUI_ACTIVE)
            spos->state = GNUNET_FSUI_PENDING;
          GNUNET_thread_stop_sleep (spos->handle);
          GNUNET_thread_join (spos->handle, &unused);
          if (spos->state != GNUNET_FSUI_PENDING)
            spos->state++;      /* _JOINED */
        }
      spos = spos->next;
    }
  /* 1c) stop unindexing */
  xpos = ctx->unindexOperations;
  while (xpos != NULL)
    {
      if ((xpos->state == GNUNET_FSUI_ACTIVE) ||
          (xpos->state == GNUNET_FSUI_ABORTED) ||
          (xpos->state == GNUNET_FSUI_ERROR)
          || (xpos->state == GNUNET_FSUI_COMPLETED))
        {
          if (xpos->state == GNUNET_FSUI_ACTIVE)
            xpos->state = GNUNET_FSUI_PENDING;
          GNUNET_thread_stop_sleep (xpos->handle);
          GNUNET_thread_join (xpos->handle, &unused);
          if (xpos->state != GNUNET_FSUI_PENDING)
            xpos->state++;      /* _JOINED */
        }
      xpos = xpos->next;
    }
  /* 1d) stop uploading */
  upos = ctx->activeUploads.child;
  while (upos != NULL)
    {
      if ((upos->state == GNUNET_FSUI_ACTIVE) ||
          (upos->state == GNUNET_FSUI_ABORTED) ||
          (upos->state == GNUNET_FSUI_ERROR)
          || (upos->state == GNUNET_FSUI_COMPLETED))
        {
          /* NOTE: will force transitive termination
             of rest of tree! */
          if (upos->state == GNUNET_FSUI_ACTIVE)
            upos->state = GNUNET_FSUI_PENDING;
          GNUNET_thread_stop_sleep (upos->shared->handle);
          GNUNET_thread_join (upos->shared->handle, &unused);
          if (upos->state != GNUNET_FSUI_PENDING)
            upos->state++;      /* _JOINED */
        }
      upos = upos->next;
    }

  /* 2) signal suspension events */
  /* 2a) signal search suspension */
  spos = ctx->activeSearches;
  while (spos != NULL)
    {
      event.type = GNUNET_FSUI_search_suspended;
      event.data.SearchSuspended.sc.pos = spos;
      event.data.SearchSuspended.sc.cctx = spos->cctx;
      ctx->ecb (ctx->ecbClosure, &event);
      spos = spos->next;
    }
  /* 2b) signal uploads suspension */
  signalUploadSuspend (ectx, ctx, ctx->activeUploads.child);
  /* 2c) signal downloads suspension */
  signalDownloadSuspend (ectx, ctx, ctx->activeDownloads.child);
  /* 2d) signal unindex suspension */
  xpos = ctx->unindexOperations;
  while (xpos != NULL)
    {
      event.type = GNUNET_FSUI_unindex_suspended;
      event.data.UnindexSuspended.uc.pos = xpos;
      event.data.UnindexSuspended.uc.cctx = xpos->cctx;
      ctx->ecb (ctx->ecbClosure, &event);
      xpos = xpos->next;
    }

  /* 3) serialize all of the FSUI state */
  if (ctx->ipc != NULL)
    GNUNET_FSUI_serialize (ctx);

  /* 4) finally, free memory */
  /* 4a) free search memory */
  while (ctx->activeSearches != NULL)
    {
      spos = ctx->activeSearches;
      ctx->activeSearches = spos->next;
      GNUNET_ECRS_uri_destroy (spos->uri);
      for (i = spos->sizeResultsReceived - 1; i >= 0; i--)
        {
          GNUNET_ECRS_FileInfo *fi;
          fi = &spos->resultsReceived[i];
          GNUNET_ECRS_meta_data_destroy (fi->meta);
          GNUNET_ECRS_uri_destroy (fi->uri);
        }
      GNUNET_array_grow (spos->resultsReceived, spos->sizeResultsReceived, 0);
      for (i = spos->sizeUnmatchedResultsReceived - 1; i >= 0; i--)
        {
          ResultPending *rp;

          rp = &spos->unmatchedResultsReceived[i];
          GNUNET_array_grow (rp->matchingKeys, rp->matchingKeyCount, 0);
          GNUNET_ECRS_meta_data_destroy (rp->fi.meta);
          GNUNET_ECRS_uri_destroy (rp->fi.uri);
        }
      GNUNET_array_grow (spos->unmatchedResultsReceived,
                         spos->sizeUnmatchedResultsReceived, 0);
      GNUNET_free (spos);
    }
  /* 4b) free unindex memory */
  while (ctx->unindexOperations != NULL)
    {
      xpos = ctx->unindexOperations;
      ctx->unindexOperations = xpos->next;
      GNUNET_free (xpos->filename);
      GNUNET_free (xpos);
    }
  /* 4c) free upload memory */
  freeUploadList (ctx, ctx->activeUploads.child);
  /* 4d) free download memory */
  freeDownloadList (ctx->activeDownloads.child);

  /* 5) finish FSUI Context */
  if (ctx->ipc != NULL)
    {
      GNUNET_IPC_semaphore_up (ctx->ipc);
      GNUNET_IPC_semaphore_destroy (ctx->ipc);
    }
  GNUNET_mutex_destroy (ctx->lock);
  GNUNET_free (ctx->name);
  if (ctx->ipc != NULL)
    GNUNET_GE_LOG (ectx,
                   GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                   "FSUI shutdown complete.\n");
  GNUNET_free (ctx);
}


/* end of fsui.c */
