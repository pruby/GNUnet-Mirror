/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
#include "fs.h"

#define DEBUG_PERSISTENCE GNUNET_NO

/* ***************** CRON code ***************** */

/**
 * How often should cron run?
 */
#define GNUNET_FSUI_UDT_FREQUENCY (2 * GNUNET_CRON_SECONDS)

#define SQUARE(x) ((x)*(x))

/**
 * We made progress on a test download.  Since
 * a test download only contains a single block,
 * any progress means that the test succeeded.
 * We just set the flag to notify the cron in
 * the next iteration.
 */
static void
test_download_progress (unsigned long long totalBytes,
                        unsigned long long completedBytes,
                        GNUNET_CronTime eta,
                        unsigned long long lastBlockOffset,
                        const char *lastBlock, unsigned int lastBlockSize,
                        void *closure)
{
  struct SearchResultList *srl = closure;
  if (lastBlockSize > 0)        /* check against IBlock events */
    srl->test_download_start_time = 0;
}


/**
 * Cron job for download load management.
 */
static void
updateDownloadThreads (void *c)
{
  GNUNET_FSUI_Context *ctx = c;
  GNUNET_FSUI_DownloadList *dpos;
  struct SearchResultList *srl;
  struct GNUNET_FSUI_SearchList *sl;
  unsigned long long off;
  unsigned long long len;
  GNUNET_CronTime now;
  GNUNET_FSUI_Event event;

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
  now = GNUNET_get_time ();
  sl = ctx->activeSearches;
  while (sl != NULL)
    {
      srl = sl->resultsReceived;
      while (srl != NULL)
        {
          if (srl->test_download != NULL)
            {
              if (srl->test_download_start_time == 0)
                {
                  /* probe was successful, kill */
                  GNUNET_ECRS_file_download_partial_stop (srl->test_download);
                  srl->test_download = NULL;
                  srl->probeSuccess++;
                  event.type = GNUNET_FSUI_search_update;
                  event.data.SearchUpdate.sc.pos = sl;
                  event.data.SearchUpdate.sc.cctx = sl->cctx;
                  event.data.SearchUpdate.fi = srl->fi;
                  event.data.SearchUpdate.searchURI = sl->uri;
                  event.data.SearchUpdate.availability_rank =
                    srl->probeSuccess - srl->probeFailure;
                  event.data.SearchUpdate.availability_certainty =
                    srl->probeSuccess + srl->probeFailure;
                  event.data.SearchUpdate.applicability_rank =
                    srl->matchingSearchCount;
                  ctx->ecb (ctx->ecbClosure, &event);
                  ctx->active_probes--;
                  srl->last_probe_time = now;
                }
              else
                {
                  /* consider stopping */
                  if ((now - srl->test_download_start_time)
                      >
                      SQUARE (srl->probeSuccess + srl->probeFailure +
                              1) * GNUNET_FSUI_PROBE_TIME_FACTOR)
                    {
                      /* timeout hit! */
                      GNUNET_ECRS_file_download_partial_stop
                        (srl->test_download);
                      srl->test_download = NULL;
                      srl->probeFailure++;
                      event.type = GNUNET_FSUI_search_update;
                      event.data.SearchUpdate.sc.pos = sl;
                      event.data.SearchUpdate.sc.cctx = sl->cctx;
                      event.data.SearchUpdate.fi = srl->fi;
                      event.data.SearchUpdate.searchURI = sl->uri;
                      event.data.SearchUpdate.availability_rank =
                        srl->probeSuccess - srl->probeFailure;
                      event.data.SearchUpdate.availability_certainty =
                        srl->probeSuccess + srl->probeFailure;
                      event.data.SearchUpdate.applicability_rank =
                        srl->matchingSearchCount;
                      ctx->ecb (ctx->ecbClosure, &event);
                      ctx->active_probes--;
                      srl->last_probe_time = now;
                    }
                }
            }
          else
            {
              len = GNUNET_ECRS_uri_get_file_size (srl->fi.uri);
              if (len == 0)
                srl->probeSuccess = -1; /* MAX */
              /* consider starting */
              if (((srl->probeSuccess + srl->probeFailure) <
                   GNUNET_FSUI_MAX_PROBES)
                  &&
                  ((srl->last_probe_time <
                    now +
                    GNUNET_FSUI_PROBE_DELAY * SQUARE (ctx->active_probes) +
                    GNUNET_random_u64 (GNUNET_RANDOM_QUALITY_WEAK,
                                       GNUNET_FSUI_PROBE_DELAY)))
                  && (ctx->active_probes < GNUNET_FSUI_HARD_PROBE_LIMIT))
                {
                  off = len / GNUNET_ECRS_DBLOCK_SIZE;
                  if (off > 0)
                    off = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, off);
                  off *= GNUNET_ECRS_DBLOCK_SIZE;
                  if (len - off < GNUNET_ECRS_DBLOCK_SIZE)
                    len = len - off;
                  else
                    len = GNUNET_ECRS_DBLOCK_SIZE;
                  srl->test_download
                    = GNUNET_ECRS_file_download_partial_start (ctx->ectx,
                                                               ctx->cfg,
                                                               sl->
                                                               probe_context,
                                                               srl->fi.uri,
                                                               NULL, off, len,
                                                               1, GNUNET_YES,
                                                               &test_download_progress,
                                                               srl);
                  if (srl->test_download != NULL)
                    {
                      srl->test_download_start_time = now;
                      ctx->active_probes++;
                    }
                }
            }

          srl = srl->next;
        }
      sl = sl->next;
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
  struct SearchResultList *pos;
  struct SearchRecordList *rec;
  unsigned int valid;
  unsigned int i;
  GNUNET_ECRS_FileInfo *fis;
  int *av_ranks;
  unsigned int *av_certs;
  unsigned int *ap_ranks;
  char *fn;
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
  ret->name = GNUNET_get_home_filename (ectx,
                                        cfg, GNUNET_NO, "fsui", name, NULL);
  /* 1) read state  in */
  if (doResume)
    {
      fn = GNUNET_get_home_filename (ectx,
                                     cfg,
                                     GNUNET_NO, "fsui-locks", name, NULL);
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
      GNUNET_free (fn);
      GNUNET_FSUI_deserialize (ret);
    }
  else
    {
      ret->ipc = NULL;
    }
  ret->lock = GNUNET_mutex_create (GNUNET_YES);

  /* 2) do resume events */
  /* 2a) signal search restarts */
  list = ret->activeSearches;
  while (list != NULL)
    {
      valid = 0;
      pos = list->resultsReceived;
      while (pos != NULL)
        {
          if (pos->mandatoryMatchesRemaining == 0)
            valid++;
          pos = pos->next;
        }
      fis = NULL;
      av_ranks = NULL;
      av_certs = NULL;
      ap_ranks = NULL;
      if (valid > 0)
        {
          fis = GNUNET_malloc (sizeof (GNUNET_ECRS_FileInfo) * valid);
          av_ranks = GNUNET_malloc (sizeof (int) * valid);
          av_certs = GNUNET_malloc (sizeof (unsigned int) * valid);
          ap_ranks = GNUNET_malloc (sizeof (unsigned int) * valid);
          pos = list->resultsReceived;
          i = 0;
          while (pos != NULL)
            {
              if (pos->mandatoryMatchesRemaining == 0)
                {
                  fis[i] = pos->fi;
                  av_ranks[i] = pos->probeSuccess - pos->probeFailure;
                  av_certs[i] = pos->probeSuccess + pos->probeFailure;
                  ap_ranks[i] = pos->matchingSearchCount;
                  i++;
                }
              pos = pos->next;
            }
        }
      event.type = GNUNET_FSUI_search_resumed;
      event.data.SearchResumed.sc.pos = list;
      event.data.SearchResumed.sc.cctx = NULL;
      event.data.SearchResumed.fis = fis;
      event.data.SearchResumed.fisSize = valid;
      event.data.SearchResumed.anonymityLevel = list->anonymityLevel;
      event.data.SearchResumed.searchURI = list->uri;
      event.data.SearchResumed.state = list->state;
      event.data.SearchResumed.availability_rank = av_ranks;
      event.data.SearchResumed.availability_certainty = av_certs;
      event.data.SearchResumed.applicability_rank = ap_ranks;
      list->cctx = cb (closure, &event);
      GNUNET_free_non_null (fis);
      GNUNET_free_non_null (av_ranks);
      GNUNET_free_non_null (av_certs);
      GNUNET_free_non_null (ap_ranks);
      list = list->next;
    }
  /* 2b) signal download restarts */
  signalDownloadResume (ret->activeDownloads.child, ret);
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
  /* 3a) resume searching */
  list = ret->activeSearches;
  while (list != NULL)
    {
      list->probe_context
        = GNUNET_FS_create_search_context (ret->ectx, ret->cfg);
      if (list->state == GNUNET_FSUI_PENDING)
        {
          list->state = GNUNET_FSUI_ACTIVE;
          rec = list->searches;
          while (rec != NULL)
            {
              rec->search = GNUNET_ECRS_search_start (list->ctx->ectx,
                                                      list->ctx->cfg,
                                                      list->probe_context,
                                                      rec->uri,
                                                      list->anonymityLevel,
                                                      &GNUNET_FSUI_search_progress_callback,
                                                      list);
              if (rec->search == NULL)
                {
                  GNUNET_GE_LOG (ectx,
                                 GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                                 GNUNET_GE_IMMEDIATE,
                                 "Failed to resume search\n");
                  list->state = GNUNET_FSUI_PENDING;
                }
              rec = rec->next;
            }
          if (list->state != GNUNET_FSUI_ACTIVE)
            {
              /* stop searches, we failed... */
              rec = list->searches;
              while (rec != NULL)
                {
                  if (rec->search != NULL)
                    {
                      GNUNET_ECRS_search_stop (rec->search);
                      rec->search = NULL;
                    }
                  rec = rec->next;
                }
            }
        }
      list = list->next;
    }
  /* 3b) resume unindexing */
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
  /* 3c) resume downloads */
  GNUNET_cron_add_job (ret->cron,
                       &updateDownloadThreads, 0, GNUNET_FSUI_UDT_FREQUENCY,
                       ret);
  GNUNET_cron_start (ret->cron);
  /* 3d) resume uploads */
  doResumeUploads (ret->activeUploads.child, ret);
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
      GNUNET_meta_data_destroy (list->fi.meta);
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
        GNUNET_meta_data_destroy (list->meta);
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
  struct SearchRecordList *rec;
  struct SearchResultList *res;
  GNUNET_FSUI_Event event;
  void *unused;

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
          rec = spos->searches;
          while (rec != NULL)
            {
              GNUNET_ECRS_search_stop (rec->search);
              rec->search = NULL;
              rec = rec->next;
            }
          res = spos->resultsReceived;
          while (res != NULL)
            {
              if (res->test_download != NULL)
                {
                  GNUNET_ECRS_file_download_partial_stop (res->test_download);
                  res->test_download = NULL;
                  ctx->active_probes--;
                }
              res = res->next;
            }
          if (spos->state != GNUNET_FSUI_PENDING)
            spos->state++;      /* _JOINED */
        }
      if (spos->probe_context != NULL)
        {
          GNUNET_FS_destroy_search_context (spos->probe_context);
          spos->probe_context = NULL;
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
  /* 2a) signal uploads suspension */
  signalUploadSuspend (ectx, ctx, ctx->activeUploads.child);
  /* 2b) signal downloads suspension */
  signalDownloadSuspend (ectx, ctx, ctx->activeDownloads.child);
  /* 2c) signal unindex suspension */
  xpos = ctx->unindexOperations;
  while (xpos != NULL)
    {
      event.type = GNUNET_FSUI_unindex_suspended;
      event.data.UnindexSuspended.uc.pos = xpos;
      event.data.UnindexSuspended.uc.cctx = xpos->cctx;
      ctx->ecb (ctx->ecbClosure, &event);
      xpos = xpos->next;
    }
  /* 2d) signal search suspension */
  spos = ctx->activeSearches;
  while (spos != NULL)
    {
      event.type = GNUNET_FSUI_search_suspended;
      event.data.SearchSuspended.sc.pos = spos;
      event.data.SearchSuspended.sc.cctx = spos->cctx;
      ctx->ecb (ctx->ecbClosure, &event);
      spos = spos->next;
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
      while (spos->searches != NULL)
        {
          rec = spos->searches;
          spos->searches = rec->next;
          GNUNET_ECRS_uri_destroy (rec->uri);
          GNUNET_free (rec);
        }
      while (spos->resultsReceived != NULL)
        {
          res = spos->resultsReceived;
          spos->resultsReceived = res->next;
          GNUNET_meta_data_destroy (res->fi.meta);
          GNUNET_ECRS_uri_destroy (res->fi.uri);
          GNUNET_free (res->matchingSearches);
          GNUNET_free (res);
        }
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
