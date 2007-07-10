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
 * @file applications/fs/fsui/download.c
 * @brief download functions
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_error_loggers.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_uritrack_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

#define DEBUG_DTM NO

/**
 * Mark the given URI as found in a directory
 * in URITRACK.
 */
static int
listURIfoundDirectory (const ECRS_FileInfo * fi,
                       const HashCode512 * key, int isRoot, void *prnt)
{
  FSUI_DownloadList *dl = prnt;

  if (isRoot == YES)
    return OK;                  /* namespace ad, ignore */
  URITRACK_addState (dl->ctx->ectx,
                     dl->ctx->cfg, fi->uri, URITRACK_DIRECTORY_FOUND);

  return OK;
}



/**
 * Start to download a file.
 */
static FSUI_DownloadList *startDownload (struct FSUI_Context *ctx,
                                         unsigned int anonymityLevel,
                                         int is_recursive,
                                         const struct ECRS_URI *uri,
                                         const struct ECRS_MetaData *meta,
                                         const char *filename,
                                         struct FSUI_SearchList *psearch,
                                         FSUI_DownloadList * parent);

/**
 * Initiate a (recursive) download of the given
 * directory entry.
 */
static int
triggerRecursiveDownload (const ECRS_FileInfo * fi,
                          const HashCode512 * key, int isRoot, void *prnt)
{
  FSUI_DownloadList *parent = prnt;
  struct GE_Context *ectx;
  int i;
  FSUI_DownloadList *pos;
  char *filename;
  char *fullName;
  char *dotdot;

  ectx = parent->ctx->ectx;
  if (isRoot == YES)
    return OK;                  /* namespace ad, ignore */

  URITRACK_trackURI (ectx, parent->ctx->cfg, fi);
  for (i = 0; i < parent->completedDownloadsCount; i++)
    if (ECRS_equalsUri (parent->completedDownloads[i], fi->uri))
      return OK;                /* already complete! */
  pos = parent->child;
  while (pos != NULL)
    {
      if (ECRS_equalsUri (pos->fi.uri, fi->uri))
        return OK;              /* already downloading */
      pos = pos->next;
    }
  filename = ECRS_getFromMetaData (fi->meta, EXTRACTOR_FILENAME);
  if (filename == NULL)
    {
      char *tmp = ECRS_uriToString (fi->uri);
      GE_ASSERT (ectx,
                 strlen (tmp) >=
                 strlen (ECRS_URI_PREFIX) + strlen (ECRS_FILE_INFIX));
      filename =
        STRDUP (&tmp[strlen (ECRS_URI_PREFIX) + strlen (ECRS_FILE_INFIX)]);
      FREE (tmp);
    }
  fullName = MALLOC (strlen (parent->filename) + 2 + strlen (filename));
  strcpy (fullName, parent->filename);
  strcat (fullName, filename);
  while (NULL != (dotdot = strstr (fullName, "..")))
    dotdot[0] = dotdot[1] = '_';
  FREE (filename);
#if DEBUG_DTM
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Starting recursive download of `%s'\n", fullName);
#endif
  startDownload (parent->ctx,
                 parent->anonymityLevel,
                 YES, fi->uri, fi->meta, fullName, parent->search, parent);
  FREE (fullName);
  return OK;
}

/**
 * Progress notification from ECRS.  Tell FSUI client.
 */
static void
downloadProgressCallback (unsigned long long totalBytes,
                          unsigned long long completedBytes,
                          cron_t eta,
                          unsigned long long lastBlockOffset,
                          const char *lastBlock,
                          unsigned int lastBlockSize, void *cls)
{
  FSUI_DownloadList *dl = cls;
  FSUI_Event event;
  struct ECRS_MetaData *md;
  cron_t now;
  cron_t run_time;

  GE_ASSERT (dl->ctx->ectx, dl->total == totalBytes);
  dl->completed = completedBytes;
  event.type = FSUI_download_progress;
  event.data.DownloadProgress.dc.pos = dl;
  event.data.DownloadProgress.dc.cctx = dl->cctx;
  event.data.DownloadProgress.dc.ppos =
    dl->parent == &dl->ctx->activeDownloads ? NULL : dl->parent;
  event.data.DownloadProgress.dc.pcctx = dl->parent->cctx;
  event.data.DownloadProgress.dc.spos = dl->search;
  event.data.DownloadProgress.dc.sctx =
    dl->search == NULL ? NULL : dl->search->cctx;
  event.data.DownloadProgress.completed = dl->completed;
  event.data.DownloadProgress.total = dl->total;
  event.data.DownloadProgress.last_offset = lastBlockOffset;
  now = get_time ();
  run_time = now - dl->startTime;
  if ((dl->total == 0) || (dl->completed == 0))
    {
      eta = now;
    }
  else
    {
      eta = (cron_t) (dl->startTime +
                      (((double) (run_time) / (double) dl->completed))
                      * (double) dl->total);
      if (eta < now)
        eta = now;
    }
  event.data.DownloadProgress.eta = eta;
  event.data.DownloadProgress.filename = dl->filename;
  event.data.DownloadProgress.uri = dl->fi.uri;
  event.data.DownloadProgress.last_block = lastBlock;
  event.data.DownloadProgress.last_size = lastBlockSize;
  dl->ctx->ecb (dl->ctx->ecbClosure, &event);
  if ((lastBlockOffset == 0) && (dl->is_directory == SYSERR))
    {
      /* check if this is a directory */
      if ((lastBlockSize > strlen (GNUNET_DIRECTORY_MAGIC)) &&
          (0 == strncmp (GNUNET_DIRECTORY_MAGIC,
                         lastBlock, strlen (GNUNET_DIRECTORY_MAGIC))))
        dl->is_directory = YES;
      else
        dl->is_directory = NO;
    }
  if (dl->is_directory == YES)
    {
      md = NULL;
      ECRS_listDirectory (dl->ctx->ectx,
                          lastBlock,
                          lastBlockSize, &md, &listURIfoundDirectory, dl);
      if (md != NULL)
        ECRS_freeMetaData (md);
    }
  if ((dl->is_recursive == YES) && (dl->is_directory == YES))
    {
      md = NULL;
      MUTEX_LOCK (dl->ctx->lock);
      ECRS_listDirectory (dl->ctx->ectx,
                          lastBlock,
                          lastBlockSize, &md, &triggerRecursiveDownload, dl);
      MUTEX_UNLOCK (dl->ctx->lock);
      if (md != NULL)
        ECRS_freeMetaData (md);
    }
}

/**
 * Check if termination of this download is desired.
 */
static int
testTerminate (void *cls)
{
  FSUI_DownloadList *dl = cls;

  if ((dl->state == FSUI_ERROR) || (dl->state == FSUI_ABORTED))
    return SYSERR;              /* aborted - delete! */
  if (dl->state != FSUI_ACTIVE)
    return NO;                  /* suspended */
  return OK;
}

/**
 * Thread that downloads a file.
 */
void *
downloadThread (void *cls)
{
  FSUI_DownloadList *dl = cls;
  int ret;
  FSUI_Event event;
  struct GE_Context *ectx;
  struct GE_Memory *mem;
  struct GE_Context *ee;

  dl->startTime = get_time () - dl->runTime;
  ectx = dl->ctx->ectx;
#if DEBUG_DTM
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Download thread for `%s' started...\n", dl->filename);
#endif
  GE_ASSERT (ectx, dl->ctx != NULL);
  GE_ASSERT (ectx, dl->filename != NULL);
  mem = GE_memory_create (2);
  ee =
    GE_create_context_memory (GE_USER | GE_ADMIN | GE_ERROR | GE_WARNING |
                              GE_FATAL | GE_BULK | GE_IMMEDIATE, mem);
  ret =
    ECRS_downloadFile (ee, dl->ctx->cfg, dl->fi.uri, dl->filename,
                       dl->anonymityLevel, &downloadProgressCallback, dl,
                       &testTerminate, dl);
  if (ret == OK)
    {
      dl->state = FSUI_COMPLETED;
      event.type = FSUI_download_completed;
      event.data.DownloadCompleted.dc.pos = dl;
      event.data.DownloadCompleted.dc.cctx = dl->cctx;
      event.data.DownloadCompleted.dc.ppos =
        dl->parent == &dl->ctx->activeDownloads ? NULL : dl->parent;
      event.data.DownloadCompleted.dc.pcctx = dl->parent->cctx;
      event.data.DownloadCompleted.dc.spos = dl->search;
      event.data.DownloadCompleted.dc.sctx =
        dl->search == NULL ? NULL : dl->search->cctx;
      event.data.DownloadCompleted.total = dl->total;
      event.data.DownloadCompleted.filename = dl->filename;
      event.data.DownloadCompleted.uri = dl->fi.uri;
      URITRACK_addState (dl->ctx->ectx,
                         dl->ctx->cfg,
                         dl->fi.uri, URITRACK_DOWNLOAD_COMPLETED);
      dl->ctx->ecb (dl->ctx->ecbClosure, &event);
    }
  else if (dl->state == FSUI_ACTIVE)
    {
      const char *error;

      /* ECRS error */
      dl->state = FSUI_ERROR;
      event.type = FSUI_download_error;
      event.data.DownloadError.dc.pos = dl;
      event.data.DownloadError.dc.cctx = dl->cctx;
      event.data.DownloadError.dc.ppos =
        dl->parent == &dl->ctx->activeDownloads ? NULL : dl->parent;
      event.data.DownloadError.dc.pcctx = dl->parent->cctx;
      event.data.DownloadError.dc.spos = dl->search;
      event.data.DownloadError.dc.sctx =
        dl->search == NULL ? NULL : dl->search->cctx;
      error = GE_memory_get (mem, 0);
      if (error == NULL)
        error = _("Download failed (no reason given)");
      event.data.DownloadError.message = error;
      URITRACK_addState (dl->ctx->ectx,
                         dl->ctx->cfg, dl->fi.uri, URITRACK_DOWNLOAD_ABORTED);
      dl->ctx->ecb (dl->ctx->ecbClosure, &event);
    }
  else if (dl->state == FSUI_ABORTED)
    {                           /* aborted */
      event.type = FSUI_download_aborted;
      event.data.DownloadAborted.dc.pos = dl;
      event.data.DownloadAborted.dc.cctx = dl->cctx;
      event.data.DownloadAborted.dc.ppos =
        dl->parent == &dl->ctx->activeDownloads ? NULL : dl->parent;
      event.data.DownloadAborted.dc.pcctx = dl->parent->cctx;
      event.data.DownloadAborted.dc.spos = dl->search;
      event.data.DownloadAborted.dc.sctx =
        dl->search == NULL ? NULL : dl->search->cctx;
      URITRACK_addState (dl->ctx->ectx, dl->ctx->cfg, dl->fi.uri,
                         URITRACK_DOWNLOAD_ABORTED);
      dl->ctx->ecb (dl->ctx->ecbClosure, &event);
    }
  else
    {
      /* else: suspended */
      GE_BREAK (NULL, dl->state == FSUI_SUSPENDING);
    }


  if ((ret == OK) &&
      (dl->is_directory == YES) && (ECRS_fileSize (dl->fi.uri) > 0))
    {
      char *dirBlock;
      int fd;
      char *fn;
      size_t totalBytes;
      struct ECRS_MetaData *md;

      totalBytes = ECRS_fileSize (dl->fi.uri);
      fn = MALLOC (strlen (dl->filename) + strlen (GNUNET_DIRECTORY_EXT) + 1);
      strcpy (fn, dl->filename);
      fd = strlen (fn) - 1;
      if (fn[fd] == '/' || fn[fd] == '\\')
        {
          fn[fd] = '\0';
          strcat (fn, GNUNET_DIRECTORY_EXT);
        }
      fd = disk_file_open (ectx, fn, O_LARGEFILE | O_RDONLY);
      if (fd != -1)
        {
          dirBlock = MMAP (NULL, totalBytes, PROT_READ, MAP_SHARED, fd, 0);
          if (MAP_FAILED == dirBlock)
            {
              GE_LOG_STRERROR_FILE (ectx,
                                    GE_ERROR | GE_BULK | GE_ADMIN | GE_USER,
                                    "mmap", fn);
            }
          else
            {
              md = NULL;
              ECRS_listDirectory (dl->ctx->ectx,
                                  dirBlock,
                                  totalBytes,
                                  &md, &listURIfoundDirectory, dl);
              if (md != NULL)
                ECRS_freeMetaData (md);

              if (dl->is_recursive)
                {
                  /* load directory, start downloads */
                  md = NULL;
                  MUTEX_LOCK (dl->ctx->lock);
                  ECRS_listDirectory (dl->ctx->ectx,
                                      dirBlock,
                                      totalBytes,
                                      &md, &triggerRecursiveDownload, dl);
                  MUTEX_UNLOCK (dl->ctx->lock);
                  ECRS_freeMetaData (md);
                  MUNMAP (dirBlock, totalBytes);
                }
            }
          CLOSE (fd);
        }
      FREE (fn);
    }
#if DEBUG_DTM
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Download thread for `%s' terminated (%s)...\n",
          dl->filename, ret == OK ? "COMPLETED" : "ABORTED");
#endif
  dl->runTime = get_time () - dl->startTime;
  GE_free_context (ee);
  GE_memory_free (mem);
  return NULL;
}

/**
 * Start to download a file.
 */
static FSUI_DownloadList *
startDownload (struct FSUI_Context *ctx,
               unsigned int anonymityLevel,
               int is_recursive,
               const struct ECRS_URI *uri,
               const struct ECRS_MetaData *meta,
               const char *filename,
               struct FSUI_SearchList *psearch, FSUI_DownloadList * parent)
{
  FSUI_DownloadList *dl;
  FSUI_Event event;

  GE_ASSERT (NULL, ctx != NULL);
  GE_ASSERT (NULL, parent != NULL);
  if (!(ECRS_isFileUri (uri) || ECRS_isLocationUri (uri)))
    {
      GE_BREAK (NULL, 0);       /* wrong type of URI! */
      return NULL;
    }
  dl = MALLOC (sizeof (FSUI_DownloadList));
  memset (dl, 0, sizeof (FSUI_DownloadList));
  dl->startTime = 0;            /* not run at all so far! */
  dl->runTime = 0;              /* not run at all so far! */
  dl->state = FSUI_PENDING;
  dl->is_recursive = is_recursive;
  dl->parent = parent;
  dl->search = psearch;
  dl->is_directory = SYSERR;    /* don't know */
  dl->anonymityLevel = anonymityLevel;
  dl->ctx = ctx;
  dl->filename = STRDUP (filename);
  dl->fi.uri = ECRS_dupUri (uri);
  dl->fi.meta = ECRS_dupMetaData (meta);
  dl->total = ECRS_fileSize (uri);
  dl->child = NULL;
  dl->cctx = NULL;
  /* signal start! */
  event.type = FSUI_download_started;
  event.data.DownloadStarted.dc.pos = dl;
  event.data.DownloadStarted.dc.cctx = NULL;
  event.data.DownloadStarted.dc.ppos =
    dl->parent == &ctx->activeDownloads ? NULL : dl->parent;
  event.data.DownloadStarted.dc.pcctx = dl->parent->cctx;
  event.data.DownloadStarted.dc.spos = dl->search;
  event.data.DownloadStarted.dc.sctx =
    dl->search == NULL ? NULL : dl->search->cctx;
  event.data.DownloadStarted.total = ECRS_fileSize (dl->fi.uri);
  event.data.DownloadStarted.filename = dl->filename;
  event.data.DownloadStarted.fi.uri = dl->fi.uri;
  event.data.DownloadStarted.fi.meta = dl->fi.meta;
  event.data.DownloadStarted.anonymityLevel = dl->anonymityLevel;
  URITRACK_addState (ctx->ectx, ctx->cfg, uri, URITRACK_DOWNLOAD_STARTED);
  dl->cctx = dl->ctx->ecb (dl->ctx->ecbClosure, &event);
  dl->next = parent->child;
  parent->child = dl;
  if (psearch != NULL)
    {
      GROW (psearch->my_downloads,
            psearch->my_downloads_size, psearch->my_downloads_size + 1);
      psearch->my_downloads[psearch->my_downloads_size - 1] = dl;
    }
  return dl;
}

/**
 * Start to download a file.
 *
 * @return OK on success, SYSERR if the target file is
 *  already used for another download at the moment (or
 *  if the disk does not have enough space).
 */
struct FSUI_DownloadList *
FSUI_startDownload (struct FSUI_Context *ctx,
                    unsigned int anonymityLevel,
                    int doRecursive,
                    const struct ECRS_URI *uri,
                    const struct ECRS_MetaData *meta,
                    const char *filename,
                    struct FSUI_SearchList *psearch,
                    struct FSUI_DownloadList *pdownload)
{
  struct FSUI_DownloadList *ret;

  MUTEX_LOCK (ctx->lock);
  if (pdownload == NULL)
    pdownload = &ctx->activeDownloads;
  ret = startDownload (ctx,
                       anonymityLevel,
                       doRecursive, uri, meta, filename, psearch, pdownload);
  MUTEX_UNLOCK (ctx->lock);
  return ret;
}

/**
 * Starts or stops download threads in accordance with thread pool
 * size and active downloads.  Call only while holding FSUI lock (or
 * during start/stop).  Called from cron job in fsui.c.
 *
 * @return YES if change done that may require re-trying
 */
int
FSUI_updateDownloadThread (FSUI_DownloadList * list)
{
  struct GE_Context *ectx;
  FSUI_DownloadList *dpos;
  void *unused;
  int ret;

  if (list == NULL)
    return NO;
  ectx = list->ctx->ectx;

#if DEBUG_DTM
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Download thread manager investigates pending download of file `%s' (%u/%u downloads)\n",
          list->filename,
          list->ctx->activeDownloadThreads, list->ctx->threadPoolSize);
#endif
  ret = NO;
  /* should this one be started? */
  if ((list->ctx->threadPoolSize
       > list->ctx->activeDownloadThreads) &&
      (list->state == FSUI_PENDING) &&
      ((list->total > list->completed) || (list->total == 0)))
    {
#if DEBUG_DTM
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "Download thread manager starts download of file `%s'\n",
              list->filename);
#endif
      list->state = FSUI_ACTIVE;
      list->handle = PTHREAD_CREATE (&downloadThread, list, 128 * 1024);
      if (list->handle != NULL)
        {
          list->ctx->activeDownloadThreads++;
        }
      else
        {
          GE_LOG_STRERROR (ectx,
                           GE_ADMIN | GE_USER | GE_BULK | GE_ERROR,
                           "pthread_create");
          list->state = FSUI_ERROR_JOINED;
        }
    }

  /* should this one be stopped? */
  if ((list->ctx->threadPoolSize
       < list->ctx->activeDownloadThreads) && (list->state == FSUI_ACTIVE))
    {
#if DEBUG_DTM
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "Download thread manager aborts active download of file `%s' (%u/%u downloads)\n",
              list->filename,
              list->ctx->activeDownloadThreads, list->ctx->threadPoolSize);
#endif
      list->state = FSUI_SUSPENDING;
      GE_ASSERT (ectx, list->handle != NULL);
      PTHREAD_STOP_SLEEP (list->handle);
      PTHREAD_JOIN (list->handle, &unused);
      list->handle = NULL;
      list->ctx->activeDownloadThreads--;
      list->state = FSUI_PENDING;
      ret = YES;
    }

  /* has this one "died naturally"? */
  if ((list->state == FSUI_COMPLETED) ||
      (list->state == FSUI_ABORTED) || (list->state == FSUI_ERROR))
    {
#if DEBUG_DTM
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "Download thread manager collects inactive download of file `%s'\n",
              list->filename);
#endif
      PTHREAD_JOIN (list->handle, &unused);
      list->handle = NULL;
      list->ctx->activeDownloadThreads--;
      list->state++;            /* adds _JOINED */
      ret = YES;
    }

  dpos = list->child;
  while (dpos != NULL)
    {
      if (YES == FSUI_updateDownloadThread (dpos))
        ret = YES;
      dpos = dpos->next;
    }
  return ret;
}


/**
 * Abort a download (and all child-downloads).
 *
 * @return SYSERR if no such download is pending,
 *         NO if the download has already finished
 */
int
FSUI_abortDownload (struct FSUI_Context *ctx, struct FSUI_DownloadList *dl)
{
  struct FSUI_DownloadList *c;

  GE_ASSERT (ctx->ectx, dl != NULL);
  c = dl->child;
  while (c != NULL)
    {
      FSUI_abortDownload (ctx, c);
      c = c->next;
    }
  if ((dl->state != FSUI_ACTIVE) && (dl->state != FSUI_PENDING))
    return NO;
  if (dl->state == FSUI_ACTIVE)
    {
      dl->state = FSUI_ABORTED;
      PTHREAD_STOP_SLEEP (dl->handle);
    }
  else
    {
      dl->state = FSUI_ABORTED_JOINED;
    }
  return OK;
}

/**
 * Stops a download (and all downloads that are
 * child downloads of this download).
 *
 * @return SYSERR if no such download is pending
 */
int
FSUI_stopDownload (struct FSUI_Context *ctx, struct FSUI_DownloadList *dl)
{
  void *unused;
  struct FSUI_DownloadList *prev;
  FSUI_Event event;
  int i;

  GE_ASSERT (ctx->ectx, dl != NULL);
  while (dl->child != NULL)
    FSUI_stopDownload (ctx, dl->child);
  MUTEX_LOCK (ctx->lock);
  prev =
    (dl->parent != NULL) ? dl->parent->child : ctx->activeDownloads.child;
  while ((prev != dl) && (prev != NULL) && (prev->next != dl))
    prev = prev->next;
  if (prev == NULL)
    {
      MUTEX_UNLOCK (ctx->lock);
      GE_LOG (ctx->ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "FSUI_stopDownload failed to locate download.\n");
      return SYSERR;
    }
  if (prev == dl)
    dl->parent->child = dl->next;       /* first child of parent */
  else
    prev->next = dl->next;      /* not first child */
  MUTEX_UNLOCK (ctx->lock);
  if ((dl->state == FSUI_ACTIVE) ||
      (dl->state == FSUI_COMPLETED) ||
      (dl->state == FSUI_ABORTED) || (dl->state == FSUI_ERROR))
    {
      GE_ASSERT (ctx->ectx, dl->handle != NULL);
      PTHREAD_JOIN (dl->handle, &unused);
      MUTEX_LOCK (ctx->lock);
      dl->ctx->activeDownloadThreads--;
      MUTEX_UNLOCK (ctx->lock);
      dl->handle = NULL;
      if (dl->state == FSUI_ACTIVE)
        dl->state = FSUI_PENDING;
      else
        dl->state++;            /* add _JOINED */
    }
  else
    {
      GE_ASSERT (ctx->ectx, dl->handle == NULL);
    }
  event.type = FSUI_download_stopped;
  event.data.DownloadStopped.dc.pos = dl;
  event.data.DownloadStopped.dc.cctx = dl->cctx;
  event.data.DownloadStopped.dc.ppos =
    dl->parent == &ctx->activeDownloads ? NULL : dl->parent;
  event.data.DownloadStopped.dc.pcctx = dl->parent->cctx;
  event.data.DownloadStopped.dc.spos = dl->search;
  event.data.DownloadStopped.dc.sctx =
    dl->search == NULL ? NULL : dl->search->cctx;
  ctx->ecb (ctx->ecbClosure, &event);
  if (dl->search != NULL)
    {
      for (i = 0; i < dl->search->my_downloads_size; i++)
        {
          if (dl->search->my_downloads[i] == dl)
            {
              dl->search->my_downloads[i] =
                dl->search->my_downloads[dl->search->my_downloads_size - 1];
              GROW (dl->search->my_downloads,
                    dl->search->my_downloads_size,
                    dl->search->my_downloads_size - 1);
            }
        }
    }
  for (i = dl->completedDownloadsCount - 1; i >= 0; i--)
    ECRS_freeUri (dl->completedDownloads[i]);
  GROW (dl->completedDownloads, dl->completedDownloadsCount, 0);
  ECRS_freeUri (dl->fi.uri);
  ECRS_freeMetaData (dl->fi.meta);
  FREE (dl->filename);
  FREE (dl);
  return OK;
}


/* end of download.c */
