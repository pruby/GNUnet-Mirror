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
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_uritrack_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

#define DEBUG_DTM GNUNET_NO

/**
 * Mark the given URI as found in a directory
 * in URITRACK.
 */
static int
listURIfoundDirectory (const GNUNET_ECRS_FileInfo * fi,
                       const GNUNET_HashCode * key, int isRoot, void *prnt)
{
  GNUNET_FSUI_DownloadList *dl = prnt;

  if (isRoot == GNUNET_YES)
    return GNUNET_OK;           /* namespace ad, ignore */
  GNUNET_URITRACK_add_state (dl->ctx->ectx,
                             dl->ctx->cfg, fi->uri,
                             GNUNET_URITRACK_DIRECTORY_FOUND);

  return GNUNET_OK;
}



/**
 * Start to download a file.
 */
static GNUNET_FSUI_DownloadList *startDownload (struct GNUNET_FSUI_Context
                                                *ctx,
                                                unsigned int anonymityLevel,
                                                int is_recursive,
                                                const struct GNUNET_ECRS_URI
                                                *uri,
                                                const struct
                                                GNUNET_ECRS_MetaData *meta,
                                                const char *filename,
                                                struct GNUNET_FSUI_SearchList
                                                *psearch,
                                                GNUNET_FSUI_DownloadList *
                                                parent);

/**
 * Initiate a (recursive) download of the given
 * directory entry.
 */
static int
triggerRecursiveDownload (const GNUNET_ECRS_FileInfo * fi,
                          const GNUNET_HashCode * key, int isRoot, void *prnt)
{
  GNUNET_FSUI_DownloadList *parent = prnt;
  struct GNUNET_GE_Context *ectx;
  int i;
  GNUNET_FSUI_DownloadList *pos;
  char *filename;
  char *fullName;
  char *dotdot;

  ectx = parent->ctx->ectx;
  if (isRoot == GNUNET_YES)
    return GNUNET_OK;           /* namespace ad, ignore */

  GNUNET_URITRACK_track (ectx, parent->ctx->cfg, fi);
  for (i = 0; i < parent->completedDownloadsCount; i++)
    if (GNUNET_ECRS_uri_test_equal (parent->completedDownloads[i], fi->uri))
      return GNUNET_OK;         /* already complete! */
  pos = parent->child;
  while (pos != NULL)
    {
      if (GNUNET_ECRS_uri_test_equal (pos->fi.uri, fi->uri))
        return GNUNET_OK;       /* already downloading */
      pos = pos->next;
    }
  filename = GNUNET_ECRS_meta_data_get_by_type (fi->meta, EXTRACTOR_FILENAME);
  if (filename == NULL)
    {
      char *tmp = GNUNET_ECRS_uri_to_string (fi->uri);
      GNUNET_GE_ASSERT (ectx,
                        strlen (tmp) >=
                        strlen (GNUNET_ECRS_URI_PREFIX) +
                        strlen (GNUNET_ECRS_FILE_INFIX));
      filename =
        GNUNET_strdup (&tmp
                       [strlen (GNUNET_ECRS_URI_PREFIX) +
                        strlen (GNUNET_ECRS_FILE_INFIX)]);
      GNUNET_free (tmp);
    }
  fullName =
    GNUNET_malloc (strlen (parent->filename) + 2 + strlen (filename));
  strcpy (fullName, parent->filename);
  strcat (fullName, filename);
  while (NULL != (dotdot = strstr (fullName, "..")))
    dotdot[0] = dotdot[1] = '_';
  GNUNET_free (filename);
#if DEBUG_DTM
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Starting recursive download of `%s'\n", fullName);
#endif
  startDownload (parent->ctx,
                 parent->anonymityLevel,
                 GNUNET_YES, fi->uri, fi->meta, fullName, parent->search,
                 parent);
  GNUNET_free (fullName);
  return GNUNET_OK;
}

/**
 * Progress notification from ECRS.  Tell FSUI client.
 */
static void
downloadProgressCallback (unsigned long long totalBytes,
                          unsigned long long completedBytes,
                          GNUNET_CronTime eta,
                          unsigned long long lastBlockOffset,
                          const char *lastBlock,
                          unsigned int lastBlockSize, void *cls)
{
  GNUNET_FSUI_DownloadList *dl = cls;
  GNUNET_FSUI_Event event;
  struct GNUNET_ECRS_MetaData *md;
  GNUNET_CronTime now;
  GNUNET_CronTime run_time;

  GNUNET_GE_ASSERT (dl->ctx->ectx, dl->total == totalBytes);
  dl->completed = completedBytes;
  event.type = GNUNET_FSUI_download_progress;
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
  now = GNUNET_get_time ();
  run_time = now - dl->startTime;
  if ((dl->total == 0) || (dl->completed == 0))
    {
      eta = now;
    }
  else
    {
      eta = (GNUNET_CronTime) (dl->startTime +
                               (((double) (run_time) /
                                 (double) dl->completed)) *
                               (double) dl->total);
      if (eta < now)
        eta = now;
    }
  event.data.DownloadProgress.eta = eta;
  event.data.DownloadProgress.filename = dl->filename;
  event.data.DownloadProgress.uri = dl->fi.uri;
  event.data.DownloadProgress.last_block = lastBlock;
  event.data.DownloadProgress.last_size = lastBlockSize;
  dl->ctx->ecb (dl->ctx->ecbClosure, &event);
  if ((lastBlockOffset == 0) && (dl->is_directory == GNUNET_SYSERR))
    {
      /* check if this is a directory */
      if ((lastBlockSize > strlen (GNUNET_DIRECTORY_MAGIC)) &&
          (0 == strncmp (GNUNET_DIRECTORY_MAGIC,
                         lastBlock, strlen (GNUNET_DIRECTORY_MAGIC))))
        dl->is_directory = GNUNET_YES;
      else
        dl->is_directory = GNUNET_NO;
    }
  if (dl->is_directory == GNUNET_YES)
    {
      md = NULL;
      GNUNET_ECRS_directory_list_contents (dl->ctx->ectx,
                                           lastBlock,
                                           lastBlockSize, &md,
                                           &listURIfoundDirectory, dl);
      if (md != NULL)
        GNUNET_ECRS_meta_data_destroy (md);
    }
  if ((dl->is_recursive == GNUNET_YES) && (dl->is_directory == GNUNET_YES))
    {
      md = NULL;
      GNUNET_mutex_lock (dl->ctx->lock);
      GNUNET_ECRS_directory_list_contents (dl->ctx->ectx,
                                           lastBlock,
                                           lastBlockSize, &md,
                                           &triggerRecursiveDownload, dl);
      GNUNET_mutex_unlock (dl->ctx->lock);
      if (md != NULL)
        GNUNET_ECRS_meta_data_destroy (md);
    }
}

/**
 * Check if termination of this download is desired.
 */
static int
testTerminate (void *cls)
{
  GNUNET_FSUI_DownloadList *dl = cls;

  if ((dl->state == GNUNET_FSUI_ERROR) || (dl->state == GNUNET_FSUI_ABORTED))
    return GNUNET_SYSERR;       /* aborted - delete! */
  if (dl->state != GNUNET_FSUI_ACTIVE)
    return GNUNET_NO;           /* suspended */
  return GNUNET_OK;
}

/**
 * Thread that downloads a file.
 */
static void *
downloadThread (void *cls)
{
  GNUNET_FSUI_DownloadList *dl = cls;
  int ret;
  GNUNET_FSUI_Event event;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GE_Memory *mem;
  struct GNUNET_GE_Context *ee;

  dl->startTime = GNUNET_get_time () - dl->runTime;
  ectx = dl->ctx->ectx;
#if DEBUG_DTM
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Download thread for `%s' started...\n", dl->filename);
#endif
  GNUNET_GE_ASSERT (ectx, dl->ctx != NULL);
  GNUNET_GE_ASSERT (ectx, dl->filename != NULL);
  mem = GNUNET_GE_memory_create (2);
  ee =
    GNUNET_GE_create_context_memory (GNUNET_GE_USER | GNUNET_GE_ADMIN |
                                     GNUNET_GE_ERROR | GNUNET_GE_WARNING |
                                     GNUNET_GE_FATAL | GNUNET_GE_BULK |
                                     GNUNET_GE_IMMEDIATE, mem);
  ret =
    GNUNET_ECRS_file_download (ee, dl->ctx->cfg, dl->fi.uri, dl->filename,
                               dl->anonymityLevel, &downloadProgressCallback,
                               dl, &testTerminate, dl);
  if (ret == GNUNET_OK)
    {
      dl->state = GNUNET_FSUI_COMPLETED;
      event.type = GNUNET_FSUI_download_completed;
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
      GNUNET_URITRACK_add_state (dl->ctx->ectx,
                                 dl->ctx->cfg,
                                 dl->fi.uri,
                                 GNUNET_URITRACK_DOWNLOAD_COMPLETED);
      dl->ctx->ecb (dl->ctx->ecbClosure, &event);
    }
  else if (dl->state == GNUNET_FSUI_ACTIVE)
    {
      const char *error;

      /* ECRS error */
      dl->state = GNUNET_FSUI_ERROR;
      event.type = GNUNET_FSUI_download_error;
      event.data.DownloadError.dc.pos = dl;
      event.data.DownloadError.dc.cctx = dl->cctx;
      event.data.DownloadError.dc.ppos =
        dl->parent == &dl->ctx->activeDownloads ? NULL : dl->parent;
      event.data.DownloadError.dc.pcctx = dl->parent->cctx;
      event.data.DownloadError.dc.spos = dl->search;
      event.data.DownloadError.dc.sctx =
        dl->search == NULL ? NULL : dl->search->cctx;
      error = GNUNET_GE_memory_get (mem, 0);
      if (error == NULL)
        error = _("Download failed (no reason given)");
      event.data.DownloadError.message = error;
      GNUNET_URITRACK_add_state (dl->ctx->ectx,
                                 dl->ctx->cfg, dl->fi.uri,
                                 GNUNET_URITRACK_DOWNLOAD_ABORTED);
      dl->ctx->ecb (dl->ctx->ecbClosure, &event);
    }
  else if (dl->state == GNUNET_FSUI_ABORTED)
    {                           /* aborted */
      event.type = GNUNET_FSUI_download_aborted;
      event.data.DownloadAborted.dc.pos = dl;
      event.data.DownloadAborted.dc.cctx = dl->cctx;
      event.data.DownloadAborted.dc.ppos =
        dl->parent == &dl->ctx->activeDownloads ? NULL : dl->parent;
      event.data.DownloadAborted.dc.pcctx = dl->parent->cctx;
      event.data.DownloadAborted.dc.spos = dl->search;
      event.data.DownloadAborted.dc.sctx =
        dl->search == NULL ? NULL : dl->search->cctx;
      GNUNET_URITRACK_add_state (dl->ctx->ectx, dl->ctx->cfg, dl->fi.uri,
                                 GNUNET_URITRACK_DOWNLOAD_ABORTED);
      dl->ctx->ecb (dl->ctx->ecbClosure, &event);
    }
  else
    {
      /* else: suspended */
      GNUNET_GE_BREAK (NULL, dl->state == GNUNET_FSUI_SUSPENDING);
    }


  if ((ret == GNUNET_OK) &&
      (dl->is_directory == GNUNET_YES)
      && (GNUNET_ECRS_uri_get_file_size (dl->fi.uri) > 0))
    {
      char *dirBlock;
      int fd;
      char *fn;
      size_t totalBytes;
      struct GNUNET_ECRS_MetaData *md;

      totalBytes = GNUNET_ECRS_uri_get_file_size (dl->fi.uri);
      fn =
        GNUNET_malloc (strlen (dl->filename) + strlen (GNUNET_DIRECTORY_EXT) +
                       1);
      strcpy (fn, dl->filename);
      fd = strlen (fn) - 1;
      if (fn[fd] == '/' || fn[fd] == '\\')
        {
          fn[fd] = '\0';
          strcat (fn, GNUNET_DIRECTORY_EXT);
        }
      fd = GNUNET_disk_file_open (ectx, fn, O_LARGEFILE | O_RDONLY);
      if (fd != -1)
        {
          dirBlock = MMAP (NULL, totalBytes, PROT_READ, MAP_SHARED, fd, 0);
          if (MAP_FAILED == dirBlock)
            {
              GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                           GNUNET_GE_ERROR | GNUNET_GE_BULK |
                                           GNUNET_GE_ADMIN | GNUNET_GE_USER,
                                           "mmap", fn);
            }
          else
            {
              md = NULL;
              GNUNET_ECRS_directory_list_contents (dl->ctx->ectx,
                                                   dirBlock,
                                                   totalBytes,
                                                   &md,
                                                   &listURIfoundDirectory,
                                                   dl);
              if (md != NULL)
                GNUNET_ECRS_meta_data_destroy (md);

              if (dl->is_recursive)
                {
                  /* load directory, start downloads */
                  md = NULL;
                  GNUNET_mutex_lock (dl->ctx->lock);
                  GNUNET_ECRS_directory_list_contents (dl->ctx->ectx,
                                                       dirBlock,
                                                       totalBytes,
                                                       &md,
                                                       &triggerRecursiveDownload,
                                                       dl);
                  GNUNET_mutex_unlock (dl->ctx->lock);
                  GNUNET_ECRS_meta_data_destroy (md);
                  MUNMAP (dirBlock, totalBytes);
                }
            }
          CLOSE (fd);
        }
      GNUNET_free (fn);
    }
#if DEBUG_DTM
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Download thread for `%s' terminated (%s)...\n",
                 dl->filename, ret == GNUNET_OK ? "COMPLETED" : "ABORTED");
#endif
  dl->runTime = GNUNET_get_time () - dl->startTime;
  GNUNET_GE_free_context (ee);
  GNUNET_GE_memory_free (mem);
  return NULL;
}

/**
 * Start to download a file.
 */
static GNUNET_FSUI_DownloadList *
startDownload (struct GNUNET_FSUI_Context *ctx,
               unsigned int anonymityLevel,
               int is_recursive,
               const struct GNUNET_ECRS_URI *uri,
               const struct GNUNET_ECRS_MetaData *meta,
               const char *filename,
               struct GNUNET_FSUI_SearchList *psearch,
               GNUNET_FSUI_DownloadList * parent)
{
  GNUNET_FSUI_DownloadList *dl;
  GNUNET_FSUI_Event event;

  GNUNET_GE_ASSERT (NULL, ctx != NULL);
  GNUNET_GE_ASSERT (NULL, parent != NULL);
  if (!(GNUNET_ECRS_uri_test_chk (uri) || GNUNET_ECRS_uri_test_loc (uri)))
    {
      GNUNET_GE_BREAK (NULL, 0);        /* wrong type of URI! */
      return NULL;
    }
  dl = GNUNET_malloc (sizeof (GNUNET_FSUI_DownloadList));
  memset (dl, 0, sizeof (GNUNET_FSUI_DownloadList));
  dl->startTime = 0;            /* not run at all so far! */
  dl->runTime = 0;              /* not run at all so far! */
  dl->state = GNUNET_FSUI_PENDING;
  dl->is_recursive = is_recursive;
  dl->parent = parent;
  dl->search = psearch;
  dl->is_directory = GNUNET_SYSERR;     /* don't know */
  dl->anonymityLevel = anonymityLevel;
  dl->ctx = ctx;
  dl->filename = GNUNET_strdup (filename);
  dl->fi.uri = GNUNET_ECRS_uri_duplicate (uri);
  dl->fi.meta = GNUNET_ECRS_meta_data_duplicate (meta);
  dl->total = GNUNET_ECRS_uri_get_file_size (uri);
  dl->child = NULL;
  dl->cctx = NULL;
  /* signal start! */
  event.type = GNUNET_FSUI_download_started;
  event.data.DownloadStarted.dc.pos = dl;
  event.data.DownloadStarted.dc.cctx = NULL;
  event.data.DownloadStarted.dc.ppos =
    dl->parent == &ctx->activeDownloads ? NULL : dl->parent;
  event.data.DownloadStarted.dc.pcctx = dl->parent->cctx;
  event.data.DownloadStarted.dc.spos = dl->search;
  event.data.DownloadStarted.dc.sctx =
    dl->search == NULL ? NULL : dl->search->cctx;
  event.data.DownloadStarted.total =
    GNUNET_ECRS_uri_get_file_size (dl->fi.uri);
  event.data.DownloadStarted.filename = dl->filename;
  event.data.DownloadStarted.fi.uri = dl->fi.uri;
  event.data.DownloadStarted.fi.meta = dl->fi.meta;
  event.data.DownloadStarted.anonymityLevel = dl->anonymityLevel;
  GNUNET_URITRACK_add_state (ctx->ectx, ctx->cfg, uri,
                             GNUNET_URITRACK_DOWNLOAD_STARTED);
  dl->cctx = dl->ctx->ecb (dl->ctx->ecbClosure, &event);
  dl->next = parent->child;
  parent->child = dl;
  if (psearch != NULL)
    {
      GNUNET_array_grow (psearch->my_downloads,
                         psearch->my_downloads_size,
                         psearch->my_downloads_size + 1);
      psearch->my_downloads[psearch->my_downloads_size - 1] = dl;
    }
  return dl;
}

/**
 * Start to download a file.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if the target file is
 *  already used for another download at the moment (or
 *  if the disk does not have enough space).
 */
struct GNUNET_FSUI_DownloadList *
GNUNET_FSUI_download_start (struct GNUNET_FSUI_Context *ctx,
                            unsigned int anonymityLevel,
                            int doRecursive,
                            const struct GNUNET_ECRS_URI *uri,
                            const struct GNUNET_ECRS_MetaData *meta,
                            const char *filename,
                            struct GNUNET_FSUI_SearchList *psearch,
                            struct GNUNET_FSUI_DownloadList *pdownload)
{
  struct GNUNET_FSUI_DownloadList *ret;

  GNUNET_mutex_lock (ctx->lock);
  if (pdownload == NULL)
    pdownload = &ctx->activeDownloads;
  ret = startDownload (ctx,
                       anonymityLevel,
                       doRecursive, uri, meta, filename, psearch, pdownload);
  GNUNET_mutex_unlock (ctx->lock);
  return ret;
}

/**
 * Starts or stops download threads in accordance with thread pool
 * size and active downloads.  Call only while holding FSUI lock (or
 * during start/stop).  Called from cron job in fsui.c.
 *
 * @return GNUNET_YES if change done that may require re-trying
 */
int
GNUNET_FSUI_updateDownloadThread (GNUNET_FSUI_DownloadList * list)
{
  struct GNUNET_GE_Context *ectx;
  GNUNET_FSUI_DownloadList *dpos;
  void *unused;
  int ret;

  if (list == NULL)
    return GNUNET_NO;
  ectx = list->ctx->ectx;

#if DEBUG_DTM
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Download thread manager investigates pending download of file `%s' (%u/%u downloads)\n",
                 list->filename,
                 list->ctx->activeDownloadThreads, list->ctx->threadPoolSize);
#endif
  ret = GNUNET_NO;
  /* should this one be started? */
  if ((list->ctx->threadPoolSize
       > list->ctx->activeDownloadThreads) &&
      (list->state == GNUNET_FSUI_PENDING) &&
      ((list->total > list->completed) || (list->total == 0)))
    {
#if DEBUG_DTM
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Download thread manager starts download of file `%s'\n",
                     list->filename);
#endif
      list->state = GNUNET_FSUI_ACTIVE;
      list->handle = GNUNET_thread_create (&downloadThread, list, 128 * 1024);
      if (list->handle != NULL)
        {
          list->ctx->activeDownloadThreads++;
        }
      else
        {
          GNUNET_GE_LOG_STRERROR (ectx,
                                  GNUNET_GE_ADMIN | GNUNET_GE_USER |
                                  GNUNET_GE_BULK | GNUNET_GE_ERROR,
                                  "pthread_create");
          list->state = GNUNET_FSUI_ERROR_JOINED;
        }
    }

  /* should this one be stopped? */
  if ((list->ctx->threadPoolSize
       < list->ctx->activeDownloadThreads)
      && (list->state == GNUNET_FSUI_ACTIVE))
    {
#if DEBUG_DTM
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Download thread manager aborts active download of file `%s' (%u/%u downloads)\n",
                     list->filename,
                     list->ctx->activeDownloadThreads,
                     list->ctx->threadPoolSize);
#endif
      list->state = GNUNET_FSUI_SUSPENDING;
      GNUNET_GE_ASSERT (ectx, list->handle != NULL);
      GNUNET_thread_stop_sleep (list->handle);
      GNUNET_thread_join (list->handle, &unused);
      list->handle = NULL;
      list->ctx->activeDownloadThreads--;
      list->state = GNUNET_FSUI_PENDING;
      ret = GNUNET_YES;
    }

  /* has this one "died naturally"? */
  if ((list->state == GNUNET_FSUI_COMPLETED) ||
      (list->state == GNUNET_FSUI_ABORTED)
      || (list->state == GNUNET_FSUI_ERROR))
    {
#if DEBUG_DTM
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Download thread manager collects inactive download of file `%s'\n",
                     list->filename);
#endif
      GNUNET_thread_stop_sleep (list->handle);
      GNUNET_thread_join (list->handle, &unused);
      list->handle = NULL;
      list->ctx->activeDownloadThreads--;
      list->state++;            /* adds _JOINED */
      ret = GNUNET_YES;
    }

  dpos = list->child;
  while (dpos != NULL)
    {
      if (GNUNET_YES == GNUNET_FSUI_updateDownloadThread (dpos))
        ret = GNUNET_YES;
      dpos = dpos->next;
    }
  return ret;
}


/**
 * Abort a download (and all child-downloads).
 *
 * @return GNUNET_SYSERR if no such download is pending,
 *         GNUNET_NO if the download has already finished
 */
int
GNUNET_FSUI_download_abort (struct GNUNET_FSUI_Context *ctx,
                            struct GNUNET_FSUI_DownloadList *dl)
{
  struct GNUNET_FSUI_DownloadList *c;

  GNUNET_GE_ASSERT (ctx->ectx, dl != NULL);
  c = dl->child;
  while (c != NULL)
    {
      GNUNET_FSUI_download_abort (ctx, c);
      c = c->next;
    }
  if ((dl->state != GNUNET_FSUI_ACTIVE) && (dl->state != GNUNET_FSUI_PENDING))
    return GNUNET_NO;
  if (dl->state == GNUNET_FSUI_ACTIVE)
    {
      dl->state = GNUNET_FSUI_ABORTED;
      GNUNET_thread_stop_sleep (dl->handle);
    }
  else
    {
      dl->state = GNUNET_FSUI_ABORTED_JOINED;
    }
  return GNUNET_OK;
}

/**
 * Stops a download (and all downloads that are
 * child downloads of this download).
 *
 * @return GNUNET_SYSERR if no such download is pending
 */
int
GNUNET_FSUI_download_stop (struct GNUNET_FSUI_Context *ctx,
                           struct GNUNET_FSUI_DownloadList *dl)
{
  void *unused;
  struct GNUNET_FSUI_DownloadList *prev;
  GNUNET_FSUI_Event event;
  int i;

  GNUNET_GE_ASSERT (ctx->ectx, dl != NULL);
  while (dl->child != NULL)
    GNUNET_FSUI_download_stop (ctx, dl->child);
  GNUNET_mutex_lock (ctx->lock);
  prev =
    (dl->parent != NULL) ? dl->parent->child : ctx->activeDownloads.child;
  while ((prev != dl) && (prev != NULL) && (prev->next != dl))
    prev = prev->next;
  if (prev == NULL)
    {
      GNUNET_mutex_unlock (ctx->lock);
      GNUNET_GE_LOG (ctx->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "GNUNET_FSUI_stopDownload failed to locate download.\n");
      return GNUNET_SYSERR;
    }
  if (prev == dl)
    dl->parent->child = dl->next;       /* first child of parent */
  else
    prev->next = dl->next;      /* not first child */
  GNUNET_mutex_unlock (ctx->lock);
  if ((dl->state == GNUNET_FSUI_ACTIVE) ||
      (dl->state == GNUNET_FSUI_COMPLETED) ||
      (dl->state == GNUNET_FSUI_ABORTED) || (dl->state == GNUNET_FSUI_ERROR))
    {
      GNUNET_GE_ASSERT (ctx->ectx, dl->handle != NULL);
      GNUNET_thread_stop_sleep (dl->handle);
      GNUNET_thread_join (dl->handle, &unused);
      GNUNET_mutex_lock (ctx->lock);
      dl->ctx->activeDownloadThreads--;
      GNUNET_mutex_unlock (ctx->lock);
      dl->handle = NULL;
      if (dl->state == GNUNET_FSUI_ACTIVE)
        dl->state = GNUNET_FSUI_PENDING;
      else
        dl->state++;            /* add _JOINED */
    }
  else
    {
      GNUNET_GE_ASSERT (ctx->ectx, dl->handle == NULL);
    }
  event.type = GNUNET_FSUI_download_stopped;
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
              GNUNET_array_grow (dl->search->my_downloads,
                                 dl->search->my_downloads_size,
                                 dl->search->my_downloads_size - 1);
            }
        }
    }
  for (i = dl->completedDownloadsCount - 1; i >= 0; i--)
    GNUNET_ECRS_uri_destroy (dl->completedDownloads[i]);
  GNUNET_array_grow (dl->completedDownloads, dl->completedDownloadsCount, 0);
  GNUNET_ECRS_uri_destroy (dl->fi.uri);
  GNUNET_ECRS_meta_data_destroy (dl->fi.meta);
  GNUNET_free (dl->filename);
  GNUNET_free (dl);
  return GNUNET_OK;
}


/* end of download.c */
