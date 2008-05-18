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
 * @file applications/fs/fsui/unindex.c
 * @brief unindex functions
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"


/**
 * Transform an ECRS progress callback into an FSUI event.
 */
static void
progressCallback (unsigned long long totalBytes,
                  unsigned long long completedBytes, GNUNET_CronTime eta,
                  void *cls)
{
  GNUNET_FSUI_UnindexList *utc = cls;
  GNUNET_FSUI_Event event;

  event.type = GNUNET_FSUI_unindex_progress;
  event.data.UnindexProgress.uc.pos = utc;
  event.data.UnindexProgress.uc.cctx = utc->cctx;
  event.data.UnindexProgress.total = totalBytes;
  event.data.UnindexProgress.completed = completedBytes;
  event.data.UnindexProgress.eta = eta;
  event.data.UnindexProgress.filename = utc->filename;
  utc->ctx->ecb (utc->ctx->ecbClosure, &event);
}

static int
tt (void *cls)
{
  GNUNET_FSUI_UnindexList *utc = cls;
  if (utc->state != GNUNET_FSUI_ACTIVE)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Thread that does the unindex.
 */
void *
GNUNET_FSUI_unindexThread (void *cls)
{
  GNUNET_FSUI_UnindexList *utc = cls;
  GNUNET_FSUI_Event event;
  int ret;
  unsigned long long size;
  struct GNUNET_GE_Memory *mem;
  struct GNUNET_GE_Context *ee;

  if (GNUNET_OK !=
      GNUNET_disk_file_size (utc->ctx->ectx, utc->filename, &size,
                             GNUNET_YES))
    {
      GNUNET_GE_BREAK (utc->ctx->ectx, 0);
      size = 0;
    }
  mem = GNUNET_GE_memory_create (2);
  ee =
    GNUNET_GE_create_context_memory (GNUNET_GE_USER | GNUNET_GE_ADMIN |
                                     GNUNET_GE_ERROR | GNUNET_GE_WARNING |
                                     GNUNET_GE_FATAL | GNUNET_GE_BULK |
                                     GNUNET_GE_IMMEDIATE, mem);
  ret =
    GNUNET_ECRS_file_unindex (ee, utc->ctx->cfg, utc->filename,
                              &progressCallback, utc, &tt, utc);
  if (ret == GNUNET_OK)
    {
      utc->state = GNUNET_FSUI_COMPLETED;
      event.type = GNUNET_FSUI_unindex_completed;
      event.data.UnindexCompleted.uc.pos = utc;
      event.data.UnindexCompleted.uc.cctx = utc->cctx;
      event.data.UnindexCompleted.total = size;
      event.data.UnindexCompleted.filename = utc->filename;
      utc->ctx->ecb (utc->ctx->ecbClosure, &event);
    }
  else if (utc->state == GNUNET_FSUI_ACTIVE)
    {
      const char *error;

      utc->state = GNUNET_FSUI_ERROR;
      event.type = GNUNET_FSUI_unindex_error;
      event.data.UnindexError.uc.pos = utc;
      event.data.UnindexError.uc.cctx = utc->cctx;
      error = GNUNET_GE_memory_get (mem, 0);
      if (error == NULL)
        error = _("Unindexing failed (no reason given)");
      event.data.UnindexError.message = error;
      utc->ctx->ecb (utc->ctx->ecbClosure, &event);
    }
  else if (utc->state == GNUNET_FSUI_ABORTED)
    {
      event.type = GNUNET_FSUI_unindex_aborted;
      event.data.UnindexAborted.uc.pos = utc;
      event.data.UnindexAborted.uc.cctx = utc->cctx;
      utc->ctx->ecb (utc->ctx->ecbClosure, &event);
    }
  else
    {
      /* must be suspending */
      GNUNET_GE_BREAK (NULL, utc->state == GNUNET_FSUI_PENDING);
    }
#if 0
  GNUNET_GE_LOG (utc->ctx->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FSUI unindexThread exits in state %u.\n", utc->state);
#endif
  GNUNET_GE_free_context (ee);
  GNUNET_GE_memory_free (mem);
  return NULL;
}

/**
 * Thread that does the unindex.
 */
static void *
GNUNET_FSUI_unindexThreadEvent (void *cls)
{
  GNUNET_FSUI_UnindexList *utc = cls;
  GNUNET_FSUI_Event event;
  unsigned long long size;

  if (GNUNET_OK !=
      GNUNET_disk_file_size (utc->ctx->ectx, utc->filename, &size,
                             GNUNET_YES))
    {
      GNUNET_GE_BREAK (utc->ctx->ectx, 0);
      size = 0;
    }
  event.type = GNUNET_FSUI_unindex_started;
  event.data.UnindexStarted.uc.pos = utc;
  event.data.UnindexStarted.uc.cctx = NULL;
  event.data.UnindexStarted.total = size;
  event.data.UnindexStarted.filename = utc->filename;
  utc->cctx = utc->ctx->ecb (utc->ctx->ecbClosure, &event);
  return GNUNET_FSUI_unindexThread (utc);
}

/**
 * Start unindexing a file.  Note that an unindex cannot be stopped once
 * started (not necessary anyway), but it can fail.  The function also
 * automatically the unindexed file in the global keyword space under
 * the given keywords.
 *
 * @return GNUNET_OK on success (at least we started with it),
 *  GNUNET_SYSERR if the file does not exist or gnunetd is not
 *  running
 */
struct GNUNET_FSUI_UnindexList *
GNUNET_FSUI_unindex_start (struct GNUNET_FSUI_Context *ctx,
                           const char *filename)
{
  GNUNET_FSUI_UnindexList *utc;

  if (GNUNET_YES == GNUNET_disk_directory_test (ctx->ectx, filename))
    {
      GNUNET_GE_BREAK (ctx->ectx, 0);
      return NULL;
    }
  if (GNUNET_YES != GNUNET_disk_file_test (ctx->ectx, filename))
    {
      GNUNET_GE_BREAK (ctx->ectx, 0);
      return NULL;
    }
  utc = GNUNET_malloc (sizeof (GNUNET_FSUI_UnindexList));
  utc->ctx = ctx;
  utc->filename = GNUNET_strdup (filename);
  utc->start_time = GNUNET_get_time ();
  utc->state = GNUNET_FSUI_ACTIVE;
  utc->handle =
    GNUNET_thread_create (&GNUNET_FSUI_unindexThreadEvent, utc, 32 * 1024);
  if (utc->handle == NULL)
    {
      GNUNET_GE_LOG_STRERROR (ctx->ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_USER | GNUNET_GE_IMMEDIATE,
                              "PTHREAD_CREATE");
      GNUNET_free (utc->filename);
      GNUNET_free (utc);
      return NULL;
    }
  GNUNET_mutex_lock (ctx->lock);
  utc->next = ctx->unindexOperations;
  ctx->unindexOperations = utc;
  GNUNET_mutex_unlock (ctx->lock);
  return utc;
}


/**
 * Abort a deletion operation.
 *
 * @return GNUNET_SYSERR if no such unindex is pending
 */
int
GNUNET_FSUI_unindex_abort (struct GNUNET_FSUI_UnindexList *ul)
{
  if ((ul->state != GNUNET_FSUI_ACTIVE) && (ul->state != GNUNET_FSUI_PENDING))
    return GNUNET_NO;
  if (ul->state == GNUNET_FSUI_ACTIVE)
    {
      ul->state = GNUNET_FSUI_ABORTED;
      GNUNET_thread_stop_sleep (ul->handle);
    }
  else
    {
      ul->state = GNUNET_FSUI_ABORTED_JOINED;
    }
  return GNUNET_OK;
}


/**
 * Stop a deletion operation.
 *
 * @return GNUNET_SYSERR if no such unindex is pending
 */
int
GNUNET_FSUI_unindex_stop (struct GNUNET_FSUI_UnindexList *dl)
{
  GNUNET_FSUI_UnindexList *prev;
  struct GNUNET_FSUI_Context *ctx;
  struct GNUNET_GE_Context *ectx;
  void *unused;
  GNUNET_FSUI_Event event;

  if (dl == NULL)
    return GNUNET_SYSERR;
  ctx = dl->ctx;
  ectx = ctx->ectx;
#if 0
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "GNUNET_FSUI_stopUnindex called.\n");
#endif
  GNUNET_mutex_lock (ctx->lock);
  prev = ctx->unindexOperations;
  while ((prev != dl) && (prev != NULL) && (prev->next != dl))
    prev = prev->next;
  if (prev == NULL)
    {
      GNUNET_mutex_unlock (ctx->lock);
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "GNUNET_FSUI_stopUnindex failed to locate deletion operation.\n");
      return GNUNET_SYSERR;
    }
  if (prev == dl)
    {
      ctx->unindexOperations = dl->next;
    }
  else
    {
      prev->next = dl->next;
    }
  GNUNET_mutex_unlock (ctx->lock);
  if ((dl->state == GNUNET_FSUI_ACTIVE) ||
      (dl->state == GNUNET_FSUI_COMPLETED) ||
      (dl->state == GNUNET_FSUI_ABORTED) || (dl->state == GNUNET_FSUI_ERROR))
    {
      GNUNET_GE_ASSERT (ctx->ectx, dl->handle != NULL);
      GNUNET_thread_join (dl->handle, &unused);
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
  event.type = GNUNET_FSUI_unindex_stopped;
  event.data.UnindexStopped.uc.pos = dl;
  event.data.UnindexStopped.uc.cctx = dl->cctx;
  dl->ctx->ecb (dl->ctx->ecbClosure, &event);
  GNUNET_free (dl->filename);
  GNUNET_free (dl);
  return GNUNET_OK;
}

/* end of unindex.c */
