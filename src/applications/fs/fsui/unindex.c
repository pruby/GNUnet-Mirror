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
#include "gnunet_util_error_loggers.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"


/**
 * Transform an ECRS progress callback into an FSUI event.
 */
static void
progressCallback (unsigned long long totalBytes,
                  unsigned long long completedBytes, cron_t eta, void *cls)
{
  FSUI_UnindexList *utc = cls;
  FSUI_Event event;

  event.type = FSUI_unindex_progress;
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
  FSUI_UnindexList *utc = cls;
  if (utc->state != FSUI_ACTIVE)
    return SYSERR;
  return OK;
}

/**
 * Thread that does the unindex.
 */
void *
FSUI_unindexThread (void *cls)
{
  FSUI_UnindexList *utc = cls;
  FSUI_Event event;
  int ret;
  unsigned long long size;
  struct GE_Memory *mem;
  struct GE_Context *ee;

  if (OK != disk_file_size (utc->ctx->ectx, utc->filename, &size, YES))
    {
      GE_BREAK (utc->ctx->ectx, 0);
      size = 0;
    }
  mem = GE_memory_create (2);
  ee =
    GE_create_context_memory (GE_USER | GE_ADMIN | GE_ERROR | GE_WARNING |
                              GE_FATAL | GE_BULK | GE_IMMEDIATE, mem);
  ret =
    ECRS_unindexFile (ee, utc->ctx->cfg, utc->filename, &progressCallback,
                      utc, &tt, utc);
  if (ret == OK)
    {
      utc->state = FSUI_COMPLETED;
      event.type = FSUI_unindex_completed;
      event.data.UnindexCompleted.uc.pos = utc;
      event.data.UnindexCompleted.uc.cctx = utc->cctx;
      event.data.UnindexCompleted.total = size;
      event.data.UnindexCompleted.filename = utc->filename;
      utc->ctx->ecb (utc->ctx->ecbClosure, &event);
    }
  else if (utc->state == FSUI_ACTIVE)
    {
      const char *error;

      utc->state = FSUI_ERROR;
      event.type = FSUI_unindex_error;
      event.data.UnindexError.uc.pos = utc;
      event.data.UnindexError.uc.cctx = utc->cctx;
      error = GE_memory_get (mem, 0);
      if (error == NULL)
        error = _("Unindexing failed (no reason given)");
      event.data.UnindexError.message = error;
      utc->ctx->ecb (utc->ctx->ecbClosure, &event);
    }
  else if (utc->state == FSUI_ABORTED)
    {
      event.type = FSUI_unindex_aborted;
      event.data.UnindexAborted.uc.pos = utc;
      event.data.UnindexAborted.uc.cctx = utc->cctx;
      utc->ctx->ecb (utc->ctx->ecbClosure, &event);
    }
  else
    {
      /* must be suspending */
      GE_BREAK (NULL, utc->state == FSUI_PENDING);
    }
#if 0
  GE_LOG (utc->ctx->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FSUI unindexThread exits in state %u.\n", utc->state);
#endif
  GE_free_context (ee);
  GE_memory_free (mem);
  return NULL;
}

/**
 * Thread that does the unindex.
 */
static void *
FSUI_unindexThreadEvent (void *cls)
{
  FSUI_UnindexList *utc = cls;
  FSUI_Event event;
  unsigned long long size;

  if (OK != disk_file_size (utc->ctx->ectx, utc->filename, &size, YES))
    {
      GE_BREAK (utc->ctx->ectx, 0);
      size = 0;
    }
  event.type = FSUI_unindex_started;
  event.data.UnindexStarted.uc.pos = utc;
  event.data.UnindexStarted.uc.cctx = NULL;
  event.data.UnindexStarted.total = size;
  event.data.UnindexStarted.filename = utc->filename;
  utc->cctx = utc->ctx->ecb (utc->ctx->ecbClosure, &event);
  return FSUI_unindexThread (utc);
}

/**
 * Start unindexing a file.  Note that an unindex cannot be stopped once
 * started (not necessary anyway), but it can fail.  The function also
 * automatically the unindexed file in the global keyword space under
 * the given keywords.
 *
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist or gnunetd is not
 *  running
 */
struct FSUI_UnindexList *
FSUI_startUnindex (struct FSUI_Context *ctx, const char *filename)
{
  FSUI_UnindexList *utc;

  if (YES == disk_directory_test (ctx->ectx, filename))
    {
      GE_BREAK (ctx->ectx, 0);
      return NULL;
    }
  if (YES != disk_file_test (ctx->ectx, filename))
    {
      GE_BREAK (ctx->ectx, 0);
      return NULL;
    }
  utc = MALLOC (sizeof (FSUI_UnindexList));
  utc->ctx = ctx;
  utc->filename = STRDUP (filename);
  utc->start_time = get_time ();
  utc->state = FSUI_ACTIVE;
  utc->handle = PTHREAD_CREATE (&FSUI_unindexThreadEvent, utc, 32 * 1024);
  if (utc->handle == NULL)
    {
      GE_LOG_STRERROR (ctx->ectx,
                       GE_ERROR | GE_ADMIN | GE_USER | GE_IMMEDIATE,
                       "PTHREAD_CREATE");
      FREE (utc->filename);
      FREE (utc);
      return NULL;
    }
  MUTEX_LOCK (ctx->lock);
  utc->next = ctx->unindexOperations;
  ctx->unindexOperations = utc;
  MUTEX_UNLOCK (ctx->lock);
  return utc;
}


/**
 * Abort a deletion operation.
 *
 * @return SYSERR if no such unindex is pending
 */
int
FSUI_abortUnindex (struct FSUI_Context *ctx, struct FSUI_UnindexList *ul)
{
  if ((ul->state != FSUI_ACTIVE) && (ul->state != FSUI_PENDING))
    return NO;
  if (ul->state == FSUI_ACTIVE)
    {
      ul->state = FSUI_ABORTED;
      PTHREAD_STOP_SLEEP (ul->handle);
    }
  else
    {
      ul->state = FSUI_ABORTED_JOINED;
    }
  return OK;
}


/**
 * Stop a deletion operation.
 *
 * @return SYSERR if no such unindex is pending
 */
int
FSUI_stopUnindex (struct FSUI_Context *ctx, struct FSUI_UnindexList *dl)
{
  FSUI_UnindexList *prev;
  struct GE_Context *ectx;
  void *unused;
  FSUI_Event event;

  ectx = ctx->ectx;
  if (dl == NULL)
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
#if 0
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER, "FSUI_stopUnindex called.\n");
#endif
  MUTEX_LOCK (ctx->lock);
  prev = ctx->unindexOperations;
  while ((prev != dl) && (prev != NULL) && (prev->next != dl))
    prev = prev->next;
  if (prev == NULL)
    {
      MUTEX_UNLOCK (ctx->lock);
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "FSUI_stopUnindex failed to locate deletion operation.\n");
      return SYSERR;
    }
  if (prev == dl)
    {
      ctx->unindexOperations = dl->next;
    }
  else
    {
      prev->next = dl->next;
    }
  MUTEX_UNLOCK (ctx->lock);
  if ((dl->state == FSUI_ACTIVE) ||
      (dl->state == FSUI_COMPLETED) ||
      (dl->state == FSUI_ABORTED) || (dl->state == FSUI_ERROR))
    {
      GE_ASSERT (ctx->ectx, dl->handle != NULL);
      PTHREAD_JOIN (dl->handle, &unused);
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
  event.type = FSUI_unindex_stopped;
  event.data.UnindexStopped.uc.pos = dl;
  event.data.UnindexStopped.uc.cctx = dl->cctx;
  dl->ctx->ecb (dl->ctx->ecbClosure, &event);
  FREE (dl->filename);
  FREE (dl);
  return OK;
}

/* end of unindex.c */
