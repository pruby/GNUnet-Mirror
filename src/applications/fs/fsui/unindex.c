/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
#include "gnunet_ecrs_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

/**
 * Context for the unindex thread.
 */
typedef struct {
  char * filename;
  FSUI_ThreadList * tl;
  FSUI_Context * ctx;
  cron_t start_time;
} UnindexThreadClosure;

/**
 * Transform an ECRS progress callback into an FSUI event.
 */
static void progressCallback(unsigned long long totalBytes,
			     unsigned long long completedBytes,
			     cron_t eta,
			     UnindexThreadClosure * utc) {
  FSUI_Event event;

  event.type = FSUI_unindex_progress;
  event.data.UnindexProgress.completed = completedBytes;
  event.data.UnindexProgress.total = totalBytes;
  event.data.UnindexProgress.filename = utc->filename;
  event.data.UnindexProgress.start_time = utc->start_time;
  event.data.UnindexProgress.eta = eta;
  utc->ctx->ecb(utc->ctx->ecbClosure,
		&event);
}

/**
 * Thread that does the unindex.
 */
static void * unindexThread(UnindexThreadClosure * utc) {
  FSUI_Event event;
  int ret;

  ret = ECRS_unindexFile(utc->filename,
			 (ECRS_UploadProgressCallback) &progressCallback,
			 utc,
			 NULL,
			 NULL);
  if (ret == OK) {
    event.type = FSUI_unindex_complete;
    if (OK != getFileSize(utc->filename,
			  &event.data.UnindexComplete.total)) {
      BREAK();
      event.data.UnindexComplete.total = 0;
    }
    event.data.UnindexComplete.filename = utc->filename;
    event.data.UnindexComplete.start_time = utc->start_time;
  } else {
    event.type = FSUI_unindex_error;
    event.data.message = _("Unindex failed.");
  }
  utc->ctx->ecb(utc->ctx->ecbClosure,
		&event);
  FREE(utc->filename);
  utc->tl->isDone = YES;
  FREE(utc);
  LOG(LOG_DEBUG,
      "FSUI unindexThread exits.\n");
  return NULL;
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
int FSUI_unindex(struct FSUI_Context * ctx,
		 const char * filename) {
  FSUI_ThreadList * tl;
  UnindexThreadClosure * utc;

  if (YES == isDirectory(filename)) {
    BREAK();
    return SYSERR;
  }
  utc = MALLOC(sizeof(UnindexThreadClosure));
  utc->ctx = ctx;
  utc->filename = STRDUP(filename);
  cronTime(&utc->start_time);
  tl = MALLOC(sizeof(FSUI_ThreadList));
  utc->tl = tl;
  tl->isDone = NO;
  if (0 != PTHREAD_CREATE(&tl->handle,
			  (PThreadMain) &unindexThread,
			  utc,
			  32 * 1024)) {
    LOG_STRERROR(LOG_ERROR, "PTHREAD_CREATE");
    FREE(tl);
    FREE(utc->filename);
    FREE(utc);
    return SYSERR;
  }
  MUTEX_LOCK(&ctx->lock);
  tl->next = ctx->activeThreads;
  ctx->activeThreads = tl;
  MUTEX_UNLOCK(&ctx->lock);
  cleanupFSUIThreadList(ctx);
  return OK;
}

/* end of unindex.c */
