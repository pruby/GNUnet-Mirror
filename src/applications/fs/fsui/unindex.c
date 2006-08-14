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
 * Transform an ECRS progress callback into an FSUI event.
 */
static void progressCallback(unsigned long long totalBytes,
			     unsigned long long completedBytes,
			     cron_t eta,
			     void * cls) {
  FSUI_UnindexList * utc = cls;
  FSUI_Event event;

  event.type = FSUI_unindex_progress;
  event.data.UnindexProgress.completed = completedBytes;
  event.data.UnindexProgress.total = totalBytes;
  event.data.UnindexProgress.filename = utc->filename;
  event.data.UnindexProgress.eta = eta;
  utc->ctx->ecb(utc->ctx->ecbClosure,
		&event);
}

/**
 * Thread that does the unindex.
 */
static void * unindexThread(void * cls) {
  FSUI_UnindexList * utc = cls;
  FSUI_Event event;
  int ret;

  ret = ECRS_unindexFile(utc->ctx->ectx,
			 utc->ctx->cfg,
			 utc->filename,
			 &progressCallback,
			 utc,
			 NULL,
			 NULL);
  if (ret == OK) {
    event.type = FSUI_unindex_complete;
    if (OK != disk_file_size(utc->ctx->ectx,
			     utc->filename,
			     &event.data.UnindexComplete.total,
			     YES)) {
      GE_BREAK(utc->ctx->ectx, 0);
      event.data.UnindexComplete.total = 0;
    }
    event.data.UnindexComplete.filename = utc->filename;
  } else {
    event.type = FSUI_unindex_error;
    event.data.UnindexError.message = _("Unindex failed.");
  }
  utc->ctx->ecb(utc->ctx->ecbClosure,
		&event);
  FREE(utc->filename);
  FREE(utc);
  GE_LOG(utc->ctx->ectx, 
	 GE_DEBUG | GE_REQUEST | GE_USER,
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
struct FSUI_UnindexList *
FSUI_unindex(struct FSUI_Context * ctx,
	     const char * filename) {
  FSUI_UnindexList * utc;

  if (YES == disk_directory_test(ctx->ectx,
				 filename)) {
    GE_BREAK(ctx->ectx, 0);
    return NULL;
  }
  utc = MALLOC(sizeof(FSUI_UnindexList));
  utc->ctx = ctx;
  utc->filename = STRDUP(filename);
  utc->start_time = get_time();
  utc->handle = PTHREAD_CREATE(&unindexThread,
			       utc,
			       32 * 1024);
  if (utc->handle == NULL) {
    GE_LOG_STRERROR(ctx->ectx,
		    GE_ERROR | GE_ADMIN | GE_USER | GE_IMMEDIATE,
		    "PTHREAD_CREATE");
    FREE(utc->filename);
    FREE(utc);
    return NULL;
  }
  MUTEX_LOCK(ctx->lock);
  utc->next = ctx->unindexOperations;
  ctx->unindexOperations = utc;
  MUTEX_UNLOCK(ctx->lock);
  return utc;
}

/* end of unindex.c */
