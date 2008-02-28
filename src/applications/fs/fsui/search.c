/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/search.c
 * @brief Helper functions for searching.  FSUI search performs the
 *   filtering of duplicate results as well as adding boolean search
 *   (ANDing).
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_uritrack_lib.h"
#include "gnunet_namespace_lib.h"
#include "fsui.h"

#define DEBUG_SEARCH GNUNET_NO

/**
 * Pass the result to the client and note it as shown.
 */
static void
processResult (const GNUNET_ECRS_FileInfo * fi, GNUNET_FSUI_SearchList * pos)
{
  GNUNET_FSUI_Event event;

  GNUNET_array_grow (pos->resultsReceived,
                     pos->sizeResultsReceived, pos->sizeResultsReceived + 1);
  pos->resultsReceived[pos->sizeResultsReceived - 1].uri
    = GNUNET_ECRS_uri_duplicate (fi->uri);
  pos->resultsReceived[pos->sizeResultsReceived - 1].meta
    = GNUNET_ECRS_meta_data_duplicate (fi->meta);

  event.type = GNUNET_FSUI_search_result;
  event.data.SearchResult.sc.pos = pos;
  event.data.SearchResult.sc.cctx = pos->cctx;
  event.data.SearchResult.fi = *fi;
  event.data.SearchResult.searchURI = pos->uri;
  pos->ctx->ecb (pos->ctx->ecbClosure, &event);
  GNUNET_URITRACK_add_state (pos->ctx->ectx,
                             pos->ctx->cfg, pos->uri,
                             GNUNET_URITRACK_SEARCH_RESULT);
}


/**
 * Process results found by ECRS.
 */
int
GNUNET_FSUI_search_progress_callback (const GNUNET_ECRS_FileInfo * fi,
                                      const GNUNET_HashCode * key, int isRoot,
                                      void *cls)
{
  GNUNET_FSUI_SearchList *pos = cls;
  unsigned int i;
  unsigned int j;
  ResultPending *rp;
  struct GNUNET_GE_Context *ectx;

  ectx = pos->ctx->ectx;

  GNUNET_URITRACK_track (ectx, pos->ctx->cfg, fi);
  if (isRoot)
    {
      GNUNET_NS_namespace_set_root (ectx, pos->ctx->cfg, fi->uri);
      GNUNET_NS_namespace_add_information (ectx, pos->ctx->cfg, fi->uri,
                                           fi->meta);
      return GNUNET_OK;
    }
  for (i = 0; i < pos->sizeResultsReceived; i++)
    if (GNUNET_ECRS_uri_test_equal (fi->uri, pos->resultsReceived[i].uri))
      {
#if DEBUG_SEARCH
        GNUNET_GE_LOG (ectx,
                       GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                       "Received search result that I have seen before.\n");
#endif
        return GNUNET_OK;       /* seen before */
      }
  if (pos->numberOfURIKeys == 1)
    {
#if DEBUG_SEARCH
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Received search result (showing client)!\n");
#endif
      processResult (fi, pos);
      return GNUNET_OK;
    }
  if (key == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
#if DEBUG_SEARCH
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Received search result without key to decrypt.\n");
#endif
      return GNUNET_SYSERR;
    }
  for (i = 0; i < pos->sizeUnmatchedResultsReceived; i++)
    {
      rp = &pos->unmatchedResultsReceived[i];
      if (!GNUNET_ECRS_uri_test_equal (fi->uri, rp->fi.uri))
        continue;
      for (j = 0; j < rp->matchingKeyCount; j++)
        if (0 == memcmp (key, &rp->matchingKeys[j], sizeof (GNUNET_HashCode)))
          {
#if DEBUG_SEARCH
            GNUNET_GE_LOG (ectx,
                           GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                           GNUNET_GE_USER,
                           "Received search result that I have seen before (missing keyword to show client).\n");
#endif
            return GNUNET_OK;
          }
      if (rp->matchingKeyCount + 1 == pos->numberOfURIKeys)
        {
#if DEBUG_SEARCH
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                         GNUNET_GE_USER,
                         "Received search result (showing client)!\n");
#endif
          GNUNET_array_grow (rp->matchingKeys, rp->matchingKeyCount, 0);
          processResult (&rp->fi, pos);
          GNUNET_ECRS_uri_destroy (rp->fi.uri);
          GNUNET_ECRS_meta_data_destroy (rp->fi.meta);
          pos->unmatchedResultsReceived[i]
            =
            pos->unmatchedResultsReceived[pos->
                                          sizeUnmatchedResultsReceived - 1];
          GNUNET_array_grow (pos->unmatchedResultsReceived,
                             pos->sizeUnmatchedResultsReceived,
                             pos->sizeUnmatchedResultsReceived - 1);
          return GNUNET_OK;
        }
      GNUNET_array_grow (rp->matchingKeys,
                         rp->matchingKeyCount, rp->matchingKeyCount + 1);
      rp->matchingKeys[rp->matchingKeyCount - 1] = *key;
#if DEBUG_SEARCH
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                     GNUNET_GE_USER,
                     "Received search result (waiting for more %u keys before showing client).\n",
                     pos->numberOfURIKeys - rp->matchingKeyCount);
#endif
      return GNUNET_OK;
    }
  GNUNET_array_grow (pos->unmatchedResultsReceived,
                     pos->sizeUnmatchedResultsReceived,
                     pos->sizeUnmatchedResultsReceived + 1);
  rp = &pos->unmatchedResultsReceived[pos->sizeUnmatchedResultsReceived - 1];
  rp->fi.meta = GNUNET_ECRS_meta_data_duplicate (fi->meta);
  rp->fi.uri = GNUNET_ECRS_uri_duplicate (fi->uri);
  rp->matchingKeys = NULL;
  rp->matchingKeyCount = 0;
  GNUNET_array_grow (rp->matchingKeys, rp->matchingKeyCount, 1);
  rp->matchingKeys[0] = *key;
#if DEBUG_SEARCH
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Received search result (waiting for %u more keys before showing client).\n",
                 pos->numberOfURIKeys - rp->matchingKeyCount);
#endif
  return GNUNET_OK;
}

/**
 * Start a search.
 */
struct GNUNET_FSUI_SearchList *
GNUNET_FSUI_search_start (struct GNUNET_FSUI_Context *ctx,
                          unsigned int anonymityLevel,
                          const struct GNUNET_ECRS_URI *uri)
{
  GNUNET_FSUI_SearchList *pos;
  struct GNUNET_GE_Context *ectx;
  GNUNET_FSUI_Event event;

  ectx = ctx->ectx;
  GNUNET_mutex_lock (ctx->lock);
  pos = GNUNET_malloc (sizeof (GNUNET_FSUI_SearchList));
  pos->state = GNUNET_FSUI_ACTIVE;
  pos->uri = GNUNET_ECRS_uri_duplicate (uri);
  pos->numberOfURIKeys = GNUNET_ECRS_uri_get_keyword_count_from_ksk (uri);
  pos->sizeResultsReceived = 0;
  pos->resultsReceived = NULL;
  pos->sizeUnmatchedResultsReceived = 0;
  pos->unmatchedResultsReceived = 0;
  pos->anonymityLevel = anonymityLevel;
  pos->ctx = ctx;
  pos->start_time = GNUNET_get_time ();
  event.type = GNUNET_FSUI_search_started;
  event.data.SearchStarted.sc.pos = pos;
  event.data.SearchStarted.sc.cctx = NULL;
  event.data.SearchStarted.searchURI = pos->uri;
  event.data.SearchStarted.anonymityLevel = pos->anonymityLevel;
  pos->cctx = pos->ctx->ecb (pos->ctx->ecbClosure, &event);
  pos->handle = GNUNET_ECRS_search_start (pos->ctx->ectx,
                                          pos->ctx->cfg,
                                          pos->uri,
                                          pos->anonymityLevel,
                                          &GNUNET_FSUI_search_progress_callback,
                                          pos);
  if (pos->handle == NULL)
    {
      GNUNET_ECRS_uri_destroy (pos->uri);
      GNUNET_free (pos);
      GNUNET_mutex_unlock (ctx->lock);
      return NULL;
    }
  pos->next = ctx->activeSearches;
  ctx->activeSearches = pos;
  GNUNET_mutex_unlock (ctx->lock);
  return pos;
}

/**
 * Abort a search.
 */
int
GNUNET_FSUI_search_abort (struct GNUNET_FSUI_Context *ctx,
                          struct GNUNET_FSUI_SearchList *sl)
{
  GNUNET_FSUI_Event event;

  GNUNET_mutex_lock (ctx->lock);
  if (sl->state == GNUNET_FSUI_PENDING)
    {
      sl->state = GNUNET_FSUI_ABORTED_JOINED;
      GNUNET_mutex_unlock (ctx->lock);
      return GNUNET_OK;
    }
  if (sl->state != GNUNET_FSUI_ACTIVE)
    {
      GNUNET_mutex_unlock (ctx->lock);
      return GNUNET_SYSERR;
    }
  GNUNET_ECRS_search_stop (sl->handle);
  sl->state = GNUNET_FSUI_ABORTED_JOINED;
  sl->handle = NULL;
  event.type = GNUNET_FSUI_search_aborted;
  event.data.SearchAborted.sc.pos = sl;
  event.data.SearchAborted.sc.cctx = sl->cctx;
  sl->ctx->ecb (sl->ctx->ecbClosure, &event);
  GNUNET_mutex_unlock (ctx->lock);
  return GNUNET_OK;
}

/**
 * Pause a search.
 */
int
GNUNET_FSUI_search_pause (struct GNUNET_FSUI_Context *ctx,
                          struct GNUNET_FSUI_SearchList *sl)
{
  GNUNET_FSUI_Event event;

  GNUNET_mutex_lock (ctx->lock);
  if (sl->state != GNUNET_FSUI_ACTIVE)
    {
      GNUNET_mutex_unlock (ctx->lock);
      return GNUNET_SYSERR;
    }
  GNUNET_ECRS_search_stop (sl->handle);
  sl->handle = NULL;
  sl->state = GNUNET_FSUI_PAUSED;
  event.type = GNUNET_FSUI_search_paused;
  event.data.SearchPaused.sc.pos = sl;
  event.data.SearchPaused.sc.cctx = sl->cctx;
  sl->ctx->ecb (sl->ctx->ecbClosure, &event);
  GNUNET_mutex_unlock (ctx->lock);
  return GNUNET_OK;
}

/**
 * Restart a paused search.
 */
int
GNUNET_FSUI_search_restart (struct GNUNET_FSUI_Context *ctx,
                            struct GNUNET_FSUI_SearchList *pos)
{
  GNUNET_FSUI_Event event;

  GNUNET_mutex_lock (ctx->lock);
  pos->state = GNUNET_FSUI_ACTIVE;
  event.type = GNUNET_FSUI_search_restarted;
  event.data.SearchStarted.sc.pos = pos;
  event.data.SearchStarted.sc.cctx = pos->cctx;
  pos->ctx->ecb (pos->ctx->ecbClosure, &event);
  pos->handle = GNUNET_ECRS_search_start (pos->ctx->ectx,
                                          pos->ctx->cfg,
                                          pos->uri,
                                          pos->anonymityLevel,
                                          &GNUNET_FSUI_search_progress_callback,
                                          pos);
  if (pos->handle == NULL)
    {
      pos->state = GNUNET_FSUI_PAUSED;
      GNUNET_mutex_unlock (ctx->lock);
      return GNUNET_SYSERR;
    }
  GNUNET_mutex_unlock (ctx->lock);
  return GNUNET_OK;
}

/**
 * Stop a search.
 */
int
GNUNET_FSUI_search_stop (struct GNUNET_FSUI_Context *ctx,
                         struct GNUNET_FSUI_SearchList *sl)
{
  GNUNET_FSUI_Event event;
  GNUNET_FSUI_SearchList *pos;
  GNUNET_FSUI_SearchList *prev;
  int i;

  GNUNET_mutex_lock (ctx->lock);
  if (sl->state == GNUNET_FSUI_ACTIVE)
    GNUNET_FSUI_search_abort (ctx, sl);
  prev = NULL;
  pos = ctx->activeSearches;
  while ((pos != sl) && (pos != NULL))
    {
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      GNUNET_mutex_unlock (ctx->lock);
      return GNUNET_SYSERR;
    }
  if (prev == NULL)
    ctx->activeSearches = pos->next;
  else
    prev->next = pos->next;
  for (i = 0; i < sl->my_downloads_size; i++)
    sl->my_downloads[i]->search = NULL;
  GNUNET_array_grow (sl->my_downloads, sl->my_downloads_size, 0);
  GNUNET_mutex_unlock (ctx->lock);
  pos->next = NULL;
  GNUNET_GE_ASSERT (ctx->ectx, pos->handle == NULL);
  event.type = GNUNET_FSUI_search_stopped;
  event.data.SearchStopped.sc.pos = pos;
  event.data.SearchStopped.sc.cctx = pos->cctx;
  pos->ctx->ecb (pos->ctx->ecbClosure, &event);
  GNUNET_ECRS_uri_destroy (pos->uri);
  for (i = 0; i < pos->sizeResultsReceived; i++)
    {
      GNUNET_ECRS_uri_destroy (pos->resultsReceived[i].uri);
      GNUNET_ECRS_meta_data_destroy (pos->resultsReceived[i].meta);
    }
  GNUNET_array_grow (pos->resultsReceived, pos->sizeResultsReceived, 0);
  for (i = 0; i < pos->sizeUnmatchedResultsReceived; i++)
    {
      GNUNET_ECRS_uri_destroy (pos->unmatchedResultsReceived[i].fi.uri);
      GNUNET_ECRS_meta_data_destroy (pos->unmatchedResultsReceived[i].fi.
                                     meta);
      GNUNET_array_grow (pos->unmatchedResultsReceived[i].matchingKeys,
                         pos->unmatchedResultsReceived[i].matchingKeyCount,
                         0);
    }
  GNUNET_array_grow (pos->unmatchedResultsReceived,
                     pos->sizeUnmatchedResultsReceived, 0);
  GNUNET_free (pos);
  return GNUNET_OK;
}

/* end of search.c */
