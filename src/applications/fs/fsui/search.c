/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util_error_loggers.h"
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
processResult (const ECRS_FileInfo * fi, FSUI_SearchList * pos)
{
  FSUI_Event event;

  GNUNET_array_grow (pos->resultsReceived,
                     pos->sizeResultsReceived, pos->sizeResultsReceived + 1);
  pos->resultsReceived[pos->sizeResultsReceived - 1].uri
    = ECRS_dupUri (fi->uri);
  pos->resultsReceived[pos->sizeResultsReceived - 1].meta
    = ECRS_dupMetaData (fi->meta);

  event.type = FSUI_search_result;
  event.data.SearchResult.sc.pos = pos;
  event.data.SearchResult.sc.cctx = pos->cctx;
  event.data.SearchResult.fi = *fi;
  event.data.SearchResult.searchURI = pos->uri;
  pos->ctx->ecb (pos->ctx->ecbClosure, &event);
  URITRACK_addState (pos->ctx->ectx,
                     pos->ctx->cfg, pos->uri, URITRACK_SEARCH_RESULT);
}


/**
 * Process results found by ECRS.
 */
static int
spcb (const ECRS_FileInfo * fi,
      const GNUNET_HashCode * key, int isRoot, void *cls)
{
  FSUI_SearchList *pos = cls;
  unsigned int i;
  unsigned int j;
  ResultPending *rp;
  struct GE_Context *ectx;

  ectx = pos->ctx->ectx;

  URITRACK_trackURI (ectx, pos->ctx->cfg, fi);
  if (isRoot)
    {
      NS_setNamespaceRoot (ectx, pos->ctx->cfg, fi->uri);
      NS_addNamespaceInfo (ectx, pos->ctx->cfg, fi->uri, fi->meta);
      return GNUNET_OK;
    }
  for (i = 0; i < pos->sizeResultsReceived; i++)
    if (ECRS_equalsUri (fi->uri, pos->resultsReceived[i].uri))
      {
#if DEBUG_SEARCH
        GE_LOG (ectx,
                GE_DEBUG | GE_REQUEST | GE_USER,
                "Received search result that I have seen before.\n");
#endif
        return GNUNET_OK;       /* seen before */
      }
  if (pos->numberOfURIKeys > 1)
    {
      if (key == NULL)
        {
          GE_BREAK (ectx, 0);
#if DEBUG_SEARCH
          GE_LOG (ectx,
                  GE_DEBUG | GE_REQUEST | GE_USER,
                  "Received search result without key to decrypt.\n");
#endif
          return GNUNET_SYSERR;
        }
      for (i = 0; i < pos->sizeUnmatchedResultsReceived; i++)
        {
          rp = &pos->unmatchedResultsReceived[i];
          if (ECRS_equalsUri (fi->uri, rp->fi.uri))
            {
              for (j = 0; j < rp->matchingKeyCount; j++)
                if (0 == memcmp (key,
                                 &rp->matchingKeys[j],
                                 sizeof (GNUNET_HashCode)))
                  {
#if DEBUG_SEARCH
                    GE_LOG (ectx,
                            GE_DEBUG | GE_REQUEST | GE_USER,
                            "Received search result that I have seen before (missing keyword to show client).\n");
#endif
                    return GNUNET_OK;
                  }
              if (rp->matchingKeyCount + 1 == pos->numberOfURIKeys)
                {
#if DEBUG_SEARCH
                  GE_LOG (ectx,
                          GE_DEBUG | GE_REQUEST | GE_USER,
                          "Received search result (showing client)!\n");
#endif
                  GNUNET_array_grow (rp->matchingKeys, rp->matchingKeyCount,
                                     0);
                  processResult (&rp->fi, pos);
                  ECRS_freeUri (rp->fi.uri);
                  ECRS_freeMetaData (rp->fi.meta);
                  pos->unmatchedResultsReceived[i]
                    =
                    pos->unmatchedResultsReceived[pos->
                                                  sizeUnmatchedResultsReceived
                                                  - 1];
                  GNUNET_array_grow (pos->unmatchedResultsReceived,
                                     pos->sizeUnmatchedResultsReceived,
                                     pos->sizeUnmatchedResultsReceived - 1);
                  return GNUNET_OK;
                }
              else
                {
                  GNUNET_array_grow (rp->matchingKeys,
                                     rp->matchingKeyCount,
                                     rp->matchingKeyCount + 1);
                  rp->matchingKeys[rp->matchingKeyCount - 1] = *key;
#if DEBUG_SEARCH
                  GE_LOG (ectx,
                          GE_DEBUG | GE_REQUEST | GE_USER,
                          "Received search result (waiting for more %u keys before showing client).\n",
                          pos->numberOfURIKeys - rp->matchingKeyCount);
#endif
                  return GNUNET_OK;
                }
            }
        }
      GNUNET_array_grow (pos->unmatchedResultsReceived,
                         pos->sizeUnmatchedResultsReceived,
                         pos->sizeUnmatchedResultsReceived + 1);
      rp =
        &pos->unmatchedResultsReceived[pos->sizeUnmatchedResultsReceived - 1];
      rp->fi.meta = ECRS_dupMetaData (fi->meta);
      rp->fi.uri = ECRS_dupUri (fi->uri);
      rp->matchingKeys = NULL;
      rp->matchingKeyCount = 0;
      GNUNET_array_grow (rp->matchingKeys, rp->matchingKeyCount, 1);
      rp->matchingKeys[0] = *key;
#if DEBUG_SEARCH
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "Received search result (waiting for %u more keys before showing client).\n",
              pos->numberOfURIKeys - rp->matchingKeyCount);
#endif
      return GNUNET_OK;
    }
  else
    {
#if DEBUG_SEARCH
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "Received search result (showing client)!\n");
#endif
      processResult (fi, pos);
    }
  return GNUNET_OK;
}

static int
testTerminate (void *cls)
{
  FSUI_SearchList *pos = cls;
  if ((pos->state == FSUI_ACTIVE) &&
      (pos->maxResults > pos->sizeResultsReceived))
    return GNUNET_OK;
  return GNUNET_SYSERR;
}

/**
 * Thread that searches for data.
 */
void *
FSUI_searchThread (void *cls)
{
  FSUI_SearchList *pos = cls;
  FSUI_Event event;
  int ret;
  struct GE_Memory *mem;
  struct GE_Context *ee;

  mem = GE_memory_create (2);
  ee = GE_create_context_memory (GE_USER | GE_ADMIN |
                                 GE_ERROR | GE_WARNING | GE_FATAL |
                                 GE_BULK | GE_IMMEDIATE, mem);
  ret = ECRS_search (ee,
                     pos->ctx->cfg,
                     pos->uri,
                     pos->anonymityLevel,
                     pos->timeout, &spcb, pos, &testTerminate, pos);
  if (ret != GNUNET_OK)
    {
      const char *error;

      pos->state = FSUI_ERROR;
      event.type = FSUI_search_error;
      event.data.SearchError.sc.pos = pos;
      event.data.SearchError.sc.cctx = pos->cctx;
      error = GE_memory_get (mem, 0);
      if (error == NULL)
        error = _("Error running search (no reason given).");
      event.data.SearchError.message = error;
      pos->ctx->ecb (pos->ctx->ecbClosure, &event);
    }
  else if (pos->state == FSUI_ABORTED)
    {
      event.type = FSUI_search_aborted;
      event.data.SearchAborted.sc.pos = pos;
      event.data.SearchAborted.sc.cctx = pos->cctx;
      pos->ctx->ecb (pos->ctx->ecbClosure, &event);
    }
  else if (pos->state == FSUI_ACTIVE)
    {
      pos->state = FSUI_COMPLETED;
      event.type = FSUI_search_completed;
      event.data.SearchCompleted.sc.pos = pos;
      event.data.SearchCompleted.sc.cctx = pos->cctx;
      pos->ctx->ecb (pos->ctx->ecbClosure, &event);
    }
  else
    {
      GE_ASSERT (NULL, pos->state == FSUI_PENDING);
      /* must be suspending */
    }
  GE_free_context (ee);
  GE_memory_free (mem);

  return NULL;
}

/**
 * Thread that searches for data (and signals startup).
 */
void *
FSUI_searchThreadSignal (void *cls)
{
  FSUI_SearchList *pos = cls;
  FSUI_Event event;

  event.type = FSUI_search_started;
  event.data.SearchStarted.sc.pos = pos;
  event.data.SearchStarted.sc.cctx = NULL;
  event.data.SearchStarted.searchURI = pos->uri;
  event.data.SearchStarted.anonymityLevel = pos->anonymityLevel;
  pos->cctx = pos->ctx->ecb (pos->ctx->ecbClosure, &event);
  return FSUI_searchThread (pos);
}

/**
 * Start a search.
 */
struct FSUI_SearchList *
FSUI_startSearch (struct FSUI_Context *ctx,
                  unsigned int anonymityLevel,
                  unsigned int maxResults,
                  GNUNET_CronTime timeout, const struct ECRS_URI *uri)
{
  FSUI_SearchList *pos;
  struct GE_Context *ectx;

  ectx = ctx->ectx;
  GNUNET_mutex_lock (ctx->lock);
  pos = GNUNET_malloc (sizeof (FSUI_SearchList));
  pos->maxResults = maxResults;
  pos->state = FSUI_ACTIVE;
  pos->uri = ECRS_dupUri (uri);
  pos->numberOfURIKeys = ECRS_countKeywordsOfUri (uri);
  pos->sizeResultsReceived = 0;
  pos->resultsReceived = NULL;
  pos->sizeUnmatchedResultsReceived = 0;
  pos->unmatchedResultsReceived = 0;
  pos->anonymityLevel = anonymityLevel;
  pos->ctx = ctx;
  pos->start_time = GNUNET_get_time ();
  pos->timeout = timeout;
  pos->handle =
    GNUNET_thread_create (&FSUI_searchThreadSignal, pos, 32 * 1024);
  if (pos->handle == NULL)
    {
      GE_LOG_STRERROR (ectx,
                       GE_ERROR | GE_IMMEDIATE | GE_USER | GE_ADMIN,
                       "PTHREAD_CREATE");
      ECRS_freeUri (pos->uri);
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
FSUI_abortSearch (struct FSUI_Context *ctx, struct FSUI_SearchList *sl)
{
  if (sl->state == FSUI_PENDING)
    {
      sl->state = FSUI_ABORTED_JOINED;
      return GNUNET_OK;
    }
  if (sl->state != FSUI_ACTIVE)
    return GNUNET_SYSERR;
  sl->state = FSUI_ABORTED;
  GNUNET_thread_stop_sleep (sl->handle);
  return GNUNET_OK;
}

/**
 * Stop a search.
 */
int
FSUI_stopSearch (struct FSUI_Context *ctx, struct FSUI_SearchList *sl)
{
  FSUI_Event event;
  FSUI_SearchList *pos;
  FSUI_SearchList *prev;
  void *unused;
  int i;

  GNUNET_mutex_lock (ctx->lock);
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
  if ((pos->state == FSUI_ACTIVE) ||
      (pos->state == FSUI_COMPLETED) ||
      (pos->state == FSUI_ABORTED) || (pos->state == FSUI_ERROR))
    {
      GE_ASSERT (ctx->ectx, pos->handle != NULL);
      GNUNET_thread_join (pos->handle, &unused);
      pos->handle = NULL;
      if (pos->state == FSUI_ACTIVE)
        pos->state = FSUI_PENDING;
      else
        pos->state++;           /* add _JOINED */
    }
  else
    {
      GE_ASSERT (ctx->ectx, pos->handle == NULL);
    }
  event.type = FSUI_search_stopped;
  event.data.SearchStopped.sc.pos = pos;
  event.data.SearchStopped.sc.cctx = pos->cctx;
  pos->ctx->ecb (pos->ctx->ecbClosure, &event);


  ECRS_freeUri (pos->uri);
  for (i = 0; i < pos->sizeResultsReceived; i++)
    {
      ECRS_freeUri (pos->resultsReceived[i].uri);
      ECRS_freeMetaData (pos->resultsReceived[i].meta);
    }
  GNUNET_array_grow (pos->resultsReceived, pos->sizeResultsReceived, 0);
  for (i = 0; i < pos->sizeUnmatchedResultsReceived; i++)
    {
      ECRS_freeUri (pos->unmatchedResultsReceived[i].fi.uri);
      ECRS_freeMetaData (pos->unmatchedResultsReceived[i].fi.meta);
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
