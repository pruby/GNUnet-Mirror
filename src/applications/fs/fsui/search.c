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
 *   (ANDing and ORing) and confirming if files are present in the
 *   network.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_uritrack_lib.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_pseudonym_lib.h"
#include "fsui.h"

#define DEBUG_SEARCH GNUNET_NO


/**
 * Pass the result to the client and note it as shown.
 */
static void
processResult (struct GNUNET_FSUI_SearchList *ctx,
               struct SearchResultList *pos, int update)
{
  GNUNET_FSUI_Event event;

  if (update)
    {
      event.type = GNUNET_FSUI_search_update;
      event.data.SearchUpdate.sc.pos = ctx;
      event.data.SearchUpdate.sc.cctx = ctx->cctx;
      event.data.SearchUpdate.fi = pos->fi;
      event.data.SearchUpdate.searchURI = ctx->uri;
      event.data.SearchUpdate.availability_rank =
        pos->probeSuccess - pos->probeFailure;
      event.data.SearchUpdate.availability_certainty =
        pos->probeSuccess + pos->probeFailure;
      event.data.SearchUpdate.applicability_rank = pos->matchingSearchCount;
    }
  else
    {
      event.type = GNUNET_FSUI_search_result;
      event.data.SearchResult.sc.pos = ctx;
      event.data.SearchResult.sc.cctx = ctx->cctx;
      event.data.SearchResult.fi = pos->fi;
      event.data.SearchResult.searchURI = ctx->uri;
      GNUNET_URITRACK_add_state (ctx->ctx->ectx,
                                 ctx->ctx->cfg, pos->fi.uri,
                                 GNUNET_URITRACK_SEARCH_RESULT);
    }
  ctx->ctx->ecb (ctx->ctx->ecbClosure, &event);
}

/**
 * Process results found by ECRS.
 */
int
GNUNET_FSUI_search_progress_callback (const GNUNET_ECRS_FileInfo * fi,
                                      const GNUNET_HashCode * key,
                                      int isRoot, void *cls)
{
  GNUNET_FSUI_SearchList *pos = cls;
  unsigned int i;
  struct GNUNET_GE_Context *ectx;
  struct SearchResultList *srl;
  struct SearchRecordList *rec;
  int update;
  GNUNET_HashCode nsid;

  ectx = pos->ctx->ectx;
  GNUNET_URITRACK_track (ectx, pos->ctx->cfg, fi);
  if (isRoot)
    {
      GNUNET_NS_namespace_set_root (ectx, pos->ctx->cfg, fi->uri);
      GNUNET_ECRS_uri_get_namespace_from_sks (fi->uri, &nsid);
      GNUNET_PSEUDO_add (ectx, pos->ctx->cfg, &nsid, fi->meta);
      return GNUNET_OK;
    }
  GNUNET_mutex_lock (pos->lock);
  srl = pos->resultsReceived;
  while (srl != NULL)
    {
      if (GNUNET_ECRS_uri_test_equal (fi->uri, srl->fi.uri))
        {
          for (i = 0; i < srl->matchingSearchCount; i++)
            {
              if ((GNUNET_ECRS_uri_test_sks (pos->uri)) ||
                  (0 == memcmp (key,
                                &srl->matchingSearches[i]->key,
                                sizeof (GNUNET_HashCode))))
                {
#if DEBUG_SEARCH
                  fprintf (stderr,
                           "Received search result that I have seen before.\n");
#endif
                  GNUNET_mutex_unlock (pos->lock);
                  return GNUNET_OK;     /* seen before */
                }
            }
          /* not seen before, find corresponding search! */
          rec = pos->searches;
          while ((rec != NULL) &&
                 (0 != memcmp (key, &rec->key, sizeof (GNUNET_HashCode))))
            rec = rec->next;
          if (rec == NULL)
            {
              GNUNET_GE_BREAK (NULL, 0);
              GNUNET_mutex_unlock (pos->lock);
              return GNUNET_OK; /* should have matching search */
            }
          GNUNET_array_append (srl->matchingSearches,
                               srl->matchingSearchCount, rec);
          if (rec->is_required)
            {
              if (srl->mandatoryMatchesRemaining > 0)
                srl->mandatoryMatchesRemaining--;
              else
                GNUNET_GE_BREAK (NULL, 0);
              update = 0;
#if DEBUG_SEARCH
              fprintf (stderr, "Received mandatory search result\n");
#endif
            }
          else
            {
              update = 1;
#if DEBUG_SEARCH
              fprintf (stderr, "Received optional search result\n");
#endif
            }
          if (srl->mandatoryMatchesRemaining == 0)
            {
#if DEBUG_SEARCH
              fprintf (stderr, "Passing result to client\n");
#endif
              processResult (pos, srl, update);
            }
          GNUNET_mutex_unlock (pos->lock);
          return GNUNET_OK;
        }
      srl = srl->next;
    }
  /* new result */
  rec = pos->searches;
  while ((rec != NULL) &&
         (!GNUNET_ECRS_uri_test_sks (pos->uri)) &&
         (0 != memcmp (key, &rec->key, sizeof (GNUNET_HashCode))))
    rec = rec->next;
  if (rec == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_mutex_unlock (pos->lock);
      return GNUNET_OK;         /* should have matching search */
    }
  srl = GNUNET_malloc (sizeof (struct SearchResultList));
  memset (srl, 0, sizeof (struct SearchResultList));
  GNUNET_array_append (srl->matchingSearches, srl->matchingSearchCount, rec);
  srl->fi.meta = GNUNET_ECRS_meta_data_duplicate (fi->meta);
  srl->fi.uri = GNUNET_ECRS_uri_duplicate (fi->uri);
  srl->mandatoryMatchesRemaining = pos->mandatory_keyword_count;
  if (rec->is_required)
    {
      if (srl->mandatoryMatchesRemaining > 0)
        srl->mandatoryMatchesRemaining--;
      else
        GNUNET_GE_BREAK (NULL, 0);
#if DEBUG_SEARCH
      fprintf (stderr, "Received new mandatory result\n");
#endif
    }
  else
    {
#if DEBUG_SEARCH
      fprintf (stderr, "Received new optional result\n");
#endif
    }
  srl->next = pos->resultsReceived;
  pos->resultsReceived = srl;
  if (srl->mandatoryMatchesRemaining == 0)
    {
#if DEBUG_SEARCH
      fprintf (stderr, "Passing new result to client\n");
#endif
      processResult (pos, srl, 0);
    }
  GNUNET_mutex_unlock (pos->lock);
  return GNUNET_OK;
}

/**
 * This function is called on each keyword in the
 * search list.  Start the corresponding ECRS search.
 *
 * @param closure our GNUNET_FSUI_SearchList.
 */
static int
create_ecrs_search (const char *keyword, int is_mandatory, void *closure)
{
  struct GNUNET_FSUI_SearchList *pos = closure;
  struct SearchRecordList *srl;

#if DEBUG_SEARCH
  fprintf (stderr, "Starting search for `%s' (%d)\n", keyword, is_mandatory);
#endif
  srl = GNUNET_malloc (sizeof (struct SearchRecordList));
  memset (srl, 0, sizeof (struct SearchRecordList));
  srl->uri = GNUNET_ECRS_keyword_command_line_to_uri (pos->ctx->ectx,
                                                      1, &keyword);
  GNUNET_hash (keyword, strlen (keyword), &srl->key);
  srl->is_required = is_mandatory;
  if (is_mandatory)
    pos->mandatory_keyword_count++;
  srl->next = pos->searches;
  pos->searches = srl;
  srl->search =
    GNUNET_ECRS_search_start (pos->ctx->ectx,
                              pos->ctx->cfg,
                              srl->uri,
                              pos->anonymityLevel,
                              &GNUNET_FSUI_search_progress_callback, pos);
  if (srl->search == NULL)
    {
      GNUNET_ECRS_uri_destroy (srl->uri);
      pos->searches = srl->next;
      GNUNET_free (srl);
      pos->start_time = 0;      /* flag to indicate error */
      return GNUNET_SYSERR;
    }
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
  struct SearchRecordList *srl;

  if (!(GNUNET_ECRS_uri_test_ksk (uri) || GNUNET_ECRS_uri_test_sks (uri)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;
    }
  ectx = ctx->ectx;
  pos = GNUNET_malloc (sizeof (GNUNET_FSUI_SearchList));
  memset (pos, 0, sizeof (GNUNET_FSUI_SearchList));
  pos->state = GNUNET_FSUI_ACTIVE;
  pos->anonymityLevel = anonymityLevel;
  pos->ctx = ctx;
  pos->start_time = GNUNET_get_time ();
  pos->uri = GNUNET_ECRS_uri_duplicate (uri);
  pos->lock = GNUNET_mutex_create (GNUNET_NO);
  event.type = GNUNET_FSUI_search_started;
  event.data.SearchStarted.sc.pos = pos;
  event.data.SearchStarted.sc.cctx = NULL;
  event.data.SearchStarted.searchURI = pos->uri;
  event.data.SearchStarted.anonymityLevel = pos->anonymityLevel;
  pos->cctx = pos->ctx->ecb (pos->ctx->ecbClosure, &event);
  GNUNET_mutex_lock (pos->lock);
  if (GNUNET_ECRS_uri_test_ksk (uri))
    {
      /* (possibly boolean) keyword search */
      GNUNET_ECRS_uri_get_keywords_from_ksk (uri, &create_ecrs_search, pos);
      if (pos->start_time == 0)
        {
          /* failed to start ECRS searches */
          while (pos->searches != NULL)
            {
              srl = pos->searches;
              pos->searches = srl->next;
              GNUNET_ECRS_search_stop (srl->search);
              GNUNET_ECRS_uri_destroy (srl->uri);
              GNUNET_free (srl);
            }
        }
    }
  else
    {
      /* Namespace search, only one ECRS search */
      srl = GNUNET_malloc (sizeof (struct SearchRecordList));
      memset (srl, 0, sizeof (struct SearchRecordList));
      srl->uri = GNUNET_ECRS_uri_duplicate (uri);
      srl->search = GNUNET_ECRS_search_start (pos->ctx->ectx,
                                              pos->ctx->cfg,
                                              pos->uri,
                                              pos->anonymityLevel,
                                              &GNUNET_FSUI_search_progress_callback,
                                              pos);
      if (srl->search == NULL)
        {
          GNUNET_ECRS_uri_destroy (srl->uri);
          GNUNET_free (srl);
        }
      else
        {
          pos->searches = srl;
        }
    }
  if (pos->searches == NULL)
    {
      /* failed to initiate searches */
      event.type = GNUNET_FSUI_search_stopped;
      event.data.SearchStopped.sc.pos = pos;
      event.data.SearchStopped.sc.cctx = NULL;
      pos->cctx = pos->ctx->ecb (pos->ctx->ecbClosure, &event);
      GNUNET_ECRS_uri_destroy (pos->uri);
      GNUNET_mutex_unlock (pos->lock);
      GNUNET_mutex_destroy (pos->lock);
      GNUNET_free (pos);
      return NULL;
    }
  GNUNET_mutex_unlock (pos->lock);
  /* success, add to FSUI state */
  GNUNET_mutex_lock (ctx->lock);
  pos->next = ctx->activeSearches;
  ctx->activeSearches = pos;
  GNUNET_mutex_unlock (ctx->lock);
  return pos;
}

/**
 * Abort a search.
 */
int
GNUNET_FSUI_search_abort (struct GNUNET_FSUI_SearchList *sl)
{
  GNUNET_FSUI_Event event;
  struct SearchRecordList *rec;
  struct SearchResultList *srl;
  struct GNUNET_FSUI_Context *ctx;

  ctx = sl->ctx;
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
  sl->state = GNUNET_FSUI_ABORTED_JOINED;
  GNUNET_mutex_unlock (ctx->lock);
  /* must not hold lock while stopping ECRS searches! */
  while (sl->searches != NULL)
    {
      rec = sl->searches;
      GNUNET_ECRS_search_stop (rec->search);
      sl->searches = rec->next;
      GNUNET_ECRS_uri_destroy (rec->uri);
      GNUNET_free (rec);
    }
  /* clean up a bit more: we don't need matchingSearches
     anymore, and the pointers are now invalid! */
  GNUNET_mutex_lock (ctx->lock);
  srl = sl->resultsReceived;
  while (srl != NULL)
    {
      GNUNET_array_grow (srl->matchingSearches, srl->matchingSearchCount, 0);
      if (srl->test_download != NULL)
        {
          GNUNET_ECRS_file_download_partial_stop (srl->test_download);
          srl->test_download = NULL;
          ctx->active_probes--;
        }
      srl = srl->next;
    }
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
GNUNET_FSUI_search_pause (struct GNUNET_FSUI_SearchList *sl)
{
  GNUNET_FSUI_Event event;
  struct SearchRecordList *rec;
  struct SearchResultList *srl;
  struct GNUNET_FSUI_Context *ctx;

  ctx = sl->ctx;
  GNUNET_mutex_lock (ctx->lock);
  if (sl->state != GNUNET_FSUI_ACTIVE)
    {
      GNUNET_mutex_unlock (ctx->lock);
      return GNUNET_SYSERR;
    }
  sl->state = GNUNET_FSUI_PAUSED;
  GNUNET_mutex_unlock (ctx->lock);
  /* must not hold lock while stopping ECRS searches */
  rec = sl->searches;
  while (rec != NULL)
    {
      if (rec->search != NULL)
        GNUNET_ECRS_search_stop (rec->search);
      rec->search = NULL;
      rec = rec->next;
    }
  GNUNET_mutex_lock (ctx->lock);
  srl = sl->resultsReceived;
  while (srl != NULL)
    {
      if (srl->test_download != NULL)
        {
          GNUNET_ECRS_file_download_partial_stop (srl->test_download);
          srl->test_download = NULL;
          ctx->active_probes--;
        }
      srl = srl->next;
    }
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
GNUNET_FSUI_search_restart (struct GNUNET_FSUI_SearchList *pos)
{
  GNUNET_FSUI_Event event;
  struct SearchRecordList *rec;
  struct GNUNET_FSUI_Context *ctx;

  ctx = pos->ctx;
  GNUNET_mutex_lock (ctx->lock);
  pos->state = GNUNET_FSUI_ACTIVE;
  event.type = GNUNET_FSUI_search_restarted;
  event.data.SearchStarted.sc.pos = pos;
  event.data.SearchStarted.sc.cctx = pos->cctx;
  pos->ctx->ecb (pos->ctx->ecbClosure, &event);
  rec = pos->searches;
  while (rec != NULL)
    {
      rec->search = GNUNET_ECRS_search_start (pos->ctx->ectx,
                                              pos->ctx->cfg,
                                              rec->uri,
                                              pos->anonymityLevel,
                                              &GNUNET_FSUI_search_progress_callback,
                                              pos);
      if (rec->search == NULL)
        break;
      rec = rec->next;
    }
  if (rec != NULL)
    {
      /* failed to restart, auto-pause again */
      GNUNET_FSUI_search_pause (pos);
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
GNUNET_FSUI_search_stop (struct GNUNET_FSUI_SearchList *sl)
{
  GNUNET_FSUI_Event event;
  GNUNET_FSUI_SearchList *pos;
  GNUNET_FSUI_SearchList *prev;
  int i;
  struct SearchRecordList *rec;
  struct SearchResultList *srl;
  struct GNUNET_FSUI_Context *ctx;

  ctx = sl->ctx;
  GNUNET_mutex_lock (ctx->lock);
  if (sl->state == GNUNET_FSUI_ACTIVE)
    GNUNET_FSUI_search_abort (sl);
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
  while (sl->searches != NULL)
    {
      rec = sl->searches;
      sl->searches = rec->next;
      if (rec->search != NULL)
        {
          GNUNET_GE_BREAK (ctx->ectx, 0);
          GNUNET_ECRS_search_stop (rec->search);
          rec->search = NULL;
        }
      GNUNET_ECRS_uri_destroy (rec->uri);
      GNUNET_free (rec);
    }
  event.type = GNUNET_FSUI_search_stopped;
  event.data.SearchStopped.sc.pos = pos;
  event.data.SearchStopped.sc.cctx = pos->cctx;
  pos->ctx->ecb (pos->ctx->ecbClosure, &event);
  GNUNET_ECRS_uri_destroy (pos->uri);
  while (sl->resultsReceived != NULL)
    {
      srl = sl->resultsReceived;
      sl->resultsReceived = srl->next;
      GNUNET_array_grow (srl->matchingSearches, srl->matchingSearchCount, 0);
      GNUNET_ECRS_uri_destroy (srl->fi.uri);
      GNUNET_ECRS_meta_data_destroy (srl->fi.meta);
      if (srl->test_download != NULL)
        {
          GNUNET_ECRS_file_download_partial_stop (srl->test_download);
          ctx->active_probes--;
        }
      GNUNET_free (srl);
    }
  GNUNET_mutex_destroy (pos->lock);
  GNUNET_free (pos);
  return GNUNET_OK;
}

/* end of search.c */
