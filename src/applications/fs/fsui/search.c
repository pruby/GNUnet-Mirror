/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
#include "gnunet_protocols.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

/**
 * Pass the result to the client and note it as shown.
 */
static void processResult(const ECRS_FileInfo * fi,
			  FSUI_SearchList * pos) {
  FSUI_Event event;
  
  GROW(pos->resultsReceived,
       pos->sizeResultsReceived,
       pos->sizeResultsReceived+1);
  pos->resultsReceived[pos->sizeResultsReceived-1].uri
    = ECRS_dupUri(fi->uri);
  pos->resultsReceived[pos->sizeResultsReceived-1].meta
    = ECRS_dupMetaData(fi->meta);

  event.type = search_result;
  event.data.SearchResult.fi = *fi;
  event.data.SearchResult.searchURI = pos->uri;
  pos->ctx->ecb(pos->ctx->ecbClosure,
		&event);
}

/**
 * Process results found by ECRS.
 */
static int spcb(const ECRS_FileInfo * fi,
		const HashCode512 * key,
		FSUI_SearchList * pos) {
  unsigned int i;
  unsigned int j;
  ResultPending * rp;

  FSUI_trackURI(fi);
  for (i=0;i<pos->sizeResultsReceived;i++)
    if (ECRS_equalsUri(fi->uri,
		       pos->resultsReceived[i].uri))
      return OK; /* seen before */
  if (pos->numberOfURIKeys > 1) {
    if (key == NULL) {
      BREAK();
      return SYSERR;
    }
    for (i=0;i<pos->sizeUnmatchedResultsReceived;i++) {
      rp = &pos->unmatchedResultsReceived[i];
      if (ECRS_equalsUri(fi->uri,
			 rp->fi.uri)) {
	for (j=0;j<rp->matchingKeyCount;j++)
	  if (equalsHashCode512(key,
				&rp->matchingKeys[j]))
	    return OK;
	if (rp->matchingKeyCount + 1 < pos->numberOfURIKeys) {
	  GROW(rp->matchingKeys,
	       rp->matchingKeyCount,
	       0);
	  processResult(&rp->fi,
			pos);
	  ECRS_freeUri(rp->fi.uri);
	  ECRS_freeMetaData(rp->fi.meta);
	  pos->unmatchedResultsReceived[i] 
	    = pos->unmatchedResultsReceived[pos->sizeUnmatchedResultsReceived-1];
	  GROW(pos->unmatchedResultsReceived,
	       pos->sizeUnmatchedResultsReceived,
	       pos->sizeUnmatchedResultsReceived-1);
	  return OK;
	} else {
	  GROW(rp->matchingKeys,
	       rp->matchingKeyCount,
	       rp->matchingKeyCount+1);
	  rp->matchingKeys[rp->matchingKeyCount-1] = *key;
	  return OK;
	}	
      }
    }
    GROW(pos->unmatchedResultsReceived,
	 pos->sizeUnmatchedResultsReceived,
	 pos->sizeUnmatchedResultsReceived+1);
    rp = &pos->unmatchedResultsReceived[pos->sizeUnmatchedResultsReceived-1];
    rp->fi.meta = ECRS_dupMetaData(fi->meta);
    rp->fi.uri = ECRS_dupUri(fi->uri);
    rp->matchingKeys = NULL;
    rp->matchingKeyCount = 0;
    GROW(rp->matchingKeys,
	 rp->matchingKeyCount,
	 1);
    rp->matchingKeys[0] = *key;
    return OK;
  } else {
    processResult(fi,
		  pos);
  }
  return OK;
}

static int testTerminate(FSUI_SearchList * pos) {
  if (pos->signalTerminate == NO)
    return OK;
  else
    return SYSERR;
}

static void * searchThread(FSUI_SearchList * pos) {
  ECRS_search(pos->uri,
	      pos->anonymityLevel,
	      cronTime(NULL) + cronYEARS, /* timeout!?*/
	      (ECRS_SearchProgressCallback) &spcb,
	      pos,
	      (ECRS_TestTerminate) &testTerminate,
	      pos);
  return NULL;
}

/**
 * Start a search.
 */
int FSUI_startSearch(struct FSUI_Context * ctx,
		     unsigned int anonymityLevel,
		     const struct ECRS_URI * uri) {
  FSUI_SearchList * pos;

  MUTEX_LOCK(&ctx->lock);
  pos = ctx->activeSearches;
  while (pos != NULL) {
    if (ECRS_equalsUri(uri,
		       pos->uri)) {
      MUTEX_UNLOCK(&ctx->lock);
      return SYSERR;
    }
    pos = pos->next;
  }  
  pos = MALLOC(sizeof(FSUI_SearchList));
  pos->signalTerminate = NO;
  pos->uri = ECRS_dupUri(uri);
  pos->numberOfURIKeys = 1; /* FIXME! */
  pos->sizeResultsReceived = 0;
  pos->resultsReceived = NULL;
  pos->sizeUnmatchedResultsReceived = 0;
  pos->unmatchedResultsReceived = 0;
  pos->anonymityLevel = anonymityLevel;
  pos->ctx = ctx;
  if (0 != PTHREAD_CREATE(&pos->handle,
			  (PThreadMain) &searchThread,
			  pos,
			  16 * 1024)) {
    LOG_STRERROR(LOG_ERROR, "PTHREAD_CREATE");
    ECRS_freeUri(pos->uri);
    FREE(pos);
    MUTEX_UNLOCK(&ctx->lock);
    return SYSERR;
  }
  pos->next = ctx->activeSearches;
  ctx->activeSearches = pos;
  MUTEX_UNLOCK(&ctx->lock);
  return OK;
}

/**
 * Stop a search.
 */
int FSUI_stopSearch(struct FSUI_Context * ctx,
		    const struct ECRS_URI * uri) {
  FSUI_SearchList * pos;
  FSUI_SearchList * prev;
  void * unused;
  int i;

  prev = NULL;
  MUTEX_LOCK(&ctx->lock);
  pos = ctx->activeSearches;
  while (pos != NULL) {
    if (ECRS_equalsUri(uri,
		       pos->uri)) {
      pos->signalTerminate = YES;
      PTHREAD_JOIN(&pos->handle,
		   &unused);
      ECRS_freeUri(pos->uri);
      for (i=0;i<pos->sizeResultsReceived;i++) {
	ECRS_freeUri(pos->resultsReceived[i].uri);
	ECRS_freeMetaData(pos->resultsReceived[i].meta);
      }
      GROW(pos->resultsReceived,
	   pos->sizeResultsReceived,
	   0);
      for (i=0;i<pos->sizeResultsReceived;i++) {
	ECRS_freeUri(pos->unmatchedResultsReceived[i].fi.uri);
	ECRS_freeMetaData(pos->unmatchedResultsReceived[i].fi.meta);
	GROW(pos->unmatchedResultsReceived[i].matchingKeys,
	     pos->unmatchedResultsReceived[i].matchingKeyCount,
	     0);
      }     
      GROW(pos->unmatchedResultsReceived,
	   pos->sizeUnmatchedResultsReceived,
	   0);      
      if (prev == NULL)
	ctx->activeSearches = pos->next;
      else
	prev->next = pos->next;
      FREE(pos);      
      MUTEX_UNLOCK(&ctx->lock);
      return OK;
    }
    prev = pos;    
    pos = pos->next;
  }  
  MUTEX_UNLOCK(&ctx->lock);
  return SYSERR;
}

/**
 * List active searches.  Can also be used to obtain
 * search results that were already signaled earlier.
 */
int FSUI_listSearches(struct FSUI_Context * ctx,
		      FSUI_SearchIterator iter,
		      void * closure) {
  int ret;
  FSUI_SearchList * pos;

  ret = 0;
  MUTEX_LOCK(&ctx->lock);
  pos = ctx->activeSearches;
  while (pos != NULL) {
    if (iter != NULL) {
      if (OK != iter(closure,
		     pos->uri,
		     pos->anonymityLevel,
		     pos->sizeResultsReceived,
		     pos->resultsReceived)) {
	MUTEX_UNLOCK(&ctx->lock);
	return SYSERR;
      }
    }
    ret++;
    pos = pos->next;
  }  
  MUTEX_UNLOCK(&ctx->lock);
  return ret;
}

/* end of search.c */
