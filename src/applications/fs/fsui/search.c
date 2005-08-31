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

#define DEBUG_SEARCH NO

/* must match namespace_info.c */
#define NS_ROOTS "data" DIR_SEPARATOR_STR "namespace-root" DIR_SEPARATOR_STR

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

  event.type = FSUI_search_result;
  event.data.SearchResult.fi = *fi;
  event.data.SearchResult.searchURI = pos->uri;
  pos->ctx->ecb(pos->ctx->ecbClosure,
		&event);
}

static void setNamespaceRoot(const ECRS_FileInfo * fi) {
  char * fn;
  char * fnBase;
  HashCode512 ns;
  char * name;

  if (OK != ECRS_getNamespaceId(fi->uri,
				&ns)) {
    BREAK();
    return;
  }
  name = ECRS_getNamespaceName(&ns);
  fn = getConfigurationString("GNUNET", "GNUNET_HOME");
  fnBase = expandFileName(fn);
  FREE(fn);
  fn = MALLOC(strlen(fnBase) +
	      strlen(NS_ROOTS) +
	      strlen(name) +
	      6);
  strcpy(fn, fnBase);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, NS_ROOTS);
  mkdirp(fn);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, name);
  FREE(name);
  FREE(fnBase);
  if (OK == ECRS_getSKSContentHash(fi->uri,
				   &ns)) {
    writeFile(fn,
	      &ns,
	      sizeof(HashCode512),
	      "644");
  }
  FREE(fn);
}

/**
 * Process results found by ECRS.
 */
static int spcb(const ECRS_FileInfo * fi,
		const HashCode512 * key,
		int isRoot,
		void * cls) {
  FSUI_SearchList * pos = cls;
  unsigned int i;
  unsigned int j;
  ResultPending * rp;

  FSUI_trackURI(fi);
  if (isRoot) {
    setNamespaceRoot(fi);
    FSUI_addNamespaceInfo(fi->uri,
			  fi->meta);
    return OK;
  }
  for (i=0;i<pos->sizeResultsReceived;i++)
    if (ECRS_equalsUri(fi->uri,
		       pos->resultsReceived[i].uri)) {
#if DEBUG_SEARCH
      LOG(LOG_DEBUG,
	  "Received search result that I have seen before.\n");
#endif
      return OK; /* seen before */
    }
  if (pos->numberOfURIKeys > 1) {
    if (key == NULL) {
      BREAK();
#if DEBUG_SEARCH
      LOG(LOG_DEBUG,
	  "Received search result without key to decrypt.\n");
#endif
      return SYSERR;
    }
    for (i=0;i<pos->sizeUnmatchedResultsReceived;i++) {
      rp = &pos->unmatchedResultsReceived[i];
      if (ECRS_equalsUri(fi->uri,
			 rp->fi.uri)) {
	for (j=0;j<rp->matchingKeyCount;j++)
	  if (equalsHashCode512(key,
				&rp->matchingKeys[j])) {
#if DEBUG_SEARCH
	    LOG(LOG_DEBUG,
		"Received search result that I have seen before (missing keyword to show client).\n");
#endif
	    return OK;
	  }
	if (rp->matchingKeyCount + 1 == pos->numberOfURIKeys) {
#if DEBUG_SEARCH
	  LOG(LOG_DEBUG,
	      "Received search result (showing client)!\n");
#endif
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
#if DEBUG_SEARCH
	  LOG(LOG_DEBUG,
	      "Received search result (waiting for more %u keys before showing client).\n",
	      pos->numberOfURIKeys - rp->matchingKeyCount);
#endif
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
#if DEBUG_SEARCH
    LOG(LOG_DEBUG,
	"Received search result (waiting for %u more keys before showing client).\n",
	pos->numberOfURIKeys  - rp->matchingKeyCount);
#endif
    return OK;
  } else {
#if DEBUG_SEARCH
    LOG(LOG_DEBUG,
	"Received search result (showing client)!\n");
#endif
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

/**
 * Thread that searches for data.
 */
void * searchThread(FSUI_SearchList * pos) {
  ECRS_search(pos->uri,
	      pos->anonymityLevel,
	      cronTime(NULL) + cronYEARS, /* timeout!?*/
	      &spcb,
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
      LOG(LOG_ERROR,
	  _("This search is already pending!\n"));
      BREAK();
      MUTEX_UNLOCK(&ctx->lock);
      return SYSERR;
    }
    pos = pos->next;
  }
  pos = MALLOC(sizeof(FSUI_SearchList));
  pos->signalTerminate = NO;
  pos->uri = ECRS_dupUri(uri);
  pos->numberOfURIKeys = ECRS_countKeywordsOfUri(uri);
  pos->sizeResultsReceived = 0;
  pos->resultsReceived = NULL;
  pos->sizeUnmatchedResultsReceived = 0;
  pos->unmatchedResultsReceived = 0;
  pos->anonymityLevel = anonymityLevel;
  pos->ctx = ctx;
  if (0 != PTHREAD_CREATE(&pos->handle,
			  (PThreadMain) &searchThread,
			  pos,
			  32 * 1024)) {
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
