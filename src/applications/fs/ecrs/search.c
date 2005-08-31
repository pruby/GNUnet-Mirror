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
 * @file applications/fs/ecrs/search.c
 * @brief Helper functions for searching.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_fs_lib.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs_core.h"
#include "ecrs.h"

#define DEBUG_SEARCH NO

typedef struct {

  /**
   * The handle for the query.
   */
  struct FS_SEARCH_HANDLE * handle;

  /**
   * When does this query time-out (we may want
   * to refresh it at that point).
   */
  cron_t timeout;

  /**
   * What was the last time we transmitted
   * this query?
   */
  cron_t lastTransmission;

  /**
   * With which priority does the query run?
   */
  unsigned int priority;

  /**
   * What type of query is it?
   */
  unsigned int type;

  /**
   * How many keys are there?
   */
  unsigned int keyCount;

  /**
   * The keys (for the search).
   */
  HashCode512 * keys;

  /**
   * The key (for decryption)
   */
  HashCode512 decryptKey;

} PendingSearch;

/**
 * Context of the sendQueries cron-job.
 */
typedef struct {
  /**
   * Time when the cron-job was first started.
   */
  cron_t start;

  /**
   * What is the global timeout?
   */
  cron_t timeout;

  /**
   * Search context
   */
  struct FS_SEARCH_CONTEXT * sctx;

  /**
   * Number of queries running at the moment.
   */
  unsigned int queryCount;

  /**
   * queryCount pending searches.
   */
  PendingSearch ** queries;

  ECRS_SearchProgressCallback spcb;

  void * spcbClosure;

  int aborted;

  Mutex lock;

} SendQueriesContext;

/**
 * Add a query to the SQC.
 */
static void addPS(unsigned int type,
		  unsigned int keyCount,
		  const HashCode512 * keys,
		  const HashCode512 * dkey,
		  SendQueriesContext * sqc) {
  PendingSearch * ps;

  ps = MALLOC(sizeof(PendingSearch));
  ps->timeout = 0;
  ps->lastTransmission = 0;
  ps->priority = 5 + randomi(20);
  ps->type = type;
  ps->keyCount = keyCount;
  ps->keys = MALLOC(sizeof(HashCode512) * keyCount);
  memcpy(ps->keys,
	 keys,
	 sizeof(HashCode512) * keyCount);
  ps->decryptKey = *dkey;
  ps->handle = NULL;
  MUTEX_LOCK(&sqc->lock);
  GROW(sqc->queries,
       sqc->queryCount,
       sqc->queryCount+1);
  sqc->queries[sqc->queryCount-1] = ps;
  MUTEX_UNLOCK(&sqc->lock);
}

/**
 * Add the query that corresponds to the given URI
 * to the SQC.
 */
static void addQueryForURI(const struct ECRS_URI * uri,
			   SendQueriesContext * sqc) {
  switch (uri->type) {
  case chk:
    LOG(LOG_ERROR,
	_("CHK URI not allowed for search.\n"));
    break;
  case sks: {
    HashCode512 keys[2];
    HashCode512 hk; /* hk = hash(identifier) */

    hash(&uri->data.sks.identifier,
	 sizeof(HashCode512),
	 &hk);
    xorHashCodes(&hk,
		 &uri->data.sks.namespace,
		 &keys[0]); /* compute routing key r = H(identifier) ^ namespace */
    keys[1] = uri->data.sks.namespace;
    addPS(K_BLOCK,
	  2,
	  &keys[0],
	  &uri->data.sks.identifier,
	  sqc);
    break;
  }
  case ksk: {
    HashCode512 hc;
    HashCode512 query;
    struct PrivateKey * pk;
    PublicKey pub;
    int i;

#if DEBUG_SEARCH
    LOG(LOG_DEBUG,
	"Computing queries (this may take a while).\n");
#endif
    for (i=0;i<uri->data.ksk.keywordCount;i++) {
      hash(uri->data.ksk.keywords[i],
	   strlen(uri->data.ksk.keywords[i]),
	   &hc);
      pk = makeKblockKey(&hc);
      getPublicKey(pk,
		   &pub);
      hash(&pub,
	   sizeof(PublicKey),
	   &query);
      addPS(ANY_BLOCK, /* K_BLOCK, N_BLOCK or KN_BLOCK ok */
	    1,
	    &query,
	    &hc,
	    sqc);
      freePrivateKey(pk);
    }	
#if DEBUG_SEARCH
    LOG(LOG_DEBUG,
	"Queries ready.\n");
#endif
    break;
  }
  case loc:
    LOG(LOG_ERROR,
	_("LOC URI not allowed for search.\n"));
    break;
  default:
    BREAK();
    /* unknown URI type */
    break;
  }
}

/**
 * Compute the "current" ID of an updateable SBlock.  Will set the ID
 * of the sblock itself for non-updateable content, the ID of the next
 * identifier for sporadically updated SBlocks and the ID computed from
 * the timing function for periodically updated SBlocks.
 *
 * @param sb the SBlock (must be in plaintext)
 * @param now the time for which the ID should be computed
 * @param c the resulting current ID (set)
 */
static int computeIdAtTime(const SBlock * sb,
			   TIME_T now,
			   HashCode512 * c) {
  TIME_T pos;
  HashCode512 tmp;
  unsigned int iter;

  if (ntohl(sb->updateInterval) == SBLOCK_UPDATE_SPORADIC) {
    memcpy(c,
	   &sb->nextIdentifier,
	   sizeof(HashCode512));
    return OK;
  }
  if (ntohl(sb->updateInterval) == SBLOCK_UPDATE_NONE) {
    /* H(N-I)^S is the current routing key, so N-I = k */
    deltaId(&sb->identifierIncrement,
	    &sb->nextIdentifier,
	    c);
    return OK;
  }
  GNUNET_ASSERT(ntohl(sb->updateInterval) != 0);
  pos = ntohl(sb->creationTime);
  deltaId(&sb->identifierIncrement,
	  &sb->nextIdentifier,
	  c);

  iter = (now - (pos + ntohl(sb->updateInterval))) / ntohl(sb->updateInterval);
  if (iter > 0xFFFF)
    /* too many iterators, signal error! */
    return SYSERR;
  while (pos + ntohl(sb->updateInterval) < now) {
    pos += ntohl(sb->updateInterval);
    addHashCodes(c,
		 &sb->identifierIncrement,
		 &tmp);
    *c = tmp;
  }
  return OK;
}

/**
 * We found an NBlock.  Decode the meta-data and call the callback of
 * the SQC with the root-URI for the namespace, together with the
 * namespace advertisement.
 */
static int processNBlock(const NBlock * nb,
			 const HashCode512 * key,
			 unsigned int size,
			 SendQueriesContext * sqc) {
  ECRS_FileInfo fi;
  struct ECRS_URI uri;
  int ret;

  fi.meta = ECRS_deserializeMetaData((const char*)&nb[1],
				     size - sizeof(NBlock));
  if (fi.meta == NULL) {
    BREAK(); /* nblock malformed */
    return SYSERR;
  }
  fi.uri = &uri;
  uri.type = sks;
  uri.data.sks.namespace = nb->namespace;
  uri.data.sks.identifier = nb->rootEntry;
  if (sqc->spcb != NULL) {
    ret = sqc->spcb(&fi, key, YES, sqc->spcbClosure);
    if (ret == SYSERR)
      sqc->aborted = YES;
  } else
    ret = OK;
  ECRS_freeMetaData(fi.meta);
  return ret;
}

/**
 * Process replies received in response to our
 * queries.  Verifies, decrypts and passes valid
 * replies to the callback.
 *
 * @return SYSERR if the entry is malformed
 */
static int receiveReplies(const HashCode512 * key,
			  const Datastore_Value * value,
			  SendQueriesContext * sqc) {
  unsigned int type;
  ECRS_FileInfo fi;
  int i;
  unsigned int size;
  PendingSearch * ps;
  int ret;
  HashCode512 query;

  type = ntohl(value->type);
  size = ntohl(value->size) - sizeof(Datastore_Value);
#if DEBUG_SEARCH
  LOG(LOG_DEBUG,
      "Search received reply of type %u and size %u.\n",
      type, size);
#endif
  if (OK != getQueryFor(size,
			(const DBlock*) &value[1],
			&query))
    return SYSERR;
  for (i=0;i<sqc->queryCount;i++) {
    ps = sqc->queries[i];
    if ( equalsHashCode512(&query,
			   &ps->keys[0]) &&
	 ( (ps->type == type) ||
	   (ps->type == ANY_BLOCK) ) &&
	 (YES == isDatumApplicable(type,
				   size,
				   (const DBlock*) &value[1],
				   ps->keyCount,
				   ps->keys)) ) {
      switch (type) {
      case K_BLOCK: {
	KBlock * kb;
	const char * dstURI;
#if DEBUG_SEARCH
	EncName enc;
#endif
	int j;
	
	if (size < sizeof(KBlock))
	  return SYSERR;
	kb = MALLOC(size);
	memcpy(kb, &value[1], size);
#if DEBUG_SEARCH
	IFLOG(LOG_DEBUG,
	      hash2enc(&ps->decryptKey,
		       &enc));
	LOG(LOG_DEBUG,
	    "Decrypting KBlock with key %s.\n",
	    &enc);
#endif
	ECRS_decryptInPlace(&ps->decryptKey,
			    &kb[1],
			    size - sizeof(KBlock));
	j = sizeof(KBlock);
	while ( (j < size) &&
		(((const char*)kb)[j] != '\0') )
	  j++;
	if (j == size) {
	  BREAK(); /* kblock malformed */
	  FREE(kb);
	  return SYSERR;
	}
	dstURI = (const char*) &kb[1];
	j++;
	fi.meta = ECRS_deserializeMetaData(&((const char*)kb)[j],
					   size - j);
	if (fi.meta == NULL) {
	  BREAK(); /* kblock malformed */
	  FREE(kb);
	  return SYSERR;
	}
	fi.uri = ECRS_stringToUri(dstURI);
	if (fi.uri == NULL) {
	  BREAK(); /* kblock malformed */
	  ECRS_freeMetaData(fi.meta);
	  FREE(kb);
	  return SYSERR;
	}
	if (sqc->spcb != NULL) {
	  ret = sqc->spcb(&fi,
			  &ps->decryptKey,
			  NO,
			  sqc->spcbClosure);
	  if (ret == SYSERR)
	    sqc->aborted = YES;
	} else
	  ret = OK;
	ECRS_freeUri(fi.uri);
	ECRS_freeMetaData(fi.meta);
	FREE(kb);
	return ret;
      }
      case N_BLOCK: {
	const NBlock * nb;
	
	if (size < sizeof(NBlock))
	  return SYSERR;
	nb = (const NBlock*) &value[1];
	return processNBlock(nb,
			     NULL,
			     size,
			     sqc);
      }
      case KN_BLOCK:  {
	KNBlock * kb;
	int ret;
	
	if (size < sizeof(KNBlock))
	  return SYSERR;
	kb = MALLOC(size);
	memcpy(kb, &value[1], size);
	ECRS_decryptInPlace(&ps->decryptKey,
			    &kb->nblock,
			    size - sizeof(KBlock) - sizeof(unsigned int));
	ret = processNBlock(&kb->nblock,
			    &ps->decryptKey,
			    size - sizeof(KNBlock) + sizeof(NBlock),
			    sqc);
	FREE(kb);
	return ret;
      }
      case S_BLOCK: {
	SBlock * sb;
	const char * dstURI;
	int j;
	TIME_T now;
	HashCode512 updateId;
	URI updateURI;
	
	if (size < sizeof(SBlock))
	  return SYSERR;
	sb = MALLOC(size);
	memcpy(sb, &value[1], size);
	ECRS_decryptInPlace(&ps->decryptKey,
			    &sb->creationTime,
			    size
			    - sizeof(Signature)
			    - sizeof(PublicKey)
			    - sizeof(HashCode512));
	j = sizeof(SBlock);
	while ( (j < size) &&
		(((char*) &sb[1])[j] != '\0') )
	  j++;
	if (j == size) {
	  BREAK(); /* sblock malformed */
	  FREE(sb);
	  return SYSERR;
	}
	dstURI = (const char*) &sb[1];
	j++;
	fi.meta = ECRS_deserializeMetaData(&dstURI[j],
					   size - j);
	if (fi.meta == NULL) {
	  BREAK(); /* kblock malformed */
	  FREE(sb);
	  return SYSERR;
	}
	fi.uri = ECRS_stringToUri(dstURI);
	if (fi.uri == NULL) {
	  BREAK(); /* sblock malformed */
	  ECRS_freeMetaData(fi.meta);
	  FREE(sb);
	  return SYSERR;
	}
	if (sqc->spcb != NULL) {
	  ret = sqc->spcb(&fi, NULL, NO, sqc->spcbClosure);
	  if (ret == SYSERR)
	    sqc->aborted = YES;
	} else
	  ret = OK;
	ECRS_freeUri(fi.uri);
	ECRS_freeMetaData(fi.meta);

	/* compute current/NEXT URI (if updateable SBlock) and issue
	   respective query automatically! */
	TIME(&now);	
	if (OK != computeIdAtTime(sb,
				  now,
				  &updateId)) {
	  FREE(sb);
	  return SYSERR;
	}
	if (equalsHashCode512(&updateId,
			      &ps->decryptKey)) {
	  FREE(sb);
	  return ret; /* have latest version */
	}
	if (ps->keyCount != 2) {
	  BREAK();
	  FREE(sb);
	  return SYSERR;
	}

	updateURI.type = sks;
	updateURI.data.sks.namespace = ps->keys[1];
	updateURI.data.sks.identifier = updateId;
	addQueryForURI(&updateURI,
		       sqc);
	FREE(sb);
	return ret;
      }
      default:
	BREAK();
	break;
      } /* end switch */
    } /* for all matches */
  } /* for all pending queries */
  return OK;
}


/**
 * Search for content.
 *
 * @param timeout how long to wait (relative)
 * @param uri specifies the search parameters
 * @param uri set to the URI of the uploaded file
 */
int ECRS_search(const struct ECRS_URI * uri,
		unsigned int anonymityLevel,
		cron_t timeout,
		ECRS_SearchProgressCallback spcb,
		void * spcbClosure,
		ECRS_TestTerminate tt,
		void * ttClosure) {
  SendQueriesContext ctx;
  PendingSearch * ps;
  int i;
  cron_t now;
  cron_t remTime;
  cron_t new_ttl;
  unsigned int new_priority;

  cronTime(&ctx.start);
  cronTime(&now);
  timeout += now;
  ctx.timeout = timeout;
  ctx.queryCount = 0;
  ctx.queries = NULL;
  ctx.spcb = spcb;
  ctx.spcbClosure = spcbClosure;
  ctx.aborted = NO;
  MUTEX_CREATE_RECURSIVE(&ctx.lock);
  ctx.sctx = FS_SEARCH_makeContext(&ctx.lock);
  addQueryForURI(uri,
		 &ctx);
  while ( (OK == tt(ttClosure)) &&
	  (timeout > now) &&
	  (ctx.aborted == NO) ) {
    remTime = timeout - now;

    MUTEX_LOCK(&ctx.lock);
    for (i=0;i<ctx.queryCount;i++) {
      ps = ctx.queries[i];
      if ( (now < ps->timeout) &&
	   (ps->timeout != 0) )
	continue;
      if (ps->handle != NULL)
	FS_stop_search(ctx.sctx,
		       ps->handle);
      /* increase ttl/priority */
      new_ttl = ps->timeout - ps->lastTransmission;
      if (new_ttl < 4 * 5 * cronSECONDS)
	new_ttl = 4 * 5 * cronSECONDS + randomi(5 * cronSECONDS);
      new_ttl = new_ttl + randomi(5 * cronSECONDS + 2 * new_ttl);
      if (new_ttl > 0xFFFFFF)
	new_ttl = randomi(0xFFFFFF); /* if we get to large, reduce! */
      if (remTime < new_ttl)
	new_ttl = remTime;
      ps->timeout = new_ttl + now;
      new_priority = ps->priority;
      new_priority = new_priority + randomi(4 + 2 * new_priority);
      if (new_priority > 0xFFFFFF)
	new_priority = randomi(0xFFFFFF); /* if we get to large, reduce! */
      ps->priority = new_priority;
      ps->lastTransmission = now;
#if DEBUG_SEARCH
      LOG(LOG_DEBUG,
	  "ECRS initiating FS search with timeout %llus and priority %u.\n",
	  (ps->timeout - now) / cronSECONDS,
	  ps->priority);
#endif
      ps->handle
	= FS_start_search(ctx.sctx,
			  ps->type,
			  ps->keyCount,
			  ps->keys,
			  anonymityLevel,
			  ps->priority,
			  ps->timeout,
			  (Datum_Iterator) &receiveReplies,
			  &ctx);
    }
    MUTEX_UNLOCK(&ctx.lock);
    gnunet_util_sleep(100 * cronMILLIS);
    cronTime(&now);
  }
  for (i=0;i<ctx.queryCount;i++) {
    if (ctx.queries[i]->handle != NULL)
      FS_stop_search(ctx.sctx,
		     ctx.queries[i]->handle);
    FREE(ctx.queries[i]->keys);
    FREE(ctx.queries[i]);
  }
  GROW(ctx.queries,
       ctx.queryCount,
       0);
  FS_SEARCH_destroyContext(ctx.sctx);
  MUTEX_DESTROY(&ctx.lock);
  return OK;
}


/* end of search.c */
