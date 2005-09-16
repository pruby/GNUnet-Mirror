/*
     This file is part of GNUnet
     (C) 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/lib/fslib.c
 * @brief convenience methods to access the FS application from clients
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fs_lib.h"
#include "gnunet_protocols.h"
#include "fs.h"
#include "ecrs_core.h"

#define DEBUG_FSLIB NO

typedef struct FS_SEARCH_HANDLE {
  CS_fs_request_search_MESSAGE * req;
  Datum_Iterator callback;
  void * closure;
} SEARCH_HANDLE;

typedef struct FS_SEARCH_CONTEXT {
  GNUNET_TCP_SOCKET * sock;
  PTHREAD_T thread;
  Mutex * lock;
  SEARCH_HANDLE ** handles;
  unsigned int handleCount;
  unsigned int handleSize;
  int abort;
} SEARCH_CONTEXT;

/**
 * Thread that processes replies from gnunetd and
 * calls the appropriate callback.
 */
static void * processReplies(SEARCH_CONTEXT * ctx) {
  CS_MESSAGE_HEADER * hdr;
  int i;
  int matched;
  CS_fs_reply_content_MESSAGE * rep;
  HashCode512 query;
  unsigned int size;
  cron_t delay;

  delay = 100 * cronMILLIS;
  while (ctx->abort == NO) {
    hdr = NULL;
    if (OK == readFromSocket(ctx->sock,
			     &hdr)) {
#if DEBUG_FSLIB
      LOG(LOG_DEBUG,
	  "FSLIB: received message from gnunetd\n");
#endif
      delay = 100 * cronMILLIS;
      /* verify hdr, if reply, process, otherwise
	 signal protocol problem; if ok, find
	 matching callback, call on value */
      if ( (ntohs(hdr->size) < sizeof(CS_fs_reply_content_MESSAGE)) ||
	   (ntohs(hdr->type) != CS_PROTO_gap_RESULT) ) {
	BREAK();
	FREE(hdr);
	continue;
      }
      rep = (CS_fs_reply_content_MESSAGE*) hdr;
      size = ntohs(hdr->size) - sizeof(CS_fs_reply_content_MESSAGE);
      if (OK != getQueryFor(size,
			    (DBlock*)&rep[1],
			    &query)) {
	BREAK();
	FREE(hdr);
	continue;
      }
      matched = 0;
      MUTEX_LOCK(ctx->lock);
      for (i=ctx->handleCount-1;i>=0;i--) {
	if (equalsHashCode512(&query,
			      &ctx->handles[i]->req->query[0])) {
	  Datastore_Value * value;

	  matched++;
	  if (ctx->handles[i]->callback != NULL) {	
	    value = MALLOC(sizeof(Datastore_Value) + size);
	    value->size = htonl(size + sizeof(Datastore_Value));
	    value->type = htonl(getTypeOfBlock(size,
					       (DBlock*) &rep[1]));
	    value->prio = htonl(0);
	    value->anonymityLevel = htonl(0);
	    value->expirationTime = htonll(0);
	    memcpy(&value[1],
		   &rep[1],
		   size);
	    if (SYSERR == ctx->handles[i]->callback(&query,
						    value,
						    ctx->handles[i]->closure)) {
	      ctx->handles[i]->callback = NULL;
	    }
	    FREE(value);
	  }
	}
      }
      MUTEX_UNLOCK(ctx->lock);
#if DEBUG_FSLIB
      if (matched == 0)
	LOG(LOG_DEBUG,
	    "FSLIB: received content but have no pending request\n");
#endif
    } else {
#if DEBUG_FSLIB
      LOG(LOG_DEBUG,
	  "FSLIB: error communicating with gnunetd; sleeping for %ums\n",
	  delay);
#endif
      gnunet_util_sleep(delay);
      delay *= 2;
      if (delay > 5 * cronSECONDS)
	delay = 5 * cronSECONDS;
    }
    FREENONNULL(hdr);
  }
  return NULL;
}

SEARCH_CONTEXT * FS_SEARCH_makeContext(Mutex * lock) {
  SEARCH_CONTEXT * ret;
  ret = MALLOC(sizeof(SEARCH_CONTEXT));
  ret->lock = lock;
  ret->sock = getClientSocket();
  ret->handles = NULL;
  ret->handleCount = 0;
  ret->handleSize = 0;
  ret->abort = NO;
  if (0 != PTHREAD_CREATE(&ret->thread,
			  (PThreadMain) &processReplies,
			  ret,
			  64 * 1024))
    DIE_STRERROR("PTHREAD_CREATE");
  return ret;
}

void FS_SEARCH_destroyContext(struct FS_SEARCH_CONTEXT * ctx) {
  void * unused;

  GNUNET_ASSERT(ctx->handleCount == 0);
  ctx->abort = YES;
  closeSocketTemporarily(ctx->sock);
  PTHREAD_JOIN(&ctx->thread,
	       &unused);
  ctx->lock = NULL;
  releaseClientSocket(ctx->sock);
  GROW(ctx->handles,
       ctx->handleSize,
       0);
  FREE(ctx);
}

/**
 * Search for blocks matching the given key and type.
 *
 * @param timeout how long to search
 * @param anonymityLevel what are the anonymity
 *        requirements for this request? 0 for no
 *        anonymity (DHT/direct transfer ok)
 * @param callback method to call for each result
 * @param prio priority to use for the search
 */
SEARCH_HANDLE * FS_start_search(SEARCH_CONTEXT * ctx,
				unsigned int type,
				unsigned int keyCount,
				const HashCode512 * keys,
				unsigned int anonymityLevel,
				unsigned int prio,
				cron_t timeout,
				Datum_Iterator callback,
				void * closure) {
  SEARCH_HANDLE * ret;
  CS_fs_request_search_MESSAGE * req;
#if DEBUG_FSLIB
  EncName enc;
#endif

  ret = MALLOC(sizeof(SEARCH_HANDLE));
#if DEBUG_FSLIB
  LOG(LOG_DEBUG,
      "FSLIB: start search (%p)\n",
      ret);
#endif
  req = MALLOC(sizeof(CS_fs_request_search_MESSAGE) + (keyCount-1) * sizeof(HashCode512));
  req->header.size = htons(sizeof(CS_fs_request_search_MESSAGE) + (keyCount-1) * sizeof(HashCode512));
  req->header.type = htons(CS_PROTO_gap_QUERY_START);
  req->prio = htonl(prio);
  req->anonymityLevel = htonl(anonymityLevel);
  req->expiration = htonll(timeout);
  req->type = htonl(type);
  memcpy(&req->query[0],
	 keys,
	 keyCount * sizeof(HashCode512));
  ret->req = req;
  ret->callback = callback;
  ret->closure = closure;
  MUTEX_LOCK(ctx->lock);
  if (ctx->handleCount == ctx->handleSize) {
    GROW(ctx->handles,
	 ctx->handleSize,
	 ctx->handleSize * 2 + 4);
  }
  ctx->handles[ctx->handleCount++] = ret;
  MUTEX_UNLOCK(ctx->lock);
#if DEBUG_FSLIB
  IFLOG(LOG_DEBUG,
	hash2enc(&req->query[0],
		 &enc));
  LOG(LOG_DEBUG,
      "FSLIB: initiating search for `%s' of type %u\n",
      &enc,
      type);
#endif
  if (OK != writeToSocket(ctx->sock,
			  &req->header)) {
    FS_stop_search(ctx,
		   ret);
    return NULL;
  }
#if DEBUG_FSLIB
  LOG(LOG_DEBUG,
      "FSLIB: search started (%p)\n",
      ret);
#endif
  return ret;
}

/**
 * Stop searching.
 */
void FS_stop_search(SEARCH_CONTEXT * ctx,
		    SEARCH_HANDLE * handle) {
  int i;

#if DEBUG_FSLIB
  LOG(LOG_DEBUG,
      "FSLIB: stop search (%p)\n",
      handle);
#endif
  handle->req->header.type = htons(CS_PROTO_gap_QUERY_STOP);
  writeToSocket(ctx->sock,
		&handle->req->header);
  MUTEX_LOCK(ctx->lock);
  for (i=ctx->handleCount-1;i>=0;i--)
    if (ctx->handles[i] == handle) {
      ctx->handles[i] = ctx->handles[--ctx->handleCount];
      break;
    }
  MUTEX_UNLOCK(ctx->lock);
  FREE(handle->req);
#if DEBUG_FSLIB
  LOG(LOG_DEBUG,
      "FSLIB: search stopped (%p)\n",
      handle);
#endif
  FREE(handle);
}

/**
 * What is the current average priority of entries
 * in the routing table like?  Returns -1 on error.
 */
int FS_getAveragePriority(GNUNET_TCP_SOCKET * sock) {
  CS_MESSAGE_HEADER req;
  int ret;

  req.size = htons(sizeof(CS_MESSAGE_HEADER));
  req.type = htons(CS_PROTO_gap_GET_AVG_PRIORITY);
  if (OK != writeToSocket(sock,
			  &req))
    return -1;
  if (OK != readTCPResult(sock,
			  &ret))
    return -1;
  return ret;
}

/**
 * Insert a block.
 *
 * @param block the block (properly encoded and all)
 * @return OK on success, SYSERR on error
 */
int FS_insert(GNUNET_TCP_SOCKET * sock,
	      const Datastore_Value * block) {
  int ret;
  CS_fs_request_insert_MESSAGE * ri;
  unsigned int size;

  if (ntohl(block->size) <= sizeof(Datastore_Value)) {
    BREAK();
    return SYSERR;
  }
  size = ntohl(block->size) - sizeof(Datastore_Value);
  ri = MALLOC(sizeof(CS_fs_request_insert_MESSAGE) + size);
  ri->header.size = htons(sizeof(CS_fs_request_insert_MESSAGE) + size);
  ri->header.type = htons(CS_PROTO_gap_INSERT);
  ri->prio = block->prio;
  ri->expiration = block->expirationTime;
  ri->anonymityLevel = block->anonymityLevel;
  memcpy(&ri[1],
	 &block[1],
	 size);
  if (OK != writeToSocket(sock,
			  &ri->header)) {
    FREE(ri);
    return SYSERR;
  }
  FREE(ri);

  if (OK != readTCPResult(sock,
			  &ret))
    return SYSERR;
  return ret;
}

/**
 * Initialize to index a file
 */
int FS_initIndex(GNUNET_TCP_SOCKET * sock,
		 const HashCode512 * fileHc,
		 const char * fn) {
  int ret;
  CS_fs_request_init_index_MESSAGE *ri;
  unsigned int size, fnSize;

  fnSize = strlen(fn);
  size = sizeof(CS_fs_request_init_index_MESSAGE) + fnSize;
  ri = MALLOC(size);
  ri->header.size = htons(size);
  ri->header.type = htons(CS_PROTO_gap_INIT_INDEX);
  ri->reserved = htonl(0);
  ri->fileId = *fileHc;
  memcpy(&ri[1], fn, fnSize);

#if DEBUG_FSLIB
  LOG(LOG_DEBUG,
      "Sending index initialization request to gnunetd\n");
#endif
  if (OK != writeToSocket(sock,
        &ri->header)) {
    FREE(ri);
    return SYSERR;
  }
  FREE(ri);
#if DEBUG_FSLIB
  LOG(LOG_DEBUG,
      "Waiting for confirmation of index initialization request by gnunetd\n");
#endif
  if (OK != readTCPResult(sock,
        &ret))
    return SYSERR;
  return ret;
}

/**
 * Index a block.
 *
 * @param fileHc the hash of the entire file
 * @param block the data from the file (in plaintext)
 * @param offset the offset of the block into the file
 * @return OK on success, SYSERR on error
 */
int FS_index(GNUNET_TCP_SOCKET * sock,
	     const HashCode512 * fileHc,	
	     const Datastore_Value * block,
	     unsigned long long offset) {
  int ret;
  CS_fs_request_index_MESSAGE * ri;
  unsigned int size;

  size = ntohl(block->size) - sizeof(Datastore_Value);
  ri = MALLOC(sizeof(CS_fs_request_index_MESSAGE) + size);
  ri->header.size = htons(sizeof(CS_fs_request_index_MESSAGE) + size);
  ri->header.type = htons(CS_PROTO_gap_INDEX);
  ri->prio = block->prio;
  ri->expiration = block->expirationTime;
  ri->anonymityLevel = block->anonymityLevel;
  ri->fileId = *fileHc;
  ri->fileOffset = htonll(offset);
  memcpy(&ri[1],
	 &block[1],
	 size);
#if DEBUG_FSLIB
  LOG(LOG_DEBUG,
      "Sending index request to gnunetd\n");
#endif
  if (OK != writeToSocket(sock,
			  &ri->header)) {
    FREE(ri);
    return SYSERR;
  }
  FREE(ri);
#if DEBUG_FSLIB
  LOG(LOG_DEBUG,
      "Waiting for confirmation of index request by gnunetd\n");
#endif
  if (OK != readTCPResult(sock,
			  &ret))
    return SYSERR;
  return ret;
}

/**
 * Delete a block.  The arguments are the same as the ones for
 * FS_insert.
 *
 * @param block the block (properly encoded and all)
 * @return number of items deleted on success,
 *    SYSERR on error
 */
int FS_delete(GNUNET_TCP_SOCKET * sock,
	      const Datastore_Value * block) {
  int ret;
  CS_fs_request_delete_MESSAGE * rd;
  unsigned int size;

  size = ntohl(block->size) - sizeof(Datastore_Value);
  rd = MALLOC(sizeof(CS_fs_request_delete_MESSAGE) + size);
  rd->header.size = htons(sizeof(CS_fs_request_delete_MESSAGE) + size);
  rd->header.type = htons(CS_PROTO_gap_DELETE);
  memcpy(&rd[1],
	 &block[1],
	 size);
  if (OK != writeToSocket(sock,
			  &rd->header)) {
    FREE(rd);
    BREAK();
    return SYSERR;
  }
  FREE(rd);
  if (OK != readTCPResult(sock,
			  &ret)) {
    BREAK();
    return SYSERR;
  }
  return ret;
}

/**
 * Unindex a file.
 *
 * @param hc the hash of the entire file
 * @return OK on success, SYSERR on error
 */
int FS_unindex(GNUNET_TCP_SOCKET * sock,
	       unsigned int blocksize,
	       const HashCode512 * hc) {
  int ret;
  CS_fs_request_unindex_MESSAGE ru;

  ru.header.size = htons(sizeof(CS_fs_request_unindex_MESSAGE));
  ru.header.type = htons(CS_PROTO_gap_UNINDEX);
  ru.blocksize = htonl(blocksize);
  ru.fileId = *hc;
  if (OK != writeToSocket(sock,
			  &ru.header))
    return SYSERR;
  if (OK != readTCPResult(sock,
			  &ret))
    return SYSERR;
  return ret;
}

/**
 * Test if a file of the given hash is indexed.
 *
 * @param hc the hash of the entire file
 * @return YES if so, NO if not, SYSERR on error
 */
int FS_testIndexed(GNUNET_TCP_SOCKET * sock,
		   const HashCode512 * hc) {
  RequestTestindex ri;
  int ret;

  ri.header.size = htons(sizeof(RequestTestindex));
  ri.header.type = htons(CS_PROTO_gap_TESTINDEX);
  ri.reserved = htonl(0);
  ri.fileId = *hc;
  if (OK != writeToSocket(sock,
			  &ri.header))
    return SYSERR;
  if (OK != readTCPResult(sock,
			  &ret))
    return SYSERR;
  return ret;
}


/* end of fslib.c */
