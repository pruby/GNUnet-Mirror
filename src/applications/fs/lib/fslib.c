/*
     This file is part of GNUnet

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

typedef struct FS_SEARCH_HANDLE {
  RequestSearch * req;
  Datum_Iterator callback;
  void * closure;
} SEARCH_HANDLE;

typedef struct FS_SEARCH_CONTEXT {
  GNUNET_TCP_SOCKET * sock;
  PTHREAD_T thread;
  Mutex lock;  
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
  CS_HEADER * hdr;
  int i;
  ReplyContent * rep;
  HashCode160 query;
  unsigned int size;
  cron_t delay;

  delay = 100 * cronMILLIS;
  while (ctx->abort == NO) {
    hdr = NULL;
    if (OK == readFromSocket(ctx->sock,
			     &hdr)) {
      delay = 100 * cronMILLIS;
      /* verify hdr, if reply, process, otherwise
	 signal protocol problem; if ok, find
	 matching callback, call on value */
      if ( (ntohs(hdr->size) < sizeof(ReplyContent)) ||
	   (ntohs(hdr->type) != AFS_CS_PROTO_RESULT) ) {
	BREAK();
	FREE(hdr);
	continue;
      }
      rep = (ReplyContent*) hdr;
      size = ntohs(hdr->size) - sizeof(ReplyContent);
      if (OK != getQueryFor(size,
			    (char*)&rep[1],
			    &query)) {
	BREAK();
	FREE(hdr);
	continue;
      }      
      MUTEX_LOCK(&ctx->lock);
      for (i=ctx->handleCount-1;i>=0;i--) {
	if (equalsHashCode160(&query,
			      &ctx->handles[i]->req->query[0])) {
	  Datastore_Value * value;

	  value = MALLOC(sizeof(Datastore_Value) + size);
	  value->size = htonl(size + sizeof(Datastore_Value));
	  value->type = htonl(getTypeOfBlock(size,
					     &rep[1]));
	  value->prio = htonl(0);
	  value->anonymityLevel = htonl(0);
	  value->expirationTime = htonll(0);
	  memcpy(&value[1],
		 &rep[1],
		 size);
	  ctx->handles[i]->callback(&query,
				    value,
				    ctx->handles[i]->closure);
	  FREE(value);
	}
      }
      MUTEX_UNLOCK(&ctx->lock);      
    } else {
      gnunet_util_sleep(delay);
      delay *= 2;
      if (delay > 5 * cronSECONDS)
	delay = 5 * cronSECONDS;
    }
    FREENONNULL(hdr);
  }
  return NULL;
}

SEARCH_CONTEXT * FS_SEARCH_makeContext() {
  SEARCH_CONTEXT * ret;
  ret = MALLOC(sizeof(SEARCH_CONTEXT));
  MUTEX_CREATE_RECURSIVE(&ret->lock);
  ret->sock = getClientSocket();
  ret->handles = NULL;
  ret->handleCount = 0;
  ret->handleSize = 0;
  ret->abort = NO;
  if (0 != PTHREAD_CREATE(&ret->thread,
			  (PThreadMain) &processReplies,
			  ret,
			  16 * 1024))
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
  MUTEX_DESTROY(&ctx->lock);
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
				const HashCode160 * keys,
				unsigned int anonymityLevel,
				unsigned int prio,
				cron_t timeout,
				Datum_Iterator callback,
				void * closure) {
  SEARCH_HANDLE * ret;
  RequestSearch * req;
  EncName enc;

  ret = MALLOC(sizeof(SEARCH_HANDLE));
  req = MALLOC(sizeof(RequestSearch) + (keyCount-1) * sizeof(HashCode160));
  req->header.size = htons(sizeof(RequestSearch) + (keyCount-1) * sizeof(HashCode160));
  req->header.type = htons(AFS_CS_PROTO_QUERY_START);
  req->prio = htonl(prio);
  req->anonymityLevel = htonl(anonymityLevel);
  req->expiration = htonll(timeout);
  req->type = htonl(type);
  memcpy(&req->query[0],
	 keys,
	 keyCount * sizeof(HashCode160));
  ret->req = req;
  ret->callback = callback;
  ret->closure = closure;
  MUTEX_LOCK(&ctx->lock);
  if (ctx->handleCount == ctx->handleSize) {
    GROW(ctx->handles,
	 ctx->handleSize,
	 ctx->handleSize * 2 + 4);    
  }
  ctx->handles[ctx->handleCount++] = ret;
  MUTEX_UNLOCK(&ctx->lock);
  IFLOG(LOG_DEBUG,
	hash2enc(&req->query[0],
		 &enc));
  LOG(LOG_DEBUG,
      "FS initiating search for %s of type %u\n",
      &enc,
      type);
  if (OK != writeToSocket(ctx->sock,
			  &req->header)) {
    FS_stop_search(ctx,
		   ret);
    return NULL;
  }
  return ret;
}

/**
 * Stop searching.
 */
void FS_stop_search(SEARCH_CONTEXT * ctx,
		    SEARCH_HANDLE * handle) {
  int i;

  handle->req->header.type = htons(AFS_CS_PROTO_QUERY_STOP);
  writeToSocket(ctx->sock,
		&handle->req->header);  
  MUTEX_LOCK(&ctx->lock);
  for (i=ctx->handleCount-1;i>=0;i--)
    if (ctx->handles[i] == handle) {
      ctx->handles[i] = ctx->handles[--ctx->handleCount];
      break;
    }
  MUTEX_UNLOCK(&ctx->lock);      
  FREE(handle->req);
  FREE(handle);
}

/**
 * What is the current average priority of entries
 * in the routing table like?  Returns -1 on error.
 */
unsigned int FS_getAveragePriority(GNUNET_TCP_SOCKET * sock) {
  CS_HEADER req;
  unsigned int ret;

  req.size = htons(sizeof(CS_HEADER));
  req.type = htons(AFS_CS_PROTO_GET_AVG_PRIORITY);
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
  RequestInsert * ri;
  unsigned int size;

  size = ntohl(block->size) - sizeof(Datastore_Value);
  ri = MALLOC(sizeof(RequestInsert) + size);
  ri->header.size = htons(sizeof(RequestInsert) + size);
  ri->header.type = htons(AFS_CS_PROTO_INSERT);
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
 * Index a block. 
 * 
 * @param fileHc the hash of the entire file
 * @param block the data from the file (in plaintext)
 * @param offset the offset of the block into the file
 * @return OK on success, SYSERR on error
 */
int FS_index(GNUNET_TCP_SOCKET * sock,
	     const HashCode160 * fileHc,	  
	     const Datastore_Value * block,
	     unsigned long long offset) {
  int ret;
  RequestIndex * ri;
  unsigned int size;

  size = ntohl(block->size) - sizeof(Datastore_Value);
  ri = MALLOC(sizeof(RequestIndex) + size);
  ri->header.size = htons(sizeof(RequestIndex) + size);
  ri->header.type = htons(AFS_CS_PROTO_INDEX);
  ri->prio = block->prio;
  ri->expiration = block->expirationTime;
  ri->anonymityLevel = block->anonymityLevel;
  ri->fileId = *fileHc;
  ri->fileOffset = htonll(offset);
  memcpy(&ri[1],
	 &block[1],
	 size);
  LOG(LOG_DEBUG,
      "Sending index request to gnunetd\n");
  if (OK != writeToSocket(sock,
			  &ri->header)) {
    FREE(ri);
    return SYSERR; 
  }
  FREE(ri);
  LOG(LOG_DEBUG,
      "Waiting for confirmation of index request by gnunetd\n");
  if (OK != readTCPResult(sock,
			  &ret))
    return SYSERR;
  return ret;
}

/**
 * Delete a block. 
 * 
 * @param block the block (properly encoded and all)
 * @return OK on success, SYSERR on error
 */
int FS_delete(GNUNET_TCP_SOCKET * sock,
	      const Datastore_Value * block) {
  int ret;  
  RequestDelete * rd;
  unsigned int size;

  size = ntohl(block->size) - sizeof(Datastore_Value);
  rd = MALLOC(sizeof(RequestDelete) + size);
  rd->header.size = htons(sizeof(RequestDelete) + size);
  rd->header.type = htons(AFS_CS_PROTO_DELETE);
  memcpy(&rd[1],
	 &block[1],
	 size);
  if (OK != writeToSocket(sock,
			  &rd->header)) {
    FREE(rd);
    return SYSERR; 
  }
  FREE(rd);
  if (OK != readTCPResult(sock,
			  &ret))
    return SYSERR;
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
	       const HashCode160 * hc) {
  int ret;
  RequestUnindex ru;

  ru.header.size = htons(sizeof(RequestUnindex));
  ru.header.type = htons(AFS_CS_PROTO_UNINDEX);
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

/* end of fslib.c */
