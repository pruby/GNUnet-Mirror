/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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

#define DEBUG_FSLIB GNUNET_NO

typedef struct GNUNET_FS_SearchHandle
{
  CS_fs_request_search_MESSAGE *req;
  GNUNET_DatastoreValueIterator callback;
  void *closure;
} SEARCH_HANDLE;

typedef struct GNUNET_FS_SearchContext
{
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_ClientServerConnection *sock;
  struct GNUNET_ThreadHandle *thread;
  struct GNUNET_Mutex *lock;
  SEARCH_HANDLE **handles;
  unsigned int handleCount;
  unsigned int handleSize;
  int abort;
} SEARCH_CONTEXT;

/**
 * How often should we automatically retry if we
 * get a transient error back from gnunetd?
 */
#define AUTO_RETRY 4

/**
 * Thread that processes replies from gnunetd and
 * calls the appropriate callback.
 */
static void *
processReplies (void *cls)
{
  SEARCH_CONTEXT *ctx = cls;
  GNUNET_MessageHeader *hdr;
  int i;
  int matched;
  const CS_fs_reply_content_MESSAGE *rep;
  GNUNET_HashCode query;
  unsigned int size;
  GNUNET_CronTime delay;

  delay = 100 * GNUNET_CRON_MILLISECONDS;
  while (ctx->abort == GNUNET_NO)
    {
      hdr = NULL;
      if (GNUNET_OK == GNUNET_client_connection_read (ctx->sock, &hdr))
        {
#if DEBUG_FSLIB
          GNUNET_GE_LOG (ctx->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "FSLIB: received message from gnunetd\n");
#endif
          delay = 100 * GNUNET_CRON_MILLISECONDS;
          /* verify hdr, if reply, process, otherwise
             signal protocol problem; if ok, find
             matching callback, call on value */
          if ((ntohs (hdr->size) < sizeof (CS_fs_reply_content_MESSAGE)) ||
              (ntohs (hdr->type) != GNUNET_CS_PROTO_GAP_RESULT))
            {
              GNUNET_GE_BREAK (ctx->ectx, 0);
              GNUNET_free (hdr);
              continue;
            }
          rep = (const CS_fs_reply_content_MESSAGE *) hdr;
          size = ntohs (hdr->size) - sizeof (CS_fs_reply_content_MESSAGE);
          if (GNUNET_OK != GNUNET_EC_file_block_check_and_get_query (size, (DBlock *) & rep[1], GNUNET_NO,      /* gnunetd will have checked already */
                                                                     &query))
            {
              GNUNET_GE_BREAK (ctx->ectx, 0);
              GNUNET_free (hdr);
              continue;
            }
          matched = 0;
          GNUNET_mutex_lock (ctx->lock);
          for (i = ctx->handleCount - 1; i >= 0; i--)
            {
              if (0 ==
                  memcmp (&query, &ctx->handles[i]->req->query[0],
                          sizeof (GNUNET_HashCode)))
                {
                  GNUNET_DatastoreValue *value;

                  matched++;
                  if (ctx->handles[i]->callback != NULL)
                    {
                      value =
                        GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + size);
                      value->size =
                        htonl (size + sizeof (GNUNET_DatastoreValue));
                      value->type =
                        htonl (GNUNET_EC_file_block_get_type
                               (size, (DBlock *) & rep[1]));
                      value->prio = htonl (0);
                      value->anonymityLevel = rep->anonymityLevel;
                      value->expirationTime = rep->expirationTime;
                      memcpy (&value[1], &rep[1], size);
                      if (GNUNET_SYSERR == ctx->handles[i]->callback (&query,
                                                                      value,
                                                                      ctx->
                                                                      handles
                                                                      [i]->
                                                                      closure,
                                                                      0))
                        {
                          ctx->handles[i]->callback = NULL;
                        }
                      GNUNET_free (value);
                    }
                }
            }
          GNUNET_mutex_unlock (ctx->lock);
#if DEBUG_FSLIB
          if (matched == 0)
            GNUNET_GE_LOG (ctx->ectx,
                           GNUNET_GE_DEBUG | GNUNET_GE_REQUEST |
                           GNUNET_GE_USER,
                           "FSLIB: received content but have no pending request\n");
#endif
        }
      else
        {
#if DEBUG_FSLIB
          GNUNET_GE_LOG (ctx->ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "FSLIB: error communicating with gnunetd; sleeping for %ums\n",
                         delay);
#endif
          if (ctx->abort == GNUNET_NO)
            GNUNET_thread_sleep (delay);
          delay *= 2;
          if (delay > 5 * GNUNET_CRON_SECONDS)
            delay = 5 * GNUNET_CRON_SECONDS;
        }
      GNUNET_free_non_null (hdr);
    }
  return NULL;
}

SEARCH_CONTEXT *
GNUNET_FS_create_search_context (struct GNUNET_GE_Context * ectx,
                                 struct GNUNET_GC_Configuration * cfg,
                                 struct GNUNET_Mutex * lock)
{
  SEARCH_CONTEXT *ret;

  GNUNET_GE_ASSERT (ectx, lock != NULL);
  ret = GNUNET_malloc (sizeof (SEARCH_CONTEXT));
  ret->ectx = ectx;
  ret->cfg = cfg;
  ret->lock = lock;
  ret->sock = GNUNET_client_connection_create (ectx, cfg);
  if (ret->sock == NULL)
    {
      GNUNET_free (ret);
      return NULL;
    }
  ret->handles = NULL;
  ret->handleCount = 0;
  ret->handleSize = 0;
  ret->abort = GNUNET_NO;
  ret->thread = GNUNET_thread_create (&processReplies, ret, 128 * 1024);
  if (ret->thread == NULL)
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_FATAL | GNUNET_GE_ADMIN |
                            GNUNET_GE_BULK, "PTHREAD_CREATE");
  return ret;
}

void
GNUNET_FS_destroy_search_context (struct GNUNET_FS_SearchContext *ctx)
{
  void *unused;

  GNUNET_mutex_lock (ctx->lock);
  GNUNET_GE_ASSERT (ctx->ectx, ctx->handleCount == 0);
  ctx->abort = GNUNET_YES;
  GNUNET_client_connection_close_forever (ctx->sock);
  GNUNET_mutex_unlock (ctx->lock);
  GNUNET_thread_stop_sleep (ctx->thread);
  GNUNET_thread_join (ctx->thread, &unused);
  ctx->lock = NULL;
  GNUNET_client_connection_destroy (ctx->sock);
  GNUNET_array_grow (ctx->handles, ctx->handleSize, 0);
  GNUNET_free (ctx);
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
SEARCH_HANDLE *
GNUNET_FS_start_search (SEARCH_CONTEXT * ctx,
                        const GNUNET_PeerIdentity * target,
                        unsigned int type,
                        unsigned int keyCount,
                        const GNUNET_HashCode * keys,
                        unsigned int anonymityLevel,
                        unsigned int prio,
                        GNUNET_CronTime timeout,
                        GNUNET_DatastoreValueIterator callback, void *closure)
{
  SEARCH_HANDLE *ret;
  CS_fs_request_search_MESSAGE *req;
#if DEBUG_FSLIB
  GNUNET_EncName enc;
#endif

  ret = GNUNET_malloc (sizeof (SEARCH_HANDLE));
#if DEBUG_FSLIB
  GNUNET_GE_LOG (ctx->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FSLIB: start search (%p)\n", ret);
#endif
  req =
    GNUNET_malloc (sizeof (CS_fs_request_search_MESSAGE) +
                   (keyCount - 1) * sizeof (GNUNET_HashCode));
  req->header.size =
    htons (sizeof (CS_fs_request_search_MESSAGE) +
           (keyCount - 1) * sizeof (GNUNET_HashCode));
  req->header.type = htons (GNUNET_CS_PROTO_GAP_QUERY_START);
  req->prio = htonl (prio);
  req->anonymityLevel = htonl (anonymityLevel);
  req->expiration = GNUNET_htonll (timeout);
  req->type = htonl (type);
  if (target != NULL)
    req->target = *target;
  else
    memset (&req->target, 0, sizeof (GNUNET_PeerIdentity));
  memcpy (&req->query[0], keys, keyCount * sizeof (GNUNET_HashCode));
  ret->req = req;
  ret->callback = callback;
  ret->closure = closure;
  GNUNET_mutex_lock (ctx->lock);
  if (ctx->handleCount == ctx->handleSize)
    {
      GNUNET_array_grow (ctx->handles, ctx->handleSize,
                         ctx->handleSize * 2 + 4);
    }
  ctx->handles[ctx->handleCount++] = ret;
  GNUNET_mutex_unlock (ctx->lock);
#if DEBUG_FSLIB
  IF_GELOG (ctx->ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&req->query[0], &enc));
  GNUNET_GE_LOG (ctx->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FSLIB: initiating search for `%s' of type %u\n", &enc,
                 type);
#endif
  GNUNET_GE_ASSERT (NULL, ctx->sock != NULL);
  if (GNUNET_OK != GNUNET_client_connection_write (ctx->sock, &req->header))
    {
      GNUNET_FS_stop_search (ctx, ret);
      return NULL;
    }
#if DEBUG_FSLIB
  GNUNET_GE_LOG (ctx->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FSLIB: search started (%p)\n", ret);
#endif
  return ret;
}

/**
 * Stop searching.
 */
void
GNUNET_FS_stop_search (SEARCH_CONTEXT * ctx, SEARCH_HANDLE * handle)
{
  int i;

#if DEBUG_FSLIB
  GNUNET_GE_LOG (ctx->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FSLIB: stop search (%p)\n", handle);
#endif
  handle->req->header.type = htons (GNUNET_CS_PROTO_GAP_QUERY_STOP);
  GNUNET_GE_ASSERT (NULL, ctx->sock != NULL);
  if (GNUNET_OK !=
      GNUNET_client_connection_write (ctx->sock, &handle->req->header))
    {
      GNUNET_GE_LOG (ctx->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_REQUEST |
                     GNUNET_GE_DEVELOPER,
                     "FSLIB: failed to request stop search with gnunetd\n");
    }
  GNUNET_mutex_lock (ctx->lock);
  for (i = ctx->handleCount - 1; i >= 0; i--)
    if (ctx->handles[i] == handle)
      {
        ctx->handles[i] = ctx->handles[--ctx->handleCount];
        break;
      }
  GNUNET_mutex_unlock (ctx->lock);
  GNUNET_free (handle->req);
#if DEBUG_FSLIB
  GNUNET_GE_LOG (ctx->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FSLIB: search stopped (%p)\n", handle);
#endif
  GNUNET_free (handle);
}

/**
 * What is the current average priority of entries
 * in the routing table like?  Returns -1 on error.
 */
int
GNUNET_FS_get_current_average_priority (struct GNUNET_ClientServerConnection
                                        *sock)
{
  GNUNET_MessageHeader req;
  int ret;

  req.size = htons (sizeof (GNUNET_MessageHeader));
  req.type = htons (GNUNET_CS_PROTO_GAP_GET_AVG_PRIORITY);
  if (GNUNET_OK != GNUNET_client_connection_write (sock, &req))
    return -1;
  if (GNUNET_OK != GNUNET_client_connection_read_result (sock, &ret))
    return -1;
  return ret;
}

/**
 * Insert a block.
 *
 * @param block the block (properly encoded and all)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error, GNUNET_NO on transient error
 */
int
GNUNET_FS_insert (struct GNUNET_ClientServerConnection *sock,
                  const GNUNET_DatastoreValue * block)
{
  int ret;
  CS_fs_request_insert_MESSAGE *ri;
  unsigned int size;
  int retry;

  if (ntohl (block->size) <= sizeof (GNUNET_DatastoreValue))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  size = ntohl (block->size) - sizeof (GNUNET_DatastoreValue);
  ri = GNUNET_malloc (sizeof (CS_fs_request_insert_MESSAGE) + size);
  ri->header.size = htons (sizeof (CS_fs_request_insert_MESSAGE) + size);
  ri->header.type = htons (GNUNET_CS_PROTO_GAP_INSERT);
  ri->prio = block->prio;
  ri->expiration = block->expirationTime;
  ri->anonymityLevel = block->anonymityLevel;
  memcpy (&ri[1], &block[1], size);
  retry = AUTO_RETRY;
  do
    {
      if (GNUNET_OK != GNUNET_client_connection_write (sock, &ri->header))
        {
          GNUNET_free (ri);
          return GNUNET_SYSERR;
        }
      if (GNUNET_OK != GNUNET_client_connection_read_result (sock, &ret))
        {
          GNUNET_GE_BREAK (NULL, 0);
          GNUNET_free (ri);
          return GNUNET_SYSERR;
        }
    }
  while ((ret == GNUNET_NO) && (retry-- > 0));
  GNUNET_free (ri);
  return ret;
}

/**
 * Initialize to index a file
 */
int
GNUNET_FS_prepare_to_index (struct GNUNET_ClientServerConnection *sock,
                            const GNUNET_HashCode * fileHc, const char *fn)
{
  int ret;
  CS_fs_request_init_index_MESSAGE *ri;
  unsigned int size;
  size_t fnSize;

  fnSize = strlen (fn);
  fnSize = (fnSize + 7) & (~7); /* align */
  size = sizeof (CS_fs_request_init_index_MESSAGE) + fnSize;
  GNUNET_GE_ASSERT (NULL, size < 65536);
  ri = GNUNET_malloc (size);
  memset (ri, 0, size);
  ri->header.size = htons (size);
  ri->header.type = htons (GNUNET_CS_PROTO_GAP_INIT_INDEX);
  ri->reserved = htonl (0);
  ri->fileId = *fileHc;
  memcpy (&ri[1], fn, strlen (fn));

#if DEBUG_FSLIB
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Sending index initialization request to gnunetd\n");
#endif
  if (GNUNET_OK != GNUNET_client_connection_write (sock, &ri->header))
    {
      GNUNET_free (ri);
      return GNUNET_SYSERR;
    }
  GNUNET_free (ri);
#if DEBUG_FSLIB
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Waiting for confirmation of index initialization request by gnunetd\n");
#endif
  if (GNUNET_OK != GNUNET_client_connection_read_result (sock, &ret))
    return GNUNET_SYSERR;
  return ret;
}

/**
 * Index a block.
 *
 * @param fileHc the GNUNET_hash of the entire file
 * @param block the data from the file (in plaintext)
 * @param offset the offset of the block into the file
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_FS_index (struct GNUNET_ClientServerConnection *sock,
                 const GNUNET_HashCode * fileHc,
                 const GNUNET_DatastoreValue * block,
                 unsigned long long offset)
{
  int ret;
  CS_fs_request_index_MESSAGE *ri;
  unsigned int size;
  int retry;

  size = ntohl (block->size) - sizeof (GNUNET_DatastoreValue);
  ri = GNUNET_malloc (sizeof (CS_fs_request_index_MESSAGE) + size);
  ri->header.size = htons (sizeof (CS_fs_request_index_MESSAGE) + size);
  ri->header.type = htons (GNUNET_CS_PROTO_GAP_INDEX);
  ri->prio = block->prio;
  ri->expiration = block->expirationTime;
  ri->anonymityLevel = block->anonymityLevel;
  ri->fileId = *fileHc;
  ri->fileOffset = GNUNET_htonll (offset);
  memcpy (&ri[1], &block[1], size);
#if DEBUG_FSLIB
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Sending index request to gnunetd\n");
#endif
  retry = AUTO_RETRY;
  do
    {
      if (GNUNET_OK != GNUNET_client_connection_write (sock, &ri->header))
        {
          GNUNET_free (ri);
          return GNUNET_SYSERR;
        }
#if DEBUG_FSLIB
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Waiting for confirmation of index request by gnunetd\n");
#endif
      if (GNUNET_OK != GNUNET_client_connection_read_result (sock, &ret))
        {
          GNUNET_free (ri);
          return GNUNET_SYSERR;
        }
    }
  while ((ret == GNUNET_NO) && (retry-- > 0));
  GNUNET_free (ri);
  return ret;
}

/**
 * Delete a block.  The arguments are the same as the ones for
 * GNUNET_FS_insert.
 *
 * @param block the block (properly encoded and all)
 * @return number of items deleted on success,
 *    GNUNET_SYSERR on error
 */
int
GNUNET_FS_delete (struct GNUNET_ClientServerConnection *sock,
                  const GNUNET_DatastoreValue * block)
{
  int ret;
  CS_fs_request_delete_MESSAGE *rd;
  unsigned int size;
  int retry;

  size = ntohl (block->size) - sizeof (GNUNET_DatastoreValue);
  rd = GNUNET_malloc (sizeof (CS_fs_request_delete_MESSAGE) + size);
  rd->header.size = htons (sizeof (CS_fs_request_delete_MESSAGE) + size);
  rd->header.type = htons (GNUNET_CS_PROTO_GAP_DELETE);
  memcpy (&rd[1], &block[1], size);
  retry = AUTO_RETRY;
  do
    {
      if (GNUNET_OK != GNUNET_client_connection_write (sock, &rd->header))
        {
          GNUNET_free (rd);
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      if (GNUNET_OK != GNUNET_client_connection_read_result (sock, &ret))
        {
          GNUNET_GE_BREAK (NULL, 0);
          GNUNET_free (rd);
          return GNUNET_SYSERR;
        }
    }
  while ((ret == GNUNET_NO) && (retry-- > 0));
  GNUNET_free (rd);
  return ret;
}

/**
 * Unindex a file.
 *
 * @param hc the GNUNET_hash of the entire file
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_FS_unindex (struct GNUNET_ClientServerConnection *sock,
                   unsigned int blocksize, const GNUNET_HashCode * hc)
{
  int ret;
  CS_fs_request_unindex_MESSAGE ru;

  ru.header.size = htons (sizeof (CS_fs_request_unindex_MESSAGE));
  ru.header.type = htons (GNUNET_CS_PROTO_GAP_UNINDEX);
  ru.blocksize = htonl (blocksize);
  ru.fileId = *hc;
  if (GNUNET_OK != GNUNET_client_connection_write (sock, &ru.header))
    return GNUNET_SYSERR;
  if (GNUNET_OK != GNUNET_client_connection_read_result (sock, &ret))
    return GNUNET_SYSERR;
  return ret;
}

/**
 * Test if a file of the given GNUNET_hash is indexed.
 *
 * @param hc the GNUNET_hash of the entire file
 * @return GNUNET_YES if so, GNUNET_NO if not, GNUNET_SYSERR on error
 */
int
GNUNET_FS_test_indexed (struct GNUNET_ClientServerConnection *sock,
                        const GNUNET_HashCode * hc)
{
  RequestTestindex ri;
  int ret;

  ri.header.size = htons (sizeof (RequestTestindex));
  ri.header.type = htons (GNUNET_CS_PROTO_GAP_TESTINDEX);
  ri.reserved = htonl (0);
  ri.fileId = *hc;
  if (GNUNET_OK != GNUNET_client_connection_write (sock, &ri.header))
    return GNUNET_SYSERR;
  if (GNUNET_OK != GNUNET_client_connection_read_result (sock, &ret))
    return GNUNET_SYSERR;
  return ret;
}


/* end of fslib.c */
