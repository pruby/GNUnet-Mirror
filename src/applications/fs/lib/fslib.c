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

#define DEBUG_FSLIB NO

typedef struct FS_SEARCH_HANDLE
{
  CS_fs_request_search_MESSAGE *req;
  Datum_Iterator callback;
  void *closure;
} SEARCH_HANDLE;

typedef struct FS_SEARCH_CONTEXT
{
  struct GC_Configuration *cfg;
  struct GE_Context *ectx;
  struct ClientServerConnection *sock;
  struct PTHREAD *thread;
  struct MUTEX *lock;
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
  MESSAGE_HEADER *hdr;
  int i;
  int matched;
  const CS_fs_reply_content_MESSAGE *rep;
  HashCode512 query;
  unsigned int size;
  cron_t delay;

  delay = 100 * cronMILLIS;
  while (ctx->abort == NO)
    {
      hdr = NULL;
      if (OK == connection_read (ctx->sock, &hdr))
        {
#if DEBUG_FSLIB
          GE_LOG (ctx->ectx,
                  GE_DEBUG | GE_REQUEST | GE_USER,
                  "FSLIB: received message from gnunetd\n");
#endif
          delay = 100 * cronMILLIS;
          /* verify hdr, if reply, process, otherwise
             signal protocol problem; if ok, find
             matching callback, call on value */
          if ((ntohs (hdr->size) < sizeof (CS_fs_reply_content_MESSAGE)) ||
              (ntohs (hdr->type) != CS_PROTO_gap_RESULT))
            {
              GE_BREAK (ctx->ectx, 0);
              FREE (hdr);
              continue;
            }
          rep = (const CS_fs_reply_content_MESSAGE *) hdr;
          size = ntohs (hdr->size) - sizeof (CS_fs_reply_content_MESSAGE);
          if (OK != getQueryFor (size, (DBlock *) & rep[1], NO, /* gnunetd will have checked already */
                                 &query))
            {
              GE_BREAK (ctx->ectx, 0);
              FREE (hdr);
              continue;
            }
          matched = 0;
          MUTEX_LOCK (ctx->lock);
          for (i = ctx->handleCount - 1; i >= 0; i--)
            {
              if (equalsHashCode512 (&query, &ctx->handles[i]->req->query[0]))
                {
                  Datastore_Value *value;

                  matched++;
                  if (ctx->handles[i]->callback != NULL)
                    {
                      value = MALLOC (sizeof (Datastore_Value) + size);
                      value->size = htonl (size + sizeof (Datastore_Value));
                      value->type = htonl (getTypeOfBlock (size,
                                                           (DBlock *) &
                                                           rep[1]));
                      value->prio = htonl (0);
                      value->anonymityLevel = rep->anonymityLevel;
                      value->expirationTime = rep->expirationTime;
                      memcpy (&value[1], &rep[1], size);
                      if (SYSERR == ctx->handles[i]->callback (&query,
                                                               value,
                                                               ctx->
                                                               handles[i]->
                                                               closure, 0))
                        {
                          ctx->handles[i]->callback = NULL;
                        }
                      FREE (value);
                    }
                }
            }
          MUTEX_UNLOCK (ctx->lock);
#if DEBUG_FSLIB
          if (matched == 0)
            GE_LOG (ctx->ectx,
                    GE_DEBUG | GE_REQUEST | GE_USER,
                    "FSLIB: received content but have no pending request\n");
#endif
        }
      else
        {
#if DEBUG_FSLIB
          GE_LOG (ctx->ectx,
                  GE_DEBUG | GE_REQUEST | GE_USER,
                  "FSLIB: error communicating with gnunetd; sleeping for %ums\n",
                  delay);
#endif
          if (ctx->abort == NO)
            PTHREAD_SLEEP (delay);
          delay *= 2;
          if (delay > 5 * cronSECONDS)
            delay = 5 * cronSECONDS;
        }
      FREENONNULL (hdr);
    }
  return NULL;
}

SEARCH_CONTEXT *
FS_SEARCH_makeContext (struct GE_Context * ectx,
                       struct GC_Configuration * cfg, struct MUTEX * lock)
{
  SEARCH_CONTEXT *ret;

  GE_ASSERT (ectx, lock != NULL);
  ret = MALLOC (sizeof (SEARCH_CONTEXT));
  ret->ectx = ectx;
  ret->cfg = cfg;
  ret->lock = lock;
  ret->sock = client_connection_create (ectx, cfg);
  if (ret->sock == NULL)
    {
      FREE (ret);
      return NULL;
    }
  ret->handles = NULL;
  ret->handleCount = 0;
  ret->handleSize = 0;
  ret->abort = NO;
  ret->thread = PTHREAD_CREATE (&processReplies, ret, 128 * 1024);
  if (ret->thread == NULL)
    GE_DIE_STRERROR (ectx, GE_FATAL | GE_ADMIN | GE_BULK, "PTHREAD_CREATE");
  return ret;
}

void
FS_SEARCH_destroyContext (struct FS_SEARCH_CONTEXT *ctx)
{
  void *unused;

  MUTEX_LOCK (ctx->lock);
  GE_ASSERT (ctx->ectx, ctx->handleCount == 0);
  ctx->abort = YES;
  connection_close_forever (ctx->sock);
  MUTEX_UNLOCK (ctx->lock);
  PTHREAD_STOP_SLEEP (ctx->thread);
  PTHREAD_JOIN (ctx->thread, &unused);
  ctx->lock = NULL;
  connection_destroy (ctx->sock);
  GROW (ctx->handles, ctx->handleSize, 0);
  FREE (ctx);
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
FS_start_search (SEARCH_CONTEXT * ctx,
                 const PeerIdentity * target,
                 unsigned int type,
                 unsigned int keyCount,
                 const HashCode512 * keys,
                 unsigned int anonymityLevel,
                 unsigned int prio,
                 cron_t timeout, Datum_Iterator callback, void *closure)
{
  SEARCH_HANDLE *ret;
  CS_fs_request_search_MESSAGE *req;
#if DEBUG_FSLIB
  EncName enc;
#endif

  ret = MALLOC (sizeof (SEARCH_HANDLE));
#if DEBUG_FSLIB
  GE_LOG (ctx->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER, "FSLIB: start search (%p)\n", ret);
#endif
  req =
    MALLOC (sizeof (CS_fs_request_search_MESSAGE) +
            (keyCount - 1) * sizeof (HashCode512));
  req->header.size =
    htons (sizeof (CS_fs_request_search_MESSAGE) +
           (keyCount - 1) * sizeof (HashCode512));
  req->header.type = htons (CS_PROTO_gap_QUERY_START);
  req->prio = htonl (prio);
  req->anonymityLevel = htonl (anonymityLevel);
  req->expiration = htonll (timeout);
  req->type = htonl (type);
  if (target != NULL)
    req->target = *target;
  else
    memset (&req->target, 0, sizeof (PeerIdentity));
  memcpy (&req->query[0], keys, keyCount * sizeof (HashCode512));
  ret->req = req;
  ret->callback = callback;
  ret->closure = closure;
  MUTEX_LOCK (ctx->lock);
  if (ctx->handleCount == ctx->handleSize)
    {
      GROW (ctx->handles, ctx->handleSize, ctx->handleSize * 2 + 4);
    }
  ctx->handles[ctx->handleCount++] = ret;
  MUTEX_UNLOCK (ctx->lock);
#if DEBUG_FSLIB
  IF_GELOG (ctx->ectx,
            GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (&req->query[0], &enc));
  GE_LOG (ctx->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FSLIB: initiating search for `%s' of type %u\n", &enc, type);
#endif
  GE_ASSERT (NULL, ctx->sock != NULL);
  if (OK != connection_write (ctx->sock, &req->header))
    {
      FS_stop_search (ctx, ret);
      return NULL;
    }
#if DEBUG_FSLIB
  GE_LOG (ctx->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FSLIB: search started (%p)\n", ret);
#endif
  return ret;
}

/**
 * Stop searching.
 */
void
FS_stop_search (SEARCH_CONTEXT * ctx, SEARCH_HANDLE * handle)
{
  int i;

#if DEBUG_FSLIB
  GE_LOG (ctx->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FSLIB: stop search (%p)\n", handle);
#endif
  handle->req->header.type = htons (CS_PROTO_gap_QUERY_STOP);
  GE_ASSERT (NULL, ctx->sock != NULL);
  if (OK != connection_write (ctx->sock, &handle->req->header))
    {
      GE_LOG (ctx->ectx,
              GE_WARNING | GE_REQUEST | GE_DEVELOPER,
              "FSLIB: failed to request stop search with gnunetd\n");
    }
  MUTEX_LOCK (ctx->lock);
  for (i = ctx->handleCount - 1; i >= 0; i--)
    if (ctx->handles[i] == handle)
      {
        ctx->handles[i] = ctx->handles[--ctx->handleCount];
        break;
      }
  MUTEX_UNLOCK (ctx->lock);
  FREE (handle->req);
#if DEBUG_FSLIB
  GE_LOG (ctx->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FSLIB: search stopped (%p)\n", handle);
#endif
  FREE (handle);
}

/**
 * What is the current average priority of entries
 * in the routing table like?  Returns -1 on error.
 */
int
FS_getAveragePriority (struct ClientServerConnection *sock)
{
  MESSAGE_HEADER req;
  int ret;

  req.size = htons (sizeof (MESSAGE_HEADER));
  req.type = htons (CS_PROTO_gap_GET_AVG_PRIORITY);
  if (OK != connection_write (sock, &req))
    return -1;
  if (OK != connection_read_result (sock, &ret))
    return -1;
  return ret;
}

/**
 * Insert a block.
 *
 * @param block the block (properly encoded and all)
 * @return OK on success, SYSERR on error, NO on transient error
 */
int
FS_insert (struct ClientServerConnection *sock, const Datastore_Value * block)
{
  int ret;
  CS_fs_request_insert_MESSAGE *ri;
  unsigned int size;
  int retry;

  if (ntohl (block->size) <= sizeof (Datastore_Value))
    {
      GE_BREAK (NULL, 0);
      return SYSERR;
    }
  size = ntohl (block->size) - sizeof (Datastore_Value);
  ri = MALLOC (sizeof (CS_fs_request_insert_MESSAGE) + size);
  ri->header.size = htons (sizeof (CS_fs_request_insert_MESSAGE) + size);
  ri->header.type = htons (CS_PROTO_gap_INSERT);
  ri->prio = block->prio;
  ri->expiration = block->expirationTime;
  ri->anonymityLevel = block->anonymityLevel;
  memcpy (&ri[1], &block[1], size);
  retry = AUTO_RETRY;
  do
    {
      if (OK != connection_write (sock, &ri->header))
        {
          FREE (ri);
          return SYSERR;
        }
      if (OK != connection_read_result (sock, &ret))
        {
          GE_BREAK (NULL, 0);
          FREE (ri);
          return SYSERR;
        }
    }
  while ((ret == NO) && (retry-- > 0));
  FREE (ri);
  return ret;
}

/**
 * Initialize to index a file
 */
int
FS_initIndex (struct ClientServerConnection *sock,
              const HashCode512 * fileHc, const char *fn)
{
  int ret;
  CS_fs_request_init_index_MESSAGE *ri;
  unsigned int size;
  size_t fnSize;

  fnSize = strlen (fn);
  fnSize = (fnSize + 7) & (~7); /* align */
  size = sizeof (CS_fs_request_init_index_MESSAGE) + fnSize;
  GE_ASSERT (NULL, size < 65536);
  ri = MALLOC (size);
  memset (ri, 0, size);
  ri->header.size = htons (size);
  ri->header.type = htons (CS_PROTO_gap_INIT_INDEX);
  ri->reserved = htonl (0);
  ri->fileId = *fileHc;
  memcpy (&ri[1], fn, strlen (fn));

#if DEBUG_FSLIB
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Sending index initialization request to gnunetd\n");
#endif
  if (OK != connection_write (sock, &ri->header))
    {
      FREE (ri);
      return SYSERR;
    }
  FREE (ri);
#if DEBUG_FSLIB
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Waiting for confirmation of index initialization request by gnunetd\n");
#endif
  if (OK != connection_read_result (sock, &ret))
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
int
FS_index (struct ClientServerConnection *sock,
          const HashCode512 * fileHc,
          const Datastore_Value * block, unsigned long long offset)
{
  int ret;
  CS_fs_request_index_MESSAGE *ri;
  unsigned int size;
  int retry;

  size = ntohl (block->size) - sizeof (Datastore_Value);
  ri = MALLOC (sizeof (CS_fs_request_index_MESSAGE) + size);
  ri->header.size = htons (sizeof (CS_fs_request_index_MESSAGE) + size);
  ri->header.type = htons (CS_PROTO_gap_INDEX);
  ri->prio = block->prio;
  ri->expiration = block->expirationTime;
  ri->anonymityLevel = block->anonymityLevel;
  ri->fileId = *fileHc;
  ri->fileOffset = htonll (offset);
  memcpy (&ri[1], &block[1], size);
#if DEBUG_FSLIB
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Sending index request to gnunetd\n");
#endif
  retry = AUTO_RETRY;
  do
    {
      if (OK != connection_write (sock, &ri->header))
        {
          FREE (ri);
          return SYSERR;
        }
#if DEBUG_FSLIB
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "Waiting for confirmation of index request by gnunetd\n");
#endif
      if (OK != connection_read_result (sock, &ret))
        {
          FREE (ri);
          return SYSERR;
        }
    }
  while ((ret == NO) && (retry-- > 0));
  FREE (ri);
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
int
FS_delete (struct ClientServerConnection *sock, const Datastore_Value * block)
{
  int ret;
  CS_fs_request_delete_MESSAGE *rd;
  unsigned int size;
  int retry;

  size = ntohl (block->size) - sizeof (Datastore_Value);
  rd = MALLOC (sizeof (CS_fs_request_delete_MESSAGE) + size);
  rd->header.size = htons (sizeof (CS_fs_request_delete_MESSAGE) + size);
  rd->header.type = htons (CS_PROTO_gap_DELETE);
  memcpy (&rd[1], &block[1], size);
  retry = AUTO_RETRY;
  do
    {
      if (OK != connection_write (sock, &rd->header))
        {
          FREE (rd);
          GE_BREAK (NULL, 0);
          return SYSERR;
        }
      if (OK != connection_read_result (sock, &ret))
        {
          GE_BREAK (NULL, 0);
          FREE (rd);
          return SYSERR;
        }
    }
  while ((ret == NO) && (retry-- > 0));
  FREE (rd);
  return ret;
}

/**
 * Unindex a file.
 *
 * @param hc the hash of the entire file
 * @return OK on success, SYSERR on error
 */
int
FS_unindex (struct ClientServerConnection *sock,
            unsigned int blocksize, const HashCode512 * hc)
{
  int ret;
  CS_fs_request_unindex_MESSAGE ru;

  ru.header.size = htons (sizeof (CS_fs_request_unindex_MESSAGE));
  ru.header.type = htons (CS_PROTO_gap_UNINDEX);
  ru.blocksize = htonl (blocksize);
  ru.fileId = *hc;
  if (OK != connection_write (sock, &ru.header))
    return SYSERR;
  if (OK != connection_read_result (sock, &ret))
    return SYSERR;
  return ret;
}

/**
 * Test if a file of the given hash is indexed.
 *
 * @param hc the hash of the entire file
 * @return YES if so, NO if not, SYSERR on error
 */
int
FS_testIndexed (struct ClientServerConnection *sock, const HashCode512 * hc)
{
  RequestTestindex ri;
  int ret;

  ri.header.size = htons (sizeof (RequestTestindex));
  ri.header.type = htons (CS_PROTO_gap_TESTINDEX);
  ri.reserved = htonl (0);
  ri.fileId = *hc;
  if (OK != connection_write (sock, &ri.header))
    return SYSERR;
  if (OK != connection_read_result (sock, &ret))
    return SYSERR;
  return ret;
}


/* end of fslib.c */
