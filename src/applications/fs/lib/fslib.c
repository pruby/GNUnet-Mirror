/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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

/**
 * How often should we automatically retry a request
 * that failed? (Note that searches are retried
 * indefinitely in any case; this only applies
 * to upload/delete operations).
 */
#define AUTO_RETRY 5

/**
 * In memory, the search handle is followed
 * by a copy of the corresponding request of
 * type "CS_fs_request_search_MESSAGE *".
 */
struct GNUNET_FS_SearchHandle
{
  /**
   * This is a linked list.
   */
  struct GNUNET_FS_SearchHandle *next;

  /**
   * Function to call with results.
   */
  GNUNET_DatastoreValueIterator callback;

  /**
   * Extra argument to pass to callback.
   */
  void *closure;
};

/**
 * Context for a set of search operations.
 */
struct GNUNET_FS_SearchContext
{
  /**
   * Configuration data.
   */
  struct GNUNET_GC_Configuration *cfg;

  /**
   * Error logging.
   */
  struct GNUNET_GE_Context *ectx;

  /**
   * Connection to gnunetd.
   */
  struct GNUNET_ClientServerConnection *sock;

  /**
   * Thread listening for replies.
   */
  struct GNUNET_ThreadHandle *thread;

  /**
   * Lock for access to this struct.
   */
  struct GNUNET_Mutex *lock;

  /**
   * List of active requests.
   */
  struct GNUNET_FS_SearchHandle *handles;

  /**
   * Flag to signal that we should abort.
   */
  int abort;

  unsigned int total_received;

  unsigned int total_requested;
};

/**
 * Retransmit all of the requests to gnunetd
 * (used after a disconnect).
 */
static int
reissue_requests (struct GNUNET_FS_SearchContext *ctx)
{
  const CS_fs_request_search_MESSAGE *req;
  struct GNUNET_FS_SearchHandle *pos;

  pos = ctx->handles;
  while (pos != NULL)
    {
      req = (const CS_fs_request_search_MESSAGE *) &pos[1];
      if (GNUNET_OK !=
          GNUNET_client_connection_write (ctx->sock, &req->header))
        return GNUNET_SYSERR;
      pos = pos->next;
    }
  if (GNUNET_SYSERR == GNUNET_client_connection_ensure_connected (ctx->sock))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Thread that processes replies from gnunetd and
 * calls the appropriate callback.
 */
static void *
reply_process_thread (void *cls)
{
  struct GNUNET_FS_SearchContext *ctx = cls;
  GNUNET_MessageHeader *hdr;
  int matched;
  const CS_fs_reply_content_MESSAGE *rep;
  GNUNET_HashCode query;
  unsigned int size;
  GNUNET_CronTime delay;
  const CS_fs_request_search_MESSAGE *req;
  GNUNET_DatastoreValue *value;
  struct GNUNET_FS_SearchHandle *pos;
  struct GNUNET_FS_SearchHandle *spos;
  struct GNUNET_FS_SearchHandle *prev;
  int unique;

  delay = 100 * GNUNET_CRON_MILLISECONDS;
  while (ctx->abort == GNUNET_NO)
    {
      hdr = NULL;
      if (GNUNET_OK == GNUNET_client_connection_read (ctx->sock, &hdr))
        {
#if DEBUG_FSLIB
          fprintf (stderr, "FSLIB: received message from gnunetd\n");
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
          if (GNUNET_OK != GNUNET_EC_file_block_check_and_get_query (size, (GNUNET_EC_DBlock *) & rep[1], GNUNET_NO,    /* gnunetd will have checked already */
                                                                     &query))
            {
              GNUNET_GE_BREAK (ctx->ectx, 0);
              GNUNET_free (hdr);
              continue;
            }
          unique =
            GNUNET_EC_file_block_get_type (size,
                                           (GNUNET_EC_DBlock *) & rep[1]) ==
            GNUNET_ECRS_BLOCKTYPE_DATA;
          value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + size);
          value->size = htonl (size + sizeof (GNUNET_DatastoreValue));
          value->type =
            htonl (GNUNET_EC_file_block_get_type
                   (size, (GNUNET_EC_DBlock *) & rep[1]));
          value->priority = htonl (0);
          value->anonymity_level = rep->anonymity_level;
          value->expiration_time = rep->expiration_time;
          memcpy (&value[1], &rep[1], size);
          matched = 0;
          GNUNET_mutex_lock (ctx->lock);
          prev = NULL;
          pos = ctx->handles;
          while (pos != NULL)
            {
              req = (const CS_fs_request_search_MESSAGE *) &pos[1];
              if (0 ==
                  memcmp (&query, &req->query[0], sizeof (GNUNET_HashCode)))
                {
                  matched++;
                  spos = pos;
                  if (unique)
                    {
                      if (prev == NULL)
                        ctx->handles = pos->next;
                      else
                        prev->next = pos->next;
                      if (prev == NULL)
                        pos = ctx->handles;
                      else
                        pos = prev->next;
                    }
                  else
                    {
                      prev = pos;
                      pos = pos->next;
                    }
#if DEBUG_FSLIB
                  fprintf (stderr,
                           "FSLIB passes response %u to client (%d)\n",
                           ctx->total_received++, unique);
#endif
                  if ((spos->callback != NULL) &&
                      (GNUNET_SYSERR == spos->callback (&query,
                                                        value,
                                                        spos->closure, 0)))
                    spos->callback = NULL;
                  if (unique)
                    GNUNET_free (spos);
                }
              else
                {
                  prev = pos;
                  pos = pos->next;
                }
            }
          GNUNET_free (value);
#if DEBUG_FSLIB
          if (matched == 0)
            fprintf (stderr,
                     "FSLIB: received content but have no pending request\n");
#endif
          GNUNET_mutex_unlock (ctx->lock);
        }
      else
        {
          while (GNUNET_NO == ctx->abort)
            {
              GNUNET_thread_sleep (delay);
              delay *= 2;
              if (delay > 5 * GNUNET_CRON_SECONDS)
                delay = 5 * GNUNET_CRON_SECONDS;
              if ((GNUNET_OK ==
                   GNUNET_client_connection_ensure_connected (ctx->sock))
                  && (GNUNET_OK == reissue_requests (ctx)))
                break;          /* we're back, continue outer loop! */
            }
        }
      GNUNET_free_non_null (hdr);
    }
  return NULL;
}

struct GNUNET_FS_SearchContext *
GNUNET_FS_create_search_context (struct GNUNET_GE_Context *ectx,
                                 struct GNUNET_GC_Configuration *cfg)
{
  struct GNUNET_FS_SearchContext *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_SearchContext));
  memset (ret, 0, sizeof (struct GNUNET_FS_SearchContext));
  ret->ectx = ectx;
  ret->cfg = cfg;
  ret->lock = GNUNET_mutex_create (GNUNET_YES);
  ret->sock = GNUNET_client_connection_create (ectx, cfg);
  if (ret->sock == NULL)
    {
      GNUNET_mutex_destroy (ret->lock);
      GNUNET_free (ret);
      return NULL;
    }
  ret->handles = NULL;
  ret->abort = GNUNET_NO;
  ret->thread = GNUNET_thread_create (&reply_process_thread, ret, 128 * 1024);
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
  struct GNUNET_FS_SearchHandle *pos;

  ctx->abort = GNUNET_YES;
  GNUNET_client_connection_close_forever (ctx->sock);
  GNUNET_thread_stop_sleep (ctx->thread);
  GNUNET_thread_join (ctx->thread, &unused);
  GNUNET_client_connection_destroy (ctx->sock);
  while (ctx->handles != NULL)
    {
      pos = ctx->handles;
      ctx->handles = pos->next;
      GNUNET_free (pos);
    }
  GNUNET_mutex_destroy (ctx->lock);
  GNUNET_free (ctx);
}

/**
 * Search for blocks matching the given key and type.
 *
 * @param timeout how long to search
 * @param anonymity_level what are the anonymity
 *        requirements for this request? 0 for no
 *        anonymity (DHT/direct transfer ok)
 * @param callback method to call for each result
 * @param priority priority to use for the search
 */
int
GNUNET_FS_start_search (struct GNUNET_FS_SearchContext *ctx,
                        const GNUNET_PeerIdentity * target,
                        unsigned int type,
                        unsigned int keyCount,
                        const GNUNET_HashCode * keys,
                        unsigned int anonymityLevel,
                        GNUNET_DatastoreValueIterator callback, void *closure)
{
  struct GNUNET_FS_SearchHandle *ret;
  CS_fs_request_search_MESSAGE *req;
  int ok;
#if DEBUG_FSLIB
  GNUNET_EncName enc;
#endif

  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_SearchHandle) +
                       sizeof (CS_fs_request_search_MESSAGE) +
                       (keyCount - 1) * sizeof (GNUNET_HashCode));
  req = (CS_fs_request_search_MESSAGE *) & ret[1];
#if DEBUG_FSLIB
  GNUNET_hash_to_enc (keys, &enc);
  fprintf (stderr, "FSLIB: start search for `%s' (%p)\n", (char *) &enc, ret);
#endif
  req->header.size =
    htons (sizeof (CS_fs_request_search_MESSAGE) +
           (keyCount - 1) * sizeof (GNUNET_HashCode));
  req->header.type = htons (GNUNET_CS_PROTO_GAP_QUERY_START);
  req->anonymity_level = htonl (anonymityLevel);
  req->type = htonl (type);
  if (target != NULL)
    req->target = *target;
  else
    memset (&req->target, 0, sizeof (GNUNET_PeerIdentity));
  memcpy (&req->query[0], keys, keyCount * sizeof (GNUNET_HashCode));
  ret->callback = callback;
  ret->closure = closure;
  GNUNET_mutex_lock (ctx->lock);
  ret->next = ctx->handles;
  ctx->handles = ret;
#if DEBUG_FSLIB
  fprintf (stderr,
           "FSLIB passes request %u to daemon (%d)\n",
           ctx->total_requested++, type);
#endif
  ok = GNUNET_client_connection_write (ctx->sock, &req->header);
  GNUNET_mutex_unlock (ctx->lock);
  return ok;
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
  ri->priority = block->priority;
  ri->expiration = block->expiration_time;
  ri->anonymity_level = block->anonymity_level;
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
  fprintf (stderr, "Sending index initialization request to gnunetd\n");
#endif
  if (GNUNET_OK != GNUNET_client_connection_write (sock, &ri->header))
    {
      GNUNET_free (ri);
      return GNUNET_SYSERR;
    }
  GNUNET_free (ri);
#if DEBUG_FSLIB
  fprintf (stderr,
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
#if DEBUG_FSLIB
  GNUNET_HashCode hc;
  GNUNET_EncName enc;
#endif

  size = ntohl (block->size) - sizeof (GNUNET_DatastoreValue);
  ri = GNUNET_malloc (sizeof (CS_fs_request_index_MESSAGE) + size);
  ri->header.size = htons (sizeof (CS_fs_request_index_MESSAGE) + size);
  ri->header.type = htons (GNUNET_CS_PROTO_GAP_INDEX);
  ri->priority = block->priority;
  ri->expiration = block->expiration_time;
  ri->anonymity_level = block->anonymity_level;
  ri->fileId = *fileHc;
  ri->fileOffset = GNUNET_htonll (offset);
  memcpy (&ri[1], &block[1], size);
#if DEBUG_FSLIB
  GNUNET_EC_file_block_get_query ((const GNUNET_EC_DBlock *) &block[1], size,
                                  &hc);
  GNUNET_hash_to_enc (&hc, &enc);
  fprintf (stderr,
           "Sending index request for `%s' to gnunetd)\n",
           (const char *) &enc);
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
      fprintf (stderr,
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
  CS_fs_request_test_index_MESSAGE ri;
  int ret;

  ri.header.size = htons (sizeof (CS_fs_request_test_index_MESSAGE));
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
