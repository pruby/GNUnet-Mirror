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
 * @file dht/tools/dht_api.c
 * @brief DHT-module's core API's implementation.
 * @author Tomi Tukiainen, Christian Grothoff, Nathan Evans
 */
#include "platform.h"
#include "gnunet_protocols.h"
#include "dht.h"
#include "gnunet_dht_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"

#define DEBUG_DHT_API GNUNET_NO

/**
 * Doubly-linked list of get requests.
 */
struct GNUNET_DHT_GetRequest
{
  struct GNUNET_DHT_GetRequest *prev;

  struct GNUNET_DHT_GetRequest *next;

  CS_dht_request_get_MESSAGE request;
};

/**
 * Data exchanged between main thread and GET thread.
 */
struct GNUNET_DHT_Context
{

  /**
   * Connection with gnunetd.
   */
  struct GNUNET_ClientServerConnection *sock;

  /**
   * Lock for head and tail fields.
   */
  struct GNUNET_Mutex *lock;

  /**
   * Callback to call for each result.
   */
  GNUNET_ResultProcessor processor;

  /**
   * Extra argument for processor.
   */
  void *closure;

  /**
   * Thread polling for replies from gnunetd.
   */
  struct GNUNET_ThreadHandle *poll_thread;

  /**
   * Head of our pending requests.
   */
  struct GNUNET_DHT_GetRequest *head;

  /**
   * Tail of our pending requests.
   */
  struct GNUNET_DHT_GetRequest *tail;

  /**
   * Are we done (for whichever reason)?
   */
  int aborted;

  /**
   * Set to YES if we had a write error and need to
   * resubmit all of our requests.
   */
  int restart;

};

/**
 * Main loop of the poll thread.
 *
 * @param cls the DHT context
 * @return NULL (always)
 */
static void *
poll_thread (void *cls)
{
  struct GNUNET_DHT_Context *info = cls;
  GNUNET_MessageHeader *reply;
  CS_dht_request_put_MESSAGE *put;
  struct GNUNET_DHT_GetRequest *get;
  unsigned int size;

  while (info->aborted == GNUNET_NO)
    {
      reply = NULL;
      if ((info->restart == GNUNET_YES) ||
          (GNUNET_OK != GNUNET_client_connection_read (info->sock, &reply)))
        {
          info->restart = GNUNET_NO;
          while ((info->aborted == GNUNET_NO) &&
                 (GNUNET_OK !=
                  GNUNET_client_connection_ensure_connected (info->sock)))
            GNUNET_thread_sleep (100 * GNUNET_CRON_MILLISECONDS);
          if (info->aborted != GNUNET_NO)
            break;
          GNUNET_mutex_lock (info->lock);
          get = info->head;
          while ((get != NULL) &&
                 (info->restart == GNUNET_NO) && (info->aborted == GNUNET_NO))
            {
              if (GNUNET_OK !=
                  GNUNET_client_connection_write (info->sock,
                                                  &get->request.header))
                info->restart = GNUNET_YES;
              get = get->next;
            }
          GNUNET_mutex_unlock (info->lock);
          continue;
        }
      if ((sizeof (CS_dht_request_put_MESSAGE) > ntohs (reply->size)) ||
          (GNUNET_CS_PROTO_DHT_REQUEST_PUT != ntohs (reply->type)))
        {
          fprintf (stderr,
                   "Received message of type %u and size %u\n",
                   ntohs (reply->type), ntohs (reply->size));
          GNUNET_GE_BREAK (NULL, 0);
          GNUNET_free (reply);
          break;                /*  invalid reply */
        }
      size = ntohs (reply->size) - sizeof (CS_dht_request_put_MESSAGE);
      put = (CS_dht_request_put_MESSAGE *) reply;
      if ((info->processor != NULL) &&
          (GNUNET_OK != info->processor (&put->key,
                                         ntohl (put->type),
                                         size,
                                         (const char *) &put[1],
                                         info->closure)))
        info->aborted = GNUNET_YES;
      GNUNET_free (reply);
    }
  info->aborted = GNUNET_YES;
  return NULL;
}

/**
 * Set up a context for performing asynchronous DHT operations.
 *
 * @param resultCallback function to call for results,
 *        the operation also aborts if the callback returns
 *        GNUNET_SYSERR
 * @return NULL on error
 */
struct GNUNET_DHT_Context *
GNUNET_DHT_context_create (struct GNUNET_GC_Configuration
                           *cfg,
                           struct GNUNET_GE_Context
                           *ectx,
                           GNUNET_ResultProcessor
                           resultCallback, void *resCallbackClosure)
{
  struct GNUNET_DHT_Context *ctx;
  struct GNUNET_ClientServerConnection *sock;

  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    return NULL;
  ctx = GNUNET_malloc (sizeof (struct GNUNET_DHT_Context));
  ctx->lock = GNUNET_mutex_create (GNUNET_NO);
  ctx->sock = sock;
  ctx->processor = resultCallback;
  ctx->closure = resCallbackClosure;
  ctx->poll_thread = GNUNET_thread_create (&poll_thread, ctx, 1024 * 8);
  if (ctx->poll_thread == NULL)
    {
      GNUNET_client_connection_destroy (sock);
      GNUNET_mutex_destroy (ctx->lock);
      GNUNET_free (ctx);
      return NULL;
    }
  return ctx;
}


/**
 * Start an asynchronous GET operation on the DHT looking for
 * key.
 *
 * @param type the type of key to look up
 * @param key the key to look up
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
struct GNUNET_DHT_GetRequest *
GNUNET_DHT_get_start (struct GNUNET_DHT_Context *ctx,
                      unsigned int type, const GNUNET_HashCode * key)
{
  struct GNUNET_DHT_GetRequest *req;

  req = GNUNET_malloc (sizeof (struct GNUNET_DHT_GetRequest));
  req->request.header.size = htons (sizeof (CS_dht_request_get_MESSAGE));
  req->request.header.type = htons (GNUNET_CS_PROTO_DHT_REQUEST_GET);
  req->request.type = htonl (type);
  req->request.key = *key;
  GNUNET_mutex_lock (ctx->lock);
  GNUNET_DLL_insert (ctx->head, ctx->tail, req);
  GNUNET_mutex_unlock (ctx->lock);
  if (GNUNET_OK !=
      GNUNET_client_connection_write (ctx->sock, &req->request.header))
    ctx->restart = GNUNET_YES;
  return req;
}


/**
 * Stop an asynchronous GET operation on the DHT looking for
 * key.
 *
 * @param req request to stop
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DHT_get_stop (struct GNUNET_DHT_Context *ctx,
                     struct GNUNET_DHT_GetRequest *req)
{
  CS_dht_request_get_MESSAGE creq;

  creq.header.size = htons (sizeof (CS_dht_request_get_MESSAGE));
  creq.header.type = htons (GNUNET_CS_PROTO_DHT_REQUEST_GET_END);
  creq.type = req->request.type;
  creq.key = req->request.key;
  GNUNET_mutex_lock (ctx->lock);
  GNUNET_DLL_remove (ctx->head, ctx->tail, req);
  GNUNET_mutex_unlock (ctx->lock);
  if (GNUNET_OK != GNUNET_client_connection_write (ctx->sock, &creq.header))
    ctx->restart = GNUNET_YES;
  GNUNET_free (req);
  return GNUNET_OK;
}

/**
 * Destroy a previously created context for DHT operations.
 *
 * @param ctx context to destroy
 * @return GNUNET_SYSERR on error
 */
int
GNUNET_DHT_context_destroy (struct GNUNET_DHT_Context *ctx)
{
  void *unused;

  GNUNET_GE_ASSERT (NULL, ctx->head == NULL);
  GNUNET_GE_ASSERT (NULL, ctx->tail == NULL);
  ctx->aborted = GNUNET_YES;
  GNUNET_client_connection_close_forever (ctx->sock);
  GNUNET_thread_stop_sleep (ctx->poll_thread);
  GNUNET_thread_join (ctx->poll_thread, &unused);
  GNUNET_client_connection_destroy (ctx->sock);
  GNUNET_mutex_destroy (ctx->lock);
  GNUNET_free (ctx);
  return GNUNET_OK;
}

/**
 * Perform a synchronous put operation.   The peer does not have
 * to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to store
 * @param value what to store
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DHT_put (struct GNUNET_GC_Configuration *cfg,
                struct GNUNET_GE_Context *ectx,
                const GNUNET_HashCode * key,
                unsigned int type, unsigned int size, const char *value)
{
  struct GNUNET_ClientServerConnection *sock;
  CS_dht_request_put_MESSAGE *req;
  int ret;
  int ret2;

#if DEBUG_DHT_API
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "DHT_LIB_put called with value '%.*s'\n", size, value);
#endif
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    return GNUNET_SYSERR;
  req = GNUNET_malloc (sizeof (CS_dht_request_put_MESSAGE) + size);
  req->header.size = htons (sizeof (CS_dht_request_put_MESSAGE) + size);
  req->header.type = htons (GNUNET_CS_PROTO_DHT_REQUEST_PUT);
  req->key = *key;
  req->type = htonl (type);
  memcpy (&req[1], value, size);
  ret = GNUNET_client_connection_write (sock, &req->header);
  if ( (GNUNET_OK != GNUNET_client_connection_read_result (sock, &ret2)) ||
       (ret2 != GNUNET_OK) )    
    ret = GNUNET_SYSERR;
  GNUNET_client_connection_destroy (sock);
  GNUNET_free (req);
  return ret;
}

static int
waitForConnect (const char *name, unsigned long long value, void *cls)
{
  unsigned long long * ok = cls;
  if ((value > 0) && (0 == strcmp (_("# dht connections"), name)))
    {
      *ok = value;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * Check if this peer has DHT connections to 
 * any other peer.
 *
 * @param sock connection to gnunetd
 * @return number of connections
 */
unsigned long long
GNUNET_DHT_test_connected(struct GNUNET_ClientServerConnection *sock)
{
  unsigned long long ret;

  GNUNET_STATS_get_statistics (NULL, sock, &waitForConnect, &ret);
  return ret; 
}


/* end of dht_api.c */
