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

#include "dht_api.h"

#define DEBUG_DHT_API GNUNET_NO

static void *
poll_thread (void *cls)
{
  struct GNUNET_DHT_Context *info = cls;
  GNUNET_MessageHeader *reply;
  CS_dht_request_put_MESSAGE *put;
  unsigned int size;

  while (info->aborted == GNUNET_NO)
    {
      if (GNUNET_client_connection_test_connected (info->sock) == 0)
        break;
      reply = NULL;
      if (GNUNET_OK != GNUNET_client_connection_read (info->sock, &reply))
        break;
      if ((sizeof (CS_dht_request_put_MESSAGE) > ntohs (reply->size)) ||
          (GNUNET_CS_PROTO_DHT_REQUEST_PUT != ntohs (reply->type)))
        {
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
  GNUNET_thread_stop_sleep (info->poll_thread);
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
  ctx->sock = sock;
  ctx->closure = resCallbackClosure;
  ctx->processor = resultCallback;
  ctx->poll_thread = GNUNET_thread_create (&poll_thread, ctx, 1024 * 8);
  ctx->aborted = GNUNET_NO;
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
int
GNUNET_DHT_get_start (struct GNUNET_DHT_Context *ctx,
                      unsigned int type, const GNUNET_HashCode * key)
{
  CS_dht_request_get_MESSAGE req;

  if (ctx->sock == NULL)
    return GNUNET_SYSERR;
  req.header.size = htons (sizeof (CS_dht_request_get_MESSAGE));
  req.header.type = htons (GNUNET_CS_PROTO_DHT_REQUEST_GET);
  req.type = htonl (type);
  req.key = *key;
  if (GNUNET_OK != GNUNET_client_connection_write (ctx->sock, &req.header))
    {
      return GNUNET_SYSERR;
    }

  return GNUNET_OK;
}


/**
 * Stop an asynchronous GET operation on the DHT looking for
 * key.
 * @param type the type of key to look up
 * @param key the key to look up
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_DHT_get_stop (struct GNUNET_DHT_Context *ctx,
                     unsigned int type, const GNUNET_HashCode * key)
{

  CS_dht_request_get_MESSAGE req;

  if (ctx->sock == NULL)
    return GNUNET_SYSERR;
  req.header.size = htons (sizeof (CS_dht_request_get_MESSAGE));
  req.header.type = htons (GNUNET_CS_PROTO_DHT_REQUEST_GET_END);
  req.type = htonl (type);
  req.key = *key;
  if (GNUNET_OK != GNUNET_client_connection_write (ctx->sock, &req.header))
    {
      return GNUNET_SYSERR;
    }

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
  ctx->aborted = GNUNET_YES;
  GNUNET_client_connection_close_forever (ctx->sock);
  GNUNET_thread_join (ctx->poll_thread, &unused);
  GNUNET_client_connection_destroy (ctx->sock);
  return GNUNET_OK;
}

/**
 * Perform a synchronous put operation.   The peer does not have
 * to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to store
 * @param expire how long until the content should expire (absolute time)
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
  GNUNET_client_connection_destroy (sock);
  GNUNET_free (req);
  return ret;
}

/* end of dht_api.c */
