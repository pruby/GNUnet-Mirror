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
 * @file dht/tools/dht_api.c
 * @brief DHT-module's core API's implementation.
 * @author Tomi Tukiainen, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "dht.h"
#include "gnunet_dht_lib.h"
#include "gnunet_util.h"

#define DEBUG_DHT_API GNUNET_NO

/**
 * Data exchanged between main thread and GET thread.
 */
typedef struct
{

  /**
   * Connection with gnunetd.
   */
  struct GNUNET_ClientServerConnection *sock;

  /**
   * Callback to call for each result.
   */
  GNUNET_DataProcessor processor;

  /**
   * Extra argument for processor.
   */
  void *closure;

  /**
   * Parent thread that is waiting for the
   * timeout (used to notify if we are exiting
   * early, i.e. because of gnunetd closing the
   * connection or the processor callback requesting
   * it).
   */
  struct GNUNET_ThreadHandle *parent;

  /**
   * Are we done (for whichever reason)?
   */
  int aborted;

  /**
   * Total number of results obtained
   */
  unsigned int total;

} GetInfo;


static void *
poll_thread (void *cls)
{
  GetInfo *info = cls;
  GNUNET_MessageHeader *reply;
  CS_dht_request_put_MESSAGE *put;
  GNUNET_DataContainer *cont;
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
      if (info->processor != NULL)
        {
          cont = GNUNET_malloc (sizeof (GNUNET_DataContainer) + size);
          cont->size = htonl (sizeof (GNUNET_DataContainer) + size);
          memcpy (&cont[1], &put[1], size);
          if (GNUNET_OK != info->processor (&put->key, cont, info->closure))
            info->aborted = GNUNET_YES;
          GNUNET_free (cont);
        }
      info->total++;
      GNUNET_free (reply);
    }
  info->aborted = GNUNET_YES;
  GNUNET_thread_stop_sleep (info->parent);
  return NULL;
}


/**
 * Perform a synchronous GET operation on the DHT identified by
 * 'table' using 'key' as the key; store the result in 'result'.  If
 * result->dataLength == 0 the result size is unlimited and
 * result->data needs to be allocated; otherwise result->data refers
 * to dataLength bytes and the result is to be stored at that
 * location; dataLength is to be set to the actual size of the
 * result.
 *
 * The peer does not have to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to look up
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param maxResults maximum number of results to obtain, size of the results array
 * @param results where to store the results (on success)
 * @return number of results on success, GNUNET_SYSERR on error (i.e. timeout)
 */
int
GNUNET_DHT_get (struct GNUNET_GC_Configuration *cfg,
                struct GNUNET_GE_Context *ectx,
                unsigned int type,
                const GNUNET_HashCode * key,
                GNUNET_CronTime timeout, GNUNET_DataProcessor processor,
                void *closure)
{
  struct GNUNET_ClientServerConnection *sock;
  CS_dht_request_get_MESSAGE req;
  struct GNUNET_ThreadHandle *thread;
  GNUNET_CronTime start;
  GNUNET_CronTime now;
  GNUNET_CronTime delta;
  GetInfo info;
  void *unused;

  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    return GNUNET_SYSERR;
  req.header.size = htons (sizeof (CS_dht_request_get_MESSAGE));
  req.header.type = htons (GNUNET_CS_PROTO_DHT_REQUEST_GET);
  req.type = htonl (type);
  req.key = *key;
  if (GNUNET_OK != GNUNET_client_connection_write (sock, &req.header))
    {
      GNUNET_client_connection_destroy (sock);
      return GNUNET_SYSERR;
    }
  info.sock = sock;
  info.processor = processor;
  info.closure = closure;
  info.parent = GNUNET_thread_get_self ();
  info.aborted = GNUNET_NO;
  info.total = 0;
  thread = GNUNET_thread_create (&poll_thread, &info, 1024 * 8);
  start = GNUNET_get_time ();
  while ((start + timeout > (now = GNUNET_get_time ())) &&
         (GNUNET_shutdown_test () == GNUNET_NO)
         && (info.aborted == GNUNET_NO))
    {
      delta = (start + timeout) - now;
      if (delta > 100 * GNUNET_CRON_MILLISECONDS)
        delta = 100 * GNUNET_CRON_MILLISECONDS; /* in case we miss SIGINT
                                                   on CTRL-C */
      GNUNET_thread_sleep (delta);
    }
  info.aborted = GNUNET_YES;
  GNUNET_client_connection_close_forever (sock);
  GNUNET_thread_join (thread, &unused);
  GNUNET_thread_release_self (info.parent);
  GNUNET_client_connection_destroy (sock);
  return info.total;
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
                unsigned int type, const GNUNET_DataContainer * value)
{
  struct GNUNET_ClientServerConnection *sock;
  CS_dht_request_put_MESSAGE *req;
  int ret;

#if DEBUG_DHT_API
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "DHT_LIB_put called with value '%.*s'\n",
                 ntohl (value->size), &value[1]);
#endif
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    return GNUNET_SYSERR;
  GNUNET_GE_ASSERT (NULL,
                    ntohl (value->size) >= sizeof (GNUNET_DataContainer));
  req =
    GNUNET_malloc (sizeof (CS_dht_request_put_MESSAGE) + ntohl (value->size) -
                   sizeof (GNUNET_DataContainer));
  req->header.size =
    htons (sizeof (CS_dht_request_put_MESSAGE) + ntohl (value->size) -
           sizeof (GNUNET_DataContainer));
  req->header.type = htons (GNUNET_CS_PROTO_DHT_REQUEST_PUT);
  req->key = *key;
  req->type = htonl (type);
  memcpy (&req[1], &value[1],
          ntohl (value->size) - sizeof (GNUNET_DataContainer));
  ret = GNUNET_client_connection_write (sock, &req->header);
  GNUNET_client_connection_destroy (sock);
  GNUNET_free (req);
  return ret;
}

/* end of dht_api.c */
