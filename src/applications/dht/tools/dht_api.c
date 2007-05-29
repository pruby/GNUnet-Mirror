/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util_network_client.h"

#define DEBUG_DHT_API NO

/**
 * Data exchanged between main thread and GET thread.
 */
typedef struct {

  /**
   * Connection with gnunetd.
   */
  struct ClientServerConnection * sock;

  /**
   * Callback to call for each result.
   */
  DataProcessor processor;

  /**
   * Extra argument for processor.
   */
  void * closure;

  /**
   * Parent thread that is waiting for the
   * timeout (used to notify if we are exiting
   * early, i.e. because of gnunetd closing the
   * connection or the processor callback requesting
   * it).
   */
  struct PTHREAD * parent;

  /**
   * Are we done (for whichever reason)?
   */
  int aborted;

  /**
   * Total number of results obtained, or -1 on error.
   */
  int total;
} GetInfo;


static void * 
poll_thread(void * cls) {
  GetInfo * info = cls;
  MESSAGE_HEADER * reply;
  CS_dht_request_put_MESSAGE * put;
  DataContainer * cont;
  unsigned short size;

  while (info->aborted == NO) {
    if (connection_test_open(info->sock) == 0) 
      break;
    reply = NULL;
    if (OK != connection_read(info->sock,
			      &reply)) 
      break;
    if ( (sizeof(CS_dht_request_put_MESSAGE) > ntohs(reply->size)) ||
	 (CS_PROTO_dht_REQUEST_PUT != ntohs(reply->type)) ) {
      GE_BREAK(NULL, 0);
      info->total = SYSERR;
      break; /*  invalid reply */
    }
  
    put = (CS_dht_request_put_MESSAGE*) reply;
    /* re-use "expire" field of the reply (which is 0 anyway)
       for the header of DataContainer (which fits) to avoid
       copying -- go C pointer arithmetic! */
    cont = (DataContainer*) &((char *) &put[1])[-sizeof(DataContainer)];
    size = ntohs(reply->size) - sizeof(CS_dht_request_put_MESSAGE);
    cont->size = htonl(size + sizeof(DataContainer));
    if ( (info->processor != NULL) &&
	 (OK != info->processor(&put->key,
				cont,
				info->closure)) )
      info->aborted = YES;    
    info->total++;
    FREE(reply);
  }
  info->aborted = YES;
  PTHREAD_STOP_SLEEP(info->parent);
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
 * @return number of results on success, SYSERR on error (i.e. timeout)
 */
int DHT_LIB_get(struct GC_Configuration * cfg,
		struct GE_Context * ectx,
		unsigned int type,
		const HashCode512 * key,
		cron_t timeout,
		DataProcessor processor,
		void * closure) {
  struct ClientServerConnection * sock;
  CS_dht_request_get_MESSAGE req;
  struct PTHREAD * thread;
  cron_t start;
  cron_t now;
  cron_t delta;
  GetInfo info;
  void * unused;

  sock = client_connection_create(ectx,
				  cfg);
  if (sock == NULL)
    return SYSERR;
  req.header.size = htons(sizeof(CS_dht_request_get_MESSAGE));
  req.header.type = htons(CS_PROTO_dht_REQUEST_GET);
  req.type = htonl(type);
  req.timeout = htonll(timeout);
  req.key = *key;
  if (OK != connection_write(sock,
			     &req.header)) {
    connection_destroy(sock);
    return SYSERR;
  }
  info.sock = sock;
  info.processor = processor;
  info.closure = closure;
  info.parent = PTHREAD_GET_SELF();
  info.aborted = NO;
  info.total = 0;
  thread = PTHREAD_CREATE(&poll_thread,
			  &info,
			  1024 * 8);
  start = get_time();
  while ( (start + timeout > (now = get_time())) &&
	  (GNUNET_SHUTDOWN_TEST() == NO) &&
	  (info.aborted == NO) ) {
    delta =(start + timeout) - now;
    if (delta > 100 * cronMILLIS)
      delta = 100 * cronMILLIS; /* in case we miss SIGINT
				   on CTRL-C */
    PTHREAD_SLEEP(delta);
  }
  info.aborted = YES;
  connection_close_forever(sock);
  PTHREAD_JOIN(thread, &unused);
  PTHREAD_REL_SELF(info.parent);
  connection_destroy(sock);
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
 * @return OK on success, SYSERR on error
 */
int DHT_LIB_put(struct GC_Configuration * cfg,
		struct GE_Context * ectx,
		const HashCode512 * key,
		unsigned int type,
		cron_t expire,
		const DataContainer * value) {
  struct ClientServerConnection * sock;
  CS_dht_request_put_MESSAGE * req;
  int ret;
  cron_t now;

  now = get_time();
  if (expire < now) {
    GE_BREAK(ectx, 0); /* content already expired!? */
    return SYSERR;
  }
#if DEBUG_DHT_API
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "DHT_LIB_put called with value '%.*s'\n",
	 ntohl(value->size),
	 &value[1]);
#endif
  sock = client_connection_create(ectx,
				  cfg);
  if (sock == NULL) 
    return SYSERR;
  GE_ASSERT(NULL,
	    ntohl(value->size) >= sizeof(DataContainer));
  req = MALLOC(sizeof(CS_dht_request_put_MESSAGE) +
	       ntohl(value->size) -
	       sizeof(DataContainer));
  req->header.size
    = htons(sizeof(CS_dht_request_put_MESSAGE) +
	    ntohl(value->size) -
	    sizeof(DataContainer));
  req->header.type
    = htons(CS_PROTO_dht_REQUEST_PUT);
  req->key = *key;
  req->type = htonl(type);
  req->expire = htonll(expire - now); /* convert to relative time */
  memcpy(&req[1],
	 &value[1],
	 ntohl(value->size) - sizeof(DataContainer));
  ret = connection_write(sock,
			 &req->header);
  connection_destroy(sock);
  FREE(req);
  return ret;
}

/* end of dht_api.c */
