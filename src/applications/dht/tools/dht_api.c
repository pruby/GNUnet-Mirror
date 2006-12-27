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
  int ret;

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
#if 0
  while (1) {
    reply = NULL;
    if (OK != connection_read(sock,
			      &reply)) {
      connection_destroy(sock);
      return SYSERR;
    }
    if ( (sizeof(CS_dht_reply_ack_MESSAGE) == ntohs(reply->size)) &&
	 (CS_PROTO_dht_REPLY_ACK == ntohs(reply->type)) ) {
      connection_destroy(sock);
      ret = checkACK(reply);
      FREE(reply);
      break; /* termination message, end loop! */
    }
    if ( (sizeof(CS_dht_reply_results_MESSAGE) > ntohs(reply->size)) ||
	 (CS_PROTO_dht_REPLY_GET != ntohs(reply->type)) ) {
      GE_LOG(ectx,
	     GE_WARNING | GE_BULK | GE_USER,
	     _("Unexpected reply to `%s' operation.\n"),
	     "GET");
      connection_destroy(sock);
      FREE(reply);
      return SYSERR;
    }
    /* ok, we got some replies! */
    res = (CS_dht_reply_results_MESSAGE*) reply;
    ret = ntohl(res->totalResults);

    size = ntohs(reply->size) - sizeof(CS_dht_reply_results_MESSAGE);
    result = MALLOC(size + sizeof(DataContainer));
    result->size = htonl(size + sizeof(DataContainer));
    memcpy(&result[1],
	   &res[1],
	   size);
    FREE(reply);
    processor(&keys[0],
	      result,
	      closure);
    FREE(result);
  }
#endif
  connection_destroy(sock);
  return ret;
}
	
/**
 * Perform a synchronous put operation.   The peer does not have
 * to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to store
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param value what to store
 * @return OK on success, SYSERR on error (or timeout)
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

  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "DHT_LIB_put called with value '%.*s'\n",
	 ntohl(value->size),
	 &value[1]);
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
  req->expire = htonll(expire);
  memcpy(&req[1],
	 &value[1],
	 ntohl(value->size) - sizeof(DataContainer));
  ret = connection_write(sock,
			 &req->header);
  connection_destroy(sock);
  return ret;
}

/* end of dht_api.c */
