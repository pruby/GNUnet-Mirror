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
 * @file tools/dht_api.c
 * @brief DHT-module's core API's implementation.
 * @author Tomi Tukiainen, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_lib.h"
#include "gnunet_dht.h"
#include "gnunet_util_network_client.h"

/**
 * Check if the given message is an ACK.  If so,
 * return the status, otherwise SYSERR.
 */
static int checkACK(MESSAGE_HEADER * reply) {
  GE_LOG(NULL,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "received ACK from gnunetd\n");
 if ( (sizeof(CS_dht_reply_ack_MESSAGE) == ntohs(reply->size)) &&
       (CS_PROTO_dht_REPLY_ACK == ntohs(reply->type)) )
    return ntohl(((CS_dht_reply_ack_MESSAGE*)reply)->status);
  return SYSERR;
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
		const DHT_TableId * table,
		unsigned int type,
		unsigned int prio,
		unsigned int keyCount,
		const HashCode512 * keys,
		cron_t timeout,
		DataProcessor processor,
		void * closure) {
  struct ClientServerConnection * sock;
  CS_dht_request_get_MESSAGE * req;
  CS_dht_reply_results_MESSAGE * res;
  MESSAGE_HEADER * reply;
  int ret;
  unsigned int size;
  DataContainer * result;

  sock = client_connection_create(ectx,
				  cfg);
  if (sock == NULL)
    return SYSERR;

  req = MALLOC(sizeof(CS_dht_request_get_MESSAGE) +
	       (keyCount-1) * sizeof(HashCode512));
  req->header.size = htons(sizeof(CS_dht_request_get_MESSAGE) +
			   (keyCount-1) * sizeof(HashCode512));
  req->header.type = htons(CS_PROTO_dht_REQUEST_GET);
  req->type = htonl(type);
  req->timeout = htonll(timeout);
  req->table = *table;
  req->priority = htonl(prio);
  memcpy(&req->keys,
	 keys,
	 keyCount * sizeof(HashCode512));
  if (OK != connection_write(sock,
			     &req->header)) {
    connection_destroy(sock);
    return SYSERR;
  }
  FREE(req);
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
		const DHT_TableId * table,
		const HashCode512 * key,
		unsigned int prio,
		cron_t timeout,
		const DataContainer * value) {
  struct ClientServerConnection * sock;
  CS_dht_request_put_MESSAGE * req;
  MESSAGE_HEADER * reply;
  int ret;

  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "DHT_LIB_put called with value '%.*s'\n",
	 ntohl(value->size),
	 &value[1]);

  sock = client_connection_create(ectx,
				  cfg);
  if (sock == NULL) {
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Could not connect to gnunetd\n");
    return SYSERR;
  }
  req = MALLOC(sizeof(CS_dht_request_put_MESSAGE) +
	       ntohl(value->size) -
	       sizeof(DataContainer));
  req->header.size
    = htons(sizeof(CS_dht_request_put_MESSAGE) +
	    ntohl(value->size) -
	    sizeof(DataContainer));
  req->header.type
    = htons(CS_PROTO_dht_REQUEST_PUT);
  req->table = *table;
  req->key = *key;
  req->priority = htonl(prio);
  req->timeout = htonll(timeout);
  memcpy(&req[1],
	 &value[1],
	 ntohl(value->size) - sizeof(DataContainer));
  ret = SYSERR;
  if (OK == connection_write(sock,
			     &req->header))
    reply = NULL;
    if (OK == connection_read(sock,
			     &reply)) {
      if (OK == checkACK(reply))
	ret = OK;
      FREE(reply);
    }
  connection_destroy(sock);
  return ret;
}

/* end of dht_api.c */
