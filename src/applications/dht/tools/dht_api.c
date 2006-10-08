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
 * Information for each table that this client is responsible
 * for.
 */
typedef struct {

  /**
   * ID of the table.
   */
  DHT_TableId table;

  /**
   * The socket that was used to join GNUnet to receive
   * requests for this table.
   */
  struct ClientServerConnection * sock;

  /**
   * The thread that is processing the requests received
   * from GNUnet on sock.
   */
  struct PTHREAD * processor;

  /**
   * The Datastore provided by the client that performs the
   * actual storage operations.
   */
  Blockstore * store;

  /**
   * Did we receive a request to leave the table?
   */
  int leave_request;

  struct MUTEX * lock;

  struct GC_Configuration * cfg;

  struct GE_Context * ectx;

} TableList;

/**
 * Connections to GNUnet helt by this module.
 */
static TableList ** tables;

/**
 * Size of the tables array.
 */
static unsigned int tableCount;

/**
 * Lock for access to tables array.
 */
static struct MUTEX * lock;

/**
 * FIXME -- avoid this global!
 */
static struct GE_Context * ectx;


/**
 * Check if the given message is an ACK.  If so,
 * return the status, otherwise SYSERR.
 */
static int checkACK(MESSAGE_HEADER * reply) {
  GE_LOG(ectx, 
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "received ACK from gnunetd\n");
  if ( (sizeof(CS_dht_reply_ack_MESSAGE) == ntohs(reply->size)) &&
       (CS_PROTO_dht_REPLY_ACK == ntohs(reply->type)) )
    return ntohl(((CS_dht_reply_ack_MESSAGE*)reply)->status);
  return SYSERR;
}

/**
 * Send an ACK message of the given value to gnunetd.
 */
static int sendAck(struct ClientServerConnection * sock,
		   DHT_TableId * table,
		   int value) {
  CS_dht_reply_ack_MESSAGE msg;

  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "sending ACK to gnunetd\n");
  msg.header.size = htons(sizeof(CS_dht_reply_ack_MESSAGE));
  msg.header.type = htons(CS_PROTO_dht_REPLY_ACK);
  msg.status = htonl(value);
  msg.table = *table;
  return connection_write(sock,
		       &msg.header);
}

static int sendAllResults(const HashCode512 * key,
			  const DataContainer * value,
			  void * cls) {
  TableList * list = (TableList*) cls;
  CS_dht_reply_results_MESSAGE * reply;

  reply = MALLOC(sizeof(CS_dht_reply_results_MESSAGE) + ntohl(value->size) + sizeof(HashCode512));
  reply->header.size = htons(sizeof(CS_dht_reply_results_MESSAGE) + ntohl(value->size) + sizeof(HashCode512));
  reply->header.type = htons(CS_PROTO_dht_REPLY_GET);
  reply->totalResults = htonl(1);
  reply->table = list->table;
  reply->key = *key;
  memcpy(&reply->data,
	 value,
	 ntohl(value->size));
  if (OK != connection_write(list->sock,
			  &reply->header)) {
    GE_LOG(ectx, 
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Failed to send `%s'.  Closing connection.\n"),
	   "CS_dht_reply_results_MESSAGE");
    MUTEX_LOCK(list->lock);
    connection_destroy(list->sock);
    list->sock = NULL;
    MUTEX_UNLOCK(list->lock);
    FREE(reply);
    return SYSERR;
  }
  FREE(reply);
  return OK;

}

/**
 * Thread that processes requests from gnunetd (by forwarding
 * them to the implementation of list->store).
 */
static void * process_thread(void * cls) {
  TableList * list = cls;
  MESSAGE_HEADER * buffer;
  MESSAGE_HEADER * reply;
  CS_dht_request_join_MESSAGE req;
  int ok;

  req.header.size = htons(sizeof(CS_dht_request_join_MESSAGE));
  req.header.type = htons(CS_PROTO_dht_REQUEST_JOIN);
  req.table = list->table;

  while (list->leave_request == NO) {
    if (list->sock == NULL) {
      PTHREAD_SLEEP(500 * cronMILLIS);
      MUTEX_LOCK(list->lock);
      if (list->leave_request == NO)
	list->sock  = client_connection_create(ectx,
					       list->cfg);
      MUTEX_UNLOCK(list->lock);
    }
    if (list->sock == NULL)
      continue;

    ok = NO;
    /* send 'join' message via socket! */
    if (OK == connection_write(list->sock,
			       &req.header)) {
      reply = NULL;
      if (OK == connection_read(list->sock,
				&reply)) {
	if (OK == checkACK(reply))
	  ok = YES;
	FREENONNULL(reply);
      }
    }
    if (ok == NO) {
      MUTEX_LOCK(list->lock);
      connection_destroy(list->sock);
      list->sock = NULL;
      MUTEX_UNLOCK(list->lock);
      continue; /* retry... */
    }

    buffer = NULL;
    while (OK == connection_read(list->sock,
				&buffer)) {
      GE_LOG(ectx, 
	     GE_DEBUG | GE_REQUEST | GE_USER,
	     "Received message of type %d from gnunetd\n",
	     ntohs(buffer->type));

      switch (ntohs(buffer->type)) {
      case CS_PROTO_dht_REQUEST_GET: {
	CS_dht_request_get_MESSAGE * req;
	int resCount;
	int keyCount;

	if (sizeof(CS_dht_request_get_MESSAGE) != ntohs(buffer->size)) {
	  GE_LOG(ectx,
		 GE_ERROR | GE_BULK | GE_USER,
		 _("Received invalid `%s' request (size %d)\n"),
		 "GET",
		 ntohs(buffer->size));
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	  FREE(buffer);
	}
	req = (CS_dht_request_get_MESSAGE*) buffer;
	if (0 != memcmp(&req->table,
			&list->table,
			sizeof(HashCode512))) {
	  GE_LOG(ectx,
		 GE_ERROR | GE_BULK | GE_USER,
		 _("Received invalid `%s' request (wrong table)\n"),
		 "GET");
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	  break;
	}
	
	keyCount = 1 + ( (ntohs(req->header.size) - sizeof(CS_dht_request_get_MESSAGE)) / sizeof(HashCode512));
	resCount = list->store->get(list->store->closure,
				    ntohl(req->type),
				    ntohl(req->priority),
				    keyCount,
				    &req->keys,	
				    &sendAllResults,
				    list);
	if ( (resCount != SYSERR) &&
	     (OK != sendAck(list->sock,
			    &list->table,
			    resCount)) ) {
	  GE_LOG(ectx,
		 GE_WARNING | GE_BULK | GE_USER,
		 _("Failed to send `%s'.  Closing connection.\n"),
		 "ACK");
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	}
	break;
      }
	
	
      case CS_PROTO_dht_REQUEST_PUT: {
	CS_dht_request_put_MESSAGE * req;
	DataContainer * value;
	
	if (sizeof(CS_dht_request_put_MESSAGE) > ntohs(buffer->size)) {
	  GE_LOG(ectx,
		 GE_ERROR | GE_BULK | GE_USER,
		 _("Received invalid `%s' request (size %d)\n"),
		 "PUT",
	      ntohs(buffer->size));
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	  break;
	}
	req = (CS_dht_request_put_MESSAGE*) buffer;
	if (0 != memcmp(&req->table,
			&list->table,
			sizeof(HashCode512))) {
	  GE_LOG(ectx,
		 GE_ERROR | GE_BULK | GE_USER,
		 _("Received invalid `%s' request (wrong table)\n"),
		 "PUT");
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	  break;
	}
	value = MALLOC(sizeof(DataContainer) +
		       ntohs(buffer->size) - sizeof(CS_dht_request_put_MESSAGE));
	value->size = htonl(sizeof(DataContainer) +
			    ntohs(buffer->size) - sizeof(CS_dht_request_put_MESSAGE));
	memcpy(&value[1],
	       &req[1],
	       ntohs(buffer->size) - sizeof(CS_dht_request_put_MESSAGE));
	if (OK !=
	    sendAck(list->sock,
		    &req->table,
		    list->store->put(list->store->closure,
				     &req->key,
				     value,
				     ntohl(req->priority)))) {
	  GE_LOG(ectx, 
		 GE_ERROR | GE_BULK | GE_USER,
		 _("Failed to send `%s'.  Closing connection.\n"),
		 "ACK");
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	}
	FREE(value);
	break;
      }


      case CS_PROTO_dht_REQUEST_REMOVE: {
	CS_dht_request_remove_MESSAGE * req;
	DataContainer * value;
	
	if (sizeof(CS_dht_request_remove_MESSAGE) > ntohs(buffer->size)) {
	  GE_LOG(ectx, 
		 GE_ERROR | GE_BULK | GE_USER,
		 _("Received invalid `%s' request (size %d)\n"),
		 "REMOVE",
	      ntohs(buffer->size));
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	  break;
	}
	req = (CS_dht_request_remove_MESSAGE*) buffer;
	if (0 != memcmp(&req->table,
			&list->table,
			sizeof(HashCode512))) {
	  GE_LOG(ectx,
		 GE_ERROR | GE_BULK | GE_USER,
		 _("Received invalid `%s' request (wrong table)\n"),
		 "REMOVE");
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	  break;
	}

	value = MALLOC(sizeof(DataContainer) +
		       ntohs(buffer->size) - sizeof(CS_dht_request_remove_MESSAGE));
	value->size = htonl(sizeof(DataContainer) +
			    ntohs(buffer->size) - sizeof(CS_dht_request_remove_MESSAGE));
	memcpy(&value[1],
	       &req[1],
	       ntohs(buffer->size) - sizeof(CS_dht_request_remove_MESSAGE));
	if (OK !=
	    sendAck(list->sock,
		    &req->table,
		    list->store->del(list->store->closure,
				     &req->key,
				     value))) {
	  GE_LOG(ectx, 
		 GE_ERROR | GE_BULK | GE_USER,
		 _("Failed to send `%s'.  Closing connection.\n"),
		 "ACK");
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	}
	FREE(value);
	break;
      }
	
      case CS_PROTO_dht_REQUEST_ITERATE: {
	CS_dht_request_iterate_MESSAGE * req;
	int resCount;

	if (sizeof(CS_dht_request_iterate_MESSAGE) != ntohs(buffer->size)) {
	  GE_LOG(ectx, 
		 GE_ERROR | GE_BULK | GE_USER,
		 _("Received invalid `%s' request (size %d)\n"),
		 "ITERATE",
	      ntohs(buffer->size));
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	  FREE(buffer);
	}
	req = (CS_dht_request_iterate_MESSAGE*) buffer;
	resCount = list->store->iterate(list->store->closure,
					&sendAllResults,
					list);
	if (OK != sendAck(list->sock,
					  &list->table,
					  resCount)) {
	  GE_LOG(ectx, 
		 GE_WARNING | GE_BULK | GE_USER,
		 _("Failed to send `%s'.  Closing connection.\n"),
		 "ACK");
	  MUTEX_LOCK(list->lock);
	  connection_destroy(list->sock);
	  list->sock = NULL;
	  MUTEX_UNLOCK(list->lock);
	}
	break;
      }


      default:
	GE_LOG(ectx, 
	       GE_ERROR | GE_BULK | GE_USER,
	       _("Received unknown request type %d at %s:%d\n"),
	       ntohs(buffer->type),
	    __FILE__, __LINE__);
	MUTEX_LOCK(list->lock);
	connection_destroy(list->sock);
	list->sock = NULL;
	MUTEX_UNLOCK(list->lock);
      } /* end of switch */
      FREE(buffer);
      buffer = NULL;
    }
    MUTEX_LOCK(list->lock);
    connection_destroy(list->sock);
    list->sock = NULL;
    MUTEX_UNLOCK(list->lock);
  }

  return NULL;
}


/**
 * Join a table (start storing data for the table).  Join
 * fails if the node is already joint with the particular
 * table.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @return SYSERR on error, OK on success
 */
int DHT_LIB_join(Blockstore * store,
		 struct GC_Configuration * cfg,
		 struct GE_Context * ectx,
		 const DHT_TableId * table) {
  TableList * list;
  int i;

  MUTEX_LOCK(lock);
  for (i=0;i<tableCount;i++)
    if (0 == memcmp(&tables[i]->table,
		    table,
		    sizeof(HashCode512))) {
      GE_LOG(ectx,
	     GE_WARNING | GE_BULK | GE_USER,
	     _("This client already participates in the given DHT!\n"));
      MUTEX_UNLOCK(lock);
      return SYSERR;
    }
  list = MALLOC(sizeof(TableList));
  list->cfg = cfg;
  list->ectx = ectx;
  list->table = *table;
  list->store = store;
  list->leave_request = NO;
  list->sock = client_connection_create(ectx,
					cfg);
  if (list->sock == NULL) {
    FREE(list);
    MUTEX_UNLOCK(lock);
    return SYSERR;
  }
  list->lock = MUTEX_CREATE(NO);
  list->processor = PTHREAD_CREATE(&process_thread,
				   list,
				   32 * 1024);
  if (list->processor == NULL) {
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_ADMIN | GE_USER | GE_BULK,
		    "pthread_create");
    connection_destroy(list->sock);
    MUTEX_DESTROY(list->lock);
    FREE(list);
    MUTEX_UNLOCK(lock);
    return SYSERR;
  }
  GROW(tables,
       tableCount,
       tableCount+1);
  tables[tableCount-1] = list;
  MUTEX_UNLOCK(lock);
  return OK;
}


/**
 * Leave a table (stop storing data for the table).  Leave
 * fails if the node is not joint with the table.
 *
 * @param datastore the storage callbacks to use for the table
 * @param table the ID of the table
 * @return SYSERR on error, OK on success
 */
int DHT_LIB_leave(const DHT_TableId * table) {
  TableList * list;
  int i;
  void * unused;
  CS_dht_request_leave_MESSAGE req;
  MESSAGE_HEADER * reply;
  int ret;
  struct ClientServerConnection * sock;

  list = NULL;
  MUTEX_LOCK(lock);
  for (i=0;i<tableCount;i++) {
    if (0 == memcmp(&tables[i]->table,
		    table,
		    sizeof(HashCode512))) {
      list = tables[i];
      tables[i] = tables[tableCount-1];
      GROW(tables,
	   tableCount,
	   tableCount-1);
      break;
    }
  }
  MUTEX_UNLOCK(lock);
  if (list == NULL) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Cannot leave DHT: table not known!\n"));
    return SYSERR; /* no such table! */
  }

  list->leave_request = YES;
  /* send LEAVE message! */
  req.header.size = htons(sizeof(CS_dht_request_leave_MESSAGE));
  req.header.type = htons(CS_PROTO_dht_REQUEST_LEAVE);
  req.table = *table;

  ret = SYSERR;
  sock = client_connection_create(list->ectx,
				  list->cfg);
  if (sock != NULL) {
    if (OK == connection_write(sock,
			       &req.header)) {
      reply = NULL;
      if (OK == connection_read(sock,
			       &reply)) {
	if (OK == checkACK(reply))
	  ret = OK;	
	else
	  GE_LOG(ectx, GE_WARNING | GE_BULK | GE_USER,
	      _("gnunetd signaled error in response to `%s' message\n"),
	      "CS_dht_request_leave_MESSAGE");      	
	FREE(reply);
      } else {
	GE_LOG(ectx, GE_WARNING | GE_BULK | GE_USER,
	    _("Failed to receive response to `%s' message from gnunetd\n"),
	    "CS_dht_request_leave_MESSAGE");
      }
    } else {
      GE_LOG(ectx, GE_WARNING | GE_BULK | GE_USER,
	  _("Failed to send `%s' message to gnunetd\n"),
	  "CS_dht_request_leave_MESSAGE");
    }
    connection_destroy(sock);
  }
  MUTEX_LOCK(list->lock);
  if (list->sock != NULL)
    connection_close_temporarily(list->sock); /* signal process_thread */
  MUTEX_UNLOCK(list->lock);
  unused = NULL;
  PTHREAD_JOIN(list->processor, &unused);
  if (list->sock != NULL)
    connection_destroy(list->sock);
  MUTEX_DESTROY(list->lock);
  FREE(list);
  return ret;
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
      GE_LOG(ectx, GE_WARNING | GE_BULK | GE_USER,
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
  if (sock == NULL)
    return SYSERR;
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

/**
 * Perform a synchronous remove operation.  The peer does not have
 * to be part of the table!
 *
 * @param table table to use for the lookup
 * @param key the key to store
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param value what to remove; NULL for all values matching the key
 * @return OK on success, SYSERR on error (or timeout)
 */
int DHT_LIB_remove(struct GC_Configuration * cfg,
		   struct GE_Context * ectx,
		   const DHT_TableId * table,
		   const HashCode512 * key,
		   cron_t timeout,
		   const DataContainer * value) {
  struct ClientServerConnection * sock;
  CS_dht_request_remove_MESSAGE * req;
  MESSAGE_HEADER * reply;
  int ret;
  size_t n;

  sock = client_connection_create(ectx, cfg);
  if (sock == NULL)
    return SYSERR;
  n = sizeof(CS_dht_request_remove_MESSAGE);
  if (value != NULL)
    n += ntohl(value->size) - sizeof(DataContainer);
  req = MALLOC(n);
  req->header.size = htons(n);
  req->header.type = htons(CS_PROTO_dht_REQUEST_REMOVE);
  req->table = *table;
  req->key = *key;
  req->timeout = htonll(timeout);
  if (value != NULL)
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


/**
 * Initialize DHT_LIB. 
 */
void __attribute__ ((constructor)) DHT_LIB_init() {
  lock = MUTEX_CREATE(NO);
}

/**
 * Shutdown DHT_LIB. 
 */
void __attribute__ ((destructor))  DHT_LIB_fini() {
  MUTEX_DESTROY(lock);
}


/* end of dht_api.c */
