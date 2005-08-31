/*
      This file is part of GNUnet

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
 * @file module/cs.c
 * @brief DHT application protocol using the DHT service.
 *   This is merely for the dht-client library.  The code
 *   of this file is mostly converting from and to TCP messages.
 * @author Marko Räihä, Christian Grothoff
 */

#include "platform.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "gnunet_rpc_service.h"
#include "gnunet_dht_service.h"

/**
 * Global core API.
 */
static CoreAPIForApplication * coreAPI = NULL;

/**
 * Reference to the DHT service API.
 */
static DHT_ServiceAPI * dhtAPI;

/**
 * Information for each table for which persistence is provided
 * by a local client via the TCP link.
 */
typedef struct {
  /**
   * Handle to access the client.
   */
  ClientHandle handler;
  /**
   * For which table is this client responsible?
   */
  DHT_TableId table;

  /**
   * What was the Blockstore that was passed to the DHT service?
   * (must be a pointer since this reference is passed out).
   */
  Blockstore * store;

  /**
   * Semaphore that is aquired before using the maxResults
   * and results fields for sending a request to the client.
   * Released after the request has been processed.
   */
  Semaphore * prerequest;

  /**
   * Semaphore that is up'ed by the client handler whenever a reply
   * was received.  The client exit handler also needs to up this
   * semaphore to unblock threads that wait for replies.
   */
  Semaphore * prereply;

  /**
   * Semaphore that is down'ed by the client handler before storing
   * the data from a reply.  The cs-functions need to up it
   * once they have prepared the handlers.
   */
  Semaphore * postreply;

  /**
   * Function to call for results
   */
  DataProcessor resultCallback;

  /**
   * Extra argument to result callback.
   */
  void * resultCallbackClosure;

  /**
   * Status value; used to communciate errors (typically using
   * SYSERR/OK or number of results).
   */
  int status;

} DHT_CLIENT_TableHandlers;

typedef struct {
  ClientHandle client;
  struct DHT_PUT_RECORD * put_record;
  DHT_TableId table;
  unsigned int replicas; /* confirmed puts? */
} DHT_CLIENT_PUT_RECORD;

typedef struct {
  ClientHandle client;
  struct DHT_REMOVE_RECORD * remove_record;
  DHT_TableId table;
  unsigned int replicas; /* confirmed dels? */
} DHT_CLIENT_REMOVE_RECORD;

typedef struct {
  ClientHandle client;
  struct DHT_GET_RECORD * get_record;
  DHT_TableId table;
  unsigned int count;
} DHT_CLIENT_GET_RECORD;

static DHT_CLIENT_GET_RECORD ** getRecords;

static unsigned int getRecordsSize;

static DHT_CLIENT_PUT_RECORD ** putRecords;

static unsigned int putRecordsSize;

static DHT_CLIENT_REMOVE_RECORD ** removeRecords;

static unsigned int removeRecordsSize;

/**
 * If clients provide a datastore implementation for a table,
 * we keep the corresponding client handler in this array.
 */
static DHT_CLIENT_TableHandlers ** csHandlers;

/**
 * Size of the csHandlers array.
 */
static unsigned int csHandlersCount;

/**
 * Lock for accessing csHandlers.
 */
static Mutex csLock;

/* ******* implementation of Blockstore via TCP link ********** */

/**
 * Lookup an item in the datastore.
 *
 * @param key the value to lookup
 * @param maxResults maximum number of results
 * @param results where to store the result
 * @return number of results, SYSERR on error
 */
static int tcp_get(void * closure,
		   unsigned int type,
		   unsigned int prio,
		   unsigned int keyCount,
		   const HashCode512 * keys,
		   DataProcessor resultCallback,
		   void * resCallbackClosure) {
  CS_dht_request_get_MESSAGE * req;
  unsigned short size;
  DHT_CLIENT_TableHandlers * handlers = closure;
  int ret;

  if (keyCount < 1)
    return SYSERR;

  SEMAPHORE_DOWN(handlers->prerequest);
  handlers->resultCallback = resultCallback;
  handlers->resultCallbackClosure = resCallbackClosure;
  handlers->status = 0;
  size = sizeof(CS_dht_request_get_MESSAGE) +
    (keyCount-1) * sizeof(HashCode512);
  if (((unsigned int)size)
      != sizeof(CS_dht_request_get_MESSAGE) +
      (keyCount-1) * sizeof(HashCode512)) {
    SEMAPHORE_UP(handlers->prerequest);
    return SYSERR; /* too many keys, size > rangeof(short) */
  }
  req = MALLOC(size);
  req->header.size = htons(size);
  req->header.type = htons(CS_PROTO_dht_REQUEST_GET);
  req->type = htonl(type);
  req->priority = htonl(prio);
  req->table = handlers->table;
  memcpy(&req->keys,
	 keys,
	 sizeof(HashCode512) * keyCount);
  req->timeout = htonll(0);
  if (OK != coreAPI->sendToClient(handlers->handler,
				  &req->header)) {
    SEMAPHORE_UP(handlers->prerequest);
    return SYSERR;
  }
  FREE(req);
  SEMAPHORE_UP(handlers->postreply);
  SEMAPHORE_DOWN(handlers->prereply);
  ret = handlers->status;
  SEMAPHORE_UP(handlers->prerequest);
  return ret;
}

/**
 * Store an item in the datastore.
 *
 * @param key the key of the item
 * @param value the value to store
 * @param prio the priority for the store
 * @return OK if the value could be stored, SYSERR if not (i.e. out of space)
 */
static int tcp_put(void * closure,
		   const HashCode512 * key,
		   const DataContainer * value,
		   unsigned int prio) {
  CS_dht_request_put_MESSAGE * req;
  DHT_CLIENT_TableHandlers * handlers = closure;
  int ret;
  size_t n;

  n = sizeof(CS_dht_request_put_MESSAGE) + ntohl(value->size);
  req = MALLOC(n);
  SEMAPHORE_DOWN(handlers->prerequest);
  handlers->status = 0;
  req->header.size = htons(n);
  req->header.type = htons(CS_PROTO_dht_REQUEST_PUT);
  req->table = handlers->table;
  req->key = *key;
  req->timeout = htonl(0);
  req->priority = htonl(prio);
  memcpy(&req[1],
	 value,
	 ntohl(value->size));
  if (OK != coreAPI->sendToClient(handlers->handler,
				  &req->header)) {
    FREE(req);
    SEMAPHORE_UP(handlers->prerequest);
    return SYSERR;
  }
  FREE(req);
  LOG(LOG_EVERYTHING,
      "Sending STORE request to client!\n");
  SEMAPHORE_UP(handlers->postreply);
  SEMAPHORE_DOWN(handlers->prereply);
  ret = handlers->status;
  LOG(LOG_EVERYTHING,
      "Client confirmed STORE request with status %d!\n",
      ret);
  SEMAPHORE_UP(handlers->prerequest);
  return ret;
}

/**
 * Remove an item from the datastore.
 * @param key the key of the item
 * @param value the value to remove, NULL for all values of the key
 * @return OK if the value could be removed, SYSERR if not (i.e. not present)
 */
static int tcp_del(void * closure,
		   const HashCode512 * key,
		   const DataContainer * value) {
  CS_dht_request_remove_MESSAGE * req;
  DHT_CLIENT_TableHandlers * handlers = closure;
  int ret;
  size_t n;

  n = sizeof(CS_dht_request_remove_MESSAGE);
  if (value != NULL)
    n += htonl(value->size);
  req = MALLOC(n);
  SEMAPHORE_DOWN(handlers->prerequest);
  handlers->status = 0;
  req->header.size = htons(n);
  req->header.type = htons(CS_PROTO_dht_REQUEST_REMOVE);
  req->table = handlers->table;
  req->key = *key;
  req->timeout = htonl(0);
  if (value != NULL)
    memcpy(&req[1],
	   value,
	   htonl(value->size));
  if (OK != coreAPI->sendToClient(handlers->handler,
				  &req->header)) {
    FREE(req);
    SEMAPHORE_UP(handlers->prerequest);
    return SYSERR;
  }
  FREE(req);
  SEMAPHORE_UP(handlers->postreply);
  SEMAPHORE_DOWN(handlers->prereply);
  ret = handlers->status;
  SEMAPHORE_UP(handlers->prerequest);
  return ret;
}

/**
 * Iterate over all keys in the local datastore
 *
 * @param processor function to call on each item
 * @param cls argument to processor
 * @return number of results, SYSERR on error
 */
static int tcp_iterate(void * closure,		
		       DataProcessor processor,
		       void * cls) {
  CS_dht_request_iterate_MESSAGE req;
  DHT_CLIENT_TableHandlers * handlers = closure;
  int ret;

  SEMAPHORE_DOWN(handlers->prerequest);
  handlers->status = 0;
  handlers->resultCallback = processor;
  handlers->resultCallbackClosure = cls;
  req.header.size = htons(sizeof(CS_dht_request_iterate_MESSAGE));
  req.header.type = htons(CS_PROTO_dht_REQUEST_ITERATE);
  if (OK != coreAPI->sendToClient(handlers->handler,
				  &req.header)) {
    SEMAPHORE_UP(handlers->prerequest);
    return SYSERR;
  }
  SEMAPHORE_UP(handlers->postreply);
  SEMAPHORE_DOWN(handlers->prereply);
  ret = handlers->status;
  SEMAPHORE_UP(handlers->prerequest);
  return ret;
}

/* *********************** CS handlers *********************** */

static int sendAck(ClientHandle client,
		   DHT_TableId * table,
		   int value) {
  CS_dht_reply_ack_MESSAGE msg;

  msg.header.size = htons(sizeof(CS_dht_reply_ack_MESSAGE));
  msg.header.type = htons(CS_PROTO_dht_REPLY_ACK);
  msg.status = htonl(value);
  msg.table = *table;
  return coreAPI->sendToClient(client,
			       &msg.header);
}

/**
 * CS handler for joining existing DHT-table.
 */
static int csJoin(ClientHandle client,
                  const CS_MESSAGE_HEADER * message) {
  DHT_CLIENT_TableHandlers * ptr;
  CS_dht_request_join_MESSAGE * req;
  int ret;

  if (ntohs(message->size) != sizeof(CS_dht_request_join_MESSAGE))
    return SYSERR;
  req = (CS_dht_request_join_MESSAGE*) message;
  MUTEX_LOCK(&csLock);
  ptr = MALLOC(sizeof(DHT_CLIENT_TableHandlers));
  ptr->store = MALLOC(sizeof(Blockstore));
  ptr->store->iterate = &tcp_iterate;
  ptr->store->del = &tcp_del;
  ptr->store->put = &tcp_put;
  ptr->store->get = &tcp_get;
  ptr->store->closure = ptr;
  ptr->handler = client;
  ptr->table = req->table;
  ptr->prerequest = SEMAPHORE_NEW(1);
  ptr->prereply   = SEMAPHORE_NEW(0);
  ptr->postreply  = SEMAPHORE_NEW(0);
  ret = dhtAPI->join(ptr->store,
		     &req->table);
  if (ret == OK) {
    GROW(csHandlers,
	 csHandlersCount,
	 csHandlersCount+1);
    csHandlers[csHandlersCount-1] = ptr;
  } else {
    SEMAPHORE_FREE(ptr->prerequest);
    SEMAPHORE_FREE(ptr->prereply);
    SEMAPHORE_FREE(ptr->postreply);
    FREE(ptr->store);
    FREE(ptr);
  }
  ret = sendAck(client,
		&req->table,
		ret);
  MUTEX_UNLOCK(&csLock);
  return ret;
}

/**
 * CS handler for leaving DHT-table.
 */
static int csLeave(ClientHandle client,
                   const CS_MESSAGE_HEADER * message) {

  CS_dht_request_leave_MESSAGE * req;
  int i;
  DHT_CLIENT_TableHandlers * ptr;

  if (ntohs(message->size) != sizeof(CS_dht_request_leave_MESSAGE))
    return SYSERR;
  req = (CS_dht_request_leave_MESSAGE*) message;
  LOG(LOG_EVERYTHING,
      "Client leaving request received!\n");

  MUTEX_LOCK(&csLock);
  for (i=0;i<csHandlersCount;i++) {
    ptr = csHandlers[i];
    if ( (equalsHashCode512(&ptr->table,
			    &req->table)) ) {
      csHandlers[i] = csHandlers[csHandlersCount-1];
      GROW(csHandlers,
	   csHandlersCount,
	   csHandlersCount-1);
      MUTEX_UNLOCK(&csLock);

      /* release clients waiting on this DHT */
      ptr->status = SYSERR;
      SEMAPHORE_UP(ptr->prereply);
      SEMAPHORE_DOWN(ptr->prerequest);
      SEMAPHORE_FREE(ptr->prerequest);
      SEMAPHORE_FREE(ptr->prereply);
      SEMAPHORE_FREE(ptr->postreply);
      FREE(ptr->store);
      FREE(ptr);
      return sendAck(client,
		     &req->table,
		     OK);
    }
  }
  MUTEX_UNLOCK(&csLock);
  LOG(LOG_WARNING,
      _("`%s' failed: table not found!\n"),
      "CS_DHT_LEAVE");
  return sendAck(client,
		 &req->table,
		 SYSERR);
}

static void cs_put_abort(DHT_CLIENT_PUT_RECORD * record) {
  int i;

  MUTEX_LOCK(&csLock);
  dhtAPI->put_stop(record->put_record);
  if (OK != sendAck(record->client,
		    &record->table,
		    record->replicas)) {
    LOG(LOG_FAILURE,
	_("`%s' failed.  Terminating connection to client.\n"),
	"sendAck");
    coreAPI->terminateClientConnection(record->client);
  }
  for (i=putRecordsSize-1;i>=0;i--)
    if (putRecords[i] == record) {
      putRecords[i] = putRecords[putRecordsSize-1];
      GROW(putRecords,
	   putRecordsSize,
	   putRecordsSize-1);
      break;
    }
  MUTEX_UNLOCK(&csLock);
  FREE(record);
}

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int csPut(ClientHandle client,
		 const CS_MESSAGE_HEADER * message) {
  CS_dht_request_put_MESSAGE * req;
  DataContainer * data;
  DHT_CLIENT_PUT_RECORD * ptr;
  unsigned int size;

  if (ntohs(message->size) < sizeof(CS_dht_request_put_MESSAGE))
    return SYSERR;
  req = (CS_dht_request_put_MESSAGE*) message;
  size = ntohs(req->header.size)
    - sizeof(CS_dht_request_put_MESSAGE)
    + sizeof(DataContainer);
  GNUNET_ASSERT(size < MAX_BUFFER_SIZE);
  if (size == 0) {
    data = NULL;
  } else {
    data = MALLOC(size);
    data->size = htonl(size);
    memcpy(&data[1],
	   &req[1],
	   size - sizeof(DataContainer));
  }
  ptr = MALLOC(sizeof(DHT_CLIENT_PUT_RECORD));
  ptr->client = client;
  ptr->replicas = 0;
  ptr->table = req->table;
  ptr->put_record = NULL;

  MUTEX_LOCK(&csLock);
  GROW(putRecords,
       putRecordsSize,
       putRecordsSize+1);
  putRecords[putRecordsSize-1] = ptr;
  MUTEX_UNLOCK(&csLock);
  ptr->put_record = dhtAPI->put_start(&req->table,
				      &req->key,
				      ntohll(req->timeout),
				      data,
				      (DHT_OP_Complete) &cs_put_abort,
				      ptr);
  FREE(data);
  return OK;
}

static void cs_remove_abort(DHT_CLIENT_REMOVE_RECORD * record) {
  int i;

  dhtAPI->remove_stop(record->remove_record);
  if (OK != sendAck(record->client,
		    &record->table,
		    record->replicas)) {
    LOG(LOG_FAILURE,
	_("sendAck failed.  Terminating connection to client.\n"));
    coreAPI->terminateClientConnection(record->client);
  }
  MUTEX_LOCK(&csLock);
  for (i=removeRecordsSize-1;i>=0;i--)
    if (removeRecords[i] == record) {
      removeRecords[i] = removeRecords[removeRecordsSize-1];
      GROW(removeRecords,
	   removeRecordsSize,
	   removeRecordsSize-1);
      break;
    }
  MUTEX_UNLOCK(&csLock);

  FREE(record);
}

struct CSRemoveClosure {
  ClientHandle client;
  CS_dht_request_remove_MESSAGE * message;
};

/**
 * CronJob for removing <key,value>-pairs inserted by this node.
 */
static void csRemoveJob(struct CSRemoveClosure * cpc) {
  CS_dht_request_remove_MESSAGE * req;
  DataContainer * data;
  DHT_CLIENT_REMOVE_RECORD * ptr;
  ClientHandle client;
  unsigned int size;

  req = cpc->message;
  client = cpc->client;
  FREE(cpc);
  size = ntohs(req->header.size)
    - sizeof(CS_dht_request_remove_MESSAGE)
    + sizeof(DataContainer);
  GNUNET_ASSERT(size < 0xFFFF);
  if (size == 0) {
    data = NULL;
  } else {
    data = MALLOC(size);
    data->size = htonl(size);
    memcpy(&data[1],
	   &req[1],
	   size - sizeof(DataContainer));
  }
  ptr = MALLOC(sizeof(DHT_CLIENT_REMOVE_RECORD));
  ptr->client = client;
  ptr->replicas = 0;
  ptr->table = req->table;
  ptr->remove_record = NULL;
  MUTEX_LOCK(&csLock);
  GROW(removeRecords,
       removeRecordsSize,
       removeRecordsSize+1);
  removeRecords[removeRecordsSize-1] = ptr;
  MUTEX_UNLOCK(&csLock);
  ptr->remove_record = dhtAPI->remove_start(&req->table,
					    &req->key,
					    ntohll(req->timeout),
					    data,
					    (DHT_OP_Complete) &cs_remove_abort,
					    ptr);
  FREE(req);
  FREE(data);
}

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int csRemove(ClientHandle client,
		    const CS_MESSAGE_HEADER * message) {
  struct CSRemoveClosure * cpc;

  if (ntohs(message->size) < sizeof(CS_dht_request_remove_MESSAGE))
    return SYSERR;
  cpc = MALLOC(sizeof(struct CSRemoveClosure));
  cpc->message = MALLOC(ntohs(message->size));
  memcpy(cpc->message,
	 message,
	 ntohs(message->size));
  cpc->client = client;
  addCronJob((CronJob)&csRemoveJob,
	     0,
	     0,
	     cpc);
  return OK;
}



static int cs_get_result_callback(const HashCode512 * key,
				  const DataContainer * value,
				  DHT_CLIENT_GET_RECORD * record) {
  CS_dht_reply_results_MESSAGE * msg;
  size_t n;

  n = sizeof(CS_dht_reply_results_MESSAGE) + ntohl(value->size);
  msg = MALLOC(n);
  msg->key = *key;
  memcpy(&msg[1],
	 value,
	 ntohl(value->size));
  LOG(LOG_DEBUG,
      "`%s' processes reply '%.*s'\n",
      __FUNCTION__,
      ntohl(value->size) - sizeof(DataContainer),
      &value[1]);
  msg->table = record->table;
  msg->header.size = htons(n);
  msg->header.type = htons(CS_PROTO_dht_REPLY_GET);
  if (OK != coreAPI->sendToClient(record->client,
				  &msg->header)) {
    LOG(LOG_FAILURE,
	_("`%s' failed. Terminating connection to client.\n"),
	"sendToClient");
    coreAPI->terminateClientConnection(record->client);
  }
  FREE(msg);
  return OK;
}
				
static void cs_get_abort(DHT_CLIENT_GET_RECORD * record) {
  int i;

  dhtAPI->get_stop(record->get_record);
  if (record->count == 0) {
    if (OK != sendAck(record->client,
		      &record->table,
		      SYSERR)) {
      LOG(LOG_FAILURE,
	  _("`%s' failed. Terminating connection to client.\n"),
	  "sendAck");
      coreAPI->terminateClientConnection(record->client);
    }
  } else {
    if (OK != sendAck(record->client,
		      &record->table,
		      record->count)) {
      LOG(LOG_FAILURE,
	  _("`%s' failed. Terminating connection to client.\n"),
	  "sendAck");
      coreAPI->terminateClientConnection(record->client);
    }
  }
  MUTEX_LOCK(&csLock);
  for (i=getRecordsSize-1;i>=0;i--)
    if (getRecords[i] == record) {
      getRecords[i] = getRecords[getRecordsSize-1];
      GROW(getRecords,
	   getRecordsSize,
	   getRecordsSize-1);
      break;
    }
  MUTEX_UNLOCK(&csLock);
  FREE(record);
}

struct CSGetClosure {
  ClientHandle client;
  CS_dht_request_get_MESSAGE * message;
};

/**
 * CS handler for fetching <key,value>-pairs from DHT-table.
 */
static int csGetJob(struct CSGetClosure * cpc) {
  CS_dht_request_get_MESSAGE * req;
  DHT_CLIENT_GET_RECORD * ptr;
  ClientHandle client;
  unsigned int keyCount;

  client = cpc->client;
  req = cpc->message;
  FREE(cpc);

  keyCount = 1 + ((ntohs(req->header.size) - sizeof(CS_dht_request_get_MESSAGE)) / sizeof(HashCode512));
  ptr = MALLOC(sizeof(DHT_CLIENT_GET_RECORD));
  ptr->client = client;
  ptr->count = 0;
  ptr->table = req->table;
  ptr->get_record = NULL;

  MUTEX_LOCK(&csLock);
  GROW(getRecords,
       getRecordsSize,
       getRecordsSize+1);
  getRecords[getRecordsSize-1] = ptr;
  MUTEX_UNLOCK(&csLock);
  ptr->get_record = dhtAPI->get_start(&req->table,
				      ntohl(req->type),
				      keyCount,
				      &req->keys,
				      ntohll(req->timeout),
				      (DataProcessor) &cs_get_result_callback,
				      ptr,
				      (DHT_OP_Complete) &cs_get_abort,
				      ptr);
  return OK;
}

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int csGet(ClientHandle client,
		 const CS_MESSAGE_HEADER * message) {
  struct CSGetClosure * cpc;

  if (ntohs(message->size) != sizeof(CS_dht_request_get_MESSAGE))
    return SYSERR;

  cpc = MALLOC(sizeof(struct CSGetClosure));
  cpc->message = MALLOC(ntohs(message->size));
  memcpy(cpc->message,
	 message,
	 ntohs(message->size));
  cpc->client = client;
  addCronJob((CronJob)&csGetJob,
	     0,
	     0,
	     cpc);
  return OK;
}

/**
 * CS handler for ACKs.  Finds the appropriate handler entry, stores
 * the status value in status and up's the semaphore to signal
 * that we received a reply.
 */
static int csACK(ClientHandle client,
		 const CS_MESSAGE_HEADER * message) {
  DHT_CLIENT_TableHandlers * ptr;
  CS_dht_reply_ack_MESSAGE * req;
  int i;

  if (ntohs(message->size) != sizeof(CS_dht_reply_ack_MESSAGE))
    return SYSERR;
  req =(CS_dht_reply_ack_MESSAGE*) message;
  LOG(LOG_EVERYTHING,
      "`%s' received from client.\n",
      "CS_dht_reply_ack_MESSAGE");
  MUTEX_LOCK(&csLock);
  for (i=0;i<csHandlersCount;i++) {
    ptr = csHandlers[i];
    if ( (ptr->handler == client) &&
	 (equalsHashCode512(&ptr->table,
			    &req->table)) ) {
      SEMAPHORE_DOWN(ptr->postreply);
      ptr->status = ntohl(req->status);
      SEMAPHORE_UP(ptr->prereply);
      MUTEX_UNLOCK(&csLock);
      return OK;
    }
  }
  MUTEX_UNLOCK(&csLock);
  LOG(LOG_ERROR,
      _("Failed to deliver `%s' message.\n"),
      "CS_dht_reply_ack_MESSAGE");
  return SYSERR; /* failed to signal */
}

/**
 * CS handler for results.  Finds the appropriate record
 * and passes on the new result.  If all results have been
 * collected, signals using the semaphore.
 */
static int csResults(ClientHandle client,
		     const CS_MESSAGE_HEADER * message) {
  CS_dht_reply_results_MESSAGE * req;
  DHT_CLIENT_TableHandlers * ptr;
  unsigned int dataLength;
  int i;

  if (ntohs(message->size) < sizeof(CS_dht_reply_results_MESSAGE)) {
    BREAK();
    return SYSERR;
  }
  req = (CS_dht_reply_results_MESSAGE*) message;
  dataLength = ntohs(message->size) - sizeof(CS_dht_reply_results_MESSAGE);
  if (dataLength != ntohl(req->data.size)) {
    BREAK();
    return SYSERR;
  }
  LOG(LOG_EVERYTHING,
      "`%s' received from client.\n",
      "CS_dht_reply_results_MESSAGE");
  MUTEX_LOCK(&csLock);
  for (i=0;i<csHandlersCount;i++) {
    if ( (csHandlers[i]->handler == client) &&
	 (equalsHashCode512(&csHandlers[i]->table,
			    &req->table)) ) {
      ptr = csHandlers[i];
      SEMAPHORE_DOWN(ptr->postreply);
      LOG(LOG_EVERYTHING,
	  "`%s' received result '%.*s'!\n",
	  __FUNCTION__,
	  dataLength - sizeof(DataContainer),
	  &(&req->data)[1]);

      ptr->resultCallback(&req->key,
			  &req->data,			
			  ptr->resultCallbackClosure);
      ptr->status++;
      MUTEX_UNLOCK(&csLock);
      return OK;
    }
  }
  MUTEX_UNLOCK(&csLock);
  LOG(LOG_ERROR,
      _("Failed to deliver `%s' message.\n"),
      "CS_dht_reply_results_MESSAGE");
  return SYSERR; /* failed to deliver */
}

/**
 * CS handler for handling exiting client.  Triggers
 * csLeave for all tables that rely on this client.
 */
static void csClientExit(ClientHandle client) {
  int i;
  DHT_CLIENT_GET_RECORD * gr;
  DHT_CLIENT_PUT_RECORD * pr;
  DHT_CLIENT_REMOVE_RECORD * rr;
  int haveCron;

  MUTEX_LOCK(&csLock);
  for (i=0;i<csHandlersCount;i++) {
    if (csHandlers[i]->handler == client) {
      CS_dht_request_leave_MESSAGE message;

      message.header.size = ntohs(sizeof(CS_dht_request_leave_MESSAGE));
      message.header.type = ntohs(CS_PROTO_dht_REQUEST_LEAVE);
      message.table = csHandlers[i]->table;
      csLeave(client,
	      &message.header);
      i--;
    }
  }
  haveCron = isCronRunning();
  MUTEX_UNLOCK(&csLock);
  if (YES == haveCron)
    suspendCron();
  MUTEX_LOCK(&csLock);
  for (i=0;i<getRecordsSize;i++) {
    if (getRecords[i]->client == client) {
      gr = getRecords[i];

      delCronJob((CronJob) &cs_get_abort,
		 0,
		 gr);
      dhtAPI->get_stop(gr->get_record);
      getRecords[i] = getRecords[getRecordsSize-1];
      GROW(getRecords,
	   getRecordsSize,
	   getRecordsSize-1);
    }
  }
  for (i=0;i<putRecordsSize;i++) {
    if (putRecords[i]->client == client) {
      pr = putRecords[i];

      delCronJob((CronJob) &cs_put_abort,
		 0,
		 pr);
      dhtAPI->put_stop(pr->put_record);
      putRecords[i] = putRecords[putRecordsSize-1];
      GROW(putRecords,
	   putRecordsSize,
	   putRecordsSize-1);
    }
  }
  for (i=0;i<removeRecordsSize;i++) {
    if (removeRecords[i]->client == client) {
      rr = removeRecords[i];

      delCronJob((CronJob) &cs_remove_abort,
		 0,
		 rr);
      dhtAPI->remove_stop(rr->remove_record);
      removeRecords[i] = removeRecords[removeRecordsSize-1];
      GROW(removeRecords,
	   removeRecordsSize,
	   removeRecordsSize-1);
    }
  }
  MUTEX_UNLOCK(&csLock);
  if (YES == haveCron)
    resumeCron();
}

int initialize_module_dht(CoreAPIForApplication * capi) {
  int status;

  dhtAPI = capi->requestService("dht");
  if (dhtAPI == NULL)
    return SYSERR;
  coreAPI = capi;
  LOG(LOG_DEBUG,
      "DHT registering client handlers: "
      "%d %d %d %d %d %d %d\n",
      CS_PROTO_dht_REQUEST_JOIN,
      CS_PROTO_dht_REQUEST_LEAVE,
      CS_PROTO_dht_REQUEST_PUT,
      CS_PROTO_dht_REQUEST_GET,
      CS_PROTO_dht_REQUEST_REMOVE,
      CS_PROTO_dht_REPLY_GET,
      CS_PROTO_dht_REPLY_ACK);
  status = OK;
  MUTEX_CREATE_RECURSIVE(&csLock);
  if (SYSERR == capi->registerClientHandler(CS_PROTO_dht_REQUEST_JOIN,
                                            &csJoin))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(CS_PROTO_dht_REQUEST_LEAVE,
                                            &csLeave))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(CS_PROTO_dht_REQUEST_PUT,
                                            &csPut))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(CS_PROTO_dht_REQUEST_GET,
                                            &csGet))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(CS_PROTO_dht_REQUEST_REMOVE,
                                            &csRemove))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(CS_PROTO_dht_REPLY_GET,
                                            &csResults))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(CS_PROTO_dht_REPLY_ACK,
                                            &csACK))
    status = SYSERR;
  if (SYSERR == capi->registerClientExitHandler(&csClientExit))
    status = SYSERR;
  return status;
}

/**
 * Unregisters handlers, cleans memory structures etc when node exits.
 */
int done_module_dht() {
  int status;

  status = OK;
  LOG(LOG_DEBUG,
      "DHT: shutdown\n");
  if (OK != coreAPI->unregisterClientHandler(CS_PROTO_dht_REQUEST_JOIN,
					     &csJoin))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(CS_PROTO_dht_REQUEST_LEAVE,
					     &csLeave))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(CS_PROTO_dht_REQUEST_PUT,
					     &csPut))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(CS_PROTO_dht_REQUEST_GET,
					     &csGet))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(CS_PROTO_dht_REQUEST_REMOVE,
					     &csRemove))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(CS_PROTO_dht_REPLY_GET,
					     &csResults))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(CS_PROTO_dht_REPLY_ACK,
					     &csACK))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientExitHandler(&csClientExit))
    status = SYSERR;

  while (putRecordsSize > 0) {
    delCronJob((CronJob) &cs_put_abort,
	       0,
	       putRecords[0]);
    cs_put_abort(putRecords[0]);
  }

  while (removeRecordsSize > 0) {
    delCronJob((CronJob) &cs_remove_abort,
	       0,
	       removeRecords[0]);
    cs_remove_abort(removeRecords[0]);
  }

  while (getRecordsSize > 0) {
    delCronJob((CronJob) &cs_get_abort,
	       0,
	       getRecords[0]);
    cs_get_abort(getRecords[0]);
  }

  /* simulate client-exit for all existing handlers */
  while (csHandlersCount > 0)
    csClientExit(csHandlers[0]->handler);
  coreAPI->releaseService(dhtAPI);
  dhtAPI = NULL;
  coreAPI = NULL;
  MUTEX_DESTROY(&csLock);
  return status;
}

/* end of cs.c */
