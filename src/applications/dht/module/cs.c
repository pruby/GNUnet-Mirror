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

} CS_TableHandlers;

typedef struct {
  ClientHandle client;
  struct DHT_PUT_RECORD * put_record;
  DHT_TableId table;
  unsigned int replicas;
  unsigned int maxReplicas;
} CS_PUT_RECORD;

typedef struct {
  ClientHandle client;
  struct DHT_REMOVE_RECORD * remove_record;
  DHT_TableId table;
  unsigned int replicas;
  unsigned int maxReplicas;
} CS_REMOVE_RECORD;

typedef struct {
  ClientHandle client;
  struct DHT_GET_RECORD * get_record;
  DHT_TableId table;
  unsigned int count;
  unsigned int replyCount;
  DataContainer ** replies;
} CS_GET_RECORD;

static CS_GET_RECORD ** getRecords;

static unsigned int getRecordsSize;

static CS_PUT_RECORD ** putRecords;

static unsigned int putRecordsSize;

static CS_REMOVE_RECORD ** removeRecords;

static unsigned int removeRecordsSize;

/**
 * If clients provide a datastore implementation for a table,
 * we keep the corresponding client handler in this array.
 */
static CS_TableHandlers ** csHandlers;

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
		   unsigned int keyCount,
		   const HashCode160 * keys,
		   DataProcessor resultCallback,
		   void * resCallbackClosure) {
  DHT_CS_REQUEST_GET * req;
  unsigned short size;
  CS_TableHandlers * handlers = closure;
  int ret;

  if (keyCount < 1)
    return SYSERR;

  SEMAPHORE_DOWN(handlers->prerequest);
  handlers->resultCallback = resultCallback;
  handlers->resultCallbackClosure = resCallbackClosure;
  handlers->status = 0;
  size = sizeof(DHT_CS_REQUEST_GET) + 
    (keyCount-1) * sizeof(HashCode160);
  if (((unsigned int)size) 
      != sizeof(DHT_CS_REQUEST_GET) + 
      (keyCount-1) * sizeof(HashCode160)) {
    SEMAPHORE_UP(handlers->prerequest);
    return SYSERR; /* too many keys, size > rangeof(short) */
  }
  req = MALLOC(size);
  req->header.size = htons(size);
  req->header.type = htons(DHT_CS_PROTO_REQUEST_GET);
  req->type = htonl(type);
  req->table = handlers->table;
  memcpy(&req->keys,
	 keys,
	 sizeof(HashCode160) * keyCount);
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
 * @return OK if the value could be stored, SYSERR if not (i.e. out of space)
 */
static int tcp_put(void * closure,
		   const HashCode160 * key,
		   unsigned int type,
		   const DataContainer * value) {
  DHT_CS_REQUEST_PUT * req;
  CS_TableHandlers * handlers = closure;
  int ret;
  size_t n;
  
  n = sizeof(DHT_CS_REQUEST_PUT) + ntohl(value->size);
  req = MALLOC(n);
  SEMAPHORE_DOWN(handlers->prerequest);
  handlers->status = 0;
  req->header.size = htons(n);
  req->header.type = htons(DHT_CS_PROTO_REQUEST_PUT);
  req->table = handlers->table;
  req->key = *key;
  req->timeout = htonl(0);
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
		   const HashCode160 * key,
		   unsigned int type,
		   const DataContainer * value) {
  DHT_CS_REQUEST_REMOVE * req;
  CS_TableHandlers * handlers = closure;
  int ret;
  size_t n;
  
  n = sizeof(DHT_CS_REQUEST_REMOVE);
  if (value != NULL)
    n += htonl(value->size);
  req = MALLOC(n);
  SEMAPHORE_DOWN(handlers->prerequest);
  handlers->status = 0;
  req->header.size = htons(n);
  req->header.type = htons(DHT_CS_PROTO_REQUEST_REMOVE);
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
  DHT_CS_REQUEST_ITERATE req;
  CS_TableHandlers * handlers = closure;
  int ret;
  
  SEMAPHORE_DOWN(handlers->prerequest);
  handlers->status = 0;
  handlers->resultCallback = processor;
  handlers->resultCallbackClosure = cls;
  req.header.size = htons(sizeof(DHT_CS_REQUEST_ITERATE));
  req.header.type = htons(DHT_CS_PROTO_REQUEST_ITERATE);
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
  DHT_CS_REPLY_ACK msg;

  msg.header.size = htons(sizeof(DHT_CS_REPLY_ACK));
  msg.header.type = htons(DHT_CS_PROTO_REPLY_ACK);
  msg.status = htonl(value);
  msg.table = *table;
  return coreAPI->sendToClient(client,
			       &msg.header);
}

/**
 * CS handler for joining existing DHT-table.
 */
static int csJoin(ClientHandle client,
                  const CS_HEADER * message) {
  CS_TableHandlers * ptr;
  DHT_CS_REQUEST_JOIN * req;
  int ret;

  if (ntohs(message->size) != sizeof(DHT_CS_REQUEST_JOIN))
    return SYSERR;
  req = (DHT_CS_REQUEST_JOIN*) message;
  MUTEX_LOCK(&csLock);
  ptr = MALLOC(sizeof(CS_TableHandlers));
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
		     &req->table,
		     ntohl(req->timeout));
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
                   const CS_HEADER * message) {

  int i;
  DHT_CS_REQUEST_LEAVE * req;
  CS_TableHandlers * ptr;

  if (ntohs(message->size) != sizeof(DHT_CS_REQUEST_LEAVE))
    return SYSERR;
  req = (DHT_CS_REQUEST_LEAVE*) message;
  LOG(LOG_EVERYTHING,
      "Client leaving request received!\n");

  MUTEX_LOCK(&csLock);
  for (i=0;i<csHandlersCount;i++) {
    if ( (equalsHashCode160(&csHandlers[i]->table,
			    &req->table)) ) {     
      if (OK != dhtAPI->leave(&req->table,
			      ntohll(req->timeout))) {
	LOG(LOG_WARNING,
	    _("'%s' failed!\n"),
	    "CS_DHT_LEAVE");
      }
      ptr = csHandlers[i];
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
      _("'%s' failed: table not found!\n"),
      "CS_DHT_LEAVE");
  return sendAck(client,
		 &req->table,
		 SYSERR);
}

static void cs_put_abort(CS_PUT_RECORD * record) {
  int i;

  MUTEX_LOCK(&csLock);
  dhtAPI->put_stop(record->put_record);
  if (OK != sendAck(record->client,
		    &record->table,
		    record->replicas)) {
    LOG(LOG_FAILURE,
	_("sendAck failed.  Terminating connection to client.\n"));
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
 * Notification: peer 'store' agreed to store data.
 */
static void cs_put_complete_callback(const PeerIdentity * store,
				     CS_PUT_RECORD * record) {
  int mark = 0;
  MUTEX_LOCK(&csLock);
  record->replicas++;
  if (record->replicas == record->maxReplicas) 
    mark = 1;
  MUTEX_UNLOCK(&csLock);
  if (mark == 1) {
    /* trigger cron-job early if replication count reached. */
    advanceCronJob((CronJob) &cs_put_abort,
		   0,
		   record);
  }
}

struct CSPutClosure {
  ClientHandle client;
  DHT_CS_REQUEST_PUT * message;
};

/**
 * Cron job for the CS handler inserting <key,value>-pair into DHT-table.
 */
static void csPutJob(struct CSPutClosure * cpc) {
  ClientHandle client;
  DHT_CS_REQUEST_PUT * req;
  DataContainer * data;
  CS_PUT_RECORD * ptr;

  req = cpc->message;
  client = cpc->client;
  FREE(cpc);
  cont.dataLength = ntohs(req->header.size) - sizeof(DHT_CS_REQUEST_PUT);
  if (cont.dataLength == 0)
    cont.data = NULL;
  else
    cont.data = &((DHT_CS_REQUEST_PUT_GENERIC*)req)->value[0];

  ptr = MALLOC(sizeof(CS_PUT_RECORD));
  ptr->client = client;
  ptr->replicas = 0;
  ptr->table = req->table;
  ptr->maxReplicas = 7;
  ptr->put_record = NULL;

  MUTEX_LOCK(&csLock);
  GROW(putRecords,
       putRecordsSize,
       putRecordsSize+1);
  putRecords[putRecordsSize-1] = ptr;
  addCronJob((CronJob) &cs_put_abort,
	     ntohll(req->timeout),
	     0,
	     ptr);
  MUTEX_UNLOCK(&csLock);
  ptr->put_record = dhtAPI->put_start(&req->table,
				      &req->key,
				      ntohll(req->timeout),
				      &cont,
				      ptr->maxReplicas,
				      (DHT_PUT_Complete) &cs_put_complete_callback,
				      ptr);
  FREE(req);
}

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int csPut(ClientHandle client,
		 const CS_HEADER * message) {
  struct CSPutClosure * cpc;

  if (ntohs(message->size) < sizeof(DHT_CS_REQUEST_PUT))
    return SYSERR;
  cpc = MALLOC(sizeof(struct CSPutClosure));
  cpc->message = MALLOC(ntohs(message->size));
  memcpy(cpc->message,
	 message,
	 ntohs(message->size));
  cpc->client = client;
  addCronJob((CronJob)&csPutJob,
	     0,
	     0,
	     cpc);
  return OK;
}

static void cs_remove_abort(CS_REMOVE_RECORD * record) {
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

/**
 * Notification: peer 'store' agreed to store data.
 */
static void cs_remove_complete_callback(const PeerIdentity * store,
					CS_REMOVE_RECORD * record) {
  int mark = 0;
  MUTEX_LOCK(&csLock);
  record->replicas++;
  if (record->replicas == record->maxReplicas)
    mark = 1;
  MUTEX_UNLOCK(&csLock);
  if (mark == 1) {
    /* trigger cron-job early if replication count reached. */
    advanceCronJob((CronJob) &cs_remove_abort,
		   0,
		   record);
  }
}

struct CSRemoveClosure {
  ClientHandle client;
  DHT_CS_REQUEST_REMOVE * message;
};

/**
 * CronJob for removing <key,value>-pairs inserted by this node.
 */
static void csRemoveJob(struct CSRemoveClosure * cpc) {
  DHT_CS_REQUEST_REMOVE * req;
  DataContainer cont;
  CS_REMOVE_RECORD * ptr;
  ClientHandle client;

  req = cpc->message;
  client = cpc->client;
  FREE(cpc);
  cont.dataLength = ntohs(req->header.size) - sizeof(DHT_CS_REQUEST_REMOVE);
  if (cont.dataLength == 0)
    cont.data = NULL;
  else
    cont.data = &((DHT_CS_REQUEST_REMOVE_GENERIC*)req)->value[0];
  
  ptr = MALLOC(sizeof(CS_REMOVE_RECORD));
  ptr->client = client;
  ptr->replicas = 0;
  ptr->table = req->table;
  ptr->maxReplicas = 7;
  ptr->remove_record = NULL;
  addCronJob((CronJob) &cs_remove_abort,
	     ntohll(req->timeout),
	     0,
	     ptr);
  MUTEX_LOCK(&csLock);
  GROW(removeRecords,
       removeRecordsSize,
       removeRecordsSize+1);
  removeRecords[removeRecordsSize-1] = ptr;
  MUTEX_UNLOCK(&csLock);
  ptr->remove_record = dhtAPI->remove_start(&req->table,
					    &req->key,
					    ntohll(req->timeout),
					    &cont,
					    ptr->maxReplicas,
					    (DHT_REMOVE_Complete) &cs_remove_complete_callback,
					    ptr);
  FREE(req);
}

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int csRemove(ClientHandle client,
		    const CS_HEADER * message) {
  struct CSRemoveClosure * cpc;

  if (ntohs(message->size) < sizeof(DHT_CS_REQUEST_REMOVE))
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


static void cs_get_abort(CS_GET_RECORD * record) {
  int i;
  DHT_CS_REPLY_RESULTS * msg;
  size_t n;

  dhtAPI->get_stop(record->get_record);
  for (i=0;i<record->count;i++) {
    n = sizeof(DHT_CS_REPLY_RESULTS) + record->replies[i].dataLength;
    msg = MALLOC(n);
    memcpy(&((DHT_CS_REPLY_RESULTS_GENERIC*)msg)->data[0],
	   record->replies[i].data,
	   record->replies[i].dataLength);
    LOG(LOG_DEBUG,
	"'%s' processes reply '%.*s'\n",
	__FUNCTION__,
	record->replies[i].dataLength,
	record->replies[i].data);
    FREENONNULL(record->replies[i].data);
    msg->totalResults = htonl(record->count);
    msg->table = record->table;
    msg->header.size = htons(n);
    msg->header.type = htons(DHT_CS_PROTO_REPLY_GET);
    if (OK != coreAPI->sendToClient(record->client,
				    &msg->header)) {
      LOG(LOG_FAILURE,
	  _("'%s' failed. Terminating connection to client.\n"),
	  "sendToClient");
      coreAPI->terminateClientConnection(record->client);
    }
  }
  GROW(record->replies,
       record->count,
       0);
  if (record->count == 0) {
    if (OK != sendAck(record->client,
		      &record->table,
		      SYSERR)) {
      LOG(LOG_FAILURE,
	  _("'%s' failed. Terminating connection to client.\n"),
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

/**
 * Notification: peer 'store' agreed to store data.
 */
static void cs_get_complete_callback(const DataContainer * value,
				     CS_GET_RECORD * record) {
  DataContainer * copy;
  int mark = 0;

  LOG(LOG_EVERYTHING,
      "'%s' called with result '%.*s'!\n",
      __FUNCTION__,
      value->dataLength,
      value->data);
  MUTEX_LOCK(&csLock);
  GROW(record->replies,
       record->count,
       record->count+1);
  copy = &record->replies[record->count-1];
  copy->dataLength = value->dataLength;
  copy->data = MALLOC(copy->dataLength);
  memcpy(copy->data,
	 value->data,
	 copy->dataLength);
  if (record->count == record->maxReplies)
    mark = 1;
  MUTEX_UNLOCK(&csLock);
  if (mark == 1) {
    /* trigger cron-job early if maxResult count reached. */
    advanceCronJob((CronJob) &cs_get_abort,
		   0,
		   record);
  }
}

struct CSGetClosure {
  ClientHandle client;
  DHT_CS_REQUEST_GET * message;
};

/**
 * CS handler for fetching <key,value>-pairs from DHT-table.
 */
static int csGetJob(struct CSGetClosure * cpc) {
  DHT_CS_REQUEST_GET * req;
  CS_GET_RECORD * ptr;
  ClientHandle client;

  client = cpc->client;
  req = cpc->message;
  FREE(cpc);
  
  ptr = MALLOC(sizeof(CS_GET_RECORD));
  ptr->client = client;
  ptr->count = 0;
  ptr->maxReplies = 7;
  ptr->table = req->table;
  ptr->get_record = NULL;

  addCronJob((CronJob) &cs_get_abort,
	     ntohll(req->timeout),
	     0,
	     ptr);
  MUTEX_LOCK(&csLock);
  GROW(getRecords,
       getRecordsSize,
       getRecordsSize+1);
  getRecords[getRecordsSize-1] = ptr;
  MUTEX_UNLOCK(&csLock);
  ptr->get_record = dhtAPI->get_start(&req->table,
				      &req->key,
				      ntohll(req->timeout),
				      ptr->maxReplies,
				      (DHT_GET_Complete) &cs_get_complete_callback,
				      ptr);
  return OK;
}

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int csGet(ClientHandle client,
		 const CS_HEADER * message) {
  struct CSGetClosure * cpc;

  if (ntohs(message->size) != sizeof(DHT_CS_REQUEST_GET))
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
		 const CS_HEADER * message) {
  CS_TableHandlers * ptr;
  DHT_CS_REPLY_ACK * req;
  int i;

  if (ntohs(message->size) != sizeof(DHT_CS_REPLY_ACK))
    return SYSERR;
  req =(DHT_CS_REPLY_ACK*) message;
  LOG(LOG_EVERYTHING,
      "ACK received from client.\n");
  MUTEX_LOCK(&csLock);
  for (i=0;i<csHandlersCount;i++) {
    if ( (csHandlers[i]->handler == client) &&
	 (equalsHashCode160(&csHandlers[i]->table,
			    &req->table)) ) {     
      SEMAPHORE_DOWN(ptr->postreply);
      ptr = csHandlers[i];
      ptr->status = ntohl(req->status);
      SEMAPHORE_UP(ptr->prereply);
      MUTEX_UNLOCK(&csLock);
      return OK;
    }
  }
  MUTEX_UNLOCK(&csLock);
  LOG(LOG_ERROR,
      _("Failed to deliver csACK signal.\n"));
  return SYSERR; /* failed to signal */
}

/**
 * CS handler for results.  Finds the appropriate record
 * and appends the new result.  If all results have been
 * collected, signals using the semaphore.
 */
static int csResults(ClientHandle client,
		     const CS_HEADER * message) {
  DHT_CS_REPLY_RESULTS * req;
  CS_TableHandlers * ptr;
  unsigned int tot;
  unsigned int dataLength;
  DataContainer * cont;
  int i;

  if (ntohs(message->size) < sizeof(DHT_CS_REPLY_RESULTS))
    return SYSERR;
  req = (DHT_CS_REPLY_RESULTS*) message;
  tot = ntohl(req->totalResults);
  dataLength = ntohs(message->size) - sizeof(DHT_CS_REPLY_RESULTS);
  LOG(LOG_EVERYTHING,
      "%d RESULTS received from client.\n",
      tot);  
  MUTEX_LOCK(&csLock);
  for (i=0;i<csHandlersCount;i++) {
    if ( (csHandlers[i]->handler == client) &&
	 (equalsHashCode160(&csHandlers[i]->table,
			    &req->table)) ) {     
      ptr = csHandlers[i];
      SEMAPHORE_DOWN(ptr->postreply);
      if ( (ptr->status == ptr->maxResults) ||
	   (tot > ptr->maxResults) ) {
	MUTEX_UNLOCK(&csLock);
	LOG(LOG_ERROR,
	    _("Received more results than allowed!\n"));
	return SYSERR;
      }
      LOG(LOG_EVERYTHING,
	  "'%s' received result '%.*s'!\n",
	  __FUNCTION__,
	  dataLength,
	  &((DHT_CS_REPLY_RESULTS_GENERIC*)req)->data[0]);
      
      ptr->resultCallback(data,
			  ptr->resultCallbackClosure);
      ptr->status++;
      if (ptr->status == tot)
	SEMAPHORE_UP(ptr->prereply); /* all replies received, signal! */
      MUTEX_UNLOCK(&csLock);
      return OK;
    }
  }
  MUTEX_UNLOCK(&csLock);
  LOG(LOG_ERROR,
      _("Failed to deliver '%s' content.\n"),
      "CS_REPLY_GET");
  return SYSERR; /* failed to deliver */ 
}

/**
 * CS handler for handling exiting client.  Triggers
 * csLeave for all tables that rely on this client.
 */
static void csClientExit(ClientHandle client) {
  int i;
  int j;
  CS_GET_RECORD * gr;
  CS_PUT_RECORD * pr;
  CS_REMOVE_RECORD * rr;
  int haveCron;

  MUTEX_LOCK(&csLock);
  for (i=0;i<csHandlersCount;i++) {
    if (csHandlers[i]->handler == client) {
      DHT_CS_REQUEST_LEAVE message;

      message.header.size = ntohs(sizeof(DHT_CS_REQUEST_LEAVE));
      message.header.type = ntohs(DHT_CS_PROTO_REQUEST_LEAVE);
      message.timeout = ntohll(0);
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
      for (j=0;j<gr->count;j++)
	FREENONNULL(gr->replies[j].data);
      GROW(gr->replies,
	   gr->count,
	   0);      
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

int initialize_dht_protocol(CoreAPIForApplication * capi) {
  int status;

  dhtAPI = capi->requestService("dht");
  if (dhtAPI == NULL)
    return SYSERR;
  coreAPI = capi;
  LOG(LOG_DEBUG, 
      "DHT registering client handlers: "
      "%d %d %d %d %d %d %d\n",
      DHT_CS_PROTO_REQUEST_JOIN,
      DHT_CS_PROTO_REQUEST_LEAVE,
      DHT_CS_PROTO_REQUEST_PUT,
      DHT_CS_PROTO_REQUEST_GET,
      DHT_CS_PROTO_REQUEST_REMOVE,
      DHT_CS_PROTO_REPLY_GET,
      DHT_CS_PROTO_REPLY_ACK);
  status = OK;
  MUTEX_CREATE_RECURSIVE(&csLock);
  if (SYSERR == capi->registerClientHandler(DHT_CS_PROTO_REQUEST_JOIN,
                                            &csJoin))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(DHT_CS_PROTO_REQUEST_LEAVE,
                                            &csLeave))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(DHT_CS_PROTO_REQUEST_PUT,
                                            &csPut))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(DHT_CS_PROTO_REQUEST_GET,
                                            &csGet))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(DHT_CS_PROTO_REQUEST_REMOVE,
                                            &csRemove))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(DHT_CS_PROTO_REPLY_GET,
                                            &csResults))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(DHT_CS_PROTO_REPLY_ACK,
                                            &csACK))
    status = SYSERR;
  if (SYSERR == capi->registerClientExitHandler(&csClientExit))
    status = SYSERR;
  return status;
}

/**
 * Unregisters handlers, cleans memory structures etc when node exits.
 */
int done_dht_protocol() {
  int status;

  status = OK;
  LOG(LOG_DEBUG, 
      "DHT: shutdown\n");
  if (OK != coreAPI->unregisterClientHandler(DHT_CS_PROTO_REQUEST_JOIN,
					     &csJoin))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(DHT_CS_PROTO_REQUEST_LEAVE,
					     &csLeave))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(DHT_CS_PROTO_REQUEST_PUT,
					     &csPut))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(DHT_CS_PROTO_REQUEST_GET,
					     &csGet))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(DHT_CS_PROTO_REQUEST_REMOVE,
					     &csRemove))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(DHT_CS_PROTO_REPLY_GET,
					     &csResults))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(DHT_CS_PROTO_REPLY_ACK,
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
