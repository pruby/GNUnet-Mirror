/*
      This file is part of GNUnet
      Copyright (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
static CoreAPIForApplication * coreAPI;

/**
 * Reference to the DHT service API.
 */
static DHT_ServiceAPI * dhtAPI;

typedef struct {
  struct ClientHandle * client;
  struct DHT_PUT_RECORD * put_record;
  DHT_TableId table;
  unsigned int replicas; /* confirmed puts? */
} DHT_CLIENT_PUT_RECORD;

typedef struct {
  struct ClientHandle * client;
  struct DHT_GET_RECORD * get_record;
  DHT_TableId table;
  unsigned int count;
} DHT_CLIENT_GET_RECORD;

static DHT_CLIENT_GET_RECORD ** getRecords;

static unsigned int getRecordsSize;

static DHT_CLIENT_PUT_RECORD ** putRecords;

static unsigned int putRecordsSize;

/**
 * Lock.
 */
static struct MUTEX * csLock;

static struct GE_Context * ectx;


static int sendAck(struct ClientHandle * client,
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

static void cs_put_abort(void * cls) {
  DHT_CLIENT_PUT_RECORD * record = cls;
  int i;

  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Signaling client put completion: %d\n",
	 record->replicas);
  MUTEX_LOCK(csLock);
  dhtAPI->put_stop(record->put_record);
  if (OK != sendAck(record->client,
		    &record->table,
		    record->replicas)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_IMMEDIATE | GE_USER,
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
  MUTEX_UNLOCK(csLock);
  FREE(record);
}

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int csPut(struct ClientHandle * client,
		 const MESSAGE_HEADER * message) {
  CS_dht_request_put_MESSAGE * req;
  DataContainer * data;
  DHT_CLIENT_PUT_RECORD * ptr;
  unsigned int size;

  if (ntohs(message->size) < sizeof(CS_dht_request_put_MESSAGE)) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  req = (CS_dht_request_put_MESSAGE*) message;
  size = ntohs(req->header.size)
    - sizeof(CS_dht_request_put_MESSAGE)
    + sizeof(DataContainer);
  GE_ASSERT(ectx, size < MAX_BUFFER_SIZE);
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

  MUTEX_LOCK(csLock);
  GROW(putRecords,
       putRecordsSize,
       putRecordsSize+1);
  putRecords[putRecordsSize-1] = ptr;
  MUTEX_UNLOCK(csLock);
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Starting DHT put\n");
  ptr->put_record = dhtAPI->put_start(&req->table,
				      &req->key,
				      ntohll(req->timeout),
				      data,
				      &cs_put_abort,
				      ptr);
  FREE(data);
  return OK;
}

static int cs_get_result_callback(const HashCode512 * key,
				  const DataContainer * value,
				  void * cls) {
  DHT_CLIENT_GET_RECORD * record = cls;
  CS_dht_reply_results_MESSAGE * msg;
  size_t n;

  n = sizeof(CS_dht_reply_results_MESSAGE) + ntohl(value->size);
  msg = MALLOC(n);
  msg->key = *key;
  memcpy(&msg[1],
	 value,
	 ntohl(value->size));
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "`%s' processes reply '%.*s'\n",
	 __FUNCTION__,
	 ntohl(value->size) - sizeof(DataContainer),
	 &value[1]);
  msg->table = record->table;
  msg->header.size = htons(n);
  msg->header.type = htons(CS_PROTO_dht_REPLY_GET);
  if (OK != coreAPI->sendToClient(record->client,
				  &msg->header)) {
    GE_LOG(ectx,
	   GE_ERROR | GE_IMMEDIATE | GE_USER,
	   _("`%s' failed. Terminating connection to client.\n"),
	   "sendToClient");
    coreAPI->terminateClientConnection(record->client);
  }
  FREE(msg);
  return OK;
}
				
static void cs_get_abort(void * cls) {
  DHT_CLIENT_GET_RECORD * record = cls;
  int i;

  dhtAPI->get_stop(record->get_record);
  if (record->count == 0) {
    if (OK != sendAck(record->client,
		      &record->table,
		      SYSERR)) {
      GE_LOG(ectx,
	     GE_ERROR | GE_IMMEDIATE | GE_USER,
	     _("`%s' failed. Terminating connection to client.\n"),
	     "sendAck");
      coreAPI->terminateClientConnection(record->client);
    }
  } else {
    if (OK != sendAck(record->client,
		      &record->table,
		      record->count)) {
      GE_LOG(ectx,
	     GE_ERROR | GE_IMMEDIATE | GE_USER,
	     _("`%s' failed. Terminating connection to client.\n"),
	     "sendAck");
      coreAPI->terminateClientConnection(record->client);
    }
  }
  MUTEX_LOCK(csLock);
  for (i=getRecordsSize-1;i>=0;i--)
    if (getRecords[i] == record) {
      getRecords[i] = getRecords[getRecordsSize-1];
      GROW(getRecords,
	   getRecordsSize,
	   getRecordsSize-1);
      break;
    }
  MUTEX_UNLOCK(csLock);
  FREE(record);
}

struct CSGetClosure {
  struct ClientHandle * client;
  CS_dht_request_get_MESSAGE * message;
};

/**
 * CS handler for fetching <key,value>-pairs from DHT-table.
 */
static int csGetJob(struct CSGetClosure * cpc) {
  CS_dht_request_get_MESSAGE * req;
  DHT_CLIENT_GET_RECORD * ptr;
  struct ClientHandle * client;
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

  MUTEX_LOCK(csLock);
  GROW(getRecords,
       getRecordsSize,
       getRecordsSize+1);
  getRecords[getRecordsSize-1] = ptr;
  MUTEX_UNLOCK(csLock);
  ptr->get_record = dhtAPI->get_start(&req->table,
				      ntohl(req->type),
				      keyCount,
				      &req->keys,
				      ntohll(req->timeout),
				      &cs_get_result_callback,
				      ptr,
				      &cs_get_abort,
				      ptr);
  return OK;
}

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int csGet(struct ClientHandle * client,
		 const MESSAGE_HEADER * message) {
  struct CSGetClosure * cpc;

  if (ntohs(message->size) != sizeof(CS_dht_request_get_MESSAGE)) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }

  cpc = MALLOC(sizeof(struct CSGetClosure));
  cpc->message = MALLOC(ntohs(message->size));
  memcpy(cpc->message,
	 message,
	 ntohs(message->size));
  cpc->client = client;
  cron_add_job(coreAPI->cron,
	       (CronJob)&csGetJob,
	       0,
	       0,
	       cpc);
  return OK;
}

/**
 * CS handler for handling exiting client.  Triggers
 * csLeave for all tables that rely on this client.
 */
static void csClientExit(struct ClientHandle * client) {
  int i;
  DHT_CLIENT_GET_RECORD * gr;
  DHT_CLIENT_PUT_RECORD * pr;

  cron_suspend(coreAPI->cron,
	       YES);
  MUTEX_LOCK(csLock);
  for (i=0;i<getRecordsSize;i++) {
    if (getRecords[i]->client == client) {
      gr = getRecords[i];

      cron_del_job(coreAPI->cron,
		   &cs_get_abort,
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

      cron_del_job(coreAPI->cron,
		   &cs_put_abort,
		   0,
		   pr);
      dhtAPI->put_stop(pr->put_record);
      putRecords[i] = putRecords[putRecordsSize-1];
      GROW(putRecords,
	   putRecordsSize,
	   putRecordsSize-1);
    }
  }
  MUTEX_UNLOCK(csLock);
  cron_resume_jobs(coreAPI->cron,
		   YES);
}

int initialize_module_dht(CoreAPIForApplication * capi) {
  int status;

  ectx = capi->ectx;
  dhtAPI = capi->requestService("dht");
  if (dhtAPI == NULL)
    return SYSERR;
  coreAPI = capi;
  GE_LOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
      "DHT registering client handlers: "
      "%d %d %d %d\n",
      CS_PROTO_dht_REQUEST_PUT,
      CS_PROTO_dht_REQUEST_GET,
      CS_PROTO_dht_REPLY_GET,
      CS_PROTO_dht_REPLY_ACK);
  status = OK;
  csLock = MUTEX_CREATE(YES);
  if (SYSERR == capi->registerClientHandler(CS_PROTO_dht_REQUEST_PUT,
                                            &csPut))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler(CS_PROTO_dht_REQUEST_GET,
                                            &csGet))
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
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "DHT: shutdown\n");
  if (OK != coreAPI->unregisterClientHandler(CS_PROTO_dht_REQUEST_PUT,
					     &csPut))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler(CS_PROTO_dht_REQUEST_GET,
					     &csGet))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientExitHandler(&csClientExit))
    status = SYSERR;

  while (putRecordsSize > 0) {
    cron_del_job(coreAPI->cron,
		 &cs_put_abort,
		 0,
		 putRecords[0]);
    cs_put_abort(putRecords[0]);
  }

  while (getRecordsSize > 0) {
    cron_del_job(coreAPI->cron,
		 &cs_get_abort,
		 0,
		 getRecords[0]);
    cs_get_abort(getRecords[0]);
  }
  coreAPI->releaseService(dhtAPI);
  dhtAPI = NULL;
  coreAPI = NULL;
  MUTEX_DESTROY(csLock);
  return status;
}

/* end of cs.c */






