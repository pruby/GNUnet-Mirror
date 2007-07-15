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
#include "dht.h"
#include "gnunet_dht_service.h"

#define DEBUG_CS NO

/**
 * Global core API.
 */
static CoreAPIForApplication *coreAPI;

/**
 * Reference to the DHT service API.
 */
static DHT_ServiceAPI *dhtAPI;

typedef struct
{

  struct ClientHandle *client;

  struct DHT_GET_RECORD *get_record;

} DHT_CLIENT_GET_RECORD;

static DHT_CLIENT_GET_RECORD **getRecords;

static unsigned int getRecordsSize;

/**
 * Lock.
 */
static struct MUTEX *lock;

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int
csPut (struct ClientHandle *client, const MESSAGE_HEADER * message)
{
  const CS_dht_request_put_MESSAGE *req;
  unsigned int size;

  if (ntohs (message->size) < sizeof (CS_dht_request_put_MESSAGE))
    {
      GE_BREAK (NULL, 0);
      return SYSERR;
    }
  req = (const CS_dht_request_put_MESSAGE *) message;
  size = ntohs (req->header.size) - sizeof (CS_dht_request_put_MESSAGE);
  GE_ASSERT (NULL, size < MAX_BUFFER_SIZE);
#if DEBUG_CS
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "`%s' at %s:%d processes put '%.*s'\n",
          __FUNCTION__, __FILE__, __LINE__, size, &req[1]);
#endif
  dhtAPI->put (&req->key, ntohl (req->type), size, ntohll (req->expire) + get_time (),  /* convert to absolute time */
               (const char *) &req[1]);
  return OK;
}

int
get_result (const HashCode512 * key, const DataContainer * value, void *cls)
{
  DHT_CLIENT_GET_RECORD *record = cls;
  CS_dht_request_put_MESSAGE *msg;
  size_t n;

  GE_ASSERT (NULL, ntohl (value->size) >= sizeof (DataContainer));
  n =
    sizeof (CS_dht_request_put_MESSAGE) + ntohl (value->size) -
    sizeof (DataContainer);
  if (n > MAX_BUFFER_SIZE)
    {
      GE_BREAK (NULL, 0);
      return SYSERR;
    }
  msg = MALLOC (n);
  msg->header.size = htons (n);
  msg->header.type = htons (CS_PROTO_dht_REQUEST_PUT);
  msg->expire = 0;              /* unknown */
  msg->key = *key;
  memcpy (&msg[1], &value[1], ntohl (value->size) - sizeof (DataContainer));
#if DEBUG_CS
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "`%s' at %s:%d processes reply '%.*s'\n",
          __FUNCTION__,
          __FILE__,
          __LINE__, ntohl (value->size) - sizeof (DataContainer), &value[1]);
#endif
  if (OK != coreAPI->sendToClient (record->client, &msg->header, YES))
    {
      GE_LOG (coreAPI->ectx,
              GE_ERROR | GE_IMMEDIATE | GE_USER,
              _("`%s' failed. Terminating connection to client.\n"),
              "sendToClient");
      coreAPI->terminateClientConnection (record->client);
    }
  FREE (msg);
  return OK;
}

static void
get_timeout (void *cls)
{
  DHT_CLIENT_GET_RECORD *record = cls;
  int i;
  int found;

  found = NO;
  MUTEX_LOCK (lock);
  for (i = getRecordsSize - 1; i >= 0; i--)
    if (getRecords[i] == record)
      {
        getRecords[i] = getRecords[getRecordsSize - 1];
        GROW (getRecords, getRecordsSize, getRecordsSize - 1);
        found = YES;
        break;
      }
  MUTEX_UNLOCK (lock);
  if (found == YES)
    {
      dhtAPI->get_stop (record->get_record);
      FREE (record);
    }
}

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int
csGet (struct ClientHandle *client, const MESSAGE_HEADER * message)
{
  const CS_dht_request_get_MESSAGE *get;
  DHT_CLIENT_GET_RECORD *cpc;

  if (ntohs (message->size) != sizeof (CS_dht_request_get_MESSAGE))
    {
      GE_BREAK (NULL, 0);
      return SYSERR;
    }
#if DEBUG_CS
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "`%s' at %s:%d processes get\n", __FUNCTION__, __FILE__, __LINE__);
#endif
  get = (const CS_dht_request_get_MESSAGE *) message;
  cpc = MALLOC (sizeof (DHT_CLIENT_GET_RECORD));
  cpc->client = client;
  cpc->get_record = dhtAPI->get_start (ntohl (get->type),
                                       &get->key,
                                       ntohll (get->timeout),
                                       &get_result, cpc, &get_timeout, cpc);
  MUTEX_LOCK (lock);
  APPEND (getRecords, getRecordsSize, cpc);
  MUTEX_UNLOCK (lock);
  return OK;
}

/**
 * CS handler for handling exiting client.  Triggers
 * get_stop for all operations that rely on this client.
 */
static void
csClientExit (struct ClientHandle *client)
{
  int i;
  struct DHT_GET_RECORD *gr;
  DHT_CLIENT_GET_RECORD *cgr;
  MUTEX_LOCK (lock);
  for (i = 0; i < getRecordsSize; i++)
    {
      cgr = getRecords[i];
      if (cgr->client == client)
        {
          gr = cgr->get_record;
          getRecords[i] = getRecords[getRecordsSize - 1];
          GROW (getRecords, getRecordsSize, getRecordsSize - 1);
          MUTEX_UNLOCK (lock);
          dhtAPI->get_stop (gr);
          FREE (cgr);
          MUTEX_LOCK (lock);
          i--;
        }
    }
  MUTEX_UNLOCK (lock);
}

int
initialize_module_dht (CoreAPIForApplication * capi)
{
  int status;

  dhtAPI = capi->requestService ("dht");
  if (dhtAPI == NULL)
    return SYSERR;
  coreAPI = capi;
  GE_LOG (coreAPI->ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          _("`%s' registering client handlers: %d %d\n"),
          "dht", CS_PROTO_dht_REQUEST_PUT, CS_PROTO_dht_REQUEST_GET);
  status = OK;
  lock = MUTEX_CREATE (NO);
  if (SYSERR == capi->registerClientHandler (CS_PROTO_dht_REQUEST_PUT,
                                             &csPut))
    status = SYSERR;
  if (SYSERR == capi->registerClientHandler (CS_PROTO_dht_REQUEST_GET,
                                             &csGet))
    status = SYSERR;
  if (SYSERR == capi->registerClientExitHandler (&csClientExit))
    status = SYSERR;
  GE_ASSERT (capi->ectx,
             0 == GC_set_configuration_value_string (capi->cfg,
                                                     capi->ectx,
                                                     "ABOUT",
                                                     "dht",
                                                     gettext_noop
                                                     ("Enables efficient non-anonymous routing")));
  return status;
}

/**
 * Unregisters handlers, cleans memory structures etc when node exits.
 */
int
done_module_dht ()
{
  int status;

  status = OK;
  GE_LOG (coreAPI->ectx, GE_DEBUG | GE_REQUEST | GE_USER, "DHT: shutdown\n");
  if (OK != coreAPI->unregisterClientHandler (CS_PROTO_dht_REQUEST_PUT,
                                              &csPut))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientHandler (CS_PROTO_dht_REQUEST_GET,
                                              &csGet))
    status = SYSERR;
  if (OK != coreAPI->unregisterClientExitHandler (&csClientExit))
    status = SYSERR;

  while (getRecordsSize > 0)
    get_timeout (getRecords[0]);
  coreAPI->releaseService (dhtAPI);
  dhtAPI = NULL;
  coreAPI = NULL;
  MUTEX_DESTROY (lock);
  return status;
}

/* end of cs.c */
