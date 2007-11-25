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

#define DEBUG_CS GNUNET_NO

/**
 * Global core API.
 */
static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * Reference to the DHT service API.
 */
static GNUNET_DHT_ServiceAPI *dhtAPI;

typedef struct
{

  struct GNUNET_ClientHandle *client;

  struct GNUNET_DHT_GetHandle *get_record;

} DHT_CLIENT_GET_RECORD;

static DHT_CLIENT_GET_RECORD **getRecords;

static unsigned int getRecordsSize;

/**
 * Lock.
 */
static struct GNUNET_Mutex *lock;

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int
csPut (struct GNUNET_ClientHandle *client,
       const GNUNET_MessageHeader * message)
{
  const CS_dht_request_put_MESSAGE *req;
  unsigned int size;

  if (ntohs (message->size) < sizeof (CS_dht_request_put_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  req = (const CS_dht_request_put_MESSAGE *) message;
  size = ntohs (req->header.size) - sizeof (CS_dht_request_put_MESSAGE);
  GNUNET_GE_ASSERT (NULL, size < GNUNET_MAX_BUFFER_SIZE);
#if DEBUG_CS
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "`%s' at %s:%d processes put '%.*s'\n",
                 __FUNCTION__, __FILE__, __LINE__, size, &req[1]);
#endif
  dhtAPI->put (&req->key, ntohl (req->type), size, GNUNET_ntohll (req->expire) + GNUNET_get_time (),    /* convert to absolute time */
               (const char *) &req[1]);
  return GNUNET_OK;
}

int
get_result (const GNUNET_HashCode * key, const GNUNET_DataContainer * value,
            void *cls)
{
  DHT_CLIENT_GET_RECORD *record = cls;
  CS_dht_request_put_MESSAGE *msg;
  size_t n;

  GNUNET_GE_ASSERT (NULL,
                    ntohl (value->size) >= sizeof (GNUNET_DataContainer));
  n =
    sizeof (CS_dht_request_put_MESSAGE) + ntohl (value->size) -
    sizeof (GNUNET_DataContainer);
  if (n > GNUNET_MAX_BUFFER_SIZE)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  msg = GNUNET_malloc (n);
  msg->header.size = htons (n);
  msg->header.type = htons (GNUNET_CS_PROTO_DHT_REQUEST_PUT);
  msg->expire = 0;              /* unknown */
  msg->key = *key;
  memcpy (&msg[1], &value[1],
          ntohl (value->size) - sizeof (GNUNET_DataContainer));
#if DEBUG_CS
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "`%s' at %s:%d processes reply '%.*s'\n",
                 __FUNCTION__,
                 __FILE__,
                 __LINE__,
                 ntohl (value->size) - sizeof (GNUNET_DataContainer),
                 &value[1]);
#endif
  if (GNUNET_OK !=
      coreAPI->sendToClient (record->client, &msg->header, GNUNET_YES))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _("`%s' failed. Terminating connection to client.\n"),
                     "sendToClient");
      coreAPI->terminateClientConnection (record->client);
    }
  GNUNET_free (msg);
  return GNUNET_OK;
}

static void
get_timeout (void *cls)
{
  DHT_CLIENT_GET_RECORD *record = cls;
  int i;
  int found;

  found = GNUNET_NO;
  GNUNET_mutex_lock (lock);
  for (i = getRecordsSize - 1; i >= 0; i--)
    if (getRecords[i] == record)
      {
        getRecords[i] = getRecords[getRecordsSize - 1];
        GNUNET_array_grow (getRecords, getRecordsSize, getRecordsSize - 1);
        found = GNUNET_YES;
        break;
      }
  GNUNET_mutex_unlock (lock);
  if (found == GNUNET_YES)
    {
      dhtAPI->get_stop (record->get_record);
      GNUNET_free (record);
    }
}

/**
 * CS handler for inserting <key,value>-pair into DHT-table.
 */
static int
csGet (struct GNUNET_ClientHandle *client,
       const GNUNET_MessageHeader * message)
{
  const CS_dht_request_get_MESSAGE *get;
  DHT_CLIENT_GET_RECORD *cpc;

  if (ntohs (message->size) != sizeof (CS_dht_request_get_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
#if DEBUG_CS
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "`%s' at %s:%d processes get\n", __FUNCTION__, __FILE__,
                 __LINE__);
#endif
  get = (const CS_dht_request_get_MESSAGE *) message;
  cpc = GNUNET_malloc (sizeof (DHT_CLIENT_GET_RECORD));
  cpc->client = client;
  cpc->get_record = dhtAPI->get_start (ntohl (get->type),
                                       &get->key,
                                       GNUNET_ntohll (get->timeout),
                                       &get_result, cpc, &get_timeout, cpc);
  GNUNET_mutex_lock (lock);
  GNUNET_array_append (getRecords, getRecordsSize, cpc);
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * CS handler for handling exiting client.  Triggers
 * get_stop for all operations that rely on this client.
 */
static void
csClientExit (struct GNUNET_ClientHandle *client)
{
  int i;
  struct GNUNET_DHT_GetHandle *gr;
  DHT_CLIENT_GET_RECORD *cgr;
  GNUNET_mutex_lock (lock);
  for (i = 0; i < getRecordsSize; i++)
    {
      cgr = getRecords[i];
      if (cgr->client == client)
        {
          gr = cgr->get_record;
          getRecords[i] = getRecords[getRecordsSize - 1];
          GNUNET_array_grow (getRecords, getRecordsSize, getRecordsSize - 1);
          GNUNET_mutex_unlock (lock);
          dhtAPI->get_stop (gr);
          GNUNET_free (cgr);
          GNUNET_mutex_lock (lock);
          i--;
        }
    }
  GNUNET_mutex_unlock (lock);
}

int
initialize_module_dht (GNUNET_CoreAPIForPlugins * capi)
{
  int status;

  dhtAPI = capi->requestService ("dht");
  if (dhtAPI == NULL)
    return GNUNET_SYSERR;
  coreAPI = capi;
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _("`%s' registering client handlers: %d %d\n"),
                 "dht", GNUNET_CS_PROTO_DHT_REQUEST_PUT,
                 GNUNET_CS_PROTO_DHT_REQUEST_GET);
  status = GNUNET_OK;
  lock = GNUNET_mutex_create (GNUNET_NO);
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_DHT_REQUEST_PUT, &csPut))
    status = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      capi->registerClientHandler (GNUNET_CS_PROTO_DHT_REQUEST_GET, &csGet))
    status = GNUNET_SYSERR;
  if (GNUNET_SYSERR == capi->registerClientExitHandler (&csClientExit))
    status = GNUNET_SYSERR;
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
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

  status = GNUNET_OK;
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "DHT: shutdown\n");
  if (GNUNET_OK !=
      coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_DHT_REQUEST_PUT,
                                        &csPut))
    status = GNUNET_SYSERR;
  if (GNUNET_OK !=
      coreAPI->unregisterClientHandler (GNUNET_CS_PROTO_DHT_REQUEST_GET,
                                        &csGet))
    status = GNUNET_SYSERR;
  if (GNUNET_OK != coreAPI->unregisterClientExitHandler (&csClientExit))
    status = GNUNET_SYSERR;

  while (getRecordsSize > 0)
    get_timeout (getRecords[0]);
  coreAPI->releaseService (dhtAPI);
  dhtAPI = NULL;
  coreAPI = NULL;
  GNUNET_mutex_destroy (lock);
  return status;
}

/* end of cs.c */
