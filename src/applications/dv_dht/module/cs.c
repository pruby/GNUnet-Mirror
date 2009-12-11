/*
      This file is part of GNUnet
      Copyright (C) 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_core.h"
#include "gnunet_protocols.h"
#include "dht.h"
#include "gnunet_dv_dht_service.h"
#include "service.h"

/**
 * Global core API.
 */
static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * Reference to the DV DHT service API.
 */
static GNUNET_DV_DHT_ServiceAPI *dvdhtAPI;

/**
 * Type of the linked list that is used by CS to
 * keep track of clients and their pending GET
 * requests.
 */
struct DV_DHT_CLIENT_GET_RECORD
{

  struct DV_DHT_CLIENT_GET_RECORD *next;

  struct GNUNET_ClientHandle *client;

  struct GNUNET_DV_DHT_GetHandle *get_record;

};

/**
 * Linked list of active GET requests.
 */
static struct DV_DHT_CLIENT_GET_RECORD *getRecords;

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
  dvdhtAPI->put (&req->key, ntohl (req->type), size, (const char *) &req[1]);
  return coreAPI->cs_send_value (client, GNUNET_OK);
}

static int
get_result (const GNUNET_HashCode * key,
            unsigned int type,
            unsigned int size, const char *value, void *cls)
{
  struct DV_DHT_CLIENT_GET_RECORD *record = cls;
  CS_dht_request_put_MESSAGE *msg;
  size_t n;

  n = sizeof (CS_dht_request_put_MESSAGE) + size;
  if (n > GNUNET_MAX_BUFFER_SIZE)
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  msg = GNUNET_malloc (n);
  msg->header.size = htons (n);
  msg->header.type = htons (GNUNET_CS_PROTO_DV_DHT_REQUEST_PUT);
  msg->type = htonl (type);
  msg->key = *key;
  memcpy (&msg[1], value, size);
  if (GNUNET_OK !=
      coreAPI->cs_send_message (record->client, &msg->header, GNUNET_YES))
    {
      GNUNET_GE_LOG (coreAPI->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE | GNUNET_GE_USER,
                     _("`%s' failed. Terminating connection to client.\n"),
                     "cs_send_to_client");
      coreAPI->cs_disconnect_now (record->client);
    }
  GNUNET_free (msg);
  return GNUNET_OK;
}

/**
 * CS handler for getting key from DHT.
 */
static int
csGet (struct GNUNET_ClientHandle *client,
       const GNUNET_MessageHeader * message)
{
  const CS_dht_request_get_MESSAGE *get;
  struct DV_DHT_CLIENT_GET_RECORD *cpc;

  if (ntohs (message->size) != sizeof (CS_dht_request_get_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  get = (const CS_dht_request_get_MESSAGE *) message;
  cpc = GNUNET_malloc (sizeof (struct DV_DHT_CLIENT_GET_RECORD));
  cpc->client = client;
  cpc->get_record = dvdhtAPI->get_start (ntohl (get->type),
                                         &get->key, &get_result, cpc);
  GNUNET_mutex_lock (lock);
  cpc->next = getRecords;
  getRecords = cpc;
  GNUNET_mutex_unlock (lock);
  return GNUNET_OK;
}

/**
 * CS handler for stopping existing get from DHT.
 */
static int
csGetEnd (struct GNUNET_ClientHandle *client,
          const GNUNET_MessageHeader * message)
{
  const CS_dht_request_get_MESSAGE *get;
  struct DV_DHT_CLIENT_GET_RECORD *pos;
  struct DV_DHT_CLIENT_GET_RECORD *prev;

  if (ntohs (message->size) != sizeof (CS_dht_request_get_MESSAGE))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  get = (const CS_dht_request_get_MESSAGE *) message;
  GNUNET_mutex_lock (lock);
  pos = getRecords;
  prev = NULL;
  while (pos != NULL)
    {
      if ((memcmp (pos->client, client, sizeof (client)) == 0) &&
          (memcmp
           (&pos->get_record->key, &get->key, sizeof (GNUNET_HashCode)))
          && (ntohs (get->type) == pos->get_record->type))
        break;
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_OK;
    }
  if (prev == NULL)
    getRecords = pos->next;
  else
    prev->next = pos->next;
  GNUNET_mutex_unlock (lock);
  dvdhtAPI->get_stop (pos->get_record);
  GNUNET_free (pos);

  return GNUNET_OK;
}

/**
 * CS handler for handling exiting client.  Triggers
 * get_stop for all operations that rely on this client.
 */
static void
csClientExit (struct GNUNET_ClientHandle *client)
{
  struct GNUNET_DV_DHT_GetHandle *gr;
  struct DV_DHT_CLIENT_GET_RECORD *pos;
  struct DV_DHT_CLIENT_GET_RECORD *prev;

  GNUNET_mutex_lock (lock);
  pos = getRecords;
  prev = NULL;
  while (pos != NULL)
    {
      if (pos->client == client)
        {
          gr = pos->get_record;
          if (prev == NULL)
            getRecords = pos->next;
          else
            prev->next = pos->next;
          GNUNET_mutex_unlock (lock);
          dvdhtAPI->get_stop (gr);
          GNUNET_free (pos);
          GNUNET_mutex_lock (lock);
          pos = getRecords;
          continue;
        }
      prev = pos;
      pos = pos->next;
    }
  GNUNET_mutex_unlock (lock);
}

int
initialize_module_dv_dht (GNUNET_CoreAPIForPlugins * capi)
{
  int status;
  GNUNET_GE_LOG (capi->ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 _("`%s' registering client handlers: %d %d %d\n"),
                 "dv_dht", GNUNET_CS_PROTO_DV_DHT_REQUEST_PUT,
                 GNUNET_CS_PROTO_DV_DHT_REQUEST_GET,
                 GNUNET_CS_PROTO_DV_DHT_REQUEST_GET_END);

  dvdhtAPI = capi->service_request ("dv_dht");
  if (dvdhtAPI == NULL)
    return GNUNET_SYSERR;
  coreAPI = capi;

  status = GNUNET_OK;
  lock = GNUNET_mutex_create (GNUNET_NO);
  if (GNUNET_SYSERR ==
      coreAPI->cs_handler_register (GNUNET_CS_PROTO_DV_DHT_REQUEST_PUT,
                                    &csPut))
    status = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      coreAPI->cs_handler_register (GNUNET_CS_PROTO_DV_DHT_REQUEST_GET,
                                    &csGet))
    status = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      coreAPI->cs_handler_register (GNUNET_CS_PROTO_DV_DHT_REQUEST_GET_END,
                                    &csGetEnd))
    status = GNUNET_SYSERR;
  if (GNUNET_SYSERR ==
      coreAPI->cs_disconnect_handler_register (&csClientExit))
    status = GNUNET_SYSERR;
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    0 ==
                    GNUNET_GC_set_configuration_value_string (coreAPI->cfg,
                                                              coreAPI->ectx,
                                                              "ABOUT", "dht",
                                                              gettext_noop
                                                              ("Enables efficient non-anonymous routing")));
  return status;
}

/**
 * Find the record, remove it from the linked list
 * and cancel the operation with the DHT API.
 */
static void
kill_record (void *cls)
{
  struct DV_DHT_CLIENT_GET_RECORD *record = cls;
  struct DV_DHT_CLIENT_GET_RECORD *pos;
  struct DV_DHT_CLIENT_GET_RECORD *prev;

  GNUNET_mutex_lock (lock);
  pos = getRecords;
  prev = NULL;
  while (pos != NULL)
    {
      if (pos == record)
        break;
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      GNUNET_mutex_unlock (lock);
      return;
    }
  if (prev == NULL)
    getRecords = pos->next;
  else
    prev->next = pos->next;
  GNUNET_mutex_unlock (lock);
  dvdhtAPI->get_stop (record->get_record);
  GNUNET_free (record);
}

/**
 * Unregisters handlers, cleans memory structures etc when node exits.
 */
int
done_module_dv_dht ()
{
  int status;

  status = GNUNET_OK;
  GNUNET_GE_LOG (coreAPI->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "DHT: shutdown\n");
  if (GNUNET_OK !=
      coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_DV_DHT_REQUEST_PUT,
                                      &csPut))
    status = GNUNET_SYSERR;
  if (GNUNET_OK !=
      coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_DV_DHT_REQUEST_GET,
                                      &csGet))
    status = GNUNET_SYSERR;
  if (GNUNET_OK != coreAPI->cs_disconnect_handler_unregister (&csClientExit))
    status = GNUNET_SYSERR;

  while (getRecords != NULL)
    kill_record (getRecords);
  coreAPI->service_release (dvdhtAPI);
  dvdhtAPI = NULL;
  coreAPI = NULL;
  GNUNET_mutex_destroy (lock);
  return status;
}

/* end of cs.c */
