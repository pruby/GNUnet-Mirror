/*
      This file is part of GNUnet
      (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file fs/gap/fs_dht.c
 * @brief integration of file-sharing with the DHT
 *        infrastructure
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_dht_service.h"
#include "gnunet_protocols.h"
#include "ecrs_core.h"
#include "fs.h"
#include "fs_dht.h"
#include "querymanager.h"

/**
 * Linked list containing the DHT get handles
 * of our active requests.
 */
struct ActiveRequestRecords
{

  struct ActiveRequestRecords * next;

  struct GNUNET_DHT_GetHandle * handle;

  GNUNET_CronTime end_time;

  unsigned int type;

};

static GNUNET_DHT_ServiceAPI * dht;

static GNUNET_CoreAPIForPlugins * coreAPI;

static struct GNUNET_Mutex * lock;

static struct ActiveRequestRecords * records;

/**
 * Cancel all requests with the DHT that
 * are older than a certain time limit.
 */
static void
purge_old_records(GNUNET_CronTime limit)
{
  struct ActiveRequestRecords * pos;
  struct ActiveRequestRecords * prev;

  prev = NULL;
  pos = records;
  while (pos != NULL)
    {
      if (pos->end_time < limit)
	{
	  if (prev == NULL)
	    records = pos->next;
	  else
	    prev->next = pos->next;
	  dht->get_stop(pos->handle);
	  GNUNET_free(pos);
	  if (prev == NULL)
	    pos = records;
	  else
	    pos = prev->next;
	}
      else
	{
	  prev = pos;
	  pos = pos->next;
	}
    }
}


/**
 * We got a result from the DHT.  Check that it is valid
 * and pass to our clients.  
 *
 * @param key the current key
 * @param value the current value
 * @param cls argument passed for context (closure)
 * @return GNUNET_OK to continue with iteration, GNUNET_SYSERR to abort
 */
static int
response_callback(const GNUNET_HashCode * key,
		  const GNUNET_DataContainer * value,
		  void *cls)
{
  struct ActiveRequestRecords * record = cls;
  unsigned int size;
  const DBlock * dblock;
  GNUNET_HashCode hc;

  size = ntohl(value->size);
  if (size < 4)
    {
      GNUNET_GE_BREAK_OP(NULL, 0);
      return GNUNET_OK;
    }
  dblock = (const DBlock*) &value[1];
  if ( (GNUNET_SYSERR ==
	GNUNET_EC_file_block_check_and_get_query(size,
						 dblock,
						 GNUNET_YES,
						 &hc)) ||
       (0 != memcmp(key,
		    &hc,
		    sizeof(GNUNET_HashCode))) )
    { 
      GNUNET_GE_BREAK_OP(NULL, 0);
      return GNUNET_OK;
    }
  GNUNET_FS_QUERYMANAGER_handle_response(NULL,
					 &hc,
					 0,
					 size,
					 dblock); 
  if (record->type == GNUNET_ECRS_BLOCKTYPE_DATA)
    {
      record->end_time = 0; /* delete ASAP */
      return GNUNET_SYSERR; /* no more! */
    }
  return GNUNET_OK;
}

/**
 * Execute a GAP query.  Determines where to forward
 * the query and when (and captures state for the response).
 * May also have to check the local datastore.
 *
 * @param type type of content requested
 * @param querie hash code of the query
 */
void
GNUNET_FS_DHT_execute_query(unsigned int type,
			    const GNUNET_HashCode * query)
{
  struct ActiveRequestRecords * record;
  GNUNET_CronTime now;

  if (dht == NULL)
    return;
  now = GNUNET_get_time();
  record = GNUNET_malloc(sizeof(struct ActiveRequestRecords));
  record->end_time = now + MAX_DHT_DELAY;
  record->handle = dht->get_start(type,
				  query,
				  &response_callback,
				  record);
  record->type = type;
  GNUNET_mutex_lock(lock);
  record->next = records;
  records = record;
  purge_old_records(now);
  GNUNET_mutex_unlock(lock);
}


int
GNUNET_FS_DHT_init(GNUNET_CoreAPIForPlugins * capi)
{
  coreAPI = capi;
  lock = GNUNET_mutex_create(GNUNET_YES);
  dht = capi->request_service("dht");  
  return 0;
}

int
GNUNET_FS_DHT_done()  
{
  purge_old_records(-1);
  if (dht != NULL)
    coreAPI->release_service(dht);
  coreAPI = NULL;
  GNUNET_mutex_destroy(lock);
  lock = NULL;
  return 0;
}

