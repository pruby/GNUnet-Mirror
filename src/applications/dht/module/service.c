/*
      This file is part of GNUnet
      (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file module/service.c
 * @brief internal GNUnet DHT service
 * @author Christian Grothoff
 */

#include "platform.h"
#include "dstore.h"
#include "table.h"
#include "routing.h"
#include "gnunet_dht_service.h"

/**
 * Global core API.
 */
static CoreAPIForApplication * coreAPI;

typedef struct DHT_GET_RECORD {
  /**
   * Key that we are looking for.
   */  
  HashCode512 key;

  /**
   * Function to call for each result.
   */
  DataProcessor callback;

  /**
   * Extra argument to callback.
   */
  void * cls;

  /**
   * Function to call once we are done
   */
  DHT_OP_Complete callbackComplete;

  /**
   * Extra argument to callbackComplete
   */
  void * closure;

  /**
   * Type of the content that we are looking for.
   */
  unsigned int type;

} DHT_GET_RECORD;

static void client_result_converter(const HashCode512 * key,
				    unsigned int type,
				    unsigned int size,
				    const char * data,
				    void * cls) {
  struct DHT_GET_RECORD * get = cls;
  DataContainer * dc;

  dc = MALLOC(sizeof(DataContainer) + size);
  dc->size = ntohl(sizeof(DataContainer) + size);
  memcpy(&dc[1],
	 data,
	 size);
  get->callback(key,
		dc,
		get->cls);
  FREE(dc);
}

/**
 * Cron job that notifies the client.
 */
static void timeout_callback(void * cls) {
  struct DHT_GET_RECORD * rec = cls;

  rec->callbackComplete(rec->closure);
}

/**
 * Perform an asynchronous GET operation on the DHT identified by
 * 'table' using 'key' as the key.  The peer does not have to be part
 * of the table (if so, we will attempt to locate a peer that is!).
 *
 * Even in the case of a time-out (once completion callback has been
 * invoked), clients will still call the "stop" function explicitly.
 *
 * @param table table to use for the lookup
 * @param key the key to look up
 * @param timeout how long to wait until this operation should
 *        automatically time-out
 * @param callback function to call on each result
 * @param closure extra argument to callback
 * @param callbackComplete function called on time-out
 *        (but not on explicit async_stop).
 * @return handle to stop the async get
 */
static struct DHT_GET_RECORD *
dht_get_async_start(unsigned int type,
		    const HashCode512 * key,
		    cron_t timeout,
		    DataProcessor callback,
		    void * cls,
		    DHT_OP_Complete callbackComplete,
		    void * closure) {
  struct DHT_GET_RECORD * ret;

  ret = MALLOC(sizeof(DHT_GET_RECORD));
  ret->key = *key;
  ret->callback = callback;
  ret->cls = cls;
  ret->callbackComplete = callbackComplete;
  ret->closure = closure;
  ret->type = type;
  cron_add_job(coreAPI->cron,
	       &timeout_callback,
	       timeout,
	       0,
	       ret);
  dht_get_start(key,
		type,
		&client_result_converter,
		ret);
  return ret;
}

/**
 * Stop async DHT-get.  Frees associated resources.
 */
static int
dht_get_async_stop(struct DHT_GET_RECORD * record) {
  cron_suspend(coreAPI->cron,
	       YES);
  cron_del_job(coreAPI->cron,
	       &timeout_callback,
	       0,
	       record);		
  cron_resume_jobs(coreAPI->cron,
		   YES);
  dht_get_stop(&record->key,
	       record->type,
	       &client_result_converter,
	       record);  
  FREE(record);
  return OK;
}

/**
 * Provide the DHT service.  The DHT service depends on the RPC
 * service.
 *
 * @param capi the core API
 * @return NULL on errors, DHT_API otherwise
 */
DHT_ServiceAPI * 
provide_module_dht(CoreAPIForApplication * capi) {
  static DHT_ServiceAPI api;

  if (OK != init_dht_store(1024 * 1024,
			   capi))
    return NULL;
  if (OK != init_dht_table(capi)) {
    done_dht_store();
    return NULL;
  }
  if (OK != init_dht_routing(capi)) {
    done_dht_table();
    done_dht_store();
    return NULL;
  }
  coreAPI = capi;
  api.get_start = &dht_get_async_start;
  api.get_stop = &dht_get_async_stop;
  api.put = &dht_put;
  return &api;
}

/**
 * Shutdown DHT service.
 */
int release_module_dht() {
  done_dht_routing();
  done_dht_table();
  done_dht_store();
  return OK;
}

/* end of service.c */
