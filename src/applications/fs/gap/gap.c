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
 * @file fs/gap/gap.c
 * @brief protocol that performs anonymous routing
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"
#include "gap.h"
#include "fs.h"
#include "ondemand.h"
#include "plan.h"
#include "pid_table.h"

/**
 * The GAP routing table.
 */
static struct RequestList ** table;

static GNUNET_CoreAPIForPlugins * coreAPI;

static GNUNET_Datastore_ServiceAPI * datastore;

static struct GNUNET_CronManager * cron;

/**
 * Size of the routing table.
 */
static unsigned int table_size;

/**
 * Constant but peer-dependent value that randomizes the construction
 * of the indices into the routing table.  See
 * computeRoutingIndex.
 */
static unsigned int random_qsel;


static unsigned int
get_table_index(const GNUNET_HashCode * key)
{
  unsigned int res
    = (((unsigned int *) key)[0] ^
       ((unsigned int *) key)[1] / (1 + random_qsel))
    % table_size;
  GNUNET_GE_ASSERT (coreAPI->ectx, res < table_size);
  return res;
}

/**
 * Cron-job to inject (artificially) delayed messages.
 */
static void
send_delayed(void * cls)
{
  GNUNET_MessageHeader * msg = cls;
  
  coreAPI->p2p_inject_message(NULL,
			      (const char*) msg,
			      ntohl(msg->size),
			      GNUNET_YES,
			      NULL);
  GNUNET_free(msg);
}

/**
 * An iterator over a set of Datastore items.  This
 * function is called whenever GAP is processing a
 * request.  It should
 * 1) abort if the load is getting too high
 * 2) try on-demand encoding (and if that fails,
 *    discard the entry)
 * 3) assemble a response and inject it via 
 *    loopback WITH a delay
 *
 * @param datum called with the next item
 * @param closure user-defined extra argument
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 *
 * @return GNUNET_SYSERR to abort the iteration, GNUNET_OK to continue,
 *         GNUNET_NO to delete the item and continue (if supported)
 */
static int 
datastore_value_processor (const GNUNET_HashCode * key,
			   const GNUNET_DatastoreValue *
			   value, void *closure,
			   unsigned long long uid)
{
  struct RequestList *  req = closure;
  P2P_gap_reply_MESSAGE * msg;
  GNUNET_DatastoreValue * enc;
  unsigned int size;
  unsigned long long et;
  GNUNET_CronTime now;
  int ret;
  GNUNET_HashCode hc;
  GNUNET_HashCode mhc;
  
  enc = NULL;
  if (ntohl(value->type) == GNUNET_ECRS_BLOCKTYPE_ONDEMAND)
    {
      if (GNUNET_OK !=
	  GNUNET_FS_ONDEMAND_get_indexed_content(value,
						 key,
						 &enc))
	return GNUNET_NO;
      value = enc;
    }
  if (req->bloomfilter != NULL)
    {
      GNUNET_hash(&value[1],
		  ntohl(value->size) - sizeof(GNUNET_DatastoreValue),
		  &hc);
      GNUNET_FS_HELPER_mingle_hash(&hc,
				   req->bloomfilter_mutator,
				   &mhc);
      if (GNUNET_YES == GNUNET_bloomfilter_test(req->bloomfilter,
						&mhc))
	return GNUNET_OK; /* not useful */		  
    }
  et = GNUNET_ntohll(value->expirationTime);
  now = GNUNET_get_time();
  if (now > et)
    et -= now;
  else
    et = 0;
  et %= MAX_MIGRATION_EXP;
  size = sizeof(P2P_gap_reply_MESSAGE) + ntohl(value->size) - sizeof(GNUNET_DatastoreValue);
  msg = GNUNET_malloc(size);
  msg->header.type = htons(GNUNET_P2P_PROTO_GAP_RESULT);
  msg->header.size = htons(size);
  msg->reserved = htonl(0);
  msg->expiration = et;
  memcpy(&msg[1],
	 &value[1],
	 size - sizeof(P2P_gap_reply_MESSAGE));
  GNUNET_cron_add_job(cron,
		      send_delayed,
		      GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
					 TTL_DECREMENT),		      
		      0,
		      msg);
  ret = (ntohl(value->type) == GNUNET_ECRS_BLOCKTYPE_DATA) ? GNUNET_SYSERR : GNUNET_OK;
  GNUNET_free(msg);
  GNUNET_free_non_null(enc);
  return ret;
}

/**
 * Execute a GAP query.  Determines where to forward
 * the query and when (and captures state for the response).
 * Also check the local datastore.
 *
 * @param respond_to where to send replies
 * @param priority how important is the request for us?
 * @param ttl how long should the query live?
 * @param type type of content requested
 * @param query_count how many queries are in the queries array?
 * @param queries hash codes of the query
 * @param filter_mutator how to map replies to the bloom filter
 * @param filter_size size of the bloom filter
 * @param bloomfilter_data the bloom filter bits
 */
void
GNUNET_FS_GAP_execute_query(const GNUNET_PeerIdentity * respond_to,
			    unsigned int priority,
			    enum GNUNET_FS_RoutingPolicy policy,
			    int ttl,
			    unsigned int type,
			    unsigned int query_count,
			    const GNUNET_HashCode * queries,
			    int filter_mutator,
			    unsigned int filter_size,
			    const void * bloomfilter_data) 
{
  struct RequestList * rl;
  PID_INDEX peer;
  unsigned int index;
  GNUNET_CronTime now;

  GNUNET_GE_ASSERT(NULL, query_count > 0);
  peer = GNUNET_FS_PT_intern(respond_to);
  GNUNET_mutex_lock(GNUNET_FS_lock);
  index = get_table_index(&queries[0]);
  now = GNUNET_get_time();

  /* check if table is full (and/or delete old entries!) */
  if ( (table[index] != NULL) &&
       (table[index]->next != NULL) )
    {
      /* limit to at most two entries per slot in table */
      if ( (now + ttl < table[index]->expiration) &&
	   (now + ttl < table[index]->next->expiration) )
	{
	  /* do not process */
	  GNUNET_mutex_unlock(GNUNET_FS_lock);
	  return;
	}
      if (table[index]->expiration >
	  table[index]->next->expiration)
	{
	  GNUNET_FS_SHARED_free_request_list(table[index]->next);
	  table[index]->next = NULL;
	}
      else
	{
	  rl = table[index];
	  table[index] = rl->next;
	  GNUNET_FS_SHARED_free_request_list(rl);
	}
    }

  /* create new table entry */
  rl = GNUNET_malloc(sizeof(struct RequestList) + (query_count-1) * sizeof(GNUNET_HashCode));
  memset(rl, 0, sizeof(struct RequestList));
  memcpy(&rl->queries[0], queries, query_count * sizeof(GNUNET_HashCode));
  rl->key_count = query_count;
  if (filter_size > 0)
    {
      rl->bloomfilter_size = filter_size;
      rl->bloomfilter_mutator = filter_mutator;
      rl->bloomfilter = GNUNET_bloomfilter_init(coreAPI->ectx,
						bloomfilter_data,
						filter_size,
						GAP_BLOOMFILTER_K);
    }
  rl->anonymityLevel = 1;
  rl->type = type;
  rl->value = priority;
  rl->expiration = GNUNET_get_time() + ttl * GNUNET_CRON_SECONDS;
  rl->next = table[index];
  rl->response_target = GNUNET_FS_PT_intern(respond_to);
  table[index] = rl;  
  
  /* check local data store */
  datastore->get(&queries[0],
		 type,
		 datastore_value_processor,
		 rl);
  /* if not found or not unique, forward */
  GNUNET_FS_PLAN_request(NULL, peer, rl);
  GNUNET_mutex_unlock(GNUNET_FS_lock);
}

/**
 * Handle the given response (by forwarding it to
 * other peers as necessary).  
 *
 * @param sender who send the response (good too know
 *        for future routing decisions)
 * @param primary_query hash code used for lookup 
 *        (note that namespace membership may
 *        require additional verification that has
 *        not yet been performed; checking the
 *        signature has already been done)
 * @param expiration relative time until the content
 *        will expire 
 * @param size size of the data
 * @param data the data itself
 * @return how much was this content worth to us?
 */
unsigned int
GNUNET_FS_GAP_handle_response(const GNUNET_PeerIdentity * sender,
			      const GNUNET_HashCode * primary_query,
			      GNUNET_CronTime expiration,
			      unsigned int size,
			      const DBlock * data)
{
  GNUNET_HashCode hc;
  GNUNET_PeerIdentity target;
  struct RequestList * rl;
  unsigned int value;
  P2P_gap_reply_MESSAGE * msg;
  PID_INDEX rid;

  rid = GNUNET_FS_PT_intern(sender);
  value = 0;
  GNUNET_mutex_lock(GNUNET_FS_lock);
  rl = table[get_table_index(primary_query)];
  while (rl != NULL)
    {      
      if (GNUNET_OK == GNUNET_FS_SHARED_test_valid_new_response(rl,
								primary_query,
								size,
								data,
								&hc))
	{
	  GNUNET_GE_ASSERT(NULL, rl->response_target != 0);
	  GNUNET_FS_PT_resolve(rl->response_target,
			       &target);
	  /* queue response */
	  msg = GNUNET_malloc(sizeof(P2P_gap_reply_MESSAGE) + size);
	  msg->header.type = htons(GNUNET_CS_PROTO_GAP_RESULT);
	  msg->header.size = htons(sizeof(P2P_gap_reply_MESSAGE) + size);
	  msg->reserved = 0;
	  msg->expiration = GNUNET_htonll(expiration);
	  memcpy(&msg[1],
		 data,
		 size);
	  coreAPI->unicast(&target,
			   &msg->header,
			   BASE_REPLY_PRIORITY * (1 + rl->value),
			   MAX_GAP_DELAY);
	  GNUNET_free(msg);
	  if ( (rl->type != GNUNET_ECRS_BLOCKTYPE_DATA) &&
	       (rl->bloomfilter != NULL) )
	    GNUNET_FS_SHARED_mark_response_seen(rl, &hc);
	  GNUNET_FS_PLAN_success(rid, NULL, rl->response_target, rl);
	  value += rl->value;
	  rl->value = 0;
	}
      rl = rl->next;
    }
  GNUNET_mutex_unlock(GNUNET_FS_lock);
  GNUNET_FS_PT_change_rc(rid, -1);
  return value;
}

int 
GNUNET_FS_GAP_init(GNUNET_CoreAPIForPlugins * capi)
{
  unsigned long long ts;

  coreAPI = capi;
  datastore = capi->request_service("datastore");
  random_qsel = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 0xFFFF);
  if (-1 ==
      GNUNET_GC_get_configuration_value_number (coreAPI->cfg, "GAP", "TABLESIZE",
						MIN_INDIRECTION_TABLE_SIZE,
						GNUNET_MAX_GNUNET_malloc_CHECKED
						/
						sizeof
						(struct RequestList *),
						MIN_INDIRECTION_TABLE_SIZE,
						&ts))
    return GNUNET_SYSERR;
  table_size = ts;
  table = GNUNET_malloc (sizeof (struct RequestList*) * table_size);
  memset (table,
          0, sizeof (struct RequestList*) * table_size);
  cron =  GNUNET_cron_create(coreAPI->ectx);
  GNUNET_cron_start(cron);
  return 0;
}

int 
GNUNET_FS_GAP_done()
{
  unsigned int i;
  struct RequestList * rl;

  for (i = 0; i < table_size; i++)
    {
      while (NULL != (rl = table[i]))
	{
	  table[i] = rl->next;
	  GNUNET_FS_SHARED_free_request_list(rl);
	}
    }
  GNUNET_free(table);
  coreAPI->release_service(datastore);
  datastore = NULL;
  GNUNET_cron_stop(cron);
  GNUNET_cron_destroy(cron);
  return 0;
}

/* end of gap.c */
