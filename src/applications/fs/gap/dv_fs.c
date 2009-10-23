/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/gap/dv_fs.c
 * @brief functions for handling CS and P2P file-sharing requests
 * @author Christian Grothoff, Nathan Evans
 *
 * This file contains all of the entry points to the file-sharing
 * module.
 *
 * TODO:
 * - integrate with migration submodule
 * - make sure we do an immediate PUSH for DHT stuff
 *   given to us with anonymity_level zero.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_directories.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_traffic_service.h"
#include "ecrs_core.h"
#include "anonymity.h"
#include "fs.h"
#include "fs_dv_dht.h"
#include "gap.h"
#include "migration.h"
#include "dv_querymanager.h"
#include "ondemand.h"
#include "plan.h"
#include "pid_table.h"
#include "shared.h"
#include "gnunet_dv_service.h"


#define DEBUG_FS GNUNET_NO

/**
 * Lock shared between all C files in this
 * directory.
 */
struct GNUNET_Mutex *GNUNET_FS_lock;

static struct GNUNET_GE_Context *ectx;

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Identity_ServiceAPI *identity;

static GNUNET_Stats_ServiceAPI *stats;

static GNUNET_DV_ServiceAPI *dv_api;

static GNUNET_Datastore_ServiceAPI *datastore;

static int active_migration;

static int stat_gap_query_received;

static int stat_gap_query_drop_busy;

static int stat_gap_content_received;

static int stat_gap_trust_awarded;

/**
 * Hard CPU limit
 */
static unsigned long long hardCPULimit;

/**
 * Hard network upload limit.
 */
static unsigned long long hardUpLimit;


struct DV_send_closure
{
  struct RequestList *request;
  const P2P_gap_query_MESSAGE *message;
};

/* ********************* CS handlers ********************** */

/**
 * Process a request to insert content from the client.
 *
 * @return GNUNET_SYSERR if the TCP connection should be closed, otherwise GNUNET_OK
 */
static int
handle_cs_insert_request (struct GNUNET_ClientHandle *sock,
                          const GNUNET_MessageHeader * req)
{
  const CS_fs_request_insert_MESSAGE *ri;
  GNUNET_DatastoreValue *datum;
  struct GNUNET_GE_Context *cectx;
  GNUNET_HashCode query;
  int ret;
#if DEBUG_FS
  GNUNET_EncName enc;
#endif

  ri = (const CS_fs_request_insert_MESSAGE *) req;
  if ((ntohs (req->size) < sizeof (CS_fs_request_insert_MESSAGE)) ||
      (GNUNET_OK !=
       GNUNET_EC_file_block_check_and_get_query (ntohs (ri->header.size) -
                                                 sizeof
                                                 (CS_fs_request_insert_MESSAGE),
                                                 (const GNUNET_EC_DBlock *)
                                                 &ri[1], GNUNET_YES, &query)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  datum = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) +
                         ntohs (req->size) -
                         sizeof (CS_fs_request_insert_MESSAGE));
  datum->size =
    htonl (sizeof (GNUNET_DatastoreValue) + ntohs (req->size) -
           sizeof (CS_fs_request_insert_MESSAGE));
  datum->expiration_time = ri->expiration;
  datum->priority = ri->priority;
  datum->anonymity_level = ri->anonymity_level;
  datum->type =
    htonl (GNUNET_EC_file_block_get_type
           (ntohs (ri->header.size) - sizeof (CS_fs_request_insert_MESSAGE),
            (const GNUNET_EC_DBlock *) &ri[1]));
#if DEBUG_FS
  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&query, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received REQUEST INSERT (query: `%s', type: %u, priority %u)\n",
                 &enc, ntohl (datum->type), ntohl (ri->priority));
#endif
  memcpy (&datum[1],
          &ri[1], ntohs (req->size) - sizeof (CS_fs_request_insert_MESSAGE));
  ret = datastore->putUpdate (&query, datum);
  if (ret == GNUNET_NO)
    {
      cectx = coreAPI->cs_log_context_create (sock);
      GNUNET_GE_LOG (cectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Datastore full.\n"));
      GNUNET_GE_free_context (cectx);
    }
  GNUNET_free (datum);
  return coreAPI->cs_send_value (sock, ret);
}

/**
 * Process a request to symlink a file
 */
static int
handle_cs_init_index_request (struct GNUNET_ClientHandle *sock,
                              const GNUNET_MessageHeader * req)
{
  const CS_fs_request_init_index_MESSAGE *ri;
  struct GNUNET_GE_Context *cectx;
  int fnLen;
  int ret;
  char *fn;

  fnLen = ntohs (req->size) - sizeof (CS_fs_request_init_index_MESSAGE);
  if ((ntohs (req->size) < sizeof (CS_fs_request_init_index_MESSAGE))
#if WINDOWS
      || (fnLen > _MAX_PATH)
#endif
    )
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  ri = (const CS_fs_request_init_index_MESSAGE *) req;
  fn = GNUNET_malloc (fnLen + 1);
  strncpy (fn, (const char *) &ri[1], fnLen + 1);
  fn[fnLen] = 0;
  cectx = coreAPI->cs_log_context_create (sock);
  ret =
    GNUNET_FS_ONDEMAND_index_prepare_with_symlink (cectx, &ri->fileId, fn);
  GNUNET_GE_free_context (cectx);
  GNUNET_free (fn);
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Sending confirmation (%s) of index initialization request to client\n",
                 ret == GNUNET_OK ? "success" : "failure");
#endif
  return coreAPI->cs_send_value (sock, ret);
}

/**
 * Process a request to index content from the client.
 *
 * @return GNUNET_SYSERR if the TCP connection should be closed, otherwise GNUNET_OK
 */
static int
handle_cs_index_request (struct GNUNET_ClientHandle *sock,
                         const GNUNET_MessageHeader * req)
{
  int ret;
  const CS_fs_request_index_MESSAGE *ri;
  struct GNUNET_GE_Context *cectx;
#if DEBUG_FS
  GNUNET_HashCode hc;
  GNUNET_EncName enc;
#endif

  if (ntohs (req->size) < sizeof (CS_fs_request_index_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  cectx = coreAPI->cs_log_context_create (sock);
  ri = (const CS_fs_request_index_MESSAGE *) req;
#if DEBUG_FS
  GNUNET_EC_file_block_get_query ((const GNUNET_EC_DBlock *) &ri[1],
                                  ntohs (ri->header.size) -
                                  sizeof (CS_fs_request_index_MESSAGE), &hc);
  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&hc, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received REQUEST INDEX (query: `%s', priority %u)\n",
                 &enc, ntohl (ri->priority));
#endif
  ret = GNUNET_FS_ONDEMAND_add_indexed_content (cectx,
                                                datastore,
                                                ntohl (ri->priority),
                                                GNUNET_ntohll
                                                (ri->expiration),
                                                GNUNET_ntohll
                                                (ri->fileOffset),
                                                ntohl (ri->anonymity_level),
                                                &ri->fileId,
                                                ntohs (ri->header.size) -
                                                sizeof
                                                (CS_fs_request_index_MESSAGE),
                                                (const GNUNET_EC_DBlock *)
                                                &ri[1]);
  GNUNET_GE_free_context (cectx);
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Sending confirmation (%s) of index request to client\n",
                 ret == GNUNET_OK ? "success" : "failure");
#endif
  return coreAPI->cs_send_value (sock, ret);
}

/**
 * Process a query to delete content.
 *
 * @return GNUNET_SYSERR if the TCP connection should be closed, otherwise GNUNET_OK
 */
static int
handle_cs_delete_request (struct GNUNET_ClientHandle *sock,
                          const GNUNET_MessageHeader * req)
{
  int ret;
  const CS_fs_request_delete_MESSAGE *rd;
  GNUNET_DatastoreValue *value;
  GNUNET_HashCode query;
  unsigned int type;
#if DEBUG_FS
  GNUNET_EncName enc;
#endif

  if (ntohs (req->size) < sizeof (CS_fs_request_delete_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  rd = (const CS_fs_request_delete_MESSAGE *) req;
  value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) +
                         ntohs (req->size) -
                         sizeof (CS_fs_request_delete_MESSAGE));
  value->size =
    ntohl (sizeof (GNUNET_DatastoreValue) + ntohs (req->size) -
           sizeof (CS_fs_request_delete_MESSAGE));
  type =
    GNUNET_EC_file_block_get_type (ntohs (rd->header.size) -
                                   sizeof (CS_fs_request_delete_MESSAGE),
                                   (const GNUNET_EC_DBlock *) &rd[1]);
  value->type = htonl (type);
  memcpy (&value[1],
          &rd[1], ntohs (req->size) - sizeof (CS_fs_request_delete_MESSAGE));
  if (GNUNET_OK !=
      GNUNET_EC_file_block_check_and_get_query (ntohs (rd->header.size) -
                                                sizeof
                                                (CS_fs_request_delete_MESSAGE),
                                                (const GNUNET_EC_DBlock *)
                                                &rd[1], GNUNET_NO, &query))
    {
      GNUNET_free (value);
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
#if DEBUG_FS
  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&query, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received REQUEST DELETE (query: `%s', type: %u)\n", &enc,
                 type);
#endif
  GNUNET_mutex_lock (GNUNET_FS_lock);
  value->type = htonl (GNUNET_ECRS_BLOCKTYPE_ANY);
  ret = datastore->get (&query, type,
                        &GNUNET_FS_HELPER_complete_value_from_database_callback,
                        value);
  if ((0 < ret) && (value->type != htonl (GNUNET_ECRS_BLOCKTYPE_ANY)))
    {
      ret = datastore->del (&query, value);
    }
  else
    {                           /* not found */
      ret = GNUNET_SYSERR;
    }
  GNUNET_mutex_unlock (GNUNET_FS_lock);
  GNUNET_free (value);
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Sending confirmation (%s) of delete request to client\n",
                 ret != GNUNET_SYSERR ? "success" : "failure");
#endif
  return coreAPI->cs_send_value (sock, ret);
}

/**
 * Process a client request unindex content.
 */
static int
handle_cs_unindex_request (struct GNUNET_ClientHandle *sock,
                           const GNUNET_MessageHeader * req)
{
  int ret;
  const CS_fs_request_unindex_MESSAGE *ru;
  struct GNUNET_GE_Context *cectx;

  cectx = coreAPI->cs_log_context_create (sock);
  if (ntohs (req->size) != sizeof (CS_fs_request_unindex_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_GE_BREAK (cectx, 0);
      GNUNET_GE_free_context (cectx);
      return GNUNET_SYSERR;
    }
  ru = (const CS_fs_request_unindex_MESSAGE *) req;
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received REQUEST UNINDEX\n");
#endif
  ret = GNUNET_FS_ONDEMAND_delete_indexed_content (cectx,
                                                   datastore,
                                                   ntohl (ru->blocksize),
                                                   &ru->fileId);
  GNUNET_GE_free_context (cectx);
  return coreAPI->cs_send_value (sock, ret);
}

/**
 * Process a client request to test if certain
 * data is indexed.
 */
static int
handle_cs_test_indexed_request (struct GNUNET_ClientHandle *sock,
                                const GNUNET_MessageHeader * req)
{
  int ret;
  const CS_fs_request_test_index_MESSAGE *ru;

  if (ntohs (req->size) != sizeof (CS_fs_request_test_index_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  ru = (const CS_fs_request_test_index_MESSAGE *) req;
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received REQUEST TESTINDEXED\n");
#endif
  ret = GNUNET_FS_ONDEMAND_test_indexed_file (datastore, &ru->fileId);
  return coreAPI->cs_send_value (sock, ret);
}

struct FPPClosure
{
  struct GNUNET_ClientHandle *sock;
  struct GNUNET_MultiHashMap *seen;
  unsigned int processed;
  int have_more;
};

/**
 * Any response that we get should be passed
 * back to the client.  If the response is unique,
 * we should abort the iteration (return GNUNET_SYSERR).
 */
static int
fast_path_processor (const GNUNET_HashCode * key,
                     const GNUNET_DatastoreValue *
                     value, void *closure, unsigned long long uid)
{
  struct FPPClosure *cls = closure;
  GNUNET_HashCode hc;
  unsigned int type;
  int ret;

  if (cls->processed > GNUNET_GAP_MAX_SYNC_PROCESSED)
    {
      cls->have_more = GNUNET_YES;
      return GNUNET_SYSERR;
    }
  type = ntohl (((const GNUNET_EC_DBlock *) &value[1])->type);
  ret = GNUNET_FS_HELPER_send_to_client (coreAPI,
                                         key, value, cls->sock, NULL, &hc);
  if (ret == GNUNET_NO)
    return GNUNET_NO;           /* delete + continue */
  cls->processed++;
  if (ret != GNUNET_OK)
    cls->have_more = GNUNET_YES;        /* switch to async processing */
  if ((type == GNUNET_ECRS_BLOCKTYPE_DATA) || (ret != GNUNET_OK))
    return GNUNET_SYSERR;       /* unique response or client can take no more */
  if (cls->seen == NULL)
    cls->seen = GNUNET_multi_hash_map_create (8);
  GNUNET_multi_hash_map_put (cls->seen,
                             &hc,
                             NULL, GNUNET_MultiHashMapOption_UNIQUE_FAST);
  return GNUNET_OK;
}


/**
 * Process a query from the client. Forwards to the network.
 *
 * @return GNUNET_SYSERR if the TCP connection should be closed, otherwise GNUNET_OK
 */
static int
handle_cs_query_start_request (struct GNUNET_ClientHandle *sock,
                               const GNUNET_MessageHeader * req)
{
  static GNUNET_PeerIdentity all_zeros;
  struct FPPClosure fpp;
  const CS_fs_request_search_MESSAGE *rs;
  unsigned int keyCount;
  unsigned int type;
  unsigned int anonymityLevel;
  int have_target;
#if DEBUG_FS
  GNUNET_EncName enc;
#endif

  if (ntohs (req->size) < sizeof (CS_fs_request_search_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  rs = (const CS_fs_request_search_MESSAGE *) req;
  type = ntohl (rs->type);
  /* try "fast path" avoiding gap/dht if unique reply is locally available */
#if DEBUG_FS
  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&rs->query[0], &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received QUERY (query: `%s', type: %u)\n", &enc, type);
#endif
  fpp.sock = sock;
  fpp.seen = NULL;
  fpp.have_more = GNUNET_NO;
  fpp.processed = 0;
  if (GNUNET_OK ==
      coreAPI->cs_send_message_now_test (sock,
                                         GNUNET_GAP_ESTIMATED_DATA_SIZE,
                                         GNUNET_NO))
    {
      if (type == GNUNET_ECRS_BLOCKTYPE_DATA)
        {
          if (((1 == datastore->get (&rs->query[0],
                                     type, &fast_path_processor, &fpp)) ||
               (1 == datastore->get (&rs->query[0],
                                     GNUNET_ECRS_BLOCKTYPE_ONDEMAND,
                                     &fast_path_processor, &fpp))) &&
              (fpp.have_more == GNUNET_NO))
            goto CLEANUP;
        }
      else
        datastore->get (&rs->query[0], type, &fast_path_processor, &fpp);
    }
  else
    fpp.have_more = GNUNET_YES;
  anonymityLevel = ntohl (rs->anonymity_level);
  keyCount =
    1 + (ntohs (req->size) -
         sizeof (CS_fs_request_search_MESSAGE)) / sizeof (GNUNET_HashCode);
  have_target =
    memcmp (&all_zeros, &rs->target, sizeof (GNUNET_PeerIdentity)) != 0;
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "in dv_fs, have_target is %d", have_target);

  GNUNET_DV_FS_QUERYMANAGER_start_query (&rs->query[0], keyCount,
                                         anonymityLevel, type, sock,
                                         have_target ? &rs->target : NULL,
                                         fpp.seen, fpp.have_more);
CLEANUP:
  if (fpp.seen != NULL)
    GNUNET_multi_hash_map_destroy (fpp.seen);
  return GNUNET_OK;
}

/**
 * Process a stop request from the client.
 *
 * @return GNUNET_SYSERR if the TCP connection should be closed, otherwise GNUNET_OK
 */
static int
handle_cs_query_stop_request (struct GNUNET_ClientHandle *sock,
                              const GNUNET_MessageHeader * req)
{
  const CS_fs_request_search_MESSAGE *rs;
  unsigned int keyCount;
  unsigned int type;
  unsigned int anonymityLevel;

  if (ntohs (req->size) < sizeof (CS_fs_request_search_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  rs = (const CS_fs_request_search_MESSAGE *) req;
  type = ntohl (rs->type);
  anonymityLevel = ntohl (rs->anonymity_level);
  keyCount =
    1 + (ntohs (req->size) -
         sizeof (CS_fs_request_search_MESSAGE)) / sizeof (GNUNET_HashCode);
  GNUNET_DV_FS_QUERYMANAGER_stop_query (&rs->query[0], keyCount,
                                        anonymityLevel, type, sock);
  return GNUNET_OK;
}


/**
 * Return 1 if the current network (upstream) or CPU load is
 * (far) too high, 0 if the load is ok.
 */
static int
test_load_too_high ()
{
  return ((hardCPULimit > 0) &&
          (GNUNET_cpu_get_load (ectx,
                                coreAPI->cfg) >= hardCPULimit)) ||
    ((hardUpLimit > 0) &&
     (GNUNET_network_monitor_get_load (coreAPI->load_monitor,
                                       GNUNET_ND_UPLOAD) >= hardUpLimit));
}

static int
send_results_dv (const GNUNET_HashCode * key,
                 const GNUNET_DatastoreValue * value, void *closure,
                 unsigned long long uid)
{
  struct DV_send_closure *dvcls = (struct DV_send_closure *) closure;
  const P2P_gap_query_MESSAGE *original_msg = dvcls->message;
  P2P_gap_reply_MESSAGE *msg;
  GNUNET_DatastoreValue *enc;
  unsigned int size;
  unsigned long long et;
  GNUNET_CronTime now;
  int ret;
  int want_more;

  want_more = GNUNET_OK;

  enc = NULL;
  if (ntohl (value->type) == GNUNET_ECRS_BLOCKTYPE_ONDEMAND)
    {
      if (GNUNET_OK !=
          GNUNET_FS_ONDEMAND_get_indexed_content (value, key, &enc))
        return GNUNET_NO;
      value = enc;
    }

  et = GNUNET_ntohll (value->expiration_time);
  now = GNUNET_get_time ();
  /* convert to relative expiration time */
  if (now < et)
    {
      et -= now;
      if (ntohl (value->type) == GNUNET_ECRS_BLOCKTYPE_KEYWORD)
        et %= GNUNET_GAP_MAX_MIGRATION_EXP_KSK;
      else
        et %= GNUNET_GAP_MAX_MIGRATION_EXP;
    }
  else
    {
      if (ntohl (value->type) == GNUNET_ECRS_BLOCKTYPE_KEYWORD)
        return want_more;       /* expired KSK -- ignore! */
      /* indicate entry has expired */
      et = -1;
    }
  size =
    sizeof (P2P_gap_reply_MESSAGE) + ntohl (value->size) -
    sizeof (GNUNET_DatastoreValue);
  msg = GNUNET_malloc (size);
  msg->header.type = htons (GNUNET_P2P_PROTO_GAP_RESULT);
  msg->header.size = htons (size);
  msg->reserved = htonl (0);
  msg->expiration = GNUNET_htonll (et);
  memcpy (&msg[1], &value[1], size - sizeof (P2P_gap_reply_MESSAGE));

  ret =
    dv_api->dv_send (&original_msg->returnTo, &msg->header,
                     htonl (original_msg->priority), et);
  if (stats != NULL)
    {
      //stats->change (stat_trust_earned, req->value_offered);
    }

  GNUNET_free_non_null (enc);
  return ret;

}

/**
 * Handle P2P query for content.
 */
static int
handle_p2p_query (const GNUNET_PeerIdentity * sender,
                  const GNUNET_MessageHeader * msg)
{
  const P2P_gap_query_MESSAGE *req;
  unsigned int query_count;
  unsigned short size;
  unsigned int bloomfilter_size;
  int ttl;
  unsigned int prio;
  unsigned int type;
  unsigned int netLoad;
  int have_peer;
  int have_data;
  GNUNET_EncName enc;
  enum GNUNET_FS_RoutingPolicy policy;
  double preference;
  struct DV_send_closure *dv_cls;

  if (stats != NULL)
    stats->change (stat_gap_query_received, 1);
  if (test_load_too_high ())
    {
#if DEBUG_GAP
      if (sender != NULL)
        {
          IF_GELOG (ectx,
                    GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                    GNUNET_hash_to_enc (&sender->hashPubKey, &enc));
        }
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Dropping query from %s, this peer is too busy.\n",
                     sender == NULL ? "localhost" : (char *) &enc);
#endif
      if (stats != NULL)
        stats->change (stat_gap_query_drop_busy, 1);
      return GNUNET_OK;
    }
  size = ntohs (msg->size);
  if (size < sizeof (P2P_gap_query_MESSAGE))
    {
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;     /* malformed query */
    }
  req = (const P2P_gap_query_MESSAGE *) msg;
  query_count = ntohl (req->number_of_queries);
  if ((query_count == 0) ||
      (query_count > GNUNET_MAX_BUFFER_SIZE / sizeof (GNUNET_HashCode)) ||
      (size <
       sizeof (P2P_gap_query_MESSAGE) + (query_count -
                                         1) * sizeof (GNUNET_HashCode))
      || (0 ==
          memcmp (&req->returnTo, coreAPI->my_identity,
                  sizeof (GNUNET_PeerIdentity))))
    {
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;     /* malformed query */
    }
  bloomfilter_size =
    size - (sizeof (P2P_gap_query_MESSAGE) +
            (query_count - 1) * sizeof (GNUNET_HashCode));
  GNUNET_GE_ASSERT (NULL, bloomfilter_size < size);
  prio = ntohl (req->priority);
  netLoad =
    GNUNET_network_monitor_get_load (coreAPI->load_monitor, GNUNET_ND_UPLOAD);
  if ((netLoad == (unsigned int) -1)
      || (netLoad < GNUNET_GAP_IDLE_LOAD_THRESHOLD))
    {
      prio = 0;                 /* minimum priority, no charge! */
      policy = GNUNET_FS_RoutingPolicy_ALL;
    }
  else
    {
      prio = -identity->changeHostTrust (sender, -prio);
      if (netLoad < GNUNET_GAP_IDLE_LOAD_THRESHOLD + prio)
        {
          policy = GNUNET_FS_RoutingPolicy_ALL;
        }
      else if (netLoad < 90 + 10 * prio)
        {
          policy =
            GNUNET_FS_RoutingPolicy_ANSWER | GNUNET_FS_RoutingPolicy_FORWARD;
        }
      else if (netLoad < 100)
        {
          policy = GNUNET_FS_RoutingPolicy_ANSWER;
        }
      else
        {
          if (stats != NULL)
            stats->change (stat_gap_query_drop_busy, 1);
          return GNUNET_OK;     /* drop */
        }
    }
  if ((policy & GNUNET_FS_RoutingPolicy_INDIRECT) == 0)
    /* kill the priority (since we cannot benefit) */
    prio = 0;
  ttl = GNUNET_FS_HELPER_bound_ttl (ntohl (req->ttl), prio);
  type = ntohl (req->type);
  /* decrement ttl (always) */
  if (ttl < 0)
    {
      ttl -= 2 * GNUNET_GAP_TTL_DECREMENT +
        GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                           GNUNET_GAP_TTL_DECREMENT);
      if (ttl > 0)
        /* integer underflow => drop (should be very rare)! */
        return GNUNET_OK;
    }
  else
    {
      ttl -= 2 * GNUNET_GAP_TTL_DECREMENT +
        GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                           GNUNET_GAP_TTL_DECREMENT);
    }
  preference = (double) prio;
  if (preference < GNUNET_GAP_QUERY_BANDWIDTH_VALUE)
    preference = GNUNET_GAP_QUERY_BANDWIDTH_VALUE;
  coreAPI->p2p_connection_preference_increase (sender, preference);

  GNUNET_mutex_lock (GNUNET_FS_lock);
  have_peer = dv_api->have_peer (sender);
  have_data = datastore->get (&req->queries[0], type, NULL, NULL);
  GNUNET_hash_to_enc (&req->queries[0], &enc);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                 GNUNET_GE_BULK,
                 "have_peer returned %d, get (%s) returned %d results for query type %d",
                 have_peer, (char *) &enc, have_data, type);
  if ((dv_api->have_peer (sender) > 0)
      && (datastore->get (&req->queries[0], type, NULL, NULL) > 0))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "We have the data, we know the return peer intimately (DV), so we will try and send results thataway!\n");

      dv_cls = GNUNET_malloc (sizeof (struct DV_send_closure));
      dv_cls->message = (const P2P_gap_query_MESSAGE *) msg;
      dv_cls->request = NULL;   /* Not used for now... */
      datastore->get (&req->queries[0], type, &send_results_dv, dv_cls);
      GNUNET_free (dv_cls);
      GNUNET_mutex_unlock (GNUNET_FS_lock);
      return GNUNET_OK;
    }
  else if ((dv_api->have_peer (sender) > 0)
           && (datastore->
               get (&req->queries[0], GNUNET_ECRS_BLOCKTYPE_DATA, NULL,
                    NULL) > 0))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "We have the data (blocktype_data), we know the return peer intimately (DV), so we will try and send results thataway!\n");

      dv_cls = GNUNET_malloc (sizeof (struct DV_send_closure));
      dv_cls->message = (const P2P_gap_query_MESSAGE *) msg;
      dv_cls->request = NULL;   /* Not used for now... */
      datastore->get (&req->queries[0], GNUNET_ECRS_BLOCKTYPE_DATA,
                      &send_results_dv, dv_cls);
      GNUNET_free (dv_cls);
      GNUNET_mutex_unlock (GNUNET_FS_lock);
      return GNUNET_OK;
    }
  else if ((dv_api->have_peer (sender) > 0)
           && (datastore->
               get (&req->queries[0], GNUNET_ECRS_BLOCKTYPE_ANY, NULL,
                    NULL) > 0))
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_ADMIN | GNUNET_GE_USER |
                     GNUNET_GE_BULK,
                     "We have the data (blocktype_any), we know the return peer intimately (DV), so we will try and send results thataway!\n");

      dv_cls = GNUNET_malloc (sizeof (struct DV_send_closure));
      dv_cls->message = (const P2P_gap_query_MESSAGE *) msg;
      dv_cls->request = NULL;   /* Not used for now... */
      datastore->get (&req->queries[0], GNUNET_ECRS_BLOCKTYPE_ANY,
                      &send_results_dv, dv_cls);
      GNUNET_free (dv_cls);
      GNUNET_mutex_unlock (GNUNET_FS_lock);
      return GNUNET_OK;
    }
  GNUNET_mutex_unlock (GNUNET_FS_lock);

  GNUNET_FS_GAP_execute_query (sender,
                               prio,
                               ntohl (req->priority),
                               policy,
                               ttl,
                               type,
                               query_count,
                               &req->queries[0],
                               ntohl (req->filter_mutator),
                               bloomfilter_size, &req->queries[query_count]);
  return GNUNET_OK;
}


/**
 * Use content (forward to whoever sent the query).
 * @param hostId the peer from where the content came,
 *     NULL for the local peer
 */
static int
handle_p2p_content (const GNUNET_PeerIdentity * sender,
                    const GNUNET_MessageHeader * pmsg)
{
  const P2P_gap_reply_MESSAGE *msg;
  const GNUNET_EC_DBlock *dblock;
  GNUNET_DatastoreValue *value;
  GNUNET_HashCode query;
  unsigned short size;
  unsigned int data_size;
  unsigned int prio;
  unsigned long long expiration;
  double preference;
  GNUNET_CronTime now;

  size = ntohs (pmsg->size);
  if (size < sizeof (P2P_gap_reply_MESSAGE))
    {
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;     /* invalid! */
    }
  msg = (const P2P_gap_reply_MESSAGE *) pmsg;
  data_size = size - sizeof (P2P_gap_reply_MESSAGE);
  dblock = (const GNUNET_EC_DBlock *) &msg[1];

  expiration = GNUNET_ntohll (msg->expiration);
  if ((expiration > GNUNET_GAP_MAX_MIGRATION_EXP_KSK) &&
      (ntohl (dblock->type) == GNUNET_ECRS_BLOCKTYPE_KEYWORD))
    return GNUNET_OK;           /* expired KSK block -- ignore! */
  if (GNUNET_OK !=
      GNUNET_EC_file_block_check_and_get_query (data_size,
                                                dblock, GNUNET_YES, &query))
    {
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;     /* invalid! */
    }
  if ((stats != NULL) && (sender != NULL))
    stats->change (stat_gap_content_received, 1);
  /* forward to other peers */
  prio = GNUNET_FS_GAP_handle_response (sender,
                                        &query,
                                        expiration, data_size, dblock);
  /* convert expiration to absolute time and bound properly for
     storage in local datastore */
  now = GNUNET_get_time ();
  if (expiration > GNUNET_GAP_MAX_MIGRATION_EXP)
    {
      /* expired, sometime in the past */
      expiration = now - 1;
    }
  else
    {
      /* expires in future, apply bounding! */
      if (ntohl (dblock->type) == GNUNET_ECRS_BLOCKTYPE_KEYWORD)
        expiration %= GNUNET_GAP_MAX_MIGRATION_EXP_KSK;
      else
        expiration %= GNUNET_GAP_MAX_MIGRATION_EXP;
      expiration += now;
    }
  /* forward to local clients */
  prio += GNUNET_DV_FS_QUERYMANAGER_handle_response (sender,
                                                     &query,
                                                     expiration,
                                                     data_size, dblock);
  if ((sender != NULL) &&
      (active_migration == GNUNET_YES) &&
      ((prio > 0) || (!test_load_too_high ())))
    {
      /* consider storing in local datastore */
      value = GNUNET_malloc (data_size + sizeof (GNUNET_DatastoreValue));
      value->size = htonl (data_size + sizeof (GNUNET_DatastoreValue));
      value->type = dblock->type;
      value->priority = htonl (prio);
      value->anonymity_level = htonl (1);
      value->expiration_time = GNUNET_htonll (expiration);
      memcpy (&value[1], dblock, data_size);
      datastore->putUpdate (&query, value);
      GNUNET_free (value);
    }
  if (sender != NULL)
    {                           /* if we are the sender, sender will be NULL */
      identity->changeHostTrust (sender, prio);
      if (stats != NULL)
        stats->change (stat_gap_trust_awarded, prio);
      preference = (double) prio;
      if (preference < GNUNET_GAP_CONTENT_BANDWIDTH_VALUE)
        preference = GNUNET_GAP_CONTENT_BANDWIDTH_VALUE;
      coreAPI->p2p_connection_preference_increase (sender, preference);
    }
  return GNUNET_OK;
}


/**
 * Initialize the FS module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 *
 * @return GNUNET_SYSERR on errors
 */
int
initialize_module_dv_fs (GNUNET_CoreAPIForPlugins * capi)
{
  ectx = capi->ectx;
  coreAPI = capi;
  GNUNET_GE_ASSERT (ectx, sizeof (GNUNET_EC_ContentHashKey) == 128);
  GNUNET_GE_ASSERT (ectx, sizeof (GNUNET_EC_DBlock) == 4);
  GNUNET_GE_ASSERT (ectx, sizeof (GNUNET_EC_IBlock) == 132);
  GNUNET_GE_ASSERT (ectx, sizeof (GNUNET_EC_KBlock) == 524);
  GNUNET_GE_ASSERT (ectx, sizeof (GNUNET_EC_SBlock) == 588);
  GNUNET_GE_ASSERT (ectx, sizeof (GNUNET_EC_KSBlock) == 1116);

  if ((-1 == GNUNET_GC_get_configuration_value_number (coreAPI->cfg, "LOAD", "HARDCPULIMIT", 0, 100000, /* 1000 CPUs!? */
                                                       0,       /* 0 == no limit */
                                                       &hardCPULimit)) || (-1 == GNUNET_GC_get_configuration_value_number (coreAPI->cfg, "LOAD", "HARDUPLIMIT", 0, 999999999, 0,        /* 0 == no limit */
                                                                                                                           &hardUpLimit)))
    return GNUNET_SYSERR;
  active_migration
    = GNUNET_GC_get_configuration_value_yesno (coreAPI->cfg,
                                               "DV_FS",
                                               "ACTIVEMIGRATION", GNUNET_NO);
  stats = coreAPI->service_request ("stats");
  if (stats != NULL)
    {
      stat_gap_query_received =
        stats->create (gettext_noop ("# gap requests total received"));
      stat_gap_query_drop_busy =
        stats->create (gettext_noop ("# gap requests dropped due to load"));
      stat_gap_content_received =
        stats->create (gettext_noop ("# gap content total received"));
      stat_gap_trust_awarded =
        stats->create (gettext_noop ("# gap total trust awarded"));
    }
  identity = coreAPI->service_request ("identity");
  if (identity == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      coreAPI->service_release (stats);
      return GNUNET_SYSERR;
    }
  datastore = coreAPI->service_request ("datastore");
  dv_api = coreAPI->service_request ("dv");
  if (datastore == NULL)
    {
      coreAPI->service_release (identity);
      coreAPI->service_release (stats);
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  GNUNET_FS_lock = coreAPI->global_lock_get (); // GNUNET_mutex_create (GNUNET_YES);
  GNUNET_FS_ANONYMITY_init (coreAPI);
  GNUNET_FS_PLAN_init (coreAPI);
  GNUNET_FS_ONDEMAND_init (coreAPI);
  GNUNET_FS_PT_init (ectx, stats);
  GNUNET_DV_FS_QUERYMANAGER_init (coreAPI);
  GNUNET_FS_DV_DHT_init (coreAPI);
  GNUNET_FS_GAP_init (coreAPI);
  GNUNET_FS_MIGRATION_init (coreAPI);
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _
                 ("`%s' registering client handlers %d %d %d %d %d %d %d %d and P2P handlers %d %d\n"),
                 "fs", GNUNET_CS_PROTO_GAP_QUERY_START,
                 GNUNET_CS_PROTO_GAP_QUERY_STOP,
                 GNUNET_CS_PROTO_GAP_INSERT,
                 GNUNET_CS_PROTO_GAP_INDEX, GNUNET_CS_PROTO_GAP_DELETE,
                 GNUNET_CS_PROTO_GAP_UNINDEX, GNUNET_CS_PROTO_GAP_TESTINDEX,
                 GNUNET_CS_PROTO_GAP_INIT_INDEX,
                 GNUNET_P2P_PROTO_GAP_QUERY, GNUNET_P2P_PROTO_GAP_RESULT);
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->p2p_ciphertext_handler_register
                    (GNUNET_P2P_PROTO_GAP_QUERY, &handle_p2p_query));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->p2p_ciphertext_handler_register
                    (GNUNET_P2P_PROTO_GAP_RESULT, &handle_p2p_content));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_register
                    (GNUNET_CS_PROTO_GAP_QUERY_START,
                     &handle_cs_query_start_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_register
                    (GNUNET_CS_PROTO_GAP_QUERY_STOP,
                     &handle_cs_query_stop_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_register (GNUNET_CS_PROTO_GAP_INSERT,
                                                  &handle_cs_insert_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_register (GNUNET_CS_PROTO_GAP_INDEX,
                                                  &handle_cs_index_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    cs_handler_register (GNUNET_CS_PROTO_GAP_INIT_INDEX,
                                         &handle_cs_init_index_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_register (GNUNET_CS_PROTO_GAP_DELETE,
                                                  &handle_cs_delete_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_register (GNUNET_CS_PROTO_GAP_UNINDEX,
                                                  &handle_cs_unindex_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    cs_handler_register (GNUNET_CS_PROTO_GAP_TESTINDEX,
                                         &handle_cs_test_indexed_request));
  GNUNET_GE_ASSERT (coreAPI->ectx,
                    0 ==
                    GNUNET_GC_set_configuration_value_string (coreAPI->cfg,
                                                              coreAPI->ectx,
                                                              "ABOUT",
                                                              "dv_fs",
                                                              gettext_noop
                                                              ("enables (anonymous) file-sharing")));
  return GNUNET_OK;
}

void
done_module_dv_fs ()
{
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "dv_fs shutdown\n");

  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->p2p_ciphertext_handler_unregister
                    (GNUNET_P2P_PROTO_GAP_QUERY, &handle_p2p_query));

  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->p2p_ciphertext_handler_unregister
                    (GNUNET_P2P_PROTO_GAP_RESULT, &handle_p2p_content));

  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_unregister
                    (GNUNET_CS_PROTO_GAP_QUERY_START,
                     &handle_cs_query_start_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_unregister
                    (GNUNET_CS_PROTO_GAP_INSERT, &handle_cs_insert_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_unregister (GNUNET_CS_PROTO_GAP_INDEX,
                                                    &handle_cs_index_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_unregister
                    (GNUNET_CS_PROTO_GAP_INIT_INDEX,
                     &handle_cs_init_index_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_unregister
                    (GNUNET_CS_PROTO_GAP_DELETE, &handle_cs_delete_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_unregister
                    (GNUNET_CS_PROTO_GAP_UNINDEX,
                     &handle_cs_unindex_request));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->cs_handler_unregister
                    (GNUNET_CS_PROTO_GAP_TESTINDEX,
                     &handle_cs_test_indexed_request));
  GNUNET_FS_MIGRATION_done ();
  GNUNET_FS_GAP_done ();
  GNUNET_FS_DV_DHT_done ();
  GNUNET_DV_FS_QUERYMANAGER_done ();
  GNUNET_FS_ONDEMAND_done ();
  GNUNET_FS_PLAN_done ();
  GNUNET_FS_ANONYMITY_done ();
  GNUNET_FS_PT_done ();
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }
  if (dv_api != NULL)
    coreAPI->service_release (dv_api);

  coreAPI->service_release (datastore);
  datastore = NULL;
  coreAPI->service_release (identity);
  identity = NULL;
  GNUNET_FS_lock = NULL;
}


/**
 * Update FS.
 */
void
update_module_dv_fs (GNUNET_UpdateAPI * uapi)
{
  uapi->service_update ("datastore");
}


/* end of dv_fs.c */
