/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/module/fs.c
 * @brief main functions of the file sharing service
 * @author Christian Grothoff
 *
 * FS CORE. This is the code that is plugged into the GNUnet core to
 * enable File Sharing.
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_gap_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_datastore_service.h"
#include "gnunet_traffic_service.h"
#include "gnunet_stats_service.h"
#include "anonymity.h"
#include "dht_push.h"
#include "ecrs_core.h"
#include "migration.h"
#include "ondemand.h"
#include "querymanager.h"
#include "fs.h"

#define DEBUG_FS GNUNET_NO

struct DHT_GET_CLS
{

  struct DHT_GET_CLS *next;

  struct GNUNET_DHT_GetHandle *rec;

  struct GNUNET_ClientHandle *sock;

  GNUNET_CronTime expires;

  GNUNET_HashCode key;

  unsigned int prio;

};

typedef struct LG_Job
{
  unsigned int keyCount;
  unsigned int type;
  GNUNET_HashCode *queries;
  struct LG_Job *next;
} LG_Job;

/**
 * DHT GET operations that are currently pending.
 */
static struct DHT_GET_CLS *dht_pending;

/**
 * Global core API.
 */
static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * GAP service.
 */
static GNUNET_GAP_ServiceAPI *gap;

/**
 * DHT service.  Maybe NULL!
 */
static GNUNET_DHT_ServiceAPI *dht;

/**
 * Datastore service.
 */
static GNUNET_Datastore_ServiceAPI *datastore;

/**
 * Traffic service.
 */
static GNUNET_Traffic_ServiceAPI *traffic;

/**
 * Stats service.
 */
static GNUNET_Stats_ServiceAPI *stats;

static int stat_expired_replies_dropped;

static int stat_valid_replies_received;

static struct GNUNET_Mutex *lock;

static int migration;

static struct GNUNET_Semaphore *ltgSignal;

static struct GNUNET_ThreadHandle *localGetProcessor;

static LG_Job *lg_jobs;

static struct GNUNET_GE_Context *ectx;

static GNUNET_DatastoreValue *
gapWrapperToDatastoreValue (const GNUNET_DataContainer * value, int prio)
{
  GNUNET_DatastoreValue *dv;
  const GapWrapper *gw;
  unsigned int size;
  GNUNET_CronTime et;
  GNUNET_CronTime now;

  if (ntohl (value->size) < sizeof (GapWrapper))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  gw = (const GapWrapper *) value;
  size =
    ntohl (gw->dc.size) - sizeof (GapWrapper) +
    sizeof (GNUNET_DatastoreValue);
  dv = GNUNET_malloc (size);
  dv->size = htonl (size);
  dv->type =
    htonl (GNUNET_EC_file_block_get_type
           (size - sizeof (GNUNET_DatastoreValue), (DBlock *) & gw[1]));
  dv->prio = htonl (prio);
  dv->anonymityLevel = htonl (0);
  et = GNUNET_ntohll (gw->timeout);
  now = GNUNET_get_time ();
  /* bound ET to MAX_MIGRATION_EXP from now */
  if (et > now)
    {
      et -= now;
      et = et % MAX_MIGRATION_EXP;
      et += now;
    }
  dv->expirationTime = GNUNET_htonll (et);
  memcpy (&dv[1], &gw[1], size - sizeof (GNUNET_DatastoreValue));
  return dv;
}

/**
 * Store an item in the datastore.
 *
 * @param query the unique identifier of the item
 * @param value the value to store
 * @param prio how much does our routing code value
 *        this datum?
 * @return GNUNET_OK if the value could be stored,
 *         GNUNET_NO if the value verifies but is not stored,
 *         GNUNET_SYSERR if the value is malformed
 */
static int
gapPut (void *closure,
        const GNUNET_HashCode * query,
        const GNUNET_DataContainer * value, unsigned int prio)
{
  GNUNET_DatastoreValue *dv;
  const GapWrapper *gw;
  unsigned int size;
  int ret;
  GNUNET_HashCode hc;
#if DEBUG_FS
  GNUNET_EncName enc;
#endif

  gw = (const GapWrapper *) value;
  size = ntohl (gw->dc.size) - sizeof (GapWrapper);
  if ((GNUNET_OK != GNUNET_EC_file_block_check_and_get_query (size,
                                                              (const DBlock *)
                                                              &gw[1],
                                                              GNUNET_YES,
                                                              &hc))
      || (0 != memcmp (&hc, query, sizeof (GNUNET_HashCode))))
    {
      GNUNET_GE_BREAK_OP (ectx, 0);     /* value failed verification! */
      return GNUNET_SYSERR;
    }
  dv = gapWrapperToDatastoreValue (value, prio);
  if (dv == NULL)
    {
      GNUNET_GE_BREAK_OP (ectx, 0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_YES != GNUNET_EC_is_block_applicable_for_query (ntohl (dv->type),
                                                             ntohl (dv->
                                                                    size) -
                                                             sizeof
                                                             (GNUNET_DatastoreValue),
                                                             (const DBlock *)
                                                             &dv[1], &hc, 0,
                                                             query))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (dv);
      return GNUNET_SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_valid_replies_received, 1);
  if (GNUNET_ntohll (dv->expirationTime) < GNUNET_get_time ())
    {
      /* do not do anything with expired data
         _except_ if it is pure content that one
         of our clients has requested -- then we
         should ignore expiration */
      if (ntohl (dv->type) == GNUNET_ECRS_BLOCKTYPE_DATA)
        processResponse (query, dv);
      else if (stats != NULL)
        stats->change (stat_expired_replies_dropped, 1);

      GNUNET_free (dv);
      return GNUNET_NO;
    }
  processResponse (query, dv);


#if DEBUG_FS
  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (query, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received GAP-PUT request (query: `%s')\n", &enc);
#endif
  if (migration)
    ret = datastore->putUpdate (query, dv);
  else
    ret = GNUNET_OK;
  GNUNET_free (dv);
  if (ret == GNUNET_SYSERR)
    ret = GNUNET_NO;            /* error in put != content invalid! */
  return ret;
}

static int
get_result_callback (const GNUNET_HashCode * query,
                     const GNUNET_DataContainer * value, void *ctx)
{
  struct DHT_GET_CLS *cls = ctx;
  const GapWrapper *gw;
  unsigned int size;
  GNUNET_HashCode hc;
#if DEBUG_FS
  GNUNET_EncName enc;

  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (query, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Found reply to query `%s'.\n", &enc);
#endif
  gw = (const GapWrapper *) value;
  size = ntohl (gw->dc.size) - sizeof (GapWrapper);
  if ((GNUNET_OK != GNUNET_EC_file_block_check_and_get_query (size,
                                                              (const DBlock *)
                                                              &gw[1],
                                                              GNUNET_YES,
                                                              &hc))
      || (0 != memcmp (&hc, query, sizeof (GNUNET_HashCode))))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_OK;
    }

  gapPut (NULL, query, value, cls->prio);
  return GNUNET_OK;
}

/**
 * Stop processing a query.
 *
 * @return GNUNET_SYSERR if the TCP connection should be closed, otherwise GNUNET_OK
 */
static int
csHandleRequestQueryStop (struct GNUNET_ClientHandle *sock,
                          const GNUNET_MessageHeader * req)
{
  const CS_fs_request_search_MESSAGE *rs;
  struct DHT_GET_CLS *pos;
  struct DHT_GET_CLS *prev;
#if DEBUG_FS
  GNUNET_EncName enc;
#endif

  if (ntohs (req->size) < sizeof (CS_fs_request_search_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  rs = (const CS_fs_request_search_MESSAGE *) req;
#if DEBUG_FS
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&rs->query[0], &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received QUERY STOP (query: `%s')\n", &enc);
#endif
  gap->get_stop (ntohl (rs->type),
                 1 + (ntohs (req->size) -
                      sizeof (CS_fs_request_search_MESSAGE)) /
                 sizeof (GNUNET_HashCode), &rs->query[0]);
  untrackQuery (&rs->query[0], sock);
  GNUNET_mutex_lock (lock);
  prev = NULL;
  pos = dht_pending;
  while (pos != NULL)
    {
      if ((pos->sock == sock) &&
          (0 == memcmp (&pos->key, &rs->query[0], sizeof (GNUNET_HashCode))))
        {
          if (prev == NULL)
            dht_pending = pos->next;
          else
            prev->next = pos->next;
          dht->get_stop (pos->rec);
          GNUNET_free (pos);
          break;
        }
      prev = pos;
      pos = pos->next;
    }
  GNUNET_mutex_unlock (lock);

  return GNUNET_OK;
}

/**
 * Process a request to insert content from the client.
 *
 * @return GNUNET_SYSERR if the TCP connection should be closed, otherwise GNUNET_OK
 */
static int
csHandleCS_fs_request_insert_MESSAGE (struct GNUNET_ClientHandle *sock,
                                      const GNUNET_MessageHeader * req)
{
  const CS_fs_request_insert_MESSAGE *ri;
  GNUNET_DatastoreValue *datum;
  struct GNUNET_GE_Context *cectx;
  GNUNET_HashCode query;
  int ret;
  unsigned int type;
#if DEBUG_FS
  GNUNET_EncName enc;
#endif

  cectx =
    coreAPI->
    cs_create_client_log_context (GNUNET_GE_USER |
                                  GNUNET_GE_EVENTKIND |
                                  GNUNET_GE_ROUTEKIND, sock);
  if (ntohs (req->size) < sizeof (CS_fs_request_insert_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_GE_BREAK (cectx, 0);
      GNUNET_GE_free_context (cectx);
      return GNUNET_SYSERR;
    }
  ri = (const CS_fs_request_insert_MESSAGE *) req;
  datum = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) +
                         ntohs (req->size) -
                         sizeof (CS_fs_request_insert_MESSAGE));
  datum->size =
    htonl (sizeof (GNUNET_DatastoreValue) + ntohs (req->size) -
           sizeof (CS_fs_request_insert_MESSAGE));
  datum->expirationTime = ri->expiration;
  datum->prio = ri->prio;
  datum->anonymityLevel = ri->anonymityLevel;
  if (GNUNET_OK !=
      GNUNET_EC_file_block_check_and_get_query (ntohs (ri->header.size) -
                                                sizeof
                                                (CS_fs_request_insert_MESSAGE),
                                                (const DBlock *) &ri[1],
                                                GNUNET_YES, &query))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_GE_BREAK (cectx, 0);
      GNUNET_free (datum);
      GNUNET_GE_free_context (cectx);
      return GNUNET_SYSERR;
    }
  type =
    GNUNET_EC_file_block_get_type (ntohs (ri->header.size) -
                                   sizeof (CS_fs_request_insert_MESSAGE),
                                   (const DBlock *) &ri[1]);
#if DEBUG_FS
  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&query, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received REQUEST INSERT (query: `%s', type: %u, priority %u)\n",
                 &enc, type, ntohl (ri->prio));
#endif
  datum->type = htonl (type);
  memcpy (&datum[1],
          &ri[1], ntohs (req->size) - sizeof (CS_fs_request_insert_MESSAGE));
  GNUNET_mutex_lock (lock);
  if ((type != GNUNET_ECRS_BLOCKTYPE_DATA)
      || (0 == datastore->get (&query, type, NULL, NULL)))
    ret = datastore->put (&query, datum);
  else
    ret = GNUNET_OK;
  GNUNET_mutex_unlock (lock);
  if ((ntohl (ri->anonymityLevel) == 0) && (dht != NULL))
    {
      GapWrapper *gw;
      unsigned int size;
      GNUNET_CronTime now;
      GNUNET_CronTime et;
      GNUNET_HashCode hc;

      size = sizeof (GapWrapper) +
        ntohs (ri->header.size) - sizeof (CS_fs_request_insert_MESSAGE);
      gw = GNUNET_malloc (size);
      gw->reserved = 0;
      gw->dc.size = htonl (size);
      et = GNUNET_ntohll (ri->expiration);
      /* expiration time normalization and randomization */
      now = GNUNET_get_time ();
      if (et > now)
        {
          et -= now;
          et = et % MAX_MIGRATION_EXP;
          if (et > 0)
            et = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, et);
          et = et + now;
        }
      gw->timeout = GNUNET_htonll (et);
      memcpy (&gw[1], &ri[1], size - sizeof (GapWrapper));
      /* sanity check */
      if ((GNUNET_OK !=
           GNUNET_EC_file_block_check_and_get_query (size -
                                                     sizeof (GapWrapper),
                                                     (const DBlock *) &gw[1],
                                                     GNUNET_YES, &hc))
          || (0 != memcmp (&hc, &query, sizeof (GNUNET_HashCode))))
        {
          GNUNET_GE_BREAK (NULL, 0);
        }
      else
        {
          dht->put (&query, type, size, (const char *) gw);
        }
      GNUNET_free (gw);
    }
  GNUNET_free (datum);
  GNUNET_GE_free_context (cectx);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * Process a request to symlink a file
 */
static int
csHandleCS_fs_request_init_index_MESSAGE (struct GNUNET_ClientHandle *sock,
                                          const GNUNET_MessageHeader * req)
{
  int ret;
  char *fn;
  CS_fs_request_init_index_MESSAGE *ri;
  int fnLen;
  struct GNUNET_GE_Context *cectx;

  cectx =
    coreAPI->
    cs_create_client_log_context (GNUNET_GE_USER |
                                  GNUNET_GE_EVENTKIND |
                                  GNUNET_GE_ROUTEKIND, sock);
  if (ntohs (req->size) < sizeof (CS_fs_request_init_index_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_GE_BREAK (cectx, 0);
      GNUNET_GE_free_context (cectx);
      return GNUNET_SYSERR;
    }

  ri = (CS_fs_request_init_index_MESSAGE *) req;

  fnLen = ntohs (ri->header.size) - sizeof (CS_fs_request_init_index_MESSAGE);
#if WINDOWS
  if (fnLen > _MAX_PATH)
    {
      GNUNET_GE_BREAK (cectx, 0);
      GNUNET_GE_free_context (cectx);
      return GNUNET_SYSERR;
    }
#endif
  fn = GNUNET_malloc (fnLen + 1);
  strncpy (fn, (char *) &ri[1], fnLen + 1);
  fn[fnLen] = 0;
  ret = ONDEMAND_initIndex (cectx, &ri->fileId, fn);

  GNUNET_free (fn);
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Sending confirmation (%s) of index initialization request to client\n",
                 ret == GNUNET_OK ? "success" : "failure");
#endif
  GNUNET_GE_free_context (cectx);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * Process a request to index content from the client.
 *
 * @return GNUNET_SYSERR if the TCP connection should be closed, otherwise GNUNET_OK
 */
static int
csHandleCS_fs_request_index_MESSAGE (struct GNUNET_ClientHandle *sock,
                                     const GNUNET_MessageHeader * req)
{
  int ret;
  const CS_fs_request_index_MESSAGE *ri;
  struct GNUNET_GE_Context *cectx;

  cectx =
    coreAPI->
    cs_create_client_log_context (GNUNET_GE_USER |
                                  GNUNET_GE_EVENTKIND |
                                  GNUNET_GE_ROUTEKIND, sock);
  if (ntohs (req->size) < sizeof (CS_fs_request_index_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_GE_BREAK (cectx, 0);
      GNUNET_GE_free_context (cectx);
      return GNUNET_SYSERR;
    }
  ri = (const CS_fs_request_index_MESSAGE *) req;
  ret = ONDEMAND_index (cectx,
                        datastore,
                        ntohl (ri->prio),
                        GNUNET_ntohll (ri->expiration),
                        GNUNET_ntohll (ri->fileOffset),
                        ntohl (ri->anonymityLevel),
                        &ri->fileId,
                        ntohs (ri->header.size) -
                        sizeof (CS_fs_request_index_MESSAGE),
                        (const DBlock *) &ri[1]);
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Sending confirmation (%s) of index request to client\n",
                 ret == GNUNET_OK ? "success" : "failure");
#endif
  GNUNET_GE_free_context (cectx);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * If the data portion and type of the value match our value in the
 * closure, copy the header (prio, anonymityLevel, expirationTime) and
 * abort the iteration: we found what we're looing for.  Otherwise
 * continue.
 */
static int
completeValue (const GNUNET_HashCode * key,
               const GNUNET_DatastoreValue * value, void *closure,
               unsigned long long uid)
{
  GNUNET_DatastoreValue *comp = closure;

  if ((comp->size != value->size) ||
      (0 != memcmp (&value[1],
                    &comp[1],
                    ntohl (value->size) - sizeof (GNUNET_DatastoreValue))))
    {
#if DEBUG_FS
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "`%s' found value that does not match (%u, %u).\n",
                     __FUNCTION__, ntohl (comp->size), ntohl (value->size));
#endif
      return GNUNET_OK;
    }
  *comp = *value;               /* make copy! */
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "`%s' found value that matches.\n", __FUNCTION__);
#endif
  return GNUNET_SYSERR;
}

/**
 * Process a query to delete content.
 *
 * @return GNUNET_SYSERR if the TCP connection should be closed, otherwise GNUNET_OK
 */
static int
csHandleCS_fs_request_delete_MESSAGE (struct GNUNET_ClientHandle *sock,
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
  struct GNUNET_GE_Context *cectx;

  cectx =
    coreAPI->
    cs_create_client_log_context (GNUNET_GE_USER |
                                  GNUNET_GE_EVENTKIND |
                                  GNUNET_GE_ROUTEKIND, sock);
  if (ntohs (req->size) < sizeof (CS_fs_request_delete_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_GE_BREAK (cectx, 0);
      GNUNET_GE_free_context (cectx);
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
                                   (const DBlock *) &rd[1]);
  value->type = htonl (type);
  memcpy (&value[1],
          &rd[1], ntohs (req->size) - sizeof (CS_fs_request_delete_MESSAGE));
  if (GNUNET_OK !=
      GNUNET_EC_file_block_check_and_get_query (ntohs (rd->header.size) -
                                                sizeof
                                                (CS_fs_request_delete_MESSAGE),
                                                (const DBlock *) &rd[1],
                                                GNUNET_NO, &query))
    {
      GNUNET_free (value);
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_GE_BREAK (cectx, 0);
      GNUNET_GE_free_context (cectx);
      return GNUNET_SYSERR;
    }
#if DEBUG_FS
  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&query, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received REQUEST DELETE (query: `%s', type: %u)\n", &enc,
                 type);
#endif
  GNUNET_mutex_lock (lock);
  if (GNUNET_SYSERR == datastore->get (&query, type, &completeValue, value))
    {                           /* aborted == found! */
      ret = datastore->del (&query, value);
    }
  else
    {                           /* not found */
      ret = GNUNET_SYSERR;
    }
  GNUNET_mutex_unlock (lock);
  GNUNET_free (value);
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Sending confirmation (%s) of delete request to client\n",
                 ret != GNUNET_SYSERR ? "success" : "failure");
#endif
  GNUNET_GE_free_context (cectx);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * Process a client request unindex content.
 */
static int
csHandleCS_fs_request_unindex_MESSAGE (struct GNUNET_ClientHandle *sock,
                                       const GNUNET_MessageHeader * req)
{
  int ret;
  const CS_fs_request_unindex_MESSAGE *ru;
  struct GNUNET_GE_Context *cectx;

  cectx =
    coreAPI->
    cs_create_client_log_context (GNUNET_GE_USER |
                                  GNUNET_GE_EVENTKIND |
                                  GNUNET_GE_ROUTEKIND, sock);
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
  ret = ONDEMAND_unindex (cectx,
                          datastore, ntohl (ru->blocksize), &ru->fileId);
  GNUNET_GE_free_context (cectx);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * Process a client request to test if certain
 * data is indexed.
 */
static int
csHandleCS_fs_request_test_index_MESSAGEed (struct GNUNET_ClientHandle *sock,
                                            const GNUNET_MessageHeader * req)
{
  int ret;
  const RequestTestindex *ru;

  if (ntohs (req->size) != sizeof (RequestTestindex))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  ru = (const RequestTestindex *) req;
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received REQUEST TESTINDEXED\n");
#endif
  ret = ONDEMAND_testindexed (datastore, &ru->fileId);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * Process a client request to obtain the current
 * averge priority.
 */
static int
csHandleRequestGetAvgPriority (struct GNUNET_ClientHandle *sock,
                               const GNUNET_MessageHeader * req)
{
#if DEBUG_FS
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received REQUEST GETAVGPRIORITY\n");
#endif
  return coreAPI->sendValueToClient (sock, gap->getAvgPriority ());
}

/**
 * Closure for the gapGetConverter method.
 */
typedef struct
{
  GNUNET_DataProcessor resultCallback;
  void *resCallbackClosure;
  unsigned int keyCount;
  const GNUNET_HashCode *keys;
  int count;
} GGC;

/**
 * Callback that converts the GNUNET_DatastoreValue values
 * from the datastore to GNUNET_Blockstore values for the
 * gap routing protocol.
 */
static int
gapGetConverter (const GNUNET_HashCode * key,
                 const GNUNET_DatastoreValue * invalue, void *cls,
                 unsigned long long uid)
{
  GGC *ggc = (GGC *) cls;
  GapWrapper *gw;
  int ret;
  unsigned int size;
  GNUNET_CronTime et;
  GNUNET_CronTime now;
  const GNUNET_DatastoreValue *value;
  GNUNET_DatastoreValue *xvalue;
  unsigned int level;
  GNUNET_EncName enc;
#if EXTRA_CHECKS
  GNUNET_HashCode hc;
#endif

#if DEBUG_FS
  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (key, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Converting reply for query `%s' for gap.\n", &enc);
#endif
  if ((ntohl (invalue->type) == GNUNET_ECRS_BLOCKTYPE_ONDEMAND) ||
      (ntohl (invalue->type) == GNUNET_ECRS_BLOCKTYPE_ONDEMAND_OLD))
    {
      if (GNUNET_OK != ONDEMAND_getIndexed (datastore, invalue, key, &xvalue))
        return GNUNET_SYSERR;
      value = xvalue;
    }
  else
    {
      xvalue = NULL;
      value = invalue;
    }

  et = GNUNET_ntohll (value->expirationTime);
  now = GNUNET_get_time ();
  if ((et <= now) && (ntohl (value->type) != GNUNET_ECRS_BLOCKTYPE_DATA))
    {
      /* content expired and not just data -- drop! */
      GNUNET_free_non_null (xvalue);
      return GNUNET_OK;
    }

#if EXTRA_CHECKS
  if ((GNUNET_OK !=
       GNUNET_EC_file_block_check_and_get_query (ntohl (value->size) -
                                                 sizeof
                                                 (GNUNET_DatastoreValue),
                                                 (const DBlock *) &value[1],
                                                 GNUNET_YES, &hc))
      || (!equalsGNUNET_HashCode (&hc, key)))
    {
      GNUNET_GE_BREAK (ectx, 0);        /* value failed verification! */
      return GNUNET_SYSERR;
    }
#endif
  ret = GNUNET_EC_is_block_applicable_for_query (ntohl (value->type),
                                                 ntohl (value->size) -
                                                 sizeof
                                                 (GNUNET_DatastoreValue),
                                                 (const DBlock *) &value[1],
                                                 key, ggc->keyCount,
                                                 ggc->keys);
  if (ret == GNUNET_SYSERR)
    {
      IF_GELOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                GNUNET_hash_to_enc (key, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "Converting reply for query `%s' for gap failed (datum not applicable).\n",
                     &enc);
      GNUNET_free_non_null (xvalue);
      return GNUNET_SYSERR;     /* no query will ever match */
    }
  if (ret == GNUNET_NO)
    {
      IF_GELOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                GNUNET_hash_to_enc (key, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "Converting reply for query `%s' for gap failed (type not applicable).\n",
                     &enc);
      GNUNET_free_non_null (xvalue);
      return GNUNET_OK;         /* Additional filtering based on type;
                                   i.e., namespace request and namespace
                                   in reply does not match namespace in query */
    }
  size =
    sizeof (GapWrapper) + ntohl (value->size) -
    sizeof (GNUNET_DatastoreValue);

  level = ntohl (value->anonymityLevel);
  if (GNUNET_OK != checkCoverTraffic (ectx, traffic, level))
    {
      /* traffic required by module not loaded;
         refuse to hand out data that requires
         anonymity! */
      GNUNET_free_non_null (xvalue);
      IF_GELOG (ectx, GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                GNUNET_hash_to_enc (key, &enc));
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "Converting reply for query `%s' for gap failed (insufficient cover traffic).\n",
                     &enc);
      return GNUNET_OK;
    }
  gw = GNUNET_malloc (size);
  gw->dc.size = htonl (size);
  /* expiration time normalization and randomization */
  if (et > now)
    {
      et -= now;
      et = et % MAX_MIGRATION_EXP;
      if (et > 0)
        et = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, et);
      et = et + now;
    }
  gw->timeout = GNUNET_htonll (et);
  memcpy (&gw[1], &value[1], size - sizeof (GapWrapper));

  if (ggc->resultCallback != NULL)
    ret = ggc->resultCallback (key, &gw->dc, ggc->resCallbackClosure);
  else
    ret = GNUNET_OK;
  ggc->count++;
  GNUNET_free (gw);
  GNUNET_free_non_null (xvalue);
  return ret;
}

/**
 * Lookup an item in the datastore.
 *
 * @param key the value to lookup
 * @param resultCallback function to call for each result that was found
 * @param resCallbackClosure extra argument to resultCallback
 * @return number of results, GNUNET_SYSERR on error
 */
static int
gapGet (void *closure,
        unsigned int type,
        unsigned int prio,
        unsigned int keyCount,
        const GNUNET_HashCode * keys,
        GNUNET_DataProcessor resultCallback, void *resCallbackClosure)
{
  int ret;
  GGC myClosure;
#if DEBUG_FS
  GNUNET_EncName enc;

  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&keys[0], &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "GAP requests content for `%s' of type %u\n", &enc, type);
#endif
  myClosure.count = 0;
  myClosure.keyCount = keyCount;
  myClosure.keys = keys;
  myClosure.resultCallback = resultCallback;
  myClosure.resCallbackClosure = resCallbackClosure;
  ret = GNUNET_OK;
  if (type == GNUNET_ECRS_BLOCKTYPE_DATA)
    ret = datastore->get (&keys[0],
                          GNUNET_ECRS_BLOCKTYPE_ONDEMAND,
                          &gapGetConverter, &myClosure);
  if ((myClosure.count == 0) && (type == GNUNET_ECRS_BLOCKTYPE_DATA))
    ret = datastore->get (&keys[0],
                          GNUNET_ECRS_BLOCKTYPE_ONDEMAND_OLD,
                          &gapGetConverter, &myClosure);
  if (myClosure.count == 0)
    ret = datastore->get (&keys[0], type, &gapGetConverter, &myClosure);
  if (ret != GNUNET_SYSERR)
    ret = myClosure.count;      /* return number of actual
                                   results (unfiltered) that
                                   were found */
  return ret;
}

/**
 * Remove an item from the datastore.
 *
 * @param key the key of the item
 * @param value the value to remove, NULL for all values of the key
 * @return GNUNET_OK if the value could be removed, GNUNET_SYSERR if not (i.e. not present)
 */
static int
gapDel (void *closure, const GNUNET_HashCode * key,
        const GNUNET_DataContainer * value)
{
  GNUNET_GE_BREAK (ectx, 0);    /* gap does not use 'del'! */
  return GNUNET_SYSERR;
}

/**
 * Iterate over all keys in the local datastore
 *
 * @param processor function to call on each item
 * @param cls argument to processor
 * @return number of results, GNUNET_SYSERR on error
 */
static int
gapIterate (void *closure, GNUNET_DataProcessor processor, void *cls)
{
  GNUNET_GE_BREAK (ectx, 0);    /* gap does not use 'iterate' */
  return GNUNET_SYSERR;
}

static int
replyHashFunction (const GNUNET_DataContainer * content, GNUNET_HashCode * id)
{
  const GapWrapper *gw;
  unsigned int size;

  size = ntohl (content->size);
  if (size < sizeof (GapWrapper))
    {
      GNUNET_GE_BREAK (ectx, 0);
      memset (id, 0, sizeof (GNUNET_HashCode));
      return GNUNET_SYSERR;
    }
  gw = (const GapWrapper *) content;
  GNUNET_hash (&gw[1], size - sizeof (GapWrapper), id);
  return GNUNET_OK;
}

static int
uniqueReplyIdentifier (const GNUNET_DataContainer * content,
                       unsigned int type,
                       int verify, const GNUNET_HashCode * primaryKey)
{
  GNUNET_HashCode q;
  unsigned int t;
  const GapWrapper *gw;
  unsigned int size;

  size = ntohl (content->size);
  if (size < sizeof (GapWrapper))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_NO;
    }
  gw = (const GapWrapper *) content;
  if ((GNUNET_OK ==
       GNUNET_EC_file_block_check_and_get_query (size - sizeof (GapWrapper),
                                                 (const DBlock *) &gw[1],
                                                 verify, &q))
      && (0 == memcmp (&q, primaryKey, sizeof (GNUNET_HashCode)))
      && ((type == GNUNET_ECRS_BLOCKTYPE_ANY)
          || (type ==
              (t =
               GNUNET_EC_file_block_get_type (size - sizeof (GapWrapper),
                                              (const DBlock *) &gw[1])))))
    {
      switch (type)
        {
        case GNUNET_ECRS_BLOCKTYPE_DATA:
          return GNUNET_YES;
        default:
          return GNUNET_NO;
        }
    }
  else
    return GNUNET_NO;
}

static int
fastPathProcessor (const GNUNET_HashCode * query,
                   const GNUNET_DataContainer * value, void *cls)
{
  GNUNET_DatastoreValue *dv;

  dv = gapWrapperToDatastoreValue (value, 0);
  if (dv == NULL)
    return GNUNET_SYSERR;
  processResponse (query, dv);
  GNUNET_free (dv);
  return GNUNET_OK;
}

/**
 * FastPathProcessor that only processes the first reply
 * (essentially to establish "done" == uniqueReplyIdentifier
 * as true or false.
 */
static int
fastPathProcessorFirst (const GNUNET_HashCode * query,
                        const GNUNET_DataContainer * value, void *cls)
{
  int *done = cls;
  GNUNET_DatastoreValue *dv;

  dv = gapWrapperToDatastoreValue (value, 0);
  if (dv == NULL)
    return GNUNET_SYSERR;
  processResponse (query, dv);
  if (GNUNET_YES ==
      uniqueReplyIdentifier (value, ntohl (dv->type), GNUNET_NO, query))
    *done = GNUNET_YES;
  GNUNET_free (dv);
  return GNUNET_SYSERR;
}

/**
 * Thread to lookup local replies to search queries
 * asynchronously.
 */
static void *
localGetter (void *noargs)
{
  LG_Job *job;
  while (1)
    {
      GNUNET_semaphore_down (ltgSignal, GNUNET_YES);
      GNUNET_mutex_lock (lock);
      if (lg_jobs == NULL)
        {
          GNUNET_mutex_unlock (lock);
          break;
        }
      job = lg_jobs;
      lg_jobs = job->next;
      GNUNET_mutex_unlock (lock);
      gapGet (NULL,
              job->type,
              GNUNET_EXTREME_PRIORITY,
              job->keyCount, job->queries, &fastPathProcessor, NULL);
      GNUNET_free (job->queries);
      GNUNET_free (job);
    }
  return NULL;
}

static void
queueLG_Job (unsigned int type,
             unsigned int keyCount, const GNUNET_HashCode * queries)
{
  LG_Job *job;

  job = GNUNET_malloc (sizeof (LG_Job));
  job->keyCount = keyCount;
  job->queries = GNUNET_malloc (sizeof (GNUNET_HashCode) * keyCount);
  memcpy (job->queries, queries, sizeof (GNUNET_HashCode) * keyCount);
  GNUNET_mutex_lock (lock);
  job->next = lg_jobs;
  lg_jobs = job;
  GNUNET_mutex_unlock (lock);
  GNUNET_semaphore_up (ltgSignal);
}

/**
 * Process a query from the client. Forwards to the network.
 *
 * @return GNUNET_SYSERR if the TCP connection should be closed, otherwise GNUNET_OK
 */
static int
csHandleRequestQueryStart (struct GNUNET_ClientHandle *sock,
                           const GNUNET_MessageHeader * req)
{
  static GNUNET_PeerIdentity all_zeros;
  const CS_fs_request_search_MESSAGE *rs;
  unsigned int keyCount;
#if DEBUG_FS
  GNUNET_EncName enc;
#endif
  unsigned int type;
  int done;
  int have_target;

  if (ntohs (req->size) < sizeof (CS_fs_request_search_MESSAGE))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  rs = (const CS_fs_request_search_MESSAGE *) req;
  if (memcmp (&all_zeros, &rs->target, sizeof (GNUNET_PeerIdentity)) == 0)
    have_target = GNUNET_NO;
  else
    have_target = GNUNET_YES;
#if DEBUG_FS
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&rs->query[0], &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FS received QUERY START (query: `%s', ttl %llu, priority %u, anonymity %u)\n",
                 &enc, GNUNET_ntohll (rs->expiration) - GNUNET_get_time (),
                 ntohl (rs->prio), ntohl (rs->anonymityLevel));
#endif
  type = ntohl (rs->type);
  trackQuery (&rs->query[0], type, sock);
  keyCount =
    1 + (ntohs (req->size) -
         sizeof (CS_fs_request_search_MESSAGE)) / sizeof (GNUNET_HashCode);

  /* try a "fast path" avoiding gap/dht if unique reply is locally available */
  done = GNUNET_NO;
  gapGet (NULL,
          type,
          GNUNET_EXTREME_PRIORITY,
          keyCount, &rs->query[0], &fastPathProcessorFirst, &done);
  if (done == GNUNET_YES)
    {
#if DEBUG_FS
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "FS successfully took GAP shortcut for `%s'.\n", &enc);
#endif
      return GNUNET_OK;
    }

  /* run gapGet asynchronously (since it may take a while due to lots of IO) */
  queueLG_Job (type, keyCount, &rs->query[0]);
  gap->get_start (have_target == GNUNET_NO ? NULL : &rs->target,
                  type,
                  ntohl (rs->anonymityLevel),
                  keyCount,
                  &rs->query[0], GNUNET_ntohll (rs->expiration),
                  ntohl (rs->prio));
  if ((ntohl (rs->anonymityLevel) == 0) && (have_target == GNUNET_NO)
      && (dht != NULL))
    {
      struct DHT_GET_CLS *cls;

      cls = GNUNET_malloc (sizeof (struct DHT_GET_CLS));
      cls->sock = sock;
      cls->prio = ntohl (rs->prio);
      cls->key = rs->query[0];
      cls->rec = dht->get_start (type,
                                 &rs->query[0], &get_result_callback, cls);
      cls->expires = GNUNET_ntohll (rs->expiration);
      if (cls->rec == NULL)
        GNUNET_free (cls);      /* should never happen... */
      else
        {
          GNUNET_mutex_lock (lock);
          cls->next = dht_pending;
          dht_pending = cls;
          GNUNET_mutex_unlock (lock);
        }
    }
  return GNUNET_OK;
}

static int
fastGet (const GNUNET_HashCode * key)
{
  return datastore->fast_get (key);
}

/**
 * Method called whenever a given client disconnects.
 */
static void
csHandleClientExit (struct GNUNET_ClientHandle *client)
{
  struct DHT_GET_CLS *pos;
  struct DHT_GET_CLS *prev;

  GNUNET_mutex_lock (lock);
  prev = NULL;
  pos = dht_pending;
  while (pos != NULL)
    {
      if (pos->sock == client)
        {
          if (prev == NULL)
            dht_pending = pos->next;
          else
            prev->next = pos->next;
          dht->get_stop (pos->rec);
          GNUNET_free (pos);
          if (prev == NULL)
            pos = dht_pending;
          else
            pos = prev->next;
          continue;
        }
      prev = pos;
      pos = pos->next;
    }
  GNUNET_mutex_unlock (lock);
}

/**
 * Initialize the FS module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 *
 * @return GNUNET_SYSERR on errors
 */
int
initialize_module_fs (GNUNET_CoreAPIForPlugins * capi)
{
  static GNUNET_Blockstore dsGap;
  unsigned long long quota;

  ectx = capi->ectx;
  GNUNET_GE_ASSERT (ectx, sizeof (CHK) == 128);
  GNUNET_GE_ASSERT (ectx, sizeof (DBlock) == 4);
  GNUNET_GE_ASSERT (ectx, sizeof (IBlock) == 132);
  GNUNET_GE_ASSERT (ectx, sizeof (KBlock) == 524);
  GNUNET_GE_ASSERT (ectx, sizeof (SBlock) == 724);
  GNUNET_GE_ASSERT (ectx, sizeof (NBlock) == 716);
  GNUNET_GE_ASSERT (ectx, sizeof (KNBlock) == 1244);
  migration = GNUNET_GC_get_configuration_value_yesno (capi->cfg,
                                                       "FS",
                                                       "ACTIVEMIGRATION",
                                                       GNUNET_YES);
  if (migration == GNUNET_SYSERR)
    return GNUNET_SYSERR;
  if (GNUNET_GC_get_configuration_value_number (capi->cfg,
                                                "FS",
                                                "QUOTA",
                                                1,
                                                ((unsigned long long) -1) /
                                                1024, 1024, &quota) == -1)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("You must specify a postive number for `%s' in the configuration in section `%s'.\n"),
                     "QUOTA", "FS");
      return GNUNET_SYSERR;
    }
  datastore = capi->request_service ("datastore");
  if (datastore == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  traffic = capi->request_service ("traffic");
  stats = capi->request_service ("stats");
  if (stats != NULL)
    {
      stat_expired_replies_dropped
        = stats->create (gettext_noop ("# FS expired replies dropped"));
      stat_valid_replies_received
        = stats->create (gettext_noop ("# FS valid replies received"));
    }
  gap = capi->request_service ("gap");
  if (gap == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      capi->release_service (datastore);
      if (stats != NULL)
        capi->release_service (stats);
      capi->release_service (traffic);
      return GNUNET_SYSERR;
    }
  dht = capi->request_service ("dht");
  if (dht != NULL)
    init_dht_push (capi, dht);
  ltgSignal = GNUNET_semaphore_create (0);
  localGetProcessor = GNUNET_thread_create (&localGetter, NULL, 128 * 1024);
  if (localGetProcessor == NULL)
    GNUNET_GE_DIE_STRERROR (ectx,
                            GNUNET_GE_ADMIN | GNUNET_GE_FATAL |
                            GNUNET_GE_BULK, "pthread_create");
  coreAPI = capi;
  ONDEMAND_init (capi);
  lock = GNUNET_mutex_create (GNUNET_NO);
  dsGap.closure = NULL;
  dsGap.get = &gapGet;
  dsGap.put = &gapPut;
  dsGap.del = &gapDel;
  dsGap.iterate = &gapIterate;
  dsGap.fast_get = &fastGet;
  initQueryManager (capi);
  gap->init (&dsGap,
             &uniqueReplyIdentifier,
             (GNUNET_ReplyHashingCallback) & replyHashFunction);
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 _
                 ("`%s' registering client handlers %d %d %d %d %d %d %d %d %d\n"),
                 "fs", GNUNET_CS_PROTO_GAP_QUERY_START,
                 GNUNET_CS_PROTO_GAP_QUERY_STOP, GNUNET_CS_PROTO_GAP_INSERT,
                 GNUNET_CS_PROTO_GAP_INDEX, GNUNET_CS_PROTO_GAP_DELETE,
                 GNUNET_CS_PROTO_GAP_UNINDEX, GNUNET_CS_PROTO_GAP_TESTINDEX,
                 GNUNET_CS_PROTO_GAP_GET_AVG_PRIORITY,
                 GNUNET_CS_PROTO_GAP_INIT_INDEX);

  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->cs_exit_handler_register (&csHandleClientExit));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->
                    registerClientHandler (GNUNET_CS_PROTO_GAP_QUERY_START,
                                           &csHandleRequestQueryStart));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->
                    registerClientHandler (GNUNET_CS_PROTO_GAP_QUERY_STOP,
                                           &csHandleRequestQueryStop));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->registerClientHandler (GNUNET_CS_PROTO_GAP_INSERT,
                                                 &csHandleCS_fs_request_insert_MESSAGE));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->registerClientHandler (GNUNET_CS_PROTO_GAP_INDEX,
                                                 &csHandleCS_fs_request_index_MESSAGE));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->
                    registerClientHandler (GNUNET_CS_PROTO_GAP_INIT_INDEX,
                                           &csHandleCS_fs_request_init_index_MESSAGE));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->registerClientHandler (GNUNET_CS_PROTO_GAP_DELETE,
                                                 &csHandleCS_fs_request_delete_MESSAGE));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->registerClientHandler (GNUNET_CS_PROTO_GAP_UNINDEX,
                                                 &csHandleCS_fs_request_unindex_MESSAGE));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->
                    registerClientHandler (GNUNET_CS_PROTO_GAP_TESTINDEX,
                                           &csHandleCS_fs_request_test_index_MESSAGEed));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    capi->
                    registerClientHandler
                    (GNUNET_CS_PROTO_GAP_GET_AVG_PRIORITY,
                     &csHandleRequestGetAvgPriority));
  initMigration (capi, datastore, gap, dht, traffic);
  GNUNET_GE_ASSERT (capi->ectx,
                    0 == GNUNET_GC_set_configuration_value_string (capi->cfg,
                                                                   capi->ectx,
                                                                   "ABOUT",
                                                                   "fs",
                                                                   gettext_noop
                                                                   ("enables (anonymous) file-sharing")));
  return GNUNET_OK;
}

void
done_module_fs ()
{
  LG_Job *job;
  void *unused;

  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "fs shutdown\n");
  doneMigration ();
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    cs_exit_handler_unregister (&csHandleClientExit));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    unregisterClientHandler (GNUNET_CS_PROTO_GAP_QUERY_START,
                                             &csHandleRequestQueryStart));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    unregisterClientHandler (GNUNET_CS_PROTO_GAP_QUERY_STOP,
                                             &csHandleRequestQueryStop));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    unregisterClientHandler (GNUNET_CS_PROTO_GAP_INSERT,
                                             &csHandleCS_fs_request_insert_MESSAGE));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    unregisterClientHandler (GNUNET_CS_PROTO_GAP_INDEX,
                                             &csHandleCS_fs_request_index_MESSAGE));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    unregisterClientHandler (GNUNET_CS_PROTO_GAP_INIT_INDEX,
                                             &csHandleCS_fs_request_init_index_MESSAGE));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    unregisterClientHandler (GNUNET_CS_PROTO_GAP_DELETE,
                                             &csHandleCS_fs_request_delete_MESSAGE));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    unregisterClientHandler (GNUNET_CS_PROTO_GAP_UNINDEX,
                                             &csHandleCS_fs_request_unindex_MESSAGE));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    unregisterClientHandler (GNUNET_CS_PROTO_GAP_TESTINDEX,
                                             &csHandleCS_fs_request_test_index_MESSAGEed));
  GNUNET_GE_ASSERT (ectx,
                    GNUNET_SYSERR !=
                    coreAPI->
                    unregisterClientHandler
                    (GNUNET_CS_PROTO_GAP_GET_AVG_PRIORITY,
                     &csHandleRequestGetAvgPriority));
  while (lg_jobs != NULL)
    {
      job = lg_jobs->next;
      GNUNET_free (lg_jobs->queries);
      GNUNET_free (lg_jobs);
      lg_jobs = job;
    }
  GNUNET_semaphore_up (ltgSignal);      /* lg_jobs == NULL => thread will terminate */
  GNUNET_thread_join (localGetProcessor, &unused);
  doneQueryManager ();
  coreAPI->release_service (datastore);
  datastore = NULL;
  if (stats != NULL)
    {
      coreAPI->release_service (stats);
      stats = NULL;
    }
  coreAPI->release_service (gap);
  gap = NULL;
  if (dht != NULL)
    {
      done_dht_push ();
      coreAPI->release_service (dht);
      dht = NULL;
    }
  if (traffic != NULL)
    {
      coreAPI->release_service (traffic);
      traffic = NULL;
    }
  coreAPI = NULL;
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  ONDEMAND_done ();
  GNUNET_semaphore_destroy (ltgSignal);
  ltgSignal = NULL;
}

/**
 * Update FS module.
 */
void
update_module_fs (GNUNET_UpdateAPI * uapi)
{
  /* general sub-module updates */
  uapi->updateModule ("datastore");
  uapi->updateModule ("dht");
  uapi->updateModule ("gap");
  uapi->updateModule ("traffic");
}

/* end of fs.c */
