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

#define DEBUG_FS NO

typedef struct
{
  struct DHT_GET_RECORD *rec;
  unsigned int prio;
} DHT_GET_CLS;

typedef struct LG_Job
{
  unsigned int keyCount;
  unsigned int type;
  HashCode512 *queries;
  struct LG_Job *next;
} LG_Job;

/**
 * Global core API.
 */
static CoreAPIForApplication *coreAPI;

/**
 * GAP service.
 */
static GAP_ServiceAPI *gap;

/**
 * DHT service.  Maybe NULL!
 */
static DHT_ServiceAPI *dht;

/**
 * Datastore service.
 */
static Datastore_ServiceAPI *datastore;

/**
 * Traffic service.
 */
static Traffic_ServiceAPI *traffic;

/**
 * Stats service.
 */
static Stats_ServiceAPI *stats;

static int stat_expired_replies_dropped;

static int stat_valid_replies_received;

static struct MUTEX *lock;

static int migration;

static struct SEMAPHORE *ltgSignal;

static struct PTHREAD *localGetProcessor;

static LG_Job *lg_jobs;

static struct GE_Context *ectx;

static Datastore_Value *
gapWrapperToDatastoreValue (const DataContainer * value, int prio)
{
  Datastore_Value *dv;
  const GapWrapper *gw;
  unsigned int size;
  cron_t et;
  cron_t now;

  if (ntohl (value->size) < sizeof (GapWrapper))
    {
      GE_BREAK (ectx, 0);
      return NULL;
    }
  gw = (const GapWrapper *) value;
  size = ntohl (gw->dc.size) - sizeof (GapWrapper) + sizeof (Datastore_Value);
  dv = MALLOC (size);
  dv->size = htonl (size);
  dv->type = htonl (getTypeOfBlock (size - sizeof (Datastore_Value),
                                    (DBlock *) & gw[1]));
  dv->prio = htonl (prio);
  dv->anonymityLevel = htonl (0);
  et = ntohll (gw->timeout);
  now = get_time ();
  /* bound ET to MAX_MIGRATION_EXP from now */
  if (et > now)
    {
      et -= now;
      et = et % MAX_MIGRATION_EXP;
      et += now;
    }
  dv->expirationTime = htonll (et);
  memcpy (&dv[1], &gw[1], size - sizeof (Datastore_Value));
  return dv;
}

/**
 * Store an item in the datastore.
 *
 * @param query the unique identifier of the item
 * @param value the value to store
 * @param prio how much does our routing code value
 *        this datum?
 * @return OK if the value could be stored,
 *         NO if the value verifies but is not stored,
 *         SYSERR if the value is malformed
 */
static int
gapPut (void *closure,
        const HashCode512 * query,
        const DataContainer * value, unsigned int prio)
{
  Datastore_Value *dv;
  const GapWrapper *gw;
  unsigned int size;
  int ret;
  HashCode512 hc;
#if DEBUG_FS
  EncName enc;
#endif

  gw = (const GapWrapper *) value;
  size = ntohl (gw->dc.size) - sizeof (GapWrapper);
  if ((OK != getQueryFor (size,
                          (const DBlock *) &gw[1],
                          YES, &hc)) || (!equalsHashCode512 (&hc, query)))
    {
      GE_BREAK_OP (ectx, 0);    /* value failed verification! */
      return SYSERR;
    }
  dv = gapWrapperToDatastoreValue (value, prio);
  if (dv == NULL)
    {
      GE_BREAK_OP (ectx, 0);
      return SYSERR;
    }
  if (YES != isDatumApplicable (ntohl (dv->type),
                                ntohl (dv->size) - sizeof (Datastore_Value),
                                (const DBlock *) &dv[1], &hc, 0, query))
    {
      GE_BREAK (ectx, 0);
      FREE (dv);
      return SYSERR;
    }
  if (stats != NULL)
    stats->change (stat_valid_replies_received, 1);
  if (ntohll (dv->expirationTime) < get_time ())
    {
      /* do not do anything with expired data
         _except_ if it is pure content that one
         of our clients has requested -- then we
         should ignore expiration */
      if (ntohl (dv->type) == D_BLOCK)
        processResponse (query, dv);
      else if (stats != NULL)
        stats->change (stat_expired_replies_dropped, 1);

      FREE (dv);
      return NO;
    }
  processResponse (query, dv);


#if DEBUG_FS
  IF_GELOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (query, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FS received GAP-PUT request (query: `%s')\n", &enc);
#endif
  if (migration)
    ret = datastore->putUpdate (query, dv);
  else
    ret = OK;
  FREE (dv);
  if (ret == SYSERR)
    ret = NO;                   /* error in put != content invalid! */
  return ret;
}

static int
get_result_callback (const HashCode512 * query,
                     const DataContainer * value, void *ctx)
{
  DHT_GET_CLS *cls = ctx;
  const GapWrapper *gw;
  unsigned int size;
  HashCode512 hc;
#if DEBUG_FS
  EncName enc;

  IF_GELOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (query, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Found reply to query `%s'.\n", &enc);
#endif
  gw = (const GapWrapper *) value;
  size = ntohl (gw->dc.size) - sizeof (GapWrapper);
  if ((OK != getQueryFor (size,
                          (const DBlock *) &gw[1],
                          YES, &hc)) || (!equalsHashCode512 (&hc, query)))
    {
      GE_BREAK (NULL, 0);
      return OK;
    }

  gapPut (NULL, query, value, cls->prio);
  return OK;
}

static void
get_complete_callback (void *ctx)
{
  DHT_GET_CLS *cls = ctx;
  dht->get_stop (cls->rec);
  FREE (cls);
}

/**
 * Stop processing a query.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int
csHandleRequestQueryStop (struct ClientHandle *sock,
                          const MESSAGE_HEADER * req)
{
  const CS_fs_request_search_MESSAGE *rs;
#if DEBUG_FS
  EncName enc;
#endif

  if (ntohs (req->size) < sizeof (CS_fs_request_search_MESSAGE))
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  rs = (const CS_fs_request_search_MESSAGE *) req;
#if DEBUG_FS
  IF_GELOG (ectx,
            GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (&rs->query[0], &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FS received QUERY STOP (query: `%s')\n", &enc);
#endif
  gap->get_stop (ntohl (rs->type),
                 1 + (ntohs (req->size) -
                      sizeof (CS_fs_request_search_MESSAGE)) /
                 sizeof (HashCode512), &rs->query[0]);
  untrackQuery (&rs->query[0], sock);
  return OK;
}

/**
 * Process a request to insert content from the client.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int
csHandleCS_fs_request_insert_MESSAGE (struct ClientHandle *sock,
                                      const MESSAGE_HEADER * req)
{
  const CS_fs_request_insert_MESSAGE *ri;
  Datastore_Value *datum;
  struct GE_Context *cectx;
  HashCode512 query;
  int ret;
  unsigned int type;
#if DEBUG_FS
  EncName enc;
#endif

  cectx =
    coreAPI->createClientLogContext (GE_USER | GE_EVENTKIND | GE_ROUTEKIND,
                                     sock);
  if (ntohs (req->size) < sizeof (CS_fs_request_insert_MESSAGE))
    {
      GE_BREAK (ectx, 0);
      GE_BREAK (cectx, 0);
      GE_free_context (cectx);
      return SYSERR;
    }
  ri = (const CS_fs_request_insert_MESSAGE *) req;
  datum = MALLOC (sizeof (Datastore_Value) +
                  ntohs (req->size) - sizeof (CS_fs_request_insert_MESSAGE));
  datum->size = htonl (sizeof (Datastore_Value) +
                       ntohs (req->size) -
                       sizeof (CS_fs_request_insert_MESSAGE));
  datum->expirationTime = ri->expiration;
  datum->prio = ri->prio;
  datum->anonymityLevel = ri->anonymityLevel;
  if (OK !=
      getQueryFor (ntohs (ri->header.size) -
                   sizeof (CS_fs_request_insert_MESSAGE),
                   (const DBlock *) &ri[1], YES, &query))
    {
      GE_BREAK (ectx, 0);
      GE_BREAK (cectx, 0);
      FREE (datum);
      GE_free_context (cectx);
      return SYSERR;
    }
  type =
    getTypeOfBlock (ntohs (ri->header.size) -
                    sizeof (CS_fs_request_insert_MESSAGE),
                    (const DBlock *) &ri[1]);
#if DEBUG_FS
  IF_GELOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (&query, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FS received REQUEST INSERT (query: `%s', type: %u, priority %u)\n",
          &enc, type, ntohl (ri->prio));
#endif
  datum->type = htonl (type);
  memcpy (&datum[1],
          &ri[1], ntohs (req->size) - sizeof (CS_fs_request_insert_MESSAGE));
  MUTEX_LOCK (lock);
  if ((type != D_BLOCK) || (0 == datastore->get (&query, type, NULL, NULL)))
    ret = datastore->put (&query, datum);
  else
    ret = OK;
  MUTEX_UNLOCK (lock);
  if ((ntohl (ri->anonymityLevel) == 0) && (dht != NULL))
    {
      GapWrapper *gw;
      unsigned int size;
      cron_t now;
      cron_t et;
      HashCode512 hc;

      size = sizeof (GapWrapper) +
        ntohs (ri->header.size) - sizeof (CS_fs_request_insert_MESSAGE);
      gw = MALLOC (size);
      gw->reserved = 0;
      gw->dc.size = htonl (size);
      et = ntohll (ri->expiration);
      /* expiration time normalization and randomization */
      now = get_time ();
      if (et > now)
        {
          et -= now;
          et = et % MAX_MIGRATION_EXP;
          if (et > 0)
            et = weak_randomi (et);
          et = et + now;
        }
      gw->timeout = htonll (et);
      memcpy (&gw[1], &ri[1], size - sizeof (GapWrapper));
      /* sanity check */
      if ((OK != getQueryFor (size - sizeof (GapWrapper),
                              (const DBlock *) &gw[1],
                              YES,
                              &hc)) || (!equalsHashCode512 (&hc, &query)))
        {
          GE_BREAK (NULL, 0);
        }
      else
        {
          dht->put (&query, type, size, et, (const char *) gw);
        }
      FREE (gw);
    }
  FREE (datum);
  GE_free_context (cectx);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * Process a request to symlink a file
 */
static int
csHandleCS_fs_request_init_index_MESSAGE (struct ClientHandle *sock,
                                          const MESSAGE_HEADER * req)
{
  int ret;
  char *fn;
  CS_fs_request_init_index_MESSAGE *ri;
  int fnLen;
  struct GE_Context *cectx;

  cectx =
    coreAPI->createClientLogContext (GE_USER | GE_EVENTKIND | GE_ROUTEKIND,
                                     sock);
  if (ntohs (req->size) < sizeof (CS_fs_request_init_index_MESSAGE))
    {
      GE_BREAK (ectx, 0);
      GE_BREAK (cectx, 0);
      GE_free_context (cectx);
      return SYSERR;
    }

  ri = (CS_fs_request_init_index_MESSAGE *) req;

  fnLen = ntohs (ri->header.size) - sizeof (CS_fs_request_init_index_MESSAGE);
#if WINDOWS
  if (fnLen > _MAX_PATH)
    {
      GE_BREAK (cectx, 0);
      GE_free_context (cectx);
      return SYSERR;
    }
#endif
  fn = MALLOC (fnLen + 1);
  strncpy (fn, (char *) &ri[1], fnLen + 1);
  fn[fnLen] = 0;
  ret = ONDEMAND_initIndex (cectx, &ri->fileId, fn);

  FREE (fn);
#if DEBUG_FS
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Sending confirmation (%s) of index initialization request to client\n",
          ret == OK ? "success" : "failure");
#endif
  GE_free_context (cectx);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * Process a request to index content from the client.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int
csHandleCS_fs_request_index_MESSAGE (struct ClientHandle *sock,
                                     const MESSAGE_HEADER * req)
{
  int ret;
  const CS_fs_request_index_MESSAGE *ri;
  struct GE_Context *cectx;

  cectx =
    coreAPI->createClientLogContext (GE_USER | GE_EVENTKIND | GE_ROUTEKIND,
                                     sock);
  if (ntohs (req->size) < sizeof (CS_fs_request_index_MESSAGE))
    {
      GE_BREAK (ectx, 0);
      GE_BREAK (cectx, 0);
      GE_free_context (cectx);
      return SYSERR;
    }
  ri = (const CS_fs_request_index_MESSAGE *) req;
  ret = ONDEMAND_index (cectx,
                        datastore,
                        ntohl (ri->prio),
                        ntohll (ri->expiration),
                        ntohll (ri->fileOffset),
                        ntohl (ri->anonymityLevel),
                        &ri->fileId,
                        ntohs (ri->header.size) -
                        sizeof (CS_fs_request_index_MESSAGE),
                        (const DBlock *) &ri[1]);
#if DEBUG_FS
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Sending confirmation (%s) of index request to client\n",
          ret == OK ? "success" : "failure");
#endif
  GE_free_context (cectx);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * If the data portion and type of the value match our value in the
 * closure, copy the header (prio, anonymityLevel, expirationTime) and
 * abort the iteration: we found what we're looing for.  Otherwise
 * continue.
 */
static int
completeValue (const HashCode512 * key,
               const Datastore_Value * value, void *closure,
               unsigned long long uid)
{
  Datastore_Value *comp = closure;

  if ((comp->size != value->size) ||
      (0 != memcmp (&value[1],
                    &comp[1],
                    ntohl (value->size) - sizeof (Datastore_Value))))
    {
#if DEBUG_FS
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "`%s' found value that does not match (%u, %u).\n",
              __FUNCTION__, ntohl (comp->size), ntohl (value->size));
#endif
      return OK;
    }
  *comp = *value;               /* make copy! */
#if DEBUG_FS
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "`%s' found value that matches.\n", __FUNCTION__);
#endif
  return SYSERR;
}

/**
 * Process a query to delete content.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int
csHandleCS_fs_request_delete_MESSAGE (struct ClientHandle *sock,
                                      const MESSAGE_HEADER * req)
{
  int ret;
  const CS_fs_request_delete_MESSAGE *rd;
  Datastore_Value *value;
  HashCode512 query;
  unsigned int type;
#if DEBUG_FS
  EncName enc;
#endif
  struct GE_Context *cectx;

  cectx =
    coreAPI->createClientLogContext (GE_USER | GE_EVENTKIND | GE_ROUTEKIND,
                                     sock);
  if (ntohs (req->size) < sizeof (CS_fs_request_delete_MESSAGE))
    {
      GE_BREAK (ectx, 0);
      GE_BREAK (cectx, 0);
      GE_free_context (cectx);
      return SYSERR;
    }
  rd = (const CS_fs_request_delete_MESSAGE *) req;
  value = MALLOC (sizeof (Datastore_Value) +
                  ntohs (req->size) - sizeof (CS_fs_request_delete_MESSAGE));
  value->size = ntohl (sizeof (Datastore_Value) +
                       ntohs (req->size) -
                       sizeof (CS_fs_request_delete_MESSAGE));
  type =
    getTypeOfBlock (ntohs (rd->header.size) -
                    sizeof (CS_fs_request_delete_MESSAGE),
                    (const DBlock *) &rd[1]);
  value->type = htonl (type);
  memcpy (&value[1],
          &rd[1], ntohs (req->size) - sizeof (CS_fs_request_delete_MESSAGE));
  if (OK !=
      getQueryFor (ntohs (rd->header.size) -
                   sizeof (CS_fs_request_delete_MESSAGE),
                   (const DBlock *) &rd[1], NO, &query))
    {
      FREE (value);
      GE_BREAK (ectx, 0);
      GE_BREAK (cectx, 0);
      GE_free_context (cectx);
      return SYSERR;
    }
#if DEBUG_FS
  IF_GELOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (&query, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FS received REQUEST DELETE (query: `%s', type: %u)\n", &enc, type);
#endif
  MUTEX_LOCK (lock);
  if (SYSERR == datastore->get (&query, type, &completeValue, value))   /* aborted == found! */
    ret = datastore->del (&query, value);
  else                          /* not found */
    ret = SYSERR;
  MUTEX_UNLOCK (lock);
  FREE (value);
#if DEBUG_FS
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Sending confirmation (%s) of delete request to client\n",
          ret != SYSERR ? "success" : "failure");
#endif
  GE_free_context (cectx);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * Process a client request unindex content.
 */
static int
csHandleCS_fs_request_unindex_MESSAGE (struct ClientHandle *sock,
                                       const MESSAGE_HEADER * req)
{
  int ret;
  const CS_fs_request_unindex_MESSAGE *ru;
  struct GE_Context *cectx;

  cectx =
    coreAPI->createClientLogContext (GE_USER | GE_EVENTKIND | GE_ROUTEKIND,
                                     sock);
  if (ntohs (req->size) != sizeof (CS_fs_request_unindex_MESSAGE))
    {
      GE_BREAK (ectx, 0);
      GE_BREAK (cectx, 0);
      GE_free_context (cectx);
      return SYSERR;
    }
  ru = (const CS_fs_request_unindex_MESSAGE *) req;
#if DEBUG_FS
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER, "FS received REQUEST UNINDEX\n");
#endif
  ret = ONDEMAND_unindex (cectx,
                          datastore, ntohl (ru->blocksize), &ru->fileId);
  GE_free_context (cectx);
  return coreAPI->sendValueToClient (sock, ret);
}

/**
 * Process a client request to test if certain
 * data is indexed.
 */
static int
csHandleCS_fs_request_test_index_MESSAGEed (struct ClientHandle *sock,
                                            const MESSAGE_HEADER * req)
{
  int ret;
  const RequestTestindex *ru;

  if (ntohs (req->size) != sizeof (RequestTestindex))
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  ru = (const RequestTestindex *) req;
#if DEBUG_FS
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
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
csHandleRequestGetAvgPriority (struct ClientHandle *sock,
                               const MESSAGE_HEADER * req)
{
#if DEBUG_FS
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FS received REQUEST GETAVGPRIORITY\n");
#endif
  return coreAPI->sendValueToClient (sock, gap->getAvgPriority ());
}

/**
 * Closure for the gapGetConverter method.
 */
typedef struct
{
  DataProcessor resultCallback;
  void *resCallbackClosure;
  unsigned int keyCount;
  const HashCode512 *keys;
  int count;
} GGC;

/**
 * Callback that converts the Datastore_Value values
 * from the datastore to Blockstore values for the
 * gap routing protocol.
 */
static int
gapGetConverter (const HashCode512 * key,
                 const Datastore_Value * invalue, void *cls,
                 unsigned long long uid)
{
  GGC *ggc = (GGC *) cls;
  GapWrapper *gw;
  int ret;
  unsigned int size;
  cron_t et;
  cron_t now;
  const Datastore_Value *value;
  Datastore_Value *xvalue;
  unsigned int level;
  EncName enc;
#if EXTRA_CHECKS
  HashCode512 hc;
#endif

#if DEBUG_FS
  IF_GELOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (key, &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Converting reply for query `%s' for gap.\n", &enc);
#endif
  et = ntohll (invalue->expirationTime);
  now = get_time ();
  if ((et <= now) && (ntohl (invalue->type) != D_BLOCK))
    {
      /* content expired and not just data -- drop! */
      return OK;
    }

  if (ntohl (invalue->type) == ONDEMAND_BLOCK)
    {
      if (OK != ONDEMAND_getIndexed (datastore, invalue, key, &xvalue))
        return SYSERR;
      value = xvalue;
    }
  else
    {
      xvalue = NULL;
      value = invalue;
    }
#if EXTRA_CHECKS
  if ((OK != getQueryFor (ntohl (value->size) - sizeof (Datastore_Value),
                          (const DBlock *) &value[1],
                          YES, &hc)) || (!equalsHashCode512 (&hc, key)))
    {
      GE_BREAK (ectx, 0);       /* value failed verification! */
      return SYSERR;
    }
#endif
  ret = isDatumApplicable (ntohl (value->type),
                           ntohl (value->size) - sizeof (Datastore_Value),
                           (const DBlock *) &value[1],
                           key, ggc->keyCount, ggc->keys);
  if (ret == SYSERR)
    {
      IF_GELOG (ectx, GE_WARNING | GE_BULK | GE_USER, hash2enc (key, &enc));
      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              "Converting reply for query `%s' for gap failed (datum not applicable).\n",
              &enc);
      FREENONNULL (xvalue);
      return SYSERR;            /* no query will ever match */
    }
  if (ret == NO)
    {
      IF_GELOG (ectx, GE_WARNING | GE_BULK | GE_USER, hash2enc (key, &enc));
      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              "Converting reply for query `%s' for gap failed (type not applicable).\n",
              &enc);
      FREENONNULL (xvalue);
      return OK;                /* Additional filtering based on type;
                                   i.e., namespace request and namespace
                                   in reply does not match namespace in query */
    }
  size = sizeof (GapWrapper) + ntohl (value->size) - sizeof (Datastore_Value);

  level = ntohl (value->anonymityLevel);
  if (OK != checkCoverTraffic (ectx, traffic, level))
    {
      /* traffic required by module not loaded;
         refuse to hand out data that requires
         anonymity! */
      FREENONNULL (xvalue);
      IF_GELOG (ectx, GE_WARNING | GE_BULK | GE_USER, hash2enc (key, &enc));
      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              "Converting reply for query `%s' for gap failed (insufficient cover traffic).\n",
              &enc);
      return OK;
    }
  gw = MALLOC (size);
  gw->dc.size = htonl (size);
  /* expiration time normalization and randomization */
  if (et > now)
    {
      et -= now;
      et = et % MAX_MIGRATION_EXP;
      if (et > 0)
        et = weak_randomi (et);
      et = et + now;
    }
  gw->timeout = htonll (et);
  memcpy (&gw[1], &value[1], size - sizeof (GapWrapper));

  if (ggc->resultCallback != NULL)
    ret = ggc->resultCallback (key, &gw->dc, ggc->resCallbackClosure);
  else
    ret = OK;
  ggc->count++;
  FREE (gw);
  FREENONNULL (xvalue);
  return ret;
}

/**
 * Lookup an item in the datastore.
 *
 * @param key the value to lookup
 * @param resultCallback function to call for each result that was found
 * @param resCallbackClosure extra argument to resultCallback
 * @return number of results, SYSERR on error
 */
static int
gapGet (void *closure,
        unsigned int type,
        unsigned int prio,
        unsigned int keyCount,
        const HashCode512 * keys,
        DataProcessor resultCallback, void *resCallbackClosure)
{
  int ret;
  GGC myClosure;
#if DEBUG_FS
  EncName enc;

  IF_GELOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (&keys[0], &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "GAP requests content for `%s' of type %u\n", &enc, type);
#endif
  myClosure.count = 0;
  myClosure.keyCount = keyCount;
  myClosure.keys = keys;
  myClosure.resultCallback = resultCallback;
  myClosure.resCallbackClosure = resCallbackClosure;
  ret = OK;
  if (type == D_BLOCK)
    {
      ret = datastore->get (&keys[0],
                            ONDEMAND_BLOCK, &gapGetConverter, &myClosure);
    }
  if (ret != SYSERR)
    ret = datastore->get (&keys[0], type, &gapGetConverter, &myClosure);
  if (ret != SYSERR)
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
 * @return OK if the value could be removed, SYSERR if not (i.e. not present)
 */
static int
gapDel (void *closure, const HashCode512 * key, const DataContainer * value)
{
  GE_BREAK (ectx, 0);           /* gap does not use 'del'! */
  return SYSERR;
}

/**
 * Iterate over all keys in the local datastore
 *
 * @param processor function to call on each item
 * @param cls argument to processor
 * @return number of results, SYSERR on error
 */
static int
gapIterate (void *closure, DataProcessor processor, void *cls)
{
  GE_BREAK (ectx, 0);           /* gap does not use 'iterate' */
  return SYSERR;
}

static int
replyHashFunction (const DataContainer * content, HashCode512 * id)
{
  const GapWrapper *gw;
  unsigned int size;

  size = ntohl (content->size);
  if (size < sizeof (GapWrapper))
    {
      GE_BREAK (ectx, 0);
      memset (id, 0, sizeof (HashCode512));
      return SYSERR;
    }
  gw = (const GapWrapper *) content;
  hash (&gw[1], size - sizeof (GapWrapper), id);
  return OK;
}

static int
uniqueReplyIdentifier (const DataContainer * content,
                       unsigned int type,
                       int verify, const HashCode512 * primaryKey)
{
  HashCode512 q;
  unsigned int t;
  const GapWrapper *gw;
  unsigned int size;

  size = ntohl (content->size);
  if (size < sizeof (GapWrapper))
    {
      GE_BREAK (ectx, 0);
      return NO;
    }
  gw = (const GapWrapper *) content;
  if ((OK == getQueryFor (size - sizeof (GapWrapper),
                          (const DBlock *) &gw[1],
                          verify,
                          &q)) &&
      (equalsHashCode512 (&q,
                          primaryKey)) &&
      ((type == ANY_BLOCK) ||
       (type == (t = getTypeOfBlock (size - sizeof (GapWrapper),
                                     (const DBlock *) &gw[1])))))
    {
      switch (type)
        {
        case D_BLOCK:
          return YES;
        default:
          return NO;
        }
    }
  else
    return NO;
}

static int
fastPathProcessor (const HashCode512 * query,
                   const DataContainer * value, void *cls)
{
  Datastore_Value *dv;

  dv = gapWrapperToDatastoreValue (value, 0);
  if (dv == NULL)
    return SYSERR;
  processResponse (query, dv);
  FREE (dv);
  return OK;
}

/**
 * FastPathProcessor that only processes the first reply
 * (essentially to establish "done" == uniqueReplyIdentifier
 * as true or false.
 */
static int
fastPathProcessorFirst (const HashCode512 * query,
                        const DataContainer * value, void *cls)
{
  int *done = cls;
  Datastore_Value *dv;

  dv = gapWrapperToDatastoreValue (value, 0);
  if (dv == NULL)
    return SYSERR;
  processResponse (query, dv);
  if (YES == uniqueReplyIdentifier (value, ntohl (dv->type), NO, query))
    *done = YES;
  FREE (dv);
  return SYSERR;
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
      SEMAPHORE_DOWN (ltgSignal, YES);
      MUTEX_LOCK (lock);
      if (lg_jobs == NULL)
        {
          MUTEX_UNLOCK (lock);
          break;
        }
      job = lg_jobs;
      lg_jobs = job->next;
      MUTEX_UNLOCK (lock);
      gapGet (NULL,
              job->type,
              EXTREME_PRIORITY,
              job->keyCount, job->queries, &fastPathProcessor, NULL);
      FREE (job->queries);
      FREE (job);
    }
  return NULL;
}

static void
queueLG_Job (unsigned int type,
             unsigned int keyCount, const HashCode512 * queries)
{
  LG_Job *job;

  job = MALLOC (sizeof (LG_Job));
  job->keyCount = keyCount;
  job->queries = MALLOC (sizeof (HashCode512) * keyCount);
  memcpy (job->queries, queries, sizeof (HashCode512) * keyCount);
  MUTEX_LOCK (lock);
  job->next = lg_jobs;
  lg_jobs = job;
  MUTEX_UNLOCK (lock);
  SEMAPHORE_UP (ltgSignal);
}

/**
 * Process a query from the client. Forwards to the network.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int
csHandleRequestQueryStart (struct ClientHandle *sock,
                           const MESSAGE_HEADER * req)
{
  static PeerIdentity all_zeros;
  const CS_fs_request_search_MESSAGE *rs;
  unsigned int keyCount;
#if DEBUG_FS
  EncName enc;
#endif
  unsigned int type;
  int done;
  int have_target;

  if (ntohs (req->size) < sizeof (CS_fs_request_search_MESSAGE))
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  rs = (const CS_fs_request_search_MESSAGE *) req;
  if (memcmp (&all_zeros, &rs->target, sizeof (PeerIdentity)) == 0)
    have_target = NO;
  else
    have_target = YES;
#if DEBUG_FS
  IF_GELOG (ectx,
            GE_DEBUG | GE_REQUEST | GE_USER, hash2enc (&rs->query[0], &enc));
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FS received QUERY START (query: `%s', ttl %llu, priority %u, anonymity %u)\n",
          &enc,
          ntohll (rs->expiration) - get_time (),
          ntohl (rs->prio), ntohl (rs->anonymityLevel));
#endif
  type = ntohl (rs->type);
  trackQuery (&rs->query[0], type, sock);
  keyCount =
    1 + (ntohs (req->size) -
         sizeof (CS_fs_request_search_MESSAGE)) / sizeof (HashCode512);

  /* try a "fast path" avoiding gap/dht if unique reply is locally available */
  done = NO;
  gapGet (NULL,
          type,
          EXTREME_PRIORITY,
          keyCount, &rs->query[0], &fastPathProcessorFirst, &done);
  if (done == YES)
    {
#if DEBUG_FS
      GE_LOG (ectx,
              GE_DEBUG | GE_REQUEST | GE_USER,
              "FS successfully took GAP shortcut for `%s'.\n", &enc);
#endif
      return OK;
    }

  /* run gapGet asynchronously (since it may take a while due to lots of IO) */
  queueLG_Job (type, keyCount, &rs->query[0]);
  gap->get_start (have_target == NO ? NULL : &rs->target,
                  type,
                  ntohl (rs->anonymityLevel),
                  keyCount,
                  &rs->query[0], ntohll (rs->expiration), ntohl (rs->prio));
  if ((ntohl (rs->anonymityLevel) == 0) &&
      (have_target == NO) && (dht != NULL))
    {
      DHT_GET_CLS *cls;

      cls = MALLOC (sizeof (DHT_GET_CLS));
      cls->prio = ntohl (rs->prio);
      cls->rec = dht->get_start (type,
                                 &rs->query[0],
                                 ntohll (rs->expiration),
                                 &get_result_callback,
                                 cls, &get_complete_callback, cls);
      if (cls->rec == NULL)
        FREE (cls);             /* should never happen... */
    }
  return OK;
}

static int
fastGet (const HashCode512 * key)
{
  return datastore->fast_get (key);
}

/**
 * Initialize the FS module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 *
 * @return SYSERR on errors
 */
int
initialize_module_fs (CoreAPIForApplication * capi)
{
  static Blockstore dsGap;
  unsigned long long quota;

  ectx = capi->ectx;
  GE_ASSERT (ectx, sizeof (CHK) == 128);
  GE_ASSERT (ectx, sizeof (DBlock) == 4);
  GE_ASSERT (ectx, sizeof (IBlock) == 132);
  GE_ASSERT (ectx, sizeof (KBlock) == 524);
  GE_ASSERT (ectx, sizeof (SBlock) == 724);
  GE_ASSERT (ectx, sizeof (NBlock) == 716);
  GE_ASSERT (ectx, sizeof (KNBlock) == 1244);
  migration = GC_get_configuration_value_yesno (capi->cfg,
                                                "FS", "ACTIVEMIGRATION", YES);
  if (migration == SYSERR)
    return SYSERR;
  if (GC_get_configuration_value_number (capi->cfg,
                                         "FS",
                                         "QUOTA",
                                         1,
                                         ((unsigned long long) -1) / 1024,
                                         1024, &quota) == -1)
    {
      GE_LOG (ectx,
              GE_ERROR | GE_BULK | GE_USER,
              _
              ("You must specify a postive number for `%s' in the configuration in section `%s'.\n"),
              "QUOTA", "FS");
      return SYSERR;
    }
  datastore = capi->requestService ("datastore");
  if (datastore == NULL)
    {
      GE_BREAK (ectx, 0);
      return SYSERR;
    }
  traffic = capi->requestService ("traffic");
  stats = capi->requestService ("stats");
  if (stats != NULL)
    {
      stat_expired_replies_dropped
        = stats->create (gettext_noop ("# FS expired replies dropped"));
      stat_valid_replies_received
        = stats->create (gettext_noop ("# FS valid replies received"));
    }
  gap = capi->requestService ("gap");
  if (gap == NULL)
    {
      GE_BREAK (ectx, 0);
      capi->releaseService (datastore);
      if (stats != NULL)
        capi->releaseService (stats);
      capi->releaseService (traffic);
      return SYSERR;
    }
  dht = capi->requestService ("dht");
  if (dht != NULL)
    init_dht_push (capi, dht);
  ltgSignal = SEMAPHORE_CREATE (0);
  localGetProcessor = PTHREAD_CREATE (&localGetter, NULL, 128 * 1024);
  if (localGetProcessor == NULL)
    GE_DIE_STRERROR (ectx, GE_ADMIN | GE_FATAL | GE_BULK, "pthread_create");
  coreAPI = capi;
  ONDEMAND_init (capi);
  lock = MUTEX_CREATE (NO);
  dsGap.closure = NULL;
  dsGap.get = &gapGet;
  dsGap.put = &gapPut;
  dsGap.del = &gapDel;
  dsGap.iterate = &gapIterate;
  dsGap.fast_get = &fastGet;
  initQueryManager (capi);
  gap->init (&dsGap,
             &uniqueReplyIdentifier, (ReplyHashFunction) & replyHashFunction);
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          _("`%s' registering client handlers %d %d %d %d %d %d %d %d %d\n"),
          "fs",
          CS_PROTO_gap_QUERY_START,
          CS_PROTO_gap_QUERY_STOP,
          CS_PROTO_gap_INSERT,
          CS_PROTO_gap_INDEX,
          CS_PROTO_gap_DELETE,
          CS_PROTO_gap_UNINDEX,
          CS_PROTO_gap_TESTINDEX,
          CS_PROTO_gap_GET_AVG_PRIORITY, CS_PROTO_gap_INIT_INDEX);

  GE_ASSERT (ectx,
             SYSERR != capi->registerClientHandler (CS_PROTO_gap_QUERY_START,
                                                    &csHandleRequestQueryStart));
  GE_ASSERT (ectx,
             SYSERR != capi->registerClientHandler (CS_PROTO_gap_QUERY_STOP,
                                                    &csHandleRequestQueryStop));
  GE_ASSERT (ectx,
             SYSERR != capi->registerClientHandler (CS_PROTO_gap_INSERT,
                                                    &csHandleCS_fs_request_insert_MESSAGE));
  GE_ASSERT (ectx,
             SYSERR != capi->registerClientHandler (CS_PROTO_gap_INDEX,
                                                    &csHandleCS_fs_request_index_MESSAGE));
  GE_ASSERT (ectx,
             SYSERR != capi->registerClientHandler (CS_PROTO_gap_INIT_INDEX,
                                                    &csHandleCS_fs_request_init_index_MESSAGE));
  GE_ASSERT (ectx,
             SYSERR != capi->registerClientHandler (CS_PROTO_gap_DELETE,
                                                    &csHandleCS_fs_request_delete_MESSAGE));
  GE_ASSERT (ectx,
             SYSERR != capi->registerClientHandler (CS_PROTO_gap_UNINDEX,
                                                    &csHandleCS_fs_request_unindex_MESSAGE));
  GE_ASSERT (ectx,
             SYSERR != capi->registerClientHandler (CS_PROTO_gap_TESTINDEX,
                                                    &csHandleCS_fs_request_test_index_MESSAGEed));
  GE_ASSERT (ectx,
             SYSERR !=
             capi->registerClientHandler (CS_PROTO_gap_GET_AVG_PRIORITY,
                                          &csHandleRequestGetAvgPriority));
  initMigration (capi, datastore, gap, dht, traffic);
  GE_ASSERT (capi->ectx,
             0 == GC_set_configuration_value_string (capi->cfg,
                                                     capi->ectx,
                                                     "ABOUT",
                                                     "fs",
                                                     gettext_noop
                                                     ("enables (anonymous) file-sharing")));
  return OK;
}

void
done_module_fs ()
{
  LG_Job *job;
  void *unused;

  GE_LOG (ectx, GE_DEBUG | GE_REQUEST | GE_USER, "fs shutdown\n");
  doneMigration ();
  GE_ASSERT (ectx,
             SYSERR !=
             coreAPI->unregisterClientHandler (CS_PROTO_gap_QUERY_START,
                                               &csHandleRequestQueryStart));
  GE_ASSERT (ectx,
             SYSERR !=
             coreAPI->unregisterClientHandler (CS_PROTO_gap_QUERY_STOP,
                                               &csHandleRequestQueryStop));
  GE_ASSERT (ectx,
             SYSERR != coreAPI->unregisterClientHandler (CS_PROTO_gap_INSERT,
                                                         &csHandleCS_fs_request_insert_MESSAGE));
  GE_ASSERT (ectx,
             SYSERR != coreAPI->unregisterClientHandler (CS_PROTO_gap_INDEX,
                                                         &csHandleCS_fs_request_index_MESSAGE));
  GE_ASSERT (ectx,
             SYSERR !=
             coreAPI->unregisterClientHandler (CS_PROTO_gap_INIT_INDEX,
                                               &csHandleCS_fs_request_init_index_MESSAGE));
  GE_ASSERT (ectx,
             SYSERR != coreAPI->unregisterClientHandler (CS_PROTO_gap_DELETE,
                                                         &csHandleCS_fs_request_delete_MESSAGE));
  GE_ASSERT (ectx,
             SYSERR != coreAPI->unregisterClientHandler (CS_PROTO_gap_UNINDEX,
                                                         &csHandleCS_fs_request_unindex_MESSAGE));
  GE_ASSERT (ectx,
             SYSERR !=
             coreAPI->unregisterClientHandler (CS_PROTO_gap_TESTINDEX,
                                               &csHandleCS_fs_request_test_index_MESSAGEed));
  GE_ASSERT (ectx,
             SYSERR !=
             coreAPI->unregisterClientHandler (CS_PROTO_gap_GET_AVG_PRIORITY,
                                               &csHandleRequestGetAvgPriority));
  doneQueryManager ();
  while (lg_jobs != NULL)
    {
      job = lg_jobs->next;
      FREE (lg_jobs->queries);
      FREE (lg_jobs);
      lg_jobs = job;
    }
  SEMAPHORE_UP (ltgSignal);     /* lg_jobs == NULL => thread will terminate */
  PTHREAD_JOIN (localGetProcessor, &unused);
  coreAPI->releaseService (datastore);
  datastore = NULL;
  if (stats != NULL)
    {
      coreAPI->releaseService (stats);
      stats = NULL;
    }
  coreAPI->releaseService (gap);
  gap = NULL;
  if (dht != NULL)
    {
      done_dht_push ();
      coreAPI->releaseService (dht);
      dht = NULL;
    }
  if (traffic != NULL)
    {
      coreAPI->releaseService (traffic);
      traffic = NULL;
    }
  coreAPI = NULL;
  MUTEX_DESTROY (lock);
  lock = NULL;
  ONDEMAND_done ();
  SEMAPHORE_DESTROY (ltgSignal);
  ltgSignal = NULL;
}

/**
 * Update FS module.
 */
void
update_module_fs (UpdateAPI * uapi)
{
  /* general sub-module updates */
  uapi->updateModule ("datastore");
  uapi->updateModule ("dht");
  uapi->updateModule ("gap");
  uapi->updateModule ("traffic");
}

/* end of fs.c */
