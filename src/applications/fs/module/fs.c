/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/module/fs.c
 * @brief main functions of the file sharing service
 * @author Christian Grothoff
 *
 * FS CORE. This is the code that is plugged into the GNUnet core to
 * enable File Sharing.
 *
 * TODO:
 * - DHT integration (will have to modify DHT API, too!)
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_gap_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_datastore_service.h"
#include "ecrs_core.h"
#include "migration.h"
#include "ondemand.h"
#include "querymanager.h"
#include "fs.h"

/**
 * What is the maximum expiration time for migrated
 * content?
 */
#define MAX_MIGRATION_EXP (1L * cronMONTHS)

/**
 * Global core API.
 */
static CoreAPIForApplication * coreAPI;

/**
 * GAP service.
 */
static GAP_ServiceAPI * gap;

/**
 * DHT service.  Maybe NULL!
 */
static DHT_ServiceAPI * dht;

/**
 * Datastore service.
 */
static Datastore_ServiceAPI * datastore;

static Mutex lock;


/**
 * Process a query from the client. Forwards to the network.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */ 
static int csHandleRequestQueryStart(ClientHandle sock,
				     const CS_HEADER * req) {
  RequestSearch * rs;

  if (ntohs(req->size) < sizeof(RequestSearch)) {
    BREAK();
    return SYSERR;
  }
  rs = (RequestSearch*) req;
  trackQuery(&rs->query[0], sock);
  gap->get_start(ntohl(rs->type),
		 ntohl(rs->anonymityLevel),		 
		 1 + (ntohs(req->size) - sizeof(RequestSearch)) / sizeof(HashCode160),
		 &rs->query[0],
		 ntohll(rs->expiration),
		 ntohl(rs->prio));
  if (ntohl(rs->anonymityLevel) == 0) {
    /* FIXME: query(rs); -- pass to dht! */
  }
  return OK;
}


/**
 * Stop processing a query.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */ 
static int csHandleRequestQueryStop(ClientHandle sock,
				    const CS_HEADER * req) {
  RequestSearch * rs;

  if (ntohs(req->size) < sizeof(RequestSearch)) {
    BREAK();
    return SYSERR;
  }
  rs = (RequestSearch*) req;
  if (ntohl(rs->anonymityLevel) == 0) {
    /* FIXME: cancel with dht */
  }
  gap->get_stop(ntohl(rs->type),
		1 + (ntohs(req->size) - sizeof(RequestSearch)) / sizeof(HashCode160),
		&rs->query[0]);
  untrackQuery(&rs->query[0], sock);
  return OK;
}

/**
 * Process a request to insert content from the client.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int csHandleRequestInsert(ClientHandle sock,
				 const CS_HEADER * req) {
  RequestInsert * ri;
  Datastore_Value * datum;
  int ret;
  HashCode160 query;

  if (ntohs(req->size) < sizeof(RequestIndex)) {
    BREAK();
    return SYSERR;
  }
  ri = (RequestInsert*) req;
  /* FIXME: if anonymity level is 0, also do 
     DHT insertion! */
  datum = MALLOC(sizeof(Datastore_Value) + 
		 ntohs(req->size) - sizeof(RequestIndex));
  datum->expirationTime = ri->expiration;
  datum->prio = ri->prio;
  datum->anonymityLevel = ri->anonymityLevel;
  datum->type = ri->type;
  if (OK != getQueryFor(ntohl(ri->type),
			ntohs(ri->header.size) - sizeof(RequestInsert),
			(char*)&ri[1],
			&query)) {
    BREAK();
    FREE(datum);
    return SYSERR;
  }
  MUTEX_LOCK(&lock);
  ret = datastore->put(&query,
		       datum);
  MUTEX_UNLOCK(&lock);
  FREE(datum);
  return coreAPI->sendValueToClient(sock, 
				    ret);
}

/**
 * Process a request to index content from the client.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int csHandleRequestIndex(ClientHandle sock,
				const CS_HEADER * req) {
  int ret;
  RequestIndex * ri;
  
  LOG(LOG_DEBUG,
      "Received index request from client\n");
  if (ntohs(req->size) < sizeof(RequestIndex)) {
    BREAK();
    return SYSERR;
  }
  ri = (RequestIndex*) req;
  ret = ONDEMAND_index(datastore,
		       ntohl(ri->prio),
		       ntohll(ri->expiration),
		       ntohll(ri->fileOffset),
		       ntohl(ri->anonymityLevel),
		       &ri->fileId,
		       ntohs(ri->header.size) - sizeof(RequestIndex),
		       &((RequestIndex_GENERIC*)ri)->data[0]);
  LOG(LOG_DEBUG,
      "Sending confirmation of index request to client\n");
  return coreAPI->sendValueToClient(sock,
				    ret);
}

/**
 * If the data portion and type of the value match our value in the
 * closure, copy the header (prio, anonymityLevel, expirationTime) and
 * abort the iteration: we found what we're looing for.  Otherwise
 * continue.
 */
static int completeValue(const HashCode160 * key,
			 const Datastore_Value * value, 
			 void * closure) {
  Datastore_Value * comp = closure;
  
  if ( (comp->size != value->size) ||
       (0 != memcmp(&value[1],
		    &comp[1],
		    ntohl(value->size) - sizeof(Datastore_Value))) )
    return OK;
  *comp = *value; /* make copy! */
  return SYSERR;
}

/**
 * Process a query to delete content.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int csHandleRequestDelete(ClientHandle sock,
				 const CS_HEADER * req) {
  int ret;
  RequestDelete * rd;
  Datastore_Value * value;
  HashCode160 query;
  
  if (ntohs(req->size) < sizeof(RequestDelete)) {
    BREAK();
    return SYSERR;
  }
  rd = (RequestDelete*) req;  
  value = MALLOC(sizeof(Datastore_Value) +
		 ntohs(req->size) - sizeof(RequestDelete));
  value->size = ntohl(sizeof(Datastore_Value) +
		      ntohs(req->size) - sizeof(RequestDelete));
  value->type = rd->type;
  if (OK != getQueryFor(ntohl(rd->type),
			ntohs(rd->header.size) - sizeof(RequestDelete),
			(char*)&rd[1],
			&query)) {
    FREE(value);
    BREAK();
    return SYSERR;
  }
  MUTEX_LOCK(&lock);
  if (SYSERR == datastore->get(&query,
			       ntohl(rd->type),
			       &completeValue,
			       value)) /* aborted == found! */
    ret = datastore->del(&query,
			 value);
  else /* not found */
    ret = SYSERR;
  MUTEX_UNLOCK(&lock);
  FREE(value);
  return coreAPI->sendValueToClient(sock, 
				    ret);
}

/**
 * Process a client request unindex content.
 */
static int csHandleRequestUnindex(ClientHandle sock,
				  const CS_HEADER * req) {
  int ret;
  RequestUnindex * ru;
  
  if (ntohs(req->size) != sizeof(RequestUnindex)) {
    BREAK();
    return SYSERR;
  }
  ru = (RequestUnindex*) req;  
  ret = ONDEMAND_unindex(datastore,
			 ntohl(ru->blocksize),
			 &ru->fileId);
  return coreAPI->sendValueToClient(sock, 
				    ret);
}


/**
 * Process a client request to test if certain
 * data is indexed.
 */
static int csHandleRequestTestIndexed(ClientHandle sock,
				      const CS_HEADER * req) {
  int ret;
  RequestTestindex * ru;
  
  if (ntohs(req->size) != sizeof(RequestTestindex)) {
    BREAK();
    return SYSERR;
  }
  ru = (RequestTestindex*) req;  
  ret = ONDEMAND_testindexed(datastore,
			     &ru->fileId);
  return coreAPI->sendValueToClient(sock, 
				    ret);
}

/**
 * Process a client request to obtain the current
 * averge priority.
 */
static int csHandleRequestGetAvgPriority(ClientHandle sock,
					 const CS_HEADER * req) {
  return coreAPI->sendValueToClient(sock, 
				    0); /* FIXME! */
}

/**
 * Closure for the gapGetConverter method.
 */
typedef struct {
  DataProcessor resultCallback;
  void * resCallbackClosure;
  unsigned int keyCount;
  const HashCode160 * keys;
  int count;
} GGC;

/**
 * Callback that converts the Datastore_Value values
 * from the datastore to Blockstore values for the
 * gap routing protocol.
 */
static int gapGetConverter(const HashCode160 * key,
			   const Datastore_Value * value,
			   void * cls) {
  GGC * ggc = (GGC*) cls;
  GapWrapper * gw;
  int ret;
  unsigned int size;
  cron_t et;

  ret = isDatumApplicable(ntohl(value->type),
			  ntohl(value->size) - sizeof(Datastore_Value),
			  (char*) &value[1],
			  ggc->keyCount,
			  ggc->keys);
  if (ret == SYSERR)
    return SYSERR; /* no query will ever match */
  if (ret == NO)
    return OK; /* Additional filtering based on type;
		  i.e., namespace request and namespace
		  in reply does not match namespace in query */
  size = sizeof(GapWrapper) +
    ntohl(value->size) -
    sizeof(Datastore_Value);
  gw = MALLOC(size);
  gw->dc.size = htonl(size);
  gw->type = value->type;
  et = ntohll(value->expirationTime);
  /* FIMXE: mingle et? */
  gw->timeout = htonll(et);
  memcpy(&gw[1],
	 &value[1],
	 size - sizeof(GapWrapper));
  /* FIXME: check anonymity level,
     if 0, consider using DHT migration instead;
     if high, consider traffic volume before migrating */
  if (ggc->resultCallback != NULL)
    ret = ggc->resultCallback(key,
			      &gw->dc,
			      ggc->resCallbackClosure);
  else
    ret = OK;
  FREE(gw);
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
static int gapGet(void * closure,
		  unsigned int type,
		  unsigned int prio,
		  unsigned int keyCount,
		  const HashCode160 * keys,
		  DataProcessor resultCallback,
		  void * resCallbackClosure) {
  int ret;
  GGC myClosure;

  myClosure.keyCount = keyCount;
  myClosure.keys = keys;
  myClosure.resultCallback = resultCallback;
  myClosure.resCallbackClosure = resCallbackClosure;
  ret = datastore->get(&keys[0],
		       type,
		       &gapGetConverter,
		       &myClosure);
  if (ret != SYSERR)
    ret = myClosure.count; /* return number of actual
			      results (unfiltered) that
			      were found */
  return ret;
}
  
/**
 * Store an item in the datastore.
 *
 * @param key the key of the item
 * @param value the value to store
 * @param prio how much does our routing code value
 *        this datum?
 * @return OK if the value could be stored,
 *         NO if the value verifies but is not stored,
 *         SYSERR if the value is malformed
 */
static int gapPut(void * closure,
		  const HashCode160 * key,
		  unsigned int type,
		  const DataContainer * value,
		  unsigned int prio) {
  Datastore_Value * dv;
  GapWrapper * gw;
  unsigned int size;
  int ret;
  HashCode160 hc;

  if (ntohl(value->size) < sizeof(GapWrapper)) {
    BREAK();
    return SYSERR;
  }
  gw = (GapWrapper*) value;
  size = ntohl(gw->dc.size) 
    - sizeof(GapWrapper) 
    + sizeof(Datastore_Value);
  if ( (type != htonl(gw->type)) ||
       (OK != getQueryFor(type,
			  size - sizeof(Datastore_Value),
			  (char*)&gw[1],
			  &hc)) ||
       (! equalsHashCode160(&hc, key)) ) {
    BREAK(); /* value failed verification! */
    return SYSERR;
  }

  dv = MALLOC(size);
  dv->size = htonl(size);
  dv->type = gw->type;
  dv->prio = htonl(prio);
  dv->anonymityLevel = htonl(0);
  if (ntohll(gw->timeout) > cronTime(NULL) + MAX_MIGRATION_EXP)     
    dv->expirationTime = htonll(cronTime(NULL) + MAX_MIGRATION_EXP);
  else
    dv->expirationTime = gw->timeout;
  memcpy(&dv[1],
	 &gw[1],
	 size - sizeof(Datastore_Value));
  processResponse(key, dv); 
  ret = datastore->putUpdate(key,
			     dv);
  FREE(dv);
  return ret;
}

/**
 * Remove an item from the datastore.
 *
 * @param key the key of the item
 * @param value the value to remove, NULL for all values of the key
 * @return OK if the value could be removed, SYSERR if not (i.e. not present)
 */
static int gapDel(void * closure,
		  const HashCode160 * key,
		  unsigned int type,
		  const DataContainer * value) {
  BREAK(); /* gap does not use 'del'! */
  return SYSERR;
}

/**
 * Iterate over all keys in the local datastore
 *
 * @param processor function to call on each item
 * @param cls argument to processor
 * @return number of results, SYSERR on error
 */
static int gapIterate(void * closure,		 
		      DataProcessor processor,
		      void * cls) {
  BREAK(); /* gap does not use 'iterate' */
  return SYSERR;
}

/**
 * Initialize the FS module. This method name must match
 * the library name (libgnunet_XXX => initialize_XXX).
 *
 * @return SYSERR on errors
 */
int initialize_module_fs(CoreAPIForApplication * capi) {
  static Blockstore dsGap;

  if (getConfigurationInt("AFS",
			  "DISKQUOTA") <= 0) {
    LOG(LOG_ERROR,
	_("You must specify a postive number for '%s' in the configuration in section '%s'.\n"),
	"DISKQUOTA", "AFS");
    return SYSERR;
  }
  datastore = capi->requestService("datastore");
  if (datastore == NULL) {
    BREAK();
    return SYSERR;
  }
  gap = capi->requestService("gap");
  if (gap == NULL) {
    BREAK();
    capi->releaseService(datastore);
    return SYSERR;
  }
  dht = capi->requestService("dht");

  coreAPI = capi;  
  MUTEX_CREATE(&lock);
  dsGap.closure = NULL;
  dsGap.get = &gapGet;
  dsGap.put = &gapPut;
  dsGap.del = &gapDel;
  dsGap.iterate = &gapIterate;
  initQueryManager(capi);
  gap->init(&dsGap);
  
  /* if (dht != NULL) dht->join(&dsDht, &table);*/ 

  LOG(LOG_DEBUG,
      _("'%s' registering client handlers %d %d %d %d %d %d %d %d %d\n"),
      "fs",
      AFS_CS_PROTO_QUERY_START,
      AFS_CS_PROTO_QUERY_STOP,
      AFS_CS_PROTO_RESULT,
      AFS_CS_PROTO_INSERT,
      AFS_CS_PROTO_INDEX,
      AFS_CS_PROTO_DELETE,
      AFS_CS_PROTO_UNINDEX,
      AFS_CS_PROTO_TESTINDEX,
      AFS_CS_PROTO_GET_AVG_PRIORITY);

  GNUNET_ASSERT(SYSERR != capi->registerClientHandler(AFS_CS_PROTO_QUERY_START,
						      &csHandleRequestQueryStart));
  GNUNET_ASSERT(SYSERR != capi->registerClientHandler(AFS_CS_PROTO_QUERY_STOP,
						      &csHandleRequestQueryStop));
  GNUNET_ASSERT(SYSERR != capi->registerClientHandler(AFS_CS_PROTO_INSERT,
						      &csHandleRequestInsert));
  GNUNET_ASSERT(SYSERR != capi->registerClientHandler(AFS_CS_PROTO_INDEX,
						      &csHandleRequestIndex));
  GNUNET_ASSERT(SYSERR != capi->registerClientHandler(AFS_CS_PROTO_DELETE,
						      &csHandleRequestDelete));
  GNUNET_ASSERT(SYSERR != capi->registerClientHandler(AFS_CS_PROTO_UNINDEX,
						      &csHandleRequestUnindex));
  GNUNET_ASSERT(SYSERR != capi->registerClientHandler(AFS_CS_PROTO_TESTINDEX,
						      &csHandleRequestTestIndexed));
  GNUNET_ASSERT(SYSERR != capi->registerClientHandler(AFS_CS_PROTO_GET_AVG_PRIORITY,
						      &csHandleRequestGetAvgPriority));
  initMigration(capi, datastore, gap, dht);
  return OK;
}

void done_module_fs() {
  doneMigration();
  GNUNET_ASSERT(SYSERR != coreAPI->unregisterClientHandler(AFS_CS_PROTO_QUERY_START,
							   &csHandleRequestQueryStart));
  GNUNET_ASSERT(SYSERR != coreAPI->unregisterClientHandler(AFS_CS_PROTO_QUERY_STOP,
							   &csHandleRequestQueryStop));
  GNUNET_ASSERT(SYSERR != coreAPI->unregisterClientHandler(AFS_CS_PROTO_INSERT,
							   &csHandleRequestInsert));
  GNUNET_ASSERT(SYSERR != coreAPI->unregisterClientHandler(AFS_CS_PROTO_INDEX,
							   &csHandleRequestIndex));
  GNUNET_ASSERT(SYSERR != coreAPI->unregisterClientHandler(AFS_CS_PROTO_DELETE,
							   &csHandleRequestDelete));
  GNUNET_ASSERT(SYSERR != coreAPI->unregisterClientHandler(AFS_CS_PROTO_UNINDEX,
							   &csHandleRequestUnindex));
  GNUNET_ASSERT(SYSERR != coreAPI->unregisterClientHandler(AFS_CS_PROTO_TESTINDEX,
							   &csHandleRequestTestIndexed));
  GNUNET_ASSERT(SYSERR != coreAPI->unregisterClientHandler(AFS_CS_PROTO_GET_AVG_PRIORITY,
							   &csHandleRequestGetAvgPriority));
  /* dht->leave(&table, timeout); */  
  doneQueryManager();
  coreAPI->releaseService(datastore);
  datastore = NULL;
  coreAPI->releaseService(gap);
  gap = NULL;
  if (dht != NULL) {
    coreAPI->releaseService(dht);
    dht = NULL;
  }
  coreAPI = NULL;
  MUTEX_DESTROY(&lock);
}

/**
 * Update FS module.
 *
 * @return SYSERR on errors
 */
void update_module_fs(UpdateAPI * uapi) {
  uapi->updateModule("datastore");
}

/* end of fs.c */
