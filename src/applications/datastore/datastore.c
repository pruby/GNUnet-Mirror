/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/datastore/datastore.c
 * @brief This module is responsible to manage content, in particular
 *        it needs to decide what content to keep.  This module
 *        also uses the bloomfilter to reduce get operations on the
 *        database.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"
#include "gnunet_sqstore_service.h"
#include "gnunet_state_service.h"
#include "gnunet_stats_service.h"
#include "filter.h"
#include "prefetch.h"

#define DEBUG_DATASTORE NO

/**
 * SQ-store handle
 */
static SQstore_ServiceAPI * sq;

/**
 * Core API handle.
 */
static CoreAPIForApplication * coreAPI;

/**
 * Minimum priority in the DB.
 */
static unsigned int minPriority;

/**
 * Available space (maybe negative!)
 */
static long long available;

/**
 * Quota from config file.
 */
static unsigned long long quota;

/**
 * Require 1/100th of quota to be 'free' space.
 */
#define MIN_FREE (quota / 100)

static unsigned long long getSize() {
  return sq->getSize();
}

static int fastGet(const HashCode512 * query) {
  return testAvailable(query);
}

static int get(const HashCode512 * query,
	       unsigned int type,
	       Datum_Iterator iter,
	       void * closure) {
  if (! testAvailable(query)) {
#if DEBUG_DATASTORE
    EncName enc;

    IF_GELOG(coreAPI->ectx,
	     GE_DEBUG | GE_REQUEST | GE_USER,
	     hash2enc(query,
		      &enc));
    GE_LOG(coreAPI->ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Datastore availability pre-test failed for `%s'.\n",
	   &enc);
#endif
    return 0;
  }
  return sq->get(query,
		 type,
		 iter,
		 closure);
}

/**
 * Explicitly remove some content from the database.
 */
static int del(const HashCode512 * query,
	       const Datastore_Value * value) {
  int ok;
  EncName enc;

  if (! testAvailable(query)) {
    IF_GELOG(coreAPI->ectx,
	     GE_WARNING | GE_BULK | GE_USER,
	     hash2enc(query,
		      &enc));
    GE_LOG(coreAPI->ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Availability test failed for `%s' at %s:%d.\n"),
	   &enc,
	   __FILE__, __LINE__);
    return 0;
  }
  ok = sq->del(query, value);
  if (ok >= 0) {
    makeUnavailable(query); /* update filter! */
    available += ntohl(value->size);
#if DEBUG_DATASTORE
    IF_GELOG(coreAPI->ectx,
	     GE_DEBUG | GE_REQUEST | GE_USER,
	     hash2enc(query,
		      &enc));
    GE_LOG(coreAPI->ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Deleted `%s' from database.\n",
	   &enc);
#endif
  } else {
    IF_GELOG(coreAPI->ectx,
	     GE_WARNING | GE_BULK | GE_USER,
	     hash2enc(query,
		      &enc));
    GE_LOG(coreAPI->ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Database failed to delete `%s'.\n"),
	   &enc);
  }
  return ok;
}

/**
 * Store an item in the datastore.  If the item is
 * already present, a second copy is created.
 *
 * @return YES on success, NO if the datastore is
 *   full and the priority of the item is not high enough
 *   to justify removing something else, SYSERR on
 *   other serious error (i.e. IO permission denied)
 */
static int put(const HashCode512 * key,
	       const Datastore_Value * value) {
  int ok;

  /* check if we have enough space / priority */
  if (ntohll(value->expirationTime) < get_time()) {
    GE_LOG(coreAPI->ectx,
	   GE_INFO | GE_REQUEST | GE_USER,
	   "Received content for put already expired!\n");
    return NO;
  }
  if ( (available < ntohl(value->size) ) &&
       (minPriority > ntohl(value->prio)) ) {
    GE_LOG(coreAPI->ectx,
	   GE_INFO | GE_REQUEST | GE_USER,
	   "Datastore full (%llu/%llu) and content priority too low to kick out other content.  Refusing put.\n",
	   sq->getSize(),
	   quota);
    return SYSERR; /* new content has such a low priority that
		      we should not even bother! */
  }
  if (ntohl(value->prio) < minPriority)
    minPriority = ntohl(value->prio);

  /* add the content */
  ok = sq->put(key,
	       value);
  if (ok == YES) {
    makeAvailable(key);
    available -= ntohl(value->size);
  }
  return ok;
}

typedef struct {
  int exists;
  const Datastore_Value * value;
  Datastore_Value * existing;
} CE;

static int checkExists(const HashCode512 * key,
		       const Datastore_Value * value,
		       void * cls) {
  CE * ce = cls;

  if ( (value->size != ce->value->size) ||
       (0 != memcmp(&value[1],
		    &ce->value[1],
		    ntohl(value->size) - sizeof(Datastore_Value))) )
    return OK; /* found another value, but different content! */
  ce->existing = MALLOC(ntohl(value->size));
  memcpy(ce->existing,
	 value,
	 ntohl(value->size));
  ce->exists = YES;
  return SYSERR; /* abort iteration! */
}

/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities are summed up and the higher expiration time and
 * lower anonymity level is used.
 *
 * @return YES on success, NO if the datastore is
 *   full and the priority of the item is not high enough
 *   to justify removing something else, SYSERR on
 *   other serious error (i.e. IO permission denied)
 */
static int putUpdate(const HashCode512 * key,
		     const Datastore_Value * value) {
  CE cls;
  int ok;

  /* check if it already exists... */
  cls.exists = NO;
  cls.existing = NULL;
  cls.value = value;
  sq->get(key,
	  ntohl(value->type),
	  &checkExists,
	  &cls);
  if (ntohl(value->type) == D_BLOCK)
    sq->get(key,
	    ONDEMAND_BLOCK,
	    &checkExists,
	    &cls);

  if (cls.exists) {
    if ( (ntohl(value->prio) == 0) &&
	 (ntohll(value->expirationTime) <= ntohll(cls.existing->expirationTime)) ) {
      FREE(cls.existing);
      return OK;
    }
    /* update prio */
    sq->update(key,
	       cls.existing,
	       ntohl(value->prio),
	       ntohll(value->expirationTime));
    FREE(cls.existing);
    return OK;
  }
#if DEBUG_DATASTORE
  GE_LOG(coreAPI->ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Migration: available %llu (need %u), min priority %u have %u\n",
	 available,
	 ntohl(value->size),
	 minPriority,
	 ntohl(value->prio));
#endif
  /* check if we have enough space / priority */
  if ( (available < ntohl(value->size) ) &&
       (minPriority > ntohl(value->prio)) )
    return NO; /* new content has such a low priority that
		  we should not even bother! */
  if (ntohl(value->prio) < minPriority)
    minPriority = ntohl(value->prio);

  /* add the content */
  ok = sq->put(key,
	       value);
  if (ok == YES) {
    makeAvailable(key);
    available -= ntohl(value->size);
  }
  return ok;
}

/**
 * @return *closure if we are below quota,
 *         SYSERR if we have deleted all of the expired content
 *         OK if we deleted expired content and are above quota
 */
static int freeSpaceExpired(const HashCode512 * key,
			    const Datastore_Value * value,
			    void * closure) {
  int * icls = closure;
  int ret;

  if (get_time() < ntohll(value->expirationTime))
    return SYSERR; /* not expired */
  ret = sq->del(key, value);
  if (ret != SYSERR)
    available += ntohl(value->size);
  if ( (available > 0) &&
       (available >= MIN_FREE) )
    return *icls;
  return OK;
}

static int freeSpaceLow(const HashCode512 * key,
			const Datastore_Value * value,
			void * closure) {
  int ret;

  minPriority = ntohl(value->prio);
  ret = sq->del(key, value);
  if (ret != SYSERR)
    available +=  ntohl(value->size);
  if ( (available > 0) &&
       (available >= MIN_FREE) )
    return SYSERR;
  return OK;
}

/**
 * Cron-job that deletes low-priority/expired content
 * if we are about to run out of space.
 *
 * Also updates available and minPriority.
 */
static void cronMaintenance(void * unused) {
  int syserr = SYSERR;

  available = quota - sq->getSize();
  if ( (available < 0) ||
       (available < MIN_FREE) ) {
    sq->iterateExpirationTime(ANY_BLOCK,
			      &freeSpaceExpired,
			      &syserr);
    if ( (available < 0) ||
	 (available < MIN_FREE) ) {
      sq->iterateLowPriority(ANY_BLOCK,
			     &freeSpaceLow,
			     NULL);
    }
  } else {
    minPriority = 0;
  }
}

/**
 * Initialize the manager-module.
 */
Datastore_ServiceAPI *
provide_module_datastore(CoreAPIForApplication * capi) {
  static Datastore_ServiceAPI api;
  unsigned long long lquota;
  unsigned int sqot;
  State_ServiceAPI * state;
  Stats_ServiceAPI * stats;

  if (-1 == GC_get_configuration_value_number(capi->cfg,
					      "FS",
					      "QUOTA",
					      0,
					      ((unsigned long long)-1)/1024/1024,
					      1024,
					      &lquota)) {
    GE_BREAK(capi->ectx, 0);
    return NULL; /* OOPS */
  }
  quota
    = lquota * 1024 * 1024; /* MB to bytes */
  stats = capi->requestService("stats");
  if (stats != NULL) {
    stats->set(stats->create(gettext_noop("# bytes allowed in datastore")),
	       quota);
    capi->releaseService(stats);
  }
  state = capi->requestService("state");
  if (state != NULL) {
    sqot = htonl(lquota);
    state->write(capi->ectx,
		 "FS-LAST-QUOTA",
		 sizeof(unsigned int),
		 &sqot);
    capi->releaseService(state);
  } else {
    GE_LOG(capi->ectx,
	   GE_USER | GE_ADMIN | GE_ERROR | GE_BULK,
	   _("Failed to load state service. Trying to do without.\n"));
  }
  sq = capi->requestService("sqstore");
  if (sq == NULL) {
    GE_BREAK(capi->ectx, 0);
    return NULL;
  }
  coreAPI = capi;
  initPrefetch(capi->ectx,
	       capi->cfg,
	       sq);
  if (OK != initFilters(capi->ectx,
			capi->cfg)) {
    GE_BREAK(capi->ectx, 0);
    donePrefetch();
    capi->releaseService(sq);
    return NULL;
  }
  available = quota - sq->getSize();
  cron_add_job(capi->cron,
	       &cronMaintenance,
	       10 * cronSECONDS,
	       10 * cronSECONDS,
	       NULL);
  api.getSize = &getSize;
  api.put = &put;
  api.fast_get = &fastGet;
  api.putUpdate = &putUpdate;
  api.get = &get;
  api.getRandom = &getRandom; /* in prefetch.c */
  api.del = &del;

  return &api;
}

/**
 * Shutdown the manager module.
 */
void release_module_datastore() {
  cron_del_job(coreAPI->cron,
	       &cronMaintenance,
	       10 * cronSECONDS,
	       NULL);
  donePrefetch();
  doneFilters();
  coreAPI->releaseService(sq);
  sq = NULL;
  coreAPI = NULL;
}

/**
 * Callback that adds all element of the SQStore to the
 * bloomfilter.
 */
static int filterAddAll(const HashCode512 * key,
			const Datastore_Value * value,
			void * closure) {
  makeAvailable(key);
  return OK;
}

/**
 * Update Datastore.  Currently only re-builds the bloomfilter.
 * At some point we'll want to add code to convert data between
 * different sqstore's here, too.
 */
void update_module_datastore(UpdateAPI * uapi) {
  unsigned long long quota;
  unsigned int lastQuota;
  int * lq;
  State_ServiceAPI * state;

  if (-1 == GC_get_configuration_value_number(uapi->cfg,
					      "FS",
					      "QUOTA",
					      0,
					      ((unsigned long long)-1)/1024/1024,
					      1024,
					      &quota))
    return; /* OOPS */
  state = uapi->requestService("state");
  if (state != NULL) {
    lq = NULL;
    if (sizeof(int) != state->read(uapi->ectx,
				   "FS-LAST-QUOTA",
				   (void**)&lq)) {
      uapi->releaseService(state);
      return; /* first start? */
    }
    uapi->releaseService(state);
    lastQuota = ntohl(*lq);
    FREE(lq);
    if (lastQuota == quota)
      return; /* unchanged */
  } else {
    GE_LOG(uapi->ectx,
	   GE_USER | GE_ADMIN | GE_ERROR | GE_BULK,
	   _("Failed to load state service. Trying to do without.\n"));
  }

  /* ok, need to convert! */
  deleteFilter(uapi->ectx,
	       uapi->cfg);
  initFilters(uapi->ectx,
	      uapi->cfg);
  sq = uapi->requestService("sqstore");
  sq->get(NULL,
	  ANY_BLOCK,
	  &filterAddAll,
	  NULL);
  uapi->releaseService(sq);
  sq = NULL;
  doneFilters();
}


/* end of datastore.c */
