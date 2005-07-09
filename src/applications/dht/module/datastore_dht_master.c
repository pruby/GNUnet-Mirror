 /*
      This file is part of GNUnet

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
 * @file applications/dht/module/datastore_dht_master.c
 * @brief provides the implementation of the
 * Blockstore API for the DHT master table; based on
 * datastore_memory.c.
 * @author Simo Viitanen, Christian Grothoff
 *
 *
 * The main difference between this datastore and the default
 * memory-datastore is that entries have a timestamp and are
 * timed-out after a certain time of inactivity.  Also,
 * duplicate entries are removed.<p>
 *
 * The priorities are ignored, except in get where
 * the priority is the maximum number of results to return.
 * The number of keys specified in a GET must always be one.
 */

#include "platform.h"

#include "gnunet_core.h"
#include "datastore_dht_master.h"

typedef struct {
  HashCode512 hash;
  cron_t lastRefreshTime;
} MasterEntry;

/**
 * @brief datastructure for one entry in the table.
 */
typedef struct HT_Entry_t {
  struct HT_Entry_t * next;
  HashCode512 key;
  unsigned int count;
  MasterEntry * values;
} HT_Entry;

/**
 * @brief the per-table data
 */
typedef struct {
  Mutex lock;
  size_t max_memory;
  HT_Entry * first;
} MemoryDatastore;


/**
 * Lookup an item in the datastore.
 *
 * @param key the value to lookup
 * @param prio is interpreted as the maximum number
 *  of results to return
 * @return number of results available, SYSERR on error
 */
static int lookup(void * closure,
		  unsigned int type,
		  unsigned int prio,
		  unsigned int keyCount,
		  const HashCode512 * keys,
		  DataProcessor resultCallback,
		  void * resCallbackClosure) {
  MemoryDatastore * ds = (MemoryDatastore*) closure;
  HT_Entry * pos;
  int count;
  int i;
  DataContainer * data;

  GNUNET_ASSERT(keyCount == 1);
  if (ds == NULL)
    return SYSERR;
  MUTEX_LOCK(&ds->lock);
  pos = ds->first;
  while (pos != NULL) {
    if (equalsHashCode512(&keys[0], &pos->key)) {
      int * perm;

      if (pos->count > prio)
	count = prio;
      else
	count = pos->count;
      if (count < pos->count)
	perm = permute(WEAK, pos->count); /* randomize returned set! */
      else
	perm = NULL;

      for (i=0;i<count;i++) {
	int j;
	if (perm == NULL)
	  j = i;
	else
	  j = perm[i];
	data = MALLOC(sizeof(DataContainer) +
		      sizeof(HashCode512));
	data->size = htonl(sizeof(DataContainer) +
			   sizeof(HashCode512));
	memcpy(&data[1],
	       &pos->values[j].hash,
	       sizeof(HashCode512));	
	resultCallback(NULL,
		       data,
		       resCallbackClosure);
	FREE(data);
      }
      FREENONNULL(perm);
      MUTEX_UNLOCK(&ds->lock);
      return count;
    }
    pos = pos->next;
  }
  MUTEX_UNLOCK(&ds->lock);
  return 0;
}

/**
 * Store an item in the datastore.
 *
 * @param key the key of the item
 * @param value the value to store, must be of size HashCode512 for
 *        the master table!
 * @return OK if the value could be stored, SYSERR if not,
 *         NO for out of space)
 */
static int store(void * closure,
		 const HashCode512 * key,
		 const DataContainer * value,
		 unsigned int prio) {
  MemoryDatastore * ds = (MemoryDatastore*) closure;
  HT_Entry * pos;
  int i;

  if ( (ds == NULL) || (value == NULL) )
    return SYSERR;
  if (ntohl(value->size) - sizeof(DataContainer)
      != sizeof(HashCode512))
    return SYSERR;

  MUTEX_LOCK(&ds->lock);
  pos = ds->first;
  while (pos != NULL) {
    if (equalsHashCode512(key, &pos->key)) {
      for (i=0;i<pos->count;i++)
	if (equalsHashCode512(&pos->values[i].hash,
			      (HashCode512*)&value[1])) {
	  pos->values[i].lastRefreshTime = cronTime(NULL);
	  MUTEX_UNLOCK(&ds->lock);
	  return OK; /* already present */
	}
      if (ds->max_memory < sizeof(MasterEntry)) {
	MUTEX_UNLOCK(&ds->lock);
	return NO;
      }
      ds->max_memory -= sizeof(MasterEntry);
      GROW(pos->values,
	   pos->count,
	   pos->count+1);
      pos->values[pos->count-1].lastRefreshTime = cronTime(NULL);
      memcpy(&pos->values[pos->count-1].hash,
	     &value[1],
	     sizeof(HashCode512));
      MUTEX_UNLOCK(&ds->lock);
      return OK;
    } /* end key match */
    pos = pos->next;
  }
  /* no key matched, create fresh entry */
  if (ds->max_memory < sizeof(HT_Entry) + sizeof(MasterEntry)) {
    MUTEX_UNLOCK(&ds->lock);
    return NO;
  }
  ds->max_memory -= sizeof(HT_Entry) + sizeof(MasterEntry);
  pos = MALLOC(sizeof(HT_Entry));
  pos->key = *key;
  pos->count = 1;
  pos->values = MALLOC(sizeof(MasterEntry));
  memcpy(&pos->values[0].hash,
	 &value[1],
	 sizeof(HashCode512));
  pos->values[0].lastRefreshTime = cronTime(NULL);
  pos->next = ds->first;
  ds->first = pos;
  MUTEX_UNLOCK(&ds->lock);
  return OK;
}

/**
 * Remove an item from the datastore.
 * @param key the key of the item
 * @param value the value to remove, NULL for all values of the key
 * @return OK if the value could be removed, SYSERR if not (i.e. not present)
 */
static int ds_remove(void * closure,
		     const HashCode512 * key,
		     const DataContainer * value) {
  MemoryDatastore * ds = (MemoryDatastore*) closure;
  HT_Entry * pos;
  HT_Entry * prev;
  int i;

  if (ds == NULL)
    return SYSERR;
  if ( (value != NULL) &&
       (ntohl(value->size) - sizeof(DataContainer)
	!= sizeof(HashCode512)) )
    return SYSERR;

  MUTEX_LOCK(&ds->lock);
  prev = NULL;
  pos = ds->first;
  while (pos != NULL) {
    if (equalsHashCode512(key, &pos->key)) {
      if (value != NULL) {
	for (i=0;i<pos->count;i++) {
	  if (0 == memcmp(&pos->values[i].hash,
			  &value[1],
			  sizeof(HashCode512))) {
	    pos->values[i] = pos->values[pos->count-1];
	    GROW(pos->values,
		 pos->count,
		 pos->count-1);
	    ds->max_memory += sizeof(MasterEntry);
	    if (pos->count == 0) {
	      if (prev == NULL)
		ds->first = pos->next;
	      else
		prev->next = pos->next;
	      FREE(pos);
	      ds->max_memory += sizeof(HT_Entry);	
	    }
	    MUTEX_UNLOCK(&ds->lock);
	    return OK;
	  }
	}
      } else {
	/* remove entire link */
	if (prev == NULL)
	  ds->first = pos->next;
	else
	  prev->next = pos->next;
	
	ds->max_memory += pos->count * sizeof(MasterEntry);
	GROW(pos->values,
	     pos->count,
	     0);
	FREE(pos);
	ds->max_memory += sizeof(HT_Entry);
      }
      MUTEX_UNLOCK(&ds->lock);
      return OK;
    }
    prev = pos;
    pos = pos->next;
  }
  MUTEX_UNLOCK(&ds->lock);
  return SYSERR; /* not found */
}

/**
 * Iterate over all keys in the local datastore
 *
 * @param processor function to call on each item
 * @param cls argument to processor
 * @return number of results, SYSERR on error
 */
static int iterate(void * closure,		
		   DataProcessor processor,
		   void * cls) {
  MemoryDatastore * ds = (MemoryDatastore*) closure;
  int ret;
  HT_Entry * pos;
  int i;
  DataContainer * cont;

  if (ds == NULL)
    return SYSERR;

  MUTEX_LOCK(&ds->lock);
  pos = ds->first;
  ret = 0;
  cont = MALLOC(sizeof(HashCode512) + sizeof(DataContainer));
  cont->size = htonl(sizeof(HashCode512) + sizeof(DataContainer));
  while (pos != NULL) {
    for (i=0;i<pos->count;i++) {
      ret++;
      if (processor != NULL) {
	memcpy(&cont[1],
	       &pos->values[i].hash,
	       sizeof(HashCode512));
	if (OK != processor(&pos->key,
			    cont,
			    cls)) {
	  MUTEX_UNLOCK(&ds->lock);
	  FREE(cont);
	  return ret;
	}
      }
    }
    pos = pos->next;
  }
  MUTEX_UNLOCK(&ds->lock);
  FREE(cont);
  return SYSERR;
}

static void expirationJob(MemoryDatastore * store) {
  HT_Entry * pos;
  HT_Entry * prev;
  int i;
  cron_t now;

  prev = NULL;
  MUTEX_LOCK(&store->lock);
  cronTime(&now);
  pos = store->first;
  while (pos != NULL) {
    for (i=pos->count-1;i>=0;i--) {
      if (pos->values[i].lastRefreshTime + 15 * cronMINUTES < now) {
	pos->values[i] = pos->values[pos->count-1];
	GROW(pos->values,
	     pos->count,
	     pos->count-1);
	store->max_memory += sizeof(MasterEntry);
      }
    }
    if (pos->count == 0) {
      if (prev == NULL)
	store->first = pos->next;
      else
	prev->next = pos->next;
      pos = pos->next;
      FREE(pos);
      store->max_memory += sizeof(HT_Entry);
      continue;
    }
    prev = pos;
    pos = pos->next;
  }
  MUTEX_UNLOCK(&store->lock);
}

/**
 * Create a DHT Datastore (in memory)
 * @param max_memory do not use more than max_memory memory.
 */
Blockstore * create_datastore_dht_master(size_t max_memory) {
  Blockstore * res;
  MemoryDatastore * md;

  md = MALLOC(sizeof(MemoryDatastore));
  md->max_memory = max_memory;
  md->first = NULL;
  MUTEX_CREATE_RECURSIVE(&md->lock);

  res = MALLOC(sizeof(Blockstore));
  res->get  = &lookup;
  res->put   = &store;
  res->del  = &ds_remove;
  res->iterate = &iterate;
  res->closure = md;
  addCronJob((CronJob) &expirationJob,
	     5 * cronMINUTES,
	     5 * cronMINUTES,
	     md);
  return res;
}

/**
 * Destroy a DHT Datastore (in memory)
 * @param ds the Datastore to destroy; must have been
 *  created by create_datastore_memory.
 */
void destroy_datastore_dht_master(Blockstore * ds) {
  MemoryDatastore * md;
  HT_Entry * pos;
  HT_Entry * next;
  int icr;

  md  = ds->closure;
  icr = isCronRunning();
  if (icr)
    suspendCron();
  delCronJob((CronJob) &expirationJob,
	     5 * cronMINUTES,
	     md);
  if (icr)
    resumeCron();

  pos = md->first;
  while (pos != NULL) {
    next = pos->next;
    GROW(pos->values,
	 pos->count,
	 0);
    FREE(pos);
    pos = next;
  }
  MUTEX_DESTROY(&md->lock);
  FREE(md);
  FREE(ds);
}

/* end of datastore_dht_master.c */
