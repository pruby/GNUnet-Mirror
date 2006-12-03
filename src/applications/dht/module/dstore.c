/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file module/dstore.c
 * @brief entries in local DHT
 * @author Simo Viitanen, Christian Grothoff
 *
 * TODO:
 * - store should automatically delete
 *   oldest content when full
 * - use SQL-based database instead of
 *   in-memory database
 */

#include "platform.h"
#include "dstore.h"


/**
 * @brief datastructure for one entry in the table.
 */
typedef struct HT_Entry_t {
  struct HT_Entry_t * next;
  HashCode512 key;
  unsigned int count;
  DataContainer ** values;
} HT_Entry;

/**
 * @brief the per-table data
 */
typedef struct {
  struct MUTEX * lock;
  size_t max_memory;
  HT_Entry * first;
} MemoryDatastore;


/**
 * Lookup an item in the datastore.
 *
 * @param key the value to lookup
 * @param maxResults maximum number of results
 * @param results where to store the result; must point to
 *        an array of maxResuls containers; if the containers
 *        point to allocated memory, it will be used by lookup;
 *        otherwise lookup will allocate the data pointer;
 *        in either case dataLength is adjusted to the actual
 *        size of the data.  If not enough space is present to
 *        accomodate the data the data will be truncated.
 * @return number of results, SYSERR on error
 */
static int ds_lookup(void * closure,
		     unsigned int type,
		     unsigned int prio,
		     unsigned int keyCount,
		     const HashCode512 * keys,
		     DataProcessor resultCallback,
		     void * resCallbackClosure) {
  MemoryDatastore * ds = (MemoryDatastore*) closure;
  HT_Entry * pos;
  int i;

  if ( (ds == NULL) || (keyCount != 1) )
    return SYSERR;
  MUTEX_LOCK(ds->lock);
  pos = ds->first;
  while (pos != NULL) {
    if (0 == memcmp(&keys[0],
		    &pos->key,
		    sizeof(HashCode512))) {
      for (i=0;i<pos->count;i++)
	if (OK != resultCallback(&pos->key,
				 pos->values[i],
				 resCallbackClosure)) {
	  MUTEX_UNLOCK(ds->lock);
	  return SYSERR;
	}
      MUTEX_UNLOCK(ds->lock);
      return pos->count;
    }
    pos = pos->next;
  }
  MUTEX_UNLOCK(ds->lock);
  return 0;
}

/**
 * Store an item in the datastore.
 *
 * @param key the key of the item
 * @param value the value to store
 *  for other entries under the same key (if key already exists)
 * @return OK if the value could be stored, DHT_ERRORCODE or SYSERR if not (i.e. out of space)
 */
static int ds_store(void * closure,
		    const HashCode512 * key,
		    const DataContainer * value,
		    unsigned int prio) {
  MemoryDatastore * ds = closure;
  HT_Entry * pos;
  unsigned int size;

  if (ds == NULL)
    return SYSERR;

  size = ntohl(value->size);
  MUTEX_LOCK(ds->lock);
  pos = ds->first;
  while (pos != NULL) {
    if (0 == memcmp(key,
		    &pos->key,
		    sizeof(HashCode512))) {
      if (ds->max_memory < size) {
	MUTEX_UNLOCK(ds->lock);
	return NO;
      }
      ds->max_memory -= size;
      GROW(pos->values,
	   pos->count,
	   pos->count+1);
      pos->values[pos->count-1]
	= MALLOC(size);
      memcpy(pos->values[pos->count-1],
	     value,
	     size);
      MUTEX_UNLOCK(ds->lock);
      return OK;
    } /* end key match */
    pos = pos->next;
  }
  /* no key matched, create fresh entry */
  if (ds->max_memory < sizeof(HT_Entry) + size) {
    MUTEX_UNLOCK(ds->lock);
    return NO;
  }
  ds->max_memory -= sizeof(HT_Entry) + size;
  pos = MALLOC(sizeof(HT_Entry));
  pos->key = *key;
  pos->count = 1;
  pos->values = MALLOC(sizeof(DataContainer*));
  pos->values[0] = MALLOC(size);
  memcpy(pos->values[0],
	 value,
	 size);
  pos->next = ds->first;
  ds->first = pos;
  MUTEX_UNLOCK(ds->lock);
  return OK;
}



/**
 * Remove an item from the datastore.
 *
 * @param key the key of the item
 * @param value the value to remove, NULL for all values of the key
 * @return OK if the value could be removed, SYSERR if not (i.e. not present)
 */
static int ds_remove(void * closure,
		     const HashCode512 * key,
		     const DataContainer * value) {
  MemoryDatastore * ds = closure;
  HT_Entry * pos;
  HT_Entry * prev;
  int i;
  unsigned int size;

  if (ds == NULL)
    return SYSERR;
  size = ntohl(value->size);
  MUTEX_LOCK(ds->lock);
  prev = NULL;
  pos = ds->first;
  while (pos != NULL) {
    if (0 == memcmp(key,
		    &pos->key,
		    sizeof(HashCode512))) {
      if (value != NULL) {
	for (i=0;i<pos->count;i++) {
	  if ( (pos->values[i]->size == value->size) &&
	       (0 == memcmp(pos->values[i],
			    value,
			    size)) ) {
	    FREE(pos->values[i]);
	    ds->max_memory += size;
	    pos->values[i] = pos->values[pos->count-1];
	    GROW(pos->values,
		 pos->count,
		 pos->count-1);
	    if (pos->count == 0) {
	      if (prev == NULL)
		ds->first = pos->next;
	      else
		prev->next = pos->next;
	      FREE(pos);
	      ds->max_memory += sizeof(HT_Entry);	
	    }
	    MUTEX_UNLOCK(ds->lock);
	    return OK;
	  }
	}
      } else {
	/* remove entire link */
	if (prev == NULL)
	  ds->first = pos->next;
	else
	  prev->next = pos->next;
	
	for (i=0;i<pos->count;i++) {
	  ds->max_memory += ntohl(pos->values[i]->size);
	  FREE(pos->values[i]);
	}
	GROW(pos->values,
	     pos->count,
	     0);
	FREE(pos);
	ds->max_memory += sizeof(HT_Entry);
      }
      MUTEX_UNLOCK(ds->lock);
      return OK;
    }
    prev = pos;
    pos = pos->next;
  }
  MUTEX_UNLOCK(ds->lock);
  return SYSERR; /* not found */
}

/**
 * Iterate over all keys in the local datastore
 *
 * @param processor function to call on each item
 * @param cls argument to processor
 * @return number of results, SYSERR on error
 */
static int ds_iterate(void * closure,		
		      DataProcessor processor,
		      void * cls) {
  MemoryDatastore * ds = closure;
  int ret;
  HT_Entry * pos;
  int i;

  if (ds == NULL)
    return SYSERR;

  MUTEX_LOCK(ds->lock);
  pos = ds->first;
  ret = 0;
  while (pos != NULL) {
    for (i=0;i<pos->count;i++) {
      ret++;
      if (processor != NULL)
	if (OK != processor(&pos->key,
			    pos->values[i],
			    cls)) {
	  MUTEX_UNLOCK(ds->lock);
	  return ret;
	}
    }
    pos = pos->next;
  }
  MUTEX_UNLOCK(ds->lock);
  return SYSERR;
}
  
/**
 * Initialize dstore DHT component.
 *
 * @param capi the core API
 * @return OK on success
 */
Blockstore * init_dht_store(size_t max_size,
			    CoreAPIForApplication * capi) {
  Blockstore * res;
  MemoryDatastore * md;

  md = MALLOC(sizeof(MemoryDatastore));
  md->max_memory = max_size;
  md->first = NULL;
  md->lock = MUTEX_CREATE(YES);
  res = MALLOC(sizeof(Blockstore));
  res->get = &ds_lookup;
  res->put = &ds_store;
  res->del = &ds_remove;
  res->iterate = &ds_iterate;
  res->closure = md;
  return res;
}

/**
 * Shutdown dstore DHT component.
 *
 * @return OK on success
 */
int done_dht_store(Blockstore * ds) {
  MemoryDatastore * md;
  HT_Entry * pos;
  HT_Entry * next;
  unsigned int i;

  md  = ds->closure;
  pos = md->first;
  while (pos != NULL) {
    next = pos->next;
    for (i=0;i<pos->count;i++)
      FREENONNULL(pos->values[i]);
    FREE(pos->values);
    FREE(pos);
    pos = next;
  }
  MUTEX_DESTROY(md->lock);
  FREE(md);
  FREE(ds);
  return OK;
}

