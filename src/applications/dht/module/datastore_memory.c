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
 * @file applications/dht/module/datastore_memory.c
 * @brief provides the implementation of the 
 * DHT_Datastore API for keeping the table data in memory.
 * @author Simo Viitanen, Christian Grothoff
 */

#include "gnunet_dht_datastore_memory.h"
#include "gnunet_core.h"
#include "platform.h"

/**
 * @brief datastructure for one entry in the table. 
 */ 
typedef struct HT_Entry_t {
  struct HT_Entry_t * next;
  HashCode160 key;
  unsigned int count;
  DHT_DataContainer * values;
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
static int lookup(void * closure,
		  const HashCode160 * key,
		  unsigned int maxResults,
		  DHT_DataContainer * results) {
  MemoryDatastore * ds = (MemoryDatastore*) closure;
  HT_Entry * pos;
  int count;
  int i;

  if (ds == NULL)
    return SYSERR;
  MUTEX_LOCK(&ds->lock);
  pos = ds->first;
  while (pos != NULL) {
    if (equalsHashCode160(key, &pos->key)) {
      if (pos->count > maxResults)
	count = maxResults;
      else
	count = pos->count;
      for (i=0;i<count;i++) {
	if (results[i].dataLength > 0) {
	  if (results[i].dataLength > pos->values[i].dataLength)
	    results[i].dataLength = pos->values[i].dataLength;
	  memcpy(results[i].data,
		 pos->values[i].data,
		 results[i].dataLength);
	} else {
	  results[i].dataLength = pos->values[i].dataLength;
	  results[i].data = MALLOC(results[i].dataLength);
	  memcpy(results[i].data,
		 pos->values[i].data,
		 results[i].dataLength);
	}
      }
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
 * @param value the value to store
 *  for other entries under the same key (if key already exists)
 * @return OK if the value could be stored, DHT_ERRORCODE or SYSERR if not (i.e. out of space)
 */
static int store(void * closure,
		 const HashCode160 * key,
		 const DHT_DataContainer * value) {
  MemoryDatastore * ds = (MemoryDatastore*) closure;
  HT_Entry * pos;
  if (ds == NULL)
    return SYSERR;

  MUTEX_LOCK(&ds->lock);
  pos = ds->first;
  while (pos != NULL) {
    if (equalsHashCode160(key, &pos->key)) {
      if (ds->max_memory + pos->values[0].dataLength < 
	  value->dataLength) {
	MUTEX_UNLOCK(&ds->lock);
	return DHT_ERRORCODES__OUT_OF_SPACE;	
      }
      ds->max_memory -= value->dataLength - pos->values[0].dataLength;
      FREE(pos->values[0].data);
      pos->values[0].data = MALLOC(value->dataLength);
      memcpy(pos->values[0].data,
	     value->data,
	     value->dataLength);
      MUTEX_UNLOCK(&ds->lock);  
      return OK;
    } /* end key match */
    pos = pos->next;
  }
  /* no key matched, create fresh entry */
  if (ds->max_memory < sizeof(HT_Entry) + sizeof(DHT_DataContainer) + value->dataLength) {
    MUTEX_UNLOCK(&ds->lock);
    return DHT_ERRORCODES__OUT_OF_SPACE;
  }
  ds->max_memory -= sizeof(HT_Entry) + sizeof(DHT_DataContainer) + value->dataLength;

  pos = MALLOC(sizeof(HT_Entry));
  pos->key = *key;
  pos->count = 1;
  pos->values = MALLOC(sizeof(DHT_DataContainer));
  pos->values[0].dataLength = value->dataLength;
  pos->values[0].data = MALLOC(value->dataLength);
  memcpy(pos->values[0].data,
	 value->data,
	 value->dataLength);
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
		     const HashCode160 * key,
		     const DHT_DataContainer * value) {
  MemoryDatastore * ds = (MemoryDatastore*) closure;
  HT_Entry * pos;
  HT_Entry * prev;
  int i;
  if (ds == NULL)
    return SYSERR;

  MUTEX_LOCK(&ds->lock);
  prev = NULL;
  pos = ds->first;
  while (pos != NULL) {
    if (equalsHashCode160(key, &pos->key)) {
      if (value != NULL) {
	for (i=0;i<pos->count;i++) {
	  if ( (pos->values[i].dataLength == value->dataLength) &&
	       (0 == memcmp(pos->values[i].data,
			    value->data,
			    value->dataLength)) ) {
	    FREE(pos->values[i].data);
	    ds->max_memory += value->dataLength;
	    pos->values[i] = pos->values[pos->count-1];
	    GROW(pos->values,
		 pos->count,
		 pos->count-1);
	    ds->max_memory += sizeof(DHT_DataContainer);
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
	
	for (i=0;i<pos->count;i++) {
	  FREE(pos->values[i].data);
	  ds->max_memory += pos->values[i].dataLength;
	}
	ds->max_memory += pos->count * sizeof(DHT_DataContainer);
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
		   DHT_DataProcessor processor,
		   void * cls) {
  MemoryDatastore * ds = (MemoryDatastore*) closure;
  int ret;
  HT_Entry * pos;
  int i;

  if (ds == NULL)
    return SYSERR;

  MUTEX_LOCK(&ds->lock);
  pos = ds->first;
  ret = 0;
  while (pos != NULL) {
    for (i=0;i<pos->count;i++) {
      ret++;
      if (processor != NULL)
	if (OK != processor(&pos->key,
			    &pos->values[i],
			    cls)) {
	  MUTEX_UNLOCK(&ds->lock);
	  return ret;
	}
    }
    pos = pos->next;
  }
  MUTEX_UNLOCK(&ds->lock);
  return SYSERR;
}

/**
 * Create a DHT Datastore (in memory)
 * @param max_memory do not use more than max_memory memory.
 */
DHT_Datastore * create_datastore_memory(size_t max_memory) {
  DHT_Datastore * res;
  MemoryDatastore * md;

  md = MALLOC(sizeof(MemoryDatastore));
  md->max_memory = max_memory;
  md->first = NULL;
  MUTEX_CREATE_RECURSIVE(&md->lock);

  res = MALLOC(sizeof(DHT_Datastore));
  res->lookup = &lookup;
  res->store = &store;
  res->remove = &ds_remove;
  res->iterate = &iterate;
  res->closure = md;
  return res;
}

/**
 * Destroy a DHT Datastore (in memory)
 * @param ds the Datastore to destroy; must have been
 *  created by create_datastore_memory.
 */
void destroy_datastore_memory(DHT_Datastore * ds) {
  MemoryDatastore * md;
  HT_Entry * pos;
  HT_Entry * next;
  unsigned int i;

  md  = ds->closure;
  pos = md->first;
  while (pos != NULL) {
    next = pos->next;
    for (i=0;i<pos->count;i++) 
      FREENONNULL(pos->values[i].data);    
    FREE(pos->values);
    FREE(pos);
    pos = next;
  }
  MUTEX_DESTROY(&md->lock);
  FREE(md);
  FREE(ds);
}

/* end of datastore_memory.c */
