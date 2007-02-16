/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/datastore/prefetch.c
 * @brief This module is responsible for prefetching
 *   content that can be pushed out into the network
 * @author Christian Grothoff, Igor Wronsky
 */

#include "platform.h"
#include "prefetch.h"
#include "gnunet_protocols.h"

#define DEBUG_PREFETCH NO

/* use a 64-entry RCB buffer */
#define RCB_SIZE 64

/* how many blocks to cache from on-demand files in a row */
#define RCB_ONDEMAND_MAX 16

/**
 * Buffer with pre-fetched, encoded random content for migration.
 */
typedef struct {

  HashCode512 key;

  Datastore_Value * value;
  /**
   * 0 if we have never used this content with any peer.  Otherwise
   * the value is set to the lowest 32 bit of the peer ID (to avoid
   * sending it to the same peer twice).  After sending out the
   * content twice, it is discarded.
   */
  int used;
} ContentBuffer;


static ContentBuffer randomContentBuffer[RCB_SIZE];

/**
 * SQ-store handle
 */
static SQstore_ServiceAPI * sq;

/**
 * Semaphore on which the RCB acquire thread waits
 * if the RCB buffer is full.
 */
static struct SEMAPHORE * acquireMoreSignal;

/**
 * Set to YES to shutdown the module.
 */
static int doneSignal;

/**
 * Lock for the RCB buffer.
 */
static struct MUTEX * lock;

/**
 * Highest index in RCB that is valid.
 */
static int rCBPos = 0;

static struct PTHREAD * gather_thread;

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;
		

static int acquire(const HashCode512 * key,
		  const Datastore_Value * value,
		  void * closure) {
  int loadc;
  int loadi;
  int load;

  if (doneSignal)
    return SYSERR;
  SEMAPHORE_DOWN(acquireMoreSignal, YES);
  if (doneSignal)
    return SYSERR;
  MUTEX_LOCK(lock);
  load = 0;
  while (randomContentBuffer[rCBPos].value != NULL) {
    rCBPos = (rCBPos + 1) % RCB_SIZE;
    load++;
    if (load > RCB_SIZE) {
      GE_BREAK(ectx, 0);
      MUTEX_UNLOCK(lock);
      return SYSERR;
    }
  }
#if DEBUG_PREFETCH
  {
    EncName enc;

    hash2enc(key,
	     &enc);
    GE_LOG(ectx,
	   GE_DEBUG | GE_BULK | GE_USER,
	   "Adding content `%s' of type %u/size %u/exp %llu to prefetch buffer (%u)\n",
	   &enc,
	   ntohl(value->type),
	   ntohl(value->size),
	   ntohll(value->expirationTime),
	   rCBPos);
  }
#endif
  randomContentBuffer[rCBPos].key = *key;
  randomContentBuffer[rCBPos].used = 0;
  randomContentBuffer[rCBPos].value
    = MALLOC(ntohl(value->size));
  memcpy(randomContentBuffer[rCBPos].value,
	 value,
	 ntohl(value->size));
  MUTEX_UNLOCK(lock);
  loadi = os_disk_get_load(ectx,
			   cfg);
  loadc = os_cpu_get_load(ectx,
			  cfg);
  if (loadi > loadc)
    load = loadi;
  else
    load = loadc;
  if (load < 10)
    load = 10;    /* never sleep less than 500 ms */
  if (load > 100)
    load = 100;   /* never sleep longer than 5 seconds */
  if (doneSignal)
    return SYSERR;
  /* the higher the load, the longer the sleep */
  PTHREAD_SLEEP(50 * cronMILLIS * load);
  if (doneSignal)
    return SYSERR;
  return OK;
}

/**
 * Acquire new block(s) to the migration buffer.
 */
static void * rcbAcquire(void * unused) {
  int load;
  while (doneSignal == NO) {
    sq->iterateMigrationOrder(&acquire,
			      NULL);
    /* sleep here, too - otherwise we start looping immediately
       if there is no content in the DB! */
    load = os_cpu_get_load(ectx,
			   cfg);
    if (load < 10)
      load = 10;    /* never sleep less than 500 ms */
    if (load > 100)
      load = 100;   /* never sleep longer than 5 seconds */
    PTHREAD_SLEEP(50 * cronMILLIS * load);
  }
  return NULL;
}

/**
 * Select content for active migration.  Takes the best match from the
 * randomContentBuffer (if the RCB is non-empty) and returns it.
 *
 * @return SYSERR if the RCB is empty
 */
int getRandom(const HashCode512 * receiver,
	      unsigned int sizeLimit,
	      HashCode512 * key,
	      Datastore_Value ** value,
	      unsigned int type) {
  unsigned int dist;
  unsigned int minDist;
  int minIdx;
  int i;

  minIdx = -1;
  minDist = -1; /* max */
  MUTEX_LOCK(lock);
  for (i=0;i<RCB_SIZE;i++) {
    if (randomContentBuffer[i].value == NULL)
      continue;
    if (randomContentBuffer[i].used == *(int*) receiver)
      continue; /* used this content for this peer already! */
    if ( ( ( (type != ntohl(randomContentBuffer[i].value->type)) &&
	     (type != 0) ) ) ||
	 (sizeLimit < ntohl(randomContentBuffer[i].value->size)) )
      continue;
    if ( (ntohl(randomContentBuffer[i].value->type) == ONDEMAND_BLOCK) &&
	 (sizeLimit < 32768) )
      continue; /* 32768 == ecrs/tree.h: DBLOCK_SIZE */
    dist = distanceHashCode512(&randomContentBuffer[i].key,
			       receiver);
    if (dist < minDist) {
      minIdx = i;
      minDist = dist;
    }
  }
  if (minIdx == -1) {
    MUTEX_UNLOCK(lock);
#if DEBUG_PREFETCH
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Failed to find content in prefetch buffer\n");
#endif
    return SYSERR;
  }
#if DEBUG_PREFETCH
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Found content in prefetch buffer (%u)\n",
	   minIdx);
#endif
  *key = randomContentBuffer[minIdx].key;
  *value = randomContentBuffer[minIdx].value;

  if ( (randomContentBuffer[minIdx].used == 0) &&
       (0 != *(int*) receiver) ) {
    /* re-use once more! */
    randomContentBuffer[minIdx].used = *(int*) receiver;
    randomContentBuffer[minIdx].value = MALLOC(ntohl((*value)->size));
    memcpy(randomContentBuffer[minIdx].value,
	   *value,
	   ntohl((*value)->size));
  } else {
    randomContentBuffer[minIdx].used = 0;
    randomContentBuffer[minIdx].value = NULL;
    SEMAPHORE_UP(acquireMoreSignal);
  }
  MUTEX_UNLOCK(lock);
  return OK;
}
				
void initPrefetch(struct GE_Context * e,
		  struct GC_Configuration * c,
		  SQstore_ServiceAPI * s) {
  ectx = e;
  cfg = c;
  sq = s;
  memset(randomContentBuffer,
	 0,
	 sizeof(ContentBuffer *)*RCB_SIZE);
  acquireMoreSignal = SEMAPHORE_CREATE(RCB_SIZE);
  doneSignal = NO;
  lock = MUTEX_CREATE(NO);
  gather_thread = PTHREAD_CREATE(&rcbAcquire,
				 NULL,
				 64*1024);
  GE_ASSERT(NULL,
	    gather_thread != NULL);
}

void donePrefetch() {
  int i;
  void * unused;

  doneSignal = YES;
  PTHREAD_STOP_SLEEP(gather_thread);
  SEMAPHORE_UP(acquireMoreSignal);
  PTHREAD_JOIN(gather_thread, &unused);
  SEMAPHORE_DESTROY(acquireMoreSignal);
  for (i=0;i<RCB_SIZE;i++)
    FREENONNULL(randomContentBuffer[i].value);
  MUTEX_DESTROY(lock);
  lock = NULL;
  sq = NULL;
  cfg = NULL;
  ectx = NULL;
}

/* end of prefetch.c */
