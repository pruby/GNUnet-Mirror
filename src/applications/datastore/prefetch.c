/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @brief This module is responsible for fetching
 *   content that can be pushed out into the network
 * @author Christian Grothoff, Igor Wronsky
 */

#include "platform.h"
#include "prefetch.h"
#include "gnunet_protocols.h"

#define DEBUG_PREFETCH NO

static HashCode512 rkey;

static Datastore_Value *rvalue;

/**
 * SQ-store handle
 */
static SQstore_ServiceAPI *sq;

/**
 * Semaphore on which the RCB acquire thread waits
 * if the RCB buffer is full.
 */
static struct SEMAPHORE *acquireMoreSignal;

/**
 * Set to YES to shutdown the module.
 */
static int doneSignal;

/**
 * Lock for the RCB buffer.
 */
static struct MUTEX *lock;

static struct PTHREAD *gather_thread;

static struct GE_Context *ectx;

static struct GC_Configuration *cfg;


static int
acquire (const HashCode512 * key,
         const Datastore_Value * value, void *closure, unsigned long long uid)
{
  if (doneSignal)
    return SYSERR;
  SEMAPHORE_DOWN (acquireMoreSignal, YES);
  if (doneSignal)
    return SYSERR;
  MUTEX_LOCK (lock);
  GE_ASSERT (NULL, rvalue == NULL);
  rkey = *key;
  rvalue = MALLOC (ntohl (value->size));
  memcpy (rvalue, value, ntohl (value->size));
  MUTEX_UNLOCK (lock);
  if (doneSignal)
    return SYSERR;
  return OK;
}

/**
 * Acquire new block(s) to the migration buffer.
 */
static void *
rcbAcquire (void *unused)
{
  int load;
  while (doneSignal == NO)
    {
      sq->iterateMigrationOrder (&acquire, NULL);
      /* sleep here - otherwise we may start looping immediately
         if there is no content in the DB! */
      load = os_cpu_get_load (ectx, cfg);
      if (load < 10)
        load = 10;              /* never sleep less than 500 ms */
      if (load > 100)
        load = 100;             /* never sleep longer than 5 seconds */
      if (doneSignal == NO)
        PTHREAD_SLEEP (50 * cronMILLIS * load);
    }
  return NULL;
}

/**
 * Select content for active migration.  Takes the best match from the
 * randomContentBuffer (if the RCB is non-empty) and returns it.
 *
 * @return SYSERR if the RCB is empty
 */
int
getRandom (HashCode512 * key, Datastore_Value ** value)
{
  MUTEX_LOCK (lock);
  if (rvalue == NULL)
    {
      MUTEX_UNLOCK (lock);
      return SYSERR;
    }
  *value = rvalue;
  *key = rkey;
  rvalue = NULL;
  MUTEX_UNLOCK (lock);
  SEMAPHORE_UP (acquireMoreSignal);
  return OK;
}

void
initPrefetch (struct GE_Context *e,
              struct GC_Configuration *c, SQstore_ServiceAPI * s)
{
  ectx = e;
  cfg = c;
  sq = s;
  acquireMoreSignal = SEMAPHORE_CREATE (1);
  doneSignal = NO;
  lock = MUTEX_CREATE (NO);
  gather_thread = PTHREAD_CREATE (&rcbAcquire, NULL, 64 * 1024);
  if (gather_thread == NULL)
    GE_LOG_STRERROR (ectx,
                     GE_ERROR | GE_ADMIN | GE_USER | GE_IMMEDIATE,
                     "pthread_create");
}

void
donePrefetch ()
{
  void *unused;

  doneSignal = YES;
  if (gather_thread != NULL)
    PTHREAD_STOP_SLEEP (gather_thread);
  SEMAPHORE_UP (acquireMoreSignal);
  if (gather_thread != NULL)
    PTHREAD_JOIN (gather_thread, &unused);
  SEMAPHORE_DESTROY (acquireMoreSignal);
  FREENONNULL (rvalue);
  rvalue = NULL;
  MUTEX_DESTROY (lock);
  lock = NULL;
  sq = NULL;
  cfg = NULL;
  ectx = NULL;
}

/* end of prefetch.c */
