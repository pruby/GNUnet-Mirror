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

#define DEBUG_PREFETCH GNUNET_NO

static GNUNET_HashCode rkey;

static GNUNET_DatastoreValue *rvalue;

/**
 * SQ-store handle
 */
static GNUNET_SQstore_ServiceAPI *sq;

/**
 * Semaphore on which the RCB acquire thread waits
 * if the RCB buffer is full.
 */
static struct GNUNET_Semaphore *acquireMoreSignal;

/**
 * Set to GNUNET_YES to shutdown the module.
 */
static int doneSignal;

/**
 * Lock for the RCB buffer.
 */
static struct GNUNET_Mutex *lock;

static struct GNUNET_ThreadHandle *gather_thread;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;


static int
acquire (const GNUNET_HashCode * key,
         const GNUNET_DatastoreValue * value, void *closure,
         unsigned long long uid)
{
  if (doneSignal)
    return GNUNET_SYSERR;
  GNUNET_semaphore_down (acquireMoreSignal, GNUNET_YES);
  if (doneSignal)
    return GNUNET_SYSERR;
  GNUNET_mutex_lock (lock);
  GNUNET_GE_ASSERT (NULL, rvalue == NULL);
  rkey = *key;
  rvalue = GNUNET_malloc (ntohl (value->size));
  memcpy (rvalue, value, ntohl (value->size));
  GNUNET_mutex_unlock (lock);
  if (doneSignal)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Acquire new block(s) to the migration buffer.
 */
static void *
rcbAcquire (void *unused)
{
  int load;
  while (doneSignal == GNUNET_NO)
    {
      sq->iterateMigrationOrder (&acquire, NULL);
      /* sleep here - otherwise we may start looping immediately
         if there is no content in the DB! */
      load = GNUNET_cpu_get_load (ectx, cfg);
      if (load < 10)
        load = 10;              /* never sleep less than 500 ms */
      if (load > 100)
        load = 100;             /* never sleep longer than 5 seconds */
      if (doneSignal == GNUNET_NO)
        GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS * load);
    }
  return NULL;
}

/**
 * Select content for active migration.  Takes the best match from the
 * randomContentBuffer (if the RCB is non-empty) and returns it.
 *
 * @return GNUNET_SYSERR if the RCB is empty
 */
int
getRandom (GNUNET_HashCode * key, GNUNET_DatastoreValue ** value)
{
  GNUNET_mutex_lock (lock);
  if (rvalue == NULL)
    {
      GNUNET_mutex_unlock (lock);
      return GNUNET_SYSERR;
    }
  *value = rvalue;
  *key = rkey;
  rvalue = NULL;
  GNUNET_mutex_unlock (lock);
  GNUNET_semaphore_up (acquireMoreSignal);
  return GNUNET_OK;
}

void
initPrefetch (struct GNUNET_GE_Context *e,
              struct GNUNET_GC_Configuration *c,
              GNUNET_SQstore_ServiceAPI * s)
{
  ectx = e;
  cfg = c;
  sq = s;
  acquireMoreSignal = GNUNET_semaphore_create (1);
  doneSignal = GNUNET_NO;
  lock = GNUNET_mutex_create (GNUNET_NO);
  gather_thread = GNUNET_thread_create (&rcbAcquire, NULL, 64 * 1024);
  if (gather_thread == NULL)
    GNUNET_GE_LOG_STRERROR (ectx,
                            GNUNET_GE_ERROR | GNUNET_GE_ADMIN | GNUNET_GE_USER
                            | GNUNET_GE_IMMEDIATE, "pthread_create");
}

void
donePrefetch ()
{
  void *unused;

  doneSignal = GNUNET_YES;
  if (gather_thread != NULL)
    GNUNET_thread_stop_sleep (gather_thread);
  GNUNET_semaphore_up (acquireMoreSignal);
  if (gather_thread != NULL)
    GNUNET_thread_join (gather_thread, &unused);
  GNUNET_semaphore_destroy (acquireMoreSignal);
  GNUNET_free_non_null (rvalue);
  rvalue = NULL;
  GNUNET_mutex_destroy (lock);
  lock = NULL;
  sq = NULL;
  cfg = NULL;
  ectx = NULL;
}

/* end of prefetch.c */
