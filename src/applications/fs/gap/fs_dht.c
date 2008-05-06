/*
      This file is part of GNUnet
      (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file fs/gap/fs_dht.c
 * @brief integration of file-sharing with the DHT
 *        infrastructure
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_dht_service.h"
#include "gnunet_sqstore_service.h"
#include "gnunet_stats_service.h"
#include "gnunet_protocols.h"
#include "ecrs_core.h"
#include "fs.h"
#include "shared.h"
#include "fs_dht.h"
#include "querymanager.h"

/**
 * Linked list containing the DHT get handles
 * of our active requests.
 */
struct ActiveRequestRecords
{

  struct ActiveRequestRecords *next;

  struct GNUNET_DHT_GetHandle *handle;

  GNUNET_CronTime end_time;

  unsigned int type;

};

static GNUNET_DHT_ServiceAPI *dht;

static GNUNET_SQstore_ServiceAPI *sqstore;

static GNUNET_CoreAPIForPlugins *coreAPI;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_push_count;

static struct ActiveRequestRecords *records;

/**
 * Thread that does the pushing.
 */
static struct GNUNET_ThreadHandle *thread;

/**
 * Should the thread terminate?
 */
static int shutdown_requested;

/**
 * Total number of entries with anonymity 0.
 * Used to calculate how long we should wait
 * between iterations.
 */
static unsigned int total;


/**
 * Cancel all requests with the DHT that
 * are older than a certain time limit.
 */
static void
purge_old_records (GNUNET_CronTime limit)
{
  struct ActiveRequestRecords *pos;
  struct ActiveRequestRecords *prev;

  prev = NULL;
  pos = records;
  while (pos != NULL)
    {
      if (pos->end_time < limit)
        {
          if (prev == NULL)
            records = pos->next;
          else
            prev->next = pos->next;
          dht->get_stop (pos->handle);
          GNUNET_free (pos);
          if (prev == NULL)
            pos = records;
          else
            pos = prev->next;
        }
      else
        {
          prev = pos;
          pos = pos->next;
        }
    }
}


/**
 * We got a result from the DHT.  Check that it is valid
 * and pass to our clients.
 *
 * @param key the current key
 * @param value the current value
 * @param cls argument passed for context (closure)
 * @return GNUNET_OK to continue with iteration, GNUNET_SYSERR to abort
 */
static int
response_callback (const GNUNET_HashCode * key,
                   unsigned int type,
                   unsigned int size, const char *value, void *cls)
{
  struct ActiveRequestRecords *record = cls;
  const GNUNET_EC_DBlock *dblock;
  GNUNET_HashCode hc;

  dblock = (const GNUNET_EC_DBlock *) value;
  if ((GNUNET_SYSERR ==
       GNUNET_EC_file_block_check_and_get_query (size,
                                                 dblock,
                                                 GNUNET_YES,
                                                 &hc)) ||
      (0 != memcmp (key, &hc, sizeof (GNUNET_HashCode))))
    {
      GNUNET_GE_BREAK_OP (NULL, 0);
      return GNUNET_OK;
    }
  GNUNET_FS_QUERYMANAGER_handle_response (NULL, &hc, 0, size, dblock);
  if (record->type == GNUNET_ECRS_BLOCKTYPE_DATA)
    {
      record->end_time = 0;     /* delete ASAP */
      return GNUNET_SYSERR;     /* no more! */
    }
  return GNUNET_OK;
}

/**
 * Execute a GAP query.  Determines where to forward
 * the query and when (and captures state for the response).
 * May also have to check the local datastore.
 *
 * @param type type of content requested
 * @param querie hash code of the query
 */
void
GNUNET_FS_DHT_execute_query (unsigned int type, const GNUNET_HashCode * query)
{
  struct ActiveRequestRecords *record;
  GNUNET_CronTime now;

  if (dht == NULL)
    return;
  now = GNUNET_get_time ();
  record = GNUNET_malloc (sizeof (struct ActiveRequestRecords));
  record->end_time = now + GNUNET_GAP_MAX_DHT_DELAY;
  record->handle = dht->get_start (type, query, &response_callback, record);
  record->type = type;
  GNUNET_mutex_lock (GNUNET_FS_lock);
  record->next = records;
  records = record;
  purge_old_records (now);
  GNUNET_mutex_unlock (GNUNET_FS_lock);
}

/**
 * Callback invoked on zero-anonymity content
 * (used to push that content into the DHT).
 */
static int
push_callback (const GNUNET_HashCode * key,
               const GNUNET_DatastoreValue * value, void *closure,
               unsigned long long uid)
{
  GNUNET_CronTime delay;

  if (GNUNET_YES == shutdown_requested)
    return GNUNET_SYSERR;
  /* try pushing out everything every 6h,
     but do not push more often than every 5s */
  delay = 6 * GNUNET_CRON_HOURS / total;
  if (delay < 5 * GNUNET_CRON_SECONDS)
    delay = 5 * GNUNET_CRON_SECONDS;
  if (delay > 60 * GNUNET_CRON_SECONDS)
    delay = 60 * GNUNET_CRON_SECONDS;
  GNUNET_thread_sleep (delay);
  if (GNUNET_YES == shutdown_requested)
    return GNUNET_SYSERR;
  dht->put (key,
            ntohl (value->type),
            ntohl (value->size) - sizeof (GNUNET_DatastoreValue),
            (const char *) &value[1]);
  if (stats != NULL)
    stats->change (stat_push_count, 1);
  if (GNUNET_YES == shutdown_requested)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Main method of the thread responsible for pushing
 * out the content.
 */
static void *
push_thread (void *cls)
{
  while ((shutdown_requested == GNUNET_NO) &&
         (dht != NULL) && (sqstore != NULL))
    {
      if (total == 0)
        total = 1;
      total = sqstore->iterateNonAnonymous (0, &push_callback, NULL);
      if ((shutdown_requested == GNUNET_NO) && (total == 0))
        GNUNET_thread_sleep (5 * GNUNET_CRON_MINUTES);
    }
  return NULL;
}


int
GNUNET_FS_DHT_init (GNUNET_CoreAPIForPlugins * capi)
{
  coreAPI = capi;
  dht = capi->service_request ("dht");
  sqstore = capi->service_request ("sqstore");
  stats = capi->service_request ("stats");
  if (stats != NULL)
    stat_push_count
      = stats->create (gettext_noop ("# blocks pushed into DHT"));
  if ((dht != NULL) && (sqstore != NULL))
    {
      shutdown_requested = GNUNET_NO;
      thread = GNUNET_thread_create (&push_thread, NULL, 1024 * 128);
    }
  return 0;
}

int
GNUNET_FS_DHT_done ()
{
  void *unused;

  purge_old_records (-1);
  if (thread != NULL)
    {
      shutdown_requested = GNUNET_YES;
      GNUNET_thread_stop_sleep (thread);
      GNUNET_thread_join (thread, &unused);
    }
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }
  if (dht != NULL)
    coreAPI->service_release (dht);
  dht = NULL;
  if (sqstore != NULL)
    coreAPI->service_release (sqstore);
  sqstore = NULL;
  coreAPI = NULL;
  return 0;
}
