/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/module/dht_push.c
 * @brief This module is responsible for pushing non-anonymous
 *        inserted (not indexed!) content out into the DHT.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "dht_push.h"
#include "gnunet_stats_service.h"
#include "gnunet_sqstore_service.h"

/**
 * Disable DHT pushing?  Set to 1 to essentially disable
 * the code in this file.  Used to study its performance
 * impact.  Useful also for users that do not want to
 * use non-anonymous file-sharing (since it eliminates
 * some of the processing cost which would otherwise go
 * to waste).
 */
#define NO_PUSH GNUNET_NO

/**
 * DHT service.  Set to NULL to terminate
 */
static GNUNET_DHT_ServiceAPI *dht;

/**
 * Global core API.
 */
static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * SQStore service.
 */
static GNUNET_SQstore_ServiceAPI *sqstore;


/**
 * Thread that does the pushing.
 */
static struct GNUNET_ThreadHandle *thread;

/**
 * Total number of entries with anonymity 0.
 * Used to calculate how long we should wait
 * between iterations.
 */
static int total;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_push_count;


static int
push_callback (const GNUNET_HashCode * key,
               const GNUNET_DatastoreValue * value, void *closure,
               unsigned long long uid)
{
  GNUNET_CronTime delay;

  if (dht == NULL)
    return GNUNET_SYSERR;
  /* try pushing out everything every 6h,
     but do not push more often than every 5s */
  delay = 6 * GNUNET_CRON_HOURS / total;
  if (delay < 5 * GNUNET_CRON_SECONDS)
    delay = 5 * GNUNET_CRON_SECONDS;
  if (delay > 60 * GNUNET_CRON_SECONDS)
    delay = 60 * GNUNET_CRON_SECONDS;
  GNUNET_thread_sleep (delay);
  if (dht == NULL)
    return GNUNET_SYSERR;
  dht->put (key,
            ntohl (value->type),
            ntohl (value->size) - sizeof (GNUNET_DatastoreValue),
            (const char *) &value[1]);
  if (stats != NULL)
    stats->change (stat_push_count, 1);
  if (dht == NULL)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

static void *
push_thread (void *cls)
{
  while ((dht != NULL) && (sqstore != NULL))
    {
      if (total == 0)
        total = 1;
      total = sqstore->iterateNonAnonymous (0, &push_callback, NULL);
      if ((dht != NULL) && (total == 0))
        GNUNET_thread_sleep (15 * GNUNET_CRON_MINUTES);
    }
  return NULL;
}


/**
 * Initialize the migration module.
 */
void
init_dht_push (GNUNET_CoreAPIForPlugins * capi, GNUNET_DHT_ServiceAPI * d)
{
  coreAPI = capi;
  dht = d;
  sqstore = capi->request_service ("sqstore");
  if (sqstore == NULL)
    {
      GNUNET_GE_BREAK (capi->ectx, 0);
      return;
    }
  stats = capi->request_service ("stats");
  if (stats != NULL)
    stat_push_count
      = stats->create (gettext_noop ("# blocks pushed into DHT"));
  if (!NO_PUSH)
    {
      thread = GNUNET_thread_create (&push_thread, NULL, 1024 * 128);
    }
}

void
done_dht_push (void)
{
  void *unused;

  if (sqstore == NULL)
    return;
  dht = NULL;
  if (thread != NULL)
    {
      GNUNET_thread_stop_sleep (thread);
      GNUNET_thread_join (thread, &unused);
    }
  coreAPI->release_service (sqstore);
  if (stats != NULL)
    {
      coreAPI->release_service (stats);
      stats = NULL;
    }
  coreAPI = NULL;
}


/* end of dht_push.c */
