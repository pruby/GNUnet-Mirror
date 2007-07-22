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
#define NO_PUSH NO

/**
 * DHT service.  Set to NULL to terminate
 */
static DHT_ServiceAPI *dht;

/**
 * Global core API.
 */
static CoreAPIForApplication *coreAPI;

/**
 * SQStore service.
 */
static SQstore_ServiceAPI *sqstore;


/**
 * Thread that does the pushing.
 */
static struct PTHREAD *thread;

/**
 * Total number of entries with anonymity 0.
 * Used to calculate how long we should wait
 * between iterations.
 */
static int total;

static Stats_ServiceAPI *stats;

static int stat_push_count;


static int
push_callback (const HashCode512 * key,
               const Datastore_Value * value, void *closure,
               unsigned long long uid)
{
  cron_t delay;

  if (dht == NULL)
    return SYSERR;
  /* try pushing out everything every 6h,
     but do not push more often than every 5s */
  delay = 6 * cronHOURS / total;
  if (delay < 5 * cronSECONDS)
    delay = 5 * cronSECONDS;
  if (delay > 60 * cronSECONDS)
    delay = 60 * cronSECONDS;
  PTHREAD_SLEEP (delay);
  if (dht == NULL)
    return SYSERR;
  dht->put (key,
            ntohl (value->type),
            ntohl (value->size) - sizeof (Datastore_Value),
            ntohll (value->expirationTime), (const char *) &value[1]);
  if (stats != NULL)
    stats->change (stat_push_count, 1);
  if (dht == NULL)
    return SYSERR;
  return OK;
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
        PTHREAD_SLEEP (15 * cronMINUTES);
    }
  return NULL;
}


/**
 * Initialize the migration module.
 */
void
init_dht_push (CoreAPIForApplication * capi, DHT_ServiceAPI * d)
{
  coreAPI = capi;
  dht = d;
  sqstore = capi->requestService ("sqstore");
  if (sqstore == NULL)
    {
      GE_BREAK (capi->ectx, 0);
      return;
    }
  stats = capi->requestService ("stats");
  if (stats != NULL)
    stat_push_count
      = stats->create (gettext_noop ("# blocks pushed into DHT"));
  if (!NO_PUSH)
    {
      thread = PTHREAD_CREATE (&push_thread, NULL, 1024 * 128);
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
      PTHREAD_STOP_SLEEP (thread);
      PTHREAD_JOIN (thread, &unused);
    }
  coreAPI->releaseService (sqstore);
  if (stats != NULL)
    {
      coreAPI->releaseService (stats);
      stats = NULL;
    }
  coreAPI = NULL;
}


/* end of dht_push.c */
