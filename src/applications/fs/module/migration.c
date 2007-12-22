/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/module/migration.c
 * @brief This module is responsible for pushing content out
 * into the network.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "migration.h"
#include "fs.h"
#include "anonymity.h"
#include "gnunet_stats_service.h"
#include "gnunet_protocols.h"
#include "ondemand.h"

#define DEBUG_MIGRATION GNUNET_NO

/**
 * To how many peers may we migrate the same piece of content during
 * one iteration?  Higher values mean less IO, but also migration
 * becomes quickly much less effective (everyone has the same
 * content!).  Also, numbers larger than the number of connections are
 * simply a waste of memory.
 */
#define MAX_RECEIVERS 16

/**
 * How many migration records do we keep in memory
 * at the same time?  Each record is about 32k, so
 * 64 records will use about 2 MB of memory.
 * We might want to allow users to specify larger
 * values in the configuration file some day.
 */
#define MAX_RECORDS 64

/**
 * How often do we poll the datastore for content (at most).
 */
#define MAX_POLL_FREQUENCY (250 * GNUNET_CRON_MILLISECONDS)

/**
 * Datastore service.
 */
static GNUNET_Datastore_ServiceAPI *datastore;

/**
 * Global core API.
 */
static GNUNET_CoreAPIForPlugins *coreAPI;

/**
 * GAP service.
 */
static GNUNET_GAP_ServiceAPI *gap;

/**
 * DHT service.  Maybe NULL!
 */
static GNUNET_DHT_ServiceAPI *dht;

/**
 * Traffic service.
 */
static GNUNET_Traffic_ServiceAPI *traffic;

static GNUNET_Stats_ServiceAPI *stats;

static int stat_migration_count;

static int stat_migration_factor;

static int stat_on_demand_migration_attempts;

/**
 * Lock used to access content.
 */
static struct GNUNET_Mutex *lock;

struct MigrationRecord
{
  GNUNET_DatastoreValue *value;
  GNUNET_HashCode key;
  unsigned int receiverIndices[MAX_RECEIVERS];
  unsigned int sentCount;
};

static struct MigrationRecord content[MAX_RECORDS];

static struct GNUNET_GE_Context *ectx;

/**
 * Callback method for pushing content into the network.
 * The method chooses either a "recently" deleted block
 * or content that has a GNUNET_hash close to the receiver ID
 * (randomized to guarantee diversity, unpredictability
 * etc.).<p>
 *
 * @param receiver the receiver of the message
 * @param position is the reference to the
 *        first unused position in the buffer where GNUnet is building
 *        the message
 * @param padding is the number of bytes left in that buffer.
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
static unsigned int
activeMigrationCallback (const GNUNET_PeerIdentity * receiver,
                         void *position, unsigned int padding)
{
  static GNUNET_CronTime discard_time;
  unsigned int ret;
  GapWrapper *gw;
  unsigned int size;
  GNUNET_CronTime et;
  GNUNET_CronTime now;
  unsigned int anonymity;
  GNUNET_DatastoreValue *enc;
  GNUNET_DatastoreValue *value;
  unsigned int index;
  int entry;
  int discard_entry;
  int discard_match;
  int i;
  int j;
  int match;
  unsigned int dist;
  unsigned int minDist;

  index = coreAPI->connection_compute_index_of_peer (receiver);
  GNUNET_mutex_lock (lock);
  now = GNUNET_get_time ();
  entry = -1;
  discard_entry = -1;
  discard_match = -1;
  minDist = -1;                 /* max */
  for (i = 0; i < MAX_RECORDS; i++)
    {
      if (content[i].value == NULL)
        {
          if (discard_time >= now - MAX_POLL_FREQUENCY)
            continue;
          discard_time = now;
          if (GNUNET_OK !=
              datastore->getRandom (&content[i].key, &content[i].value))
            {
              content[i].value = NULL;  /* just to be sure... */
              continue;
            }
          else
            {
              if (stats != NULL)
                stats->change (stat_migration_factor, 1);
            }
        }
      match = 1;
      if (ntohl (content[i].value->size) + sizeof (GapWrapper) -
          sizeof (GNUNET_DatastoreValue) <= padding)
        {
          match = 0;
          for (j = 0; j < content[i].sentCount; j++)

            {
              if (content[i].receiverIndices[j] == index)
                {
                  match = 1;
                  break;
                }
            }
        }
      if (match == 0)
        {
          dist =
            GNUNET_hash_distance_u32 (&content[i].key, &receiver->hashPubKey);
          if (dist <= minDist)
            {
              entry = i;
              minDist = dist;
              break;
            }
        }
      else
        {
          if ((content[i].sentCount > discard_match) || (discard_match == -1))
            {
              discard_match = content[i].sentCount;
              discard_entry = i;
            }
        }
    }
  if ((discard_entry != -1) &&
      (discard_match > MAX_RECEIVERS / 2) &&
      (discard_time < now - MAX_POLL_FREQUENCY))
    {
      discard_time = now;
      GNUNET_free_non_null (content[discard_entry].value);
      content[discard_entry].value = NULL;
      content[discard_entry].sentCount = 0;
      if (GNUNET_OK != datastore->getRandom (&content[discard_entry].key,
                                             &content[discard_entry].value))
        {
          content[discard_entry].value = NULL;  /* just to be sure... */
          discard_entry = -1;
        }
      else
        {
          if (stats != NULL)
            stats->change (stat_migration_factor, 1);
        }
    }
  if (entry == -1)
    entry = discard_entry;
  if (entry == -1)
    {
#if DEBUG_MIGRATION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Migration: no content available for migration.\n");
#endif
      GNUNET_mutex_unlock (lock);
      return 0;
    }
  value = content[entry].value;
  if (value == NULL)
    {
      GNUNET_GE_ASSERT (NULL, 0);
      GNUNET_mutex_unlock (lock);
      return 0;
    }
  size =
    sizeof (GapWrapper) + ntohl (value->size) -
    sizeof (GNUNET_DatastoreValue);
  if (size > padding)
    {
#if DEBUG_MIGRATION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Migration: available content too big (%u > %u) for migration.\n",
                     size, padding);
#endif
      GNUNET_mutex_unlock (lock);
      return 0;
    }
#if DEBUG_MIGRATION
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                 "Migration: random lookup in datastore returned type %d.\n",
                 ntohl (value->type));
#endif
  if ((ntohl (value->type) == GNUNET_ECRS_BLOCKTYPE_ONDEMAND) ||
      (ntohl (value->type) == GNUNET_ECRS_BLOCKTYPE_ONDEMAND_OLD))
    {
      if (ONDEMAND_getIndexed (datastore,
                               value, &content[entry].key, &enc) != GNUNET_OK)
        {
          GNUNET_free_non_null (value);
          content[entry].value = NULL;
          GNUNET_mutex_unlock (lock);
#if DEBUG_MIGRATION
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "Migration: failed to locate indexed content for migration.\n");
#endif
          return 0;
        }
      if (stats != NULL)
        stats->change (stat_on_demand_migration_attempts, 1);
      content[entry].value = enc;
      GNUNET_free (value);
      value = enc;
    }

  size =
    sizeof (GapWrapper) + ntohl (value->size) -
    sizeof (GNUNET_DatastoreValue);
  if (size > padding)
    {
      GNUNET_mutex_unlock (lock);
#if DEBUG_MIGRATION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Migration: available content too big (%u > %u) for migration.\n",
                     size, padding);
#endif
      return 0;
    }
  et = GNUNET_ntohll (value->expirationTime);
  if (et > now)
    {
      et -= now;
      et = et % MAX_MIGRATION_EXP;
      et += now;
    }
  anonymity = ntohl (value->anonymityLevel);
  ret = 0;
  if (anonymity == 0)
    {
      value->anonymityLevel = htonl (1);
      anonymity = 1;
    }
  if (GNUNET_OK == checkCoverTraffic (ectx, traffic, anonymity))
    {
      gw = GNUNET_malloc (size);
      gw->dc.size = htonl (size);
      gw->timeout = GNUNET_htonll (et);
      memcpy (&gw[1], &value[1], size - sizeof (GapWrapper));
      ret = gap->tryMigrate (&gw->dc, &content[entry].key, position, padding);
      GNUNET_free (gw);
#if DEBUG_MIGRATION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "gap's tryMigrate returned %u\n", ret);
#endif
      if (ret != 0)
        {
          if (content[entry].sentCount == MAX_RECEIVERS)
            {
              GNUNET_free (content[entry].value);
              content[entry].value = NULL;
              content[entry].sentCount = 0;
            }
          else
            {
              content[entry].receiverIndices[content[entry].sentCount++] =
                index;
            }
        }
      else
        {
#if DEBUG_MIGRATION
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "Migration: not enough cover traffic\n");
#endif
        }
    }
  GNUNET_mutex_unlock (lock);
  if ((ret > 0) && (stats != NULL))
    stats->change (stat_migration_count, 1);
  GNUNET_GE_BREAK (NULL, ret <= padding);
  return ret;
}

void
initMigration (GNUNET_CoreAPIForPlugins * capi,
               GNUNET_Datastore_ServiceAPI * ds,
               GNUNET_GAP_ServiceAPI * g, GNUNET_DHT_ServiceAPI * d,
               GNUNET_Traffic_ServiceAPI * t)
{
  ectx = capi->ectx;
  lock = GNUNET_mutex_create (GNUNET_NO);
  coreAPI = capi;
  datastore = ds;
  gap = g;
  dht = d;
  traffic = t;
  coreAPI->
    connection_register_send_callback
    (GNUNET_GAP_ESTIMATED_DATA_SIZE, &activeMigrationCallback);
  stats = capi->request_service ("stats");
  if (stats != NULL)
    {
      stat_migration_count
        = stats->create (gettext_noop ("# blocks migrated"));
      stat_migration_factor
        = stats->create (gettext_noop ("# blocks fetched for migration"));
      stat_on_demand_migration_attempts
        =
        stats->create (gettext_noop ("# on-demand block migration attempts"));
    }

}

void
doneMigration ()
{
  int i;
  coreAPI->
    connection_unregister_send_callback
    (GNUNET_GAP_ESTIMATED_DATA_SIZE, &activeMigrationCallback);
  if (stats != NULL)
    {
      coreAPI->release_service (stats);
      stats = NULL;
    }
  datastore = NULL;
  gap = NULL;
  dht = NULL;
  coreAPI = NULL;
  traffic = NULL;
  for (i = 0; i < MAX_RECORDS; i++)
    {
      GNUNET_free_non_null (content[i].value);
      content[i].value = NULL;
    }
  GNUNET_mutex_destroy (lock);
  lock = NULL;
}

/* end of migration.c */
