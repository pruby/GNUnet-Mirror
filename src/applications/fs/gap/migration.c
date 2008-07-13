/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2007, 2008 Christian Grothoff (and other contributing authors)

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
#include "pid_table.h"
#include "shared.h"
#include "gnunet_stats_service.h"
#include "gnunet_protocols.h"
#include "anonymity.h"
#include "ondemand.h"

#define ENABLE_MIGRATION GNUNET_YES

#if ENABLE_MIGRATION

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

static GNUNET_Stats_ServiceAPI *stats;

static int stat_migration_count;

static int stat_migration_factor;

static int stat_migration_injected;

static int stat_on_demand_migration_attempts;

/**
 * Lock used to access content.
 */
static struct GNUNET_Mutex *lock;

struct MigrationRecord
{
  GNUNET_DatastoreValue *value;
  GNUNET_HashCode key;
  PID_INDEX receiverIndices[MAX_RECEIVERS];
  unsigned int sentCount;
};

static unsigned int content_size;

static struct MigrationRecord *content;

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
  unsigned int size;
  GNUNET_CronTime et;
  GNUNET_CronTime now;
  unsigned int anonymity;
  GNUNET_DatastoreValue *enc;
  GNUNET_DatastoreValue *value;
  P2P_gap_reply_MESSAGE *msg;
  PID_INDEX index;
  int entry;
  int discard_entry;
  int discard_match;
  int i;
  int j;
  int match;
  unsigned int dist;
  unsigned int minDist;
  struct MigrationRecord *rec;

  if (content_size == 0)
    return 0;
  index = GNUNET_FS_PT_intern (receiver);
  GNUNET_mutex_lock (GNUNET_FS_lock);
  now = GNUNET_get_time ();
  entry = -1;
  discard_entry = -1;
  discard_match = -1;
  minDist = -1;                 /* max */
  for (i = 0; i < content_size; i++)
    {
      rec = &content[i];
      if (rec->value == NULL)
        {
          if (discard_time >= now - MAX_POLL_FREQUENCY)
            continue;
          discard_time = now;
          if (GNUNET_OK != datastore->getRandom (&rec->key, &rec->value))
            {
              rec->value = NULL;        /* just to be sure... */
              continue;
            }
          else
            {
              if (stats != NULL)
                stats->change (stat_migration_factor, 1);
            }
        }
      match = 1;
      if (ntohl (rec->value->size) + sizeof (P2P_gap_reply_MESSAGE) -
          sizeof (GNUNET_DatastoreValue) <= padding)
        {
          match = 0;
          for (j = 0; j < rec->sentCount; j++)
            {
              if (rec->receiverIndices[j] == index)
                {
                  match = 1;
                  break;
                }
            }
        }
      if (match == 0)
        {
          dist = GNUNET_hash_distance_u32 (&rec->key, &receiver->hashPubKey);
          if (dist <= minDist)
            {
              entry = i;
              minDist = dist;
              break;
            }
        }
      else
        {
          if ((rec->sentCount > discard_match) || (discard_match == -1))
            {
              discard_match = rec->sentCount;
              discard_entry = i;
            }
        }
    }
  if ((discard_entry != -1) &&
      (discard_match > MAX_RECEIVERS / 2) &&
      (discard_time < now - MAX_POLL_FREQUENCY))
    {
      rec = &content[discard_entry];
      discard_time = now;
      GNUNET_free_non_null (rec->value);
      rec->value = NULL;
      GNUNET_FS_PT_decrement_rcs (rec->receiverIndices, rec->sentCount);
      rec->sentCount = 0;
      if (GNUNET_OK != datastore->getRandom (&rec->key, &rec->value))
        {
          rec->value = NULL;    /* just to be sure... */
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
      GNUNET_mutex_unlock (GNUNET_FS_lock);
      GNUNET_FS_PT_change_rc (index, -1);
      return 0;
    }
  rec = &content[entry];
  value = rec->value;
  if (value == NULL)
    {
      GNUNET_GE_ASSERT (NULL, 0);
      GNUNET_mutex_unlock (GNUNET_FS_lock);
      GNUNET_FS_PT_change_rc (index, -1);
      return 0;
    }
  size =
    sizeof (P2P_gap_reply_MESSAGE) + ntohl (value->size) -
    sizeof (GNUNET_DatastoreValue);
  if (size > padding)
    {
#if DEBUG_MIGRATION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Migration: available content too big (%u > %u) for migration.\n",
                     size, padding);
#endif
      GNUNET_mutex_unlock (GNUNET_FS_lock);
      GNUNET_FS_PT_change_rc (index, -1);
      return 0;
    }
#if DEBUG_MIGRATION
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_BULK | GNUNET_GE_USER,
                 "Migration: random lookup in datastore returned type %d.\n",
                 ntohl (value->type));
#endif
  if (ntohl (value->type) == GNUNET_ECRS_BLOCKTYPE_ONDEMAND)
    {
      if (GNUNET_FS_ONDEMAND_get_indexed_content
          (value, &rec->key, &enc) != GNUNET_OK)
        {
          GNUNET_free_non_null (value);
          rec->value = NULL;
          GNUNET_mutex_unlock (GNUNET_FS_lock);
#if DEBUG_MIGRATION
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         "Migration: failed to locate indexed content for migration.\n");
#endif
          GNUNET_FS_PT_change_rc (index, -1);
          return 0;
        }
      if (stats != NULL)
        stats->change (stat_on_demand_migration_attempts, 1);
      rec->value = enc;
      GNUNET_free (value);
      value = enc;
    }
  size =
    sizeof (P2P_gap_reply_MESSAGE) + ntohl (value->size) -
    sizeof (GNUNET_DatastoreValue);
  if (size > padding)
    {
      GNUNET_mutex_unlock (GNUNET_FS_lock);
#if DEBUG_MIGRATION
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Migration: available content too big (%u > %u) for migration.\n",
                     size, padding);
#endif
      GNUNET_FS_PT_change_rc (index, -1);
      return 0;
    }
  msg = position;
  et = GNUNET_ntohll (value->expiration_time);
  if (et > now)
    et -= now;
  else
    et = 0;
  if (ntohl (value->type) == GNUNET_ECRS_BLOCKTYPE_KEYWORD)
    et %= GNUNET_GAP_MAX_MIGRATION_EXP_KSK;
  else
    et %= GNUNET_GAP_MAX_MIGRATION_EXP;
  anonymity = ntohl (value->anonymity_level);
  ret = 0;
  if ((anonymity == 0) ||
      (GNUNET_OK == GNUNET_FS_ANONYMITY_check (anonymity,
                                               GNUNET_P2P_PROTO_GAP_RESULT)))
    {
      msg->header.type = htons (GNUNET_P2P_PROTO_GAP_RESULT);
      msg->header.size = htons (size);
      msg->reserved = htonl (0);
      msg->expiration = GNUNET_htonll (et);
      memcpy (&msg[1], &value[1], size - sizeof (P2P_gap_reply_MESSAGE));
      ret = size;
      if (rec->sentCount == MAX_RECEIVERS)
        {
          GNUNET_free (rec->value);
          rec->value = NULL;
          GNUNET_FS_PT_decrement_rcs (rec->receiverIndices, rec->sentCount);
          rec->sentCount = 0;
        }
      else
        {
          rec->receiverIndices[rec->sentCount++] = index;
          GNUNET_FS_PT_change_rc (index, 1);
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
  GNUNET_mutex_unlock (GNUNET_FS_lock);
  if ((ret > 0) && (stats != NULL))
    stats->change (stat_migration_count, 1);
  GNUNET_GE_BREAK (NULL, ret <= padding);
  GNUNET_FS_PT_change_rc (index, -1);
  return ret;
}
#endif

/**
 * Make a piece of content that we have received
 * available for transmission via migration.
 *
 * @param size size of value
 * @param value the content to make available
 * @param expiration expiration time for value
 * @param blocked_size size of the list of PID_INDEX variables
 *            refering to peers that must NOT receive
 *            the content using migration
 * @param block blocked peers
 */
void
GNUNET_FS_MIGRATION_inject (const GNUNET_HashCode * key,
                            unsigned int size,
                            const GNUNET_EC_DBlock * value,
                            GNUNET_CronTime expiration,
                            unsigned int blocked_size,
                            const PID_INDEX * blocked)
{
#if ENABLE_MIGRATION
  int i;
  int discard_entry;
  int discard_count;
  struct MigrationRecord *record;

  if (content_size == 0)
    return;
  GNUNET_mutex_lock (GNUNET_FS_lock);
  discard_entry = -1;
  discard_count = 0;
  for (i = 0; i < content_size; i++)
    {
      record = &content[i];
      if (record->value == NULL)
        {
          discard_entry = i;
          break;
        }
      if (discard_count < record->sentCount)
        {
          discard_entry = i;
          discard_count = record->sentCount;
        }
    }
  if (discard_entry == -1)
    {
      GNUNET_mutex_unlock (GNUNET_FS_lock);
      return;
    }
  if (stats != NULL)
    stats->change (stat_migration_injected, 1);
  record = &content[discard_entry];
  GNUNET_free_non_null (record->value);
  record->value = NULL;
  GNUNET_FS_PT_decrement_rcs (record->receiverIndices, record->sentCount);
  record->sentCount = 0;
  record->key = *key;
  record->value = GNUNET_malloc (size + sizeof (GNUNET_DatastoreValue));
  record->value->size = htonl (size + sizeof (GNUNET_DatastoreValue));
  record->value->expiration_time = GNUNET_htonll (expiration);
  record->value->anonymity_level = 0;
  record->value->type = value->type;
  memcpy (&record->value[1], value, size);
  for (i = 0; i < blocked_size; i++)
    {
      record->receiverIndices[i] = blocked[i];
      GNUNET_FS_PT_change_rc (blocked[i], 1);
    }
  record->sentCount = blocked_size;
  GNUNET_mutex_unlock (GNUNET_FS_lock);
#endif
}

void
GNUNET_FS_MIGRATION_init (GNUNET_CoreAPIForPlugins * capi)
{
#if ENABLE_MIGRATION
  unsigned long long option_value;

  coreAPI = capi;
  coreAPI->send_callback_register
    (GNUNET_GAP_ESTIMATED_DATA_SIZE,
     GNUNET_FS_GAP_CONTENT_MIGRATION_PRIORITY, &activeMigrationCallback);
  datastore = capi->service_request ("datastore");
  stats = capi->service_request ("stats");
  if (stats != NULL)
    {
      stat_migration_count
        = stats->create (gettext_noop ("# blocks migrated"));
      stat_migration_injected
        = stats->create (gettext_noop ("# blocks injected for migration"));
      stat_migration_factor
        = stats->create (gettext_noop ("# blocks fetched for migration"));
      stat_on_demand_migration_attempts
        = stats->create (gettext_noop ("# on-demand fetches for migration"));
    }
  GNUNET_GC_get_configuration_value_number (capi->cfg,
                                            "FS",
                                            "MIGRATIONBUFFERSIZE",
                                            0,
                                            1024 * 1024, 64, &option_value);
  GNUNET_array_grow (content, content_size, (unsigned int) option_value);
#endif
}

void
GNUNET_FS_MIGRATION_done ()
{
#if ENABLE_MIGRATION
  int i;
  struct MigrationRecord *record;

  coreAPI->send_callback_unregister
    (GNUNET_GAP_ESTIMATED_DATA_SIZE, &activeMigrationCallback);
  if (stats != NULL)
    {
      coreAPI->service_release (stats);
      stats = NULL;
    }
  coreAPI->service_release (datastore);
  datastore = NULL;
  coreAPI = NULL;
  for (i = 0; i < content_size; i++)
    {
      record = &content[i];
      GNUNET_free_non_null (record->value);
      record->value = NULL;
      GNUNET_FS_PT_decrement_rcs (record->receiverIndices, record->sentCount);
    }
  GNUNET_array_grow (content, content_size, 0);
  lock = NULL;
#endif
}

/* end of migration.c */
