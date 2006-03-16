/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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

#define DEBUG_MIGRATION NO

/**
 * Datastore service.
 */
static Datastore_ServiceAPI * datastore;

/**
 * Global core API.
 */
static CoreAPIForApplication * coreAPI;

/**
 * GAP service.
 */
static GAP_ServiceAPI * gap;

/**
 * DHT service.  Maybe NULL!
 */
static DHT_ServiceAPI * dht;

/**
 * Traffic service.
 */
static Traffic_ServiceAPI * traffic;

static Stats_ServiceAPI * stats;

static int stat_migration_count;

/**
 * Lock used to access content.
 */
static Mutex lock;

/**
 * The content that we are currently trying
 * to migrate (used to give us more than one
 * chance should we fail for some reason the
 * first time).
 */
static Datastore_Value * content;

				
/**
 * Callback method for pushing content into the network.
 * The method chooses either a "recently" deleted block
 * or content that has a hash close to the receiver ID
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
activeMigrationCallback(const PeerIdentity * receiver,
			void * position,
			unsigned int padding) {
  unsigned int ret;
  HashCode512 key;
  GapWrapper * gw;
  unsigned int size;
  cron_t et;
  cron_t now;
  unsigned int anonymity;

  MUTEX_LOCK(&lock);
  if (content != NULL) {
    size = sizeof(GapWrapper) + ntohl(content->size) - sizeof(Datastore_Value);
    if (size > padding) {
      FREE(content);
      content = NULL;
    }
  }
  if (content == NULL) {
    if (OK != datastore->getRandom(&receiver->hashPubKey,
				   padding,
				   &key,
				   &content,
				   0)) {
      MUTEX_UNLOCK(&lock);
#if DEBUG_MIGRATION
      LOG(LOG_DEBUG,
	  "Migration: random lookup in datastore failed.\n");
#endif
      return 0;
    }
  }
  size = sizeof(GapWrapper) + ntohl(content->size) - sizeof(Datastore_Value);
  if (size > padding) {
    MUTEX_UNLOCK(&lock);
#if DEBUG_MIGRATION
    LOG(LOG_DEBUG,
	"Available content of size %u too big for available space (%u)\n",
	size, 
	padding);
#endif
    return 0;
  }
  et = ntohll(content->expirationTime);
  cronTime(&now);
  if (et > now) {
    et -= now;
    et = et % MAX_MIGRATION_EXP;
    et += now;
  }
  anonymity = ntohl(content->anonymityLevel);
  ret = 0;
  if (anonymity == 0) {
    /* ret > 0; (if DHT succeeds) fixme for DHT */
  }
  if ( (ret == 0) &&
       (OK == checkCoverTraffic(traffic,
				anonymity)) ) {
    gw = MALLOC(size);
    gw->dc.size = htonl(size);
    gw->timeout = htonll(et);
    memcpy(&gw[1],
	   &content[1],
	   size - sizeof(GapWrapper));
    ret = gap->tryMigrate(&gw->dc,
			  &key,
			  position,
			  padding);
    FREE(gw);
#if DEBUG_MIGRATION
    LOG(LOG_DEBUG,
	"gap's tryMigrate returned %u\n",
	ret);
#endif

  } else {
#if DEBUG_MIGRATION
    LOG(LOG_DEBUG,
	"Migration: anonymity requirements not satisfied.\n");
#endif
  }
  if (ret > 0) {
    FREE(content);
    content = NULL;
  }
  MUTEX_UNLOCK(&lock);
  if ( (ret > 0)&&
       (stats != NULL) )
      stats->change(stat_migration_count, 1); 

  return ret;
}

void initMigration(CoreAPIForApplication * capi,
		   Datastore_ServiceAPI * ds,
		   GAP_ServiceAPI * g,
		   DHT_ServiceAPI * d,
		   Traffic_ServiceAPI * t) {
  MUTEX_CREATE(&lock);
  coreAPI = capi;
  datastore = ds;
  gap = g;
  dht = d;
  traffic = t;
  coreAPI->registerSendCallback(512,
				&activeMigrationCallback);
  stats = capi->requestService("stats");
  if (stats != NULL) 
    stat_migration_count = stats->create(gettext_noop("# blocks migrated"));

}

void doneMigration() {
  coreAPI->unregisterSendCallback(512,
				  &activeMigrationCallback);
  if (stats != NULL) {
    coreAPI->releaseService(stats);
    stats = NULL;
  }
  datastore = NULL;
  gap = NULL;
  dht = NULL;
  coreAPI = NULL;
  traffic = NULL;
  FREENONNULL(content);
  content = NULL;
  MUTEX_DESTROY(&lock);
}

/* end of migration.c */
