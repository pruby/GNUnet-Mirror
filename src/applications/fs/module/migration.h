/*
     This file is part of GNUnet.
     (C) 2001, 2002 Christian Grothoff (and other contributing authors)

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
 * This module is responsible for pushing content out
 * into the network.
 *
 * @author Christian Grothoff
 * @file applications/fs/module/migration.h
 */
#ifndef MIGRATION_H
#define MIGRATION_H

#include "gnunet_core.h"
#include "gnunet_datastore_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_gap_service.h"
#include "gnunet_traffic_service.h"


/**
 * What is the maximum expiration time for migrated content?
 *
 * This is a non-trivial issue.  If we have a ceiling for migration
 * time, it would violate anonymity if we send out content with an
 * expiration time above that ceiling (since it would expose the
 * content to originate from this peer).  But we want to store a
 * higher expiration time for our content in the DB.
 *
 * A first idea would be to pick a random time smaller than the limit
 * for outgoing content; that does not _quite_ work since that could
 * also expose us as the originator: only for our own content the
 * expiration time would randomly go up and down.
 *
 * The current best solution is to first bound the expiration time by
 * this ceiling (for inbound and outbound ETs, not for the database
 * entries locally) using modulo (to, in practice, get a constant
 * bound for the local content just like for the migrated content).
 * Then that number is randomized for _all_ outgoing content.  This
 * way, the time left changes for all entries, but statistically
 * always decreases on average as time progresses (also for all
 * entries).
 *
 * Now, for local content eventually modulo will rebound to the MAX
 * (whereas for migrated content it will hit 0 and disappear).  But
 * that is GNUNET_OK: the adversary cannot distinguish the modulo wraparound
 * from content migration (refresh with higher lifetime) which could
 * plausibly happen from the original node (and in fact would happen
 * around the same time!).  This design also achieves the design goal
 * that if the original node disappears, the migrated content will
 * eventually time-out (which is good since we don't want dangling
 * search results to stay around).
 *
 * However, this does NOT mean that migrated content cannot live
 * longer than 1 month -- remember, GNUnet peers discard expired
 * content _if they run out of space_.  So it is perfectly plausible
 * that content stays around longer.  Finally, clients (UI) may want
 * to filter / rank / display search results with their current
 * expiration to give the user some indication about availability.
 *
 */
#define MAX_MIGRATION_EXP (1L * GNUNET_CRON_MONTHS)

/**
 * Initialize the migration module.
 */
void initMigration (GNUNET_CoreAPIForPlugins * capi,
                    GNUNET_Datastore_ServiceAPI * s,
                    GNUNET_GAP_ServiceAPI * g,
                    GNUNET_DHT_ServiceAPI * d, GNUNET_Traffic_ServiceAPI * t);

void doneMigration (void);

/* end of migration.h */
#endif
