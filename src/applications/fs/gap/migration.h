/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2008 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @brief This module is responsible for pushing content out
 *         into the network.
 * @file applications/fs/gap/migration.h
 */
#ifndef MIGRATION_H
#define MIGRATION_H

#include "gnunet_core.h"
#include "ecrs_core.h"
#include "gnunet_datastore_service.h"
#include "pid_table.h"

/**
 * Initialize the migration module.
 */
void GNUNET_FS_MIGRATION_init (GNUNET_CoreAPIForPlugins * capi);

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
void GNUNET_FS_MIGRATION_inject (const GNUNET_HashCode * key,
                                 unsigned int size,
                                 const GNUNET_EC_DBlock * value,
                                 GNUNET_CronTime expiration,
                                 unsigned int blocked_size,
                                 const PID_INDEX * blocked);

void GNUNET_FS_MIGRATION_done (void);

/* end of migration.h */
#endif
