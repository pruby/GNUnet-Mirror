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
 * @file fs/gap/fs_dht.h
 * @brief integration of file-sharing with the DHT
 *        infrastructure
 * @author Christian Grothoff
 */
#ifndef FS_DHT_H
#define FS_DHT_H

#include "gnunet_util.h"

int GNUNET_FS_DHT_init (GNUNET_CoreAPIForPlugins * capi);

int GNUNET_FS_DHT_done (void);

/**
 * Execute a GAP query.  Determines where to forward
 * the query and when (and captures state for the response).
 * May also have to check the local datastore.
 *
 * @param type type of content requested
 * @param querie hash code of the query
 */
void
GNUNET_FS_DHT_execute_query (unsigned int type,
                             const GNUNET_HashCode * query);

#endif
