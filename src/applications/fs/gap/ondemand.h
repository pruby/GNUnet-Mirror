/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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

/*/
 * @file applications/fs/gap/ondemand.h
 * @brief functions for handling on-demand encoding
 * @author Christian Grothoff
 */
#ifndef ONDEMAND_H
#define ONDEMAND_H

#include "gnunet_core.h"
#include "gnunet_datastore_service.h"
#include "ecrs_core.h"

/**
 * A query on the datastore resulted in the on-demand
 * block dbv.  On-demand encode the block and return
 * the resulting DSV in enc.  If the on-demand
 * encoding fails because the file is no longer there,
 * this function also removes the OD-Entry
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR if there was an error
 */
int
GNUNET_FS_ONDEMAND_get_indexed_content (const GNUNET_DatastoreValue * dbv,
                                        const GNUNET_HashCode * query,
                                        GNUNET_DatastoreValue ** enc);


/**
 * Creates a symlink to the given file in the shared directory
 *
 * @param fn the file that was indexed
 * @param fileId the file's GNUNET_hash code
 * @return GNUNET_SYSERR on error, GNUNET_NO if symlinking failed,
 *         GNUNET_YES on success
 */
int
GNUNET_FS_ONDEMAND_index_prepare_with_symlink (struct GNUNET_GE_Context
                                               *cectx,
                                               const GNUNET_HashCode * fileId,
                                               const char *fn);

/**
 * Writes the given content to the file at the specified offset
 * and stores an OnDemandBlock into the datastore.
 *
 * @return GNUNET_NO if already present, GNUNET_YES on success,
 *  GNUNET_SYSERR on other error (i.e. datastore full)
 */
int
GNUNET_FS_ONDEMAND_add_indexed_content (struct GNUNET_GE_Context *cectx,
                                        GNUNET_Datastore_ServiceAPI *
                                        datastore, unsigned int prio,
                                        GNUNET_CronTime expiration,
                                        unsigned long long fileOffset,
                                        unsigned int anonymityLevel,
                                        const GNUNET_HashCode * fileId,
                                        unsigned int size,
                                        const DBlock * content);

/**
 * Test if the file with the given ID is
 * indexed.
 * @return GNUNET_YES if so, GNUNET_NO if not.
 */
int
GNUNET_FS_ONDEMAND_test_indexed_file (GNUNET_Datastore_ServiceAPI * datastore,
                                      const GNUNET_HashCode * fileId);

/**
 * Unindex the file with the given ID.  Removes the file from the
 * filesystem and all of the corresponding obd blocks from the
 * datastore.  Note that the IBlocks are NOT removed by this function.
 *
 * @param blocksize the size of each of the
 *        indexed blocks (required to break
 *        up the file properly when computing
 *        the keys of the odb blocks).
 */
int
GNUNET_FS_ONDEMAND_delete_indexed_content (struct GNUNET_GE_Context *cectx,
                                           GNUNET_Datastore_ServiceAPI *
                                           datastore, unsigned int blocksize,
                                           const GNUNET_HashCode * fileId);

int GNUNET_FS_ONDEMAND_init (GNUNET_CoreAPIForPlugins * capi);

int GNUNET_FS_ONDEMAND_done (void);

#endif
