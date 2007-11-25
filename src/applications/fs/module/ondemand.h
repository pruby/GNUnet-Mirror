/*
     This file is part of GNUnet
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/module/ondemand.h
 * @brief On-demand encoding of indexed files
 * @author Christian Grothoff
 */

#ifndef ONDEMAND_H
#define ONDEMAND_H

#include "gnunet_util.h"
#include "gnunet_datastore_service.h"
#include "ecrs_core.h"

#define EXTRA_CHECKS ALLOW_EXTRA_CHECKS

/**
 * Creates a symlink to the given file in the shared directory
 * @return GNUNET_SYSERR on error, GNUNET_NO if symlinking failed,
 *         GNUNET_YES on success
 */
int ONDEMAND_initIndex (struct GNUNET_GE_Context *cectx,
                        const GNUNET_HashCode * fileId, const char *fn);

/**
 * @return GNUNET_NO if already present, GNUNET_YES on success,
 *  GNUNET_SYSERR on other error (i.e. datastore full)
 */
int ONDEMAND_index (struct GNUNET_GE_Context *cectx,
                    GNUNET_Datastore_ServiceAPI * datastore,
                    unsigned int prio,
                    GNUNET_CronTime expiration,
                    unsigned long long fileOffset,
                    unsigned int anonymityLevel,
                    const GNUNET_HashCode * fileId,
                    unsigned int size, const DBlock * content);

/**
 * A query on the datastore resulted in the on-demand
 * block odb.  On-demand encode the block and return
 * the resulting DSV in enc.  If the on-demand
 * encoding fails because the file is no longer there,
 * this function also removes the OD-Entry
 * @return GNUNET_OK on success, GNUNET_SYSERR if there was an error
 */
int ONDEMAND_getIndexed (GNUNET_Datastore_ServiceAPI * datastore,
                         const GNUNET_DatastoreValue * odb,
                         const GNUNET_HashCode * query,
                         GNUNET_DatastoreValue ** enc);

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
int ONDEMAND_unindex (struct GNUNET_GE_Context *cectx,
                      GNUNET_Datastore_ServiceAPI * datastore,
                      unsigned int blocksize, const GNUNET_HashCode * fileId);

/**
 * Test if the file with the given ID is
 * indexed.
 * @return GNUNET_YES if so, GNUNET_NO if not.
 */
int ONDEMAND_testindexed (GNUNET_Datastore_ServiceAPI * datastore,
                          const GNUNET_HashCode * fileId);

int ONDEMAND_init (GNUNET_CoreAPIForPlugins * capi);

int ONDEMAND_done (void);

/* end of ondemand.h */
#endif
