/*
     This file is part of GNUnet
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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

#define EXTRA_CHECKS YES

/**
 * Creates a symlink to the given file in the shared directory
 * @return SYSERR on error, NO if symlinking failed,
 *         YES on success
 */
int ONDEMAND_initIndex(const HashCode512 * fileId,
		       const char *fn);

/**
 * @return NO if already present, YES on success,
 *  SYSERR on other error (i.e. datastore full)
 */
int ONDEMAND_index(Datastore_ServiceAPI * datastore,
		   unsigned int prio,
		   cron_t expiration,
		   unsigned long long fileOffset,
		   unsigned int anonymityLevel,
		   const HashCode512 * fileId,
		   unsigned int size,
		   const DBlock * content);

/**
 * A query on the datastore resulted in the on-demand
 * block odb.  On-demand encode the block and return
 * the resulting DSV in enc.  If the on-demand
 * encoding fails because the file is no longer there,
 * this function also removes the OD-Entry
 * @return OK on success, SYSERR if there was an error
 */
int ONDEMAND_getIndexed(Datastore_ServiceAPI * datastore,
			const Datastore_Value * odb,
			const HashCode512 * query,
			Datastore_Value ** enc);

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
int ONDEMAND_unindex(Datastore_ServiceAPI * datastore,
		     unsigned int blocksize,
		     const HashCode512 * fileId);

/**
 * Test if the file with the given ID is
 * indexed.
 * @return YES if so, NO if not.
 */
int ONDEMAND_testindexed(Datastore_ServiceAPI * datastore,
			 const HashCode512 * fileId);

/* end of ondemand.h */
#endif
