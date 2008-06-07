/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_namespace_lib.h
 * @brief high-level support for namespaces
 * @author Christian Grothoff
 */

#ifndef GNUNET_NAMESPACE_LIB_H
#define GNUNET_NAMESPACE_LIB_H

#include "gnunet_ecrs_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Iterator over all updateable content.
 *
 * @param uri URI of the last content published
 * @param lastId the ID of the last publication
 * @param nextId the ID of the next update
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_NS_UpdateIterator) (void *cls,
                                         const GNUNET_ECRS_FileInfo * uri,
                                         const char *lastId,
                                         const char *nextId);

/**
 * Create a new namespace (and publish an advertismement).
 * This function is synchronous, but may block the system
 * for a while since it must create a public-private key pair!
 *
 * @param meta meta-data about the namespace (maybe NULL)
 * @return URI on success, NULL on error (namespace already exists)
 */
struct GNUNET_ECRS_URI *GNUNET_NS_namespace_create (struct GNUNET_GE_Context
                                                    *ectx,
                                                    struct
                                                    GNUNET_GC_Configuration
                                                    *cfg,
                                                    unsigned int
                                                    anonymityLevel,
                                                    unsigned int
                                                    insertPriority,
                                                    GNUNET_CronTime
                                                    insertExpiration,
                                                    const struct
                                                    GNUNET_MetaData
                                                    *meta,
                                                    const struct
                                                    GNUNET_ECRS_URI
                                                    *advertisementURI,
                                                    const char *rootEntry);

/**
 * Delete a local namespace.  Only prevents future insertions into the
 * namespace, does not delete any content from the network!
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_NS_namespace_delete (struct GNUNET_GE_Context *ectx,
                                struct GNUNET_GC_Configuration *cfg,
                                const GNUNET_HashCode * nsid);

/**
 * Get the root of the namespace (if we have one).
 * @return NULL on error, root on success
 */
char *GNUNET_NS_namespace_get_root (struct GNUNET_GE_Context *ectx,
                                    struct GNUNET_GC_Configuration *cfg,
                                    const GNUNET_HashCode * nsid);

void GNUNET_NS_namespace_set_root (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const struct GNUNET_ECRS_URI *uri);

/**
 * Add an entry into a namespace (also for publishing
 * updates).
 *
 * @param nsid in which namespace to publish
 * @param thisId the ID of the current value
 * @param nextId the ID of a possible future update, NULL for
 *        content that can not be updated
 * @param dst to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @return the resulting SKS URI, NULL on error
 */
struct GNUNET_ECRS_URI *GNUNET_NS_add_to_namespace (struct GNUNET_GE_Context
                                                    *ectx,
                                                    struct
                                                    GNUNET_GC_Configuration
                                                    *cfg,
                                                    unsigned int
                                                    anonymityLevel,
                                                    unsigned int
                                                    insertPriority,
                                                    GNUNET_CronTime
                                                    insertExpiration,
                                                    const GNUNET_HashCode *
                                                    nsid,
                                                    const char *thisId,
                                                    const char *nextId,
                                                    const struct
                                                    GNUNET_ECRS_URI *dst,
                                                    const struct
                                                    GNUNET_MetaData *md);

/**
 * List all updateable content in a given namespace.
 */
int GNUNET_NS_namespace_list_contents (struct GNUNET_GE_Context *ectx,
                                       struct GNUNET_GC_Configuration *cfg,
                                       const GNUNET_HashCode * nsid,
                                       GNUNET_NS_UpdateIterator iterator,
                                       void *closure);

/**
 * Convert namespace URI to a human readable format
 * (using the namespace description, if available).
 */
char *GNUNET_NS_sks_uri_to_human_readable_string (struct GNUNET_GE_Context
                                                  *ectx,
                                                  struct
                                                  GNUNET_GC_Configuration
                                                  *cfg,
                                                  const struct GNUNET_ECRS_URI
                                                  *uri);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
