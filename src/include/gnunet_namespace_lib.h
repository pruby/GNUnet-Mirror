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
 * @param publicationFrequency how often are updates scheduled?
 * @param nextPublicationTime the scheduled time for the
 *  next update (0 for sporadic updates)
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_NS_UpdateIterator) (void *cls,
                                         const GNUNET_ECRS_FileInfo * uri,
                                         const GNUNET_HashCode * lastId,
                                         const GNUNET_HashCode * nextId,
                                         GNUNET_Int32Time
                                         publicationFrequency,
                                         GNUNET_Int32Time
                                         nextPublicationTime);

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
                                                    GNUNET_ECRS_MetaData
                                                    *meta,
                                                    const struct
                                                    GNUNET_ECRS_URI
                                                    *advertisementURI,
                                                    const GNUNET_HashCode *
                                                    rootEntry);

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
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int GNUNET_NS_namespace_get_root (struct GNUNET_GE_Context *ectx,
                                  struct GNUNET_GC_Configuration *cfg,
                                  const GNUNET_HashCode * nsid,
                                  GNUNET_HashCode * root);

void GNUNET_NS_namespace_set_root (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const struct GNUNET_ECRS_URI *uri);

/**
 * Add an entry into a namespace (also for publishing
 * updates).  Typical uses are (all others would be odd):
 * <ul>
 *  <li>updateInterval NONE, thisId some user-specified value
 *      or NULL if user wants system to pick random value;
 *      nextId and lastId NULL (irrelevant)</li>
 *  <li>updateInterval SPORADIC, thisId given (initial
 *      submission), nextId maybe given or NULL,
 *      lastId NULL</li>
 *  <li>updateInterval SPORADIC, lastId given (either
 *      user-provided or from listNamespaceContent
 *      iterator); thisId NULL or given (from lNC);
 *      nextId maybe given or NULL, depending on user preference</li>
 *  <li>updateInterval non-NULL, non-SPORADIC; lastId
 *      is NULL (inital submission), thisId non-NULL or
 *      rarely NULL (if user does not care about name of
 *      starting entry), nextId maybe NULL or not</li>
 *  <li>updateInterval non-NULL, non-SPORADIC; lastId
 *      is non-NULL (periodic update), thisId NULL (computed!)
 *      nextID NULL (computed)</li>
 * </ul>
 * And yes, reading the ECRS paper maybe a good idea.
 *
 * @param nsid in which namespace to publish
 * @param updateInterval the desired frequency for updates
 * @param lastId the ID of the last value (maybe NULL)
 *        set if this is an update to an existing entry
 * @param thisId the ID of the update (maybe NULL if
 *        lastId determines the value or if no specific value
 *        is desired)
 * @param nextId the ID of the next update (maybe NULL);
 *        set for sporadic updates if a specific next ID is
 *        desired
 * @param dst to which URI should the namespace entry refer?
 * @param md what meta-data should be associated with the
 *        entry?
 * @return the resulting URI, NULL on error
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
                                                    GNUNET_Int32Time
                                                    updateInterval,
                                                    const GNUNET_HashCode *
                                                    lastId,
                                                    const GNUNET_HashCode *
                                                    thisId,
                                                    const GNUNET_HashCode *
                                                    nextId,
                                                    const struct
                                                    GNUNET_ECRS_URI *dst,
                                                    const struct
                                                    GNUNET_ECRS_MetaData *md);

/**
 * Compute the next ID for peridodically updated content.
 * @param updateInterval MUST be a peridic interval (not NONE or SPORADIC)
 * @param thisId MUST be known to NS
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_NS_compute_next_identifier (struct GNUNET_GE_Context *ectx,
                                       struct GNUNET_GC_Configuration *cfg,
                                       const GNUNET_HashCode * nsid,
                                       const GNUNET_HashCode * lastId,
                                       const GNUNET_HashCode * thisId,
                                       GNUNET_Int32Time updateInterval,
                                       GNUNET_HashCode * nextId);

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
