/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * Iterator over all namespaces.
 *
 * @param rating the local rating of the namespace
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_NS_NamespaceIterator) (void *cls,
                                            const char *namespaceName,
                                            const GNUNET_HashCode *
                                            namespaceId,
                                            const struct GNUNET_ECRS_MetaData
                                            * md, int rating);

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
struct GNUNET_ECRS_URI *GNUNET_NS_namespace_create (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, unsigned int anonymityLevel, unsigned int insertPriority, GNUNET_CronTime insertExpiration, const char *namespaceName, const struct GNUNET_ECRS_MetaData *meta, const struct GNUNET_ECRS_URI *advertisementURI, const GNUNET_HashCode * rootEntry);    /* namespace_info.c */

/**
 * Delete a local namespace.  Only prevents future insertions into the
 * namespace, does not delete any content from the network!
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_NS_namespace_delete (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *namespaceName);        /* namespace.c */

/**
 * Change the ranking of a (non-local) namespace.
 *
 * @param ns the name of the namespace, as obtained
 *  from GNUNET_ECRS_get_namespace_name
 * @param delta by how much should the rating be
 *  changed?
 * @return new rating of the namespace
 */
int GNUNET_NS_namespace_rank (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *ns, int delta);  /* namespace_info.c */

/**
 * Add a namespace to the set of known namespaces.  For all namespace
 * advertisements that we discover this function should be
 * callled.
 *
 * @param ns the namespace identifier
 */
void GNUNET_NS_namespace_add_information (struct GNUNET_GE_Context *ectx,
                                          struct GNUNET_GC_Configuration *cfg,
                                          const struct GNUNET_ECRS_URI *uri,
                                          const struct GNUNET_ECRS_MetaData
                                          *meta);


/**
 * Get the root of the namespace (if we have one).
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int GNUNET_NS_namespace_get_root (struct GNUNET_GE_Context *ectx,
                                  struct GNUNET_GC_Configuration *cfg,
                                  const char *ns, GNUNET_HashCode * root);

void GNUNET_NS_namespace_set_root (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const struct GNUNET_ECRS_URI *uri);

/**
 * List all available (local or non-local) namespaces.
 */
int GNUNET_NS_namespace_list_all (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, GNUNET_NS_NamespaceIterator iterator, void *closure);    /* namespace_info.c */

/**
 * Register callback to be invoked whenever we discover
 * a new namespace.
 */
int GNUNET_NS_register_discovery_callback (struct GNUNET_GE_Context *ectx,
                                           struct GNUNET_GC_Configuration
                                           *cfg,
                                           GNUNET_NS_NamespaceIterator
                                           iterator, void *closure);

/**
 * Unregister namespace discovery callback.
 */
int GNUNET_NS_unregister_discovery_callback (GNUNET_NS_NamespaceIterator
                                             iterator, void *closure);



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
 * @param name in which namespace to publish
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
struct GNUNET_ECRS_URI *GNUNET_NS_add_to_namespace (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, unsigned int anonymityLevel, unsigned int insertPriority, GNUNET_CronTime insertExpiration, const char *name, GNUNET_Int32Time updateInterval, const GNUNET_HashCode * lastId, const GNUNET_HashCode * thisId, const GNUNET_HashCode * nextId, const struct GNUNET_ECRS_URI *dst, const struct GNUNET_ECRS_MetaData *md);      /* namespace_info.c */

/**
 * Compute the next ID for peridodically updated content.
 * @param updateInterval MUST be a peridic interval (not NONE or SPORADIC)
 * @param thisId MUST be known to NS
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_NS_compute_next_identifier (struct GNUNET_GE_Context *ectx,
                                       struct GNUNET_GC_Configuration *cfg,
                                       const char *name,
                                       const GNUNET_HashCode * lastId,
                                       const GNUNET_HashCode * thisId,
                                       GNUNET_Int32Time updateInterval,
                                       GNUNET_HashCode * nextId);

/**
 * List all updateable content in a given namespace.
 */
int GNUNET_NS_namespace_list_contents (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *name, GNUNET_NS_UpdateIterator iterator, void *closure);        /* namespace_info.c */




#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
