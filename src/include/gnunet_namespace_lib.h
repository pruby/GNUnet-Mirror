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
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Iterator over all namespaces.
 *
 * @param rating the local rating of the namespace
 * @return OK to continue iteration, SYSERR to abort
 */
typedef int (*NS_NamespaceIterator)(void * cls,
				    const char * namespaceName,
				    const HashCode512 * namespaceId,
				    const struct ECRS_MetaData * md,
				    int rating);

/**
 * Iterator over all updateable content.
 *
 * @param uri URI of the last content published
 * @param lastId the ID of the last publication
 * @param nextId the ID of the next update
 * @param publicationFrequency how often are updates scheduled?
 * @param nextPublicationTime the scheduled time for the
 *  next update (0 for sporadic updates)
 * @return OK to continue iteration, SYSERR to abort
 */
typedef int (*NS_UpdateIterator)(void * cls,
				 const ECRS_FileInfo * uri,
				 const HashCode512 * lastId,
				 const HashCode512 * nextId,
				 TIME_T publicationFrequency,
				 TIME_T nextPublicationTime);

/**
 * Create a new namespace (and publish an advertismement).
 * This function is synchronous, but may block the system
 * for a while since it must create a public-private key pair!
 *
 * @param meta meta-data about the namespace (maybe NULL)
 * @return URI on success, NULL on error (namespace already exists)
 */
struct ECRS_URI *
NS_createNamespace(struct GE_Context * ectx,
		   struct GC_Configuration * cfg,
		   unsigned int anonymityLevel,
		   unsigned int insertPriority,
		   cron_t insertExpiration,
		   const char * namespaceName,
		   const struct ECRS_MetaData * meta,
		   const struct ECRS_URI * advertisementURI,
		   const HashCode512 * rootEntry); /* namespace_info.c */

/**
 * Delete a local namespace.  Only prevents future insertions into the
 * namespace, does not delete any content from the network!
 *
 * @return OK on success, SYSERR on error
 */
int NS_deleteNamespace(struct GE_Context * ectx,
		       struct GC_Configuration * cfg,
		       const char * namespaceName); /* namespace.c */

/**
 * Change the ranking of a (non-local) namespace.
 *
 * @param ns the name of the namespace, as obtained
 *  from ECRS_getNamespaceName
 * @param delta by how much should the rating be
 *  changed?
 * @return new rating of the namespace
 */
int NS_rankNamespace(struct GE_Context * ectx,
		     struct GC_Configuration * cfg,
		     const char * ns,
		     int delta); /* namespace_info.c */

/**
 * Add a namespace to the set of known namespaces.  For all namespace
 * advertisements that we discover this function should be
 * callled.
 *
 * @param ns the namespace identifier
 */
void NS_addNamespaceInfo(struct GE_Context * ectx,
			 struct GC_Configuration * cfg,
			 const struct ECRS_URI * uri,
			 const struct ECRS_MetaData * meta);


/**
 * Get the root of the namespace (if we have one).
 * @return SYSERR on error, OK on success
 */
int NS_getNamespaceRoot(struct GE_Context * ectx,
			struct GC_Configuration * cfg,
			const char * ns,
			HashCode512 * root);

void NS_setNamespaceRoot(struct GE_Context * ectx,
			 struct GC_Configuration * cfg,
			 const struct ECRS_URI * uri);

/**
 * List all available (local or non-local) namespaces.
 */
int NS_listNamespaces(struct GE_Context * ectx,
		      struct GC_Configuration * cfg,
		      NS_NamespaceIterator iterator,
		      void * closure); /* namespace_info.c */
/**
 * Register callback to be invoked whenever we discover
 * a new namespace.
 */
int NS_registerDiscoveryCallback(struct GE_Context * ectx,
				 struct GC_Configuration * cfg,
				 NS_NamespaceIterator iterator,
				 void * closure);

/**
 * Unregister namespace discovery callback.
 */
int NS_unregisterDiscoveryCallback(NS_NamespaceIterator iterator,
				   void * closure);



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
struct ECRS_URI *
NS_addToNamespace(struct GE_Context * ectx,
		  struct GC_Configuration * cfg,
		  unsigned int anonymityLevel,
		  unsigned int insertPriority,
		  cron_t insertExpiration,
		  const char * name,
		  TIME_T updateInterval,
		  const HashCode512 * lastId,
		  const HashCode512 * thisId,
		  const HashCode512 * nextId,
		  const struct ECRS_URI * dst,
		  const struct ECRS_MetaData * md); /* namespace_info.c */

/**
 * Compute the next ID for peridodically updated content.
 * @param updateInterval MUST be a peridic interval (not NONE or SPORADIC)
 * @param thisId MUST be known to NS
 * @return OK on success, SYSERR on error
 */
int NS_computeNextId(struct GE_Context * ectx,
		     struct GC_Configuration * cfg,
		     const char * name,
		     const HashCode512 * lastId,
		     const HashCode512 * thisId,
		     TIME_T updateInterval,
		     HashCode512 * nextId);

/**
 * List all updateable content in a given namespace.
 */
int NS_listNamespaceContent(struct GE_Context * ectx,
			    struct GC_Configuration * cfg,
			    const char * name,
			    NS_UpdateIterator iterator,
			    void * closure); /* namespace_info.c */




#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
