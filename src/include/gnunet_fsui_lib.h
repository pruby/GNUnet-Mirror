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
 * @file include/gnunet_fsui_lib.h
 * @brief support for FS user interfaces
 * @author Christian Grothoff
 *
 * Writing a UI for GNUnet is now easier then ever before.  Basically,
 * the UI first calls FSUI_start, passing a callback that the UI uses
 * to process events (like completed downloads, search results, etc.).
 * The event processor does not have to be re-entrant, FSUI will only
 * call it once at a time (but possibly from different threads, the
 * event processor also may have to worry about synchronizing itself
 * with the GUI library to display updates).<p>
 *
 * After creating a FSUI_Context with FSUI_start the UI can start (or
 * cancel) uploads, downloads or searches.  The FSUI_Context can be
 * destroyed, when it is created again the next time all pending
 * operations are resumed (!).  Clients can use the various iterator
 * functions to obtain information about pending actions.<p>
 *
 * Note that there can only be one FSUI_Context for all clients.
 * Creating an FSUI_Context may _fail_ if any other UI is currently
 * running (for the same user).<p>
 *
 * Clients may use SOME functions of GNUnet's ECRS library, in
 * particular functions to deal with URIs and MetaData, but generally
 * FSUI functions should be preferred over ECRS functions (since FSUI
 * keeps state, performs additional tracking operations and avoids
 * blocking the client while operations are pending).<p>
 *
 * Closing an FSUI_Context may take a while as the context may need
 * to serialize some state and complete operations that may not be
 * interrupted (such as indexing / unindexing operations). If this
 * is not acceptable, clients should wait until all uploads and
 * unindexing operations have completed before attempting to close
 * the FSUI_Context.<p>
 *
 * Note that most of this code is completely new in GNUnet 0.7.0 and
 * thus still highly experimental.  Suggestions are welcome.
 */

#ifndef GNUNET_FSUI_LIB_H
#define GNUNET_FSUI_LIB_H

#include "gnunet_ecrs_lib.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Entry representing an FSUI download.  FSUI downloads form a tree
 * (for properly representing recursive downloads) with an invisible
 * root (for multiple parallel downloads).
 *
 * FSUI hands out references of this type to allow clients to access
 * information about active downloads.
 *
 * Structs of this type MUST NOT be stored in anything but local
 * variables (!) by FSUI clients.  This will ensure that the
 * references are always valid.
 */
struct FSUI_DownloadList;

/**
 * @brief types of FSUI events.
 */
enum FSUI_EventType {
  /**
   * We found a new search result.
   */
  FSUI_search_result,
  FSUI_search_error,
  FSUI_download_progress,
  FSUI_download_complete,
  FSUI_download_aborted,
  FSUI_download_error,
  FSUI_upload_progress,
  FSUI_upload_complete,
  FSUI_upload_error,
  FSUI_unindex_progress,
  FSUI_unindex_complete,
  FSUI_unindex_error,
  /**
   * Connection status with gnunetd changed.
   */
  FSUI_gnunetd_connected,
  /**
   * Connection status with gnunetd changed.
   */
  FSUI_gnunetd_disconnected,
  FSUI_download_suspending,
};

/**
 * @brief FSUI Event.
 */
typedef struct {
  enum FSUI_EventType type;
  union {
    struct {
      /**
       * File-Info of the data that was found.
       */
      ECRS_FileInfo fi;
     /**
       * The URI of the search for which data was
       * found.
       */
      struct ECRS_URI * searchURI;
    } SearchResult;
    /**
     * Download Progress information.  Also used
     * for download_completed event.
     */
    struct {
      /**
       * How far are we?
       */
      unsigned long long completed;
      /**
       * How large is the total download (as far
       * as known so far).
       */
      unsigned long long total;
      /**
       * Offset of the last block obtained.
       */
      unsigned long long last_offset;
      /**
       * The last block (in plaintext)
       */
      const void * last_block;
      /**
       * Size of the last block
       */
      unsigned int last_size;
      /**
       * Information about the download.
       */
      char * filename;
      /**
       * Original URI.
       */
      struct ECRS_URI * uri;
      /**
       * Estimated completion time.
       */
      cron_t eta;
      /**
       * Start time.
       */
      cron_t start_time;
      /**
       * Is this (part of) a recursive download?
       */
      int is_recursive;
      /**
       * If the download is recursive, what is the
       * main file? (otherwise equal to filename);
       */
      char * main_filename;
      /**
       * If the download is recursive, what is the
       * main URI? (otherwise equal to uri);
       */
      struct ECRS_URI * main_uri;
      /**
       * What file in the download tree are we
       * refering to?
       */
      struct FSUI_DownloadList * pos;
    } DownloadProgress;
    /**
     * DownloadError is used for both
     * download_aborted and download_error
     * message types.
     */
    struct {
      /**
       * Error message.
       */
      const char * message;
      /**
       * What file in the download tree are we
       * refering to?
       */
      struct FSUI_DownloadList * pos;
    } DownloadError;
    struct {
      /**
       * How far are we? (for the current file)
       */
      unsigned long long completed;
      /**
       * How large is the total upload (for the current file)
       */
      unsigned long long total;
      /**
       * Information about the upload.
       */
      char * filename;
      /**
       * Estimated completion time (for the current file)
       */
      cron_t eta;
      /**
       * How far are we? (for the recursive upload)
       */
      unsigned long long main_completed;
      /**
       * How large is the total upload (for the recursive upload)
       */
      unsigned long long main_total;
      /**
       * Estimated completion time (for the recursive upload)
       */
      cron_t main_eta;
      /**
       * Start time.
       */
      cron_t start_time;
      /**
       * Is this (part of) a recursive upload?
       */
      int is_recursive;
      /**
       * If the download is recursive, what is the
       * main file? (otherwise equal to filename);
       */
      char * main_filename;
    } UploadProgress;
    struct {
      /**
       * How large is the total upload.
       */
      unsigned long long total;
      /**
       * How much has been done so far.
       */
      unsigned long long completed;

      /**
       * Which file was uploaded?
       */
      char * filename;
      /**
       * URI of the uploaded file.
       */
      struct ECRS_URI * uri;
      /**
       * Estimated completion time for the entire
       * upload (!= now only for recursive uploads).
       */
      cron_t eta;
      /**
       * Start time.
       */
      cron_t start_time;
      /**
       * Is this (part of) a recursive upload?
       */
      int is_recursive;
      /**
       * If the download is recursive, what is the
       * main file? (otherwise equal to filename);
       */
      char * main_filename;
    } UploadComplete;
    struct {
      unsigned long long total;
      unsigned long long completed;
      cron_t eta;
      char * filename;
      cron_t start_time;
    } UnindexProgress;
    struct {
      unsigned long long total;
      char * filename;
      cron_t start_time;
    } UnindexComplete;
    /**
     * Used for errors.
     */
    char * message;
  } data;
} FSUI_Event;

/**
 * @brief opaque FSUI context
 */
struct FSUI_Context;

/**
 * Generic callback for all kinds of FSUI progress and error messages.
 * This function will be called for download progress, download
 * completion, upload progress and completion, search results, etc.
 *
 * The details of the argument format are yet to be defined.  What
 * FSUI guarantees is that only one thread at a time will call the
 * callback (so it need not be re-entrant).
 */
typedef void (*FSUI_EventCallback)(void * cls,
				   const FSUI_Event * event);

/**
 * Iterator over all namespaces.
 *
 * @param rating the local rating of the namespace
 * @return OK to continue iteration, SYSERR to abort
 */
typedef int (*FSUI_NamespaceIterator)(void * cls,
				      const char * namespaceName,
				      const HashCode512 * namespaceId,
				      const struct ECRS_MetaData * md,
				      int rating);

/**
 * Iterator over all searches and search results.
 *
 * @return OK to continue iteration, SYSERR to abort
 */
typedef int (*FSUI_SearchIterator)(void * cls,
				   const struct ECRS_URI * searchUri,
				   unsigned int anonymityLevel,
				   unsigned int resultCount,
				   const ECRS_FileInfo * results);

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
typedef int (*FSUI_UpdateIterator)(void * cls,
				   const ECRS_FileInfo * uri,
				   const HashCode512 * lastId,
				   const HashCode512 * nextId,
				   TIME_T publicationFrequency,
				   TIME_T nextPublicationTime);

/**
 * Iterator over active downloads.
 *
 * @param pos What file in the download tree are we
 * refering to?
 * @return OK to continue iteration, SYSERR to abort
 */
typedef int (*FSUI_DownloadIterator)(void * cls,
				     const struct FSUI_DownloadList * pos,
				     const char * filename,
				     const struct ECRS_URI * uri,
				     unsigned long long filesize,
				     unsigned long long bytesCompleted,
				     int isRecursive,
				     unsigned int anonymityLevel);

/**
 * @brief Start the FSUI manager.  Use the given progress callback to
 * notify the UI about events.  May resume processing pending
 * activities that were running when FSUI_stop was called
 * previously.<p>
 *
 * The basic idea is that graphical user interfaces use their UI name
 * (i.e.  gnunet-gtk) for 'name' and set doResume to YES.  They should
 * have a command-line switch --resume=NAME to allow the user to
 * change 'name' to something else (such that the user can resume
 * state from another GUI).  Shell UIs on the other hand should set
 * doResume to NO and may hard-wire a 'name' (which has no semantic
 * meaning, however, the name of the UI would still be a good choice).
 * <p>
 *
 * Note that suspend/resume is not implemented in this version of
 * GNUnet.
 *
 * @param name name of the tool or set of tools; used to
 *          resume activities; tools that use the same name here
 *          and that also use resume cannot run multiple instances
 *          in parallel (for the same user account); the name
 *          must be a valid filename (not a path)
 * @param doResume YES if old activities should be resumed (also
 *          implies that on shutdown, all pending activities are
 *          suspended instead of canceled);
 *          NO if activities should never be resumed
 * @param cb function to call for events, must not be NULL
 * @param closure extra argument to cb
 * @return NULL on error
 */
struct FSUI_Context * FSUI_start(const char * name,
				 int doResume,
				 FSUI_EventCallback cb,
				 void * closure); /* fsui.c */

/**
 * Stop all processes under FSUI control (may serialize
 * state to continue later if possible).  Will also let
 * uninterruptable activities complete (you may want to
 * signal the user that this may take a while).
 */
void FSUI_stop(struct FSUI_Context * ctx); /* fsui.c */

/* ******************** simple FS API **************** */

/**
 * Create an ECRS URI from a single user-supplied string of keywords.
 * The string may contain the reserved word 'AND' to create a boolean
 * search over multiple keywords.
 *
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct ECRS_URI * FSUI_parseCharKeywordURI(const char * keywords); /* helper.c */

/**
 * Create an ECRS URI from a user-supplied command line of keywords.
 * The command line may contain the reserved word 'AND' to create a
 * boolean search over multiple keywords.
 *
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct ECRS_URI * FSUI_parseArgvKeywordURI(unsigned int argc,
					   const char ** argv); /* helper.c */

/**
 * Create an ECRS URI from a user-supplied list of keywords.
 * The keywords are NOT separated by AND but already
 * given individually.
 *
 * @return an ECRS URI for the given keywords, NULL
 *  if keywords is not legal (i.e. empty).
 */
struct ECRS_URI * FSUI_parseListKeywordURI(unsigned int num_keywords,
					   const char ** keywords);

/**
 * Start a search.
 * @return SYSERR if such a search is already pending, OK on
 *  success
 */
int FSUI_startSearch(struct FSUI_Context * ctx,
		     unsigned int anonymityLevel,
		     const struct ECRS_URI * uri); /* search.c */

/**
 * Stop a search.
 * @return SYSERR if such a search is not known
 */
int FSUI_stopSearch(struct FSUI_Context * ctx,
		    const struct ECRS_URI * uri); /* search.c */

/**
 * List active searches.  Can also be used to obtain
 * search results that were already signaled earlier.
 */
int FSUI_listSearches(struct FSUI_Context * ctx,
		      FSUI_SearchIterator iter,
		      void * closure); /* search.c */

/**
 * Start to download a file.
 *
 * @return OK on success, SYSERR if the target file is
 *  already used for another download at the moment (or
 *  if the disk does not have enough space).
 */
int FSUI_startDownload(struct FSUI_Context * ctx,
		       unsigned int anonymityLevel,
		       const struct ECRS_URI * uri,
		       const char * filename); /* download.c */

/**
 * Abort a download.  If the URI was for a recursive
 * download, all sub-downloads will also be aborted.
 * Cannot be used to terminate a single file download
 * that is part of a recursive download.
 *
 * @return SYSERR if no such download is pending
 */
int FSUI_stopDownload(struct FSUI_Context * ctx,
		      const struct ECRS_URI * uri,
		      const char * filename); /* download.c */

/**
 * List active downloads.  Will NOT list completed
 * downloads, FSUI clients should listen closely
 * to the FSUI_EventCallback to not miss completion
 * events.
 *
 * @param root subtree to iterate over, use
 *        NULL for all top-level downloads
 */
int FSUI_listDownloads(struct FSUI_Context * ctx,
		       const struct FSUI_DownloadList * root,
		       FSUI_DownloadIterator iter,
		       void * closure); /* download.c */

/**
 * Clear all completed top-level downloads from the FSUI list.
 *
 * @param callback function to call on each completed download
 *        that is being cleared.
 * @return SYSERR on error, otherwise number of downloads cleared
 */
int FSUI_clearCompletedDownloads(struct FSUI_Context * ctx,
				 FSUI_DownloadIterator iter,
				 void * closure); /* download.c */


/**
 * Get parent of active download.
 * @return NULL if there is no parent
 */
const struct FSUI_DownloadList *
FSUI_getDownloadParent(const struct FSUI_DownloadList * child); /* download.c */

/**
 * Start uploading a file.  Note that an upload cannot be stopped once
 * started (not necessary anyway), but it can fail.  The function also
 * automatically the uploaded file in the global keyword space under
 * the given keywords.
 *
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist or gnunetd is not
 *  running
 */
int FSUI_upload(struct FSUI_Context * ctx,
		const char * filename,
		unsigned int anonymityLevel,
		int doIndex,
		int doExtract,
		const struct ECRS_MetaData * md,
		const struct ECRS_URI * keyUri);

/**
 * "delete" operation for uploaded files.  May fail
 * asynchronously, check progress callback.
 *
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist
 */
int FSUI_unindex(struct FSUI_Context * ctx,
		 const char * filename);

/* ***************** recursive FS API ***************** */


/**
 * Start uploading a directory.  Note that an upload cannot be stopped
 * once started (not necessary anyway), but it can fail.  All files
 * in the recursive tree will be indexed under all keywords found by
 * the specified extractor plugins AND the globalKeywords.  The
 * main directory will furthermore be published with the given keywords
 * and the specified directoryMetaData.
 *
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist
*/
int FSUI_uploadAll(struct FSUI_Context * ctx,
		   const char * dirname,
		   unsigned int anonymityLevel,
		   int doIndex,
		   int individualKeywords,
		   const struct ECRS_MetaData * directoryMetaData,
		   const struct ECRS_URI * globalURI,
		   const struct ECRS_URI * topURI); /* upload.c */

/**
 * Start to download a file or directory recursively.
 *
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist
 */
int FSUI_startDownloadAll(struct FSUI_Context * ctx,
			  unsigned int anonymityLevel,
			  const struct ECRS_URI * uri,
			  const char * dirname); /* download.c */

/* ******************** collections API **************** */

/**
 * Start collection.
 */
int FSUI_startCollection(struct FSUI_Context * ctx,
			 unsigned int anonymityLevel,
			 TIME_T updateInterval,
			 const char * name,
			 const struct ECRS_MetaData * meta); /* collection.c */

/**
 * Stop collection.
 *
 * @return OK on success, SYSERR if no collection is active
 */
int FSUI_stopCollection(struct FSUI_Context * ctx); /* collection.c */

/**
 * Are we using a collection?
 *
 * @return NULL if there is no collection, otherwise its name
 */
const char * FSUI_getCollection(struct FSUI_Context * ctx); /* collection.c */

/**
 * Upload an update of the current collection information to the
 * network now.  The function has no effect if the collection has not
 * changed since the last publication.  If we are currently not
 * collecting, this function does nothing.
 *
 * Note that clients typically don't have to call this function
 * explicitly.  FSUI will call the function on exit (for sporadically
 * updated collections), on any change to the collection (for
 * immediately updated content) or when the publication time has
 * arrived (for periodically updated collections).
 *
 * However, clients may want to call this function if explicit
 * publication of an update at another time is desired.
 */
void FSUI_publishCollectionNow(struct FSUI_Context * ctx);

/**
 * If we are currently building a collection, publish the given file
 * information in that collection.  If we are currently not
 * collecting, this function does nothing.
 *
 * Note that clients typically don't have to call this function
 * explicitly -- by using the FSUI library it should be called
 * automatically by FSUI code whenever needed.  However, the function
 * maybe useful if you're inserting files using libECRS directly or
 * need other ways to explicitly extend a collection.
 */
void FSUI_publishToCollection(struct FSUI_Context * ctx,
			      const ECRS_FileInfo * fi);


/* ******************** Namespace API ***************** */

/**
 * Create a new namespace (and publish an advertismement).
 * This function is synchronous, but may block the system
 * for a while since it must create a public-private key pair!
 *
 * @param meta meta-data about the namespace (maybe NULL)
 * @return URI on success, NULL on error (namespace already exists)
 */
struct ECRS_URI *
FSUI_createNamespace(struct FSUI_Context * ctx,
		     unsigned int anonymityLevel,
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
#define FSUI_deleteNamespace ECRS_deleteNamespace

/**
 * Change the ranking of a (non-local) namespace.
 *
 * @param ns the name of the namespace, as obtained
 *  from ECRS_getNamespaceName
 * @param delta by how much should the rating be
 *  changed?
 * @return new rating of the namespace
 */
int FSUI_rankNamespace(struct FSUI_Context * ctx,
		       const char * ns,
		       int delta); /* namespace_info.c */

/**
 * Add a namespace to the set of known namespaces.  For all namespace
 * advertisements that we discover FSUI should automatically call this
 * function.
 *
 * @param ns the namespace identifier
 */
void FSUI_addNamespaceInfo(const struct ECRS_URI * uri,
			   const struct ECRS_MetaData * meta);


/**
 * Get the root of the namespace (if we have one).
 * @return SYSERR on error, OK on success
 */
int FSUI_getNamespaceRoot(const char * ns,
			  HashCode512 * root);


/**
 * List all available (local or non-local) namespaces.
 *
 * @param local only list local namespaces (if NO, only
 *   non-local known namespaces are listed)
 */
int FSUI_listNamespaces(struct FSUI_Context * ctx,
			int local,
			FSUI_NamespaceIterator iterator,
			void * closure); /* namespace_info.c */

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
FSUI_addToNamespace(struct FSUI_Context * ctx,
		    unsigned int anonymityLevel,
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
 * @param thisId MUST be known to FSUI
 * @return OK on success, SYSERR on error
 */
int FSUI_computeNextId(const char * name,
		       const HashCode512 * lastId,
		       const HashCode512 * thisId,
		       TIME_T updateInterval,
		       HashCode512 * nextId);

/**
 * List all updateable content in a given namespace.
 */
int FSUI_listNamespaceContent(struct FSUI_Context * ctx,
			      const char * name,
			      FSUI_UpdateIterator iterator,
			      void * closure); /* namespace_info.c */

/* **************** TRACKING API ****************** */

/**
 * Toggle tracking URIs.
 *
 * @param onOff YES to enable tracking, NO to disable
 *  disabling tracking
 */
void FSUI_trackURIS(int onOff); /* file_info.c */

/**
 * Deletes all entries in the FSUI tracking cache.
 */
void FSUI_clearTrackedURIS(void); /* file_info.c */

/**
 * Get the FSUI URI tracking status.
 *
 * @return YES of tracking is enabled, NO if not
 */
int FSUI_trackStatus(void); /* file_info.c */

/**
 * Makes a URI available for directory building.  This function is
 * automatically called by all FSUI functions and only in the
 * interface for clients that call ECRS directly.
 */
void FSUI_trackURI(const ECRS_FileInfo * fi); /* file_info.c */

/**
 * List all URIs.
 */
int FSUI_listURIs(ECRS_SearchProgressCallback iterator,
		  void * closure); /* file_info.c */

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
