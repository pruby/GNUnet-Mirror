/*
     This file is part of GNUnet

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

#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"

/**
 * @brief types of FSUI events.
 */
enum FSUI_EventType { 
  /**
   * We found a new search result.
   */
  search_result,
  search_error,
  download_progress,
  download_complete,
  download_error,
  upload_progress,
  upload_complete,
  upload_error,
  unindex_progress,
  unindex_complete,
  unindex_error,
  /**
   * Connection status with gnunetd changed.
   */
  gnunetd_connected,
  /**
   * Connection status with gnunetd changed.
   */
  gnunetd_disconnected,
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
    } DownloadProgress;
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
      /* FIXME */
    } UnindexProgress;
    struct {
      /* FIXME */
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
 * Generic callback for all kinds of FSUI progress
 * and error messages.  This function will be called
 * for download progress, download completion, upload
 * progress and completion, search results, etc.
 *
 * The details of the argument format are yet to be
 * defined.  What FSUI guarantees is that only one
 * thread at a time will call the callback (so it
 * need not be re-entrant).
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
				      const struct ECRS_MetaData * md,
				      int rating);

/**
 * Iterator over all searches and search results.
 *
 * @return OK to continue iteration, SYSERR to abort
 */
typedef int (*FSUI_SearchIterator)(void * cls,
				   const struct ECRS_URI * searchUri,
				   unsigned int resultCount,
				   const ECRS_FileInfo * results);

/**
 * Iterator over all updateable content.
 *
 * @param lastId the ID of the last publication
 * @param nextId the ID of the next update
 * @param nextPublicationTime the scheduled time for the
 *  next update (0 for sporadic updates)
 * @return OK to continue iteration, SYSERR to abort
 */
typedef int (*FSUI_UpdateIterator)(void * cls,
				   const ECRS_FileInfo * uri,
				   const HashCode160 * lastId,
				   const HashCode160 * nextId,
				   cron_t nextPublicationTime); 

/**
 * Iterator over active downloads.
 *
 * @return OK to continue iteration, SYSERR to abort
 */
typedef int (*FSUI_DownloadIterator)(void * cls,
				     const char * filename,
				     const struct ECRS_URI * uri,
				     unsigned long long filesize,
				     unsigned long long bytesCompleted,
				     int isRecursive,
				     unsigned int anonymityLevel);

/**
 * Start FSUI manager.  Use the given progress callback to notify the
 * UI about events.  Start processing pending activities that were
 * running when FSUI_stop was called previously.
 *
 * @return NULL on error
 */
struct FSUI_Context * FSUI_start(FSUI_EventCallback cb,
				 void * closure); /* fsui.c */

/**
 * Stop all processes under FSUI control (serialize state, continue
 * later if possible).
 */
void FSUI_stop(struct FSUI_Context * ctx); /* fsui.c */

/**
 * Set the anonymity level in this FSUI context for
 * all actions that are started from now on (until
 * the next call to setAnonymityLevel).
 */
void FSUI_setAnonymityLevel(struct FSUI_Context * ctx,
			    unsigned int anonymityLevel); /* fsui.c */

/**
 * Get the anonymity level that is currently used
 * by this FSUI context.
 */
unsigned int FSUI_getAnonymityLevel(const struct FSUI_Context * ctx); /* fsui.c */

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
 * Start a search.
 * @return SYSERR if such a search is already pending, OK on
 *  success
 */
int FSUI_startSearch(struct FSUI_Context * ctx,
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
		       const struct ECRS_URI * uri,
		       const char * filename); /* download.c */

/**
 * Abort a download.
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
 */
int FSUI_listDownloads(struct FSUI_Context * ctx,
		       FSUI_DownloadIterator iter,
		       void * closure); /* download.c */

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
		int doIndex,
		const struct ECRS_MetaData * md,
		unsigned int keywordCount,
		const char ** keywords);

/**
 * "delete" operation for uploaded files.  May fail
 * asynchronously, check progress callback.
 *
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist
 */
void FSUI_unindex(struct FSUI_Context * ctx,
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
 * @param extractorPluginNames list of LE plugins to use
 * @param keywordCount number of keywords
 * @param keywords keywords to use ONLY for the top-level directory
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist
*/
int FSUI_uploadAll(struct FSUI_Context * ctx,
		   const char * dirname,
		   int doIndex,
		   const struct ECRS_MetaData * directoryMetaData,
		   const char * extractorPluginNames,
		   unsigned int globalKeywordCount,
		   const char ** globalKeywords,
		   unsigned int keywordCount,
		   const char ** keywords); /* upload.c */

/**
 * Start to download a file or directory recursively.
 *
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist
 */
int FSUI_startDownloadAll(struct FSUI_Context * ctx,
			  const struct ECRS_URI * uri,
			  const char * dirname); /* download.c */

/**
 * Abort a download.
 *
 * @return OK on success, SYSERR if no such download is
 *  pending
 */
int FSUI_stopDownloadAll(struct FSUI_Context * ctx,
			 const struct ECRS_URI * uri,
			 const char * dirname); /* download.c */
		    
/* ******************** collections API **************** */

/**
 * Start collection.
 */
int FSUI_startCollection(struct FSUI_Context * ctx,
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

/* ******************** Namespace API ***************** */

/**
 * Create a new namespace (and publish an advertismement).
 * This function is synchronous, but may block the system
 * for a while since it must create a public-private key pair!
 *
 * @param meta meta-data about the namespace (maybe NULL)
 * @param root set to the URI of the namespace, NULL if no advertisement
 *        was created
 *
 * @return OK on success, SYSERR on error (namespace already exists)
 */
int FSUI_createNamespace(struct FSUI_Context * ctx,
			 const char * namespaceName,
			 const struct ECRS_MetaData * meta,
			 const struct ECRS_URI * advertisementURI,
			 const HashCode160 * rootEntry,
			 struct ECRS_URI ** root); /* namespace_info.c */

/**
 * Delete a local namespace.  Only prevents future insertions
 * into the namespace, does not delete any content from
 * the network!
 *
 * @return OK on success, SYSERR on error
 */
#define FSUI_deleteNamespace ECRS_deleteNamespace

/**
 * Change the ranking of a namespace.
 */
int FSUI_rankNamespace(struct FSUI_Context * ctx,
		       const char * ns,
		       int delta); /* namespace_info.c */

/**
 * Add a namespace to the set of known namespaces.
 * For all namespace advertisements that we discover
 * FSUI should automatically call this function.
 * 
 * @param ns the namespace identifier
 */
void FSUI_addNamespaceInfo(const struct ECRS_URI * uri,
			   const struct ECRS_MetaData * meta);

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
 * updates).
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
 * @param uri set to the resulting URI
 */
int FSUI_addToNamespace(struct FSUI_Context * ctx,
			const char * name,
			cron_t updateInterval,
			const HashCode160 * lastId,
			const HashCode160 * thisId,
			const HashCode160 * nextId,
			const struct ECRS_URI * dst,
			const struct ECRS_MetaData * md,
			struct ECRS_URI ** uri); /* namespace_info.c */

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
 *  disabling tracking also deletes all entries in the
 *  cache.
 */ 
void FSUI_trackURIS(int onOff); /* file_info.c */


/**
 * Get the FSUI URI tracking status.
 *
 * @return YES of tracking is enabled, NO if not
 */ 
int FSUI_trackStatus(); /* file_info.c */

/**
 * Makes a URI available for directory building.
 * This function is automatically called by all FSUI
 * functions and only in the interface for clients that
 * call ECRS directly.
 */
void FSUI_trackURI(const ECRS_FileInfo * fi); /* file_info.c */
 
/**
 * List all URIs.
 */
int FSUI_listURIs(ECRS_SearchProgressCallback iterator,
		  void * closure); /* file_info.c */

#endif
