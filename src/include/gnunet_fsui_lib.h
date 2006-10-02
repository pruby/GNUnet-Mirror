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

struct FSUI_UploadList;

struct FSUI_SearchList;

struct FSUI_UnindexList;

/**
 * @brief types of FSUI events.
 * 
 * For the types aborted, error, suspending and complete,
 * the client MUST free the "cctx" context associated with
 * the event (if allocated).<p>
 *
 * Resume events are issued when operations resume as well
 * as when they are first initiated!<p>
 *
 * Searches "complete" if they time out or the maximum
 * number of results has been found.
 */
enum FSUI_EventType {

  FSUI_search_result,
  FSUI_search_completed,
  FSUI_search_aborted,
  FSUI_search_error,
  FSUI_search_suspending,
  FSUI_search_resuming,
  FSUI_download_progress,
  FSUI_download_complete,
  FSUI_download_aborted,
  FSUI_download_error,
  FSUI_download_suspending,
  FSUI_download_resuming,
  FSUI_upload_progress,
  FSUI_upload_complete,
  FSUI_upload_aborted,
  FSUI_upload_error,
  FSUI_upload_suspending,
  FSUI_upload_resuming,
  FSUI_unindex_progress,
  FSUI_unindex_complete,
  FSUI_unindex_aborted,
  FSUI_unindex_error,
  FSUI_unindex_suspending,
  FSUI_unindex_resuming,
  /**
   * Connection status with gnunetd changed.
   */
  FSUI_gnunetd_connected,
  /**
   * Connection status with gnunetd changed.
   */
  FSUI_gnunetd_disconnected,

};

/**
 * @brief Description of a download.  Gives the
 *  identifier of the download for FSUI and
 *  the client context.  For downloads that
 *  are not top-level, also gives the handle
 *  and client context for the parent download.
 */
typedef struct {
  
  /**
   * What file in the download tree are we
   * refering to?
   */
  struct FSUI_DownloadList * pos;
  
  void * cctx;
  
  /**
   * What is our parent download in the download tree?
   * NULL if this is the top-level download.
   */
  struct FSUI_DownloadList * ppos;
  
  void * pcctx;

} FSUI_DownloadContext;

typedef struct {

  /**
   * What file in the upload tree are we
   * refering to?
   */
  struct FSUI_UploadList * pos;
  
  void * cctx;
  
  /**
   * What is our parent upload in the upload tree?
   * NULL if this is the top-level upload.
   */
  struct FSUI_UploadList * ppos;
  
  void * pcctx;

} FSUI_UploadContext;

typedef struct {
  
  struct FSUI_SearchList * pos;

  void * cctx;

} FSUI_SearchContext;

typedef struct {

  struct FSUI_UnindexList * pos;

  void * cctx;

} FSUI_UnindexContext;

/**
 * @brief FSUI Event.
 */
typedef struct {
  enum FSUI_EventType type;
  union {

    struct {

      FSUI_SearchContext sc;

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


    struct {

      struct FSUI_SearchList * pos;

    } SearchCompleted;

    struct {

      struct FSUI_SearchList * pos;

    } SearchAborted;


    struct {

      FSUI_SearchContext sc;

      char * message;

    } SearchError;


    struct {

      FSUI_SearchContext sc;

    } SearchSuspending;


    struct {

      FSUI_SearchContext sc;

      ECRS_FileInfo * fis;

      unsigned int fisSize;

      unsigned int anonymityLevel;

      struct ECRS_URI * searchURI;

    } SearchResuming;


    struct {

      FSUI_DownloadContext dc;

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
       * Estimated completion time.
       */
      cron_t eta;

      /**
       * Information about the download.
       */
      char * filename;

      /**
       * Original URI.
       */
      struct ECRS_URI * uri;

      /**
       * The last block (in plaintext)
       */
      const void * last_block;

      /**
       * Size of the last block
       */
      unsigned int last_size;

    } DownloadProgress;


    struct {

      FSUI_DownloadContext dc;

      /**
       * How large is the total download (as far
       * as known so far).
       */
      unsigned long long total;

      /**
       * Information about the download.
       */
      char * filename;

      /**
       * Original URI.
       */
      struct ECRS_URI * uri;

    } DownloadComplete;


    struct {

      FSUI_DownloadContext dc;

      /**
       * Error message.
       */
      const char * message;

    } DownloadError;


    struct {

      FSUI_DownloadContext dc;

    } DownloadAborted;


    struct {

      FSUI_DownloadContext dc;

    } DownloadSuspending;


    struct {

      FSUI_DownloadContext dc;

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
       * Estimated completion time.
       */
      cron_t eta;

      /**
       * Information about the download.
       */
      char * filename;

      unsigned int anonymityLevel;

      /**
       * Original URI.
       */
      struct ECRS_URI * uri;

    } DownloadResuming;


    struct {

      FSUI_UploadContext uc;

      /**
       * How far are we? (for the current file)
       */
      unsigned long long completed;

      /**
       * How large is the total upload (for the current file)
       */
      unsigned long long total;

      /**
       * Estimated completion time (for the current file)
       */
      cron_t eta;

      /**
       * Information about the upload.
       */
      char * filename;

    } UploadProgress;


    struct {

      FSUI_UploadContext uc;

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

    } UploadComplete;


    struct {

      FSUI_UploadContext uc;

    } UploadAborted;


    struct {

      FSUI_UploadContext uc;

      char * message;

    } UploadError;


    struct {

      FSUI_UploadContext uc;

    } UploadSuspending;


    struct {

      FSUI_UploadContext uc;

      /**
       * How far are we? (for the current file)
       */
      unsigned long long completed;

      /**
       * How large is the total upload (for the current file)
       */
      unsigned long long total;

      /**
       * Estimated completion time (for the current file)
       */
      cron_t eta;

      unsigned int anonymityLevel;

      /**
       * Information about the upload.
       */
      char * filename;

    } UploadResuming;


    struct {

      FSUI_UnindexContext uc;

      unsigned long long total;

      unsigned long long completed;

      cron_t eta;

      char * filename;

    } UnindexProgress;


    struct {

      FSUI_UnindexContext uc;

      unsigned long long total;

      char * filename;

    } UnindexComplete;


    struct {

      FSUI_UnindexContext uc;

    } UnindexAborted;


    struct {

      FSUI_UnindexContext uc;

    } UnindexSuspending;


    struct {

      FSUI_UnindexContext uc;
      
      unsigned long long total;

      unsigned long long completed;

      cron_t eta;

      char * filename;

    } UnindexResuming;


    struct {

      FSUI_UnindexContext uc;

      char * message;

    } UnindexError;    

  } data;

} FSUI_Event;

/**
 * @brief opaque FSUI context
 */
struct FSUI_Context;

/**
 * Generic callback for all kinds of FSUI progress and error messages.
 * This function will be called for download progress, download
 * completion, upload progress and completion, search results, etc.<p>
 *
 * The details of the argument format are yet to be defined.  What
 * FSUI guarantees is that only one thread at a time will call the
 * callback (so it need not be re-entrant).<p>
 *
 * @return cctx for resume events, otherwise NULL
 */
typedef void * (*FSUI_EventCallback)(void * cls,
				     const FSUI_Event * event);

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
struct FSUI_Context * 
FSUI_start(struct GE_Context * ectx,
	   struct GC_Configuration * cfg,
	   const char * name,
	   unsigned int threadPoolSize,
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


/**
 * Start a search.
 *
 * @return NULL on error
 */
struct FSUI_SearchList *
FSUI_startSearch(struct FSUI_Context * ctx,
		 unsigned int anonymityLevel,
		 const struct ECRS_URI * uri); /* search.c */

/**
 * Stop a search.
 *
 * @return SYSERR if such a search is not known
 */
int FSUI_stopSearch(struct FSUI_Context * ctx,
		    struct FSUI_SearchList * sl); /* search.c */

/**
 * Start to download a file or directory.
 *
 * @return NULL on error
 */
struct FSUI_DownloadList *
FSUI_startDownload(struct FSUI_Context * ctx,
		   unsigned int anonymityLevel,
		   int doRecursive,
		   const struct ECRS_URI * uri,
		   const char * filename); /* download.c */

/**
 * Abort a download.  If the dl is for a recursive
 * download, all sub-downloads will also be aborted.
 *
 * @return SYSERR on error
 */
int FSUI_stopDownload(struct FSUI_Context * ctx,
		      struct FSUI_DownloadList * dl); /* download.c */

/**
 * Start uploading a file or directory.
 *
 * @param ctx 
 * @param filename name of file or directory to upload (directory
 *        implies use of recursion)
 * @param doIndex use indexing, not insertion
 * @param doExtract use libextractor
 * @param individualKeywords add KBlocks for non-top-level files
 * @param topLevelMetaData metadata for top-level file or directory
 * @param globalURI keywords for all files 
 * @param keyURI keywords for top-level file
 * @return NULL on error
 */
struct FSUI_UploadList *
FSUI_startUpload(struct FSUI_Context * ctx,
		 const char * filename,
		 unsigned int anonymityLevel,
		 unsigned int priority,
		 int doIndex,
		 int doExtract,
		 int individualKeywords,
		 const struct ECRS_MetaData * topLevelMetaData,
		 const struct ECRS_URI * globalURI,
		 const struct ECRS_URI * keyUri);


/**
 * Abort an upload.  If the context is for a recursive
 * upload, all sub-uploads will also be aborted.
 *
 * @return SYSERR on error
 */
int FSUI_stopUpload(struct FSUI_Context * ctx,
		    struct FSUI_UploadList * ul);


/**
 * "delete" operation for uploaded files.  May fail
 * asynchronously, check progress callback.
 *
 * @return NULL on error
 */
struct FSUI_UnindexList *
FSUI_unindex(struct FSUI_Context * ctx,
	     const char * filename);


/**
 * Abort an unindex operation.  If the context is for a recursive
 * upload, all sub-uploads will also be aborted.
 *
 * @return SYSERR on error
 */
int FSUI_stopUnindex(struct FSUI_Context * ctx,
		     struct FSUI_UnindexList * ul);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
