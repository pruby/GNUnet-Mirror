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
 * @brief support for GNUnet file-sharing user interfaces
 * @author Christian Grothoff
 * @see include/gnunet_ecrs_lib.h
 *
 * Writing a UI for GNUnet is now easier then ever before.  Basically,
 * the UI first calls GNUNET_FSUI_start, passing a callback that the UI uses
 * to process events (like completed downloads, search results, etc.).
 * The event processor does not have to be re-entrant, FSUI will only
 * call it once at a time (but possibly from different threads, the
 * event processor also may have to worry about synchronizing itself
 * with the GUI library to display updates).<p>
 *
 * After creating a GNUNET_FSUI_Context with GNUNET_FSUI_start the UI can start,
 * abort and stop uploads, downloads, deletions or searches.
 * The GNUNET_FSUI_Context can be destroyed, when it is created again
 * the next time all pending operations are resumed (!).
 * Clients can use the various iterator functions to obtain
 * information about pending actions.<p>
 *
 * Note that there can only be one GNUNET_FSUI_Context for a given
 * client application name if resuming is enabled.
 * Creating an GNUNET_FSUI_Context may _fail_ if any other UI is currently
 * running (for the same user and application name).<p>
 *
 * Clients may use SOME functions of GNUnet's ECRS library, in
 * particular functions to deal with URIs and MetaData, but generally
 * FSUI functions should be preferred over ECRS functions (since FSUI
 * keeps state, performs additional tracking operations and avoids
 * blocking the client while operations are pending).<p>
 *
 * Closing an GNUNET_FSUI_Context may take a while as the context may need
 * to serialize some state and complete operations that may not be
 * interrupted (such as communications with gnunetd).  Clients
 * may want to open a window informing the user about the pending
 * shutdown operation.<p>
 *
 * Any "startXXX" operation will result in FSUI state and memory
 * being allocated until it is paired with a "stopXXX" operation.
 * Before calling "stopXXX", one of three things must happen:
 * Either, the client receives an "error" (something went wrong)
 * or "completed" (action finished) event.  Alternatively, the
 * client may call abortXXX" which will result in an "aborted"
 * event.  In either case, the event itself will NOT result in
 * the memory being released by FSUI -- the client must still
 * call "GNUNET_FSUI_stopXXX" explicitly.  Clients that call
 * "GNUNET_FSUI_stopXXX" before an aborted, error or completed event
 * will be blocked until either of the three events happens.<p>
 *
 * Using the Event mechanism, clients can associate an arbitrary
 * pointer with any operation (upload, download, search or
 * deletion).  The pointer is initialized using the return value
 * from the respective start or resume events.  If any memory
 * is associated with the datastructure, the client should free
 * that memory when suspend or stop events are issued.  For all
 * events (other than start/resume), FSUI will track and provide
 * the client pointer as part of the event (cctx field).<p>
 *
 * Note that most of this code is completely new in GNUnet 0.7.0 and
 * thus still highly experimental.  Suggestions are welcome.<p>
 */

#ifndef GNUNET_FSUI_LIB_H
#define GNUNET_FSUI_LIB_H

#include "gnunet_ecrs_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Entry representing an FSUI download.  FSUI downloads form a tree
 * (for properly representing recursive downloads) with an invisible
 * root (for multiple parallel downloads).<p>
 *
 * FSUI hands out references of this type to allow clients to access
 * information about active downloads.
 */
struct GNUNET_FSUI_DownloadList;

struct GNUNET_FSUI_UploadList;

struct GNUNET_FSUI_SearchList;

struct GNUNET_FSUI_UnindexList;

/**
 * @brief types of FSUI events.
 *
 * For the types aborted, error, suspending and complete,
 * the client MUST free the "cctx" context associated with
 * the event (if allocated).  This context is created
 * by the "resume" operation.<p>
 *
 * Resume events are issued when operations resume as well
 * as when they are first initiated!<p>
 *
 * Searches "complete" if they time out or the maximum
 * number of results has been found.
 */
enum GNUNET_FSUI_EventType
{
  GNUNET_FSUI_search_started,
  GNUNET_FSUI_search_stopped,
  GNUNET_FSUI_search_result,
  GNUNET_FSUI_search_completed,
  GNUNET_FSUI_search_aborted,
  GNUNET_FSUI_search_error,
  GNUNET_FSUI_search_suspended,
  GNUNET_FSUI_search_resumed,
  GNUNET_FSUI_download_started,
  GNUNET_FSUI_download_stopped,
  GNUNET_FSUI_download_progress,
  GNUNET_FSUI_download_completed,
  GNUNET_FSUI_download_aborted,
  GNUNET_FSUI_download_error,
  GNUNET_FSUI_download_suspended,
  GNUNET_FSUI_download_resumed,
  GNUNET_FSUI_upload_started,
  GNUNET_FSUI_upload_stopped,
  GNUNET_FSUI_upload_progress,
  GNUNET_FSUI_upload_completed,
  GNUNET_FSUI_upload_aborted,
  GNUNET_FSUI_upload_error,
  GNUNET_FSUI_upload_suspended,
  GNUNET_FSUI_upload_resumed,
  GNUNET_FSUI_unindex_started,
  GNUNET_FSUI_unindex_stopped,
  GNUNET_FSUI_unindex_progress,
  GNUNET_FSUI_unindex_completed,
  GNUNET_FSUI_unindex_aborted,
  GNUNET_FSUI_unindex_error,
  GNUNET_FSUI_unindex_suspended,
  GNUNET_FSUI_unindex_resumed,
};


/**
 * Current state of a download (or uploads, or search,
 * or unindex operations).
 *
 * PENDING means that the download is waiting for a thread
 * to be assigned to run it.  Downloads start in this state,
 * and during shutdown are serialized in this state.<br>
 *
 * ACTIVE means that there is currently a thread running
 * the download (and that thread is allowed to continue).<br>
 *
 * COMPLETED means that the download is finished (but the
 * thread has not been joined yet).  The download thread
 * makes the transition from PENDING to COMPLETED when it
 * is about to terminate.<br>
 *
 * COMPLETED_JOINED means that the download is finished and
 * the thread has been joined.<br>
 *
 * ABORTED means that the user is causing the download to be
 * terminated early (but the thread has not been joined yet).  The
 * controller or the download thread make this transition; the
 * download thread is supposed to terminate shortly after the state is
 * moved to ABORTED.<br>
 *
 * ABORTED_JOINED means that the download did not complete
 * successfully, should not be restarted and that the thread
 * has been joined.<br>
 *
 * ERROR means that some fatal error is causing the download to be
 * terminated early (but the thread has not been joined yet).  The
 * controller or the download thread make this transition; the
 * download thread is supposed to terminate shortly after the state is
 * moved to ERROR.<br>
 *
 * ERROR_JOINED means that the download did not complete successfully,
 * should not be restarted and that the thread has been joined.<br>
 *
 * SUSPENDING is used to notify the download thread that it
 * should terminate because of an FSUI shutdown.  After this
 * termination the code that joins the thread should move
 * the state into PENDING (a new thread would not be started
 * immediately because "threadPoolSize" will be 0 until FSUI
 * resumes).
 */
typedef enum
{
  GNUNET_FSUI_PENDING = 0,
  GNUNET_FSUI_ACTIVE = 1,
  GNUNET_FSUI_COMPLETED = 2,
  GNUNET_FSUI_COMPLETED_JOINED = 3,
  GNUNET_FSUI_ABORTED = 4,
  GNUNET_FSUI_ABORTED_JOINED = 5,
  GNUNET_FSUI_ERROR = 6,
  GNUNET_FSUI_ERROR_JOINED = 7,
  GNUNET_FSUI_SUSPENDING = 8,
} GNUNET_FSUI_State;

/**
 * @brief Description of a download.  Gives the
 *  identifier of the download for FSUI and
 *  the client context.  For downloads that
 *  are not top-level, also gives the handle
 *  and client context for the parent download.
 */
typedef struct
{

  /**
   * What file in the download tree are we
   * refering to?
   */
  struct GNUNET_FSUI_DownloadList *pos;

  void *cctx;

  /**
   * What is our parent download in the download tree?
   * NULL if this is the top-level download.
   */
  struct GNUNET_FSUI_DownloadList *ppos;

  void *pcctx;

  /**
   * If this download is associated with a search,
   * what is the search?
   */
  struct GNUNET_FSUI_SearchList *spos;

  /**
   * If this download is associated with a search,
   * what is the client context for the search?
   */
  void *sctx;

} GNUNET_FSUI_DownloadContext;

typedef struct
{

  /**
   * What file in the upload tree are we
   * refering to?
   */
  struct GNUNET_FSUI_UploadList *pos;

  void *cctx;

  /**
   * What is our parent upload in the upload tree?
   * NULL if this is the top-level upload.
   */
  struct GNUNET_FSUI_UploadList *ppos;

  void *pcctx;

} GNUNET_FSUI_UploadContext;

typedef struct
{

  struct GNUNET_FSUI_SearchList *pos;

  void *cctx;

} GNUNET_FSUI_SearchContext;

typedef struct
{

  struct GNUNET_FSUI_UnindexList *pos;

  void *cctx;

} GNUNET_FSUI_UnindexContext;

/**
 * @brief FSUI Event.
 */
typedef struct
{
  enum GNUNET_FSUI_EventType type;
  union
  {

    struct
    {

      GNUNET_FSUI_SearchContext sc;

      /**
       * File-Info of the data that was found.
       */
      GNUNET_ECRS_FileInfo fi;

      /**
       * The URI of the search for which data was
       * found.
       */
      const struct GNUNET_ECRS_URI *searchURI;

    } SearchResult;


    struct
    {

      GNUNET_FSUI_SearchContext sc;

    } SearchCompleted;

    struct
    {

      GNUNET_FSUI_SearchContext sc;

    } SearchAborted;

    struct
    {

      GNUNET_FSUI_SearchContext sc;

      const char *message;

    } SearchError;

    struct
    {

      GNUNET_FSUI_SearchContext sc;

    } SearchSuspended;

    struct
    {

      GNUNET_FSUI_SearchContext sc;

      struct GNUNET_ECRS_URI *searchURI;

      const GNUNET_ECRS_FileInfo *fis;

      unsigned int anonymityLevel;

      unsigned int fisSize;

      GNUNET_FSUI_State state;

    } SearchResumed;

    struct
    {

      GNUNET_FSUI_SearchContext sc;

      const struct GNUNET_ECRS_URI *searchURI;

      unsigned int anonymityLevel;

    } SearchStarted;

    struct
    {

      GNUNET_FSUI_SearchContext sc;

    } SearchStopped;



    struct
    {

      GNUNET_FSUI_DownloadContext dc;

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
      GNUNET_CronTime eta;

      /**
       * Information about the download.
       */
      const char *filename;

      /**
       * Original URI.
       */
      const struct GNUNET_ECRS_URI *uri;

      /**
       * The last block (in plaintext)
       */
      const void *last_block;

      /**
       * Size of the last block
       */
      unsigned int last_size;

    } DownloadProgress;


    struct
    {

      GNUNET_FSUI_DownloadContext dc;

      /**
       * How large is the total download (as far
       * as known so far).
       */
      unsigned long long total;

      /**
       * Information about the download.
       */
      const char *filename;

      /**
       * Original URI.
       */
      const struct GNUNET_ECRS_URI *uri;

    } DownloadCompleted;


    struct
    {

      GNUNET_FSUI_DownloadContext dc;

      /**
       * Error message.
       */
      const char *message;

    } DownloadError;


    struct
    {

      GNUNET_FSUI_DownloadContext dc;

    } DownloadAborted;


    struct
    {

      GNUNET_FSUI_DownloadContext dc;

    } DownloadStopped;


    struct
    {

      GNUNET_FSUI_DownloadContext dc;

    } DownloadSuspended;


    struct
    {

      GNUNET_FSUI_DownloadContext dc;

      /**
       * How large is the total download (as far
       * as known so far).
       */
      unsigned long long total;

      /**
       * Information about the download.
       */
      const char *filename;

      /**
       * Original URI.
       */
      GNUNET_ECRS_FileInfo fi;

      unsigned int anonymityLevel;

    } DownloadStarted;

    struct
    {

      GNUNET_FSUI_DownloadContext dc;

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
      GNUNET_CronTime eta;

      /**
       * Information about the download.
       */
      const char *filename;

      GNUNET_ECRS_FileInfo fi;

      unsigned int anonymityLevel;

      GNUNET_FSUI_State state;

    } DownloadResumed;


    struct
    {

      GNUNET_FSUI_UploadContext uc;

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
      GNUNET_CronTime eta;

      /**
       * Information about the upload.
       */
      const char *filename;

    } UploadProgress;


    struct
    {

      GNUNET_FSUI_UploadContext uc;

      /**
       * How large is the total upload.
       */
      unsigned long long total;

      /**
       * Which file was uploaded?
       */
      const char *filename;

      /**
       * URI of the uploaded file.
       */
      struct GNUNET_ECRS_URI *uri;

    } UploadCompleted;


    struct
    {

      GNUNET_FSUI_UploadContext uc;

    } UploadAborted;


    struct
    {

      GNUNET_FSUI_UploadContext uc;

      const char *message;

    } UploadError;

    struct
    {

      GNUNET_FSUI_UploadContext uc;

    } UploadSuspended;

    struct
    {

      GNUNET_FSUI_UploadContext uc;

    } UploadStopped;


    struct
    {

      GNUNET_FSUI_UploadContext uc;

      /**
       * How large is the total upload (for the current file)
       */
      unsigned long long total;

      unsigned int anonymityLevel;

      /**
       * Information about the upload.
       */
      const char *filename;

    } UploadStarted;

    struct
    {

      GNUNET_FSUI_UploadContext uc;

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
      GNUNET_CronTime eta;

      /**
       * Information about the upload.
       */
      const char *filename;

      unsigned int anonymityLevel;

      GNUNET_FSUI_State state;

      /**
       * Set to the URI of the upload if upload is
       * complete.  Otherwise NULL.
       */
      struct GNUNET_ECRS_URI *uri;

    } UploadResumed;


    struct
    {

      GNUNET_FSUI_UnindexContext uc;

      unsigned long long total;

      unsigned long long completed;

      GNUNET_CronTime eta;

      const char *filename;

    } UnindexProgress;


    struct
    {

      GNUNET_FSUI_UnindexContext uc;

      unsigned long long total;

      const char *filename;

    } UnindexCompleted;


    struct
    {

      GNUNET_FSUI_UnindexContext uc;

    } UnindexAborted;

    struct
    {

      GNUNET_FSUI_UnindexContext uc;

    } UnindexStopped;


    struct
    {

      GNUNET_FSUI_UnindexContext uc;

    } UnindexSuspended;


    struct
    {

      GNUNET_FSUI_UnindexContext uc;

      unsigned long long total;

      unsigned long long completed;

      GNUNET_CronTime eta;

      const char *filename;

      GNUNET_FSUI_State state;

    } UnindexResumed;

    struct
    {

      GNUNET_FSUI_UnindexContext uc;

      unsigned long long total;

      const char *filename;

    } UnindexStarted;


    struct
    {

      GNUNET_FSUI_UnindexContext uc;

      const char *message;

    } UnindexError;

  } data;

} GNUNET_FSUI_Event;

/**
 * @brief opaque FSUI context
 */
struct GNUNET_FSUI_Context;

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
typedef void *(*GNUNET_FSUI_EventProcessor) (void *cls,
                                             const GNUNET_FSUI_Event * event);

/**
 * @brief Start the FSUI manager.  Use the given progress callback to
 * notify the UI about events.  May resume processing pending
 * activities that were running when GNUNET_FSUI_stop was called
 * previously.<p>
 *
 * The basic idea is that graphical user interfaces use their UI name
 * (i.e.  gnunet-gtk) for 'name' and set doResume to GNUNET_YES.  They should
 * have a command-line switch --resume=NAME to allow the user to
 * change 'name' to something else (such that the user can resume
 * state from another GUI).  Shell UIs on the other hand should set
 * doResume to GNUNET_NO and may hard-wire a 'name' (which has no semantic
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
 * @param doResume GNUNET_YES if old activities should be resumed (also
 *          implies that on shutdown, all pending activities are
 *          suspended instead of canceled);
 *          GNUNET_NO if activities should never be resumed
 * @param cb function to call for events, must not be NULL
 * @param closure extra argument to cb
 * @return NULL on error
 */
struct GNUNET_FSUI_Context *GNUNET_FSUI_start (struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *name, unsigned int threadPoolSize, int doResume, GNUNET_FSUI_EventProcessor cb, void *closure); /* fsui.c */

/**
 * Stop all processes under FSUI control (may serialize
 * state to continue later if possible).  Will also let
 * uninterruptable activities complete (you may want to
 * signal the user that this may take a while).
 */
void GNUNET_FSUI_stop (struct GNUNET_FSUI_Context *ctx);        /* fsui.c */


/**
 * Start a search.
 *
 * @return NULL on error
 */
struct GNUNET_FSUI_SearchList *GNUNET_FSUI_search_start (struct GNUNET_FSUI_Context *ctx, unsigned int anonymityLevel, unsigned int maxResults, GNUNET_CronTime timeout, const struct GNUNET_ECRS_URI *uri);    /* search.c */

/**
 * Abort a search.
 *
 * @return GNUNET_SYSERR if such a search is not known
 */
int GNUNET_FSUI_search_abort (struct GNUNET_FSUI_Context *ctx, struct GNUNET_FSUI_SearchList *sl);      /* search.c */

/**
 * Stop a search.
 *
 * @return GNUNET_SYSERR if such a search is not known
 */
int GNUNET_FSUI_search_stop (struct GNUNET_FSUI_Context *ctx, struct GNUNET_FSUI_SearchList *sl);       /* search.c */

/**
 * Start to download a file or directory.
 *
 * @return NULL on error
 */
struct GNUNET_FSUI_DownloadList *GNUNET_FSUI_download_start (struct GNUNET_FSUI_Context *ctx, unsigned int anonymityLevel, int doRecursive, const struct GNUNET_ECRS_URI *uri, const struct GNUNET_ECRS_MetaData *meta, const char *filename, struct GNUNET_FSUI_SearchList *parentSearch, struct GNUNET_FSUI_DownloadList *parentDownload);    /* download.c */

/**
 * Abort a download.  If the dl is for a recursive
 * download, all sub-downloads will also be aborted.
 *
 * @return GNUNET_SYSERR on error
 */
int GNUNET_FSUI_download_abort (struct GNUNET_FSUI_Context *ctx, struct GNUNET_FSUI_DownloadList *dl);  /* download.c */

/**
 * Stop a download.  If the dl is for a recursive
 * download, all sub-downloads will also be stopped.
 *
 * @return GNUNET_SYSERR on error
 */
int GNUNET_FSUI_download_stop (struct GNUNET_FSUI_Context *ctx, struct GNUNET_FSUI_DownloadList *dl);   /* download.c */

/**
 * Method that can be used to select files that
 * should be put into a directory when doing an
 * upload.  For example, "GNUNET_disk_directory_scan"
 * is a legal implementation that would simply
 * select all files of the directory for the
 * upload.
 */
typedef int (*GNUNET_FSUI_DirectoryScanCallback) (void *data,
                                                  const char *filename,
                                                  GNUNET_DirectoryEntryCallback
                                                  dec, void *decClosure);

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
struct GNUNET_FSUI_UploadList *GNUNET_FSUI_upload_start (struct
                                                         GNUNET_FSUI_Context
                                                         *ctx,
                                                         const char *filename,
                                                         GNUNET_FSUI_DirectoryScanCallback
                                                         dsc,
                                                         void *dscClosure,
                                                         unsigned int
                                                         anonymityLevel,
                                                         unsigned int
                                                         priority,
                                                         int doIndex,
                                                         int doExtract,
                                                         int
                                                         individualKeywords,
                                                         GNUNET_CronTime
                                                         expiration,
                                                         const struct
                                                         GNUNET_ECRS_MetaData
                                                         *topLevelMetaData,
                                                         const struct
                                                         GNUNET_ECRS_URI
                                                         *globalURI,
                                                         const struct
                                                         GNUNET_ECRS_URI
                                                         *keyUri);


/**
 * Abort an upload.  If the context is for a recursive
 * upload, all sub-uploads will also be aborted.
 *
 * @return GNUNET_SYSERR on error
 */
int GNUNET_FSUI_upload_abort (struct GNUNET_FSUI_Context *ctx,
                              struct GNUNET_FSUI_UploadList *ul);

/**
 * Stop an upload.  Only to be called for the top-level
 * upload.
 *
 * @return GNUNET_SYSERR on error
 */
int GNUNET_FSUI_upload_stop (struct GNUNET_FSUI_Context *ctx,
                             struct GNUNET_FSUI_UploadList *ul);


/**
 * "delete" operation for uploaded files.  May fail
 * asynchronously, check progress callback.
 *
 * @return NULL on error
 */
struct GNUNET_FSUI_UnindexList *GNUNET_FSUI_unindex_start (struct
                                                           GNUNET_FSUI_Context
                                                           *ctx,
                                                           const char
                                                           *filename);


/**
 * Abort an unindex operation.
 *
 * @return GNUNET_SYSERR on error
 */
int GNUNET_FSUI_unindex_abort (struct GNUNET_FSUI_Context *ctx,
                               struct GNUNET_FSUI_UnindexList *ul);


/**
 * Stop an unindex operation.
 *
 * @return GNUNET_SYSERR on error
 */
int GNUNET_FSUI_unindex_stop (struct GNUNET_FSUI_Context *ctx,
                              struct GNUNET_FSUI_UnindexList *ul);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
