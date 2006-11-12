/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/fsui.h
 * @brief internal definitions for libfsui
 * @author Christian Grothoff
 */
#ifndef FSUI_H
#define FSUI_H

#include "gnunet_util.h"
#include "gnunet_util_cron.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_blockstore.h"

/**
 * Track record for a given result.
 */
typedef struct {

  /**
   * What are these keys?
   */
  HashCode512 * matchingKeys;

  /**
   * What info do we have about this result?
   */
  ECRS_FileInfo fi;

  /**
   * For how many keys (hash of keyword) did we
   * get this result?
   */
  unsigned int matchingKeyCount;

} ResultPending;

/**
 * @brief list of active searches
 */
typedef struct FSUI_SearchList {

  /**
   * Desired timeout (relative) for this search
   */
  cron_t timeout;

  /**
   * start time of the search
   */
  cron_t start_time;

  /**
   * Searches are kept in a simple linked list.
   */
  struct FSUI_SearchList * next;

  /**
   * Context for this search
   */
  struct FSUI_Context * ctx;

  /**
   * Handle to the thread which performs the search.
   */
  struct PTHREAD * handle;

  /**
   * Which URI are we searching?
   */
  struct ECRS_URI * uri;

  /**
   * What downloads belong to this search?
   */
  struct FSUI_DownloadList ** my_downloads;

  /**
   * List of all results found so far.
   */
  ECRS_FileInfo * resultsReceived;

  ResultPending * unmatchedResultsReceived;

  void * cctx;

  /**
   * Desired anonymity level for this search
   */
  unsigned int anonymityLevel;

  /**
   * Maximum number of results requested.
   */
  unsigned int maxResults;

  /**
   * Of how many individual queries does the
   * boolean query consist (1 for non-boolean queries).
   */
  unsigned int numberOfURIKeys;

  /**
   * Size of the resultsReceived array
   */
  unsigned int sizeResultsReceived;

  /**
   * Number of downloads associated with this search.
   */
  unsigned int my_downloads_size;

  /**
   * Size of the queue of results that matched at least
   * one of the queries in the boolean query, but not
   * yet all of them.
   */
  unsigned int sizeUnmatchedResultsReceived;

  FSUI_State state;

} FSUI_SearchList;

/**
 * @brief list of active downloads
 */
typedef struct FSUI_DownloadList {

  /**
   * How many bytes is this download in total
   * (including files in directory).
   */
  unsigned long long total;

  /**
   * How many bytes have been retrieved so far?
   */
  unsigned long long completed;

  /**
   * URI for this download.
   */
  ECRS_FileInfo fi;

  /**
   * Filename for this download.
   */
  char * filename;

  /**
   * Next in the linked list of all downloads
   * kept in FSUI context.
   */
  struct FSUI_DownloadList * next;

  /**
   * For recursive downloads, download entry for
   * the parent.
   */
  struct FSUI_DownloadList * parent;

  /**
   * If this is a recursive download, this is the
   * list of sub-downloads that are currently
   * going on in parallel.
   */
  struct FSUI_DownloadList * child;

  /**
   * Search that this download belongs to (maybe NULL)
   */
  struct FSUI_SearchList * search;

  /**
   * FSUI context for this download.
   */
  struct FSUI_Context * ctx;

  /**
   * Client context for the downloadx
   */
  void * cctx;

  /**
   * Currently assigned thread (if any).
   */
  struct PTHREAD * handle;

  /**
   * FIs of completed sub-downloads.
   */
  struct ECRS_URI ** completedDownloads;

  /**
   * When did the download start?  Note that if a download is resumed,
   * this time is set such that the total time is accurate, not the
   * absolute start time.<p>
   * While the download thread is running, this is the
   * absolute start time assuming the thread ran continuously.
   */
  cron_t startTime;

  /**
   * While the download thread is suspended, this is the
   * total amount of time that all threads have consumed so far.
   * While the download thread is running, startTime should
   * be used instead (since runTime maybe outdated).
   */
  cron_t runTime;

  /**
   * Is this a recursive download? (YES/NO)
   */
  int is_recursive;

  /**
   * Is this file a directory?  Set to YES either if the first block
   * contains the correct directory MAGIC, or if the mime-type in the
   * meta-data was saying that the file is a directory.  Set to SYSERR
   * initially if no mime-type is specified and we have not yet seen
   * the first block.  Set to NO if a different mime-type was given or
   * if the first block did not have the correct MAGIC.<p>
   *
   * As long as is_directory is SYSERR we _defer_ processing the other
   * blocks of the file that we may receive.  After we established
   * that this is a directory (and if is_recursive is YES), we try to
   * decode the directory eagerly and start the other downloads in
   * parallel.  Once the directory is complete, we make sure that
   * really all files have been started and wait for their completion.
   */
  int is_directory;

  /**
   * Anonymity level desired for this download.
   */
  unsigned int anonymityLevel;

  /**
   * Number of completed sub-downloads.
   */
  unsigned int completedDownloadsCount;

  /**
   * State of the download.
   */
  FSUI_State state;

} FSUI_DownloadList;

/**
 * Context for the unindex thread.
 */
typedef struct FSUI_UnindexList {

  cron_t start_time;

  struct FSUI_UnindexList * next;

  struct PTHREAD * handle;

  char * filename;

  struct FSUI_Context * ctx;

  void * cctx;

  FSUI_State state;

} FSUI_UnindexList;


/**
 * Shared context for upload of entire structure.
 */
typedef struct FSUI_UploadShared {

  cron_t expiration;

  DirectoryScanCallback dsc;

  void * dscClosure;
		
  EXTRACTOR_ExtractorList * extractors;

  struct FSUI_Context * ctx;

  struct PTHREAD * handle;

  /**
   * Keywords to be used for all uploads.
   */
  struct ECRS_URI * global_keywords;

  char * extractor_config;

  int doIndex;

  unsigned int anonymityLevel;

  unsigned int priority;

  int individualKeywords;

} FSUI_UploadShared;

/**
 * Context for each file upload.
 */
typedef struct FSUI_UploadList {

  unsigned long long completed;

  unsigned long long total;

  cron_t start_time;

  struct FSUI_UploadShared * shared;

  struct FSUI_UploadList * next;

  struct FSUI_UploadList * child;

  struct FSUI_UploadList * parent;

  /**
   * Metadata for this file.
   */
  struct ECRS_MetaData * meta;

  /**
   * Keywords to be used for this upload.
   */
  struct ECRS_URI * keywords;

  /**
   * URI for this file (set upon completion).
   */
  struct ECRS_URI * uri;

  char * filename;

  /**
   * FSUI-client context.
   */
  void * cctx;

  /**
   * State of this sub-process.
   */
  FSUI_State state;

} FSUI_UploadList;

/**
 * @brief global state of the FSUI library
 */
typedef struct FSUI_Context {

  struct GE_Context * ectx;

  struct GC_Configuration * cfg;

  /**
   * IPC semaphore used to ensure mutual exclusion
   * between different processes of the same name
   * that all use resume.
   */
  struct IPC_SEMAPHORE * ipc;

  /**
   * Name of the tool using FSUI (used for resume).
   */
  char * name;

  /**
   * Lock to synchronize access to the FSUI Context.
   */
  struct MUTEX * lock;

  struct CronManager * cron;

  /**
   * Callback for notifying the client about events.
   */
  FSUI_EventCallback ecb;

  /**
   * Extra argument to ecb.
   */
  void * ecbClosure;

  /**
   * Collection related data.
   */
  DataContainer * collectionData;

  /**
   * List of active searches.
   */
  FSUI_SearchList * activeSearches;

  /**
   * List of active unindex operations.
   */
  FSUI_UnindexList * unindexOperations;

  FSUI_UploadList activeUploads;

  /**
   * Root of the tree of downloads.  On shutdown,
   * FSUI must abort each of these downloads.
   */
  FSUI_DownloadList activeDownloads;

  /**
   * Target size of the thread pool for parallel
   * downloads.
   */
  unsigned int threadPoolSize;

  /**
   * Number of download threads that are
   * currently active.
   */
  unsigned int activeDownloadThreads;

} FSUI_Context;

/* ************ cross-file prototypes ************ */

/**
 * Starts or stops download threads in accordance with thread pool
 * size and active downloads.  Call only while holding FSUI lock (or
 * during start/stop).
 *
 * @return YES if change done that may require re-trying
 */
int FSUI_updateDownloadThread(FSUI_DownloadList * list);

void * FSUI_uploadThread(void * dl);

void * FSUI_searchThread(void * pos);

void * FSUI_unindexThread(void * cls);

void FSUI_serialize(struct FSUI_Context * ctx);

void FSUI_deserialize(struct FSUI_Context * ctx);

#endif
