/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
#ifndef GNUNET_FSUI_H
#define GNUNET_FSUI_H

#include "gnunet_util.h"
#include "gnunet_util_cron.h"
#include "gnunet_ecrs_lib.h"

/**
 * How many seconds do we spend on the first test download?
 * (each additional probe will take exponentially longer)
 */
#define GNUNET_FSUI_PROBE_TIME_FACTOR (2 * GNUNET_CRON_MINUTES)

/**
 * Given n running probes, how long should we wait
 * between the end of one probe and the starting of
 * the next probe?  The exact delay will be n*n*PROBE_DELAY+rand(PROBE_DELAY).
 */
#define GNUNET_FSUI_PROBE_DELAY (5 * GNUNET_CRON_MINUTES)

/**
 * Strict upper limit on the number of concurrent probes.
 */
#define GNUNET_FSUI_HARD_PROBE_LIMIT 128


/**
 * If we have more downloads pending then we
 * can support concurrently, after how much
 * runtime of a download (without progress)
 * should we consider pausing it to give others
 * a chance?  Specified as a bit-mask where 
 * each bit represents a minute of time.
 * (0xFF == 8 minutes, 0x7FFF == 15 minutes).
 * Note that all legal values correspond to
 * values computable using "(1 << (N+1))-1"
 * Where "N" would be the number of minutes
 * without progress.  A 64-bit value is
 * permissable.<p>
 *
 * Note that downloads will NOT be automatically
 * paused even if they do not make any progress
 * UNLESS all download threads are in use.
 */
#define GNUNET_FSUI_DL_KILL_TIME_MASK 0x7FFF

/**
 * Track record for a given result.
 */
struct SearchResultList
{

  struct SearchResultList *next;

  /**
   * Test download (if any).
   */
  struct GNUNET_ECRS_DownloadContext *test_download;

  /**
   * Which individual searches does this result match?
   * (do NOT free the search records that this array
   * points to when freeing this result!).
   */
  struct SearchRecordList **matchingSearches;

  /**
   * What info do we have about this result?
   */
  GNUNET_ECRS_FileInfo fi;

  /**
   * For how many searches did we get this result?
   * (size of the matchingSearches array).
   */
  unsigned int matchingSearchCount;

  /**
   * How many more searches that are mandatory do
   * we need to match against before displaying?
   * (once this value reaches zero, we can display
   * the result).
   */
  unsigned int mandatoryMatchesRemaining;

  /**
   * How often did a test download succeed?
   */
  unsigned int probeSuccess;

  /**
   * How often did a test download fail?
   */
  unsigned int probeFailure;

  /**
   * When did we start the test?  Set to 0
   * if the download was successful.
   */
  GNUNET_CronTime test_download_start_time;

  /**
   * When did the last probe complete?
   */
  GNUNET_CronTime last_probe_time;

};

/**
 * Track record for the ECRS search requests.
 */
struct SearchRecordList
{

  struct SearchRecordList *next;

  /**
   * Handles to the ECRS SearchContexts.
   */
  struct GNUNET_ECRS_SearchContext *search;

  /**
   * Which keyword are we searching? (this is
   * the exact URI given to ECRS which should
   * contain only a single keyword).
   */
  struct GNUNET_ECRS_URI *uri;

  /**
   * Key for the search.
   */
  GNUNET_HashCode key;

  /**
   * Do we have to have a match in this search
   * for displaying the result (did the keyword
   * that was specified start with a "+"?).
   */
  unsigned int is_required;

};

/**
 * @brief list of active searches
 */
typedef struct GNUNET_FSUI_SearchList
{

  /**
   * start time of the search
   */
  GNUNET_CronTime start_time;

  /**
   * Searches are kept in a simple linked list.
   */
  struct GNUNET_FSUI_SearchList *next;

  /**
   * Context for this search
   */
  struct GNUNET_FSUI_Context *ctx;

  /**
   * Context used for availability probes and the
   * ECRS searches
   */
  struct GNUNET_FS_SearchContext *probe_context;

  /**
   * Handles to the ECRS SearchContexts.
   */
  struct SearchRecordList *searches;

  /**
   * Which URI are we searching?
   */
  struct GNUNET_ECRS_URI *uri;

  /**
   * What downloads belong to this search (full downloads).
   */
  struct GNUNET_FSUI_DownloadList **my_downloads;

  /**
   * List of all results found so far.
   */
  struct SearchResultList *resultsReceived;

  /**
   * Client context for the search.
   */
  void *cctx;

  /**
   * Desired anonymity level for this search
   */
  unsigned int anonymityLevel;

  /**
   * Number of mandatory keywords in our URI.
   */
  unsigned int mandatory_keyword_count;

  /**
   * Number of downloads associated with this search.
   */
  unsigned int my_downloads_size;

  /**
   * FSUI state of this search.
   */
  GNUNET_FSUI_State state;

} GNUNET_FSUI_SearchList;

/**
 * @brief list of active downloads
 */
typedef struct GNUNET_FSUI_DownloadList
{

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
   * Bit (1 << T) is set to 1 if we made any progress
   * "T" minutes ago.
   */
  unsigned long long progressBits;

  /**
   * URI for this download.
   */
  GNUNET_ECRS_FileInfo fi;

  /**
   * Filename for this download.
   */
  char *filename;

  /**
   * Next in the linked list of all downloads
   * kept in FSUI context.
   */
  struct GNUNET_FSUI_DownloadList *next;

  /**
   * For recursive downloads, download entry for
   * the parent.
   */
  struct GNUNET_FSUI_DownloadList *parent;

  /**
   * If this is a recursive download, this is the
   * list of sub-downloads that are currently
   * going on in parallel.
   */
  struct GNUNET_FSUI_DownloadList *child;

  /**
   * Search that this download belongs to (maybe NULL)
   */
  struct GNUNET_FSUI_SearchList *search;

  /**
   * FSUI context for this download.
   */
  struct GNUNET_FSUI_Context *ctx;

  /**
   * Client context for the downloadx
   */
  void *cctx;

  /**
   * Currently assigned ECRS context (if any).
   */
  struct GNUNET_ECRS_DownloadContext *handle;

  /**
   * FIs of completed sub-downloads.
   */
  struct GNUNET_ECRS_URI **completedDownloads;

  /**
   * When did the download start?  Note that if a download is resumed,
   * this time is set such that the total time is accurate, not the
   * absolute start time.<p>
   * While the download thread is running, this is the
   * absolute start time assuming the thread ran continuously.
   */
  GNUNET_CronTime startTime;

  /**
   * While the download thread is suspended, this is the
   * total amount of time that all threads have consumed so far.
   * While the download thread is running, startTime should
   * be used instead (since runTime maybe outdated).
   */
  GNUNET_CronTime runTime;

  /**
   * Last time we updated (shifted) our progressBits.
   */
  GNUNET_CronTime lastProgressTime;

  /**
   * When was this thread blocked from resuming if
   * all download queues are busy? (only
   * valid if the thread state is FSUI_PENDING).
   */
  GNUNET_CronTime block_resume;

  /**
   * Is this a recursive download? (GNUNET_YES/GNUNET_NO)
   * Also set to GNUNET_NO once the recursive downloads
   * have been triggered!
   */
  int is_recursive;

  /**
   * Is this file a directory?  Set to GNUNET_YES either if the first block
   * contains the correct directory MAGIC, or if the mime-type in the
   * meta-data was saying that the file is a directory.  Set to GNUNET_SYSERR
   * initially if no mime-type is specified and we have not yet seen
   * the first block.  Set to GNUNET_NO if a different mime-type was given or
   * if the first block did not have the correct MAGIC.<p>
   *
   * As long as is_directory is GNUNET_SYSERR we _defer_ processing the other
   * blocks of the file that we may receive.  After we established
   * that this is a directory (and if is_recursive is GNUNET_YES), we try to
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
  GNUNET_FSUI_State state;

} GNUNET_FSUI_DownloadList;

/**
 * Context for the unindex thread.
 */
typedef struct GNUNET_FSUI_UnindexList
{

  GNUNET_CronTime start_time;

  struct GNUNET_FSUI_UnindexList *next;

  struct GNUNET_ThreadHandle *handle;

  char *filename;

  struct GNUNET_FSUI_Context *ctx;

  void *cctx;

  GNUNET_FSUI_State state;

} GNUNET_FSUI_UnindexList;


/**
 * Shared context for upload of entire structure.
 */
typedef struct GNUNET_FSUI_UploadShared
{

  GNUNET_CronTime expiration;

  GNUNET_FSUI_DirectoryScanCallback dsc;

  void *dscClosure;

  EXTRACTOR_ExtractorList *extractors;

  struct GNUNET_FSUI_Context *ctx;

  struct GNUNET_ThreadHandle *handle;

  /**
   * Keywords to be used for all uploads.
   */
  struct GNUNET_ECRS_URI *global_keywords;

  char *extractor_config;

  char *top_filename;

  int doIndex;

  unsigned int anonymityLevel;

  unsigned int priority;

  int individualKeywords;

} GNUNET_FSUI_UploadShared;

/**
 * Context for each file upload.
 */
typedef struct GNUNET_FSUI_UploadList
{

  unsigned long long completed;

  unsigned long long total;

  GNUNET_CronTime start_time;

  struct GNUNET_FSUI_UploadShared *shared;

  struct GNUNET_FSUI_UploadList *next;

  struct GNUNET_FSUI_UploadList *child;

  struct GNUNET_FSUI_UploadList *parent;

  /**
   * Metadata for this file.
   */
  struct GNUNET_MetaData *meta;

  /**
   * Keywords to be used for this upload.
   */
  struct GNUNET_ECRS_URI *keywords;

  /**
   * URI for this file (set upon completion).
   */
  struct GNUNET_ECRS_URI *uri;

  char *filename;

  /**
   * FSUI-client context.
   */
  void *cctx;

  /**
   * State of this sub-process.
   */
  GNUNET_FSUI_State state;

  /**
   * Is this a directory (or a file)?
   */
  int is_directory;

} GNUNET_FSUI_UploadList;

/**
 * @brief global state of the FSUI library
 */
typedef struct GNUNET_FSUI_Context
{

  /**
   * What is the minimum, non-zero block_resume value of
   * any download? (updated in each iteration over
   * all downloads).
   */
  GNUNET_CronTime min_block_resume;

  /**
   * Running value in this iteration of the update
   * for min_block_resume.
   */
  GNUNET_CronTime next_min_block_resume;

  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  /**
   * IPC semaphore used to ensure mutual exclusion
   * between different processes of the same name
   * that all use resume.
   */
  struct GNUNET_IPC_Semaphore *ipc;

  /**
   * Name of the tool using FSUI (used for resume).
   */
  char *name;

  /**
   * Lock to synchronize access to the FSUI Context.
   */
  struct GNUNET_Mutex *lock;

  struct GNUNET_CronManager *cron;

  /**
   * Callback for notifying the client about events.
   */
  GNUNET_FSUI_EventProcessor ecb;

  /**
   * Extra argument to ecb.
   */
  void *ecbClosure;

  /**
   * Collection related data.
   */
  char *collectionData;

  unsigned int collectionDataSize;

  /**
   * List of active searches.
   */
  GNUNET_FSUI_SearchList *activeSearches;

  /**
   * List of active unindex operations.
   */
  GNUNET_FSUI_UnindexList *unindexOperations;

  GNUNET_FSUI_UploadList activeUploads;

  /**
   * Root of the tree of downloads.  On shutdown,
   * FSUI must abort each of these downloads.
   */
  GNUNET_FSUI_DownloadList activeDownloads;

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

  /**
   * Number of currently active search probes.
   */
  unsigned int active_probes;

} GNUNET_FSUI_Context;

/* ************ cross-file prototypes ************ */

/**
 * Starts or stops download threads in accordance with thread pool
 * size and active downloads.  Call only while holding FSUI lock (or
 * during start/stop).
 *
 * @return GNUNET_YES if change done that may require re-trying
 */
int GNUNET_FSUI_updateDownloadThread (GNUNET_FSUI_DownloadList * list);

int
GNUNET_FSUI_search_progress_callback (const GNUNET_ECRS_FileInfo * fi,
                                      const GNUNET_HashCode * key, int isRoot,
                                      void *cls);

void *GNUNET_FSUI_uploadThread (void *dl);

void *GNUNET_FSUI_unindexThread (void *cls);

void GNUNET_FSUI_serialize (struct GNUNET_FSUI_Context *ctx);

void GNUNET_FSUI_deserialize (struct GNUNET_FSUI_Context *ctx);

#endif
