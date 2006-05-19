/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @brief definition of the FSUI_Context
 * @author Christian Grothoff
 */
#ifndef FSUI_H
#define FSUI_H

#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_blockstore.h"

/**
 * Linked list of FSUI threads.
 */
typedef struct FSUI_ThreadList {

  /**
   * FSUI threads are kept in a simple
   * linked list
   */
  struct FSUI_ThreadList * next;

  /**
   * Handle to a thread.
   */
  PTHREAD_T handle;

  /**
   * Flag that indicates if it is safe (i.e.
   * non-blocking) to call join on the handle.
   * Set to YES by an FSUI thread upon exit.
   */
  int isDone;
} FSUI_ThreadList;

/**
 * Track record for a given result.
 */
typedef struct {

  /**
   * For how many keys (hash of keyword) did we
   * get this result?
   */
  unsigned int matchingKeyCount;

  /**
   * What are these keys?
   */
  HashCode512 * matchingKeys;

  /**
   * What info do we have about this result?
   */
  ECRS_FileInfo fi;
} ResultPending;

/**
 * @brief list of active searches
 */
typedef struct FSUI_SearchList {

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
  PTHREAD_T handle;

  /**
   * Set this to YES to signal the search thread that
   * termination is desired.  Then join on handle.
   */
  int signalTerminate;

  /**
   * Which URI are we searching?
   */
  struct ECRS_URI * uri;

  /**
   * Desired anonymity level for this search
   */
  unsigned int anonymityLevel;

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
   * List of all results found so far.
   */
  ECRS_FileInfo * resultsReceived;

  /**
   * Size of the queue of results that matched at least
   * one of the queries in the boolean query, but not
   * yet all of them.
   */
  unsigned int sizeUnmatchedResultsReceived;

  ResultPending * unmatchedResultsReceived;

} FSUI_SearchList;

/**
 * Current state of a download.
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
typedef enum {
  FSUI_DOWNLOAD_PENDING = 0,
  FSUI_DOWNLOAD_ACTIVE = 1,
  FSUI_DOWNLOAD_COMPLETED = 2,
  FSUI_DOWNLOAD_COMPLETED_JOINED = 3,
  FSUI_DOWNLOAD_ABORTED = 4,
  FSUI_DOWNLOAD_ABORTED_JOINED = 5,
  FSUI_DOWNLOAD_ERROR = 6,
  FSUI_DOWNLOAD_ERROR_JOINED = 7,
  FSUI_DOWNLOAD_SUSPENDING = 8,
} FSUI_DownloadState;


/**
 * @brief list of active downloads
 */
typedef struct FSUI_DownloadList {
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
   * FSUI context for this download.
   */
  struct FSUI_Context * ctx;

  /**
   * State of the download.
   */
  FSUI_DownloadState state;

  /**
   * Currently assigned thread (if any).
   */
  PTHREAD_T handle;

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
   * How many bytes have been retrieved so far for this particular file only.
   */
  unsigned long long completedFile;

  /**
   * URI for this download.
   */
  struct ECRS_URI * uri;

  /**
   * Filename for this download.
   */
  char * filename;

  /**
   * Is this a recursive download? (YES/NO)
   */
  int is_recursive;

  /**
   * When did the download start?  Note that if a download is resumed,
   * this time is set such that the total time is accurate, not the
   * absolute start time.
   */
  cron_t startTime;

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
   * FIs of completed sub-downloads.
   */
  struct ECRS_URI ** completedDownloads;

  /**
   * Number of completed sub-downloads.
   */
  unsigned int completedDownloadsCount;

} FSUI_DownloadList;

/**
 * @brief global state of the FSUI library
 */
typedef struct FSUI_Context {

  /**
   * IPC semaphore used to ensure mutual exclusion
   * between different processes of the same name
   * that all use resume.
   */
  IPC_Semaphore * ipc;

  /**
   * Name of the tool using FSUI (used for resume).
   */
  char * name;

  /**
   * Lock to synchronize access to the FSUI Context.
   */
  Mutex lock;

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
   * Active FSUI threads that cannot be stopped and
   * that FSUI must call join on before it may shutdown.
   */
  FSUI_ThreadList * activeThreads;

  /**
   * List of active searches.
   */
  FSUI_SearchList * activeSearches;

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

/**
 * Starts or stops download threads in accordance with thread pool
 * size and active downloads.  Call only while holding FSUI lock (or
 * during start/stop).
 *
 * @return YES if change done that may require re-trying
 */
int updateDownloadThread(FSUI_DownloadList * list);

/**
 * Free the subtree (assumes all threads have already been stopped and
 * that the FSUI lock is either held or that we are in FSUI stop!).
 */
void freeDownloadList(FSUI_DownloadList * list);

/**
 * Cleanup the FSUI context (removes dead entries from
 * activeThreads / activeSearches / activeDownloads).
 */
void cleanupFSUIThreadList(FSUI_Context * ctx);


/* FOR RESUME: from download.c */
/**
 * Thread that downloads a file.
 */
void * downloadThread(void * dl);

/* from search.c */
/**
 * FOR RESUME: Thread that searches for data.
 */
void * searchThread(void /* FSUI_SearchList */ * pos);

#endif
