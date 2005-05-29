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
  struct FSUI_SearchList * next;

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

  unsigned int anonymityLevel;

  /**
   * Of how many individual queries does the
   * boolean query consist (1 for non-boolean queries).
   */
  unsigned int numberOfURIKeys;

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
  struct FSUI_DownloadList * subDownloads;

  /**
   * Next entry in the linked list of subdownloads.
   */
  struct FSUI_DownloadList * subDownloadsNext;

  /**
   * FSUI context for this download.
   */
  struct FSUI_Context * ctx;

  /**
   * Handle to the thread which performs the download.
   */
  PTHREAD_T handle;

  /**
   * Set this to YES to signal the download thread that
   * termination is desired.  Then join on handle.
   */
  int signalTerminate;

  unsigned long long total;

  unsigned long long completed;

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
   * When did the download start?
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

  IPC_Semaphore * ipc;

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
   * List of active downloads
   */
  FSUI_DownloadList * activeDownloads;

} FSUI_Context;

/**
 * Cleanup the FSUI context (removes dead entries from
 * activeThreads / activeSearches).
 */
void cleanupFSUIThreadList(FSUI_Context * ctx);


/* from download.c */
/**
 * Thread that downloads a file.
 */
void * downloadThread(FSUI_DownloadList * dl);

/* from search.c */
/**
 * Thread that searches for data.
 */
void * searchThread(FSUI_SearchList * pos);

#endif
