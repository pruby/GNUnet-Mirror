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
 * @file applications/fs/fsui/download.c
 * @brief download functions
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

#define DEBUG_DTM NO

/**
 * Start to download a file.
 *
 * @return OK on success, SYSERR if the target file is
 *  already used for another download at the moment (or
 *  if the disk does not have enough space).
 */
static int startDownload(struct FSUI_Context * ctx,
			 unsigned int anonymityLevel,
			 const struct ECRS_URI * uri,
			 const char * filename,
			 int is_recursive,
			 FSUI_DownloadList * parent);

static int triggerRecursiveDownload(const ECRS_FileInfo * fi,
				    const HashCode512 * key,
				    int isRoot,
				    void * prnt) {
  FSUI_DownloadList * parent = prnt;
  int i;
  FSUI_DownloadList * pos;
  char * filename;
  char * fullName;
  char * dotdot;

  if (isRoot == YES)
    return OK; /* namespace ad, ignore */

  FSUI_trackURI(fi);
  for (i=0;i<parent->completedDownloadsCount;i++)
    if (ECRS_equalsUri(parent->completedDownloads[i],
		       fi->uri))
      return OK; /* already complete! */
  pos = parent->child;
  while (pos != NULL) {
    if (ECRS_equalsUri(pos->uri,
		       fi->uri))
      return OK; /* already downloading */
    pos = pos->next;
  }
  filename = ECRS_getFromMetaData(fi->meta,
				  EXTRACTOR_FILENAME);
  if (filename == NULL) {
    char * tmp = ECRS_uriToString(fi->uri);
    GNUNET_ASSERT(strlen(tmp) >= strlen(ECRS_URI_PREFIX) + strlen(ECRS_FILE_INFIX));
    filename = STRDUP(&tmp[strlen(ECRS_URI_PREFIX) + strlen(ECRS_FILE_INFIX)]);
    FREE(tmp);
  }
  fullName = MALLOC(strlen(parent->filename) +
		    + strlen(GNUNET_DIRECTORY_EXT) + 2
		    + strlen(filename));
  strcpy(fullName, parent->filename);
  strcat(fullName, GNUNET_DIRECTORY_EXT);
  while (NULL != (dotdot = strstr(fullName, "..")))
    dotdot[0] = dotdot[1] = '_';
  mkdirp(fullName);
  strcat(fullName, DIR_SEPARATOR_STR);
  while (NULL != (dotdot = strstr(filename, "..")))
    dotdot[0] = dotdot[1] = '_';
  strcat(fullName, filename);
  FREE(filename);
#if DEBUG_DTM
  LOG(LOG_DEBUG,
      "Starting recursive download of `%s'\n",
      fullName);
#endif
  startDownload(parent->ctx,
		parent->anonymityLevel,
		fi->uri,
		fullName,
		YES,
		parent);
  FREE(fullName);
  return OK;
}

/**
 * Progress notification from ECRS.  Tell FSUI client.
 */
static void
downloadProgressCallback(unsigned long long totalBytes,
			 unsigned long long completedBytes,
			 cron_t eta,
			 unsigned long long lastBlockOffset,
			 const char * lastBlock,
			 unsigned int lastBlockSize,
			 void * cls) {
  FSUI_DownloadList * dl = cls;
  FSUI_Event event;
  struct ECRS_MetaData * md;
  FSUI_DownloadList * root;

  root = dl;
  while ( (root->parent != NULL) &&
	  (root->parent != &dl->ctx->activeDownloads) )
    root = root->parent;

  dl->completedFile = completedBytes;
  event.type = FSUI_download_progress;
  event.data.DownloadProgress.total = totalBytes;
  event.data.DownloadProgress.completed = dl->completed + completedBytes;
  event.data.DownloadProgress.last_offset = lastBlockOffset;
  event.data.DownloadProgress.eta = eta;
  event.data.DownloadProgress.last_block = lastBlock;
  event.data.DownloadProgress.last_size = lastBlockSize;
  event.data.DownloadProgress.filename = dl->filename;
  event.data.DownloadProgress.uri = dl->uri;
  event.data.DownloadProgress.start_time = dl->startTime;
  event.data.DownloadProgress.is_recursive = dl->is_recursive;
  event.data.DownloadProgress.main_filename = root->filename;
  event.data.DownloadProgress.main_uri = root->uri;
  event.data.DownloadProgress.pos = dl;
  dl->ctx->ecb(dl->ctx->ecbClosure,
	       &event);
  if ( (lastBlockOffset == 0) &&
       (dl->is_directory == SYSERR) ) {
    /* check if this is a directory */
    if ( (lastBlockSize > strlen(GNUNET_DIRECTORY_MAGIC)) &&
	 (0 == strncmp(GNUNET_DIRECTORY_MAGIC,
		       lastBlock,
		       strlen(GNUNET_DIRECTORY_MAGIC)) ) )
      dl->is_directory = YES;
    else
      dl->is_directory = NO;
  }
  if ( (dl->is_recursive == YES) &&
       (dl->is_directory == YES) ) {
    md = NULL;
    MUTEX_LOCK(&dl->ctx->lock);
    ECRS_listDirectory(lastBlock,
		       lastBlockSize,
		       &md,
		       &triggerRecursiveDownload,
		       dl);
    MUTEX_UNLOCK(&dl->ctx->lock);
    if (md != NULL)
      ECRS_freeMetaData(md);
  }
}

/**
 * Check if termination of this download is desired.
 */
static int
testTerminate(void * cls) {
  FSUI_DownloadList * dl = cls;
  if (dl->signalTerminate == YES)
    return SYSERR;
  else
    return OK;
}

/**
 * Thread that downloads a file.
 */
void * downloadThread(void * cls) {
  FSUI_DownloadList * dl = cls;
  int ret;
  FSUI_Event event;
  struct ECRS_MetaData * md;
  FSUI_DownloadList * root;
  unsigned long long totalBytes;

#if DEBUG_DTM
  LOG(LOG_DEBUG,
      "Download thread for `%s' started...\n",
      dl->filename);
#endif
  GNUNET_ASSERT(dl->ctx != NULL);
  GNUNET_ASSERT(dl->filename != NULL);
  ret = ECRS_downloadFile(dl->uri,
			  dl->filename,
			  dl->anonymityLevel,
			  &downloadProgressCallback,
			  dl,
			  &testTerminate,
			  dl);
  if (ret == OK) {
    dl->finished = YES;
    totalBytes = ECRS_fileSize(dl->uri);
  } else {
    totalBytes = 0;
  }
  root = dl;
  while (root->parent != &dl->ctx->activeDownloads) {
    root->completed += totalBytes;
    root = root->parent;
  }
  root->completed += totalBytes;
    

  if ( (ret == OK) &&
       (dl->is_recursive) &&
       (dl->is_directory) ) {
    char * dirBlock;
    int fd;

#ifdef O_LARGEFILE
    fd = fileopen(dl->filename,
		  O_LARGEFILE | O_RDONLY);
#else
    fd = fileopen(dl->filename,
		  O_RDONLY);
#endif
    if (fd == -1) {
      LOG_FILE_STRERROR(LOG_ERROR,
			"OPEN",
			dl->filename);
    } else {
      dirBlock = MMAP(NULL,
		      totalBytes,
		      PROT_READ,
		      MAP_SHARED,
		      fd,
		      0);
      /* load directory, start downloads */
      md = NULL;
      MUTEX_LOCK(&dl->ctx->lock);
      ECRS_listDirectory(dirBlock,
			 totalBytes,
			 &md,
			 &triggerRecursiveDownload,
			 dl);
      MUTEX_UNLOCK(&dl->ctx->lock);
      ECRS_freeMetaData(md);
      MUNMAP(dirBlock, totalBytes);
      closefile(fd);
    }
  }
  if (ret != OK) {
    if (dl->signalTerminate == YES) {
      event.type = FSUI_download_aborted;
      event.data.DownloadError.message = _("Download aborted.");
    } else {
      event.type = FSUI_download_error;
      event.data.DownloadError.message = _("ECRS download failed (see logs).");
    }
    event.data.DownloadError.pos = dl;
    dl->ctx->ecb(dl->ctx->ecbClosure,
		 &event);
    dl->signalTerminate = YES;
  } else {
    dl->signalTerminate = YES;
    GNUNET_ASSERT(dl != &dl->ctx->activeDownloads);
    while ( (dl != NULL) &&
	    (dl->ctx != NULL) &&
	    (dl != &dl->ctx->activeDownloads) ) {
      event.type = FSUI_download_complete;
      event.data.DownloadProgress.total = dl->total;
      event.data.DownloadProgress.completed = dl->completed;
      event.data.DownloadProgress.last_offset = 0;
      event.data.DownloadProgress.eta = cronTime(NULL);
      event.data.DownloadProgress.last_block = NULL;
      event.data.DownloadProgress.last_size = 0;
      event.data.DownloadProgress.filename = dl->filename;
      event.data.DownloadProgress.uri = dl->uri;
      event.data.DownloadProgress.start_time = dl->startTime;
      event.data.DownloadProgress.is_recursive = dl->is_recursive;
      event.data.DownloadProgress.main_filename = root->filename;
      event.data.DownloadProgress.main_uri = root->uri;
      event.data.DownloadProgress.pos = dl;
      dl->ctx->ecb(dl->ctx->ecbClosure,
		   &event);
      dl = dl->parent;
    }
  }
#if DEBUG_DTM 
  LOG(LOG_DEBUG,
      "Download thread for `%s' terminated (%s)...\n",
      dl->filename,
      ret == OK ? "COMPLETED" : "ABORTED");
#endif
  return NULL;
}

/**
 * Start to download a file.
 *
 * @return OK on success, SYSERR if the target file is
 *  already used for another download at the moment (or
 *  if the disk does not have enough space).
 */
static int startDownload(struct FSUI_Context * ctx,
			 unsigned int anonymityLevel,
			 const struct ECRS_URI * uri,
			 const char * filename,
			 int is_recursive,
			 FSUI_DownloadList * parent) {
  FSUI_DownloadList * dl;
  FSUI_DownloadList * root;
  unsigned long long totalBytes;

  GNUNET_ASSERT(ctx != NULL);
  if (! (ECRS_isFileUri(uri) ||
	 ECRS_isLocationUri(uri)) ) {
    BREAK(); /* wrong type of URI! */
    return SYSERR;
  }
  LOG(LOG_DEBUG,
      "Starting download of file `%s'\n",
      filename);
  dl = MALLOC(sizeof(FSUI_DownloadList));
  memset(dl, 0, sizeof(FSUI_DownloadList));
  cronTime(&dl->startTime); 
  dl->signalTerminate = SYSERR;
  dl->finished = NO;
  dl->is_recursive = is_recursive;
  dl->parent = parent;
  dl->is_directory = SYSERR; /* don't know */
  dl->anonymityLevel = anonymityLevel;
  dl->ctx = ctx;
  dl->filename = STRDUP(filename);
  dl->uri = ECRS_dupUri(uri);
  dl->total = ECRS_fileSize(uri);
  dl->next = parent->child;
  totalBytes = ECRS_fileSize(uri);
  parent->child = dl;

  root = dl;
  while ( (root->parent != NULL) &&
	  (root->parent != &dl->ctx->activeDownloads) ) {
    root = root->parent;
    root->total += totalBytes;
  }
  return OK;
}

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
		       const char * filename) {
  int ret;

  GNUNET_ASSERT(filename != NULL);
  GNUNET_ASSERT(ctx != NULL);
  MUTEX_LOCK(&ctx->lock);
  ret = startDownload(ctx,
		      anonymityLevel,
		      uri,
		      filename,
		      NO,
		      &ctx->activeDownloads);
  MUTEX_UNLOCK(&ctx->lock);
  return ret;
}

/**
 * Starts or stops download threads in accordance with thread pool
 * size and active downloads.  Call only while holding FSUI lock (or
 * during start/stop).
 *
 * @return YES if change done that may require re-trying
 */
int updateDownloadThread(FSUI_DownloadList * list) {
  FSUI_DownloadList * dpos;
  void * unused;
  int ret;

  if (list == NULL)
    return NO;

#if DEBUG_DTM
  LOG(LOG_DEBUG,
      "Download thread manager investigates pending downlod of file `%s' (%u/%u downloads)\n",
      list->filename,
      list->ctx->activeDownloadThreads,
      list->ctx->threadPoolSize);
#endif
  LOG(LOG_DEBUG,
      "Download thread manager investigates pending downlod of file `%s' (%d, %llu/%llu, %d)\n",
      list->filename,
      list->signalTerminate,
      list->completed,
      list->total,
      list->finished);
  ret = NO;
  /* should this one be started? */
  if ( (list->ctx->threadPoolSize
	> list->ctx->activeDownloadThreads) &&
       (list->signalTerminate == SYSERR) &&
       ( (list->total > list->completed) ||
         (list->total == 0) ) &&
       (list->finished == NO) ) {
#if DEBUG_DTM
    LOG(LOG_DEBUG,
	"Download thread manager schedules active downlod of file `%s'\n",
	list->filename);
#endif
    list->signalTerminate = NO;
    if (0 == PTHREAD_CREATE(&list->handle,
			    &downloadThread,
			    list,
			    32 * 1024)) {
      list->ctx->activeDownloadThreads++;
    } else {
      LOG_STRERROR(LOG_WARNING, "pthread_create");	
    }
  }

  /* should this one be stopped? */
  if ( (list->ctx->threadPoolSize
	< list->ctx->activeDownloadThreads) &&
       (list->signalTerminate == NO) ) {
#if DEBUG_DTM
    LOG(LOG_DEBUG,
	"Download thread manager aborts active downlod of file `%s' (%u/%u downloads)\n",
	list->filename,
	list->ctx->activeDownloadThreads,
	list->ctx->threadPoolSize);
#endif
    list->signalTerminate = YES;
    PTHREAD_JOIN(&list->handle,
		 &unused);
    list->ctx->activeDownloadThreads--;
    list->signalTerminate = SYSERR;
    ret = YES;
  }

  /* has this one "died naturally"? */
  if (list->signalTerminate == YES) {
#if DEBUG_DTM
    LOG(LOG_DEBUG,
	"Download thread manager collects inactive downlod of file `%s'\n",
	list->filename);
#endif
    PTHREAD_JOIN(&list->handle,
		 &unused);
    list->ctx->activeDownloadThreads--;
    list->signalTerminate = SYSERR;
    ret = YES;
  }

  dpos = list->child;
  while (dpos != NULL) {
    if (YES == updateDownloadThread(dpos))
      ret = YES;
    dpos = dpos->next;
  }
  return ret;
}


/**
 * Free the subtree (assumes all threads have already been stopped and
 * that the FSUI lock is either held or that we are in FSUI stop!).
 */
void freeDownloadList(FSUI_DownloadList * list) {
  FSUI_DownloadList * dpos;
  int i;

  GNUNET_ASSERT(list->signalTerminate != NO);

  /* first, find our predecessor and
     unlink us from the tree! */
  dpos = list->parent;
  if (dpos != NULL) {
    if (dpos->child == list) {
      dpos->child = list->next;
    } else {
      dpos = dpos->child;
      while ( (dpos != NULL) &&
	      (dpos->next != list) )
	dpos = dpos->next;
      GNUNET_ASSERT(dpos != NULL);
      dpos->next = list->next;
    }
  }

  /* then, free all of our children */
  while (list->child != NULL)
    freeDownloadList(list->child);

  /* finally, free this node and its data */
  ECRS_freeUri(list->uri);
  FREE(list->filename);
  for (i=list->completedDownloadsCount-1;i>=0;i--)
    ECRS_freeUri(list->completedDownloads[i]);
  GROW(list->completedDownloads,
       list->completedDownloadsCount,
       0);
  FREE(list);
}

/**
 * Abort a download.
 *
 * @return SYSERR if no such download is pending
 */
int FSUI_stopDownload(struct FSUI_Context * ctx,
		      const struct ECRS_URI * uri,
		      const char * filename) {
  FSUI_DownloadList * dl;
  FSUI_DownloadList * prev;
  unsigned int backup;

  GNUNET_ASSERT(filename != NULL);
  MUTEX_LOCK(&ctx->lock);
  dl = ctx->activeDownloads.child;
  prev = NULL;
  while (dl != NULL) {
    if ( (ECRS_equalsUri(uri,
		       dl->uri)) &&
	 ( (filename == NULL) ||
	   (0 == strcmp(filename,
			dl->filename)) ) ) {
      backup = ctx->threadPoolSize;
      ctx->threadPoolSize = 0;
      updateDownloadThread(dl);
      freeDownloadList(dl);
      ctx->threadPoolSize = backup;
      MUTEX_UNLOCK(&ctx->lock);
      return OK;
    }
    prev = dl;
    dl = dl->next;
  }
  MUTEX_UNLOCK(&ctx->lock);
  return SYSERR;
}

/**
 * List active downloads.  Will NOT list completed
 * downloads, FSUI clients should listen closely
 * to the FSUI_ProgressCallback to not miss completion
 * events.
 */
int FSUI_listDownloads(struct FSUI_Context * ctx,
		       const FSUI_DownloadList * root,
		       FSUI_DownloadIterator iter,
		       void * closure) {
  FSUI_DownloadList * dl;
  int ret;

  ret = 0;
  MUTEX_LOCK(&ctx->lock);
  if (root == NULL)
    dl = ctx->activeDownloads.child;
  else
    dl = root->child;
  while (dl != NULL) {
    if (OK != iter(closure,
		   dl,
		   dl->filename,
		   dl->uri,
		   dl->total,
		   dl->completed,
		   dl->is_recursive,
		   dl->anonymityLevel)) {
      MUTEX_UNLOCK(&ctx->lock);
      return SYSERR;
    }
    ret++;
    dl = dl->next;
  }
  MUTEX_UNLOCK(&ctx->lock);
  return ret;
}

/**
 * Clear all completed top-level downloads from the FSUI list.
 *
 * @param callback function to call on each completed download
 *        that is being cleared.
 * @return SYSERR on error, otherwise number of downloads cleared
 */
int FSUI_clearCompletedDownloads(struct FSUI_Context * ctx,
				 FSUI_DownloadIterator iter,
				 void * closure) {
  FSUI_DownloadList * dl;
  FSUI_DownloadList * tmp;
  int ret;
  int stop;

  ret = 0;
  MUTEX_LOCK(&ctx->lock);
  dl = ctx->activeDownloads.child;
  stop = NO;
  while ( (dl != NULL) &&
	  (stop == NO) ) {
    if ( (dl->completed == dl->total) &&
	 (dl->signalTerminate == SYSERR) ) {
      if (iter != NULL)
	if (OK != iter(closure,
		       dl,
		       dl->filename,
		       dl->uri,
		       dl->total,
		       dl->completed,
		       dl->is_recursive,
		       dl->anonymityLevel))
	  stop = YES;
      tmp = dl->next;
      freeDownloadList(dl);
      dl = tmp;
      ret++;
    } else {
      dl = dl->next;
    }
  }
  MUTEX_UNLOCK(&ctx->lock);
  if (stop == NO)
    return ret;
  else
    return SYSERR;
}


/**
 * Get parent of active download.
 * @return NULL if there is no parent
 */
const FSUI_DownloadList *
FSUI_getDownloadParent(const FSUI_DownloadList * child) {
  if (child->parent ==
      &child->ctx->activeDownloads)
    return NULL;
  else
    return child->parent;
}

/**
 * Start to download a file or directory recursively.
 *
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist
 */
int FSUI_startDownloadAll(struct FSUI_Context * ctx,
			  unsigned int anonymityLevel,			
			  const struct ECRS_URI * uri,
			  const char * dirname) {
  int ret;

  GNUNET_ASSERT(dirname != NULL);
  GNUNET_ASSERT(ctx != NULL);
  MUTEX_LOCK(&ctx->lock);
  ret = startDownload(ctx,
		      anonymityLevel,
		      uri,
		      dirname,
		      YES,
		      &ctx->activeDownloads);
  MUTEX_UNLOCK(&ctx->lock);
  return ret;
}

/* end of download.c */
