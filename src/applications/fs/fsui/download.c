/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 *
 * TODO:
 * - put URI of main download into events
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

/**
 * Start to download a file.
 *
 * @return OK on success, SYSERR if the target file is
 *  already used for another download at the moment (or
 *  if the disk does not have enough space).
 */
static int startDownload(struct FSUI_Context * ctx,
			 const struct ECRS_URI * uri,
			 const char * filename,
			 int is_recursive,
			 FSUI_DownloadList * parent);

static int triggerRecursiveDownload(const ECRS_FileInfo * fi,
				    const HashCode160 * key,
				    FSUI_DownloadList * parent) {
  int i;
  FSUI_DownloadList * pos;
  char * filename;
  char * fullName;

  for (i=0;i<parent->completedDownloadsCount;i++)
    if (ECRS_equalsUri(parent->completedDownloads[i],
		       fi->uri))
      return OK; /* already complete! */
  pos = parent->subDownloads;
  while (pos != NULL) {
    if (ECRS_equalsUri(pos->uri,
		       fi->uri))
      return OK; /* already downloading */
    pos = pos->subDownloadsNext;
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
  mkdirp(fullName);
  strcat(fullName, DIR_SEPARATOR_STR);
  strcat(fullName, filename);
  FREE(filename);
  startDownload(parent->ctx,
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
			 FSUI_DownloadList * dl) {
  FSUI_Event event;
  struct ECRS_MetaData * md;

  dl->completed = completedBytes;
  event.type = download_progress;
  event.data.DownloadProgress.total = totalBytes;
  event.data.DownloadProgress.completed = completedBytes;
  event.data.DownloadProgress.last_offset = lastBlockOffset;
  event.data.DownloadProgress.eta = eta;
  event.data.DownloadProgress.last_block = lastBlock;
  event.data.DownloadProgress.last_size = lastBlockSize;
  event.data.DownloadProgress.filename = dl->filename;
  event.data.DownloadProgress.uri = dl->uri;
  event.data.DownloadProgress.start_time = dl->startTime;
  event.data.DownloadProgress.is_recursive = dl->is_recursive;
  event.data.DownloadProgress.main_filename = NULL; /* FIXME! */
  event.data.DownloadProgress.main_uri = NULL; /* FIXME! */
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
		       (ECRS_SearchProgressCallback) &triggerRecursiveDownload,
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
testTerminate(FSUI_DownloadList * dl) {
  if (dl->signalTerminate == YES)
    return SYSERR;
  else
    return OK;
}

/**
 * Thread that downloads a file.
 */
static void * downloadThread(FSUI_DownloadList * dl) {
  int ret;
  FSUI_Event event;
  unsigned long long totalBytes;
  FSUI_DownloadList * prev;
  FSUI_DownloadList * pos;
  struct ECRS_MetaData * md;
  
  totalBytes = ECRS_fileSize(dl->uri);
  ret = ECRS_downloadFile(dl->uri,
			  dl->filename,
			  dl->anonymityLevel,
			  (ECRS_DownloadProgressCallback)&downloadProgressCallback,
			  dl,
			  (ECRS_TestTerminate) &testTerminate,
			  dl);
  if (ret != OK) {
    event.type = download_error;
    event.data.message = _("Download aborted.");
  } else {
    event.type = download_complete;
    event.data.DownloadProgress.total = totalBytes;
    event.data.DownloadProgress.completed = totalBytes;
    event.data.DownloadProgress.last_offset = 0;
    event.data.DownloadProgress.eta = cronTime(NULL);
    event.data.DownloadProgress.last_block = NULL;
    event.data.DownloadProgress.last_size = 0;
    event.data.DownloadProgress.filename = dl->filename;
    event.data.DownloadProgress.uri = dl->uri;
    event.data.DownloadProgress.start_time = dl->startTime;
    event.data.DownloadProgress.is_recursive = dl->is_recursive;
    event.data.DownloadProgress.main_filename = NULL; /* FIXME! */
    event.data.DownloadProgress.main_uri = NULL; /* FIXME! */
  }
  dl->ctx->ecb(dl->ctx->ecbClosure,
	       &event);
  if ( (ret == OK) &&
       (dl->is_recursive) &&
       (dl->is_directory) ) {
    char * dirBlock;
    int fd;

#ifdef O_LARGEFILE
    fd = OPEN(dl->filename,
	      O_LARGEFILE | O_RDONLY);
#else
    fd = OPEN(dl->filename,
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
			 (ECRS_SearchProgressCallback) &triggerRecursiveDownload,
			 dl);
      MUTEX_UNLOCK(&dl->ctx->lock);
      ECRS_freeMetaData(md);
      MUNMAP(dirBlock, totalBytes);
      CLOSE(fd);
    }

    /* wait for recursive downloads (if any) */
    while ( (dl->subDownloads != NULL) &&
	    (dl->signalTerminate != YES) )
      gnunet_util_sleep(100);    
  }
  if (dl->parent != NULL) {
    /* notify parent that we're done */
    MUTEX_LOCK(&dl->ctx->lock);
    GROW(dl->parent->completedDownloads,
	 dl->parent->completedDownloadsCount,
	 dl->parent->completedDownloadsCount+1);
    dl->parent->completedDownloads[dl->parent->completedDownloadsCount-1]
      = ECRS_dupUri(dl->uri);
    prev = NULL;
    pos = dl->parent->subDownloads;
    while ( (pos != NULL) &&
	    (pos != dl) ) {
      prev = pos;
      pos = pos->subDownloadsNext;
    }
    if (pos == NULL) {
      BREAK();
    } else {
      if (prev != NULL)
	prev->next = pos->subDownloadsNext;
      else
	dl->parent->subDownloads = pos->subDownloadsNext;      
    }    
    MUTEX_UNLOCK(&dl->ctx->lock);
  }
  dl->signalTerminate = YES; 
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
			 const struct ECRS_URI * uri,
			 const char * filename,
			 int is_recursive,
			 FSUI_DownloadList * parent) {
  FSUI_DownloadList * dl;

  if (! (ECRS_isFileURI(uri) ||
	 ECRS_isLocationURI(uri)) ) {
    BREAK(); /* wrong type of URI! */
    return SYSERR; 
  }

  dl = MALLOC(sizeof(FSUI_DownloadList));
  memset(dl, 0, sizeof(FSUI_DownloadList));
  cronTime(&dl->startTime);
  dl->signalTerminate = NO;
  dl->is_recursive = is_recursive;
  dl->parent = parent;
  dl->is_directory = SYSERR; /* don't know */
  dl->anonymityLevel = ctx->anonymityLevel;
  dl->ctx = ctx;
  dl->filename = STRDUP(filename);
  dl->uri = ECRS_dupUri(uri);
  dl->total = ECRS_fileSize(uri); 
  MUTEX_LOCK(&ctx->lock);
  if (0 != PTHREAD_CREATE(&dl->handle,
			  (PThreadMain) &downloadThread,
			  dl,
			  16 * 1024)) {
    FREE(dl->filename);
    ECRS_freeUri(dl->uri);
    FREE(dl);
    MUTEX_UNLOCK(&ctx->lock);
    return SYSERR;
  }
  if (parent != NULL) {
    /* add to pending downloads of parent! */
    dl->subDownloadsNext = parent->subDownloads;
    parent->subDownloads = dl;
  }
  dl->next = ctx->activeDownloads;
  ctx->activeDownloads = dl;
  MUTEX_UNLOCK(&ctx->lock);
  cleanupFSUIThreadList(ctx);
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
		       const struct ECRS_URI * uri,
		       const char * filename) {
  return startDownload(ctx, uri, filename, NO, NULL);
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

  MUTEX_LOCK(&ctx->lock);
  dl = ctx->activeDownloads;
  while (dl != NULL) {
    if (ECRS_equalsUri(uri,
		       dl->uri)) {      
      dl->signalTerminate = YES;
      MUTEX_UNLOCK(&ctx->lock);
      cleanupFSUIThreadList(ctx);
      return OK;
    }
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
		       FSUI_DownloadIterator iter,
		       void * closure) {
  FSUI_DownloadList * dl;
  int ret;

  ret = 0;
  cleanupFSUIThreadList(ctx);      
  MUTEX_LOCK(&ctx->lock);
  dl = ctx->activeDownloads;
  while (dl != NULL) {
    if (OK != iter(closure,
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
 * Start to download a file or directory recursively.
 *
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist
 */
int FSUI_startDownloadAll(struct FSUI_Context * ctx,
			  const struct ECRS_URI * uri,
			  const char * dirname) {
  return startDownload(ctx, uri, dirname, YES, NULL);
}

/**
 * Abort a recursive download (internal function).
 * 
 * FIXME: dirname is currently not used, which means
 * that we may abort the wrong download (if there are
 * multiple downloads for the same uri!).
 *
 * Do NOT call cleanupFSUIThreadList in here -- this
 * function maybe called recursively!
 *
 * @return OK on success, SYSERR if no such download is
 *  pending
 */
static int stopDownloadAll(struct FSUI_Context * ctx,
			   const struct ECRS_URI * uri,
			   const char * dirname) {
  FSUI_DownloadList * dl;
  int i;

  dl = ctx->activeDownloads;
  while (dl != NULL) {
    if (ECRS_equalsUri(uri,
		       dl->uri)) {      
      dl->signalTerminate = YES;
      for (i=0;i<dl->completedDownloadsCount;i++)
	FSUI_stopDownloadAll(ctx,
			     dl->completedDownloads[i],
			     dirname);      
      return OK;
    }
    dl = dl->next;
  }
  return SYSERR;
}

/**
 * Abort a recursive download.
 * 
 * @return OK on success, SYSERR if no such download is
 *  pending
 */
int FSUI_stopDownloadAll(struct FSUI_Context * ctx,
			 const struct ECRS_URI * uri,
			 const char * dirname) {
  int ret;

  MUTEX_LOCK(&ctx->lock);
  ret = stopDownloadAll(ctx, uri, dirname);
  MUTEX_UNLOCK(&ctx->lock);  
  cleanupFSUIThreadList(ctx);
  return ret;
}
	
/* end of download.c */
