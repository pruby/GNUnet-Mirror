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
 * @file applications/fs/fsui/download.c
 * @brief download functions
 * @author Krista Bennett
 * @author Christian Grothoff
 *
 * TODO:
 * - does not signal all events properly!
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_uritrack_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

#define DEBUG_DTM NO

/**
 * Start to download a file.
 */
static FSUI_DownloadList *
startDownload(struct FSUI_Context * ctx,
	      unsigned int anonymityLevel,
	      int is_recursive,
	      const struct ECRS_URI * uri,
	      const char * filename,
	      FSUI_DownloadList * parent);

static int triggerRecursiveDownload(const ECRS_FileInfo * fi,
				    const HashCode512 * key,
				    int isRoot,
				    void * prnt) {
  FSUI_DownloadList * parent = prnt;
  struct GE_Context * ectx;
  int i;
  FSUI_DownloadList * pos;
  char * filename;
  char * fullName;
  char * dotdot;

  ectx = parent->ctx->ectx;
  if (isRoot == YES)
    return OK; /* namespace ad, ignore */

  URITRACK_trackURI(ectx, parent->ctx->cfg, fi);
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
    GE_ASSERT(ectx, strlen(tmp) >= strlen(ECRS_URI_PREFIX) + strlen(ECRS_FILE_INFIX));
    filename = STRDUP(&tmp[strlen(ECRS_URI_PREFIX) + strlen(ECRS_FILE_INFIX)]);
    FREE(tmp);
  }
  fullName = MALLOC(strlen(parent->filename) +
		    + strlen(GNUNET_DIRECTORY_EXT) + 2
		    + strlen(filename));
  strcpy(fullName, parent->filename);
  if (fullName[strlen(fullName)-1] == '/')
    fullName[strlen(fullName)-1] = '\0';
  else
    strcat(fullName, GNUNET_DIRECTORY_EXT);
  while (NULL != (dotdot = strstr(fullName, "..")))
    dotdot[0] = dotdot[1] = '_';
  disk_directory_create(ectx, fullName);
  strcat(fullName, DIR_SEPARATOR_STR);
  while (NULL != (dotdot = strstr(filename, "..")))
    dotdot[0] = dotdot[1] = '_';
  strcat(fullName, filename);
  FREE(filename);
#if DEBUG_DTM
  GE_LOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
      "Starting recursive download of `%s'\n",
      fullName);
#endif
  startDownload(parent->ctx,
		     parent->anonymityLevel,
		     YES,
		     fi->uri,
		     fullName,
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
  event.data.DownloadProgress.dc.pos = dl;
  event.data.DownloadProgress.dc.cctx = dl->cctx;
  event.data.DownloadProgress.dc.ppos = dl->parent;
  event.data.DownloadProgress.dc.pcctx = dl->parent != NULL ? dl->parent->cctx : NULL;
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
    MUTEX_LOCK(dl->ctx->lock);
    ECRS_listDirectory(dl->ctx->ectx,
		       lastBlock,
		       lastBlockSize,
		       &md,
		       &triggerRecursiveDownload,
		       dl);
    MUTEX_UNLOCK(dl->ctx->lock);
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

  if (dl->state != FSUI_DOWNLOAD_ACTIVE) {
    return SYSERR;
  } else {
    return OK;
  }
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
  struct GE_Context * ectx;

  ectx = dl->ctx->ectx;
#if DEBUG_DTM
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Download thread for `%s' started...\n",
	 dl->filename);
#endif
  GE_ASSERT(ectx, dl->ctx != NULL);
  GE_ASSERT(ectx, dl->filename != NULL);
  ret = ECRS_downloadFile(dl->ctx->ectx,
			  dl->ctx->cfg,
			  dl->uri,
			  dl->filename,
			  dl->anonymityLevel,
			  &downloadProgressCallback,
			  dl,
			  &testTerminate,
			  dl);  
  if (ret == OK) {
    dl->state = FSUI_DOWNLOAD_COMPLETED;
    totalBytes = ECRS_fileSize(dl->uri);
  } else {
#if DEBUG_DTM
    GE_LOG(ectx, 
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Download thread for `%s' failed (aborted or error)!\n",
	   dl->filename);
#endif
    if (dl->state == FSUI_DOWNLOAD_ACTIVE)
      dl->state = FSUI_DOWNLOAD_ERROR;
    else if ( (dl->state != FSUI_DOWNLOAD_ABORTED) &&
	      (dl->state != FSUI_DOWNLOAD_SUSPENDING) )
      GE_BREAK(ectx, 0);
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
    char * fn;

    fn = MALLOC(strlen(dl->filename) + 3 + strlen(GNUNET_DIRECTORY_EXT));
    strcpy(fn, dl->filename);
    if (fn[strlen(fn)-1] == '/') {
      fn[strlen(fn)-1] = '\0';
      strcat(fn, GNUNET_DIRECTORY_EXT);
    } 
    fd = disk_file_open(ectx,
			fn,
			O_LARGEFILE | O_RDONLY);
    if (fd == -1) {
      GE_LOG_STRERROR_FILE(ectx,
			   GE_ERROR | GE_BULK | GE_ADMIN | GE_USER,
			   "OPEN",
			   fn);
    } else {
      dirBlock = MMAP(NULL,
		      totalBytes,
		      PROT_READ,
		      MAP_SHARED,
		      fd,
		      0);
      if (MAP_FAILED == dirBlock) {
	GE_LOG_STRERROR_FILE(ectx,
			     GE_ERROR | GE_BULK | GE_ADMIN | GE_USER,
			     "MMAP", 
			     fn);	
      } else {
	/* load directory, start downloads */
	md = NULL;
	MUTEX_LOCK(dl->ctx->lock);
	ECRS_listDirectory(dl->ctx->ectx,
			   dirBlock,
			   totalBytes,
			   &md,
			   &triggerRecursiveDownload,
			   dl);
	MUTEX_UNLOCK(dl->ctx->lock);
	ECRS_freeMetaData(md);
	MUNMAP(dirBlock, totalBytes);
      }
      CLOSE(fd);
    }
    FREE(fn);
  }
  if (ret != OK) {
    switch (dl->state) {
    case FSUI_DOWNLOAD_ABORTED:
      event.type = FSUI_download_aborted;
      event.data.DownloadError.message = _("Download aborted.");
      break;
    case FSUI_DOWNLOAD_ERROR:
      event.type = FSUI_download_error;
      event.data.DownloadError.message = _("ECRS download failed (see logs).");
      break;
    case FSUI_DOWNLOAD_SUSPENDING:
      event.type = FSUI_download_suspending;
      event.data.DownloadError.message = _("ECRS download suspending.");
      break;
    default:
      event.type = FSUI_download_error;
      event.data.DownloadError.message = _("Unexpected download state.");
      printf("State: %u\n", dl->state);
      GE_BREAK(ectx, 0);
    }
    event.data.DownloadError.dc.pos = dl;
    event.data.DownloadError.dc.cctx = dl->cctx;
    event.data.DownloadError.dc.ppos = dl->parent;
    event.data.DownloadError.dc.pcctx = dl->parent != NULL ? dl->parent->cctx : NULL;
    dl->ctx->ecb(dl->ctx->ecbClosure,
		 &event);
  } else {
    GE_ASSERT(ectx, dl != &dl->ctx->activeDownloads);
    while ( (dl != NULL) &&
	    (dl->ctx != NULL) &&
	    (dl != &dl->ctx->activeDownloads) ) {
      event.type = FSUI_download_complete;
      event.data.DownloadComplete.total = dl->total;
      event.data.DownloadComplete.filename = dl->filename;
      event.data.DownloadComplete.uri = dl->uri;
      event.data.DownloadComplete.dc.pos = dl;
      event.data.DownloadComplete.dc.cctx = dl->cctx;
      event.data.DownloadComplete.dc.ppos = dl->parent;
      event.data.DownloadComplete.dc.pcctx = dl->parent != NULL ? dl->parent->cctx : NULL;
      dl->ctx->ecb(dl->ctx->ecbClosure,
		   &event);
      dl = dl->parent;
    }
  }
  dl = cls;
#if DEBUG_DTM
  GE_LOG(ectx, 
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Download thread for `%s' terminated (%s)...\n",
	 dl->filename,
	 ret == OK ? "COMPLETED" : "ABORTED");
#endif
  return NULL;
}

/**
 * Start to download a file.
 */
static FSUI_DownloadList *
startDownload(struct FSUI_Context * ctx,
	      unsigned int anonymityLevel,
	      int is_recursive,
	      const struct ECRS_URI * uri,
	      const char * filename,
	      FSUI_DownloadList * parent) {
  FSUI_DownloadList * dl;
  FSUI_DownloadList * root;
  unsigned long long totalBytes;

  GE_ASSERT(NULL, ctx != NULL);
  if (! (ECRS_isFileUri(uri) ||
	 ECRS_isLocationUri(uri)) ) {
    GE_BREAK(NULL, 0); /* wrong type of URI! */
    return NULL;
  }
  dl = MALLOC(sizeof(FSUI_DownloadList));
  memset(dl, 0, sizeof(FSUI_DownloadList));
  dl->startTime = get_time();
  dl->state = FSUI_DOWNLOAD_PENDING;
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
  return dl;
}

/**
 * Start to download a file.
 *
 * @return OK on success, SYSERR if the target file is
 *  already used for another download at the moment (or
 *  if the disk does not have enough space).
 */
struct FSUI_DownloadList *
FSUI_startDownload(struct FSUI_Context * ctx,
		   unsigned int anonymityLevel,			
		   int doRecursive,
		   const struct ECRS_URI * uri,
		   const char * filename) {
  struct FSUI_DownloadList * ret;

  MUTEX_LOCK(ctx->lock);
  ret = startDownload(ctx, 
		      anonymityLevel, 
		      doRecursive,
		      uri,
		      filename,
		      NULL);
  MUTEX_UNLOCK(ctx->lock);
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
  struct GE_Context * ectx;
  FSUI_DownloadList * dpos;
  void * unused;
  int ret;

  ectx = list->ctx->ectx;
  if (list == NULL)
    return NO;

#if DEBUG_DTM
  GE_LOG(ectx, 
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Download thread manager investigates pending downlod of file `%s' (%u/%u downloads)\n",
	 list->filename,
	 list->ctx->activeDownloadThreads,
	 list->ctx->threadPoolSize);
#endif
  ret = NO;
  /* should this one be started? */
  if ( (list->ctx->threadPoolSize
	> list->ctx->activeDownloadThreads) &&
       (list->state == FSUI_DOWNLOAD_PENDING) &&
       ( (list->total > list->completed) ||
         (list->total == 0) ) ) {
#if DEBUG_DTM
    GE_LOG(ectx, 
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Download thread manager starts downlod of file `%s'\n",
	   list->filename);
#endif
    list->state = FSUI_DOWNLOAD_ACTIVE;
    list->handle = PTHREAD_CREATE(&downloadThread,
				  list,
				  32 * 1024);
    if (list->handle != NULL) {
      list->ctx->activeDownloadThreads++;
    } else {
      GE_LOG_STRERROR(ectx,
		      GE_ADMIN | GE_USER | GE_BULK | GE_ERROR,
		      "pthread_create");	
      list->state = FSUI_DOWNLOAD_ERROR_JOINED;
    }
  }

  /* should this one be stopped? */
  if ( (list->ctx->threadPoolSize
	< list->ctx->activeDownloadThreads) &&
       (list->state == FSUI_DOWNLOAD_ACTIVE) ) {
#if DEBUG_DTM
    GE_LOG(ectx, 
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Download thread manager aborts active download of file `%s' (%u/%u downloads)\n",
	   list->filename,
	   list->ctx->activeDownloadThreads,
	   list->ctx->threadPoolSize);
#endif
    list->state = FSUI_DOWNLOAD_SUSPENDING;
    PTHREAD_STOP_SLEEP(list->handle);
    PTHREAD_JOIN(list->handle,
		 &unused);
    list->ctx->activeDownloadThreads--;
    list->state = FSUI_DOWNLOAD_PENDING;
    ret = YES;
  }

  /* has this one "died naturally"? */
  if ( (list->state == FSUI_DOWNLOAD_COMPLETED) ||
       (list->state == FSUI_DOWNLOAD_ABORTED) ||
       (list->state == FSUI_DOWNLOAD_ERROR) ) {       
#if DEBUG_DTM
    GE_LOG(ectx, 
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Download thread manager collects inactive download of file `%s'\n",
	   list->filename);
#endif
    PTHREAD_JOIN(list->handle,
		 &unused);
    list->ctx->activeDownloadThreads--;
    list->state++; /* adds _JOINED */
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

  GE_ASSERT(NULL, list->state != FSUI_DOWNLOAD_ACTIVE);

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
      GE_ASSERT(NULL, dpos != NULL);
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
		      struct FSUI_DownloadList * dl) {
  FSUI_DownloadList * prev;
  struct GE_Context * ectx;
  unsigned int backup;

  ectx = ctx->ectx;
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "FSUI_stopDownload called.\n");
  MUTEX_LOCK(ctx->lock);
  prev = (dl->parent != NULL) ? dl->parent->child : ctx->activeDownloads.child;
  while ( (prev != dl) &&
	  (prev != NULL) &&
	  (prev->next != dl) ) 
    prev = prev->next;
  if (prev == NULL) {
    MUTEX_UNLOCK(ctx->lock);
    GE_LOG(ectx, 
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "FSUI_stopDownload failed to locate download.\n");
    return SYSERR;
  }
  if (prev == dl) { /* first */
    if (dl->parent != NULL)
      dl->parent->child = dl->next;
    else
      ctx->activeDownloads.child = dl->next;
  } else { 
    prev->next = dl->next; /* unlink */    
  }
  backup = ctx->threadPoolSize;
  ctx->threadPoolSize = 0;
  updateDownloadThread(dl);
  freeDownloadList(dl);
  ctx->threadPoolSize = backup;
  MUTEX_UNLOCK(ctx->lock);
  return OK;
}


/* end of download.c */
