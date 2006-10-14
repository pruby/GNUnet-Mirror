/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/upload.c
 * @brief upload functions
 * @author Krista Bennett
 * @author Christian Grothoff
 *
 * TODO:
 * - make sure events are sent for resume/abort/error
 *   when respective FSUI calls happen!
 *   (initialize cctx!)
 * - proper tree handling
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_uritrack_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"
#include <extractor.h>

#define DEBUG_UPLOAD NO

/**
 * Transform an ECRS progress callback into an FSUI event.
 */
static void progressCallback(unsigned long long totalBytes,
			     unsigned long long completedBytes,
			     cron_t eta,
			     void * ptr) {
  FSUI_UploadList * utc = ptr;
  FSUI_Event event;
  cron_t now;

  now = get_time();
  event.type = FSUI_upload_progress;
  event.data.UploadProgress.uc.pos = utc;
  event.data.UploadProgress.uc.cctx = utc->cctx;
  event.data.UploadProgress.uc.ppos = utc->parent;
  event.data.UploadProgress.uc.pcctx = utc->parent->cctx;
  event.data.UploadProgress.completed = completedBytes;
  event.data.UploadProgress.total = totalBytes;
  event.data.UploadProgress.filename = utc->filename;
  event.data.UploadProgress.eta = eta;
  utc->ctx->ecb(utc->ctx->ecbClosure,
		&event);
}

static int testTerminate(void * cls) {
  FSUI_UploadList * utc = cls;
  if (utc->state != FSUI_ACTIVE)
    return SYSERR;
  return OK;
}

/**
 * Take the current directory entries from utc, create
 * a directory, upload it and store the uri in  *uri.
 */
static int uploadDirectory(FSUI_UploadList * utc,
			   const char * dirName,
			   const DirTrack * backup,
			   struct ECRS_URI ** uri,
			   struct ECRS_MetaData ** meta) {
  char * data;
  unsigned long long len;
  int ret;
  char * tempName;
  int lastSlash;
  FSUI_Event event;
  int handle;
  char * mdn;
  struct GE_Context * ectx;

  ectx = utc->ctx->ectx;
  GE_ASSERT(ectx, utc->filename != NULL);

  ret = SYSERR;
  if (*meta == NULL)
    (*meta) = ECRS_createMetaData();
  lastSlash = strlen(dirName)-1;
  if (dirName[lastSlash] == DIR_SEPARATOR)
    lastSlash--;
  while ( (lastSlash > 0) &&
	  (dirName[lastSlash] != DIR_SEPARATOR))
    lastSlash--;
  ECRS_delFromMetaData(*meta,
		       EXTRACTOR_FILENAME,
		       NULL);
  mdn = MALLOC(strlen(&dirName[lastSlash+1]) + 3);
  strcpy(mdn, &dirName[lastSlash+1]);
  if (mdn[strlen(mdn)-1] != '/')
    strcat(mdn, "/");  
  ECRS_addToMetaData(*meta,
		     EXTRACTOR_FILENAME,
		     mdn);
  FREE(mdn);
  ECRS_addToMetaData(*meta,
		     EXTRACTOR_MIMETYPE,
		     GNUNET_DIRECTORY_MIME);
  data = NULL;
  if (OK == ECRS_createDirectory(ectx,
				 &data,
				 &len,
				 backup->fiCount,
				 backup->fis,
				 *meta)) {
    utc->main_total += len;

    tempName = STRDUP("/tmp/gnunetdir.XXXXXX");
    handle = mkstemp(tempName);
    if (handle == -1) {
      GE_LOG_STRERROR_FILE(ectx,
			   GE_ERROR | GE_USER | GE_BULK,
			   tempName, 
			   "mkstemp");
    } else if (len != WRITE(handle,
			    data,
			    len)) {
      GE_LOG_STRERROR_FILE(ectx,
			   GE_ERROR | GE_USER | GE_BULK,
			   tempName,
			   "write");
    } else {
      CLOSE(handle);
      utc->filename = tempName;
      ret = ECRS_uploadFile(ectx,
			    utc->ctx->cfg,
			    tempName,
			    NO,
			    utc->anonymityLevel,
			    utc->priority,
			    utc->expiration,
			    &progressCallback,
			    utc,
			    &testTerminate,
			    utc,
			    uri);
      if (ret == OK) {
	GE_ASSERT(ectx, NULL != *uri);
	event.type = FSUI_upload_complete;
	event.data.UploadCompleted.uc.pos = utc;
	event.data.UploadCompleted.uc.cctx = utc->cctx;
	event.data.UploadCompleted.uc.ppos = utc->parent;
	event.data.UploadCompleted.uc.pcctx = utc->parent->cctx;
	event.data.UploadCompleted.total = utc->main_total;
	event.data.UploadCompleted.filename = dirName;
	event.data.UploadCompleted.uri = *uri;
	utc->ctx->ecb(utc->ctx->ecbClosure,
		      &event);	
	utc->completed = utc->total;
	utc->uri = *uri;
      } else if (utc->state == FSUI_ACTIVE) {
	/* ECRS internal error - signal */
	event.type = FSUI_upload_error;
	event.data.UploadError.uc.pos = utc;
	event.data.UploadError.uc.cctx = utc->cctx;
	event.data.UploadError.uc.ppos = utc->parent;
	event.data.UploadError.uc.pcctx = utc->parent->cctx;
	event.data.UploadError.message = _("Error during upload (consult logs)");
	utc->ctx->ecb(utc->ctx->ecbClosure,
		      &event);		
      }
      UNLINK(tempName);
    }
    FREE(tempName);
    FREENONNULL(data);
  } else {
    event.type = FSUI_upload_error;
    event.data.UploadError.uc.pos = utc;
    event.data.UploadError.uc.cctx = utc->cctx;
    event.data.UploadError.uc.ppos = utc->parent;
    event.data.UploadError.uc.pcctx = utc->parent->cctx;
    event.data.UploadError.message = _("Failed to create directory.");
    utc->ctx->ecb(utc->ctx->ecbClosure,
		  &event);		
  }
  if (ret != OK) {
    ECRS_freeMetaData(*meta);
    *meta = NULL;
  }
  return ret;
}

static struct FSUI_UploadList *
startUpload(struct FSUI_Context * ctx,
	    const char * filename,
	    unsigned int anonymityLevel,
	    unsigned int priority,
	    int doIndex,
	    char * config,
	    EXTRACTOR_ExtractorList * extractors,
	    int individualKeywords,
	    const struct ECRS_MetaData * md,
	    const struct ECRS_URI * globalURI,
	    const struct ECRS_URI * keyUri,
	    struct FSUI_UploadList * parent);

/**
 * For each file in the directory, upload (recursively).
 */
static int dirEntryCallback(const char * filename,
			    const char * dirName,
			    void * ptr) {
  FSUI_UploadList * parent = ptr;
  char * fn;
  struct ECRS_URI * uri;
  struct ECRS_URI * keywordUri;
  struct ECRS_MetaData * meta;
  FSUI_Event event;
  int ret;
  unsigned long long len;
  struct GE_Context * ectx;

  ectx = utc->ctx->ectx;
  fn = MALLOC(strlen(filename) + strlen(dirName) + 2);
  strcpy(fn, dirName);
  strcat(fn, "/");
  strcat(fn, filename);
  startUpload(parent->ctx,
	      fn,
	      parent->anonymityLevel,
	      parent->priority,
	      parent->doIndex,
	      parent->extractor_config,
	      parent->extractors,
	      parent->individualKeywords,
	      parent->meta,
	      parent->globalUri,
	      parent->uri,
	      parent);
  if (NO == disk_directory_test(ectx, fn)) {
    ret = ECRS_uploadFile(ectx,
			  utc->ctx->cfg,
			  fn,
			  utc->doIndex,
			  utc->anonymityLevel,
			  utc->priority,
			  utc->expiration,
			  &progressCallback,
			  utc,
			  &testTerminate,
			  utc,
			  &uri);
    if (ret == OK) {
      GE_ASSERT(ectx, uri != NULL);
      utc->completed = utc->total;
      event.type = FSUI_upload_complete;
      event.data.UploadCompleted.uc.pos = utc;
      event.data.UploadCompleted.uc.cctx = utc->cctx;
      event.data.UploadCompleted.uc.ppos = utc->parent;
      event.data.UploadCompleted.uc.pcctx = utc->parent->cctx;
      event.data.UploadCompleted.total = utc->main_total;
      event.data.UploadCompleted.filename = utc->filename;
      event.data.UploadCompleted.uri = uri;
      utc->ctx->ecb(utc->ctx->ecbClosure,
		    &event);	
      meta = ECRS_createMetaData();
      ECRS_extractMetaData(ectx,
			   meta,
			   fn,
		 	   utc->extractors);
    } else if (utc->state == FSUI_ACTIVE) {
      event.type = FSUI_upload_error;
      event.data.UploadError.uc.pos = utc;
      event.data.UploadError.uc.cctx = utc->cctx;
      event.data.UploadError.uc.ppos = utc->parent;
      event.data.UploadError.uc.pcctx = utc->parent->cctx;
      event.data.UploadError.message = _("Error during upload (consult logs)");
      utc->ctx->ecb(utc->ctx->ecbClosure,
		    &event);	
      meta = NULL;
    }
  } else {
    DirTrack current;
    DirTrack * prev;
    int i;

    memset(&current, 0, sizeof(DirTrack));
    prev = utc->dir;
    utc->dir = &current;
    disk_directory_scan(ectx,
			fn,
			&dirEntryCallback,
			utc);
    meta = NULL;
    utc->dir = prev;
    ret = uploadDirectory(utc,
			  fn,
			  &current,
			  &uri,
			  &meta);

    for (i=0;i<current.fiCount;i++) {
      ECRS_freeMetaData(current.fis[i].meta);
      ECRS_freeUri(current.fis[i].uri);
    }
    GROW(current.fis,
	 current.fiCount,
	 0);
  }
  if (ret == OK) {
    char * mfilename = MALLOC(strlen(filename) + 2);
    strcpy(mfilename, filename);
    if (YES == disk_directory_test(ectx,
				   fn))
      strcat(mfilename, "/");    
    ECRS_addToMetaData(meta,
		       EXTRACTOR_FILENAME,
		       mfilename);
    FREE(mfilename);
    if (utc->individualKeywords) {
      keywordUri = ECRS_metaDataToUri(meta);
      if (keywordUri != NULL) {
	ECRS_addToKeyspace(ectx,
			   utc->ctx->cfg,
			   keywordUri,
			   utc->anonymityLevel,
			   utc->priority,
			   utc->expiration,
			   uri,
			   meta);	
	ECRS_freeUri(keywordUri);
      }
    }
    if (utc->globalUri != NULL)
      ECRS_addToKeyspace(ectx,
			 utc->ctx->cfg,
			 utc->globalUri,
			 utc->anonymityLevel,
			 utc->priority,
			 utc->expiration,
			 uri,
			 meta);	
    if (utc->dir != NULL) {
      GROW(utc->dir->fis,
	   utc->dir->fiCount,
	   utc->dir->fiCount+1);
      /* remove split keywords! */
      ECRS_delFromMetaData(meta,
			   EXTRACTOR_SPLIT,
			   NULL);
      ECRS_delFromMetaData(meta,
			   EXTRACTOR_LOWERCASE,
			   NULL);
      utc->dir->fis[utc->dir->fiCount-1].meta = meta;
      utc->dir->fis[utc->dir->fiCount-1].uri = uri;
    } else {
      ECRS_freeMetaData(meta);
      ECRS_freeUri(uri);
    }
    URITRACK_trackURI(ectx,
		      utc->ctx->cfg,
		      &utc->dir->fis[utc->dir->fiCount-1]);
  }
  FREE(fn);
  return OK;
}

/**
 * Thread that does the upload.
 */
void * FSUI_uploadThread(void * cls) {
  FSUI_UploadList * utc = cls;
  struct ECRS_URI * uri;
  struct ECRS_URI * keywordUri;
  FSUI_Event event;
  ECRS_FileInfo fi;
  int ret;
  char * inboundFN;
  struct GE_Context * ectx;

  ectx = utc->ctx->ectx;
  GE_ASSERT(ectx, utc->filename != NULL);
  utc->start_time = get_time();
  if (OK != disk_file_size(ectx,
			   utc->filename,
			   &utc->total,
			   YES)) {
    event.type = FSUI_upload_error;
    event.data.UploadError.uc.pos = utc;
    event.data.UploadError.uc.cctx = utc->cctx;
    event.data.UploadError.uc.ppos = utc->parent;
    event.data.UploadError.uc.pcctx = utc->parent->cctx;
    event.data.UploadError.message = _("Error during upload (could not determine file size)");
    utc->ctx->ecb(utc->ctx->ecbClosure,
		  &event);	
    return NULL;
  }
  utc->completed = 0;
  ret = SYSERR;
  uri = NULL;
  inboundFN
    = ECRS_getFromMetaData(utc->meta,
			   EXTRACTOR_FILENAME);

  if (NO == disk_directory_test(ectx,
				utc->filename)) {
    utc->filename = utc->main_filename;
    ret = ECRS_uploadFile(ectx,
			  utc->ctx->cfg,
			  utc->filename,
			  utc->doIndex,
			  utc->anonymityLevel,
			  utc->priority,
			  utc->expiration,
			  &progressCallback,
			  utc,
			  &testTerminate,
			  utc,
			  &uri);
    if (ret == OK) {
      event.type = FSUI_upload_complete;
      event.data.UploadCompleted.uc.pos = utc;
      event.data.UploadCompleted.uc.cctx = utc->cctx;
      event.data.UploadCompleted.uc.ppos = utc->parent;
      event.data.UploadCompleted.uc.pcctx = utc->parent->cctx;
      event.data.UploadCompleted.total = utc->total;
      event.data.UploadCompleted.filename = utc->filename;
      event.data.UploadCompleted.uri = uri;
      utc->ctx->ecb(utc->ctx->ecbClosure,
		    &event);		
    } else {
      event.type = FSUI_upload_error;
      event.data.UploadError.uc.pos = utc;
      event.data.UploadError.uc.cctx = utc->cctx;
      event.data.UploadError.uc.ppos = utc->parent;
      event.data.UploadError.uc.pcctx = utc->parent->cctx;
      event.data.UploadError.message = _("Upload failed.");
      utc->ctx->ecb(utc->ctx->ecbClosure,
		    &event);		
    }
    if (utc->meta == NULL)
      utc->meta = ECRS_createMetaData();
    else
      ECRS_delFromMetaData(utc->meta,
			   EXTRACTOR_FILENAME,
			   NULL);
    ECRS_extractMetaData(ectx,
			 utc->meta,
			 utc->filename,
			 utc->extractors);
    utc->filename = NULL;
  } else if (utc->isRecursive) {
    DirTrack current;
    int i;

    memset(&current, 0, sizeof(DirTrack));
    utc->dir = &current;
    disk_directory_scan(ectx,
			utc->filename,
			&dirEntryCallback,
			utc);
    ret = uploadDirectory(utc,
			  utc->filename,
			  &current,
			  &uri,
			  &utc->meta);
    for (i=0;i<current.fiCount;i++) {
      ECRS_freeMetaData(current.fis[i].meta);
      ECRS_freeUri(current.fis[i].uri);
    }
    GROW(current.fis,
	 current.fiCount,
	 0);
    utc->filename = NULL;
  } else {
    event.type = FSUI_upload_error;
    event.data.UploadError.uc.pos = utc;
    event.data.UploadError.uc.cctx = utc->cctx;
    event.data.UploadError.uc.ppos = utc->parent;
    event.data.UploadError.uc.pcctx = utc->parent->cctx;
    event.data.UploadError.message = _("Cannot upload directory without using recursion.");
    utc->ctx->ecb(utc->ctx->ecbClosure,
		  &event);		
  }
  if (ret == OK) { /* publish top-level advertisements */
    fi.meta = utc->meta;
    fi.uri = uri;
    URITRACK_trackURI(ectx,
		      utc->ctx->cfg,
		      &fi);
    if (inboundFN != NULL) {
      ECRS_delFromMetaData(utc->meta,
			   EXTRACTOR_FILENAME,
			   NULL);
      ECRS_addToMetaData(utc->meta,
			 EXTRACTOR_FILENAME,
			 inboundFN);
    }
#if DEBUG_UPLOAD
    GE_LOG(ectx, 
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Adding URI to keyspace.\n");
#endif
    keywordUri = ECRS_metaDataToUri(utc->meta);
    if (keywordUri != NULL) {
      ECRS_addToKeyspace(ectx,
			 utc->ctx->cfg,
			 keywordUri,
			 utc->anonymityLevel,
			 utc->priority,
			 utc->expiration,
			 uri,
			 utc->meta);	
      ECRS_freeUri(keywordUri);
    }
    if (utc->globalUri != NULL)
      ECRS_addToKeyspace(ectx,
			 utc->ctx->cfg,
			 utc->globalUri,
			 utc->anonymityLevel,
			 utc->priority,
			 utc->expiration,
			 uri,
			 utc->meta);	
    if (utc->uri != NULL)
      ECRS_addToKeyspace(ectx,
			 utc->ctx->cfg,
			 utc->uri,
			 utc->anonymityLevel,
			 utc->priority,
			 utc->expiration,
			 uri,
			 utc->meta);	
  }
  fi.uri = uri;
  ECRS_delFromMetaData(utc->meta,
		       EXTRACTOR_SPLIT,
		       NULL);
  fi.meta = utc->meta;
  if (sendEvent)
    utc->ctx->ecb(utc->ctx->ecbClosure,
		  &event);
  if (uri != NULL)
    ECRS_freeUri(uri);

  FREENONNULL(inboundFN);
  return NULL;
}

static struct FSUI_UploadList *
startUpload(struct FSUI_Context * ctx,
	    const char * filename,
	    unsigned int anonymityLevel,
	    unsigned int priority,
	    int doIndex,
	    char * config,
	    EXTRACTOR_ExtractorList * extractors,
	    int individualKeywords,
	    const struct ECRS_MetaData * md,
	    const struct ECRS_URI * globalURI,
	    const struct ECRS_URI * keyUri,
	    struct FSUI_UploadList * parent) {
  FSUI_UploadList * utc;
  struct GE_Context * ectx;

  ectx = ctx->ectx;
  utc = MALLOC(sizeof(FSUI_UploadList));
  utc->dir = NULL;
  utc->anonymityLevel = anonymityLevel;
  utc->priority = priority;
  utc->expiration = get_time() + 120 * cronYEARS;
  utc->ctx = ctx;
  utc->isRecursive = NO;
  utc->parent = parent;
  utc->globalUri = ECRS_dupUri(globalURI);
  utc->filename = STRDUP(filename);
  utc->extractor_config = config;
  utc->extractors = extractors;
  utc->uri = ECRS_dupUri(keyUri);
  utc->meta = ECRS_dupMetaData(md);
  utc->doIndex = doIndex;
  utc->individualKeywords = NO;
  utc->force_termination = NO;
  utc->handle = PTHREAD_CREATE(&FSUI_uploadThread,
			       utc,
			       128 * 1024);
  if (utc->handle == NULL) {
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_USER | GE_BULK, 
		    "PTHREAD_CREATE");
    FREE(utc->filename);
    ECRS_freeMetaData(utc->meta);
    ECRS_freeUri(utc->uri);
    ECRS_freeUri(utc->globalURI);
    if (utc->parent == &utc->ctx->activeUploads) {
      EXTRACTOR_removeAll(utc->extractors);
      FREE(utc->extractor_config);
    }
    FREE(utc);
    return NULL;
  }

  MUTEX_LOCK(ctx->lock);
  utc->next = parent->child;
  parent->child = utc;
  MUTEX_UNLOCK(ctx->lock);
  return utc;
}


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
struct FSUI_UploadList *
FSUI_startUpload(struct FSUI_Context * ctx,
		 const char * filename,
		 unsigned int anonymityLevel,
		 unsigned int priority,
		 int doIndex,
		 int doExtract,
		 int individualKeywords,
		 const struct ECRS_MetaData * md,
		 const struct ECRS_URI * globalURI,
		 const struct ECRS_URI * keyUri) {
  char * config;
  EXTRACTOR_ExtractorList * extractors;

  if (doExtract) {
    extractors = EXTRACTOR_loadDefaultLibraries();
    if ( (0 == GC_get_configuration_value_string(ctx->cfg,
						 "FS",
						 "EXTRACTORS",
						 NULL,
						 &config)) &&
	 (config != NULL) ) {
      extractors = EXTRACTOR_loadConfigLibraries(extractors,
						 config);
    }
  } else {
    extractors = NULL;
    extractor_config = NULL;
  }
  return startUpload(ctx,
		     filename,
		     anonymityLevel,
		     priority,
		     doIndex,
		     extractors,
		     extractor_config,
		     individualKeywords,
		     md,
		     globalURI,
		     keyUri,
		     &ctx->activeUploads);
}

/**
 * Abort an upload.  If the context is for a recursive
 * upload, all sub-uploads will also be aborted.
 *
 * @return SYSERR on error
 */
int FSUI_abortUpload(struct FSUI_Context * ctx,
		     struct FSUI_UploadList * ul) {
  FSUI_UploadList * c;
  struct GE_Context * ectx;

  GE_ASSERT(ctx->ectx, ul != NULL);
  c = ul->child;
  while (c != NULL) {
    FSUI_abortDownload(ctx, c);
    c = c->next;
  }    
  if ( (ul->state != FSUI_ACTIVE) &&
       (ul->state != FSUI_PENDING) )
    return NO;
  ul->state = FSUI_ABORTED;
  PTHREAD_STOP_SLEEP(ul->handle);
  event.type = FSUI_upload_aborted;
  event.data.DownloadAborted.dc.pos = dl;
  event.data.DownloadAborted.dc.cctx = dl->cctx;
  event.data.DownloadAborted.dc.ppos = dl->parent;
  event.data.DownloadAborted.dc.pcctx = dl->parent->cctx;
  ctx->ecb(ctx->ecbClosure,
	   &event);
  return OK;
}

/**
 * Stop an upload.  If the context is for a recursive
 * upload, all sub-uploads will also be stopped.
 *
 * @return SYSERR on error
 */
int FSUI_stopUpload(struct FSUI_Context * ctx,
		    struct FSUI_UploadList * ul) {
  void * unused;
  FSUI_UploadList * prev;
  struct GE_Context * ectx;

  GE_ASSERT(ctx->ectx, ul != NULL);
  while (ul->child != NULL)
    FSUI_stopDownload(ctx,
		      ul->child);
  MUTEX_LOCK(ctx->lock);
  prev = (ul->parent != NULL) ? ul->parent->child : ctx->activeDownloads.child;
  while ( (prev != ul) &&
	  (prev != NULL) &&
	  (prev->next != ul) ) 
    prev = prev->next;
  if (prev == NULL) {
    MUTEX_UNLOCK(ctx->lock);
    GE_LOG(ctx->ectx, 
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "FSUI_stopUpload failed to locate download.\n");
    return SYSERR;
  }
  if (prev == ul) 
    ul->parent->child = ul->next; /* first child of parent */
  else 
    prev->next = ul->next; /* not first child */  
  MUTEX_UNLOCK(ctx->lock);
  if ( (dl->state == FSUI_COMPLETED) ||
       (dl->state == FSUI_ABORTED) ||
       (dl->state == FSUI_ERROR) ) {
    PTHREAD_JOIN(ul->handle,
		 &unused);
    ul->state++; /* add _JOINED */
  }
  event.type = FSUI_upload_stopped;
  event.data.UploadStopped.uc.pos = ul;
  event.data.UploadStopped.uc.cctx = ul->cctx;
  event.data.UploadStopped.uc.ppos = ul->parent;
  event.data.UploadStopped.uc.pcctx = ul->parent->cctx;
  ctx->ecb(ctx->ecbClosure,
	   &event);
  FREE(ul->filename);
  if (ul->extractor_config != NULL)
    FREE(ul->extractor_config);
  ECRS_freeMetaData(ul->meta);
  ECRS_freeUri(ul->uri);
  EXTRACTOR_removeAll(ul->extractors);
  FREE(ul);
  return OK;
}

/* end of upload.c */
