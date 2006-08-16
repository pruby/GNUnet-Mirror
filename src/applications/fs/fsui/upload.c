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
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_uritrack_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"
#include <extractor.h>

#define DEBUG_UPLOAD NO

/* LE <= 0.5.8/0.5.12 compatibility code */
#ifndef EXTRACTOR_SPLIT
#define EXTRACTOR_SPLIT 89
#endif
#ifndef EXTRACTOR_LOWERCASE
#define EXTRACTOR_LOWERCASE 101
#endif

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
  event.data.UploadProgress.completed = completedBytes;
  event.data.UploadProgress.total = totalBytes;
  event.data.UploadProgress.filename = utc->filename;
  event.data.UploadProgress.eta = eta;
  utc->ctx->ecb(utc->ctx->ecbClosure,
		&event);
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
			    NULL,
			    NULL,
			    uri);
      if (ret == OK) {
	GE_ASSERT(ectx, NULL != *uri);
	event.type = FSUI_upload_complete;
	event.data.UploadComplete.total = utc->main_total;
	event.data.UploadComplete.filename = STRDUP(dirName);
	event.data.UploadComplete.uri = *uri;
	utc->ctx->ecb(utc->ctx->ecbClosure,
		      &event);	
	FREE(event.data.UploadComplete.filename);
	utc->main_completed += len;
      }
      UNLINK(tempName);
    }
    FREE(tempName);
    FREENONNULL(data);
  }

  if (ret != OK) {
    ECRS_freeMetaData(*meta);
    *meta = NULL;
  }
  return ret;
}

/**
 * For each file in the directory, upload (recursively).
 */
static int dirEntryCallback(const char * filename,
			    const char * dirName,
			    void * ptr) {
  FSUI_UploadList * utc = ptr;
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
  utc->filename = fn;

  if (NO == disk_directory_test(ectx, fn)) {
    ret = ECRS_uploadFile(ectx,
			  utc->ctx->cfg,
			  fn,
			  utc->doIndex,
			  utc->anonymityLevel,
			  utc->priority,
			  utc->expiration,
			  (ECRS_UploadProgressCallback) &progressCallback,
			  utc,
			  NULL,
			  NULL,
			  &uri);
    if (ret == OK) {
      GE_ASSERT(ectx, uri != NULL);
      event.type = FSUI_upload_complete;
      event.data.UploadComplete.total = utc->main_total;
      event.data.UploadComplete.filename = utc->filename;
      event.data.UploadComplete.uri = uri;
      if (OK == disk_file_size(ectx, 
			       fn, 
			       &len,
			       YES))
	utc->main_completed += len;
      utc->ctx->ecb(utc->ctx->ecbClosure,
		    &event);	
      meta = ECRS_createMetaData();
      ECRS_extractMetaData(ectx,
			   meta,
			   fn,
			   utc->extractors);
    } else {
      event.type = FSUI_upload_error;
      event.data.UploadError.message = _("Upload failed.");
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
static void * uploadThread(void * cls) {
  FSUI_UploadList * utc = cls;
  struct ECRS_URI * uri;
  struct ECRS_URI * keywordUri;
  FSUI_Event event;
  ECRS_FileInfo fi;
  int ret;
  char * inboundFN;
  int sendEvent = YES;
  struct GE_Context * ectx;

  ectx = utc->ctx->ectx;
  GE_ASSERT(ectx, utc->main_filename != NULL);
  inboundFN
    = ECRS_getFromMetaData(utc->meta,
			   EXTRACTOR_FILENAME);
  utc->start_time = get_time();

  if (OK != disk_file_size(ectx,
			   utc->main_filename,
			   &utc->main_total,
			   YES)) {
    utc->main_total = 0;
    /* or signal error?? */
  }
  utc->main_completed = 0;
  ret = SYSERR;
  uri = NULL;

  if (NO == disk_directory_test(ectx,
				utc->main_filename)) {
    utc->filename = utc->main_filename;
    ret = ECRS_uploadFile(ectx,
			  utc->ctx->cfg,
			  utc->main_filename,
			  utc->doIndex,
			  utc->anonymityLevel,
			  utc->priority,
			  utc->expiration,
			  (ECRS_UploadProgressCallback) &progressCallback,
			  utc,
			  NULL,
			  NULL,
			  &uri);
    if (ret == OK) {
      event.type = FSUI_upload_complete;
      event.data.UploadComplete.total = utc->main_total;
      event.data.UploadComplete.filename = utc->filename;
      event.data.UploadComplete.uri = uri;
    } else {
      event.type = FSUI_upload_error;
      event.data.UploadError.message = _("Upload failed.");
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
    utc->filename = utc->main_filename;
    disk_directory_scan(ectx,
			utc->main_filename,
			&dirEntryCallback,
			utc);
    ret = uploadDirectory(utc,
			  utc->main_filename,
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

    if (ret != OK) {
      event.type = FSUI_upload_error;
      event.data.UploadError.message = _("Upload failed.");
    } else { /* for success, uploadDirectory sends event already! */
      sendEvent = NO;
    }
    utc->filename = NULL;
  } else {
    event.type = FSUI_upload_error;
    event.data.UploadError.message = _("Cannot upload directory without using recursion.");
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
    GE_LOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
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
  /*
  CO_publishToCollection(ectx,
			   utc->ctx->cfg,
			   utc->ctx,
			   &fi);
  */
  if (sendEvent)
    utc->ctx->ecb(utc->ctx->ecbClosure,
		  &event);
  if (uri != NULL)
    ECRS_freeUri(uri);

  FREE(utc->main_filename);
  if (utc->meta != NULL)
    ECRS_freeMetaData(utc->meta);
  if (utc->uri != NULL)
    ECRS_freeUri(utc->uri);
  if (utc->globalUri != NULL)
    ECRS_freeUri(utc->globalUri);
  EXTRACTOR_removeAll(utc->extractors);
  utc->extractors = NULL;
  FREE(utc);
  FREENONNULL(inboundFN);
  return NULL;
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
  FSUI_UploadList * utc;
  char * config;
  struct GE_Context * ectx;

  ectx = utc->ctx->ectx;
  utc = MALLOC(sizeof(FSUI_UploadList));
  utc->dir = NULL;
  utc->anonymityLevel = anonymityLevel;
  utc->priority = priority;
  utc->expiration = get_time() + 120 * cronYEARS;
  utc->ctx = ctx;
  utc->isRecursive = NO;
  if (doExtract) {
    utc->extractors = EXTRACTOR_loadDefaultLibraries();
    if ( (0 == GC_get_configuration_value_string(ctx->cfg,
						 "FS",
						 "EXTRACTORS",
						 NULL,
						 &config)) &&
	 (config != NULL) ) {
      utc->extractors = EXTRACTOR_loadConfigLibraries(utc->extractors,
						      config);
      FREE(config);
    }
  } else
    utc->extractors = NULL;
  utc->globalUri = NULL;
  utc->filename = NULL;
  utc->main_filename = STRDUP(filename);
  utc->uri = ECRS_dupUri(keyUri);
  utc->meta = ECRS_dupMetaData(md);
  utc->doIndex = doIndex;
  utc->individualKeywords = NO;
  utc->handle = PTHREAD_CREATE(&uploadThread,
			       utc,
			       128 * 1024);
  if (utc->handle == NULL) {
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_USER | GE_BULK, 
		    "PTHREAD_CREATE");
    FREE(utc->main_filename);
    ECRS_freeMetaData(utc->meta);
    ECRS_freeUri(utc->uri);
    FREE(utc);
    return NULL;
  }

  MUTEX_LOCK(ctx->lock);
  utc->next = ctx->activeUploads;
  ctx->activeUploads = utc;
  MUTEX_UNLOCK(ctx->lock);
  cleanupFSUIThreadList(ctx);
  return utc;
}

/**
 * Abort an upload.  If the context is for a recursive
 * upload, all sub-uploads will also be aborted.
 *
 * @return SYSERR on error
 */
int FSUI_stopUpload(struct FSUI_Context * ctx,
		    struct FSUI_UploadList * ul) {
  return SYSERR;
}

/* end of upload.c */
