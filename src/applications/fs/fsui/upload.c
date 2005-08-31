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
 * @file applications/fs/fsui/upload.c
 * @brief upload functions
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fsui_lib.h"
#include "fsui.h"

#define DEBUG_UPLOAD NO

/**
 * Data used to keep track of the files in the
 * current directory.
 */
typedef struct {
  unsigned int fiCount;
  ECRS_FileInfo * fis;
} DirTrack;

/**
 * Context for the upload thread.
 */
typedef struct {
  int isRecursive;
  int doIndex;
  unsigned int anonymityLevel;
  unsigned int priority;
  cron_t expiration;
  struct ECRS_MetaData * meta;
  struct ECRS_URI * uri;
  struct ECRS_URI * globalUri;
  char * filename;
  char * main_filename;
  unsigned long long main_completed;
  unsigned long long main_total;
  EXTRACTOR_ExtractorList * extractors;
  FSUI_ThreadList * tl;
  FSUI_Context * ctx;
  cron_t start_time;
  DirTrack * dir;
  int individualKeywords;
} UploadThreadClosure;

/**
 * Transform an ECRS progress callback into an FSUI event.
 */
static void progressCallback(unsigned long long totalBytes,
			     unsigned long long completedBytes,
			     cron_t eta,
			     void * ptr) {
  UploadThreadClosure * utc = ptr;
  FSUI_Event event;
  cron_t now;

  cronTime(&now);
  event.type = FSUI_upload_progress;
  event.data.UploadProgress.completed = completedBytes;
  event.data.UploadProgress.total = totalBytes;
  event.data.UploadProgress.filename = utc->filename;
  event.data.UploadProgress.is_recursive = utc->isRecursive;
  event.data.UploadProgress.main_filename = utc->main_filename;
  event.data.UploadProgress.start_time = utc->start_time;
  event.data.UploadProgress.main_completed = utc->main_completed + completedBytes;
  event.data.UploadProgress.main_total = utc->main_total;
  event.data.UploadProgress.eta = eta;
  if (totalBytes > 0) {
    event.data.UploadProgress.main_eta
      = (cron_t) (utc->start_time +
		  (((double)( (now -
			       utc->start_time) /
			     (double)(utc->main_completed
				      + completedBytes))))
		   * (double) utc->main_total);
  } else {
    event.data.UploadProgress.main_eta = eta; /* huh? */
  }
  utc->ctx->ecb(utc->ctx->ecbClosure,
		&event);
}

/**
 * Take the current directory entries from utc, create
 * a directory, upload it and store the uri in  *uri.
 */
static int uploadDirectory(UploadThreadClosure * utc,
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

  GNUNET_ASSERT(utc->filename != NULL);

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
  ECRS_addToMetaData(*meta,
		     EXTRACTOR_FILENAME,
		     &dirName[lastSlash+1]);
  ECRS_addToMetaData(*meta,
		     EXTRACTOR_MIMETYPE,
		     GNUNET_DIRECTORY_MIME);
  data = NULL;
  if (OK == ECRS_createDirectory(&data,
				 &len,
				 backup->fiCount,
				 backup->fis,
				 *meta)) {
    utc->main_total += len;

    tempName = STRDUP("/tmp/gnunetdir.XXXXXX");
    handle = mkstemp(tempName);
    if (handle == -1) {
      LOG_FILE_STRERROR(LOG_ERROR, tempName, "mkstemp");
    } else if (len != WRITE(handle,
			    data,
			    len)) {
      LOG_FILE_STRERROR(LOG_ERROR, tempName, "write");
    } else {
      closefile(handle);
      utc->filename = tempName;
      ret = ECRS_uploadFile(tempName,
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
	event.type = FSUI_upload_complete;
	event.data.UploadComplete.total = utc->main_total;
	event.data.UploadComplete.completed = utc->main_completed;
	event.data.UploadComplete.filename = STRDUP(dirName);
	event.data.UploadComplete.uri = *uri;
	event.data.UploadComplete.eta
	  = (cron_t) (utc->start_time +
		      (((double)(cronTime(NULL)
				 - utc->start_time/(double)(utc->main_completed+len))))
		      * (double)utc->main_total);
	event.data.UploadComplete.start_time = utc->start_time;
	event.data.UploadComplete.is_recursive = YES;
	event.data.UploadComplete.main_filename = utc->main_filename;
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
  UploadThreadClosure * utc = ptr;
  char * fn;
  struct ECRS_URI * uri;
  struct ECRS_URI * keywordUri;
  struct ECRS_MetaData * meta;
  FSUI_Event event;
  int ret;
  unsigned long long len;

  fn = MALLOC(strlen(filename) + strlen(dirName) + 2);
  strcpy(fn, dirName);
  strcat(fn, "/");
  strcat(fn, filename);
  utc->filename = fn;

  if (NO == isDirectory(fn)) {
    ECRS_uploadFile(fn,
		    utc->doIndex,
		    utc->anonymityLevel,
		    utc->priority,
		    utc->expiration,
		    (ECRS_UploadProgressCallback) &progressCallback,
		    utc,
		    NULL,
		    NULL,
		    &uri);
    event.type = FSUI_upload_complete;
    event.data.UploadComplete.total = utc->main_total;
    event.data.UploadComplete.completed = utc->main_completed;
    event.data.UploadComplete.filename = utc->filename;
    event.data.UploadComplete.uri = uri;
    if (OK == getFileSize(fn, &len))
      utc->main_completed += len;
    event.data.UploadComplete.eta
      = (cron_t) (utc->start_time +
		  (((double)(cronTime(NULL)
			     - utc->start_time/(double)(utc->main_completed))))
		  * (double)utc->main_total);
    event.data.UploadComplete.start_time = utc->start_time;
    event.data.UploadComplete.is_recursive = YES;
    event.data.UploadComplete.main_filename = utc->main_filename;
    utc->ctx->ecb(utc->ctx->ecbClosure,
		  &event);	
    meta = ECRS_createMetaData();
    ECRS_extractMetaData(meta,
			 fn,
			 utc->extractors);
    ret = OK;
  } else {
    DirTrack current;
    DirTrack * prev;
    int i;

    memset(&current, 0, sizeof(DirTrack));
    prev = utc->dir;
    utc->dir = &current;
    scanDirectory(fn,
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
    ECRS_addToMetaData(meta,
		       EXTRACTOR_FILENAME,
		       filename);
    if (utc->individualKeywords) {
      keywordUri = ECRS_metaDataToUri(meta);
      if (keywordUri != NULL) {
	ECRS_addToKeyspace(keywordUri,
			   utc->anonymityLevel,
			   utc->priority,
			   utc->expiration,
			   uri,
			   meta);	
	ECRS_freeUri(keywordUri);
      }
    }
    if (utc->globalUri != NULL)
      ECRS_addToKeyspace(utc->globalUri,
			 utc->anonymityLevel,
			 utc->priority,
			 utc->expiration,
			 uri,
			 meta);	
    if (utc->dir != NULL) {
      GROW(utc->dir->fis,
	   utc->dir->fiCount,
	   utc->dir->fiCount+1);
      utc->dir->fis[utc->dir->fiCount-1].meta = meta;
      utc->dir->fis[utc->dir->fiCount-1].uri = uri;
    } else {
      ECRS_freeMetaData(meta);
      ECRS_freeUri(uri);
    }
    FSUI_trackURI(&utc->dir->fis[utc->dir->fiCount-1]);
  }
  FREE(fn);
  return OK;
}

/**
 * Thread that does the upload.
 */
static void * uploadThread(UploadThreadClosure * utc) {
  struct ECRS_URI * uri;
  struct ECRS_URI * keywordUri;
  FSUI_Event event;
  ECRS_FileInfo fi;
  int ret;
  char * inboundFN;
  int sendEvent = YES;

  GNUNET_ASSERT(utc->main_filename != NULL);
  inboundFN
    = ECRS_getFromMetaData(utc->meta,
			   EXTRACTOR_FILENAME);
  cronTime(&utc->start_time);

  if (OK != getFileSize(utc->main_filename,
			&utc->main_total)) {
    utc->main_total = 0;
    /* or signal error?? */
  }
  utc->main_completed = 0;
  ret = SYSERR;
  uri = NULL;

  if (NO == isDirectory(utc->main_filename)) {
    utc->filename = utc->main_filename;
    ret = ECRS_uploadFile(utc->main_filename,
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
      event.data.UploadComplete.completed = utc->main_completed;
      event.data.UploadComplete.filename = utc->filename;
      event.data.UploadComplete.uri = uri;
      event.data.UploadComplete.eta = cronTime(NULL);
      event.data.UploadComplete.start_time = utc->start_time;
      event.data.UploadComplete.is_recursive = NO;
      event.data.UploadComplete.main_filename = utc->main_filename;
    } else {
      event.type = FSUI_upload_error;
      event.data.message = _("Upload failed.\n");
    }
    if (utc->meta == NULL)
      utc->meta = ECRS_createMetaData();
    else
      ECRS_delFromMetaData(utc->meta,
			   EXTRACTOR_FILENAME,
			   NULL);
    ECRS_extractMetaData(utc->meta,
			 utc->filename,
			 utc->extractors);
    utc->filename = NULL;
  } else if (utc->isRecursive) {
    DirTrack current;
    int i;

    memset(&current, 0, sizeof(DirTrack));
    utc->dir = &current;
    utc->filename = utc->main_filename;
    scanDirectory(utc->main_filename,
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
      event.data.message = _("Upload failed.\n");
    } else { /* for success, uploadDirectory sends event already! */
      sendEvent = NO;
    }
    utc->filename = NULL;
  } else {
    event.type = FSUI_upload_error;
    event.data.message = _("Cannot upload directory without using recursion.\n");
  }
  if (ret == OK) { /* publish top-level advertisements */
    fi.meta = utc->meta;
    fi.uri = uri;
    FSUI_trackURI(&fi);
    if (inboundFN != NULL) {
      ECRS_delFromMetaData(utc->meta,
			   EXTRACTOR_FILENAME,
			   NULL);
      ECRS_addToMetaData(utc->meta,
			 EXTRACTOR_FILENAME,
			 inboundFN);
    }
#if DEBUG_UPLOAD
    LOG(LOG_DEBUG,
	"Adding URI to keyspace.\n");
#endif
    keywordUri = ECRS_metaDataToUri(utc->meta);
    if (keywordUri != NULL) {
      ECRS_addToKeyspace(keywordUri,
			 utc->anonymityLevel,
			 utc->priority,
			 utc->expiration,
			 uri,
			 utc->meta);	
      ECRS_freeUri(keywordUri);
    }
    if (utc->globalUri != NULL)
      ECRS_addToKeyspace(utc->globalUri,
			 utc->anonymityLevel,
			 utc->priority,
			 utc->expiration,
			 uri,
			 utc->meta);	
    if (utc->uri != NULL)
      ECRS_addToKeyspace(utc->uri,
			 utc->anonymityLevel,
			 utc->priority,
			 utc->expiration,
			 uri,
			 utc->meta);	
  }
  fi.uri = uri;
  fi.meta = utc->meta;
  FSUI_publishToCollection(utc->ctx,
			   &fi);
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
  utc->tl->isDone = YES;
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
int FSUI_upload(struct FSUI_Context * ctx,
		const char * filename,
		unsigned int anonymityLevel,
		int doIndex,
		int doExtract,
		const struct ECRS_MetaData * md,
		const struct ECRS_URI * keyUri) {
  FSUI_ThreadList * tl;
  UploadThreadClosure * utc;
  char * config;

  utc = MALLOC(sizeof(UploadThreadClosure));
  utc->dir = NULL;
  utc->anonymityLevel = anonymityLevel;
  utc->priority = getConfigurationInt("FS",
				      "INSERT-PRIORITY");
  utc->expiration = cronTime(NULL) + 120 * cronYEARS;
  utc->ctx = ctx;
  utc->isRecursive = NO;
  if (doExtract) {
    utc->extractors = EXTRACTOR_loadDefaultLibraries();
    config = getConfigurationString("FS",
				    "EXTRACTORS");
    if (config != NULL) {
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
  tl = MALLOC(sizeof(FSUI_ThreadList));
  utc->tl = tl;
  tl->isDone = NO;
  if (0 != PTHREAD_CREATE(&tl->handle,
			  (PThreadMain) &uploadThread,
			  utc,
			  128 * 1024)) {
    LOG_STRERROR(LOG_ERROR, "PTHREAD_CREATE");
    FREE(tl);
    FREE(utc->main_filename);
    ECRS_freeMetaData(utc->meta);
    ECRS_freeUri(utc->uri);
    FREE(utc);
    return SYSERR;
  }

  MUTEX_LOCK(&ctx->lock);
  tl->next = ctx->activeThreads;
  ctx->activeThreads = tl;
  MUTEX_UNLOCK(&ctx->lock);
  cleanupFSUIThreadList(ctx);
  return OK;
}
/**
 * Start uploading a directory.  Note that an upload cannot be stopped
 * once started (not necessary anyway), but it can fail.  All files
 * in the recursive tree will be indexed under all keywords found by
 * the specified extractor plugins AND the globalKeywords.  The
 * main directory will furthermore be published with the given keywords
 * and the specified directoryMetaData.
 *
 * @return OK on success (at least we started with it),
 *  SYSERR if the file does not exist
*/
int FSUI_uploadAll(struct FSUI_Context * ctx,
		   const char * dirname,
		   unsigned int anonymityLevel,
		   int doIndex,
		   int individualKeywords,
		   const struct ECRS_MetaData * directoryMetaData,
		   const struct ECRS_URI * globalURI,
		   const struct ECRS_URI * topURI) {
  FSUI_ThreadList * tl;
  UploadThreadClosure * utc;
  char * config;

  utc = MALLOC(sizeof(UploadThreadClosure));
  utc->individualKeywords = individualKeywords;
  utc->ctx = ctx;
  utc->isRecursive = YES;
  utc->anonymityLevel = anonymityLevel;
  utc->priority = getConfigurationInt("FS",
				      "INSERT-PRIORITY");
  utc->expiration = cronTime(NULL) + 120 * cronYEARS;
  utc->extractors = EXTRACTOR_loadDefaultLibraries();
  config = getConfigurationString("FS",
				  "EXTRACTORS");

  if (config != NULL) {
    utc->extractors = EXTRACTOR_loadConfigLibraries(utc->extractors,
						    config);
    FREE(config);
  }
  utc->globalUri = ECRS_dupUri(globalURI);
  utc->filename = NULL;
  utc->main_filename = STRDUP(dirname);
  utc->uri = ECRS_dupUri(topURI);
  utc->meta = ECRS_dupMetaData(directoryMetaData);
  utc->doIndex = doIndex;
  tl = MALLOC(sizeof(FSUI_ThreadList));
  utc->tl = tl;
  tl->isDone = NO;
  if (0 != PTHREAD_CREATE(&tl->handle,
			  (PThreadMain) &uploadThread,
			  utc,
			  128 * 1024)) {
    LOG_STRERROR(LOG_ERROR, "PTHREAD_CREATE");
    FREE(tl);
    FREE(utc->main_filename);
    ECRS_freeMetaData(utc->meta);
    ECRS_freeUri(utc->globalUri);
    ECRS_freeUri(utc->uri);
    FREE(utc);
    return SYSERR;
  }

  MUTEX_LOCK(&ctx->lock);
  tl->next = ctx->activeThreads;
  ctx->activeThreads = tl;
  MUTEX_UNLOCK(&ctx->lock);
  cleanupFSUIThreadList(ctx);
  return OK;
}


/* end of upload.c */
