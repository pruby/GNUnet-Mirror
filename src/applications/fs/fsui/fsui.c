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
 * @file applications/fs/fsui/fsui.c
 * @brief main FSUI functions
 * @author Christian Grothoff
 *
 * TODO:
 * - upload serialize/deserialize/resume
 * - unindex deserialize/resume
 * - events for suspend (!)
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_directories.h"
#include "fsui.h"

#define DEBUG_PERSISTENCE NO

#define FSUI_UDT_FREQUENCY (2 * cronSECONDS)

#define READINT(a) \
  if (sizeof(int) != READ(fd, &big, sizeof(int))) \
    goto ERR;					  \
  else \
    a = ntohl(big)
#define READLONG(a) \
  if (sizeof(long long) != READ(fd, &bigl, sizeof(long long))) \
    goto ERR;						       \
  else \
    a = ntohll(bigl)

static struct ECRS_URI * readURI(struct GE_Context * ectx,
				 int fd) {
  char * buf;
  unsigned int big;
  struct ECRS_URI * ret;
  unsigned int size;

  READINT(size);
  buf = MALLOC(size+1);
  buf[size] = '\0';
  if (size != READ(fd,
		   buf,
		   size)) {
    FREE(buf);
    return NULL;
  }
  ret = ECRS_stringToUri(ectx, buf);
  FREE(buf);
  return ret;
 ERR:
  return NULL;
}

static void doResumeEvents(struct FSUI_DownloadList * ret,
			   FSUI_Context * ctx) {
  FSUI_Event event;

  while (ret != NULL) {
    event.type = FSUI_download_resuming;
    event.data.DownloadResuming.dc.pos = ret;
    event.data.DownloadResuming.dc.cctx = ret->cctx;
    event.data.DownloadResuming.dc.ppos = ret->parent;
    event.data.DownloadResuming.dc.pcctx = ret->parent != NULL ? ret->parent->cctx : NULL;
    event.data.DownloadResuming.eta = get_time(); /* best guess */
    event.data.DownloadResuming.total = ret->total;
    event.data.DownloadResuming.completed = ret->completedFile;
    event.data.DownloadResuming.anonymityLevel = ret->anonymityLevel;
    event.data.DownloadResuming.uri = ret->uri;
    ret->cctx = ctx->ecb(ctx->ecbClosure, &event);
    if (ret->child != NULL)
      doResumeEvents(ret->child,
		     ctx);
    ret = ret->next;
  }
}

/**
 * (Recursively) read a download list from the given fd.  The returned
 * pointer is expected to be integrated into the tree either as a next
 * or child pointer such that the given parent becomes the parent of the
 * returned node.
 *
 * @return NULL on error AND on read of empty
 *  list (these two cannot be distinguished)
 */
static FSUI_DownloadList * readDownloadList(struct GE_Context * ectx,
					    int fd,
					    FSUI_Context * ctx,
					    FSUI_DownloadList * parent) {
  char zaro;
  FSUI_DownloadList * ret;
  unsigned int big;
  unsigned long long bigl;
  int i;
  int ok;

  GE_ASSERT(ectx, ctx != NULL);
  if (1 != READ(fd, &zaro, sizeof(char))) {
    GE_BREAK(ectx, 0);
    return NULL;
  }
  if (zaro == '\0') 
    return NULL;
  ret = MALLOC(sizeof(FSUI_DownloadList));
  memset(ret,
	 0,
	 sizeof(FSUI_DownloadList));
  ret->ctx = ctx;
  READINT(ret->is_recursive);
  READINT(ret->is_directory);
  READINT(ret->anonymityLevel);
  READINT(ret->completedDownloadsCount);
  READINT(ret->state);
  switch (ret->state) { /* try to correct errors */
  case FSUI_DOWNLOAD_ACTIVE:
    ret->state = FSUI_DOWNLOAD_PENDING;
    break;
  case FSUI_DOWNLOAD_PENDING:
  case FSUI_DOWNLOAD_COMPLETED_JOINED:
  case FSUI_DOWNLOAD_ABORTED_JOINED:
  case FSUI_DOWNLOAD_ERROR_JOINED:
    break;
  case FSUI_DOWNLOAD_ERROR:
    ret->state = FSUI_DOWNLOAD_ERROR_JOINED;
    break;
  case FSUI_DOWNLOAD_ABORTED:
    ret->state = FSUI_DOWNLOAD_ABORTED_JOINED;
    break;
  case FSUI_DOWNLOAD_COMPLETED:
    ret->state = FSUI_DOWNLOAD_COMPLETED_JOINED;
    break;
  default:
    ret->state = FSUI_DOWNLOAD_PENDING;
    break;
  }
  READINT(big);
  if (big > 1024 * 1024) {
    GE_BREAK(ectx, 0);
    goto ERR;
  }
  ret->filename = MALLOC(big+1);
  if (big != READ(fd, ret->filename, big)) {
    GE_BREAK(ectx, 0);
    goto ERR;
  }
  ret->filename[big] = '\0';
  READLONG(ret->total);
  READLONG(ret->completed);
  ret->completedFile = 0;
  READLONG(ret->startTime);
  ret->startTime = get_time() - ret->startTime;
  ret->uri
    = readURI(ectx, fd);
  if (ret->completedDownloadsCount > 0)
    ret->completedDownloads
      = MALLOC(sizeof(struct ECRS_URI *) *
	       ret->completedDownloadsCount);
  else
    ret->completedDownloads
      = NULL;
  ok = ret->uri != NULL;
  for (i=0;i<ret->completedDownloadsCount;i++) {
    ret->completedDownloads[i]
      = readURI(ectx, fd);
    if (ret->completedDownloads[i] == NULL) 
      ok = NO;    
  }
  if (NO == ok) {
    GE_BREAK(ectx, 0);
    goto ERR;
  }
  ret->parent = parent;
  ret->next = readDownloadList(ectx,
			       fd,
			       ctx,
			       parent);
  ret->child = readDownloadList(ectx,
				fd,
				ctx,
				ret);
#if DEBUG_PERSISTENCE
  GE_LOG(ectx, 
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "FSUI persistence: restoring download `%s': (%llu, %llu)\n",
	 ret->filename,
	 ret->completed,
	 ret->total);
#endif
  return ret;
 ERR:
  FREENONNULL(ret->filename);
  if (ret->uri != NULL)
    ECRS_freeUri(ret->uri);
  for (i=0;i<ret->completedDownloadsCount;i++) {
    if (ret->completedDownloads[i] != NULL)
      ECRS_freeUri(ret->completedDownloads[i]);
  }
  FREE(ret);
  GE_LOG(ectx,
	 GE_WARNING | GE_BULK | GE_USER,
	 _("FSUI persistence: error restoring download\n"));
  return NULL;
}

static void WRITEINT(int fd,
		     int val) {
  int big;
  big = htonl(val);
  WRITE(fd, &big, sizeof(int));
}

static void WRITELONG(int fd,
		      long long val) {
  long long big;
  big = htonll(val);
  WRITE(fd, &big, sizeof(long long));
}

static void writeURI(int fd,
		     const struct ECRS_URI * uri) {
  char * buf;
  unsigned int size;

  buf = ECRS_uriToString(uri);
  size = strlen(buf);
  WRITEINT(fd, size);
  WRITE(fd,
	buf,
	size);
  FREE(buf);
}

static void WRITESTRING(int fd,
			const char * name) {
  WRITEINT(fd,
	   strlen(name));
  WRITE(fd,
	name,
	strlen(name));
}

/**
 * (recursively) write a download list.
 */
static void writeDownloadList(struct GE_Context * ectx,
			      int fd,
			      FSUI_Context * ctx,
			      FSUI_DownloadList * list) {
  static char zero = '\0';
  static char nonzero = '+';
  int i;
  FSUI_Event event;

  if (list == NULL) {
    WRITE(fd, &zero, sizeof(char));
    return;
  }
#if DEBUG_PERSISTENCE
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Serializing download state of download `%s': (%llu, %llu)\n",
	 list->filename,
	 list->completed,
	 list->total);
#endif
  WRITE(fd, &nonzero, sizeof(char));

  WRITEINT(fd, list->is_recursive);
  WRITEINT(fd, list->is_directory);
  WRITEINT(fd, list->anonymityLevel);
  WRITEINT(fd, list->completedDownloadsCount);
  WRITEINT(fd, list->state);
  WRITEINT(fd, strlen(list->filename));
  WRITE(fd,
	list->filename,
	strlen(list->filename));
  WRITELONG(fd, list->total);
  WRITELONG(fd, list->completed);
  WRITELONG(fd, get_time() - list->startTime);
  writeURI(fd, list->uri);
  for (i=0;i<list->completedDownloadsCount;i++)
    writeURI(fd, list->completedDownloads[i]);
  writeDownloadList(ectx,
		    fd,
		    ctx,
		    list->next);
  writeDownloadList(ectx,
		    fd,
		    ctx,
		    list->child);
  event.type = FSUI_download_suspending;
  event.data.DownloadSuspending.dc.pos = list;
  event.data.DownloadSuspending.dc.cctx = list->cctx;
  event.data.DownloadSuspending.dc.ppos = list->parent;
  event.data.DownloadSuspending.dc.pcctx = list->parent != NULL ? list->parent->cctx : NULL; 
  ctx->ecb(ctx->ecbClosure, &event);
}

/**
 * Read file info from file.
 *
 * @return OK on success, SYSERR on error
 */
static int readFileInfo(struct GE_Context * ectx,
			int fd,
			ECRS_FileInfo * fi) {
  unsigned int size;
  unsigned int big;
  char * buf;

  fi->meta = NULL;
  fi->uri = NULL;
  READINT(size);
  if (size > 1024 * 1024) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  buf = MALLOC(size);
  if (size != READ(fd,
		   buf,
		   size)) {
    FREE(buf);
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  fi->meta = ECRS_deserializeMetaData(ectx,
				      buf,
				      size);
  if (fi->meta == NULL) {
    FREE(buf);
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  FREE(buf);

  fi->uri
    = readURI(ectx, fd);
  if (fi->uri == NULL) {
    ECRS_freeMetaData(fi->meta);
    fi->meta = NULL;
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  return OK;
 ERR:
  GE_BREAK(ectx, 0);
  return SYSERR;
}

static void writeFileInfo(struct GE_Context * ectx,
			  int fd,
			  const ECRS_FileInfo * fi) {
  unsigned int size;
  char * buf;

  size = ECRS_sizeofMetaData(fi->meta,
			     ECRS_SERIALIZE_FULL | ECRS_SERIALIZE_NO_COMPRESS);
  if (size > 1024 * 1024)
    size = 1024 * 1024;
  buf = MALLOC(size);
  ECRS_serializeMetaData(ectx,
			 fi->meta,
			 buf,
			 size,
			 ECRS_SERIALIZE_PART | ECRS_SERIALIZE_NO_COMPRESS);
  WRITEINT(fd, size);
  WRITE(fd,
	buf,
	size);
  FREE(buf);
  writeURI(fd, fi->uri);
}

static void updateDownloadThreads(void * c) {
  FSUI_Context * ctx = c;
  FSUI_DownloadList * dpos;

  MUTEX_LOCK(ctx->lock);
  dpos = ctx->activeDownloads.child;
#if DEBUG_PERSISTENCE
  if (dpos != NULL)
    GE_LOG(ctx->ectx, 
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Download thread manager schedules pending downloads...\n");
#endif
  while (dpos != NULL) {
    updateDownloadThread(dpos);
    dpos = dpos->next;
  }
  MUTEX_UNLOCK(ctx->lock);
}

/**
 * Start FSUI manager.  Use the given progress callback to notify the
 * UI about events.  Start processing pending activities that were
 * running when FSUI_stop was called previously.
 *
 * @param name name of the context, must not be NULL
 * @return NULL on error
 */
struct FSUI_Context * FSUI_start(struct GE_Context * ectx,
				 struct GC_Configuration * cfg,
				 const char * name,
				 unsigned int threadPoolSize,
				 int doResume,
				 FSUI_EventCallback cb,
				 void * closure) {
  FSUI_Event event;
  FSUI_Context * ret;
  FSUI_SearchList * list;
  ResultPending * rp;
  char * fn;
  char * gh;
  int fd;
  int i;

  GE_ASSERT(ectx, cfg != NULL);
  ret = MALLOC(sizeof(FSUI_Context));
  memset(ret, 0, sizeof(FSUI_Context));
  ret->activeDownloads.state
    = FSUI_DOWNLOAD_PENDING; /* !? */
  ret->activeDownloads.ctx
    = ret;
  ret->cfg
    = cfg;
  ret->ecb = cb;
  ret->ecbClosure = closure;
  ret->threadPoolSize = threadPoolSize;
  if (ret->threadPoolSize == 0)
    ret->threadPoolSize = 32;
  ret->activeDownloadThreads = 0;

  GC_get_configuration_value_filename(cfg,
				      "GNUNET",
				      "GNUNET_HOME",
				      GNUNET_HOME_DIRECTORY,
				      &gh);
  fn = MALLOC(strlen(gh) + strlen(name) + 2 + 5);
  strcpy(fn, gh);
  FREE(gh);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, name);
  ret->name = fn;
  if (doResume) {
    ret->ipc = IPC_SEMAPHORE_CREATE(ectx,
				    fn,
				    1);
#if DEBUG_PERSISTENCE
    GE_LOG(ectx,
	   GE_INFO | GE_REQUEST | GE_USER,
	   "Getting IPC lock for FSUI (%s).\n",
	   fn);
#endif
    IPC_SEMAPHORE_DOWN(ret->ipc, YES);
#if DEBUG_PERSISTENCE
    GE_LOG(ectx, 
	   GE_INFO | GE_REQUEST | GE_USER,
	   "Aquired IPC lock.\n");
#endif
    fd = -1;
    strcat(fn, ".res");
    if (0 == ACCESS(fn, R_OK))
      fd = disk_file_open(ectx,
			  fn,
			  O_RDONLY);
    if (fd != -1) {
      char magic[8];
      unsigned int big;

      /* ****** check magic ******* */
      if (8 != READ(fd, magic, 8)) {
	GE_BREAK(ectx, 0);
	goto WARN;
      }
      if (0 != memcmp(magic,
		      "FSUI00\n\0",
		      8)) {
	GE_BREAK(ectx, 0);
	goto WARN;
      }
      /* ******* deserialize state **** */

      /* deserialize collection data */
      if (sizeof(unsigned int) !=
	  READ(fd, &big, sizeof(unsigned int))) {
	GE_BREAK(ectx, 0);
	goto WARN;
      }
      if (ntohl(big) > 16 * 1024 * 1024) {
	GE_BREAK(ectx, 0);
	goto WARN;
      }
      if (big == 0) {
	ret->collectionData = NULL;
      } else {
	ret->collectionData
	  = MALLOC(ntohl(big));
	if (ntohl(big) - sizeof(unsigned int) !=
	    READ(fd,
		 &ret->collectionData[1],
		 ntohl(big) - sizeof(unsigned int))) {
	  FREE(ret->collectionData);
	  ret->collectionData = NULL;
	  GE_BREAK(ectx, 0);
	  goto WARN;
	}
      }

      /* deserialize pending searches! */
      while (1) {
	char * buf;

	if (sizeof(unsigned int) !=
	    READ(fd, &big, sizeof(unsigned int))) {
	  GE_BREAK(ectx, 0);	
	  goto WARN;
	}
	if (ntohl(big) == 0)
	  break;
	if (ntohl(big) > 1024 * 1024) {
	  GE_BREAK(ectx, 0);	
	  goto WARN;
	}
	buf
	  = MALLOC(ntohl(big)+1);
	buf[ntohl(big)] = '\0';	
	if (ntohl(big) !=
	    READ(fd,
		 buf,
		 ntohl(big))) {
	  FREE(buf);
	  GE_BREAK(ectx, 0);	
	  goto WARN;
	}
	list
	  = MALLOC(sizeof(FSUI_SearchList));	
	list->uri
	  = ECRS_stringToUri(ectx, buf);
	FREE(buf);
	if (list->uri == NULL) {
	  FREE(list);
	  GE_BREAK(ectx, 0);	
	  goto WARN;
	}
	if (! ECRS_isKeywordUri(list->uri)) {
	  ECRS_freeUri(list->uri);
	  FREE(list);
	  GE_BREAK(ectx, 0);		
	  goto WARN;
	}
	list->numberOfURIKeys
	  = ECRS_countKeywordsOfUri(list->uri);
	if (sizeof(unsigned int) !=
	    READ(fd, &big, sizeof(unsigned int))) {
	  ECRS_freeUri(list->uri);
	  FREE(list);	
	  GE_BREAK(ectx, 0);
	  goto WARN;
	}
	list->anonymityLevel
	  = ntohl(big);
	if (sizeof(unsigned int) !=
	    READ(fd, &big, sizeof(unsigned int))) {
	  ECRS_freeUri(list->uri);
	  FREE(list);
	  GE_BREAK(ectx, 0);
	  goto WARN;
	}
	list->sizeResultsReceived
	  = ntohl(big);
	if (sizeof(unsigned int) !=
	    READ(fd, &big, sizeof(unsigned int))) {
	  ECRS_freeUri(list->uri);
	  FREE(list);
	  GE_BREAK(ectx, 0);
	  goto WARN;
	}
	list->sizeUnmatchedResultsReceived
	  = ntohl(big);
	if ( (list->sizeResultsReceived > 1024*1024) ||
	     (list->sizeUnmatchedResultsReceived > 1024*1024) ) {
	  ECRS_freeUri(list->uri);
	  FREE(list);
	  GE_BREAK(ectx, 0);
	  goto WARN;
	}
	if (list->sizeResultsReceived > 0)
	  list->resultsReceived
	    = MALLOC(list->sizeResultsReceived *
		     sizeof(ECRS_FileInfo));
	else
	  list->resultsReceived
	    = NULL;
	if (list->sizeUnmatchedResultsReceived > 0)
	  list->unmatchedResultsReceived
	    = MALLOC(list->sizeUnmatchedResultsReceived *
		     sizeof(ResultPending));
	else
	  list->unmatchedResultsReceived
	    = NULL;
	for (i=0;i<list->sizeResultsReceived;i++)
	  readFileInfo(ectx,
		       fd,
		       &list->resultsReceived[i]);
	for (i=0;i<list->sizeUnmatchedResultsReceived;i++) {
	  rp = &list->unmatchedResultsReceived[i];
	  readFileInfo(ectx,
		       fd,
		       &rp->fi);
	
	  if (sizeof(unsigned int) !=
	      READ(fd,
		   &big,
		   sizeof(unsigned int))) {
	    GE_BREAK(ectx, 0);
	    goto WARNL;
	  }
	  rp->matchingKeyCount
	    = ntohl(big);
	  if ( (rp->matchingKeyCount > 1024) ||
	       (rp->matchingKeyCount >
		list->numberOfURIKeys) ) {
	    GE_BREAK(ectx, 0);
	    goto WARNL;
	  }
	
	  if (rp->matchingKeyCount > 0)
	    rp->matchingKeys
	      = MALLOC(sizeof(HashCode512) *
		       rp->matchingKeyCount);
	  else
	    rp->matchingKeys
	      = NULL;
	  if (sizeof(HashCode512) *
	      rp->matchingKeyCount !=
	      READ(fd,
		   rp->matchingKeys,
		   sizeof(HashCode512) *
		   rp->matchingKeyCount)) {
	    GE_BREAK(ectx, 0);
	    goto WARNL;
	  }
	}
	
	
	list->signalTerminate
	  = NO;
	list->ctx
	  = ret;
	/* start search thread! */
#if DEBUG_PERSISTENCE
	GE_LOG(ectx, 
	       GE_DEBUG | GE_REQUEST | GE_USER,
	       "FSUI persistence: restarting search\n");
#endif
	list->handle = PTHREAD_CREATE(&searchThread,
				      list,
				      32 * 1024);
	if (list->handle == NULL)
	  GE_DIE_STRERROR(ectx,
			  GE_FATAL | GE_ADMIN | GE_IMMEDIATE,
			  "pthread_create");
	
	/* finally: prepend to list */
	list->next
	  = ret->activeSearches;
	ret->activeSearches
	  = list;
	/* then: signal event handler! */
	event.type = FSUI_search_resuming;
	event.data.SearchResuming.sc.pos = list;
	event.data.SearchResuming.sc.cctx = NULL;
	event.data.SearchResuming.fis = list->resultsReceived;
	event.data.SearchResuming.fisSize = list->sizeResultsReceived;
	event.data.SearchResuming.anonymityLevel = list->anonymityLevel;
	event.data.SearchResuming.searchURI = list->uri;
	list->cctx = cb(closure, &event);	
      }
      memset(&ret->activeDownloads,
	     0,
	     sizeof(FSUI_DownloadList));
      ret->activeDownloads.child
	= readDownloadList(ectx,
			   fd,
			   ret,
			   &ret->activeDownloads);
      doResumeEvents(ret->activeDownloads.child,
		     ret);

      /* deserialize uploads */
      while (1) {
	if (sizeof(unsigned int) !=
	    READ(fd, &big, sizeof(unsigned int))) {
	  GE_BREAK(ectx, 0);
	  goto WARN;
	}
	if (ntohl(big) != 1) 
	  break; /* no more uploads */
	

      }

      /* success, read complete! */
      goto END;
    WARNL:
      for (i=0;i<list->sizeResultsReceived;i++) {
	if (list->resultsReceived[i].uri != NULL)
	  ECRS_freeUri(list->resultsReceived[i].uri);
	if (list->resultsReceived[i].meta != NULL)
	  ECRS_freeMetaData(list->resultsReceived[i].meta);	
      }
      GROW(list->resultsReceived,
	   list->sizeResultsReceived,
	   0);
      for (i=0;i<list->sizeUnmatchedResultsReceived;i++) {
	rp = &list->unmatchedResultsReceived[i];
	
	if (rp->fi.uri != NULL)
	  ECRS_freeUri(rp->fi.uri);
	if (rp->fi.meta != NULL)
	  ECRS_freeMetaData(rp->fi.meta);
	FREENONNULL(rp->matchingKeys);
      }
      GROW(list->resultsReceived,
	   list->sizeResultsReceived,
	   0);
    WARN:
      GE_LOG(ectx, 
	     GE_WARNING | GE_BULK | GE_USER,
	     _("FSUI state file `%s' had syntax error at offset %u.\n"),
	     fn,
	  lseek(fd, 0, SEEK_CUR));
    END:
      CLOSE(fd);
      UNLINK(fn);
    } else {
      if (errno != ENOENT)
	GE_LOG_STRERROR_FILE(ectx,
			     GE_WARNING | GE_BULK | GE_USER,
			     "open",
			     fn);
    }
  } else {
    ret->ipc = NULL;
  }
  ret->lock = MUTEX_CREATE(YES);
  ret->cron = cron_create(ectx);  
  cron_add_job(ret->cron,
	       &updateDownloadThreads,
	       0,
	       FSUI_UDT_FREQUENCY,
	       ret);
  cron_start(ret->cron);
  return ret;
}

/**
 * Stop all processes under FSUI control (serialize state, continue
 * later if possible).
 */
void FSUI_stop(struct FSUI_Context * ctx) {
  struct GE_Context * ectx;
  FSUI_ThreadList * tpos;
  FSUI_SearchList * spos;
  FSUI_DownloadList * dpos;
  FSUI_UnindexList * xpos;
  FSUI_UploadList * upos;
  FSUI_Event event;
  void * unused;
  int i;
  int fd;
  int big;

  ectx = ctx->ectx;
  if (ctx->ipc != NULL)
    GE_LOG(ectx, 
	   GE_INFO | GE_REQUEST | GE_USER,
	   "FSUI shutdown.  This may take a while.\n");

  cron_stop(ctx->cron);
  cron_del_job(ctx->cron,
	       &updateDownloadThreads,
	       FSUI_UDT_FREQUENCY,
	       ctx);
  cron_destroy(ctx->cron);
  /* first, stop all download threads
     by reducing the thread pool size to 0 */
  ctx->threadPoolSize = 0;
  dpos = ctx->activeDownloads.child;
  while (dpos != NULL) {
    updateDownloadThread(dpos);
    dpos = dpos->next;
  }

  /* then, wait for all modal threads to complete */
  while (ctx->activeThreads != NULL) {
    tpos = ctx->activeThreads;
    ctx->activeThreads = tpos->next;
    PTHREAD_JOIN(tpos->handle, &unused);
    FREE(tpos);
  }

  /* next, serialize all of the FSUI state */
  if (ctx->ipc != NULL) {
    fd = disk_file_open(ectx,
			ctx->name,
			O_CREAT|O_TRUNC|O_WRONLY,
			S_IRUSR|S_IWUSR);
    if (fd != -1) {
      WRITE(fd,
	    "FSUI00\n\0",
	    8); /* magic */
    }
#if DEBUG_PERSISTENCE
    GE_LOG(ectx, 
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Serializing FSUI state...\n");
#endif
  } else {
#if DEBUG_PERSISTENCE
    GE_LOG(ectx, 
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "NOT serializing FSUI state...\n");
#endif
    fd = -1;
  }
  if (fd != -1) {
    if (ctx->collectionData == NULL) {
      WRITEINT(fd, 0);
    } else {
      /* serialize collection data */
      WRITE(fd,
	    ctx->collectionData,
	    ntohl(ctx->collectionData->size));
    }
  }
  while (ctx->activeSearches != NULL) {
    spos = ctx->activeSearches;
    ctx->activeSearches = spos->next;

    spos->signalTerminate = YES;
    PTHREAD_STOP_SLEEP(spos->handle);
    PTHREAD_JOIN(spos->handle, &unused);
    if (fd != -1) {
      /* serialize pending searches */
      char * tmp;
      unsigned int big;

      tmp = ECRS_uriToString(spos->uri);
      GE_ASSERT(ectx, tmp != NULL);
      big = htonl(strlen(tmp));
      WRITE(fd,
	    &big,
	    sizeof(unsigned int));
      WRITE(fd,
	    tmp,
	    strlen(tmp));
      FREE(tmp);
      big = htonl(spos->anonymityLevel);
      WRITE(fd,
	    &big,
	    sizeof(unsigned int));
      big = htonl(spos->sizeResultsReceived);
      WRITE(fd,
	    &big,
	    sizeof(unsigned int));
      big = htonl(spos->sizeUnmatchedResultsReceived);
      WRITE(fd,
	    &big,
	    sizeof(unsigned int));
      for (i=0;i<spos->sizeResultsReceived;i++)
	writeFileInfo(ectx,
		      fd,
		      &spos->resultsReceived[i]);
      for (i=0;i<spos->sizeUnmatchedResultsReceived;i++) {
	ResultPending * rp;

	rp = &spos->unmatchedResultsReceived[i];
	writeFileInfo(ectx,
		      fd,
		      &rp->fi);
	big = htonl(rp->matchingKeyCount);
	WRITE(fd,
	      &big,
	      sizeof(unsigned int));
	WRITE(fd,
	      rp->matchingKeys,
	      sizeof(HashCode512) * rp->matchingKeyCount);
      }
      event.type = FSUI_search_suspending;
      event.data.SearchSuspending.sc.pos = spos;
      event.data.SearchSuspending.sc.cctx = spos->cctx;
      ctx->ecb(ctx->ecbClosure, &event);
    }


    ECRS_freeUri(spos->uri);
    for (i=spos->sizeResultsReceived-1;i>=0;i--) {
      ECRS_FileInfo * fi;
      fi = &spos->resultsReceived[i];
      ECRS_freeMetaData(fi->meta);
      ECRS_freeUri(fi->uri);
    }
    GROW(spos->resultsReceived,
	 spos->sizeResultsReceived,
	 0);
    for (i=spos->sizeUnmatchedResultsReceived-1;i>=0;i--) {
      ResultPending * rp;

      rp = &spos->unmatchedResultsReceived[i];
      GROW(rp->matchingKeys,
	   rp->matchingKeyCount,
	   0);
      ECRS_freeMetaData(rp->fi.meta);
      ECRS_freeUri(rp->fi.uri);
    }
    GROW(spos->unmatchedResultsReceived,
	 spos->sizeUnmatchedResultsReceived,
	 0);
    FREE(spos);
  }
  if (fd != -1) {
    /* search list terminator */
    big = htonl(0);
    WRITE(fd,
	  &big,
	  sizeof(unsigned int));
    writeDownloadList(ectx,
		      fd,
		      ctx,
		      ctx->activeDownloads.child);
  }
  while (ctx->unindexOperations != NULL) {
    xpos = ctx->unindexOperations;
    ctx->unindexOperations = xpos->next;
    xpos->force_termination = YES;
    PTHREAD_STOP_SLEEP(xpos->handle);
    PTHREAD_JOIN(xpos->handle, &unused);    
    if (fd != -1) {
      WRITEINT(fd, strlen(xpos->filename));
      WRITE(fd,
	    xpos->filename,
	    strlen(xpos->filename));
      event.type = FSUI_unindex_suspending;
      event.data.UnindexSuspending.uc.pos = xpos;
      event.data.UnindexSuspending.uc.cctx = xpos->cctx;
      ctx->ecb(ctx->ecbClosure, &event);
    }
    FREE(xpos->filename);
  }
  if (fd != -1) {
    /* unindex list terminator */
    big = htonl(0);
    WRITE(fd,
	  &big,
	  sizeof(unsigned int));
  }
  while (ctx->activeUploads != NULL) {
    big = htonl(1);
    WRITE(fd,
	  &big,
	  sizeof(unsigned int));
    upos = ctx->activeUploads;
    ctx->activeUploads = upos->next;
    upos->force_termination = YES;
    PTHREAD_STOP_SLEEP(upos->handle);
    PTHREAD_JOIN(upos->handle, &unused);
    if (fd != -1) {
      WRITEINT(fd, upos->status);
      WRITELONG(fd, upos->main_completed);
      WRITELONG(fd, upos->main_total);
      WRITELONG(fd, upos->expiration);
      WRITELONG(fd, upos->start_time);
      /* dir track!? */
      writeURI(fd, upos->uri);
      writeURI(fd, upos->globalUri); /* need to handle NULL? */
      WRITESTRING(fd, upos->filename);
      WRITESTRING(fd, upos->main_filename);
      WRITEINT(fd, upos->isRecursive);
      WRITEINT(fd, upos->doIndex);
      WRITEINT(fd, upos->anonymityLevel);
      WRITEINT(fd, upos->priority);
      WRITEINT(fd, upos->individualKeywords);
      

      /* FIXME: serialize! */
      event.type = FSUI_upload_suspending;
      event.data.UploadSuspending.uc.pos = upos;
      event.data.UploadSuspending.uc.cctx = upos->cctx;
      event.data.UploadSuspending.uc.ppos = NULL;
      event.data.UploadSuspending.uc.pcctx = NULL;
    }
    FREE(upos->filename);
    FREENONNULL(upos->main_filename);
    ECRS_freeMetaData(upos->meta);
    ECRS_freeUri(upos->uri);
    if (upos->globalUri != NULL)
      ECRS_freeUri(upos->globalUri);
    EXTRACTOR_removeAll(upos->extractors);
    FREE(upos);
  }
  if (fd != -1) {
    /* upload list terminator */
    big = htonl(0);
    WRITE(fd,
	  &big,
	  sizeof(unsigned int));
  }

  if (fd != -1) {
#if DEBUG_PERSISTENCE
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "Serializing FSUI state done.\n");
#endif
    CLOSE(fd);
  }

  /* finally, free all (remaining) FSUI data */
  while (ctx->activeDownloads.child != NULL)
    freeDownloadList(ctx->activeDownloads.child);
  if (ctx->ipc != NULL) {
    IPC_SEMAPHORE_UP(ctx->ipc);
    IPC_SEMAPHORE_DESTROY(ctx->ipc);
  }
  MUTEX_DESTROY(ctx->lock);
  FREE(ctx->name);
  FREE(ctx);
  if (ctx->ipc != NULL)
    GE_LOG(ectx,
	   GE_INFO | GE_REQUEST | GE_USER,
	   "FSUI shutdown complete.\n");
}


/* *************** internal helper functions *********** */

/**
 * The idea for this function is to clean up
 * the FSUI structs by freeing up dead entries.
 */
void cleanupFSUIThreadList(FSUI_Context * ctx) {
  FSUI_ThreadList * pos;
  FSUI_ThreadList * tmp;
  FSUI_ThreadList * prev;
  void * unused;

  prev = NULL;
  MUTEX_LOCK(ctx->lock);
  pos = ctx->activeThreads;
  while (pos != NULL) {
    if (YES == pos->isDone) {
      PTHREAD_JOIN(pos->handle,
		   &unused);
      tmp = pos->next;
      FREE(pos);
      if (prev != NULL)
	prev->next = tmp;
      else
	ctx->activeThreads = tmp;
      pos = tmp;
    } else {
      prev = pos;
      pos = pos->next;
    }
  }
  MUTEX_UNLOCK(ctx->lock);
}


/* end of fsui.c */
