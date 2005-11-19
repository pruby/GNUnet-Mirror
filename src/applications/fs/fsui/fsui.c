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
 * @file applications/fs/fsui/fsui.c
 * @brief main FSUI functions
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
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

static struct ECRS_URI * readURI(int fd) {
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
  ret = ECRS_stringToUri(buf);
  FREE(buf);
  return ret;
 ERR:
  return NULL;
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
static FSUI_DownloadList * readDownloadList(int fd,
					    FSUI_Context * ctx,
					    FSUI_DownloadList * parent) {
  char zaro;
  FSUI_DownloadList * ret;
  unsigned int big;
  unsigned long long bigl;
  int i;
  int ok;

  GNUNET_ASSERT(ctx != NULL);
  if (1 != READ(fd, &zaro, sizeof(char))) {
    BREAK();
    return NULL;
  }
  if (zaro == '\0')
    return NULL;
  ret = MALLOC(sizeof(FSUI_DownloadList));
  memset(ret,
	 0,
	 sizeof(FSUI_DownloadList));
  ret->ctx = ctx;

  ret->signalTerminate
    = SYSERR;
  READINT(ret->is_recursive);
  READINT(ret->is_directory);
  READINT(ret->anonymityLevel);
  READINT(ret->completedDownloadsCount);
  READINT(ret->finished);
  READINT(big);
  if (big > 1024 * 1024) {
    BREAK();
    goto ERR;
  }
  ret->filename = MALLOC(big+1);
  if (big != READ(fd, ret->filename, big)) {
    BREAK();
    goto ERR;
  }
  ret->filename[big] = '\0';
  READLONG(ret->total);
  READLONG(ret->completed);
  ret->completedFile = 0;
  READLONG(ret->startTime);
  ret->startTime = cronTime(NULL) - ret->startTime;
  ret->uri
    = readURI(fd);
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
      = readURI(fd);
    if (ret->completedDownloads[i] == NULL)
      ok = NO;
  }
  if (NO == ok) {
    BREAK();
    goto ERR;
  }
  ret->parent = parent;
  ret->signalTerminate = SYSERR;
  ret->next = readDownloadList(fd,
			       ctx,
			       parent);
  ret->child = readDownloadList(fd,
				ctx,
				ret);
#if DEBUG_PERSISTENCE
  LOG(LOG_DEBUG,
      "FSUI persistence: restoring download `%s': %s (%llu, %llu)\n",
      ret->filename,
      ret->finished == YES ? "finished" : "pending",
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
  LOG(LOG_WARNING,
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

/**
 * (recursively) write a download list.
 */
static void writeDownloadList(int fd,
			      const FSUI_DownloadList * list) {
  static char zero = '\0';
  static char nonzero = '+';
  int i;

  if (list == NULL) {
    WRITE(fd, &zero, sizeof(char));
    return;
  }
#if DEBUG_PERSISTENCE
  LOG(LOG_DEBUG,
      "Serializing download state of download `%s': %s (%llu, %llu)\n",
      list->filename,
      list->finished == YES ? "finished" : "pending",
      list->completed,
      list->total);
#endif
  WRITE(fd, &nonzero, sizeof(char));

  WRITEINT(fd, list->is_recursive);
  WRITEINT(fd, list->is_directory);
  WRITEINT(fd, list->anonymityLevel);
  WRITEINT(fd, list->completedDownloadsCount);
  WRITEINT(fd, list->finished);
  WRITEINT(fd, strlen(list->filename));
  WRITE(fd,
	list->filename,
	strlen(list->filename));
  WRITELONG(fd, list->total);
  WRITELONG(fd, list->completed);
  WRITELONG(fd, cronTime(NULL) - list->startTime);
  writeURI(fd, list->uri);
  for (i=0;i<list->completedDownloadsCount;i++)
    writeURI(fd, list->completedDownloads[i]);

  writeDownloadList(fd,
		    list->next);
  writeDownloadList(fd,
		    list->child);
}

/**
 * Read file info from file.
 *
 * @return OK on success, SYSERR on error
 */
static int readFileInfo(int fd,
			ECRS_FileInfo * fi) {
  unsigned int size;
  unsigned int big;
  char * buf;

  fi->meta = NULL;
  fi->uri = NULL;
  if (sizeof(unsigned int) !=
      READ(fd,
	   &big,
	   sizeof(unsigned int))) {
    BREAK();
    return SYSERR;
  }
  size = ntohl(big);
  buf = MALLOC(size);
  if (size != READ(fd,
		   buf,
		   size)) {
    FREE(buf);
    BREAK();
    return SYSERR;
  }
  fi->meta = ECRS_deserializeMetaData(buf,
				      size);
  if (fi->meta == NULL) {
    FREE(buf);
    BREAK();
    return SYSERR;
  }
  FREE(buf);

  fi->uri
    = readURI(fd);
  if (fi->uri == NULL) {
    ECRS_freeMetaData(fi->meta);
    fi->meta = NULL;
    BREAK();
    return SYSERR;
  }
  return OK;
}

static void writeFileInfo(int fd,
			  const ECRS_FileInfo * fi) {
  unsigned int size;
  unsigned int big;
  char * buf;

  size = ECRS_sizeofMetaData(fi->meta);
  buf = MALLOC(size);
  ECRS_serializeMetaData(fi->meta,
			 buf,
			 size,
			 NO);
  big = htonl(size);
  WRITE(fd,
	&big,
	sizeof(unsigned int));
  WRITE(fd,
	buf,
	size);
  FREE(buf);
  writeURI(fd, fi->uri);
}

static void updateDownloadThreads(void * c) {
  FSUI_Context * ctx = c;
  FSUI_DownloadList * dpos;

  MUTEX_LOCK(&ctx->lock);
  dpos = ctx->activeDownloads.child;
#if DEBUG_PERSISTENCE
  if (dpos != NULL)
    LOG(LOG_DEBUG,
	"Download thread manager schedules pending downloads...\n");
#endif
  while (dpos != NULL) {
    updateDownloadThread(dpos);
    dpos = dpos->next;
  }
  MUTEX_UNLOCK(&ctx->lock);
}

/**
 * Start FSUI manager.  Use the given progress callback to notify the
 * UI about events.  Start processing pending activities that were
 * running when FSUI_stop was called previously.
 *
 * @param name name of the context, must not be NULL
 * @return NULL on error
 */
struct FSUI_Context * FSUI_start(const char * name,
				 int doResume,
				 FSUI_EventCallback cb,
				 void * closure) {
  FSUI_Context * ret;
  FSUI_SearchList * list;
  ResultPending * rp;
  char * fn;
  char * gh;
  int fd;
  int i;

  ret = MALLOC(sizeof(FSUI_Context));
  memset(ret, 0, sizeof(FSUI_Context));
  ret->activeDownloads.signalTerminate
    = SYSERR;
  ret->activeDownloads.ctx
    = ret;
  gh = getFileName("GNUNET",
		   "GNUNET_HOME",
		   "You must specify a directory for "
		   "user-data under '%s%s' at the beginning"
		   " of the configuration file.\n");
  fn = MALLOC(strlen(gh) + strlen(name) + 2 + 5);
  strcpy(fn, gh);
  FREE(gh);
  strcat(fn, DIR_SEPARATOR_STR);
  strcat(fn, name);
  ret->name = fn;
  if (doResume) {
    ret->ipc = IPC_SEMAPHORE_NEW(fn,
				 1);
    LOG(LOG_INFO,
	"Getting IPC lock for FSUI (%s).\n",
	fn);
    IPC_SEMAPHORE_DOWN(ret->ipc);
    LOG(LOG_INFO,
	"Aquired IPC lock.\n");
    fd = -1;
    strcat(fn, ".res");
    if (0 == ACCESS(fn, R_OK))
      fd = fileopen(fn, O_RDONLY);
    if (fd != -1) {
      char magic[8];
      unsigned int big;

      /* ****** check magic ******* */
      if (8 != READ(fd, magic, 8)) {
	BREAK();
	goto WARN;
      }
      if (0 != memcmp(magic,
		      "FSUI00\n\0",
		      8)) {
	BREAK();
	goto WARN;
      }
      /* ******* deserialize state **** */

      /* deserialize collection data */
      if (sizeof(unsigned int) !=
	  READ(fd, &big, sizeof(unsigned int))) {
	BREAK();
	goto WARN;
      }
      if (ntohl(big) > 16 * 1024 * 1024) {
	BREAK();
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
	  BREAK();
	  goto WARN;
	}
      }

      /* deserialize pending searches! */
      while (1) {
	char * buf;

	if (sizeof(unsigned int) !=
	    READ(fd, &big, sizeof(unsigned int))) {
	  BREAK();	
	  goto WARN;
	}
	if (ntohl(big) == 0)
	  break;
	if (ntohl(big) > 1024 * 1024) {
	  BREAK();	
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
	  BREAK();	
	  goto WARN;
	}
	list
	  = MALLOC(sizeof(FSUI_SearchList));
	list->uri
	  = ECRS_stringToUri(buf);
	FREE(buf);
	if (list->uri == NULL) {
	  FREE(list);
	  BREAK();	
	  goto WARN;
	}
	if (! ECRS_isKeywordUri(list->uri)) {
	  ECRS_freeUri(list->uri);
	  FREE(list);
	  BREAK();		
	  goto WARN;
	}
	list->numberOfURIKeys
	  = ECRS_countKeywordsOfUri(list->uri);
	if (sizeof(unsigned int) !=
	    READ(fd, &big, sizeof(unsigned int))) {
	  ECRS_freeUri(list->uri);
	  FREE(list);	
	  BREAK();
	  goto WARN;
	}
	list->anonymityLevel
	  = ntohl(big);
	if (sizeof(unsigned int) !=
	    READ(fd, &big, sizeof(unsigned int))) {
	  ECRS_freeUri(list->uri);
	  FREE(list);
	  BREAK();
	  goto WARN;
	}
	list->sizeResultsReceived
	  = ntohl(big);
	if (sizeof(unsigned int) !=
	    READ(fd, &big, sizeof(unsigned int))) {
	  ECRS_freeUri(list->uri);
	  FREE(list);
	  BREAK();
	  goto WARN;
	}
	list->sizeUnmatchedResultsReceived
	  = ntohl(big);
	if ( (list->sizeResultsReceived > 1024*1024) ||
	     (list->sizeUnmatchedResultsReceived > 1024*1024) ) {
	  ECRS_freeUri(list->uri);
	  FREE(list);
	  BREAK();
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
	  readFileInfo(fd,
		       &list->resultsReceived[i]);
	for (i=0;i<list->sizeUnmatchedResultsReceived;i++) {
	  rp = &list->unmatchedResultsReceived[i];
	  readFileInfo(fd,
		       &rp->fi);
	
	  if (sizeof(unsigned int) !=
	      READ(fd,
		   &big,
		   sizeof(unsigned int))) {
	    BREAK();
	    goto WARNL;
	  }
	  rp->matchingKeyCount
	    = ntohl(big);
	  if ( (rp->matchingKeyCount > 1024) ||
	       (rp->matchingKeyCount >
		list->numberOfURIKeys) ) {
	    BREAK();
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
	    BREAK();
	    goto WARNL;
	  }
	}
	
	
	list->signalTerminate
	  = NO;
	list->ctx
	  = ret;
	/* start search thread! */
#if DEBUG_PERSISTENCE
	LOG(LOG_DEBUG,
	    "FSUI persistence: restarting search\n");
#endif
	if (0 != PTHREAD_CREATE(&list->handle,
				(PThreadMain)&searchThread,
				list,
				16 * 1024))
	  DIE_STRERROR("pthread_create");
	
	/* finally: prepend to list */
	list->next
	  = ret->activeSearches;
	ret->activeSearches
	  = list;
      }
      memset(&ret->activeDownloads,
	     0,
	     sizeof(FSUI_DownloadList));
      ret->activeDownloads.child
	= readDownloadList(fd,
			   ret,
			   &ret->activeDownloads);

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
      LOG(LOG_WARNING,
	  _("FSUI state file `%s' had syntax error at offset %u.\n"),
	  fn,
	  lseek(fd, 0, SEEK_CUR));
    END:
      CLOSE(fd);
      UNLINK(fn);
    } else {
      if (errno != ENOENT)
	LOG_FILE_STRERROR(LOG_ERROR,
			  "open",
			  fn);
    }
  } else {
    ret->ipc = NULL;
  }
  MUTEX_CREATE_RECURSIVE(&ret->lock);
  ret->ecb = cb;
  ret->ecbClosure = closure;
  ret->threadPoolSize = getConfigurationInt("FS",
					    "DOWNLOAD-POOL");
  if (ret->threadPoolSize == 0)
    ret->threadPoolSize = 32;
  ret->activeDownloadThreads = 0;
  addCronJob(&updateDownloadThreads,
	     0,
	     FSUI_UDT_FREQUENCY,
	     ret);
  return ret;
}

/**
 * Stop all processes under FSUI control (serialize state, continue
 * later if possible).
 */
void FSUI_stop(struct FSUI_Context * ctx) {
  FSUI_ThreadList * tpos;
  FSUI_SearchList * spos;
  FSUI_DownloadList * dpos;
  void * unused;
  int i;
  int fd;
  int big;

  LOG(LOG_INFO,
      "FSUI shutdown.  This may take a while.\n");
  FSUI_publishCollectionNow(ctx);

  i = isCronRunning();
  if (i)
    suspendCron();
  delCronJob(&updateDownloadThreads,
	     FSUI_UDT_FREQUENCY,
	     ctx);
  if (i)
    resumeCron();
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
    PTHREAD_JOIN(&tpos->handle, &unused);
    FREE(tpos);
  }

  /* next, serialize all of the FSUI state */
  if (ctx->ipc != NULL) {
    fd = fileopen(ctx->name,
		  O_CREAT|O_TRUNC|O_WRONLY,
		  S_IRUSR|S_IWUSR);
    if (fd == -1) {
      LOG_FILE_STRERROR(LOG_ERROR,
			"open",
			ctx->name);
    } else {
      WRITE(fd,
	    "FSUI00\n\0",
	    8); /* magic */
    }
#if DEBUG_PERSISTENCE
    LOG(LOG_DEBUG,
	"Serializing FSUI state...\n");
#endif
  } else {
#if DEBUG_PERSISTENCE
    LOG(LOG_DEBUG,
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
    PTHREAD_JOIN(&spos->handle, &unused);
    if (fd != -1) {
      /* serialize pending searches */
      char * tmp;
      unsigned int big;

      tmp = ECRS_uriToString(spos->uri);
      GNUNET_ASSERT(tmp != NULL);
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
	writeFileInfo(fd,
		      &spos->resultsReceived[i]);
      for (i=0;i<spos->sizeUnmatchedResultsReceived;i++) {
	ResultPending * rp;

	rp = &spos->unmatchedResultsReceived[i];
	writeFileInfo(fd,
		      &rp->fi);
	big = htonl(rp->matchingKeyCount);
	WRITE(fd,
	      &big,
	      sizeof(unsigned int));
	WRITE(fd,
	      rp->matchingKeys,
	      sizeof(HashCode512) * rp->matchingKeyCount);
      }
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
    writeDownloadList(fd,
		      ctx->activeDownloads.child);
  }
  if (fd != -1) {
#if DEBUG_PERSISTENCE
    LOG(LOG_DEBUG,
	"Serializing FSUI state done.\n");
#endif
    CLOSE(fd);
  }

  /* finally, free all (remaining) FSUI data */
  while (ctx->activeDownloads.child != NULL)
    freeDownloadList(ctx->activeDownloads.child);
  if (ctx->ipc != NULL) {
    IPC_SEMAPHORE_UP(ctx->ipc);
    IPC_SEMAPHORE_FREE(ctx->ipc);
  }
  MUTEX_DESTROY(&ctx->lock);
  FREE(ctx->name);
  FREE(ctx);
  LOG(LOG_INFO,
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
  MUTEX_LOCK(&ctx->lock);
  pos = ctx->activeThreads;
  while (pos != NULL) {
    if (YES == pos->isDone) {
      PTHREAD_JOIN(&pos->handle,
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
  MUTEX_UNLOCK(&ctx->lock);
}


/* end of fsui.c */
