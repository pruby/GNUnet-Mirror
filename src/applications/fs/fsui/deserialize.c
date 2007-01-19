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
 * @file applications/fs/fsui/deserializer.c
 * @brief FSUI functions for reading state from disk
 * @author Christian Grothoff
 * @see serializer.c
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_directories.h"
#include "fsui.h"


static int read_int(int fd,
		    int * val) {
  int big;

  if (sizeof(int) != READ(fd, &big, sizeof(int))) \
    return SYSERR;				  \
  *val = ntohl(big);
  return OK;
}

#define READINT(a) if (OK != read_int(fd, (int*) &a)) return SYSERR;

static int read_long(int fd,
		     long long * val) {
  long long big;

  if (sizeof(long long) != READ(fd, &big, sizeof(long long))) \
    return SYSERR;				  \
  *val = ntohll(big);
  return OK;
}

#define READLONG(a) if (OK != read_long(fd, (long long*) &a)) return SYSERR;

static struct ECRS_URI * read_uri(struct GE_Context * ectx,
				  int fd) {
  char * buf;
  struct ECRS_URI * ret;
  unsigned int size;

  if (OK != read_int(fd, (int*) &size))
    return NULL;
  buf = MALLOC(size+1);
  buf[size] = '\0';
  if (size != READ(fd,
		   buf,
		   size)) {
    FREE(buf);
    return NULL;
  }
  ret = ECRS_stringToUri(ectx, buf);
  GE_BREAK(ectx, ret != NULL);
  FREE(buf);
  return ret;
}

#define READURI(u) if (NULL == (u = read_uri(ectx, fd))) return SYSERR;

static char * read_string(int fd,
			  unsigned int maxLen) {
  char * buf;
  unsigned int big;

  if (OK != read_int(fd, (int*) &big))
    return NULL;
  if (big > maxLen)
    return NULL;
  buf = MALLOC(big + 1);
  buf[big] = '\0';
  if (big != READ(fd, buf, big)) {
    FREE(buf);
    return NULL;
  }
  return buf;
}

#define READSTRING(c, max) if (NULL == (c = read_string(fd, max))) return SYSERR;

static void fixState(FSUI_State * state) {
  switch (*state) { /* try to correct errors */
  case FSUI_ACTIVE:
    *state = FSUI_PENDING;
    break;
  case FSUI_PENDING:
  case FSUI_COMPLETED_JOINED:
  case FSUI_ABORTED_JOINED:
  case FSUI_ERROR_JOINED:
    break;
  case FSUI_ERROR:
    *state = FSUI_ERROR_JOINED;
    break;
  case FSUI_ABORTED:
    *state = FSUI_ABORTED_JOINED;
    break;
  case FSUI_COMPLETED:
    *state = FSUI_COMPLETED_JOINED;
    break;
  default:
    *state = FSUI_ERROR_JOINED;
    break;
  }
}


/**
 * Read file info from file.
 *
 * @return OK on success, SYSERR on error
 */
static struct ECRS_MetaData *
read_meta(struct GE_Context * ectx,
	  int fd) {
  unsigned int size;
  char * buf;
  struct ECRS_MetaData * meta;

  if (read_int(fd, (int*)&size) != OK) {
    GE_BREAK(ectx, 0);
    return NULL;
  }
  if (size > 1024 * 1024) {
    GE_BREAK(ectx, 0);
    return NULL;
  }
  buf = MALLOC(size);
  if (size != READ(fd,
		   buf,
		   size)) {
    FREE(buf);
    GE_BREAK(ectx, 0);
    return NULL;
  }
  meta = ECRS_deserializeMetaData(ectx,
				  buf,
				  size);
  if (meta == NULL) {
    FREE(buf);
    GE_BREAK(ectx, 0);
    return NULL;
  }
  FREE(buf);
  return meta;
}

/**
 * Read file info from file.
 *
 * @return OK on success, SYSERR on error
 */
static int readFileInfo(struct GE_Context * ectx,
			int fd,
			ECRS_FileInfo * fi) {
  fi->meta = read_meta(ectx, fd);
  if (fi->meta == NULL) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  fi->uri = NULL;

  fi->uri
    = read_uri(ectx, fd);
  if (fi->uri == NULL) {
    ECRS_freeMetaData(fi->meta);
    fi->meta = NULL;
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  return OK;
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
static FSUI_DownloadList *
readDownloadList(struct GE_Context * ectx,
		 int fd,
		 FSUI_Context * ctx,
		 FSUI_DownloadList * parent) {
  FSUI_DownloadList * ret;
  FSUI_SearchList * pos;
  unsigned int big;
  int i;
  int ok;
  int soff;

  GE_ASSERT(ectx, ctx != NULL);
  if ( (OK != read_int(fd, (int*) &big)) ||
       (big == 0) )
    return NULL;
  ret = MALLOC(sizeof(FSUI_DownloadList));
  memset(ret,
	 0,
	 sizeof(FSUI_DownloadList));
  ret->ctx = ctx;
  if ( (OK != read_int(fd, (int*) &soff)) ||
       (OK != read_int(fd, (int*) &ret->state)) ||
       (OK != read_int(fd, (int*) &ret->is_recursive)) ||
       (OK != read_int(fd, (int*) &ret->is_directory)) ||
       (OK != read_int(fd, (int*) &ret->anonymityLevel)) ||
       (OK != read_int(fd, (int*) &ret->completedDownloadsCount)) ||
       (OK != read_long(fd, (long long*) &ret->total)) ||
       (OK != read_long(fd, (long long*) &ret->completed)) ||
       (OK != read_long(fd, (long long*) &ret->runTime)) ||
       (OK != read_int(fd, (int*) &big)) ||
       (big > 1024 * 1024) ) {
    GE_BREAK(NULL, 0);
    FREE(ret);
    return NULL;
  }
  fixState(&ret->state);
  ret->filename = MALLOC(big+1);
  ret->filename[big] = '\0';
  if (big != READ(fd, ret->filename, big)) {
    GE_BREAK(ectx, 0);
    FREE(ret->filename);
    FREE(ret);
    return NULL;
  }
  if (OK != readFileInfo(ectx,
			 fd,
			 &ret->fi)) {
    GE_BREAK(NULL, 0);
    FREE(ret->filename);
    FREE(ret);
    return NULL;
  }
  if (ret->completedDownloadsCount > 0)
    ret->completedDownloads
      = MALLOC(sizeof(struct ECRS_URI *) *
	       ret->completedDownloadsCount);
  ok = YES;
  for (i=0;i<ret->completedDownloadsCount;i++) {
    ret->completedDownloads[i] = read_uri(ectx, fd);
    if (ret->completedDownloads[i] == NULL) {
      GE_BREAK(NULL, 0);
      ok = NO;
    }
  }
  if (NO == ok) {
    FREE(ret->filename);
    ECRS_freeUri(ret->fi.uri);
    ECRS_freeMetaData(ret->fi.meta);
    for (i=0;i<ret->completedDownloadsCount;i++) {
      if (ret->completedDownloads[i] != NULL)
	ECRS_freeUri(ret->completedDownloads[i]);
    }
    FREE(ret->completedDownloads);
    FREE(ret);
    GE_BREAK(NULL, 0);
    return NULL;
  }
  ret->parent = parent;
  if (soff == 0) {
    ret->search = NULL;
  } else {
    pos = ctx->activeSearches;
    while (--soff > 0) {
      if (pos == NULL) {
	GE_BREAK(NULL, 0);
	break;
      }
      pos = pos->next;
    }
    ret->search = pos;
    if (pos != NULL) {
      GROW(pos->my_downloads,
	   pos->my_downloads_size,
	   pos->my_downloads_size + 1);
      pos->my_downloads[pos->my_downloads_size -1] = ret;
    }
  }
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
}

static int checkMagic(int fd) {
  char magic[8];

  if (8 != READ(fd, magic, 8)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  if (0 != memcmp(magic,
		  "FSUI01\n\0",
		  8)) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  return OK;
}

static int readCollection(int fd,
			  struct FSUI_Context * ctx) {
  int big;

  /* deserialize collection data */
  READINT(big);
  if (big == 0) {
    ctx->collectionData = NULL;
    return OK;
  }
  if ( (big > 16 * 1024 * 1024) ||
       (big < sizeof(unsigned int) ) ) {
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  ctx->collectionData
    = MALLOC(big);
  if (big - sizeof(unsigned int) !=
      READ(fd,
	   &ctx->collectionData[1],
	   big - sizeof(unsigned int))) {
    FREE(ctx->collectionData);
    ctx->collectionData = NULL;
    GE_BREAK(NULL, 0);
    return SYSERR;
  }
  return OK;
}

static int readSearches(int fd,
			struct FSUI_Context * ctx) {
  int big;
  FSUI_SearchList * list;
  FSUI_SearchList * last;
  int i;
  ResultPending * rp;
  char * buf;
  cron_t stime;

  while (1) {
    READINT(big);
    if (big == 0)
      return OK;
    list
      = MALLOC(sizeof(FSUI_SearchList));	
    memset(list,
	   0,
	   sizeof(FSUI_SearchList));
    if ( (OK != read_int(fd, (int*) &list->state)) ||
	 (OK != read_int(fd, (int*) &list->maxResults)) ||
	 (OK != read_long(fd, (long long*) &list->timeout)) ||
	 (OK != read_long(fd, (long long*) &list->start_time)) ||
	 (OK != read_long(fd, (long long*) &stime)) ||
	 (OK != read_int(fd, (int*) &list->anonymityLevel)) ||
	 (OK != read_int(fd, (int*) &list->sizeResultsReceived)) ||
	 (OK != read_int(fd, (int*) &list->sizeUnmatchedResultsReceived)) ||
	 (list->sizeResultsReceived > 1024*1024) ||	
	 (list->sizeUnmatchedResultsReceived > 1024*1024) ) {
      GE_BREAK(NULL, 0);	
      break;
    }
    fixState(&list->state);
    if (stime > get_time())
      stime = get_time();
    list->start_time += get_time() - stime;
    buf = read_string(fd, 1024 * 1024);
    if (buf == NULL) {
       GE_BREAK(NULL, 0);
       break;
    }
    list->uri
      = ECRS_stringToUri(NULL, buf);
    FREE(buf);
    if (list->uri == NULL) {
      GE_BREAK(NULL, 0);
      break;
    }
    if (! ECRS_isKeywordUri(list->uri)) {
      GE_BREAK(NULL, 0);		
      break;
    }
    list->numberOfURIKeys
      = ECRS_countKeywordsOfUri(list->uri);
    if (list->sizeResultsReceived > 0) {
      list->resultsReceived
	= MALLOC(list->sizeResultsReceived *
		 sizeof(ECRS_FileInfo));
      memset(list->resultsReceived,
	     0,
	     list->sizeResultsReceived *
	     sizeof(ECRS_FileInfo));
    }
    if (list->sizeUnmatchedResultsReceived > 0) {
      list->unmatchedResultsReceived
	= MALLOC(list->sizeUnmatchedResultsReceived *
		 sizeof(ResultPending));
      memset(list->unmatchedResultsReceived,
	     0,
	     list->sizeUnmatchedResultsReceived *
	     sizeof(ResultPending));	
    }
    for (i=0;i<list->sizeResultsReceived;i++)
      if (OK != readFileInfo(ctx->ectx,
			     fd,
			     &list->resultsReceived[i])) {
	GE_BREAK(NULL, 0);
	goto ERR;
      }
    for (i=0;i<list->sizeUnmatchedResultsReceived;i++) {
      rp = &list->unmatchedResultsReceived[i];
      if (OK != readFileInfo(ctx->ectx,
			     fd,
			     &rp->fi)) {
	GE_BREAK(NULL, 0);	
	goto ERR;
      }
      if (OK != read_int(fd, (int*) &rp->matchingKeyCount)) {
	GE_BREAK(NULL, 0);	
	goto ERR;
      }
      if ( (rp->matchingKeyCount > 1024) ||
	   (rp->matchingKeyCount >= list->numberOfURIKeys) ) {
	GE_BREAK(NULL, 0);	
	goto ERR;
      }
      if (rp->matchingKeyCount > 0) {
	rp->matchingKeys
	  = MALLOC(sizeof(HashCode512) *
		   rp->matchingKeyCount);
	if (sizeof(HashCode512) *
	    rp->matchingKeyCount !=
	    READ(fd,
		 rp->matchingKeys,
		 sizeof(HashCode512) *
		 rp->matchingKeyCount)) {
	  GE_BREAK(NULL, 0);
	  goto ERR;
	}
      }
    }	
    list->ctx
      = ctx;
    list->next
      = NULL;
    /* finally: append (!) to list */

    if (ctx->activeSearches == NULL) {
      ctx->activeSearches = list;
    } else {
      last = ctx->activeSearches;
      while (last->next != NULL)
	last = last->next;
      last->next = list;
    }
  } /* end OUTER: 'while(1)' */
 ERR:
  /* error - deallocate 'list' */
  if (list->resultsReceived != NULL) {
    for (i=0;i<list->sizeResultsReceived;i++) {
      if (list->resultsReceived[i].uri != NULL)
	ECRS_freeUri(list->resultsReceived[i].uri);
      if (list->resultsReceived[i].meta != NULL)
	ECRS_freeMetaData(list->resultsReceived[i].meta);	
    }
    GROW(list->resultsReceived,
	 list->sizeResultsReceived,
	 0);
  }
  if (list->unmatchedResultsReceived != NULL) {
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
  }
  if (list->uri != NULL)
    ECRS_freeUri(list->uri);
  FREE(list);
  return SYSERR;
}

static int readDownloads(int fd,
			 struct FSUI_Context * ctx) {
  memset(&ctx->activeDownloads,
	 0,
	 sizeof(FSUI_DownloadList));
  ctx->activeDownloads.child
    = readDownloadList(ctx->ectx,
		       fd,
		       ctx,
		       &ctx->activeDownloads);
  return OK;
}

static int readUploadList(struct FSUI_Context * ctx,
			  struct FSUI_UploadList * parent,
			  int fd,
			  struct FSUI_UploadShared * shared,
			  int top) {
  struct FSUI_UploadList * list;
  struct FSUI_UploadList l;
  unsigned long long stime;
  int big;
  int bag;
  struct GE_Context * ectx;

  ectx = ctx->ectx;
  GE_ASSERT(ectx, shared != NULL);
  while (1) {
    READINT(big);
    if (big == 0)
      return OK;
    if ( (big < 1) || (big > 15) ) {
      GE_BREAK(NULL, 0);
      return SYSERR;
    }
    READINT(bag);
    if (bag != 0x34D1F023) {
      GE_BREAK(NULL, 0);
      return SYSERR;
    }
    memset(&l,
	   0,
	   sizeof(FSUI_UploadList));
    READINT(l.state);
    fixState(&l.state);
    if (l.state == FSUI_PENDING)
      l.state = FSUI_ACTIVE;
    READLONG(l.completed);
    READLONG(l.total);
    READLONG(stime);
    if (stime < get_time())
      stime = get_time();
    READLONG(l.start_time);
    if (l.start_time != 0)
      l.start_time = (get_time() - stime) + l.start_time;
    l.uri = NULL;
    if ( (big & 2) == 2)
      READURI(l.uri);
    if ( (big & 4) == 4) {
      l.keywords = read_uri(ctx->ectx, fd);
      if (l.keywords == NULL) {
	if (l.uri != NULL)
	  ECRS_freeUri(l.uri);
	GE_BREAK(NULL, 0);
	break;
      }
    }
    if ( (big & 8) == 8) {
      l.meta = read_meta(ctx->ectx, fd);
      if (l.meta == NULL) {
	if (l.uri != NULL)
	  ECRS_freeUri(l.uri);
	if (l.keywords != NULL)
	  ECRS_freeUri(l.keywords);
	GE_BREAK(NULL, 0);
	break;
      }
    }
    l.filename = read_string(fd, 1024*1024);
    if (l.filename == NULL) {
      if (l.uri != NULL)
	ECRS_freeUri(l.uri);
      if (l.meta != NULL)
	ECRS_freeMetaData(l.meta);
      if (l.keywords != NULL)
	ECRS_freeUri(l.keywords);
      GE_BREAK(NULL, 0);
      break;
    }
    list = MALLOC(sizeof(struct FSUI_UploadList));
    memcpy(list,
	   &l,
	   sizeof(struct FSUI_UploadList));
    list->shared = shared;
    list->parent = parent;
    if (OK != readUploadList(ctx,
			     list,
			     fd,
			     shared,
			     NO)) {
      if (l.uri != NULL)
	ECRS_freeUri(l.uri);
      FREE(l.filename);
      FREE(list);
      GE_BREAK(NULL, 0);
      break;
    }
    list->next = parent->child;
    parent->child = list;
    if (top == YES)
      return OK;
  }
  return SYSERR;
}


static int readUploads(int fd,
		       struct FSUI_Context * ctx) {
  int big;
  int bag;
  struct FSUI_UploadShared * shared;
  struct FSUI_UploadShared sshared;

  memset(&ctx->activeUploads,
	 0,
	 sizeof(FSUI_UploadList));
  while (1) {
    READINT(big);
    if (big == 0)
      return OK;
    if ( (big < 1) && (big > 7) ) {
      GE_BREAK(NULL, 0);
      break;
    }
    READINT(bag);
    if (bag != 0x44D1F024) {
      GE_BREAK(NULL, 0);
      return SYSERR;
    }
    memset(&sshared,
	   0,
	   sizeof(FSUI_UploadShared));
    READINT(sshared.doIndex);
    READINT(sshared.anonymityLevel);
    READINT(sshared.priority);
    READINT(sshared.individualKeywords);
    READLONG(sshared.expiration);
    if ((big & 2) == 2)
      READSTRING(sshared.extractor_config, 1024*1024);
    if ((big & 4) == 4) {
      sshared.global_keywords = read_uri(ctx->ectx, fd);
      if (sshared.global_keywords == NULL) {
	FREENONNULL(sshared.extractor_config);
	GE_BREAK(NULL, 0);
	return SYSERR;
      }
    }
    shared = MALLOC(sizeof(FSUI_UploadShared));
    memcpy(shared,
	   &sshared,
	   sizeof(FSUI_UploadShared));
    shared->ctx = ctx;
    if (OK != readUploadList(ctx,
			     &ctx->activeUploads,
			     fd,
			     shared,
			     YES)) {
      GE_BREAK(NULL, 0);
#if 0
      /* cannot do this, readUploadList
	 may have added *some* uploads that
	 still reference shared -- need to
	 find and cleanup those first,
	 or at least detect their presence
	 and not free */
      FREE(shared->extractor_config);
      FREE(shared);
#endif
      break;
    }
  }
  return SYSERR;
}

static int readUnindex(int fd,
		       struct FSUI_Context * ctx) {
  int big;
  char * name;
  struct FSUI_UnindexList * ul;

  while (1) {
    READINT(big);
    if (big != 1)
      return OK;
    READINT(big); /* state */
    READSTRING(name, 1024 * 1024);
    ul = MALLOC(sizeof(struct FSUI_UnindexList));
    ul->state = big;
    ul->filename = name;
    ul->next = ctx->unindexOperations;
    ul->ctx = ctx;
    ctx->unindexOperations = ul;
  }
  return SYSERR;
}


void FSUI_deserialize(struct FSUI_Context * ctx) {
  int fd;

  fd = -1;
  if (0 != ACCESS(ctx->name, R_OK))
    return;
  fd = disk_file_open(ctx->ectx,
		      ctx->name,
		      O_RDONLY);
  if (fd == -1)
    return;

  if ( (OK != checkMagic(fd)) ||
       (OK != readCollection(fd, ctx) ) ||
       (OK != readSearches(fd, ctx) ) ||
       (OK != readDownloads(fd, ctx) ) ||
       (OK != readUnindex(fd, ctx) ) ||
       (OK != readUploads(fd, ctx) ) ) {
    GE_BREAK(ctx->ectx, 0);
    GE_LOG(ctx->ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("FSUI state file `%s' had syntax error at offset %u.\n"),
	   ctx->name,
	   lseek(fd, 0, SEEK_CUR));
  }
  CLOSE(fd);
  UNLINK(ctx->name);
}
