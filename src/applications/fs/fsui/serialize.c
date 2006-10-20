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
 * @file applications/fs/fsui/serialize.c
 * @brief FSUI functions for writing state to disk
 * @author Christian Grothoff
 * @see deserializer.c
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_directories.h"
#include "fsui.h"

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
  int i;

  if (list == NULL) {
    WRITEINT(fd, 0);
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
  WRITEINT(fd, 1);
  WRITEINT(fd, list->state);
  WRITEINT(fd, list->is_recursive);
  WRITEINT(fd, list->is_directory);
  WRITEINT(fd, list->anonymityLevel);
  WRITEINT(fd, list->completedDownloadsCount);
  WRITELONG(fd, list->total);
  WRITELONG(fd, list->completed);
  WRITELONG(fd, get_time() - list->startTime);
  WRITESTRING(fd, list->filename);
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

static void writeCollection(int fd,
			    struct FSUI_Context * ctx) {
  if ( (ctx->collectionData == NULL) ||
       (ctx->collectionData->size > 16 * 1024 * 1024) ) {
    WRITEINT(fd, 0);
    return;
  }
  /* serialize collection data */
  WRITE(fd,
	ctx->collectionData,
	ntohl(ctx->collectionData->size));
}

static void writeSearches(int fd,
			  struct FSUI_Context * ctx) {
  char * tmp;
  FSUI_SearchList * spos;
  int i;

  spos = ctx->activeSearches;
  while (spos != NULL) {
    if ( (spos->sizeResultsReceived > 1024 * 1024) ||
	 (spos->sizeUnmatchedResultsReceived > 1024 * 1024) ) {
      /* too large to serialize - skip! */
      spos = spos->next;
      continue;
    }
    GE_ASSERT(ctx->ectx,
	      spos->signalTerminate == YES);
    GE_ASSERT(ctx->ectx,
	      ECRS_isKeywordUri(spos->uri));
    WRITEINT(fd, 1);
    WRITEINT(fd, spos->state);
    WRITEINT(fd, spos->anonymityLevel);
    WRITEINT(fd, spos->sizeResultsReceived);
    WRITEINT(fd, spos->sizeUnmatchedResultsReceived);
    tmp = ECRS_uriToString(spos->uri);
    GE_ASSERT(NULL, tmp != NULL);
    WRITESTRING(fd, tmp);
    FREE(tmp);
    for (i=0;i<spos->sizeResultsReceived;i++)
      writeFileInfo(ctx->ectx,
		    fd,
		    &spos->resultsReceived[i]);
    for (i=0;i<spos->sizeUnmatchedResultsReceived;i++) {
      ResultPending * rp;
      
      rp = &spos->unmatchedResultsReceived[i];
      writeFileInfo(ctx->ectx,
		    fd,
		    &rp->fi);
      GE_ASSERT(ctx->ectx,
		rp->matchingKeyCount < spos->numberOfURIKeys);
      if (rp->matchingKeyCount > 1024) {
	WRITEINT(fd, 0); /* too large to serialize */
	continue;
      }
      WRITEINT(fd, rp->matchingKeyCount);
      WRITE(fd,
	    rp->matchingKeys,
	    sizeof(HashCode512) * rp->matchingKeyCount);
    }
    spos = spos->next;
  }
  WRITEINT(fd, 0);
} 

static void writeUnindexing(int fd,
			    struct FSUI_Context * ctx) {
  FSUI_UnindexList * xpos;


  xpos = ctx->unindexOperations;
  while (xpos != NULL) {
    WRITEINT(fd, 1);
    WRITEINT(fd, xpos->state);
    WRITESTRING(fd, xpos->filename);
    xpos = xpos->next;
  }
  /* unindex list terminator */
  WRITEINT(fd, 0);
}

static void writeUploads(int fd,
			 struct FSUI_Context * ctx,
			 struct FSUI_UploadList * upos) {
  struct FSUI_UploadShared * shared;

  while (upos != NULL) {
    if (upos->parent == &ctx->activeUploads) {
      shared = upos->shared;
      WRITEINT(fd, 2);
      WRITESTRING(fd, shared->extractor_config);
      WRITEINT(fd, shared->doIndex);
      WRITEINT(fd, shared->anonymityLevel);
      WRITEINT(fd, shared->priority);
      WRITEINT(fd, shared->individualKeywords);	
      WRITELONG(fd, shared->expiration);
    } else {
      WRITEINT(fd, 1);
    }
    WRITEINT(fd, upos->state);
    WRITELONG(fd, upos->completed);
    WRITELONG(fd, upos->total);
    WRITELONG(fd, get_time());
    WRITELONG(fd, upos->start_time);
    writeURI(fd, upos->uri);
    WRITESTRING(fd, upos->filename);
    writeUploads(fd, ctx, upos->child);
    upos = upos->next;
  }
  WRITEINT(fd, 0);
}

void FSUI_serialize(struct FSUI_Context * ctx) {
  int fd;

  fd = disk_file_open(ctx->ectx,
		      ctx->name,
		      O_CREAT|O_TRUNC|O_WRONLY,
		      S_IRUSR|S_IWUSR);
  if (fd == -1) 
    return;    
  WRITE(fd,
	"FSUI01\n\0",
	8); /* magic */
  writeCollection(fd, ctx);
  writeSearches(fd, ctx);
  writeDownloadList(ctx->ectx,
		    fd,
		    ctx,
		    ctx->activeDownloads.child);
  writeUnindexing(fd, ctx);
  writeUploads(fd, 
	       ctx,
	       ctx->activeUploads.child);  
  CLOSE(fd);
}

/* end of serializer */
