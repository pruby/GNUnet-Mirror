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
  GE_BREAK(NULL, name != NULL);
  WRITEINT(fd,
	   strlen(name));
  WRITE(fd,
	name,
	strlen(name));
}

static void writeMetaData(struct GE_Context * ectx,
			  int fd,
			  const struct ECRS_MetaData * meta) {
  unsigned int size;
  char * buf;

  size = ECRS_sizeofMetaData(meta,
			     ECRS_SERIALIZE_FULL | ECRS_SERIALIZE_NO_COMPRESS);
  if (size > 1024 * 1024)
    size = 1024 * 1024;
  buf = MALLOC(size);
  ECRS_serializeMetaData(ectx,
			 meta,
			 buf,
			 size,
			 ECRS_SERIALIZE_PART | ECRS_SERIALIZE_NO_COMPRESS);
  WRITEINT(fd, size);
  WRITE(fd,
	buf,
	size);
  FREE(buf);
}


static void writeFileInfo(struct GE_Context * ectx,
			  int fd,
			  const ECRS_FileInfo * fi) {
  writeMetaData(ectx, fd, fi->meta);
  writeURI(fd, fi->uri);
}


/**
 * (recursively) write a download list.
 */
static void writeDownloadList(struct GE_Context * ectx,
			      int fd,
			      FSUI_Context * ctx,
			      FSUI_DownloadList * list) {
  int i;
  FSUI_SearchList * pos;

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
  if (list->search == NULL) {
    WRITEINT(fd, 0);
  } else {
    i = 1;
    pos = ctx->activeSearches;
    while (pos != list->search) {
      if ( (pos->sizeResultsReceived <= 1024 * 1024) &&
	   (pos->sizeUnmatchedResultsReceived <= 1024 * 1024) )
	i++;
      pos = pos->next;
      if (pos == NULL) {
	GE_BREAK(ectx, 0);
	i = 0;
	break;
      }
    }
    if ( (pos != NULL) &&
	 ( (pos->sizeResultsReceived < 1024 * 1024) ||
	   (pos->sizeUnmatchedResultsReceived < 1024 * 1024) ) )
      i = 0;
    WRITEINT(fd, i);
  }
  WRITEINT(fd, list->state);
  WRITEINT(fd, list->is_recursive);
  WRITEINT(fd, list->is_directory);
  WRITEINT(fd, list->anonymityLevel);
  WRITEINT(fd, list->completedDownloadsCount);
  WRITELONG(fd, list->total);
  WRITELONG(fd, list->completed);
  WRITELONG(fd, get_time() - list->startTime);

  WRITESTRING(fd, list->filename);
  writeFileInfo(ectx,
		fd,
		&list->fi);
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
	      ECRS_isKeywordUri(spos->uri));
    WRITEINT(fd, 1);
    WRITEINT(fd, spos->state);
    WRITEINT(fd, spos->maxResults);
    WRITELONG(fd, spos->timeout);
    WRITELONG(fd, spos->start_time);
    WRITELONG(fd, get_time());
    WRITEINT(fd, spos->anonymityLevel);
    WRITEINT(fd, spos->sizeResultsReceived);
    WRITEINT(fd, spos->sizeUnmatchedResultsReceived);
    writeURI(fd, spos->uri);
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

static void writeUploadList(int fd,
			    struct FSUI_Context * ctx,
			    struct FSUI_UploadList * upos,
			    int top) {
  int bits;

  while (upos != NULL) {
    bits = 1;
    if (upos->uri != NULL)
      bits |= 2;
    if (upos->keywords != NULL)
      bits |= 4;
    if (upos->meta != NULL)
      bits |= 8;
    WRITEINT(fd, bits);
    WRITEINT(fd, 0x34D1F023);
    WRITEINT(fd, upos->state);
    WRITELONG(fd, upos->completed);
    WRITELONG(fd, upos->total);
    WRITELONG(fd, get_time());
    WRITELONG(fd, upos->start_time);
    if (upos->uri != NULL)
      writeURI(fd, upos->uri);
    if (upos->keywords != NULL)
      writeURI(fd, upos->keywords);
    if (upos->meta != NULL)
      writeMetaData(ctx->ectx, fd, upos->meta);
    WRITESTRING(fd, upos->filename);
    writeUploadList(fd, ctx, upos->child, NO);
    if (top == YES)
      break;
    upos = upos->next;
  }
  WRITEINT(fd, 0);
}

static void writeUploads(int fd,
			 struct FSUI_Context * ctx,
			 struct FSUI_UploadList * upos) {
  struct FSUI_UploadShared * shared;
  int bits;

  while (upos != NULL) {
    shared = upos->shared;
    bits = 1;
    if (shared->extractor_config != NULL)
      bits |= 2;
    if (shared->global_keywords != NULL)
      bits |= 4;
    WRITEINT(fd, bits);
    WRITEINT(fd, 0x44D1F024);
    WRITEINT(fd, shared->doIndex);
    WRITEINT(fd, shared->anonymityLevel);
    WRITEINT(fd, shared->priority);
    WRITEINT(fd, shared->individualKeywords);	
    WRITELONG(fd, shared->expiration);
    if (shared->extractor_config != NULL)
      WRITESTRING(fd,
		  shared->extractor_config);
    if (shared->global_keywords != NULL)
      writeURI(fd, shared->global_keywords);
    writeUploadList(fd,
		    ctx,
		    upos,
		    YES);
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
