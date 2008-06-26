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


typedef struct
{
  int fd;
  unsigned int have;
  unsigned int size;
  char *buffer;
} WriteBuffer;

static void
write_buffered (WriteBuffer * wb, const void *s, unsigned int size)
{
  const char *src = s;
  unsigned int min;
  unsigned int pos;
  int ret;

  if (wb->fd == -1)
    return;
  pos = 0;
  do
    {
      /* first, just use buffer */
      min = wb->size - wb->have;
      if (min > size - pos)
        min = size - pos;
      memcpy (&wb->buffer[wb->have], &src[pos], min);
      pos += min;
      wb->have += min;
      if (pos == size)
        return;                 /* done */
      GNUNET_GE_ASSERT (NULL, wb->have == wb->size);
      ret = WRITE (wb->fd, wb->buffer, wb->size);
      if (ret != wb->size)
        {
          CLOSE (wb->fd);
          wb->fd = -1;
          return;               /* error */
        }
      wb->have = 0;
    }
  while (pos < size);           /* should always be true */
}


static void
WRITEINT (WriteBuffer * wb, int val)
{
  int big;
  big = htonl (val);
  write_buffered (wb, &big, sizeof (int));
}

static void
WRITELONG (WriteBuffer * wb, long long val)
{
  long long big;
  big = GNUNET_htonll (val);
  write_buffered (wb, &big, sizeof (long long));
}

static void
writeURI (WriteBuffer * wb, const struct GNUNET_ECRS_URI *uri)
{
  char *buf;
  unsigned int size;

  buf = GNUNET_ECRS_uri_to_string (uri);
  size = strlen (buf);
  WRITEINT (wb, size);
  write_buffered (wb, buf, size);
  GNUNET_free (buf);
}

static void
WRITESTRING (WriteBuffer * wb, const char *name)
{
  GNUNET_GE_BREAK (NULL, name != NULL);
  WRITEINT (wb, strlen (name));
  write_buffered (wb, name, strlen (name));
}

static void
writeMetaData (struct GNUNET_GE_Context *ectx,
               WriteBuffer * wb, const struct GNUNET_MetaData *meta)
{
  unsigned int size;
  char *buf;

  size = GNUNET_meta_data_get_serialized_size (meta,
                                               GNUNET_SERIALIZE_FULL
                                               |
                                               GNUNET_SERIALIZE_NO_COMPRESS);
  if (size > 1024 * 1024)
    size = 1024 * 1024;
  buf = GNUNET_malloc (size);
  GNUNET_meta_data_serialize (ectx,
                              meta,
                              buf,
                              size,
                              GNUNET_SERIALIZE_PART |
                              GNUNET_SERIALIZE_NO_COMPRESS);
  WRITEINT (wb, size);
  write_buffered (wb, buf, size);
  GNUNET_free (buf);
}


static void
writeFileInfo (struct GNUNET_GE_Context *ectx, WriteBuffer * wb,
               const GNUNET_ECRS_FileInfo * fi)
{
  writeMetaData (ectx, wb, fi->meta);
  writeURI (wb, fi->uri);
}


/**
 * (recursively) write a download list.
 */
static void
writeDownloadList (struct GNUNET_GE_Context *ectx,
                   WriteBuffer * wb, GNUNET_FSUI_Context * ctx,
                   GNUNET_FSUI_DownloadList * list)
{
  int i;
  GNUNET_FSUI_SearchList *pos;

  if (list == NULL)
    {
      WRITEINT (wb, 0);
      return;
    }
#if DEBUG_PERSISTENCE
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Serializing download state of download `%s': (%llu, %llu)\n",
                 list->filename, list->completed, list->total);
#endif
  WRITEINT (wb, 1);
  if (list->search == NULL)
    {
      WRITEINT (wb, 0);
    }
  else
    {
      i = 1;
      pos = ctx->activeSearches;
      while (pos != list->search)
        {
          pos = pos->next;
          if (pos == NULL)
            {
              GNUNET_GE_BREAK (ectx, 0);
              i = 0;
              break;
            }
          i++;
        }
      if (pos == NULL)
        i = 0;
      WRITEINT (wb, i);
    }
  WRITEINT (wb, list->state);
  WRITEINT (wb, list->is_recursive);
  WRITEINT (wb, list->is_directory);
  WRITEINT (wb, list->anonymityLevel);
  WRITEINT (wb, list->completedDownloadsCount);
  WRITELONG (wb, list->total);
  WRITELONG (wb, list->completed);
  WRITELONG (wb, GNUNET_get_time () - list->startTime);

  WRITESTRING (wb, list->filename);
  writeFileInfo (ectx, wb, &list->fi);
  for (i = 0; i < list->completedDownloadsCount; i++)
    writeURI (wb, list->completedDownloads[i]);
  writeDownloadList (ectx, wb, ctx, list->next);
  writeDownloadList (ectx, wb, ctx, list->child);
}

static void
writeCollection (WriteBuffer * wb, struct GNUNET_FSUI_Context *ctx)
{
  if ((ctx->collectionData == NULL) ||
      (ctx->collectionDataSize > 16 * 1024 * 1024))
    {
      WRITEINT (wb, 0);
      return;
    }
  /* serialize collection data */
  WRITEINT (wb, ctx->collectionDataSize);
  write_buffered (wb, ctx->collectionData, ctx->collectionDataSize);
}


/**
 * Write information about the individual ECRS searches
 * that we are performing.
 */
static void
write_search_record_list (struct GNUNET_GE_Context *ectx,
                          WriteBuffer * wb, struct SearchRecordList *pos)
{
  while (pos != NULL)
    {
      WRITEINT (wb, pos->is_required);
      write_buffered (wb, &pos->key, sizeof (GNUNET_HashCode));
      writeURI (wb, pos->uri);
      pos = pos->next;
    }
  WRITEINT (wb, -1);
}

/**
 * Write all of the results received so far
 * for this search.
 *
 * @param search_count length of search_list
 * @param search_list list of ECRS search requests
 * @param pos results to write
 */
void
write_result_list (struct GNUNET_GE_Context *ectx,
                   WriteBuffer * wb,
                   struct SearchRecordList *search_list,
                   struct SearchResultList *pos)
{
  unsigned int i;
  unsigned int idx;
  struct SearchRecordList *spos;

  while (pos != NULL)
    {
      WRITEINT (wb, pos->matchingSearchCount);
      WRITEINT (wb, pos->mandatoryMatchesRemaining);
      WRITEINT (wb, pos->probeSuccess);
      WRITEINT (wb, pos->probeFailure);
      writeFileInfo (ectx, wb, &pos->fi);
      i = pos->matchingSearchCount;
      while (i-- > 0)
        {
          idx = 1;
          spos = search_list;
          while ((spos != NULL) && (spos != pos->matchingSearches[i]))
            {
              idx++;
              spos = spos->next;
            }
          if (spos == NULL)
            idx = 0;
          WRITEINT (wb, idx);
        }
      pos = pos->next;
    }
  WRITEINT (wb, -1);
}


static void
writeSearches (WriteBuffer * wb, struct GNUNET_FSUI_Context *ctx)
{
  GNUNET_FSUI_SearchList *spos;

  spos = ctx->activeSearches;
  while (spos != NULL)
    {
      GNUNET_GE_ASSERT (ctx->ectx,
                        GNUNET_ECRS_uri_test_ksk (spos->uri) ||
                        GNUNET_ECRS_uri_test_sks (spos->uri));
      WRITEINT (wb, 1);
      WRITEINT (wb, spos->state);
      WRITELONG (wb, spos->start_time);
      WRITELONG (wb, GNUNET_get_time ());
      WRITEINT (wb, spos->anonymityLevel);
      WRITEINT (wb, spos->mandatory_keyword_count);
      writeURI (wb, spos->uri);
      write_search_record_list (ctx->ectx, wb, spos->searches);
      write_result_list (ctx->ectx,
                         wb, spos->searches, spos->resultsReceived);
      spos = spos->next;
    }
  WRITEINT (wb, 0);
}

static void
writeUnindexing (WriteBuffer * wb, struct GNUNET_FSUI_Context *ctx)
{
  GNUNET_FSUI_UnindexList *xpos;


  xpos = ctx->unindexOperations;
  while (xpos != NULL)
    {
      WRITEINT (wb, 1);
      WRITEINT (wb, xpos->state);
      WRITESTRING (wb, xpos->filename);
      xpos = xpos->next;
    }
  /* unindex list terminator */
  WRITEINT (wb, 0);
}

static void
writeUploadList (WriteBuffer * wb,
                 struct GNUNET_FSUI_Context *ctx,
                 struct GNUNET_FSUI_UploadList *upos, int top)
{
  int bits;

  while (upos != NULL)
    {
      bits = 1;
      if (upos->uri != NULL)
        bits |= 2;
      if (upos->keywords != NULL)
        bits |= 4;
      if (upos->meta != NULL)
        bits |= 8;
      WRITEINT (wb, bits);
      WRITEINT (wb, 0x34D1F023);
      WRITEINT (wb, upos->state);
      WRITELONG (wb, upos->completed);
      WRITELONG (wb, upos->total);
      WRITELONG (wb, GNUNET_get_time ());
      WRITELONG (wb, upos->start_time);
      if (upos->uri != NULL)
        writeURI (wb, upos->uri);
      if (upos->keywords != NULL)
        writeURI (wb, upos->keywords);
      if (upos->meta != NULL)
        writeMetaData (ctx->ectx, wb, upos->meta);
      WRITESTRING (wb, upos->filename);
      writeUploadList (wb, ctx, upos->child, GNUNET_NO);
      if (top == GNUNET_YES)
        break;
      upos = upos->next;
    }
  if (top != GNUNET_YES)
    WRITEINT (wb, 0);
}

static void
writeUploads (WriteBuffer * wb, struct GNUNET_FSUI_Context *ctx,
              struct GNUNET_FSUI_UploadList *upos)
{
  struct GNUNET_FSUI_UploadShared *shared;
  int bits;

  while (upos != NULL)
    {
      shared = upos->shared;
      bits = 1;
      if (shared->extractor_config != NULL)
        bits |= 2;
      if (shared->global_keywords != NULL)
        bits |= 4;
      WRITEINT (wb, bits);
      WRITEINT (wb, 0x44D1F024);
      WRITEINT (wb, shared->doIndex);
      WRITEINT (wb, shared->anonymityLevel);
      WRITEINT (wb, shared->priority);
      WRITEINT (wb, shared->individualKeywords);
      WRITELONG (wb, shared->expiration);
      if (shared->extractor_config != NULL)
        WRITESTRING (wb, shared->extractor_config);
      WRITESTRING (wb, shared->top_filename);
      if (shared->global_keywords != NULL)
        writeURI (wb, shared->global_keywords);
      writeUploadList (wb, ctx, upos, GNUNET_YES);
      upos = upos->next;
    }
  WRITEINT (wb, 0);
}

void
GNUNET_FSUI_serialize (struct GNUNET_FSUI_Context *ctx)
{
  WriteBuffer wb;

  wb.fd = GNUNET_disk_file_open (ctx->ectx,
                                 ctx->name,
                                 O_CREAT | O_TRUNC | O_WRONLY,
                                 S_IRUSR | S_IWUSR);
  if (wb.fd == -1)
    return;
  wb.have = 0;
  wb.size = 64 * 1024;
  wb.buffer = GNUNET_malloc (wb.size);
  write_buffered (&wb, "FSUI03\n\0", 8);        /* magic */
  writeCollection (&wb, ctx);
  writeSearches (&wb, ctx);
  writeDownloadList (ctx->ectx, &wb, ctx, ctx->activeDownloads.child);
  writeUnindexing (&wb, ctx);
  writeUploads (&wb, ctx, ctx->activeUploads.child);
  WRITE (wb.fd, wb.buffer, wb.have);
  CLOSE (wb.fd);
  GNUNET_free (wb.buffer);
}

/* end of serialize.c */
