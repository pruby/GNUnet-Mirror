/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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

typedef struct
{
  int fd;
  unsigned int have;
  unsigned int size;
  unsigned int pos;
  char *buffer;
} ReadBuffer;

static int
read_buffered (ReadBuffer * rb, void *d, unsigned int size)
{
  char *dst = d;
  unsigned int min;
  unsigned int pos;
  int ret;

  if (rb->fd == -1)
    return -1;
  pos = 0;
  do
    {
      /* first, use buffer */
      min = rb->have - rb->pos;
      if (min > 0)
        {
          if (min > size - pos)
            min = size - pos;
          memcpy (&dst[pos], &rb->buffer[rb->pos], min);
          rb->pos += min;
          pos += min;
        }
      if (pos == size)
        return pos;             /* done! */
      GNUNET_GE_ASSERT (NULL, rb->have == rb->pos);
      /* fill buffer */
      ret = READ (rb->fd, rb->buffer, rb->size);
      if (ret == -1)
        {
          CLOSE (rb->fd);
          rb->fd = -1;
          return -1;
        }
      if (ret == 0)
        return 0;
      rb->pos = 0;
      rb->have = ret;
    }
  while (pos < size);           /* should always be true */
  return pos;
}


static int
read_int (ReadBuffer * rb, int *val)
{
  int big;

  if (sizeof (int) != read_buffered (rb, &big, sizeof (int)))
    return GNUNET_SYSERR;
  *val = ntohl (big);
  return GNUNET_OK;
}

static unsigned int
read_uint (ReadBuffer * rb, unsigned int *val)
{
  unsigned int big;

  if (sizeof (unsigned int) !=
      read_buffered (rb, &big, sizeof (unsigned int)))
    return GNUNET_SYSERR;
  *val = ntohl (big);
  return GNUNET_OK;
}

#define READINT(a) if (GNUNET_OK != read_int(rb, (int*) &a)) return GNUNET_SYSERR;

static int
read_long (ReadBuffer * rb, long long *val)
{
  long long big;

  if (sizeof (long long) != read_buffered (rb, &big, sizeof (long long)))
    return GNUNET_SYSERR;
  *val = GNUNET_ntohll (big);
  return GNUNET_OK;
}

#define READLONG(a) if (GNUNET_OK != read_long(rb, (long long*) &a)) return GNUNET_SYSERR;

static struct GNUNET_ECRS_URI *
read_uri (struct GNUNET_GE_Context *ectx, ReadBuffer * rb)
{
  char *buf;
  struct GNUNET_ECRS_URI *ret;
  unsigned int size;

  if (GNUNET_OK != read_uint (rb, &size))
    return NULL;
  buf = GNUNET_malloc (size + 1);
  buf[size] = '\0';
  if (size != read_buffered (rb, buf, size))
    {
      GNUNET_free (buf);
      return NULL;
    }
  ret = GNUNET_ECRS_string_to_uri (ectx, buf);
  GNUNET_GE_BREAK (ectx, ret != NULL);
  GNUNET_free (buf);
  return ret;
}

#define READURI(u) if (NULL == (u = read_uri(ectx, rb))) return GNUNET_SYSERR;

static char *
read_string (ReadBuffer * rb, unsigned int maxLen)
{
  char *buf;
  unsigned int big;

  if (GNUNET_OK != read_uint (rb, &big))
    return NULL;
  if (big > maxLen)
    return NULL;
  buf = GNUNET_malloc (big + 1);
  buf[big] = '\0';
  if (big != read_buffered (rb, buf, big))
    {
      GNUNET_free (buf);
      return NULL;
    }
  return buf;
}

#define READSTRING(c, max) if (NULL == (c = read_string(rb, max))) return GNUNET_SYSERR;

static void
fixState (GNUNET_FSUI_State * state)
{
  switch (*state)
    {                           /* try to correct errors */
    case GNUNET_FSUI_ACTIVE:
      *state = GNUNET_FSUI_PENDING;
      break;
    case GNUNET_FSUI_PENDING:
    case GNUNET_FSUI_COMPLETED_JOINED:
    case GNUNET_FSUI_ABORTED_JOINED:
    case GNUNET_FSUI_ERROR_JOINED:
      break;
    case GNUNET_FSUI_ERROR:
      *state = GNUNET_FSUI_ERROR_JOINED;
      break;
    case GNUNET_FSUI_ABORTED:
      *state = GNUNET_FSUI_ABORTED_JOINED;
      break;
    case GNUNET_FSUI_COMPLETED:
      *state = GNUNET_FSUI_COMPLETED_JOINED;
      break;
    default:
      *state = GNUNET_FSUI_ERROR_JOINED;
      break;
    }
}


/**
 * Read file info from file.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static struct GNUNET_ECRS_MetaData *
read_meta (struct GNUNET_GE_Context *ectx, ReadBuffer * rb)
{
  unsigned int size;
  char *buf;
  struct GNUNET_ECRS_MetaData *meta;

  if (read_uint (rb, &size) != GNUNET_OK)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  if (size > 1024 * 1024)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  buf = GNUNET_malloc (size);
  if (size != read_buffered (rb, buf, size))
    {
      GNUNET_free (buf);
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  meta = GNUNET_ECRS_meta_data_deserialize (ectx, buf, size);
  if (meta == NULL)
    {
      GNUNET_free (buf);
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  GNUNET_free (buf);
  return meta;
}

/**
 * Read file info from file.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
readFileInfo (struct GNUNET_GE_Context *ectx, ReadBuffer * rb,
              GNUNET_ECRS_FileInfo * fi)
{
  fi->meta = read_meta (ectx, rb);
  if (fi->meta == NULL)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  fi->uri = NULL;

  fi->uri = read_uri (ectx, rb);
  if (fi->uri == NULL)
    {
      GNUNET_ECRS_meta_data_destroy (fi->meta);
      fi->meta = NULL;
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
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
static GNUNET_FSUI_DownloadList *
readDownloadList (struct GNUNET_GE_Context *ectx,
                  ReadBuffer * rb, GNUNET_FSUI_Context * ctx,
                  GNUNET_FSUI_DownloadList * parent)
{
  GNUNET_FSUI_DownloadList *ret;
  GNUNET_FSUI_SearchList *pos;
  unsigned int big;
  int i;
  int ok;
  int soff;

  GNUNET_GE_ASSERT (ectx, ctx != NULL);
  if ((GNUNET_OK != read_uint (rb, &big)) || (big == 0))
    return NULL;
  ret = GNUNET_malloc (sizeof (GNUNET_FSUI_DownloadList));
  memset (ret, 0, sizeof (GNUNET_FSUI_DownloadList));
  ret->ctx = ctx;
  if ((GNUNET_OK != read_int (rb, &soff)) ||
      (GNUNET_OK != read_int (rb, (int *) &ret->state)) ||
      (GNUNET_OK != read_int (rb, &ret->is_recursive)) ||
      (GNUNET_OK != read_int (rb, &ret->is_directory)) ||
      (GNUNET_OK != read_uint (rb, &ret->anonymityLevel)) ||
      (GNUNET_OK != read_uint (rb, &ret->completedDownloadsCount)) ||
      (GNUNET_OK != read_long (rb, (long long *) &ret->total)) ||
      (GNUNET_OK != read_long (rb, (long long *) &ret->completed)) ||
      (GNUNET_OK != read_long (rb, (long long *) &ret->runTime)) ||
      (GNUNET_OK != read_uint (rb, &big)) || (big > 1024 * 1024))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_free (ret);
      return NULL;
    }
  fixState (&ret->state);
  ret->filename = GNUNET_malloc (big + 1);
  ret->filename[big] = '\0';
  if (big != read_buffered (rb, ret->filename, big))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (ret->filename);
      GNUNET_free (ret);
      return NULL;
    }
  if (GNUNET_OK != readFileInfo (ectx, rb, &ret->fi))
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_free (ret->filename);
      GNUNET_free (ret);
      return NULL;
    }
  if (ret->completedDownloadsCount > 0)
    ret->completedDownloads
      =
      GNUNET_malloc (sizeof (struct GNUNET_ECRS_URI *) *
                     ret->completedDownloadsCount);
  ok = GNUNET_YES;
  for (i = 0; i < ret->completedDownloadsCount; i++)
    {
      ret->completedDownloads[i] = read_uri (ectx, rb);
      if (ret->completedDownloads[i] == NULL)
        {
          GNUNET_GE_BREAK (NULL, 0);
          ok = GNUNET_NO;
        }
    }
  if (GNUNET_NO == ok)
    {
      GNUNET_free (ret->filename);
      GNUNET_ECRS_uri_destroy (ret->fi.uri);
      GNUNET_ECRS_meta_data_destroy (ret->fi.meta);
      for (i = 0; i < ret->completedDownloadsCount; i++)
        {
          if (ret->completedDownloads[i] != NULL)
            GNUNET_ECRS_uri_destroy (ret->completedDownloads[i]);
        }
      GNUNET_free (ret->completedDownloads);
      GNUNET_free (ret);
      GNUNET_GE_BREAK (NULL, 0);
      return NULL;
    }
  ret->parent = parent;
  if (soff == 0)
    {
      ret->search = NULL;
    }
  else
    {
      pos = ctx->activeSearches;
      while (--soff > 0)
        {
          if (pos == NULL)
            {
              GNUNET_GE_BREAK (NULL, 0);
              break;
            }
          pos = pos->next;
        }
      ret->search = pos;
      if (pos != NULL)
        {
          GNUNET_array_grow (pos->my_downloads,
                             pos->my_downloads_size,
                             pos->my_downloads_size + 1);
          pos->my_downloads[pos->my_downloads_size - 1] = ret;
        }
    }
  ret->next = readDownloadList (ectx, rb, ctx, parent);
  ret->child = readDownloadList (ectx, rb, ctx, ret);
#if DEBUG_PERSISTENCE
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "FSUI persistence: restoring download `%s': (%llu, %llu)\n",
                 ret->filename, ret->completed, ret->total);
#endif
  return ret;
}

static int
checkMagic (ReadBuffer * rb)
{
  char magic[8];

  if (8 != read_buffered (rb, magic, 8))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (0 != memcmp (magic, "FSUI03\n\0", 8))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

static int
readCollection (ReadBuffer * rb, struct GNUNET_FSUI_Context *ctx)
{
  int big;

  /* deserialize collection data */
  READINT (big);
  if (big == 0)
    {
      ctx->collectionData = NULL;
      return GNUNET_OK;
    }
  if ((big > 16 * 1024 * 1024) || (big < sizeof (unsigned int)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  ctx->collectionDataSize = big;
  ctx->collectionData = GNUNET_malloc (big);
  if (big != read_buffered (rb, ctx->collectionData, big))
    {
      GNUNET_free (ctx->collectionData);
      ctx->collectionData = NULL;
      ctx->collectionDataSize = 0;
      GNUNET_GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * Read in information about the individual ECRS searches
 * that we are performing.
 */
struct SearchRecordList *
read_search_record_list (struct GNUNET_GE_Context *ectx, ReadBuffer * rb)
{
  unsigned int is_required;
  GNUNET_HashCode key;
  struct GNUNET_ECRS_URI *uri;
  struct SearchRecordList *ret;
  struct SearchRecordList *head;
  struct SearchRecordList *tail;

  ret = NULL;
  head = NULL;
  tail = NULL;
  while (1)
    {
      if (GNUNET_OK != read_uint (rb, &is_required))
        break;
      if (is_required == -1)
        break;                  /* end of list marker */
      if (sizeof (GNUNET_HashCode)
          != read_buffered (rb, &key, sizeof (GNUNET_HashCode)))
        break;
      uri = read_uri (ectx, rb);
      if (uri == NULL)
        break;                  /* error */
      ret = GNUNET_malloc (sizeof (struct SearchRecordList));
      ret->key = key;
      ret->uri = uri;
      ret->search = NULL;
      ret->is_required = is_required;
      ret->next = NULL;
      if (head == NULL)
        head = ret;
      if (tail != NULL)
        tail->next = ret;
      tail = ret;
    }
  return head;
}

/**
 * Read all of the results received so far
 * for this search.
 *
 * @param search_count length of search_list
 * @param search_list list of ECRS search requests
 */
struct SearchResultList *
read_result_list (struct GNUNET_GE_Context *ectx,
                  ReadBuffer * rb,
                  unsigned int search_count,
                  struct SearchRecordList **search_list)
{
  unsigned int matching;
  unsigned int remaining;
  unsigned int probeSucc;
  unsigned int probeFail;
  struct SearchResultList *ret;
  struct SearchResultList *head;
  struct SearchResultList *tail;
  unsigned int i;
  unsigned int idx;

  ret = NULL;
  head = NULL;
  tail = NULL;
  while (1)
    {
      if (GNUNET_OK != read_uint (rb, &matching))
        break;
      if (matching == -1)
        break;                  /* end of list marker */
      if ((GNUNET_OK != read_uint (rb, &remaining)) ||
          (GNUNET_OK != read_uint (rb, &probeSucc)) ||
          (GNUNET_OK != read_uint (rb, &probeFail)))
        break;
      ret = GNUNET_malloc (sizeof (struct SearchResultList));
      if (GNUNET_OK != readFileInfo (ectx, rb, &ret->fi))
        {
          GNUNET_free (ret);
          break;
        }
      ret->matchingSearchCount = matching;
      ret->mandatoryMatchesRemaining = remaining;
      ret->probeSuccess = probeSucc;
      ret->probeFailure = probeFail;
      if ((ret->probeSuccess + ret->probeFailure > GNUNET_FSUI_MAX_PROBES) ||
          (ret->probeSuccess > GNUNET_FSUI_MAX_PROBES) ||
          (ret->probeFailure > GNUNET_FSUI_MAX_PROBES))
        {
          GNUNET_GE_BREAK (NULL, 0);
          /* try to recover */
          ret->probeSuccess = 0;
          ret->probeFailure = 0;
        }
      ret->test_download = NULL;
      ret->next = NULL;
      ret->matchingSearches = NULL;
      i = 0;
      GNUNET_array_grow (ret->matchingSearches, i, ret->matchingSearchCount);
      while (i-- > 0)
        {
          if ((GNUNET_OK != read_uint (rb, &idx)) || (idx > search_count))
            {
              GNUNET_GE_BREAK (NULL, 0);
              GNUNET_array_grow (ret->matchingSearches,
                                 ret->matchingSearchCount, 0);
              GNUNET_free (ret);
              return head;
            }
          if (idx == 0)
            {
              GNUNET_GE_BREAK (NULL, 0);
              ret->matchingSearches[i] = NULL;
            }
          else
            {
              GNUNET_GE_BREAK (NULL, search_list[idx - 1] != NULL);
              ret->matchingSearches[i] = search_list[idx - 1];
            }
        }
      if (head == NULL)
        head = ret;
      if (tail != NULL)
        tail->next = ret;
      tail = ret;
    }
  return head;
}

/**
 * Read in all of the FSUI-searches that we are
 * performing.
 */
static int
readSearches (ReadBuffer * rb, struct GNUNET_FSUI_Context *ctx)
{
  int big;
  GNUNET_FSUI_SearchList *list;
  GNUNET_FSUI_SearchList *last;
  struct SearchResultList *srp;
  struct SearchRecordList *srl;
  struct SearchRecordList **srla;
  char *buf;
  GNUNET_CronTime stime;
  unsigned int total_searches;
  unsigned int i;

  while (1)
    {
      READINT (big);
      if (big == 0)
        return GNUNET_OK;
      list = GNUNET_malloc (sizeof (GNUNET_FSUI_SearchList));
      memset (list, 0, sizeof (GNUNET_FSUI_SearchList));
      list->lock = GNUNET_mutex_create (GNUNET_NO);
      list->ctx = ctx;
      if ((GNUNET_OK != read_int (rb, (int *) &list->state)) ||
          (GNUNET_OK != read_long (rb, (long long *) &list->start_time)) ||
          (GNUNET_OK != read_long (rb, (long long *) &stime)) ||
          (GNUNET_OK != read_uint (rb, &list->anonymityLevel)) ||
          (GNUNET_OK != read_uint (rb, &list->mandatory_keyword_count)))
        {
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      fixState (&list->state);
      if (stime > GNUNET_get_time ())
        stime = GNUNET_get_time ();
      list->start_time += GNUNET_get_time () - stime;
      buf = read_string (rb, 1024 * 1024);
      if (buf == NULL)
        {
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      list->uri = GNUNET_ECRS_string_to_uri (NULL, buf);
      GNUNET_free (buf);
      if (list->uri == NULL)
        {
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      if (!
          (GNUNET_ECRS_uri_test_ksk (list->uri)
           || GNUNET_ECRS_uri_test_sks (list->uri)))
        {
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      list->searches = read_search_record_list (ctx->ectx, rb);
      if (list->searches == NULL)
        goto ERR;               /* can never be empty in practice */
      srl = list->searches;
      total_searches = 0;
      while (srl != NULL)
        {
          total_searches++;
          srl = srl->next;
        }
      srla =
        GNUNET_malloc (total_searches * sizeof (struct SearchRecordList *));
      srl = list->searches;
      i = total_searches;
      while (srl != NULL)
        {
          srla[--i] = srl;
          srl = srl->next;
        }
      list->resultsReceived = read_result_list (ctx->ectx, rb,
                                                total_searches, srla);
      GNUNET_free (srla);
      list->next = NULL;

      /* finally: append (!) to list */
      if (ctx->activeSearches == NULL)
        {
          ctx->activeSearches = list;
        }
      else
        {
          last = ctx->activeSearches;
          while (last->next != NULL)
            last = last->next;
          last->next = list;
        }
    }                           /* end OUTER: 'while(1)' */
ERR:
  /* error - deallocate 'list' */
  while (list->resultsReceived != NULL)
    {
      srp = list->resultsReceived;
      list->resultsReceived = srp->next;
      GNUNET_free (srp);
    }
  while (list->searches != NULL)
    {
      srl = list->searches;
      list->searches = srl->next;
      if (srl->uri != NULL)
        GNUNET_ECRS_uri_destroy (srl->uri);
      GNUNET_free (srl);
    }
  if (list->uri != NULL)
    GNUNET_ECRS_uri_destroy (list->uri);
  GNUNET_mutex_destroy (list->lock);
  GNUNET_free (list);
  return GNUNET_SYSERR;
}

static int
readDownloads (ReadBuffer * rb, struct GNUNET_FSUI_Context *ctx)
{
  memset (&ctx->activeDownloads, 0, sizeof (GNUNET_FSUI_DownloadList));
  ctx->activeDownloads.child
    = readDownloadList (ctx->ectx, rb, ctx, &ctx->activeDownloads);
  return GNUNET_OK;
}

static int
readUploadList (struct GNUNET_FSUI_Context *ctx,
                struct GNUNET_FSUI_UploadList *parent,
                ReadBuffer * rb, struct GNUNET_FSUI_UploadShared *shared,
                int top)
{
  struct GNUNET_FSUI_UploadList *list;
  struct GNUNET_FSUI_UploadList l;
  unsigned long long stime;
  int big;
  int bag;
  struct GNUNET_GE_Context *ectx;

  ectx = ctx->ectx;
  GNUNET_GE_ASSERT (ectx, shared != NULL);
  while (1)
    {
      READINT (big);
      if (big == 0)
        return GNUNET_OK;
      if ((big < 1) || (big > 15))
        {
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      READINT (bag);
      if (bag != 0x34D1F023)
        {
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      memset (&l, 0, sizeof (GNUNET_FSUI_UploadList));
      READINT (l.state);
      fixState (&l.state);
      if (l.state == GNUNET_FSUI_PENDING)
        l.state = GNUNET_FSUI_ACTIVE;
      READLONG (l.completed);
      READLONG (l.total);
      READLONG (stime);
      if (stime < GNUNET_get_time ())
        stime = GNUNET_get_time ();
      READLONG (l.start_time);
      if (l.start_time != 0)
        l.start_time = (GNUNET_get_time () - stime) + l.start_time;
      l.uri = NULL;
      if ((big & 2) == 2)
        READURI (l.uri);
      if ((big & 4) == 4)
        {
          l.keywords = read_uri (ctx->ectx, rb);
          if (l.keywords == NULL)
            {
              if (l.uri != NULL)
                GNUNET_ECRS_uri_destroy (l.uri);
              GNUNET_GE_BREAK (NULL, 0);
              break;
            }
        }
      if ((big & 8) == 8)
        {
          l.meta = read_meta (ctx->ectx, rb);
          if (l.meta == NULL)
            {
              if (l.uri != NULL)
                GNUNET_ECRS_uri_destroy (l.uri);
              if (l.keywords != NULL)
                GNUNET_ECRS_uri_destroy (l.keywords);
              GNUNET_GE_BREAK (NULL, 0);
              break;
            }
        }
      l.filename = read_string (rb, 1024 * 1024);
      if (l.filename == NULL)
        {
          if (l.uri != NULL)
            GNUNET_ECRS_uri_destroy (l.uri);
          if (l.meta != NULL)
            GNUNET_ECRS_meta_data_destroy (l.meta);
          if (l.keywords != NULL)
            GNUNET_ECRS_uri_destroy (l.keywords);
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      list = GNUNET_malloc (sizeof (struct GNUNET_FSUI_UploadList));
      memcpy (list, &l, sizeof (struct GNUNET_FSUI_UploadList));
      list->shared = shared;
      list->parent = parent;
      if (GNUNET_OK != readUploadList (ctx, list, rb, shared, GNUNET_NO))
        {
          if (l.uri != NULL)
            GNUNET_ECRS_uri_destroy (l.uri);
          GNUNET_free (l.filename);
          GNUNET_free (list);
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      list->next = parent->child;
      parent->child = list;
      if (top == GNUNET_YES)
        return GNUNET_OK;
    }
  return GNUNET_SYSERR;
}


static int
readUploads (ReadBuffer * rb, struct GNUNET_FSUI_Context *ctx)
{
  int big;
  int bag;
  struct GNUNET_FSUI_UploadShared *shared;
  struct GNUNET_FSUI_UploadShared sshared;

  memset (&ctx->activeUploads, 0, sizeof (GNUNET_FSUI_UploadList));
  while (1)
    {
      READINT (big);
      if (big == 0)
        return GNUNET_OK;
      if ((big < 1) && (big > 7))
        {
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      READINT (bag);
      if (bag != 0x44D1F024)
        {
          GNUNET_GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      memset (&sshared, 0, sizeof (GNUNET_FSUI_UploadShared));
      READINT (sshared.doIndex);
      READINT (sshared.anonymityLevel);
      READINT (sshared.priority);
      READINT (sshared.individualKeywords);
      READLONG (sshared.expiration);
      if ((big & 2) == 2)
        READSTRING (sshared.extractor_config, 1024 * 1024);
      READSTRING (sshared.top_filename, 1024 * 1024);
      if ((big & 4) == 4)
        {
          sshared.global_keywords = read_uri (ctx->ectx, rb);
          if (sshared.global_keywords == NULL)
            {
              GNUNET_free_non_null (sshared.extractor_config);
              GNUNET_GE_BREAK (NULL, 0);
              return GNUNET_SYSERR;
            }
        }
      shared = GNUNET_malloc (sizeof (GNUNET_FSUI_UploadShared));
      memcpy (shared, &sshared, sizeof (GNUNET_FSUI_UploadShared));
      shared->ctx = ctx;
      if (GNUNET_OK !=
          readUploadList (ctx, &ctx->activeUploads, rb, shared, GNUNET_YES))
        {
          GNUNET_GE_BREAK (NULL, 0);
#if 0
          /* cannot do this, readUploadList
             may have added *some* uploads that
             still reference shared -- need to
             find and cleanup those first,
             or at least detect their presence
             and not free */
          GNUNET_free (shared->extractor_config);
          GNUNET_free (shared);
#endif
          break;
        }

    }
  return GNUNET_SYSERR;
}

static int
readUnindex (ReadBuffer * rb, struct GNUNET_FSUI_Context *ctx)
{
  int big;
  char *name;
  struct GNUNET_FSUI_UnindexList *ul;

  while (1)
    {
      READINT (big);
      if (big != 1)
        return GNUNET_OK;
      READINT (big);            /* state */
      READSTRING (name, 1024 * 1024);
      ul = GNUNET_malloc (sizeof (struct GNUNET_FSUI_UnindexList));
      ul->state = big;
      ul->filename = name;
      ul->next = ctx->unindexOperations;
      ul->ctx = ctx;
      ctx->unindexOperations = ul;
    }
  return GNUNET_SYSERR;
}


void
GNUNET_FSUI_deserialize (struct GNUNET_FSUI_Context *ctx)
{
  ReadBuffer rb;

  rb.fd = -1;
  if (0 != ACCESS (ctx->name, R_OK))
    return;
  rb.fd = GNUNET_disk_file_open (ctx->ectx, ctx->name, O_RDONLY);
  if (rb.fd == -1)
    return;
  rb.pos = 0;
  rb.size = 64 * 1024;
  rb.have = 0;
  rb.buffer = GNUNET_malloc (rb.size);
  if ((GNUNET_OK != checkMagic (&rb)) ||
      (GNUNET_OK != readCollection (&rb, ctx)) ||
      (GNUNET_OK != readSearches (&rb, ctx)) ||
      (GNUNET_OK != readDownloads (&rb, ctx)) ||
      (GNUNET_OK != readUnindex (&rb, ctx))
      || (GNUNET_OK != readUploads (&rb, ctx)))
    {
      GNUNET_GE_BREAK (ctx->ectx, 0);
      GNUNET_GE_LOG (ctx->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("FSUI state file `%s' had syntax error at offset %u.\n"),
                     ctx->name, LSEEK (rb.fd, 0, SEEK_CUR));
    }
  CLOSE (rb.fd);
  UNLINK (ctx->name);
  GNUNET_free (rb.buffer);
}

/* end of deserialize.c */
