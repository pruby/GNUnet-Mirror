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


static int
read_int (int fd, int *val)
{
  int big;

  if (sizeof (int) != READ (fd, &big, sizeof (int)))
    return GNUNET_SYSERR;
  *val = ntohl (big);
  return GNUNET_OK;
}

#define READINT(a) if (GNUNET_OK != read_int(fd, (int*) &a)) return GNUNET_SYSERR;

static int
read_long (int fd, long long *val)
{
  long long big;

  if (sizeof (long long) != READ (fd, &big, sizeof (long long)))
    return GNUNET_SYSERR;
  *val = GNUNET_ntohll (big);
  return GNUNET_OK;
}

#define READLONG(a) if (GNUNET_OK != read_long(fd, (long long*) &a)) return GNUNET_SYSERR;

static struct ECRS_URI *
read_uri (struct GE_Context *ectx, int fd)
{
  char *buf;
  struct ECRS_URI *ret;
  unsigned int size;

  if (GNUNET_OK != read_int (fd, (int *) &size))
    return NULL;
  buf = GNUNET_malloc (size + 1);
  buf[size] = '\0';
  if (size != READ (fd, buf, size))
    {
      GNUNET_free (buf);
      return NULL;
    }
  ret = ECRS_stringToUri (ectx, buf);
  GE_BREAK (ectx, ret != NULL);
  GNUNET_free (buf);
  return ret;
}

#define READURI(u) if (NULL == (u = read_uri(ectx, fd))) return GNUNET_SYSERR;

static char *
read_string (int fd, unsigned int maxLen)
{
  char *buf;
  unsigned int big;

  if (GNUNET_OK != read_int (fd, (int *) &big))
    return NULL;
  if (big > maxLen)
    return NULL;
  buf = GNUNET_malloc (big + 1);
  buf[big] = '\0';
  if (big != READ (fd, buf, big))
    {
      GNUNET_free (buf);
      return NULL;
    }
  return buf;
}

#define READSTRING(c, max) if (NULL == (c = read_string(fd, max))) return GNUNET_SYSERR;

static void
fixState (FSUI_State * state)
{
  switch (*state)
    {                           /* try to correct errors */
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
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static struct ECRS_MetaData *
read_meta (struct GE_Context *ectx, int fd)
{
  unsigned int size;
  char *buf;
  struct ECRS_MetaData *meta;

  if (read_int (fd, (int *) &size) != GNUNET_OK)
    {
      GE_BREAK (ectx, 0);
      return NULL;
    }
  if (size > 1024 * 1024)
    {
      GE_BREAK (ectx, 0);
      return NULL;
    }
  buf = GNUNET_malloc (size);
  if (size != READ (fd, buf, size))
    {
      GNUNET_free (buf);
      GE_BREAK (ectx, 0);
      return NULL;
    }
  meta = ECRS_deserializeMetaData (ectx, buf, size);
  if (meta == NULL)
    {
      GNUNET_free (buf);
      GE_BREAK (ectx, 0);
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
readFileInfo (struct GE_Context *ectx, int fd, ECRS_FileInfo * fi)
{
  fi->meta = read_meta (ectx, fd);
  if (fi->meta == NULL)
    {
      GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;
    }
  fi->uri = NULL;

  fi->uri = read_uri (ectx, fd);
  if (fi->uri == NULL)
    {
      ECRS_freeMetaData (fi->meta);
      fi->meta = NULL;
      GE_BREAK (ectx, 0);
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
static FSUI_DownloadList *
readDownloadList (struct GE_Context *ectx,
                  int fd, FSUI_Context * ctx, FSUI_DownloadList * parent)
{
  FSUI_DownloadList *ret;
  FSUI_SearchList *pos;
  unsigned int big;
  int i;
  int ok;
  int soff;

  GE_ASSERT (ectx, ctx != NULL);
  if ((GNUNET_OK != read_int (fd, (int *) &big)) || (big == 0))
    return NULL;
  ret = GNUNET_malloc (sizeof (FSUI_DownloadList));
  memset (ret, 0, sizeof (FSUI_DownloadList));
  ret->ctx = ctx;
  if ((GNUNET_OK != read_int (fd, (int *) &soff)) ||
      (GNUNET_OK != read_int (fd, (int *) &ret->state)) ||
      (GNUNET_OK != read_int (fd, (int *) &ret->is_recursive)) ||
      (GNUNET_OK != read_int (fd, (int *) &ret->is_directory)) ||
      (GNUNET_OK != read_int (fd, (int *) &ret->anonymityLevel)) ||
      (GNUNET_OK != read_int (fd, (int *) &ret->completedDownloadsCount)) ||
      (GNUNET_OK != read_long (fd, (long long *) &ret->total)) ||
      (GNUNET_OK != read_long (fd, (long long *) &ret->completed)) ||
      (GNUNET_OK != read_long (fd, (long long *) &ret->runTime)) ||
      (GNUNET_OK != read_int (fd, (int *) &big)) || (big > 1024 * 1024))
    {
      GE_BREAK (NULL, 0);
      GNUNET_free (ret);
      return NULL;
    }
  fixState (&ret->state);
  ret->filename = GNUNET_malloc (big + 1);
  ret->filename[big] = '\0';
  if (big != READ (fd, ret->filename, big))
    {
      GE_BREAK (ectx, 0);
      GNUNET_free (ret->filename);
      GNUNET_free (ret);
      return NULL;
    }
  if (GNUNET_OK != readFileInfo (ectx, fd, &ret->fi))
    {
      GE_BREAK (NULL, 0);
      GNUNET_free (ret->filename);
      GNUNET_free (ret);
      return NULL;
    }
  if (ret->completedDownloadsCount > 0)
    ret->completedDownloads
      =
      GNUNET_malloc (sizeof (struct ECRS_URI *) *
                     ret->completedDownloadsCount);
  ok = GNUNET_YES;
  for (i = 0; i < ret->completedDownloadsCount; i++)
    {
      ret->completedDownloads[i] = read_uri (ectx, fd);
      if (ret->completedDownloads[i] == NULL)
        {
          GE_BREAK (NULL, 0);
          ok = GNUNET_NO;
        }
    }
  if (GNUNET_NO == ok)
    {
      GNUNET_free (ret->filename);
      ECRS_freeUri (ret->fi.uri);
      ECRS_freeMetaData (ret->fi.meta);
      for (i = 0; i < ret->completedDownloadsCount; i++)
        {
          if (ret->completedDownloads[i] != NULL)
            ECRS_freeUri (ret->completedDownloads[i]);
        }
      GNUNET_free (ret->completedDownloads);
      GNUNET_free (ret);
      GE_BREAK (NULL, 0);
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
              GE_BREAK (NULL, 0);
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
  ret->next = readDownloadList (ectx, fd, ctx, parent);
  ret->child = readDownloadList (ectx, fd, ctx, ret);
#if DEBUG_PERSISTENCE
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "FSUI persistence: restoring download `%s': (%llu, %llu)\n",
          ret->filename, ret->completed, ret->total);
#endif
  return ret;
}

static int
checkMagic (int fd)
{
  char magic[8];

  if (8 != READ (fd, magic, 8))
    {
      GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  if (0 != memcmp (magic, "FSUI01\n\0", 8))
    {
      GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

static int
readCollection (int fd, struct FSUI_Context *ctx)
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
      GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  ctx->collectionData = GNUNET_malloc (big);
  if (big - sizeof (unsigned int) !=
      READ (fd, &ctx->collectionData[1], big - sizeof (unsigned int)))
    {
      GNUNET_free (ctx->collectionData);
      ctx->collectionData = NULL;
      GE_BREAK (NULL, 0);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

static int
readSearches (int fd, struct FSUI_Context *ctx)
{
  int big;
  FSUI_SearchList *list;
  FSUI_SearchList *last;
  int i;
  ResultPending *rp;
  char *buf;
  GNUNET_CronTime stime;

  while (1)
    {
      READINT (big);
      if (big == 0)
        return GNUNET_OK;
      list = GNUNET_malloc (sizeof (FSUI_SearchList));
      memset (list, 0, sizeof (FSUI_SearchList));
      if ((GNUNET_OK != read_int (fd, (int *) &list->state)) ||
          (GNUNET_OK != read_int (fd, (int *) &list->maxResults)) ||
          (GNUNET_OK != read_long (fd, (long long *) &list->timeout)) ||
          (GNUNET_OK != read_long (fd, (long long *) &list->start_time)) ||
          (GNUNET_OK != read_long (fd, (long long *) &stime)) ||
          (GNUNET_OK != read_int (fd, (int *) &list->anonymityLevel)) ||
          (GNUNET_OK != read_int (fd, (int *) &list->sizeResultsReceived)) ||
          (GNUNET_OK !=
           read_int (fd, (int *) &list->sizeUnmatchedResultsReceived))
          || (list->sizeResultsReceived > 1024 * 1024)
          || (list->sizeUnmatchedResultsReceived > 1024 * 1024))
        {
          GE_BREAK (NULL, 0);
          break;
        }
      fixState (&list->state);
      if (stime > GNUNET_get_time ())
        stime = GNUNET_get_time ();
      list->start_time += GNUNET_get_time () - stime;
      buf = read_string (fd, 1024 * 1024);
      if (buf == NULL)
        {
          GE_BREAK (NULL, 0);
          break;
        }
      list->uri = ECRS_stringToUri (NULL, buf);
      GNUNET_free (buf);
      if (list->uri == NULL)
        {
          GE_BREAK (NULL, 0);
          break;
        }
      if (!(ECRS_isKeywordUri (list->uri) || ECRS_isNamespaceUri (list->uri)))
        {
          GE_BREAK (NULL, 0);
          break;
        }
      list->numberOfURIKeys = ECRS_countKeywordsOfUri (list->uri);
      if (list->sizeResultsReceived > 0)
        {
          list->resultsReceived
            =
            GNUNET_malloc (list->sizeResultsReceived *
                           sizeof (ECRS_FileInfo));
          memset (list->resultsReceived, 0,
                  list->sizeResultsReceived * sizeof (ECRS_FileInfo));
        }
      if (list->sizeUnmatchedResultsReceived > 0)
        {
          list->unmatchedResultsReceived
            = GNUNET_malloc (list->sizeUnmatchedResultsReceived *
                             sizeof (ResultPending));
          memset (list->unmatchedResultsReceived,
                  0,
                  list->sizeUnmatchedResultsReceived *
                  sizeof (ResultPending));
        }
      for (i = 0; i < list->sizeResultsReceived; i++)
        if (GNUNET_OK !=
            readFileInfo (ctx->ectx, fd, &list->resultsReceived[i]))
          {
            GE_BREAK (NULL, 0);
            goto ERR;
          }
      for (i = 0; i < list->sizeUnmatchedResultsReceived; i++)
        {
          rp = &list->unmatchedResultsReceived[i];
          if (GNUNET_OK != readFileInfo (ctx->ectx, fd, &rp->fi))
            {
              GE_BREAK (NULL, 0);
              goto ERR;
            }
          if (GNUNET_OK != read_int (fd, (int *) &rp->matchingKeyCount))
            {
              GE_BREAK (NULL, 0);
              goto ERR;
            }
          if ((rp->matchingKeyCount > 1024) ||
              (rp->matchingKeyCount >= list->numberOfURIKeys))
            {
              GE_BREAK (NULL, 0);
              goto ERR;
            }
          if (rp->matchingKeyCount > 0)
            {
              rp->matchingKeys
                =
                GNUNET_malloc (sizeof (GNUNET_HashCode) *
                               rp->matchingKeyCount);
              if (sizeof (GNUNET_HashCode) * rp->matchingKeyCount !=
                  READ (fd, rp->matchingKeys,
                        sizeof (GNUNET_HashCode) * rp->matchingKeyCount))
                {
                  GE_BREAK (NULL, 0);
                  goto ERR;
                }
            }
        }
      list->ctx = ctx;
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
  if (list->resultsReceived != NULL)
    {
      for (i = 0; i < list->sizeResultsReceived; i++)
        {
          if (list->resultsReceived[i].uri != NULL)
            ECRS_freeUri (list->resultsReceived[i].uri);
          if (list->resultsReceived[i].meta != NULL)
            ECRS_freeMetaData (list->resultsReceived[i].meta);
        }
      GNUNET_array_grow (list->resultsReceived, list->sizeResultsReceived, 0);
    }
  if (list->unmatchedResultsReceived != NULL)
    {
      for (i = 0; i < list->sizeUnmatchedResultsReceived; i++)
        {
          rp = &list->unmatchedResultsReceived[i];

          if (rp->fi.uri != NULL)
            ECRS_freeUri (rp->fi.uri);
          if (rp->fi.meta != NULL)
            ECRS_freeMetaData (rp->fi.meta);
          GNUNET_free_non_null (rp->matchingKeys);
        }
      GNUNET_array_grow (list->resultsReceived, list->sizeResultsReceived, 0);
    }
  if (list->uri != NULL)
    ECRS_freeUri (list->uri);
  GNUNET_free (list);
  return GNUNET_SYSERR;
}

static int
readDownloads (int fd, struct FSUI_Context *ctx)
{
  memset (&ctx->activeDownloads, 0, sizeof (FSUI_DownloadList));
  ctx->activeDownloads.child
    = readDownloadList (ctx->ectx, fd, ctx, &ctx->activeDownloads);
  return GNUNET_OK;
}

static int
readUploadList (struct FSUI_Context *ctx,
                struct FSUI_UploadList *parent,
                int fd, struct FSUI_UploadShared *shared, int top)
{
  struct FSUI_UploadList *list;
  struct FSUI_UploadList l;
  unsigned long long stime;
  int big;
  int bag;
  struct GE_Context *ectx;

  ectx = ctx->ectx;
  GE_ASSERT (ectx, shared != NULL);
  while (1)
    {
      READINT (big);
      if (big == 0)
        return GNUNET_OK;
      if ((big < 1) || (big > 15))
        {
          GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      READINT (bag);
      if (bag != 0x34D1F023)
        {
          GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      memset (&l, 0, sizeof (FSUI_UploadList));
      READINT (l.state);
      fixState (&l.state);
      if (l.state == FSUI_PENDING)
        l.state = FSUI_ACTIVE;
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
          l.keywords = read_uri (ctx->ectx, fd);
          if (l.keywords == NULL)
            {
              if (l.uri != NULL)
                ECRS_freeUri (l.uri);
              GE_BREAK (NULL, 0);
              break;
            }
        }
      if ((big & 8) == 8)
        {
          l.meta = read_meta (ctx->ectx, fd);
          if (l.meta == NULL)
            {
              if (l.uri != NULL)
                ECRS_freeUri (l.uri);
              if (l.keywords != NULL)
                ECRS_freeUri (l.keywords);
              GE_BREAK (NULL, 0);
              break;
            }
        }
      l.filename = read_string (fd, 1024 * 1024);
      if (l.filename == NULL)
        {
          if (l.uri != NULL)
            ECRS_freeUri (l.uri);
          if (l.meta != NULL)
            ECRS_freeMetaData (l.meta);
          if (l.keywords != NULL)
            ECRS_freeUri (l.keywords);
          GE_BREAK (NULL, 0);
          break;
        }
      list = GNUNET_malloc (sizeof (struct FSUI_UploadList));
      memcpy (list, &l, sizeof (struct FSUI_UploadList));
      list->shared = shared;
      list->parent = parent;
      if (GNUNET_OK != readUploadList (ctx, list, fd, shared, GNUNET_NO))
        {
          if (l.uri != NULL)
            ECRS_freeUri (l.uri);
          GNUNET_free (l.filename);
          GNUNET_free (list);
          GE_BREAK (NULL, 0);
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
readUploads (int fd, struct FSUI_Context *ctx)
{
  int big;
  int bag;
  struct FSUI_UploadShared *shared;
  struct FSUI_UploadShared sshared;

  memset (&ctx->activeUploads, 0, sizeof (FSUI_UploadList));
  while (1)
    {
      READINT (big);
      if (big == 0)
        return GNUNET_OK;
      if ((big < 1) && (big > 7))
        {
          GE_BREAK (NULL, 0);
          break;
        }
      READINT (bag);
      if (bag != 0x44D1F024)
        {
          GE_BREAK (NULL, 0);
          return GNUNET_SYSERR;
        }
      memset (&sshared, 0, sizeof (FSUI_UploadShared));
      READINT (sshared.doIndex);
      READINT (sshared.anonymityLevel);
      READINT (sshared.priority);
      READINT (sshared.individualKeywords);
      READLONG (sshared.expiration);
      if ((big & 2) == 2)
        READSTRING (sshared.extractor_config, 1024 * 1024);
      if ((big & 4) == 4)
        {
          sshared.global_keywords = read_uri (ctx->ectx, fd);
          if (sshared.global_keywords == NULL)
            {
              GNUNET_free_non_null (sshared.extractor_config);
              GE_BREAK (NULL, 0);
              return GNUNET_SYSERR;
            }
        }
      shared = GNUNET_malloc (sizeof (FSUI_UploadShared));
      memcpy (shared, &sshared, sizeof (FSUI_UploadShared));
      shared->ctx = ctx;
      if (GNUNET_OK !=
          readUploadList (ctx, &ctx->activeUploads, fd, shared, GNUNET_YES))
        {
          GE_BREAK (NULL, 0);
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
readUnindex (int fd, struct FSUI_Context *ctx)
{
  int big;
  char *name;
  struct FSUI_UnindexList *ul;

  while (1)
    {
      READINT (big);
      if (big != 1)
        return GNUNET_OK;
      READINT (big);            /* state */
      READSTRING (name, 1024 * 1024);
      ul = GNUNET_malloc (sizeof (struct FSUI_UnindexList));
      ul->state = big;
      ul->filename = name;
      ul->next = ctx->unindexOperations;
      ul->ctx = ctx;
      ctx->unindexOperations = ul;
    }
  return GNUNET_SYSERR;
}


void
FSUI_deserialize (struct FSUI_Context *ctx)
{
  int fd;

  fd = -1;
  if (0 != ACCESS (ctx->name, R_OK))
    return;
  fd = GNUNET_disk_file_open (ctx->ectx, ctx->name, O_RDONLY);
  if (fd == -1)
    return;

  if ((GNUNET_OK != checkMagic (fd)) ||
      (GNUNET_OK != readCollection (fd, ctx)) ||
      (GNUNET_OK != readSearches (fd, ctx)) ||
      (GNUNET_OK != readDownloads (fd, ctx)) ||
      (GNUNET_OK != readUnindex (fd, ctx))
      || (GNUNET_OK != readUploads (fd, ctx)))
    {
      GE_BREAK (ctx->ectx, 0);
      GE_LOG (ctx->ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _("FSUI state file `%s' had syntax error at offset %u.\n"),
              ctx->name, LSEEK (fd, 0, SEEK_CUR));
    }
  CLOSE (fd);
  UNLINK (ctx->name);
}
