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
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_uritrack_lib.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_identity_lib.h"
#include "fsui.h"
#include <extractor.h>

#define DEBUG_UPLOAD GNUNET_NO

/**
 * Transform an ECRS progress callback into an FSUI event.
 *
 * @param direct is this a direct ECRS trigger, or a recursive
 *        call from a child signaling progress to the parent?
 */
static void
progressCallbackR (unsigned long long totalBytes,
                   unsigned long long completedBytes, GNUNET_CronTime eta,
                   void *ptr, int direct, int add, int unaccounted)
{
  GNUNET_FSUI_UploadList *utc = ptr;
  GNUNET_FSUI_Event event;
  unsigned long long subtotal;
  GNUNET_FSUI_UploadList *pos;
  GNUNET_CronTime xeta;
  GNUNET_CronTime now;

  event.type = GNUNET_FSUI_upload_progress;
  event.data.UploadProgress.uc.pos = utc;
  event.data.UploadProgress.uc.cctx = utc->cctx;
  event.data.UploadProgress.uc.ppos = utc->parent;
  event.data.UploadProgress.uc.pcctx = utc->parent->cctx;
  if (GNUNET_YES == GNUNET_meta_data_test_for_directory (utc->meta))
    {
      if (direct == GNUNET_YES)
        unaccounted = GNUNET_YES;
      if ((direct == GNUNET_YES) && (totalBytes == completedBytes))
        add = GNUNET_YES;
      if (add == GNUNET_NO)
        {
          event.data.UploadProgress.completed =
            completedBytes + utc->completed;
          event.data.UploadProgress.total =
            utc->total + ((unaccounted == GNUNET_NO) ? 0 : totalBytes);
          if (totalBytes == completedBytes)
            utc->completed += completedBytes;
        }
      else
        {
          GNUNET_GE_ASSERT (NULL, totalBytes == completedBytes);
          event.data.UploadProgress.completed =
            completedBytes + utc->completed;
          event.data.UploadProgress.total = totalBytes + utc->total;
          utc->total += completedBytes;
          utc->completed += completedBytes;
        }
    }
  else
    {
      /* simple file upload */
      event.data.UploadProgress.completed = completedBytes;
      event.data.UploadProgress.total = totalBytes;
      utc->completed = completedBytes;
    }
  event.data.UploadProgress.eta = eta;
  event.data.UploadProgress.filename = utc->filename;
  utc->shared->ctx->ecb (utc->shared->ctx->ecbClosure, &event);
  if (utc->parent != &utc->shared->ctx->activeUploads)
    {
      subtotal = 0;
      pos = utc->parent->child;
      while (pos != NULL)
        {
          subtotal += pos->completed;
          pos = pos->next;
        }
      now = GNUNET_get_time ();
      xeta = now;
      if (subtotal > 0)
        {
          xeta = (GNUNET_CronTime) (utc->parent->start_time +
                                    (((double) (now - utc->parent->start_time)
                                      / (double) subtotal)) *
                                    (double) utc->parent->total);
        }
      progressCallbackR (totalBytes, completedBytes, xeta, utc->parent,
                         GNUNET_NO, add, unaccounted);
    }
}

/**
 * Transform an ECRS progress callback into an FSUI event.
 */
static void
progressCallback (unsigned long long totalBytes,
                  unsigned long long completedBytes, GNUNET_CronTime eta,
                  void *ptr)
{
  progressCallbackR (totalBytes, completedBytes, eta, ptr, GNUNET_YES,
                     GNUNET_NO, GNUNET_NO);
}

static int
testTerminate (void *cls)
{
  GNUNET_FSUI_UploadList *utc = cls;
  if (utc->state != GNUNET_FSUI_ACTIVE)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Take the current directory entries from utc, create
 * a directory, upload it and store the uri in  *uri.
 */
static char *
createDirectoryHelper (struct GNUNET_GE_Context *ectx,
                       struct GNUNET_GC_Configuration *cfg,
                       struct GNUNET_FSUI_UploadList *children,
                       struct GNUNET_MetaData *meta, char **error)
{
  GNUNET_ECRS_FileInfo *fis;
  unsigned int count;
  unsigned int size;
  char *data;
  unsigned long long len;
  int ret;
  char *tempName;
  struct GNUNET_FSUI_UploadList *pos;
  int handle;
  struct GNUNET_GE_Memory *mem;
  struct GNUNET_GE_Context *ee;

  fis = NULL;
  size = 0;
  count = 0;
  pos = children;
  while (pos != NULL)
    {
      if (pos->uri != NULL)
        count++;
      pos = pos->next;
    }
  GNUNET_array_grow (fis, size, count);
  count = 0;
  pos = children;
  while (pos != NULL)
    {
      if (pos->uri != NULL)
        {
          fis[count].uri = pos->uri;
          fis[count].meta = pos->meta;
          count++;
        }
      pos = pos->next;
    }
  GNUNET_GE_BREAK (ectx, count == size);
  mem = GNUNET_GE_memory_create (2);
  ee =
    GNUNET_GE_create_context_memory (GNUNET_GE_USER | GNUNET_GE_ADMIN |
                                     GNUNET_GE_ERROR | GNUNET_GE_WARNING |
                                     GNUNET_GE_FATAL | GNUNET_GE_BULK |
                                     GNUNET_GE_IMMEDIATE, mem);
  ret = GNUNET_ECRS_directory_create (ee, &data, &len, size, fis, meta);
  GNUNET_array_grow (fis, size, 0);
  if (ret != GNUNET_OK)
    {
      *error = GNUNET_strdup (GNUNET_GE_memory_get (mem, 0));
      GNUNET_GE_free_context (ee);
      GNUNET_GE_memory_free (mem);
      return NULL;
    }
  pos = children;
  while (pos != NULL)
    {
      if (pos->uri != NULL)
        GNUNET_URITRACK_add_state (ectx, cfg, pos->uri,
                                   GNUNET_URITRACK_DIRECTORY_ADDED);
      pos = pos->next;
    }
  GNUNET_GE_memory_reset (mem);
  tempName = GNUNET_strdup ("/tmp/gnunet-upload-dir.XXXXXX");
  handle = mkstemp (tempName);
  if (handle == -1)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ee,
                                   GNUNET_GE_ERROR | GNUNET_GE_USER |
                                   GNUNET_GE_BULK, "mkstemp", tempName);
      GNUNET_free (tempName);
      GNUNET_free (data);
      *error = GNUNET_strdup (GNUNET_GE_memory_get (mem, 0));
      GNUNET_GE_free_context (ee);
      GNUNET_GE_memory_free (mem);
      return NULL;
    }
  if (len != WRITE (handle, data, len))
    {
      GNUNET_GE_LOG_STRERROR_FILE (ee,
                                   GNUNET_GE_ERROR | GNUNET_GE_USER |
                                   GNUNET_GE_BULK, "write", tempName);
      *error = GNUNET_strdup (GNUNET_GE_memory_get (mem, 0));
      GNUNET_GE_free_context (ee);
      GNUNET_GE_memory_free (mem);
      GNUNET_free (data);
      return NULL;
    }
  GNUNET_GE_free_context (ee);
  GNUNET_GE_memory_free (mem);
  CLOSE (handle);
  GNUNET_free (data);
  return tempName;
}

/**
 * Signal upload error to client.
 */
static void
signalError (GNUNET_FSUI_UploadList * utc, const char *message)
{
  GNUNET_FSUI_Event event;

  utc->state = GNUNET_FSUI_ERROR;
  event.type = GNUNET_FSUI_upload_error;
  event.data.UploadError.uc.pos = utc;
  event.data.UploadError.uc.cctx = utc->cctx;
  event.data.UploadError.uc.ppos = utc->parent;
  event.data.UploadError.uc.pcctx = utc->parent->cctx;
  event.data.UploadError.message = message;
  utc->shared->ctx->ecb (utc->shared->ctx->ecbClosure, &event);
}

static void
signalUploadStarted (struct GNUNET_FSUI_UploadList *utc, int first_only)
{
  GNUNET_FSUI_Event event;

  while (utc != NULL)
    {
      event.type = GNUNET_FSUI_upload_started;
      event.data.UploadStarted.uc.pos = utc;
      event.data.UploadStarted.uc.cctx = utc->cctx;
      event.data.UploadStarted.uc.ppos = utc->parent;
      event.data.UploadStarted.uc.pcctx = utc->parent->cctx;
      event.data.UploadStarted.total = utc->total;
      event.data.UploadStarted.anonymityLevel = utc->shared->anonymityLevel;
      event.data.UploadStarted.filename = utc->filename;
      utc->cctx = utc->shared->ctx->ecb (utc->shared->ctx->ecbClosure,
                                         &event);
      signalUploadStarted (utc->child, 0);
      if (first_only)
        break;
      utc = utc->next;
    }
}

/**
 * Thread that does the upload.
 */
void *
GNUNET_FSUI_uploadThread (void *cls)
{
  GNUNET_FSUI_UploadList *utc = cls;
  GNUNET_FSUI_UploadList *cpos;
  GNUNET_FSUI_Event event;
  GNUNET_ECRS_FileInfo fi;
  int ret;
  int is_directory;
  struct GNUNET_GE_Context *ectx;
  char *filename;
  char *pfn;
  struct GNUNET_ECRS_URI *uri;
  struct GNUNET_ECRS_URI *loc;
  size_t tpos;
  size_t tend;
  char *error;
  struct GNUNET_GE_Memory *mem;
  struct GNUNET_GE_Context *ee;

  ectx = utc->shared->ctx->ectx;
  GNUNET_GE_ASSERT (ectx, utc->filename != NULL);
  cpos = utc->child;
  while (cpos != NULL)
    {
      if (cpos->state == GNUNET_FSUI_ACTIVE)
        GNUNET_FSUI_uploadThread (cpos);
      cpos = cpos->next;
    }
  if (utc->state != GNUNET_FSUI_ACTIVE)
    return NULL;                /* aborted or suspended */
  if (GNUNET_shutdown_test ())
    {
      signalError (utc, _("Application aborted."));
      return NULL;
    }
  if (GNUNET_YES == GNUNET_disk_directory_test (ectx, utc->filename))
    {
      error = NULL;
      is_directory = 1;
      filename = createDirectoryHelper (ectx,
                                        utc->shared->ctx->cfg,
                                        utc->child, utc->meta, &error);
      if (filename == NULL)
        {
          if (error == NULL)
            error =
              GNUNET_strdup (_("Failed to create temporary directory."));
          signalError (utc, error);
          GNUNET_free (error);
          return NULL;
        }
    }
  else
    {
      is_directory = 0;
      filename = GNUNET_strdup (utc->filename);
    }
  utc->start_time = GNUNET_get_time ();
  mem = GNUNET_GE_memory_create (2);
  ee =
    GNUNET_GE_create_context_memory (GNUNET_GE_USER | GNUNET_GE_ADMIN |
                                     GNUNET_GE_ERROR | GNUNET_GE_WARNING |
                                     GNUNET_GE_FATAL | GNUNET_GE_BULK |
                                     GNUNET_GE_IMMEDIATE, mem);
  ret =
    GNUNET_ECRS_file_upload (ee, utc->shared->ctx->cfg, filename,
                             utc->shared->doIndex ==
                             GNUNET_YES ? (utc->child ==
                                           NULL ? GNUNET_YES : GNUNET_NO) :
                             utc->shared->doIndex,
                             utc->shared->anonymityLevel,
                             utc->shared->priority, utc->shared->expiration,
                             &progressCallback, utc, &testTerminate, utc,
                             &utc->uri);
  if (ret != GNUNET_OK)
    {
      if (utc->state == GNUNET_FSUI_ACTIVE)
        {
          const char *err;

          err = GNUNET_GE_memory_get (mem, 0);
          signalError (utc, err ? err : "");
        }
      else if (utc->state == GNUNET_FSUI_ABORTED)
        {
          event.type = GNUNET_FSUI_upload_aborted;
          event.data.UploadAborted.uc.pos = utc;
          event.data.UploadAborted.uc.cctx = utc->cctx;
          event.data.UploadAborted.uc.ppos = utc->parent;
          event.data.UploadAborted.uc.pcctx = utc->parent->cctx;
          utc->shared->ctx->ecb (utc->shared->ctx->ecbClosure, &event);
        }
      else
        {
          /* must be suspended */
          GNUNET_GE_BREAK (NULL, utc->state == GNUNET_FSUI_PENDING);
        }
      if (utc->child != NULL)
        UNLINK (filename);
      GNUNET_free (filename);
      GNUNET_GE_free_context (ee);
      GNUNET_GE_memory_free (mem);
      return NULL;
    }
  utc->state = GNUNET_FSUI_COMPLETED;
  if (utc->shared->doIndex != GNUNET_SYSERR)
    {
      if (utc->child == NULL)
        GNUNET_meta_data_extract_from_file (utc->shared->ctx->ectx,
                                            utc->meta, utc->filename,
                                            utc->shared->extractors);
      while (GNUNET_OK ==
             GNUNET_meta_data_delete (utc->meta, EXTRACTOR_FILENAME, NULL));
      /* only publish the last part of the path
         -- we do not want to publish $HOME or similar
         trivially deanonymizing information */
      tpos = strlen (utc->filename) - 1;
      if ((utc->filename[tpos] == DIR_SEPARATOR) && (tpos > 0))
        tpos--;
      while ((tpos > 0) && (utc->filename[tpos] != DIR_SEPARATOR))
        tpos--;
      pfn = GNUNET_malloc (strlen (&utc->filename[tpos + 1]) + 2);
      strcpy (pfn, &utc->filename[tpos + 1]);
      if ((is_directory || (utc->child != NULL)) &&
          ((strlen (pfn) == 0) || (pfn[strlen (pfn) - 1] != DIR_SEPARATOR)))
        strcat (pfn, DIR_SEPARATOR_STR);
      GNUNET_meta_data_insert (utc->meta, EXTRACTOR_FILENAME, pfn);
      GNUNET_free (pfn);
      if (0 != strcmp (utc->shared->top_filename, utc->filename))
        {
          /* this is NOT the top-level upload, so we
             should add the directory name of our
             parent to the meta data */
          tend = tpos;          /* index of '/' */
          if ((utc->filename[tpos] == DIR_SEPARATOR) && (tpos > 0))
            tpos--;
          while ((tpos > 0) && (utc->filename[tpos] != DIR_SEPARATOR))
            tpos--;
          if (tpos + 1 < tend)
            {
              char *p;
              pfn = p = GNUNET_malloc (tend - tpos + 1);
              pfn[tend - tpos] = '\0';
              memcpy (pfn, &utc->filename[tpos + 1], tend - tpos);
              /* change OS native dir separators to unix '/' and others to '_' */
              while (*p != '\0')
                {
                  if (*p == DIR_SEPARATOR)
                    *p = '/';
                  else if (*p == '\\')
                    *p = '_';
                  p++;
                }
              GNUNET_meta_data_insert (utc->meta, EXTRACTOR_RELATION, pfn);
              GNUNET_free (pfn);
            }
        }
      if ((utc->shared->anonymityLevel == 0)
          && (utc->shared->doIndex == GNUNET_YES))
        {
          /* generate location URI for non-anonymous download */
          struct GNUNET_ClientServerConnection *sock;
          GNUNET_MessageHello *hello;

          sock = GNUNET_client_connection_create (utc->shared->ctx->ectx,
                                                  utc->shared->ctx->cfg);

          if (GNUNET_OK == GNUNET_IDENTITY_get_self (sock, &hello))
            {
              loc = GNUNET_ECRS_location_to_uri (utc->uri,
                                                 &hello->publicKey,
                                                 ntohl
                                                 (hello->expiration_time),
                                                 (GNUNET_ECRS_SignFunction) &
                                                 GNUNET_IDENTITY_sign_function,
                                                 sock);

              GNUNET_free (hello);
            }
          else
            {
              /* may happen if no transports are available... */
              loc = GNUNET_ECRS_uri_duplicate (utc->uri);
            }
          GNUNET_client_connection_destroy (sock);
        }
      else
        {
          /* no location URI, use standard URI
             (copied here to allow free later) */
          loc = GNUNET_ECRS_uri_duplicate (utc->uri);
        }
      while (GNUNET_OK ==
             GNUNET_meta_data_delete (utc->meta, EXTRACTOR_SPLIT, NULL));
      while (GNUNET_OK ==
             GNUNET_meta_data_delete (utc->meta, EXTRACTOR_LOWERCASE, NULL));
      if (utc->shared->global_keywords != NULL)
        GNUNET_ECRS_publish_under_keyword (ectx,
                                           utc->shared->ctx->cfg,
                                           utc->shared->global_keywords,
                                           utc->shared->anonymityLevel,
                                           utc->shared->priority,
                                           utc->shared->expiration, loc,
                                           utc->meta);
      if (utc->keywords != NULL)
        GNUNET_ECRS_publish_under_keyword (ectx,
                                           utc->shared->ctx->cfg,
                                           utc->keywords,
                                           utc->shared->anonymityLevel,
                                           utc->shared->priority,
                                           utc->shared->expiration, loc,
                                           utc->meta);
      if (utc->shared->individualKeywords == GNUNET_YES)
        {
          uri = GNUNET_meta_data_to_uri (utc->meta);
          GNUNET_ECRS_publish_under_keyword (ectx,
                                             utc->shared->ctx->cfg,
                                             uri,
                                             utc->shared->anonymityLevel,
                                             utc->shared->priority,
                                             utc->shared->expiration, loc,
                                             utc->meta);
          GNUNET_ECRS_uri_destroy (uri);
        }
      GNUNET_ECRS_uri_destroy (loc);
      loc = NULL;
      fi.meta = utc->meta;
      fi.uri = utc->uri;
      if (utc->shared->doIndex != GNUNET_SYSERR)
        {
          GNUNET_URITRACK_track (ectx, utc->shared->ctx->cfg, &fi);
          GNUNET_URITRACK_add_state (ectx,
                                     utc->shared->ctx->cfg,
                                     utc->uri,
                                     utc->shared->doIndex ==
                                     GNUNET_YES ? GNUNET_URITRACK_INDEXED :
                                     GNUNET_URITRACK_INSERTED);
        }
    }
  event.type = GNUNET_FSUI_upload_completed;
  event.data.UploadCompleted.uc.pos = utc;
  event.data.UploadCompleted.uc.cctx = utc->cctx;
  event.data.UploadCompleted.uc.ppos = utc->parent;
  event.data.UploadCompleted.uc.pcctx = utc->parent->cctx;
  event.data.UploadCompleted.total = utc->total;
  event.data.UploadCompleted.filename = utc->filename;
  event.data.UploadCompleted.uri = utc->uri;
  utc->shared->ctx->ecb (utc->shared->ctx->ecbClosure, &event);
  if (utc->child != NULL)
    UNLINK (filename);
  GNUNET_free (filename);
  GNUNET_GE_free_context (ee);
  GNUNET_GE_memory_free (mem);
  return NULL;
}

/**
 * Thread that does the upload.
 */
static void *
GNUNET_FSUI_uploadThreadEvent (void *cls)
{
  GNUNET_FSUI_UploadList *utc = cls;

  if (utc->parent == &utc->shared->ctx->activeUploads)
    {
      /* top-level call: signal client! */
      signalUploadStarted (utc, 1);
    }
  return GNUNET_FSUI_uploadThread (utc);
}


static void
freeUploadList (struct GNUNET_FSUI_UploadList *ul)
{
  struct GNUNET_FSUI_UploadList *next;
  struct GNUNET_FSUI_Context *ctx;

  ctx = ul->shared->ctx;
  while (ul->child != NULL)
    freeUploadList (ul->child);
  GNUNET_mutex_lock (ctx->lock);
  GNUNET_free (ul->filename);
  if (ul->keywords != NULL)
    GNUNET_ECRS_uri_destroy (ul->keywords);
  if (ul->uri != NULL)
    {
      GNUNET_ECRS_uri_destroy (ul->uri);
      ul->uri = NULL;
    }
  if (ul->meta != NULL)
    {
      GNUNET_meta_data_destroy (ul->meta);
      ul->meta = NULL;
    }
  /* unlink from parent */
  next = ul->parent->child;
  if (next == NULL)
    {
      GNUNET_GE_BREAK (NULL, 0);
      GNUNET_mutex_unlock (ctx->lock);
      return;
    }
  if (next == ul)
    {
      ul->parent->child = ul->next;
    }
  else
    {
      while (next->next != ul)
        {
          next = next->next;
          if (next == NULL)
            {
              GNUNET_GE_BREAK (NULL, 0);
              GNUNET_mutex_unlock (ctx->lock);
              return;
            }
        }
      next->next = ul->next;
    }
  GNUNET_free (ul);
  GNUNET_mutex_unlock (ctx->lock);
}

static struct GNUNET_FSUI_UploadList *addUploads (struct
                                                  GNUNET_FSUI_UploadShared
                                                  *shared,
                                                  const char *filename,
                                                  const struct GNUNET_ECRS_URI
                                                  *keywords,
                                                  const struct
                                                  GNUNET_MetaData *md,
                                                  struct
                                                  GNUNET_FSUI_UploadList
                                                  *parent);

static int
addChildUpload (const char *name, const char *dirName, void *data)
{
  struct GNUNET_FSUI_UploadList *parent = data;
  char *filename;
  struct GNUNET_FSUI_UploadList *child;
  struct GNUNET_MetaData *md_tmp;

  filename = GNUNET_malloc (strlen (dirName) + strlen (name) + 2);
  strcpy (filename, dirName);
  if (dirName[strlen (dirName) - 1] != DIR_SEPARATOR)
    strcat (filename, DIR_SEPARATOR_STR);
  strcat (filename, name);
  md_tmp = GNUNET_meta_data_create ();
  child = addUploads (parent->shared, filename, NULL, md_tmp, parent);
  GNUNET_free (filename);
  GNUNET_meta_data_destroy (md_tmp);
  if (child == NULL)
    return GNUNET_SYSERR;
  parent->total += child->total;
  return GNUNET_OK;
}

static struct GNUNET_FSUI_UploadList *
addUploads (struct GNUNET_FSUI_UploadShared *shared,
            const char *filename,
            const struct GNUNET_ECRS_URI *keywords,
            const struct GNUNET_MetaData *md,
            struct GNUNET_FSUI_UploadList *parent)
{
  GNUNET_FSUI_UploadList *utc;

  utc = GNUNET_malloc (sizeof (GNUNET_FSUI_UploadList));
  utc->completed = 0;
  utc->total = 0;               /* to be set later */
  utc->start_time = GNUNET_get_time ();
  utc->shared = shared;
  utc->next = NULL;
  utc->child = NULL;
  utc->parent = parent;
  utc->uri = NULL;
  utc->cctx = NULL;             /* to be set later */
  utc->state = GNUNET_FSUI_ACTIVE;
  if (GNUNET_YES == GNUNET_disk_file_test (shared->ctx->ectx, filename))
    {
      utc->is_directory = GNUNET_NO;
      /* add this file */
      if (GNUNET_OK != GNUNET_disk_file_size (shared->ctx->ectx,
                                              filename, &utc->total,
                                              GNUNET_YES))
        {
          GNUNET_free (utc);
          return NULL;
        }
      utc->meta =
        (md ==
         NULL) ? GNUNET_meta_data_create () : GNUNET_meta_data_duplicate (md);
    }
  else
    {
      utc->is_directory = GNUNET_YES;
      if (GNUNET_SYSERR == shared->dsc (shared->dscClosure,
                                        filename, &addChildUpload, utc))
        {
          /* error scanning upload directory */
          while (utc->child != NULL)
            freeUploadList (utc->child);
          GNUNET_free (utc);
          return NULL;
        }
      utc->meta = GNUNET_meta_data_duplicate (md);
      GNUNET_meta_data_insert (utc->meta,
                               EXTRACTOR_MIMETYPE, GNUNET_DIRECTORY_MIME);
    }
  if (keywords != NULL)
    utc->keywords = GNUNET_ECRS_uri_duplicate (keywords);
  else
    utc->keywords = NULL;
  utc->filename = GNUNET_strdup (filename);

  /* finally, link with parent */
  GNUNET_mutex_lock (shared->ctx->lock);
  utc->next = parent->child;
  parent->child = utc;
  GNUNET_mutex_unlock (shared->ctx->lock);
  return utc;
}

static void
signalUploadStopped (struct GNUNET_FSUI_UploadList *ul, int first_only)
{
  GNUNET_FSUI_Event event;

  while (ul != NULL)
    {
      signalUploadStopped (ul->child, 0);
      event.type = GNUNET_FSUI_upload_stopped;
      event.data.UploadStopped.uc.pos = ul;
      event.data.UploadStopped.uc.cctx = ul->cctx;
      event.data.UploadStopped.uc.ppos = ul->parent;
      event.data.UploadStopped.uc.pcctx = ul->parent->cctx;
      ul->shared->ctx->ecb (ul->shared->ctx->ecbClosure, &event);
      if (first_only)
        break;
      ul = ul->next;
    }
}

static void
freeShared (struct GNUNET_FSUI_UploadShared *shared)
{
  if (shared->global_keywords != NULL)
    GNUNET_ECRS_uri_destroy (shared->global_keywords);
  EXTRACTOR_removeAll (shared->extractors);
  GNUNET_free_non_null (shared->extractor_config);
  GNUNET_free (shared->top_filename);
  GNUNET_free (shared);
}

/**
 * Start uploading a file.  Note that an upload cannot be stopped once
 * started (not necessary anyway), but it can fail.  The function also
 * automatically the uploaded file in the global keyword space under
 * the given keywords.
 *
 * @return GNUNET_OK on success (at least we started with it),
 *  GNUNET_SYSERR if the file does not exist or gnunetd is not
 *  running
 */
struct GNUNET_FSUI_UploadList *
GNUNET_FSUI_upload_start (struct GNUNET_FSUI_Context *ctx,
                          const char *filename,
                          GNUNET_FSUI_DirectoryScanCallback dsc,
                          void *dscClosure,
                          unsigned int anonymityLevel,
                          unsigned int priority,
                          int doIndex,
                          int doExtract,
                          int individualKeywords,
                          GNUNET_CronTime expiration,
                          const struct GNUNET_MetaData *md,
                          const struct GNUNET_ECRS_URI *globalURI,
                          const struct GNUNET_ECRS_URI *keyUri)
{
  char *config;
  EXTRACTOR_ExtractorList *extractors;
  struct GNUNET_FSUI_UploadShared *shared;
  struct GNUNET_FSUI_UploadList *ul;

  config = NULL;
  extractors = NULL;
  if (doExtract)
    {
      extractors = EXTRACTOR_loadDefaultLibraries ();
      if (GNUNET_GC_have_configuration_value (ctx->cfg, "FS", "EXTRACTORS"))
        {
          GNUNET_GC_get_configuration_value_string (ctx->cfg,
                                                    "FS",
                                                    "EXTRACTORS", NULL,
                                                    &config);
          if (config != NULL)
            {
              extractors = EXTRACTOR_loadConfigLibraries (extractors, config);
            }
        }
    }
  shared = GNUNET_malloc (sizeof (GNUNET_FSUI_UploadShared));
  shared->dsc = dsc;
  shared->dscClosure = dscClosure;
  shared->extractors = extractors;
  shared->expiration = expiration;
  shared->ctx = ctx;
  shared->handle = NULL;
  shared->global_keywords =
    globalURI != NULL ? GNUNET_ECRS_uri_duplicate (globalURI) : NULL;
  shared->extractor_config = config;
  shared->doIndex = doIndex;
  shared->anonymityLevel = anonymityLevel;
  shared->priority = priority;
  shared->individualKeywords = individualKeywords;
  shared->top_filename = GNUNET_strdup (filename);
  ul = addUploads (shared, filename, keyUri, md, &ctx->activeUploads);
  if (ul == NULL)
    {
      freeShared (shared);
      return NULL;
    }
  shared->handle =
    GNUNET_thread_create (&GNUNET_FSUI_uploadThreadEvent, ul, 128 * 1024);
  if (shared->handle == NULL)
    {
      GNUNET_GE_LOG_STRERROR (ctx->ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_USER |
                              GNUNET_GE_BULK, "PTHREAD_CREATE");
      freeUploadList (ul);
      freeShared (shared);
      return NULL;
    }
  GNUNET_GE_ASSERT (ctx->ectx, ul->shared == shared);
  return ul;
}

/**
 * Abort an upload.  If the context is for a recursive
 * upload, all sub-uploads will also be aborted.
 * Note that if this is not the top-level upload,
 * the top-level upload will continue without the
 * subtree selected using this abort command.
 *
 * @return GNUNET_SYSERR on error
 */
int
GNUNET_FSUI_upload_abort (struct GNUNET_FSUI_UploadList *ul)
{
  GNUNET_FSUI_UploadList *c;
  GNUNET_FSUI_UploadList *p;
  struct GNUNET_FSUI_Context *ctx;
  GNUNET_FSUI_Event event;

  if (ul == NULL)
    return GNUNET_SYSERR;
  ctx = ul->shared->ctx;
  if ((ul->state != GNUNET_FSUI_ACTIVE) && (ul->state != GNUNET_FSUI_PENDING))
    return GNUNET_NO;
  if (ul->state == GNUNET_FSUI_ACTIVE)
    {
      ul->state = GNUNET_FSUI_ABORTED;
      c = ul->child;
      while (c != NULL)
        {
          GNUNET_FSUI_upload_abort (c);
          c = c->next;
        }
      GNUNET_thread_stop_sleep (ul->shared->handle);
      event.type = GNUNET_FSUI_upload_aborted;
      event.data.UploadAborted.uc.pos = ul;
      event.data.UploadAborted.uc.cctx = ul->cctx;
      event.data.UploadAborted.uc.ppos = ul->parent;
      event.data.UploadAborted.uc.pcctx = ul->parent->cctx;
      ctx->ecb (ctx->ecbClosure, &event);
    }
  else
    {
      ul->state = GNUNET_FSUI_ABORTED_JOINED;
      c = ul->child;
      while (c != NULL)
        {
          GNUNET_FSUI_upload_abort (c);
          c = c->next;
        }
      event.type = GNUNET_FSUI_upload_aborted;
      event.data.UploadAborted.uc.pos = ul;
      event.data.UploadAborted.uc.cctx = ul->cctx;
      event.data.UploadAborted.uc.ppos = ul->parent;
      event.data.UploadAborted.uc.pcctx = ul->parent->cctx;
      ctx->ecb (ctx->ecbClosure, &event);
    }
  if (!ul->is_directory)
    {
      /* reduce total size of all parents accordingly
         and generate progress events */
      p = ul->parent;
      while (p != &ctx->activeUploads)
        {
          p->total -= ul->total;
          event.type = GNUNET_FSUI_upload_progress;
          event.data.UploadProgress.uc.pos = p;
          event.data.UploadProgress.uc.cctx = p->cctx;
          event.data.UploadProgress.uc.ppos = p->parent;
          event.data.UploadProgress.uc.pcctx = p->parent->cctx;
          event.data.UploadProgress.completed = p->completed;
          event.data.UploadProgress.total = p->total;
          /* use "now" for ETA, given that the user is aborting stuff */
          event.data.UploadProgress.eta = GNUNET_get_time ();
          event.data.UploadProgress.filename = p->filename;
          ctx->ecb (ctx->ecbClosure, &event);
          p = p->parent;
        }
    }
  return GNUNET_OK;
}

/**
 * Stop an upload.  Only to be called for the top-level
 * upload.
 *
 * @return GNUNET_SYSERR on error
 */
int
GNUNET_FSUI_upload_stop (struct GNUNET_FSUI_UploadList *ul)
{
  void *unused;
  struct GNUNET_FSUI_UploadShared *shared;
  struct GNUNET_FSUI_Context *ctx;

  if (ul == NULL)
    return GNUNET_SYSERR;
  ctx = ul->shared->ctx;
  GNUNET_GE_ASSERT (ctx->ectx, ul->parent == &ctx->activeUploads);
  if ((ul->state == GNUNET_FSUI_ACTIVE) ||
      (ul->state == GNUNET_FSUI_COMPLETED) ||
      (ul->state == GNUNET_FSUI_ABORTED) || (ul->state == GNUNET_FSUI_ERROR))
    {
      GNUNET_GE_ASSERT (ctx->ectx, ul->shared->handle != NULL);
      GNUNET_thread_join (ul->shared->handle, &unused);
      ul->shared->handle = NULL;
      if (ul->state == GNUNET_FSUI_ACTIVE)
        ul->state = GNUNET_FSUI_PENDING;
      else
        ul->state++;            /* add _JOINED */
    }
  else
    {
      GNUNET_GE_ASSERT (ctx->ectx, ul->shared->handle == NULL);
    }
  signalUploadStopped (ul, 1);
  shared = ul->shared;
  freeUploadList (ul);
  freeShared (shared);
  return GNUNET_OK;
}

/* end of upload.c */
