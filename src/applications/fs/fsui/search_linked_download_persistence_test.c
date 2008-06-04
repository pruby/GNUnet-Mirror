/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/search_linked_download_persistence_test.c
 * @brief testcase for fsui download persistence for recursive
 *        download linked to search
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"

#define DEBUG_VERBOSE GNUNET_NO

#define UPLOAD_PREFIX "/tmp/gnunet-fsui-search_linked_download_persistence_test"

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; }

static struct GNUNET_GE_Context *ectx;

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = GNUNET_malloc (strlen (UPLOAD_PREFIX "/FSUITEST") + 14);
  GNUNET_snprintf (fn,
                   strlen (UPLOAD_PREFIX "/FSUITEST") + 14,
                   UPLOAD_PREFIX "/FSUITEST%u", i);
  GNUNET_disk_directory_create_for_file (NULL, fn);
  return fn;
}

static struct GNUNET_FSUI_Context *ctx;
static struct GNUNET_ECRS_URI *upURI;
static struct GNUNET_FSUI_SearchList *search;
static struct GNUNET_FSUI_DownloadList *download;
static int have_error;

/**
 * Set to 1 if we are about to stop the search and
 * thus our simple tests for download event correctness
 * would not work correctly.
 */
static int no_check;

static void *
eventCallback (void *cls, const GNUNET_FSUI_Event * event)
{
  if (no_check)
    return NULL;
  switch (event->type)
    {
    case GNUNET_FSUI_search_suspended:
      search = NULL;
      break;
    case GNUNET_FSUI_download_suspended:
      if (event->data.DownloadSuspended.dc.spos != search)
        {
          fprintf (stderr,
                   "Download suspended but search reference not set correctly.\n");
          have_error = 1;
        }
      if ((event->data.DownloadSuspended.dc.pos == download) &&
          (event->data.DownloadSuspended.dc.ppos != NULL))
        {
          fprintf (stderr,
                   "Download suspended but parent reference not set to NULL.\n");
          have_error = 1;
        }
      if ((event->data.DownloadSuspended.dc.pos != download) &&
          (event->data.DownloadSuspended.dc.ppos != download))
        {
          fprintf (stderr,
                   "Download suspended but parent reference not set correctly (%p instead of %p).\n",
                   event->data.DownloadSuspended.dc.ppos, download);
          have_error = 1;
        }
      if (event->data.DownloadSuspended.dc.pos == download)
        download = NULL;
      break;
    case GNUNET_FSUI_search_resumed:
#if DEBUG_VERBOSE
      printf ("Search resuming\n");
#endif
      search = event->data.SearchResumed.sc.pos;
      break;
    case GNUNET_FSUI_download_resumed:
      if (download == NULL)
        download = event->data.DownloadResumed.dc.pos;
      if (event->data.DownloadResumed.dc.spos != search)
        {
          fprintf (stderr,
                   "Download resuming but search reference not set correctly.\n");
          abort ();
          have_error = 1;
        }
      if ((event->data.DownloadResumed.dc.pos == download) &&
          (event->data.DownloadResumed.dc.ppos != NULL))
        {
          fprintf (stderr,
                   "Download resuming but parent reference not set to NULL.\n");
          have_error = 1;
        }
      if ((event->data.DownloadResumed.dc.pos != download) &&
          (event->data.DownloadResumed.dc.ppos != download))
        {
          fprintf (stderr,
                   "Download resuming but parent reference not set correctly.\n");
          have_error = 1;
        }
#if DEBUG_VERBOSE
      printf ("Download resuming\n");
#endif
      break;
    case GNUNET_FSUI_search_result:
#if DEBUG_VERBOSE
      printf ("Received search result\n");
#endif
      break;
    case GNUNET_FSUI_upload_progress:
#if DEBUG_VERBOSE
      printf ("Upload is progressing (%llu/%llu)...\n",
              event->data.UploadProgress.completed,
              event->data.UploadProgress.total);
#endif
      break;
    case GNUNET_FSUI_upload_completed:
      if (upURI != NULL)
        GNUNET_ECRS_uri_destroy (upURI);
      upURI = GNUNET_ECRS_uri_duplicate (event->data.UploadCompleted.uri);
#if DEBUG_VERBOSE
      printf ("Upload complete.\n");
#endif
      break;
    case GNUNET_FSUI_download_completed:
      if (event->data.DownloadCompleted.dc.spos != search)
        {
          fprintf (stderr,
                   "Download completed but search reference not set correctly.\n");
          have_error = 1;
        }
      if ((event->data.DownloadCompleted.dc.pos == download) &&
          (event->data.DownloadCompleted.dc.ppos != NULL))
        {
          fprintf (stderr,
                   "Download completed but parent reference not set to NULL.\n");
          have_error = 1;
        }
      if ((event->data.DownloadCompleted.dc.pos != download) &&
          (event->data.DownloadCompleted.dc.ppos != download))
        {
          fprintf (stderr,
                   "Download completed but parent reference not set correctly.\n");
          have_error = 1;
        }
#if DEBUG_VERBOSE
      printf ("Download complete.\n");
#endif
      break;
    case GNUNET_FSUI_download_progress:
      if (event->data.DownloadResumed.dc.spos != search)
        {
          fprintf (stderr,
                   "Download progressing but search reference not set correctly.\n");
          have_error = 1;
        }
      if ((event->data.DownloadResumed.dc.pos == download) &&
          (event->data.DownloadResumed.dc.ppos != NULL))
        {
          fprintf (stderr,
                   "Download progressing but parent reference not set to NULL.\n");
          have_error = 1;
        }
      if ((event->data.DownloadResumed.dc.pos != download) &&
          (event->data.DownloadResumed.dc.ppos != download))
        {
          fprintf (stderr,
                   "Download progressing but parent reference not set correctly.\n");
          have_error = 1;
        }
#if DEBUG_VERBOSE
      printf ("Download is progressing (%llu/%llu)...\n",
              event->data.DownloadProgress.completed,
              event->data.DownloadProgress.total);
#endif
      break;
    case GNUNET_FSUI_unindex_progress:
#if DEBUG_VERBOSE
      printf ("Unindex is progressing (%llu/%llu)...\n",
              event->data.UnindexProgress.completed,
              event->data.UnindexProgress.total);
#endif
      break;
    case GNUNET_FSUI_unindex_completed:
#if DEBUG_VERBOSE
      printf ("Unindex complete.\n");
#endif
      break;
    case GNUNET_FSUI_unindex_error:
      fprintf (stderr,
               "Received ERROR: %d %s\n",
               event->type, event->data.UnindexError.message);
      GNUNET_GE_BREAK (ectx, 0);
      break;
    case GNUNET_FSUI_upload_error:
      fprintf (stderr,
               "Received ERROR: %d %s\n",
               event->type, event->data.UploadError.message);
      GNUNET_GE_BREAK (ectx, 0);
      break;
    case GNUNET_FSUI_download_error:
      fprintf (stderr,
               "Received ERROR: %d %s\n",
               event->type, event->data.DownloadError.message);
      GNUNET_GE_BREAK (ectx, 0);
      break;
    case GNUNET_FSUI_download_aborted:
#if DEBUG_VERBOSE
      printf ("Received download aborted event.\n");
#endif
      break;
    case GNUNET_FSUI_unindex_suspended:
    case GNUNET_FSUI_upload_suspended:
#if DEBUG_VERBOSE
      fprintf (stderr, "Received SUSPENDING: %d\n", event->type);
#endif
      break;
    case GNUNET_FSUI_download_started:
      if (download == NULL)
        download = event->data.DownloadStarted.dc.pos;
      if (event->data.DownloadStarted.dc.spos != search)
        {
          fprintf (stderr,
                   "Download started but search reference not set correctly.\n");
          have_error = 1;
        }
      if ((event->data.DownloadStarted.dc.pos == download) &&
          (event->data.DownloadStarted.dc.ppos != NULL))
        {
          fprintf (stderr,
                   "Download started but parent reference not set to NULL.\n");
          have_error = 1;
        }
      if ((event->data.DownloadStarted.dc.pos != download) &&
          (event->data.DownloadStarted.dc.ppos != download))
        {
          fprintf (stderr,
                   "Download started but parent reference not set correctly.\n");
          have_error = 1;
        }
      break;
    case GNUNET_FSUI_download_stopped:
      if (event->data.DownloadStopped.dc.spos != search)
        {
          fprintf (stderr,
                   "Download stopped but search reference not set correctly.\n");
          have_error = 1;
        }
      if ((event->data.DownloadStopped.dc.pos == download) &&
          (event->data.DownloadStopped.dc.ppos != NULL))
        {
          fprintf (stderr,
                   "Download stopped but parent reference not set to NULL.\n");
          have_error = 1;
        }
      if ((event->data.DownloadStopped.dc.pos != download) &&
          (event->data.DownloadStopped.dc.ppos != download))
        {
          fprintf (stderr,
                   "Download stopped but parent reference not set correctly.\n");
          have_error = 1;
        }
      break;
    case GNUNET_FSUI_search_update:
    case GNUNET_FSUI_upload_started:
    case GNUNET_FSUI_upload_stopped:
    case GNUNET_FSUI_search_started:
    case GNUNET_FSUI_search_aborted:
    case GNUNET_FSUI_search_stopped:
    case GNUNET_FSUI_unindex_started:
    case GNUNET_FSUI_unindex_stopped:
      break;
    default:
      printf ("Unexpected event: %d\n", event->type);
      break;
    }
  return NULL;
}

#define FILESIZE (1024)

#define START_DAEMON 1

int
main (int argc, char *argv[])
{
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  int i;
  int j;
  struct GNUNET_ECRS_URI *uri = NULL;
  char *fn = NULL;
  char *keywords[] = {
    "down_foo",
    "down_bar",
  };
  char keyword[40];
  int prog;
  char *buf;
  struct GNUNET_MetaData *meta;
  struct GNUNET_ECRS_URI *kuri = NULL;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_FSUI_UnindexList *unindex = NULL;
  struct GNUNET_FSUI_UploadList *upload = NULL;
  int suspendRestart = 0;


  ok = GNUNET_YES;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_DAEMON
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg,
                                         30 * GNUNET_CRON_SECONDS));
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
  /* ACTUAL TEST CODE */
#endif
  ctx = GNUNET_FSUI_start (NULL,
                           cfg, "search_linked_download_persistence_test", 32,
                           GNUNET_YES, &eventCallback, NULL);
  CHECK (ctx != NULL);
  for (j = 4; j < 256; j += 4)
    {
      fn = makeName (j);
      buf = GNUNET_malloc (FILESIZE * j);
      for (i = 0; i < FILESIZE; i++)
        buf[i] = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 256);
      GNUNET_disk_file_write (ectx, fn, buf, FILESIZE, "600");
      GNUNET_free (buf);
      GNUNET_free (fn);
    }
  meta = GNUNET_meta_data_create ();
  kuri =
    GNUNET_ECRS_keyword_command_line_to_uri (ectx, 2,
                                             (const char **) keywords);
  GNUNET_meta_data_insert (meta, EXTRACTOR_MIMETYPE, GNUNET_DIRECTORY_MIME);
  upload =
    GNUNET_FSUI_upload_start (ctx, UPLOAD_PREFIX,
                              (GNUNET_FSUI_DirectoryScanCallback) &
                              GNUNET_disk_directory_scan, NULL, 0, 0,
                              GNUNET_YES, GNUNET_NO, GNUNET_NO,
                              GNUNET_get_time () + 5 * GNUNET_CRON_HOURS,
                              meta, kuri, kuri);
  CHECK (upload != NULL);
  GNUNET_ECRS_uri_destroy (kuri);
  kuri = NULL;
  GNUNET_FSUI_upload_stop (upload);
  CHECK (upURI != NULL);
  GNUNET_snprintf (keyword, 40, "+%s +%s", keywords[0], keywords[1]);
  uri = GNUNET_ECRS_keyword_string_to_uri (ectx, keyword);
  search = GNUNET_FSUI_search_start (ctx, 0, uri);
  CHECK (search != NULL);
  download = GNUNET_FSUI_download_start (ctx,
                                         0,
                                         GNUNET_YES,
                                         upURI,
                                         meta,
                                         UPLOAD_PREFIX "-download", search,
                                         NULL);
  GNUNET_meta_data_destroy (meta);
  prog = 0;
  suspendRestart = 10;
  while (prog < 1000)
    {
      prog++;
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if ((suspendRestart > 0)
          && (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 100) == 0))
        {
#if 1
#if DEBUG_VERBOSE
          printf ("Testing FSUI suspend-resume\n");
#endif
          GNUNET_FSUI_stop (ctx);       /* download possibly incomplete
                                           at this point, thus testing resume */
          CHECK (search == NULL);
          CHECK (download == NULL);
          ctx = GNUNET_FSUI_start (NULL,
                                   cfg,
                                   "search_linked_download_persistence_test",
                                   32, GNUNET_YES, &eventCallback, NULL);
#if DEBUG_VERBOSE
          printf ("Resumed...\n");
#endif
#endif
          suspendRestart--;
        }
      if ((search != NULL) && (suspendRestart >= 5))
        {
          no_check = 1;
          GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
          GNUNET_FSUI_search_abort (search);
          GNUNET_FSUI_search_stop (search);
          search = NULL;
          no_check = 0;
        }
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  GNUNET_FSUI_download_stop (download);
  for (j = 4; j < 256; j += 4)
    {
      fn = makeName (j);
      unindex = GNUNET_FSUI_unindex_start (ctx, fn);
      GNUNET_FSUI_unindex_stop (unindex);
      UNLINK (fn);
      GNUNET_free (fn);
    }
  /* END OF TEST CODE */
FAILURE:
  if (ctx != NULL)
    GNUNET_FSUI_stop (ctx);
  if (uri != NULL)
    GNUNET_ECRS_uri_destroy (uri);
  if (kuri != NULL)
    GNUNET_ECRS_uri_destroy (kuri);
  if (upURI != NULL)
    GNUNET_ECRS_uri_destroy (upURI);

#if START_DAEMON
  GNUNET_GE_BREAK (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
#endif
  GNUNET_GC_free (cfg);
  if (have_error)
    ok = GNUNET_NO;
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of search_linked_download_persistence_test.c */
