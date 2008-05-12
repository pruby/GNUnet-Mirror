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
 * @file applications/fs/fsui/search_pause_resume_persistence_test.c
 * @brief testcase for fsui search persistence, pause and resume
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"

#define CHECK_VERBOSE GNUNET_NO

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(NULL, 0); goto FAILURE; }

static char *
makeName (unsigned int i)
{
  char *fn;

  fn =
    GNUNET_malloc (strlen
                   ("/tmp/gnunet-fsui-search_pause_resume_persistence_test/FSUITEST")
                   + 14);
  GNUNET_snprintf (fn,
                   strlen
                   ("/tmp/gnunet-fsui-search_pause_resume_persistence_test/FSUITEST")
                   + 14,
                   "/tmp/gnunet-fsui-search_pause_resume_persistence_test/FSUITEST%u",
                   i);
  GNUNET_disk_directory_create_for_file (NULL, fn);
  return fn;
}

static volatile enum GNUNET_FSUI_EventType lastEvent;

static struct GNUNET_FSUI_SearchList *search;

static struct GNUNET_ECRS_URI *uri;

static struct GNUNET_FSUI_Context *ctx;

static struct GNUNET_Mutex *lock;

static volatile enum GNUNET_FSUI_EventType waitForEvent;

static void *
eventCallback (void *cls, const GNUNET_FSUI_Event * event)
{
  static char unused;

  GNUNET_mutex_lock (lock);
  switch (event->type)
    {
    case GNUNET_FSUI_search_resumed:
      search = event->data.SearchResumed.sc.pos;
      break;
    case GNUNET_FSUI_search_suspended:
      search = NULL;
      break;
    case GNUNET_FSUI_search_paused:
    case GNUNET_FSUI_search_restarted:
      break;
    case GNUNET_FSUI_download_resumed:
    case GNUNET_FSUI_upload_resumed:
    case GNUNET_FSUI_unindex_resumed:
      GNUNET_mutex_unlock (lock);
      return &unused;
    case GNUNET_FSUI_search_result:
#if CHECK_VERBOSE
      printf ("Received search result\n");
#endif
      uri = GNUNET_ECRS_uri_duplicate (event->data.SearchResult.fi.uri);
      break;
    case GNUNET_FSUI_upload_completed:
#if CHECK_VERBOSE
      printf ("Upload complete.\n");
#endif
      break;
    case GNUNET_FSUI_download_completed:
#if CHECK_VERBOSE
      printf ("Download complete.\n");
#endif
      break;
    case GNUNET_FSUI_unindex_completed:
#if CHECK_VERBOSE
      printf ("Unindex complete.\n");
#endif
      break;
    case GNUNET_FSUI_upload_error:
      printf ("Upload error.\n");
      break;
    case GNUNET_FSUI_download_error:
      printf ("Download error.\n");
      break;
    case GNUNET_FSUI_unindex_error:
      printf ("Unindex error.\n");
      break;
    default:
      break;
    }
  if (lastEvent != waitForEvent)
    lastEvent = event->type;
  GNUNET_mutex_unlock (lock);
  return NULL;
}

#define START_DAEMON 1

int
main (int argc, char *argv[])
{
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  char *fn = NULL;
  char *keywords[] = {
    "search_foo",
    "search_bar",
  };
  char keyword[40];
  int prog;
  struct GNUNET_ECRS_MetaData *meta;
  struct GNUNET_ECRS_URI *kuri;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_FSUI_UploadList *upload;
  struct GNUNET_FSUI_UnindexList *unindex;
  struct GNUNET_FSUI_DownloadList *download;
  struct GNUNET_ECRS_URI *luri;

  ok = GNUNET_YES;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_DAEMON
  GNUNET_disk_directory_remove (NULL,
                                "/tmp/gnunet-fsui-search_pause_resume_persistence_test/");
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg,
                                         30 * GNUNET_CRON_SECONDS));
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
  /* ACTUAL TEST CODE */
#endif
  lock = GNUNET_mutex_create (GNUNET_NO);
  ctx = GNUNET_FSUI_start (NULL,
                           cfg, "fsuisearch_pause_resume_persistence_test",
                           32, GNUNET_YES, &eventCallback, NULL);
  CHECK (ctx != NULL);
  GNUNET_snprintf (keyword, 40, "+%s +%s", keywords[0], keywords[1]);
  luri = GNUNET_ECRS_keyword_string_to_uri (NULL, keyword);
  uri = NULL;
  search = GNUNET_FSUI_search_start (ctx, 0, luri);
  GNUNET_ECRS_uri_destroy (luri);
  CHECK (NULL != search);
  GNUNET_FSUI_stop (ctx);
  /* resume search! */
  ctx = GNUNET_FSUI_start (NULL,
                           cfg, "fsuisearch_pause_resume_persistence_test",
                           32, GNUNET_YES, &eventCallback, NULL);
  GNUNET_FSUI_search_pause (search);
  GNUNET_FSUI_stop (ctx);
  /* resume search! */
  ctx = GNUNET_FSUI_start (NULL,
                           cfg, "fsuisearch_pause_resume_persistence_test",
                           32, GNUNET_YES, &eventCallback, NULL);
  GNUNET_FSUI_search_restart (search);

  fn = makeName (42);
  GNUNET_disk_file_write (NULL,
                          fn, "foo bar test!", strlen ("foo bar test!"),
                          "600");
  meta = GNUNET_ECRS_meta_data_create ();
  kuri =
    GNUNET_ECRS_keyword_command_line_to_uri (NULL, 2,
                                             (const char **) keywords);
  waitForEvent = GNUNET_FSUI_upload_completed;
  upload =
    GNUNET_FSUI_upload_start (ctx,
                              fn,
                              (GNUNET_FSUI_DirectoryScanCallback) &
                              GNUNET_disk_directory_scan, NULL, 0, 0,
                              GNUNET_YES, GNUNET_NO, GNUNET_NO,
                              GNUNET_get_time () + 5 * GNUNET_CRON_HOURS,
                              meta, kuri, kuri);
  CHECK (NULL != upload);
  GNUNET_free (fn);
  fn = NULL;
  GNUNET_ECRS_uri_destroy (kuri);
  GNUNET_ECRS_meta_data_destroy (meta);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_upload_completed)
    {
      prog++;
      if (prog == 10000)
        {
          fprintf (stderr,
                   "Upload failed to complete -- last event: %u\n",
                   lastEvent);
        }
      CHECK (prog < 10000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  GNUNET_FSUI_upload_stop (upload);
  GNUNET_FSUI_search_pause (search);
  GNUNET_FSUI_search_restart (search);
  while ((uri == NULL) && (GNUNET_shutdown_test () != GNUNET_YES))
    {
      prog++;
      CHECK (prog < 10000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
    }
  GNUNET_FSUI_search_abort (search);
  GNUNET_FSUI_search_stop (search);
  CHECK (uri != NULL);
  fn = makeName (43);
  meta = GNUNET_ECRS_meta_data_create ();
  waitForEvent = GNUNET_FSUI_download_completed;
  download =
    GNUNET_FSUI_download_start (ctx, 0, GNUNET_NO, uri, meta, fn, NULL, NULL);
  GNUNET_ECRS_meta_data_destroy (meta);
  GNUNET_free (fn);
  fn = NULL;
  GNUNET_ECRS_uri_destroy (uri);

  prog = 0;
  while (lastEvent != GNUNET_FSUI_download_completed)
    {
      prog++;
      CHECK (prog < 10000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  GNUNET_FSUI_download_stop (download);
  fn = makeName (42);
  waitForEvent = GNUNET_FSUI_unindex_completed;
  unindex = GNUNET_FSUI_unindex_start (ctx, fn);
  GNUNET_free (fn);
  fn = NULL;
  CHECK (NULL != unindex);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_unindex_completed)
    {
      prog++;
      CHECK (prog < 10000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  GNUNET_FSUI_unindex_stop (unindex);

  /* END OF TEST CODE */
FAILURE:
  if (ctx != NULL)
    GNUNET_FSUI_stop (ctx);
  if (lock != NULL)
    GNUNET_mutex_destroy (lock);
  GNUNET_free_non_null (fn);
  /* TODO: verify file 'fn(42)' == file 'fn(43)' */
  fn = makeName (42);
  UNLINK (fn);
  GNUNET_free (fn);
  fn = makeName (43);
  UNLINK (fn);
  GNUNET_free (fn);

#if START_DAEMON
  GNUNET_GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
#endif
  GNUNET_GC_free (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of search_pause_resume_persistence_test.c */
