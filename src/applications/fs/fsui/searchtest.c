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
 * @file applications/fs/fsui/searchtest.c
 * @brief testcase for fsui search persistence
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GE_BREAK(NULL, 0); goto FAILURE; }

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = GNUNET_malloc (strlen ("/tmp/gnunet-fsui-searchtest/FSUITEST") + 14);
  GNUNET_snprintf (fn,
                   strlen ("/tmp/gnunet-fsui-searchtest/FSUITEST") + 14,
                   "/tmp/gnunet-fsui-searchtest/FSUITEST%u", i);
  GNUNET_disk_directory_create_for_file (NULL, fn);
  return fn;
}

static volatile enum FSUI_EventType lastEvent;

static struct FSUI_SearchList *search;

static struct ECRS_URI *uri;

static struct FSUI_Context *ctx;

static struct GNUNET_Mutex *lock;

static volatile enum FSUI_EventType waitForEvent;

static void *
eventCallback (void *cls, const FSUI_Event * event)
{
  static char unused;

  GNUNET_mutex_lock (lock);
  switch (event->type)
    {
    case FSUI_search_resumed:
      search = event->data.SearchResumed.sc.pos;
      break;
    case FSUI_search_suspended:
      search = NULL;
      break;
    case FSUI_download_resumed:
    case FSUI_upload_resumed:
    case FSUI_unindex_resumed:
      GNUNET_mutex_unlock (lock);
      return &unused;
    case FSUI_search_result:
      printf ("Received search result\n");
      uri = ECRS_dupUri (event->data.SearchResult.fi.uri);
      break;
    case FSUI_upload_completed:
      printf ("Upload complete.\n");
      break;
    case FSUI_download_completed:
      printf ("Download complete.\n");
      break;
    case FSUI_unindex_completed:
      printf ("Unindex complete.\n");
      break;
    case FSUI_upload_error:
      printf ("Upload error.\n");
      break;
    case FSUI_download_error:
      printf ("Download error.\n");
      break;
    case FSUI_unindex_error:
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
    NULL,
  };
  char keyword[40];
  int prog;
  struct ECRS_MetaData *meta;
  struct ECRS_URI *kuri;
  struct GC_Configuration *cfg;
  struct FSUI_UploadList *upload;
  struct FSUI_UnindexList *unindex;
  struct FSUI_DownloadList *download;
  struct ECRS_URI *luri;

  ok = GNUNET_YES;
  cfg = GC_create ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
#if START_DAEMON
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GE_ASSERT (NULL, daemon > 0);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg,
                                         30 * GNUNET_CRON_SECONDS));
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
  /* ACTUAL TEST CODE */
#endif
  lock = GNUNET_mutex_create (GNUNET_NO);
  ctx = FSUI_start (NULL,
                    cfg, "fsuisearchtest", 32, GNUNET_YES, &eventCallback,
                    NULL);
  CHECK (ctx != NULL);
  GNUNET_snprintf (keyword, 40, "%s %s %s", keywords[0], _("AND"),
                   keywords[1]);
  luri = ECRS_parseCharKeywordURI (NULL, keyword);
  search = FSUI_startSearch (ctx, 0, 100, 240 * GNUNET_CRON_SECONDS, luri);
  ECRS_freeUri (luri);
  uri = NULL;
  CHECK (NULL != search);
  FSUI_stop (ctx);
  /* resume search! */
  ctx = FSUI_start (NULL,
                    cfg, "fsuisearchtest", 32, GNUNET_YES, &eventCallback,
                    NULL);
  fn = makeName (42);
  GNUNET_disk_file_write (NULL,
                          fn, "foo bar test!", strlen ("foo bar test!"),
                          "600");
  meta = ECRS_createMetaData ();
  kuri = ECRS_parseListKeywordURI (NULL, 2, (const char **) keywords);
  waitForEvent = FSUI_upload_completed;
  upload =
    FSUI_startUpload (ctx,
                      fn,
                      (DirectoryScanCallback) & GNUNET_disk_directory_scan,
                      NULL,
                      0,
                      0,
                      GNUNET_YES,
                      GNUNET_NO, GNUNET_NO,
                      GNUNET_get_time () + 5 * GNUNET_CRON_HOURS, meta, kuri,
                      kuri);
  CHECK (NULL != upload);
  GNUNET_free (fn);
  fn = NULL;
  ECRS_freeUri (kuri);
  ECRS_freeMetaData (meta);
  prog = 0;
  while (lastEvent != FSUI_upload_completed)
    {
      prog++;
      if (prog == 10000)
        {
          fprintf (stderr,
                   "Upload failed to complete -- last event: %u\n",
                   lastEvent);
        }
      CHECK (prog <
             10000) GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  FSUI_stopUpload (ctx, upload);

  while (uri == NULL)
    {
      prog++;
      CHECK (prog <
             10000) GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
    }
  FSUI_abortSearch (ctx, search);
  FSUI_stopSearch (ctx, search);
  CHECK (uri != NULL);
  fn = makeName (43);
  meta = ECRS_createMetaData ();
  waitForEvent = FSUI_download_completed;
  download =
    FSUI_startDownload (ctx, 0, GNUNET_NO, uri, meta, fn, NULL, NULL);
  ECRS_freeMetaData (meta);
  GNUNET_free (fn);
  fn = NULL;
  ECRS_freeUri (uri);

  prog = 0;
  while (lastEvent != FSUI_download_completed)
    {
      prog++;
      CHECK (prog < 10000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  FSUI_stopDownload (ctx, download);
  fn = makeName (42);
  waitForEvent = FSUI_unindex_completed;
  unindex = FSUI_startUnindex (ctx, fn);
  GNUNET_free (fn);
  fn = NULL;
  CHECK (NULL != unindex);
  prog = 0;
  while (lastEvent != FSUI_unindex_completed)
    {
      prog++;
      CHECK (prog < 10000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  FSUI_stopUnindex (ctx, unindex);

  /* END OF TEST CODE */
FAILURE:
  if (ctx != NULL)
    FSUI_stop (ctx);
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
  GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
#endif
  GC_free (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of searchtest.c */
