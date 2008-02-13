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
 * @file applications/fs/fsui/fsuitest.c
 * @brief testcase for fsui (upload-download)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"

#define DEBUG_VERBOSE GNUNET_NO

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(NULL, 0); goto FAILURE; }

static char *
makeName (unsigned int i)
{
  char *fn;

  fn =
    GNUNET_malloc (strlen ("/tmp/gnunet-fsui-serializetest/FSUITEST") + 14);
  GNUNET_snprintf (fn, strlen ("/tmp/gnunet-fsui-test/FSUITEST") + 14,
                   "/tmp/gnunet-fsui-test/FSUITEST%u", i);
  GNUNET_disk_directory_create_for_file (NULL, fn);
  return fn;
}

static volatile enum GNUNET_FSUI_EventType lastEvent;

static struct GNUNET_FSUI_Context *ctx;

static struct GNUNET_FSUI_DownloadList *download;

static void *
eventCallback (void *cls, const GNUNET_FSUI_Event * event)
{
  static char unused;
  char *fn;

  switch (event->type)
    {
    case GNUNET_FSUI_search_resumed:
    case GNUNET_FSUI_download_resumed:
    case GNUNET_FSUI_upload_resumed:
    case GNUNET_FSUI_unindex_resumed:
      return &unused;
    case GNUNET_FSUI_search_result:
#if DEBUG_VERBOSE
      printf ("Received search result\n");
#endif
      fn = makeName (43);
      download = GNUNET_FSUI_download_start (ctx,
                                             0,
                                             GNUNET_NO,
                                             event->data.SearchResult.fi.uri,
                                             event->data.SearchResult.fi.meta,
                                             fn, NULL, NULL);
      GNUNET_free (fn);
      break;
    case GNUNET_FSUI_upload_completed:
#if DEBUG_VERBOSE
      printf ("Upload complete.\n");
#endif
      break;
    case GNUNET_FSUI_download_completed:
#if DEBUG_VERBOSE
      printf ("Download complete.\n");
#endif
      break;
    case GNUNET_FSUI_unindex_completed:
#if DEBUG_VERBOSE
      printf ("Unindex complete.\n");
#endif
      break;
    default:
      break;
    }
  lastEvent = event->type;
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
  struct GNUNET_ECRS_URI *uri;
  char *filename = NULL;
  char *keywords[] = {
    "fsui_foo",
    "fsui_bar",
    NULL,
  };
  char keyword[40];
  int prog;
  struct GNUNET_ECRS_MetaData *meta;
  struct GNUNET_ECRS_URI *kuri;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_FSUI_UploadList *upload;
  struct GNUNET_FSUI_SearchList *search;
  struct GNUNET_FSUI_UnindexList *unindex;

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
                                         60 * GNUNET_CRON_SECONDS));
#endif
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
  ok = GNUNET_YES;

  /* ACTUAL TEST CODE */
  ctx = GNUNET_FSUI_start (NULL, cfg, "fsuitest", 32,   /* thread pool size */
                           GNUNET_NO,   /* no resume */
                           &eventCallback, NULL);
  CHECK (ctx != NULL);
  filename = makeName (42);
  GNUNET_disk_file_write (NULL,
                          filename,
                          "foo bar test!", strlen ("foo bar test!"), "600");
  meta = GNUNET_ECRS_meta_data_create ();
  kuri = GNUNET_ECRS_keyword_list_to_uri (NULL, 2, (const char **) keywords);
  upload = GNUNET_FSUI_upload_start (ctx, filename, (GNUNET_FSUI_DirectoryScanCallback) & GNUNET_disk_directory_scan, NULL, 0,  /* anonymity */
                                     0, /* priority */
                                     GNUNET_YES,
                                     GNUNET_NO,
                                     GNUNET_NO,
                                     GNUNET_get_time () +
                                     5 * GNUNET_CRON_HOURS, meta, kuri, kuri);
  CHECK (upload != NULL);
  GNUNET_ECRS_uri_destroy (kuri);
  GNUNET_ECRS_meta_data_destroy (meta);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_upload_completed)
    {
      prog++;
      CHECK (prog <
             10000) GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  GNUNET_snprintf (keyword, 40, "%s %s %s", keywords[0], _("AND"),
                   keywords[1]);
  uri = GNUNET_ECRS_keyword_string_to_uri (NULL, keyword);
  search = GNUNET_FSUI_search_start (ctx, 0, uri);
  GNUNET_ECRS_uri_destroy (uri);
  CHECK (search != NULL);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_download_completed)
    {
      prog++;
      CHECK (prog < 10000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  GNUNET_FSUI_search_abort (ctx, search);
  GNUNET_FSUI_search_stop (ctx, search);
  unindex = GNUNET_FSUI_unindex_start (ctx, filename);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_unindex_completed)
    {
      prog++;
      CHECK (prog < 10000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  if (lastEvent != GNUNET_FSUI_unindex_completed)
    GNUNET_FSUI_unindex_abort (ctx, unindex);
  GNUNET_FSUI_unindex_stop (ctx, unindex);


  /* END OF TEST CODE */
FAILURE:
  if (ctx != NULL)
    GNUNET_FSUI_stop (ctx);
  if (filename != NULL)
    {
      UNLINK (filename);
      GNUNET_free (filename);
    }
  filename = makeName (43);
  /* TODO: verify file 'filename(42)' == file 'filename(43)' */
  UNLINK (filename);
  GNUNET_free (filename);

#if START_DAEMON
  GNUNET_GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
#endif
  GNUNET_GC_free (cfg);

  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of fsuitest.c */
