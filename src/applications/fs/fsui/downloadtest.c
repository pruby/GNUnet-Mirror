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
 * @file applications/fs/fsui/downloadtest.c
 * @brief testcase for fsui download persistence (upload-download)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_util_crypto.h"

#define DEBUG_VERBOSE NO

#define CHECK(a) if (!(a)) { ok = NO; GE_BREAK(ectx, 0); goto FAILURE; }

static volatile int suspendRestart = 0;

static struct GE_Context *ectx;

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = MALLOC (strlen ("/tmp/gnunet-fsui-downloadtest/FSUITEST") + 14);
  SNPRINTF (fn,
            strlen ("/tmp/gnunet-fsui-downloadtest/FSUITEST") + 14,
            "/tmp/gnunet-fsui-downloadtest/FSUITEST%u", i);
  disk_directory_create_for_file (NULL, fn);
  return fn;
}

static volatile enum FSUI_EventType lastEvent;
static volatile enum FSUI_EventType waitForEvent;
static struct FSUI_Context *ctx;
static struct ECRS_URI *upURI;
static struct FSUI_SearchList *search;
static struct FSUI_DownloadList *download;

static void *
eventCallback (void *cls, const FSUI_Event * event)
{
  char *fn;

  switch (event->type)
    {
    case FSUI_search_suspended:
      search = NULL;
      break;
    case FSUI_download_suspended:
      download = NULL;
      break;
    case FSUI_search_resumed:
#if DEBUG_VERBOSE
      printf ("Search resuming\n");
#endif
      search = event->data.SearchResumed.sc.pos;
      break;
    case FSUI_download_resumed:
#if DEBUG_VERBOSE
      printf ("Download resuming\n");
#endif
      download = event->data.DownloadResumed.dc.pos;
      break;
    case FSUI_search_completed:
#if DEBUG_VERBOSE
      printf ("Search completed\n");
#endif
      if (download == NULL)
        {
          fprintf (stderr,
                   "ERROR: Search completed but download not started!\n");
        }
      break;
    case FSUI_search_result:
#if DEBUG_VERBOSE
      printf ("Received search result\n");
#endif
      if (download == NULL)
        {
          char *u;

          if (!ECRS_equalsUri (upURI, event->data.SearchResult.fi.uri))
            {
#if DEBUG_VERBOSE
              printf
                ("Received search result for different file (download not started).\n");
#endif
              return NULL;      /* ignore */
            }
          fn = makeName (43);
          u = ECRS_uriToString (event->data.SearchResult.fi.uri);
#if DEBUG_VERBOSE
          printf ("Download started: %s.\n", u);
#endif
          FREE (u);
          download = FSUI_startDownload (ctx,
                                         0,
                                         NO,
                                         event->data.SearchResult.fi.uri,
                                         event->data.SearchResult.fi.meta,
                                         fn, NULL, NULL);
          if (download == NULL)
            {
              GE_BREAK (ectx, 0);
              return NULL;
            }
          FREE (fn);
          suspendRestart = 4;
        }
      break;
    case FSUI_upload_progress:
#if DEBUG_VERBOSE
      printf ("Upload is progressing (%llu/%llu)...\n",
              event->data.UploadProgress.completed,
              event->data.UploadProgress.total);
#endif
      break;
    case FSUI_upload_completed:
      upURI = ECRS_dupUri (event->data.UploadCompleted.uri);
#if DEBUG_VERBOSE
      printf ("Upload complete.\n");
#endif
      break;
    case FSUI_download_completed:
#if DEBUG_VERBOSE
      printf ("Download complete.\n");
#endif
      FSUI_abortSearch (ctx, search);
      FSUI_stopSearch (ctx, search);
      search = NULL;
      break;
    case FSUI_download_progress:
#if DEBUG_VERBOSE
      printf ("Download is progressing (%llu/%llu)...\n",
              event->data.DownloadProgress.completed,
              event->data.DownloadProgress.total);
#endif
      break;
    case FSUI_unindex_progress:
#if DEBUG_VERBOSE
      printf ("Unindex is progressing (%llu/%llu)...\n",
              event->data.UnindexProgress.completed,
              event->data.UnindexProgress.total);
#endif
      break;
    case FSUI_unindex_completed:
#if DEBUG_VERBOSE
      printf ("Unindex complete.\n");
#endif
      break;
    case FSUI_unindex_error:
    case FSUI_upload_error:
    case FSUI_download_error:
    case FSUI_search_error:
      fprintf (stderr, "Received ERROR: %d\n", event->type);
      GE_BREAK (ectx, 0);
      break;
    case FSUI_download_aborted:
#if DEBUG_VERBOSE
      printf ("Received download aborted event.\n");
#endif
      break;
    case FSUI_unindex_suspended:
    case FSUI_upload_suspended:
#if DEBUG_VERBOSE
      fprintf (stderr, "Received SUSPENDING: %d\n", event->type);
#endif
      break;
    case FSUI_upload_started:
    case FSUI_upload_stopped:
    case FSUI_download_started:
    case FSUI_download_stopped:
    case FSUI_search_started:
    case FSUI_search_aborted:
    case FSUI_search_stopped:
    case FSUI_unindex_started:
    case FSUI_unindex_stopped:
      break;
    default:
      printf ("Unexpected event: %d\n", event->type);
      break;
    }
  if (lastEvent == waitForEvent)
    return NULL;                /* ignore all other events */
  lastEvent = event->type;
  return NULL;
}

#define FILESIZE (1024 * 1024 * 2)

#define START_DAEMON 1

int
main (int argc, char *argv[])
{
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  int i;
  struct ECRS_URI *uri = NULL;
  char *fn = NULL;
  char *keywords[] = {
    "down_foo",
    "down_bar",
    NULL,
  };
  char keyword[40];
  int prog;
  char *buf;
  struct ECRS_MetaData *meta;
  struct ECRS_URI *kuri = NULL;
  struct GC_Configuration *cfg;
  struct FSUI_UnindexList *unindex = NULL;
  struct FSUI_UploadList *upload = NULL;

  ok = YES;
  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
#if START_DAEMON
  daemon = os_daemon_start (NULL, cfg, "peer.conf", NO);
  GE_ASSERT (NULL, daemon > 0);
  CHECK (OK == connection_wait_for_running (NULL, cfg, 30 * cronSECONDS));
  PTHREAD_SLEEP (5 * cronSECONDS);      /* give apps time to start */
  /* ACTUAL TEST CODE */
#endif
  ctx = FSUI_start (NULL,
                    cfg, "fsuidownloadtest", 32, YES, &eventCallback, NULL);
  CHECK (ctx != NULL);
  fn = makeName (42);
  buf = MALLOC (FILESIZE);
  for (i = 0; i < FILESIZE; i++)
    buf[i] = weak_randomi (256);
  disk_file_write (ectx, fn, buf, FILESIZE, "600");
  FREE (buf);
  meta = ECRS_createMetaData ();
  kuri = ECRS_parseListKeywordURI (ectx, 2, (const char **) keywords);
  waitForEvent = FSUI_upload_completed;
  upload = FSUI_startUpload (ctx,
                             fn,
                             (DirectoryScanCallback) & disk_directory_scan,
                             NULL,
                             0,
                             0,
                             YES,
                             NO,
                             NO,
                             get_time () + 5 * cronHOURS, meta, kuri, kuri);
  CHECK (upload != NULL);
  ECRS_freeUri (kuri);
  kuri = NULL;
  ECRS_freeMetaData (meta);
  prog = 0;
  while (lastEvent != FSUI_upload_completed)
    {
      prog++;
      CHECK (prog < 5000);
      PTHREAD_SLEEP (50 * cronMILLIS);
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
    }
  FSUI_stopUpload (ctx, upload);
  SNPRINTF (keyword, 40, "%s %s %s", keywords[0], _("AND"), keywords[1]);
  uri = ECRS_parseCharKeywordURI (ectx, keyword);
  waitForEvent = FSUI_download_completed;
  search = FSUI_startSearch (ctx, 0, 10000, 240 * cronSECONDS, uri);
  CHECK (search != NULL);
  prog = 0;
  while (search != NULL)
    {
      prog++;
      CHECK (prog < 10000);
      PTHREAD_SLEEP (50 * cronMILLIS);
      if ((suspendRestart > 0) && (weak_randomi (4) == 0))
        {
#if 1
#if DEBUG_VERBOSE
          printf ("Testing FSUI suspend-resume\n");
#endif
          FSUI_stop (ctx);      /* download possibly incomplete
                                   at this point, thus testing resume */
          CHECK (search == NULL);
          CHECK (download == NULL);
          ctx = FSUI_start (NULL,
                            cfg,
                            "fsuidownloadtest",
                            32, YES, &eventCallback, NULL);
#if DEBUG_VERBOSE
          printf ("Resumed...\n");
#endif
#endif
          suspendRestart--;
        }
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
    }
  CHECK (search == NULL);
  CHECK (download != NULL);
  waitForEvent = FSUI_unindex_completed;
  unindex = FSUI_startUnindex (ctx, fn);
  CHECK (unindex != NULL);
  prog = 0;
  while (lastEvent != FSUI_unindex_completed)
    {
      prog++;
      CHECK (prog < 5000);
      PTHREAD_SLEEP (50 * cronMILLIS);
      CHECK (lastEvent != FSUI_unindex_error);
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
    }
  CHECK (lastEvent == FSUI_unindex_completed);
  /* END OF TEST CODE */
FAILURE:
  if (ctx != NULL)
    {
      if (unindex != NULL)
        FSUI_stopUnindex (ctx, unindex);
      if (download != NULL)
        FSUI_stopDownload (ctx, download);
      FSUI_stop (ctx);
    }
  if (fn != NULL)
    {
      UNLINK (fn);
      FREE (fn);
    }
  if (uri != NULL)
    ECRS_freeUri (uri);
  if (kuri != NULL)
    ECRS_freeUri (kuri);
  fn = makeName (43);
  /* TODO: verify file 'fn(42)' == file 'fn(43)' */
  UNLINK (fn);
  FREE (fn);
  if (upURI != NULL)
    ECRS_freeUri (upURI);

#if START_DAEMON
  GE_BREAK (NULL, OK == os_daemon_stop (NULL, daemon));
#endif
  GC_free (cfg);
  return (ok == YES) ? 0 : 1;
}

/* end of downloadtest.c */
