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
 * @file applications/fs/fsui/recursivetest.c
 * @brief testcase for fsui recursive upload-download
 * @author Christian Grothoff
 * @author Heikki Lindholm
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"

#define DEBUG_VERBOSE GNUNET_YES

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; }

#define FILESIZE (1024 * 1024 * 2)
/* depth-first directory tree d=dir f=file .=end of level*/
#define DIRECTORY_TREE_SPEC "dddf.f.d"

static struct GNUNET_GE_Context *ectx;

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = GNUNET_malloc (strlen ("/tmp/gnunet-fsui-recursivetest/FSUITEST") + 15);
  GNUNET_snprintf (fn,
                   strlen ("/tmp/gnunet-fsui-recursivetest/FSUITEST") + 15,
                   "/tmp/gnunet-fsui-recursivetest/FSUITEST%u/", i);
  return fn;
}

static int
makeHierarchyHelper (const char *current, const char *tree, int index,
                     int check)
{
  unsigned int fi, i;
  int done;
  char *s, *buf;

  fi = 0;
  done = 0;
  while (!done && tree[index] != '\0')
    {
    printf("%s/%u\n", current, fi);
    s = GNUNET_malloc (strlen(current)+strlen(DIR_SEPARATOR_STR)+14);
    GNUNET_snprintf (s, strlen(current)+strlen(DIR_SEPARATOR_STR)+14,
                     "%s%s%u",
                     current, DIR_SEPARATOR_STR, fi);
    switch (tree[index++])
      {
      case 'd':
        if (check && GNUNET_disk_directory_test (NULL, s) == GNUNET_NO)
          {
            index = -1;
            done = 1;
          }
        else
          {
            GNUNET_disk_directory_create (NULL, s);
          }
        if (!done)
          index = makeHierarchyHelper (s, tree, index, 0);
        break;
      case 'f':
        if (check && GNUNET_disk_directory_test (NULL, s) != GNUNET_NO)
          {
	    /* TODO: compare file contents */
            index = -1;
            done = 1;
          }
        else
          {
            buf = GNUNET_malloc (FILESIZE);
            for (i = 0; i < FILESIZE; i++)
              buf[i] = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 256);
            GNUNET_disk_file_write (ectx, s, buf, FILESIZE, "600");
            GNUNET_free (buf);
          }
        break;
      case '.':
        done = 1;
        break;
      default:
        break;
      }
    GNUNET_free (s);
    fi++;
    }
  return index;
}

static char *
makeHierarchy (unsigned int i, const char *tree)
{
  char *fn;

  fn = makeName(i);
  makeHierarchyHelper (fn, tree, 0, 0);
  return fn;
}

static int
checkHierarchy (unsigned int i, const char *tree)
{
  char *fn;
  int res;

  fn = makeName(i);
  if (GNUNET_disk_directory_test (NULL, fn) != GNUNET_YES)
    return GNUNET_SYSERR;
  res = (makeHierarchyHelper (fn, tree, 0, 1) == -1) ?
         GNUNET_SYSERR : GNUNET_OK;
  GNUNET_free(fn);
  return res;
}


static volatile enum GNUNET_FSUI_EventType lastEvent;
static volatile enum GNUNET_FSUI_EventType waitForEvent;
static struct GNUNET_FSUI_Context *ctx;
static struct GNUNET_ECRS_URI *upURI;
static struct GNUNET_FSUI_SearchList *search;
static struct GNUNET_FSUI_DownloadList *download;

static void *
eventCallback (void *cls, const GNUNET_FSUI_Event * event)
{
  char *fn;

  switch (event->type)
    {
    case GNUNET_FSUI_search_suspended:
      search = NULL;
      break;
    case GNUNET_FSUI_download_suspended:
      download = NULL;
      break;
    case GNUNET_FSUI_search_resumed:
      search = event->data.SearchResumed.sc.pos;
      break;
    case GNUNET_FSUI_download_resumed:
      download = event->data.DownloadResumed.dc.pos;
      break;
    case GNUNET_FSUI_search_result:
      if (download == NULL)
        {
          char *u;

          u = GNUNET_ECRS_uri_to_string (event->data.SearchResult.fi.uri);
          if (!GNUNET_ECRS_uri_test_equal
              (upURI, event->data.SearchResult.fi.uri))
            {
#if DEBUG_VERBOSE
              printf ("Received result for different file: %s.\n", u);
#endif
              GNUNET_free (u);
              return NULL;      /* ignore */
            }
#if DEBUG_VERBOSE
          printf ("Received search result; download started: %s.\n", u);
#endif
          GNUNET_free (u);
          fn = makeName (43);
          download = GNUNET_FSUI_download_start (ctx,
                                                 0,
                                                 GNUNET_YES,
                                                 event->data.SearchResult.fi.
                                                 uri,
                                                 event->data.SearchResult.fi.
                                                 meta, fn, NULL, NULL);
          if (download == NULL)
            {
              GNUNET_GE_BREAK (ectx, 0);
              return NULL;
            }
          GNUNET_free (fn);
        }
      break;
    case GNUNET_FSUI_upload_progress:
#if DEBUG_VERBOSE > 1
      printf ("Upload is progressing (%llu/%llu)...\n",
              event->data.UploadProgress.completed,
              event->data.UploadProgress.total);
#endif
      break;
    case GNUNET_FSUI_upload_completed:
      upURI = GNUNET_ECRS_uri_duplicate (event->data.UploadCompleted.uri);
#if DEBUG_VERBOSE
      printf ("Upload complete.\n");
#endif
      break;
    case GNUNET_FSUI_download_completed:
#if DEBUG_VERBOSE
      printf ("Download complete.\n");
#endif
      if (checkHierarchy(43, DIRECTORY_TREE_SPEC) == GNUNET_OK)
        {
          GNUNET_FSUI_search_abort (ctx, search);
          GNUNET_FSUI_search_stop (ctx, search);
          search = NULL;
        }
      break;
    case GNUNET_FSUI_download_progress:
#if DEBUG_VERBOSE > 1
      printf ("Download is progressing (%llu/%llu)...\n",
              event->data.DownloadProgress.completed,
              event->data.DownloadProgress.total);
#endif
      break;
    case GNUNET_FSUI_unindex_progress:
#if DEBUG_VERBOSE > 1
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
    case GNUNET_FSUI_upload_error:
    case GNUNET_FSUI_download_error:
      fprintf (stderr, "Received ERROR: %d\n", event->type);
      GNUNET_GE_BREAK (ectx, 0);
      break;
    case GNUNET_FSUI_download_aborted:
#if DEBUG_VERBOSE
      printf ("Received download aborted event.\n");
#endif
      break;
    case GNUNET_FSUI_unindex_suspended:
    case GNUNET_FSUI_upload_suspended:
    case GNUNET_FSUI_upload_started:
    case GNUNET_FSUI_upload_stopped:
    case GNUNET_FSUI_download_started:
    case GNUNET_FSUI_download_stopped:
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
  if (lastEvent == waitForEvent)
    return NULL;                /* ignore all other events */
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
  struct GNUNET_ECRS_URI *uri = NULL;
  char *fn = NULL;
  char *keywords[] = {
    "down_foo",
    "down_bar",
    NULL,
  };
  char keyword[40];
  int prog;
  struct GNUNET_ECRS_MetaData *meta;
  struct GNUNET_ECRS_URI *kuri = NULL;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_FSUI_UnindexList *unindex = NULL;
  struct GNUNET_FSUI_UploadList *upload = NULL;

  ok = GNUNET_YES;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_DAEMON
  GNUNET_disk_directory_remove (NULL, "/tmp/gnunet-fsui-test/content/");
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg,
                                         30 * GNUNET_CRON_SECONDS));
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
  /* ACTUAL TEST CODE */
#endif
  ctx = GNUNET_FSUI_start (NULL,
                           cfg, "fsuirecursivetest", 32, GNUNET_YES,
                           &eventCallback, NULL);
  CHECK (ctx != NULL);
  fn = makeHierarchy(42, DIRECTORY_TREE_SPEC);
  meta = GNUNET_ECRS_meta_data_create ();
  kuri = GNUNET_ECRS_keyword_list_to_uri (ectx, 2, (const char **) keywords);
  waitForEvent = GNUNET_FSUI_upload_completed;
  upload = GNUNET_FSUI_upload_start (ctx,
                                     fn,
                                     (GNUNET_FSUI_DirectoryScanCallback) &
                                     GNUNET_disk_directory_scan, NULL, 0, 0,
                                     GNUNET_YES, GNUNET_NO, GNUNET_NO,
                                     GNUNET_get_time () +
                                     5 * GNUNET_CRON_HOURS, meta, kuri, kuri);
  CHECK (upload != NULL);
  GNUNET_ECRS_uri_destroy (kuri);
  kuri = NULL;
  GNUNET_ECRS_meta_data_destroy (meta);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_upload_completed)
    {
      prog++;
      CHECK (prog < 5000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  GNUNET_FSUI_upload_stop (ctx, upload);
  GNUNET_snprintf (keyword, 40, "%s %s %s", keywords[0], _("AND"),
                   keywords[1]);
  uri = GNUNET_ECRS_keyword_string_to_uri (ectx, keyword);
  waitForEvent = GNUNET_FSUI_download_completed;
  search = GNUNET_FSUI_search_start (ctx, 0, uri);
  CHECK (search != NULL);
  prog = 0;
  while (search != NULL)
    {
      prog++;
      CHECK (prog < 1000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  CHECK (search == NULL);
  CHECK (download != NULL);
  /* TODO: how to unindex empty directories? */
/*  waitForEvent = GNUNET_FSUI_unindex_completed;
  unindex = GNUNET_FSUI_unindex_start (ctx, fn);
  CHECK (unindex != NULL);
  prog = 0;
  while (lastEvent != GNUNET_FSUI_unindex_completed)
    {
      prog++;
      CHECK (prog < 5000);
      GNUNET_thread_sleep (50 * GNUNET_CRON_MILLISECONDS);
      CHECK (lastEvent != GNUNET_FSUI_unindex_error);
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
    }
  CHECK (lastEvent == GNUNET_FSUI_unindex_completed);*/
  /* END OF TEST CODE */
FAILURE:
  if (ctx != NULL)
    {
      if (unindex != NULL)
        GNUNET_FSUI_unindex_stop (ctx, unindex);
      if (download != NULL)
        GNUNET_FSUI_download_stop (ctx, download);
      if (search != NULL)
        GNUNET_FSUI_search_stop (ctx, search);
      GNUNET_FSUI_stop (ctx);
    }
    if (fn != NULL)
    {
      GNUNET_disk_directory_remove (NULL, fn);
      GNUNET_free (fn);
    }
  if (uri != NULL)
    GNUNET_ECRS_uri_destroy (uri);
  if (kuri != NULL)
    GNUNET_ECRS_uri_destroy (kuri);
  fn = makeName (43);
  GNUNET_disk_directory_remove (NULL, fn);
  GNUNET_free (fn);
  if (upURI != NULL)
    GNUNET_ECRS_uri_destroy (upURI);

#if START_DAEMON
  GNUNET_GE_BREAK (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
#endif
  GNUNET_GC_free (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of recursivetest.c */