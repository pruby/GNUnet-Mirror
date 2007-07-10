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
 * @file applications/fs/fsui/serializetest.c
 * @brief testcase for fsui upload persistence
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

  fn = MALLOC (strlen ("/tmp/gnunet-fsui-serializetest/FSUITEST") + 14);
  SNPRINTF (fn,
            strlen ("/tmp/gnunet-fsui-serializetest/FSUITEST") + 14,
            "/tmp/gnunet-fsui-serializetest/FSUITEST%u", i);
  disk_directory_create_for_file (NULL, fn);
  return fn;
}

static volatile enum FSUI_EventType lastEvent;
static volatile enum FSUI_EventType waitForEvent;
static struct FSUI_Context *ctx;
static struct ECRS_URI *upURI;
static struct FSUI_UnindexList *unindex;
static struct FSUI_UploadList *upload;


static void *
eventCallback (void *cls, const FSUI_Event * event)
{
  switch (event->type)
    {
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
    case FSUI_unindex_resumed:
#if DEBUG_VERBOSE
      fprintf (stderr, "Received RESUMING: %d\n", event->type);
#endif
      unindex = event->data.UnindexResumed.uc.pos;
      break;
    case FSUI_upload_resumed:
#if DEBUG_VERBOSE
      fprintf (stderr, "Received RESUMING: %d\n", event->type);
#endif
      upload = event->data.UploadResumed.uc.pos;
      break;
      break;
    case FSUI_unindex_suspended:
      unindex = NULL;
#if DEBUG_VERBOSE
      fprintf (stderr, "Received SUSPENDING: %d\n", event->type);
#endif
      break;
    case FSUI_upload_suspended:
      upload = NULL;
#if DEBUG_VERBOSE
      fprintf (stderr, "Received SUSPENDING: %d\n", event->type);
#endif
      break;
    case FSUI_upload_started:
    case FSUI_upload_stopped:
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
  char *fn = NULL;
  char *keywords[] = {
    "down_foo",
    "down_bar",
    NULL,
  };
  int prog;
  char *buf;
  struct ECRS_MetaData *meta;
  struct ECRS_URI *kuri = NULL;
  struct GC_Configuration *cfg;

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
                    cfg, "fsuiserializetest", 32, YES, &eventCallback, NULL);
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
  suspendRestart = 4;
  while (lastEvent != FSUI_upload_completed)
    {
      if ((suspendRestart > 0) && (weak_randomi (4) == 0))
        {
#if 1
#if DEBUG_VERBOSE
          printf ("Testing FSUI suspend-resume\n");
#endif
          FSUI_stop (ctx);      /* download possibly incomplete
                                   at this point, thus testing resume */
          ctx = FSUI_start (NULL,
                            cfg,
                            "fsuiserializetest",
                            32, YES, &eventCallback, NULL);
#if DEBUG_VERBOSE
          printf ("Resumed...\n");
#endif
#endif
          suspendRestart--;
        }
      prog++;
      CHECK (prog < 5000);
      PTHREAD_SLEEP (50 * cronMILLIS);
      if (GNUNET_SHUTDOWN_TEST () == YES)
        break;
    }
  FSUI_stopUpload (ctx, upload);
  waitForEvent = FSUI_unindex_completed;
  unindex = FSUI_startUnindex (ctx, fn);
  CHECK (unindex != NULL);
  prog = 0;
  suspendRestart = 4;
  while (lastEvent != FSUI_unindex_completed)
    {
      if ((suspendRestart > 0) && (weak_randomi (4) == 0))
        {
#if 1
#if DEBUG_VERBOSE
          printf ("Testing FSUI suspend-resume\n");
#endif
          FSUI_stop (ctx);      /* download possibly incomplete
                                   at this point, thus testing resume */
          ctx = FSUI_start (NULL,
                            cfg,
                            "fsuiserializetest",
                            32, YES, &eventCallback, NULL);
#if DEBUG_VERBOSE
          printf ("Resumed...\n");
#endif
#endif
          suspendRestart--;
        }
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
      FSUI_stop (ctx);
    }
  if (fn != NULL)
    {
      UNLINK (fn);
      FREE (fn);
    }
  if (kuri != NULL)
    ECRS_freeUri (kuri);
  fn = makeName (43);
  /* TODO: verify file 'fn(42)' == file 'fn(43)' */
  UNLINK (fn);
  FREE (fn);
  if (upURI != NULL)
    ECRS_freeUri (upURI);

#if START_DAEMON
  GE_ASSERT (NULL, OK == os_daemon_stop (NULL, daemon));
#endif
  GC_free (cfg);
  return (ok == YES) ? 0 : 1;
}

/* end of downloadtest.c */
