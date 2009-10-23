/*
     This file is part of GNUnet.
     (C) 2007, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/gap/test_gap_dv.c
 * @brief gap with distance vector testcase
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"
#include "gnunet_remote_lib.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_identity_lib.h"
#include "gnunet_fsui_lib.h"
#include "../fsui/fsui.h"

#define VERBOSE GNUNET_YES
/**
 * How many peers should the testcase run?
 */
#define NUM_PEERS 15

/**
 * How many files of size (size * i) should we insert?
 */
#define NUM_FILES 20
/**
 * How many times will the info loop execute?
 * Approximate number of minutes for test (must be
 * long enough for fs/dht to get around to inserting)
 */
#define NUM_REPEAT 20
static int ok;
static int carry_on;
static int errorCode;

static int
getPeers (const char *name, unsigned long long value, void *cls)
{
  if ((value > 0) && (strstr (name, _("# dv")) != NULL))
    {
      fprintf (stderr, "%s : %llu\n", name, value);
    }

  if ((value > 0) && (0 == strcmp (_("# dv_dht connections"), name)))
    {
      ok = 1;
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

#define CHECK(a) do { if (!(a)) { ret = 1; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; } } while(0)

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = GNUNET_malloc (strlen ("/tmp/gaptest/GAPTEST") + 14);
  GNUNET_snprintf (fn,
                   strlen ("/tmp/gaptest/GAPTEST") + 14,
                   "/tmp/gaptest/GAPTEST%u", i);
  GNUNET_disk_directory_create_for_file (NULL, fn);
  return fn;
}

/**
 * Print progress messages.
 */
static void *
printstatus (void *ctx, const GNUNET_FSUI_Event * event)
{
  unsigned long long *verboselevel = ctx;
  unsigned long long delta;
  char *fstring;

  switch (event->type)
    {
    case GNUNET_FSUI_upload_progress:
      if (*verboselevel)
        {
          char *ret;
          GNUNET_CronTime now;

          now = GNUNET_get_time ();
          delta = event->data.UploadProgress.eta - now;
          if (event->data.UploadProgress.eta < now)
            delta = 0;
          ret = GNUNET_get_time_interval_as_fancy_string (delta);
          PRINTF (_("%16llu of %16llu bytes inserted "
                    "(estimating %6s to completion) - %s\n"),
                  event->data.UploadProgress.completed,
                  event->data.UploadProgress.total,
                  ret, event->data.UploadProgress.filename);
          GNUNET_free (ret);
        }
      break;
    case GNUNET_FSUI_upload_completed:
      if (*verboselevel)
        {
          delta = GNUNET_get_time () - event->data.UploadCompleted.uc.pos->start_time;
          PRINTF (_("Upload of `%s' complete, "
                    "%llu bytes took %llu msecs (%8.3f KiB/s).\n"),
                  event->data.UploadCompleted.filename,
                  event->data.UploadCompleted.total,
                  delta / GNUNET_CRON_MILLISECONDS,
                  (delta == 0)
                  ? (double) (-1.0)
                  : (double) (event->data.UploadCompleted.total
                              / 1024.0 * GNUNET_CRON_SECONDS / delta));
        }
      fstring = GNUNET_ECRS_uri_to_string (event->data.UploadCompleted.uri);
      printf (_("File `%s' has URI: %s\n"),
              event->data.UploadCompleted.filename, fstring);
      GNUNET_free (fstring);
      errorCode = 0;
			carry_on = GNUNET_YES;
      break;
    case GNUNET_FSUI_upload_aborted:
      printf (_("\nUpload aborted.\n"));
      errorCode = 2;
      carry_on = GNUNET_YES;
      break;
    case GNUNET_FSUI_upload_error:
      printf (_("\nError uploading file: %s"),
              event->data.UploadError.message);
      errorCode = 3;
      carry_on = GNUNET_YES;
      break;
    case GNUNET_FSUI_upload_started:
    case GNUNET_FSUI_upload_stopped:
      break;
    default:
      printf (_("\nUnexpected event: %d\n"), event->type);
      GNUNET_GE_BREAK (NULL, 0);
      break;
    }
  return NULL;
}

static int
uploadFile (struct GNUNET_GC_Configuration *cfg, struct GNUNET_GE_Context *ectx, int size, char *keyword)
{
  char *name;
  char *buf;
  int fd;
  struct GNUNET_ECRS_URI *key;
  struct GNUNET_MetaData *meta;
  struct GNUNET_FSUI_UploadList *ul;
  struct GNUNET_ECRS_URI *gloKeywords;
  GNUNET_CronTime start_time;
  int ret;
  struct GNUNET_FSUI_Context *ctx;
  unsigned long long verbose = VERBOSE;

  name = makeName (size);
  fd =
    GNUNET_disk_file_open (ectx, name, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
  if (fd == -1)
    {
      GNUNET_free (name);
      return -1;
    }
  meta = GNUNET_meta_data_create ();
  key = GNUNET_ECRS_keyword_string_to_uri (NULL, keyword);
  gloKeywords = GNUNET_ECRS_keyword_string_to_uri (NULL, keyword);
  buf = GNUNET_malloc (size);
  memset (buf, size % 255, size);
  ret = WRITE (fd, buf, size);

  GNUNET_free (buf);
  GNUNET_disk_file_close (ectx, name, fd);
  if (ret == -1)
  	return ret;

  carry_on = GNUNET_NO;
  ctx = GNUNET_FSUI_start (ectx, cfg, "gnunet-insert", GNUNET_NO, 32,   /* make configurable */
													 &printstatus, &verbose);

	/* first insert all of the top-level files or directories */
	GNUNET_meta_data_add_publication_date (meta);
	start_time = GNUNET_get_time ();
	ul = GNUNET_FSUI_upload_start (ctx,
																 name, NULL, ectx, 0,
																 365,
																 GNUNET_YES,
																 GNUNET_NO, GNUNET_YES,
																 start_time + (200 * GNUNET_CRON_MINUTES), meta,
																 gloKeywords, key);

  if (ul != NULL)
    {
      while (carry_on == GNUNET_NO)
      {
      	GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
      	continue;
      }
      if (errorCode == 1)
        GNUNET_FSUI_upload_abort (ul);
      GNUNET_FSUI_upload_stop (ul);
    }
  GNUNET_FSUI_stop (ctx);

	return errorCode;
}


/**
 * Testcase to test gap/dv_dht/fs_dv/dv integration
 * @return 0: ok, -1: error
 */
int
main (int argc, const char **argv)
{
  struct GNUNET_REMOTE_TESTING_DaemonContext *peers;
  struct GNUNET_REMOTE_TESTING_DaemonContext *peer_array[NUM_PEERS];
  struct GNUNET_REMOTE_TESTING_DaemonContext *pos;
  int ret = 0;
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_ClientServerConnection *sock;
  int i;
  int r;
  unsigned int rand_peer;
  char *keyword;
  int size;

  size = 250; /* Arbitrary */
  ectx = NULL;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "gap_test.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  GNUNET_GC_set_configuration_value_string (cfg, NULL,
                                            "MULTIPLE_SERVER_TESTING",
                                            "DOT_OUTPUT", "topology.dot");
  printf ("Starting %u peers...\n", NUM_PEERS);
  GNUNET_REMOTE_start_daemons (&peers, cfg, NUM_PEERS);
  if (peers == NULL)
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  pos = peers;
  for (i = 0; i < NUM_PEERS; i++)
    {
      peer_array[i] = pos;
      pos = pos->next;
    }
  sleep (30);

  /* Insert some data */
  rand_peer = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, NUM_PEERS);

  for (i = 0; i < NUM_FILES; i++)
  {
  	keyword = GNUNET_malloc(snprintf(NULL, 0, "gaptest%d", i) + 1);
  	sprintf(keyword, "gaptest%d", i);
  	fprintf(stdout, "Inserting data size %d, keyword %s at peer %d\n", size, keyword, NUM_PEERS - rand_peer);
 	  ret = uploadFile(peer_array[rand_peer]->config, ectx, (size * (i + 1))*(size * (i + 1)), keyword);
  	GNUNET_free(keyword);
	}

  fprintf (stdout, "Will run for %d minues\n", NUM_REPEAT);
  for (r = 0; r < NUM_REPEAT; r++)
    {
      fprintf (stderr, "After %d minutes\n", r);
      for (i = 0; i < NUM_PEERS; i++)
        {
          if (GNUNET_shutdown_test () == GNUNET_YES)
            break;
          fprintf (stderr, "Peer %d: ", i);
          sock =
            GNUNET_client_connection_create (NULL, peer_array[i]->config);
          GNUNET_STATS_get_statistics (NULL, sock, &getPeers, NULL);
          GNUNET_thread_sleep (2 * GNUNET_CRON_SECONDS);
          GNUNET_client_connection_destroy (sock);

        }
      if (GNUNET_shutdown_test () == GNUNET_YES)
        break;
      sleep (60);
    }

  pos = peers;
  while (pos != NULL)
    {
      GNUNET_REMOTE_kill_daemon (pos);
      pos = pos->next;
    }
  GNUNET_GC_free (cfg);
  return ret;
}

/* end of test_gap_dv.c */
