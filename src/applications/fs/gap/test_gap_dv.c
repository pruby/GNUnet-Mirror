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

#define VERBOSE GNUNET_NO
/**
 * How many peers should the testcase run?
 */
#define NUM_PEERS 15

/**
 * How many files of size (size * i) should we insert?
 */
#define NUM_FILES 50
/**
 * How many times will the info loop execute?
 * Approximate number of minutes for test (must be
 * long enough for fs/dht to get around to inserting)
 */
#define NUM_REPEAT 21

#define DOWNLOAD_TIMEOUT_SECONDS 60

#define EC_ARGUMENTS -1
#define EC_COMPLETED 0
#define EC_INCOMPLETE 1
#define EC_ABORTED 2
#define EC_DOWNLOAD_ERROR 3
#define EC_DOWNLOAD_TIMEOUT 4
#define START_SIZE 200000
#define SIZE_INCREMENT 3000

#ifdef WAIT
static int ok;
#endif

static int carry_on;
static int errorCode;
static int have_uri;
static unsigned int downloads_running;

static unsigned long long total_gap_queries_sent;
static unsigned long long total_gap_requests_started;
static unsigned long long total_gap_replies_to_client;
static unsigned long long total_gap_dv_requests_sent;
static unsigned long long total_gap_requests_dropped;
static unsigned long long total_gap_requests_received;
static unsigned long long total_gap_dv_replies;

/* Main URI to be assigned for each file */
static struct GNUNET_ECRS_URI *file_uri;

#ifdef WAIT
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
#endif

#define CHECK(a) do { if (!(a)) { ret = 1; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; } } while(0)

static int
getGAPStats (const char *name, unsigned long long value, void *cls)
{
  if ((value > 0) && (strstr (name, _("# gap client requests injected")) != NULL))
		total_gap_requests_started += value;
  else if ((value > 0) && (strstr (name, _("# gap requests total sent")) != NULL))
  	total_gap_queries_sent += value;
	else if ((value > 0) && (strstr (name, _("# dv gap requests sent")) != NULL))
		total_gap_dv_requests_sent += value;
	else if ((value > 0) && (strstr (name, _("# gap replies sent to client")) != NULL))
		total_gap_replies_to_client += value;
	else if ((value > 0) && (strstr (name, _("# gap requests dropped due to load")) != NULL))
		total_gap_requests_dropped += value;
	else if ((value > 0) && (strstr (name, _("# gap requests total received")) != NULL))
		total_gap_requests_received += value;
	else if ((value > 0) && (strstr (name, _("# gap replies sent via dv")) != NULL))
		total_gap_dv_replies += value;
  return GNUNET_OK;
}

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
 * Handle the search result.
 */
static void *
eventCallback (void *cls, const GNUNET_FSUI_Event * event)
{
#if VERBOSE
  GNUNET_EncName *enc;
  enc = GNUNET_malloc (sizeof (GNUNET_EncName));
#endif
  switch (event->type)
    {
    case GNUNET_FSUI_search_aborted:
      errorCode = 4;
      break;
    case GNUNET_FSUI_search_result:
      /*memcpy(&file_uri, event->data.SearchResult.fi.uri, sizeof(event->data.SearchResult.fi.uri));*/
      file_uri = GNUNET_ECRS_uri_duplicate(event->data.SearchResult.fi.uri);
      have_uri = GNUNET_YES;
#if VERBOSE
      if (GNUNET_ECRS_uri_test_loc (event->data.SearchResult.fi.uri))
        {
          GNUNET_ECRS_locURI_extract_peer (event->data.SearchResult.fi.uri,
                                           &enc);
          fprintf (stdout, "Received locURI putting data at peer %s\n",
                   (char *) enc);
        }
#endif
      fflush (stdout);
      break;
    case GNUNET_FSUI_search_started:
    case GNUNET_FSUI_search_stopped:
    case GNUNET_FSUI_search_update:
      break;
    default:
      GNUNET_GE_BREAK (NULL, 0);
      break;
    }
  return NULL;
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
      while ((carry_on == GNUNET_NO) && (GNUNET_shutdown_test () != GNUNET_YES))
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
 * This method is called whenever data is received.
 * The current incarnation just ensures that the main
 * method exits once the download is complete.
 */
static void *
progressModel (void *unused, const GNUNET_FSUI_Event * event)
{
	int verbose = VERBOSE;
  switch (event->type)
    {
    case GNUNET_FSUI_download_progress:
    	if (verbose)
			{
				PRINTF (_("Download of file `%s' at "
									"%16llu out of %16llu bytes (%8.3f KiB/s)\n"),
								event->data.DownloadProgress.filename,
								event->data.DownloadProgress.completed,
								event->data.DownloadProgress.total,
								(event->data.DownloadProgress.completed / 1024.0) /
								(((double) (GNUNET_get_time () - (event->data.DownloadStarted.dc.pos->startTime - 1)))
								 / (double) GNUNET_CRON_SECONDS));
			}
      break;
    case GNUNET_FSUI_download_aborted:
			errorCode = EC_ABORTED;
      break;
    case GNUNET_FSUI_download_error:
      printf (_("Error downloading: %s\n"),
              event->data.DownloadError.message);
      errorCode = EC_DOWNLOAD_ERROR;
      break;
    case GNUNET_FSUI_download_completed:
    	if (verbose)
    	{
				PRINTF (_("Download of file `%s' complete.  "
									"Speed was %8.3f KiB per second.\n"),
								event->data.DownloadCompleted.filename,
								(event->data.DownloadCompleted.total / 1024.0) /
								(((double) (GNUNET_get_time () - (event->data.DownloadStarted.dc.pos->startTime - 1)))
								 / (double) GNUNET_CRON_SECONDS));
    	}
      downloads_running--;

      if (downloads_running == 0)
        {
          errorCode = 0;
        }
      break;
    case GNUNET_FSUI_download_started:
      downloads_running++;

    case GNUNET_FSUI_download_stopped:
      break;
    default:
      break;
    }

  return NULL;
}

static int
downloadFile (struct GNUNET_GC_Configuration *cfg, struct GNUNET_GE_Context *ectx, struct GNUNET_ECRS_URI *uri)
{
  char *name;
  struct GNUNET_MetaData *meta;
  struct GNUNET_FSUI_DownloadList *dl;
  GNUNET_CronTime start_time;
  struct GNUNET_FSUI_Context *ctx;
  int count;

  name = strdup("/tmp/gaptestfile");

  carry_on = GNUNET_NO;
  downloads_running = 0;
  ctx = GNUNET_FSUI_start (ectx,
                           cfg,
                           "gnunet-download",
                           32,
                           GNUNET_NO, &progressModel, NULL);

	start_time = GNUNET_get_time ();
	errorCode = 1;
	meta = GNUNET_meta_data_create ();
	dl = GNUNET_FSUI_download_start (ctx, (unsigned int)0, 0, uri, meta, name, NULL, NULL);

	GNUNET_meta_data_destroy (meta);
	if (dl == NULL)
		{
			GNUNET_FSUI_stop (ctx);
			errorCode = -1;
		}

	count = 0;
	while ((errorCode == 1) && (count < DOWNLOAD_TIMEOUT_SECONDS) && (GNUNET_shutdown_test () != GNUNET_YES))
	{
		GNUNET_thread_sleep (1 * GNUNET_CRON_SECONDS);
		count++;
	}

	if (count >= DOWNLOAD_TIMEOUT_SECONDS)
		errorCode = EC_DOWNLOAD_TIMEOUT;

	if (dl != NULL)
		{
			GNUNET_FSUI_download_stop(dl);
			GNUNET_FSUI_download_abort(dl);
		}

  GNUNET_FSUI_stop (ctx);

  unlink (name);
	return errorCode;
}


static int
search (struct GNUNET_GC_Configuration *cfg, struct GNUNET_GE_Context *ectx, char *keyword)
{
  struct GNUNET_ECRS_URI *key;
  struct GNUNET_FSUI_SearchList *s;
  struct GNUNET_FSUI_Context *ctx;
  unsigned long long verbose = VERBOSE;

  have_uri = GNUNET_NO;
  ctx =
    GNUNET_FSUI_start (ectx, cfg, "gnunet-search", 4, GNUNET_NO,
                       &eventCallback, &verbose);

  if (ctx == NULL)
    {
      GNUNET_fini (ectx, cfg);
      return GNUNET_SYSERR;
    }

  key = GNUNET_ECRS_keyword_string_to_uri (NULL, keyword);
  errorCode = 1;

  s = GNUNET_FSUI_search_start (ctx, 0, key);
  GNUNET_ECRS_uri_destroy (key);
  if (s == NULL)
    {
      errorCode = 2;
      GNUNET_FSUI_stop (ctx);
    }
  while ((have_uri == GNUNET_NO) && (errorCode == 1) && (GNUNET_shutdown_test () != GNUNET_YES))
  {
  	GNUNET_thread_sleep(1 * GNUNET_CRON_SECONDS);
  }
  if (s != NULL)
  	GNUNET_FSUI_search_stop (s);
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
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;

  int size;
  int fd;
  int ret = 0;
  int i;
  int j;
  int len;

  unsigned long long old_total_gap_queries_sent;
  unsigned long long old_total_gap_requests_started;
  unsigned long long old_total_gap_replies_to_client;
  unsigned long long old_total_gap_dv_requests_sent;
  unsigned long long old_total_gap_dv_replies;
  unsigned long long old_total_gap_requests_dropped;
  unsigned long long new_total_gap_queries_sent;
  unsigned long long new_total_gap_requests_started;
  unsigned long long new_total_gap_replies_to_client;
  unsigned long long new_total_gap_dv_requests_sent;
  unsigned long long new_total_gap_dv_replies;
  unsigned long long new_total_gap_requests_dropped;

  unsigned int rand_peer;
  unsigned int temp_rand_peer;

  unsigned long long finish_time;

  char *keyword;
  char *buf;

  const char *filename;

  GNUNET_CronTime startTime;
  GNUNET_CronTime endTime;

  struct GNUNET_ClientServerConnection *sock;
#ifdef WAIT
	int r;
#endif

  fd = -1;
	if ((argc == 3) && (strcmp(argv[1], "-o") == 0))
	{
		filename = argv[2];
		fd = GNUNET_disk_file_open (NULL, filename, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
		if (fd == -1)
			return fd;
	}

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
  fprintf(stdout, "Sleeping for ten minutes\n");
  GNUNET_thread_sleep (600 * GNUNET_CRON_SECONDS);

  /* Insert at random peer, search for data (to get proper uri), then try to download
   * from peers 0, 1, 2, and 3 hops away from upload peer to get speed results. */
  for (i = 0; i < NUM_FILES; i++)
  {
    size = START_SIZE + (i * SIZE_INCREMENT);
  	if (GNUNET_shutdown_test() == GNUNET_YES)
  		break;
  	for (j = 0; j <= 3; j++)
		{
			rand_peer = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, NUM_PEERS);
			keyword = GNUNET_malloc(snprintf(NULL, 0, "gaptest%d", i) + 1);
			sprintf(keyword, "gaptest%d%d", i, j);
			fprintf(stdout, "Inserting data size %d, keyword %s at peer %d\n", size, keyword, NUM_PEERS - rand_peer - 1);
			ret = uploadFile(peer_array[rand_peer]->config, ectx, size, keyword);
			if (ret != 0)
			{
				fprintf(stderr, "Got bad return (%d) from uploadFile, moving to next test!\n", ret);
				continue;
			}

			if (GNUNET_shutdown_test() == GNUNET_YES)
				break;
			ret = search(peer_array[rand_peer]->config, ectx, keyword);
			if (((ret != 1) && (ret != 4)) || (have_uri == GNUNET_NO))
			{
				fprintf(stderr, "Got bad return (%d) from search (or have_uri %d is bad), moving to next test!\n", ret, have_uri);
				continue;
			}
			if (GNUNET_shutdown_test() == GNUNET_YES)
				break;

			temp_rand_peer = rand_peer + j;
			if (temp_rand_peer >= NUM_PEERS)
			{
				temp_rand_peer = temp_rand_peer - NUM_PEERS;
			}
			startTime = GNUNET_get_time();
			fprintf (stdout, "Attempting download from %d (index of peer %d)\n", NUM_PEERS - temp_rand_peer - 1, temp_rand_peer);
			ret = downloadFile(peer_array[temp_rand_peer]->config, ectx, file_uri);
			endTime = GNUNET_get_time();
			if (ret != 0)
			{
				fprintf(stderr, "Got bad return (%d) from download, this one failed!\n", ret);
				finish_time = 0;
			}
			else
			{
			  fprintf (stdout, "Download from peer %d away took %llu milliseconds\n", j, (endTime - startTime));
			  finish_time = endTime - startTime;
			}

			old_total_gap_queries_sent = total_gap_queries_sent;
			old_total_gap_requests_started = total_gap_requests_started;
			old_total_gap_replies_to_client = total_gap_replies_to_client;
			old_total_gap_dv_requests_sent = total_gap_dv_requests_sent;
      old_total_gap_dv_replies = total_gap_dv_replies;
      old_total_gap_requests_dropped = total_gap_requests_dropped;

			total_gap_queries_sent = 0;
			total_gap_requests_started = 0;
			total_gap_replies_to_client = 0;
			total_gap_dv_requests_sent = 0;
			total_gap_dv_replies = 0;
			total_gap_requests_dropped = 0;

			for (i = 0; i < NUM_PEERS; i++)
				{
					if (GNUNET_shutdown_test () == GNUNET_YES)
						break;

					sock =
						GNUNET_client_connection_create (NULL, peer_array[i]->config);
					GNUNET_STATS_get_statistics (NULL, sock, &getGAPStats, NULL);
					GNUNET_client_connection_destroy (sock);
				}

			new_total_gap_queries_sent = total_gap_queries_sent - old_total_gap_queries_sent;
			new_total_gap_requests_started = total_gap_requests_started - old_total_gap_requests_started;
			new_total_gap_replies_to_client = total_gap_replies_to_client - old_total_gap_replies_to_client;
			new_total_gap_dv_requests_sent = total_gap_dv_requests_sent - old_total_gap_dv_requests_sent;
			new_total_gap_dv_replies = total_gap_dv_replies - old_total_gap_dv_replies;
			new_total_gap_requests_dropped = total_gap_requests_dropped - old_total_gap_requests_dropped;

			fprintf(stdout, "Total gap requests initiated: %llu\nTotal gap queries sent: %llu\nTotal dv requests sent: %llu\nTotal replies to clients: %llu\nTotal gap dv replies: %llu\nTotal gap requests dropped: %llu\n", new_total_gap_requests_started, new_total_gap_requests_started, new_total_gap_dv_requests_sent, new_total_gap_replies_to_client, new_total_gap_dv_replies, new_total_gap_requests_dropped);

	     if (fd != -1)
	      {
	        len = snprintf(NULL, 0, "%d\t%d\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\n", size, j, finish_time, new_total_gap_queries_sent, new_total_gap_requests_started, new_total_gap_replies_to_client, new_total_gap_dv_requests_sent, new_total_gap_dv_replies, new_total_gap_requests_dropped) + 1;
	        buf = GNUNET_malloc(len);
	        sprintf(buf, "%d\t%d\t%llu\n", size, j, finish_time);
	        ret = WRITE (fd, buf, len - 1);
	        GNUNET_free(buf);
	      }

			if (GNUNET_shutdown_test() == GNUNET_YES)
				break;
			GNUNET_free(file_uri);
			GNUNET_free(keyword);
 	  }
	}

  if (fd != -1)
  	CLOSE (fd);

#ifdef WAIT
  fprintf (stdout, "Will run for %d minutes\n", NUM_REPEAT);
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
#endif

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
