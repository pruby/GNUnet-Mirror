/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2007, 2008 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file applications/gap/test_multi_results.c
 * @brief GAP routing testcase, linear topology
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"
#include "gnunet_stats_lib.h"

#define START_PEERS 1

#define PEER_COUNT 2

/**
 * How many search results are there?
 */
#define TOTAL 40

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_ECRS_URI *uris[TOTAL];

static struct GNUNET_ECRS_URI *key;

static unsigned int found;

static int
testTerminate (void *unused)
{
  /* wait for us to find 90% */
  return (found > (TOTAL * 90) / 100) ? GNUNET_SYSERR : GNUNET_OK;
}

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = GNUNET_malloc (strlen ("/tmp/gnunet-gaptest/GAPTEST") + 14);
  GNUNET_snprintf (fn,
                   strlen ("/tmp/gnunet-gaptest/GAPTEST") + 14,
                   "/tmp/gnunet-gaptest/GAPTEST%u", i);
  GNUNET_disk_directory_create_for_file (NULL, fn);
  return fn;
}

static struct GNUNET_ECRS_URI *
uploadFile (int size)
{
  int ret;
  char *name;
  int fd;
  char *buf;
  struct GNUNET_ECRS_URI *uri;

  name = makeName (size);
  fd =
    GNUNET_disk_file_open (ectx, name, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
  if (fd == -1)
    {
      GNUNET_free (name);
      return NULL;
    }
  buf = GNUNET_malloc (size);
  memset (buf, size % 255, size);
  WRITE (fd, buf, size);
  GNUNET_free (buf);
  GNUNET_disk_file_close (ectx, name, fd);
  ret = GNUNET_ECRS_file_upload (ectx, cfg, name, GNUNET_YES,   /* index */
                                 1,     /* anon */
                                 0,     /* priority */
                                 GNUNET_get_time () + 100 * GNUNET_CRON_MINUTES,        /* expire */
                                 NULL, NULL, &testTerminate, NULL, &uri);
  if (ret != GNUNET_SYSERR)
    {
      struct GNUNET_ECRS_MetaData *meta;

      meta = GNUNET_ECRS_meta_data_create ();
      ret = GNUNET_ECRS_publish_under_keyword (ectx, cfg, key, 0, 0, GNUNET_get_time () + 100 * GNUNET_CRON_MINUTES,    /* expire */
                                               uri, meta);
      GNUNET_ECRS_meta_data_destroy (meta);
      GNUNET_free (name);
      if (ret == GNUNET_OK)
        return uri;
      GNUNET_ECRS_uri_destroy (uri);
      return NULL;
    }
  else
    {
      GNUNET_ECRS_uri_destroy (uri);
      GNUNET_free (name);
      return NULL;
    }
}

static int
searchCB (const GNUNET_ECRS_FileInfo * fi,
          const GNUNET_HashCode * key, int isRoot, void *closure)
{
  int i;

  for (i = 0; i < TOTAL; i++)
    {
      if ((uris[i] != NULL) &&
          (GNUNET_ECRS_uri_test_equal (uris[i], fi->uri)))
        {
          GNUNET_ECRS_uri_destroy (uris[i]);
          uris[i] = NULL;
          found++;
          fprintf (stderr, ".");
          return GNUNET_OK;
        }
    }
  return GNUNET_OK;
}

#define CHECK(a) if (!(a)) { ret = 1; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; }

/**
 * Testcase to test gap routing (2 peers only).
 * @return 0: ok, -1: error
 */
int
main (int argc, char **argv)
{
  struct GNUNET_TESTING_DaemonContext *peers;
  int ret;
  int i;
  char buf[128];

  ret = 0;
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_PEERS
  peers = GNUNET_TESTING_start_daemons ("tcp",
                                        "advertising topology fs stats",
                                        "/tmp/gnunet-gap-muti-results-test",
                                        2087, 10, PEER_COUNT);
  if (peers == NULL)
    {
      fprintf (stderr, "Failed to start the gnunetd daemons!\n");
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  for (i = 1; i < PEER_COUNT; i++)
    {
      if (GNUNET_OK != GNUNET_TESTING_connect_daemons (2077 + (10 * i),
                                                       2087 + (10 * i)))
        {
          GNUNET_TESTING_stop_daemons (peers);
          fprintf (stderr, "Failed to connect the peers!\n");
          GNUNET_GC_free (cfg);
          return -1;
        }
    }
  key = GNUNET_ECRS_keyword_string_to_uri (NULL, "multi-test");
  fprintf (stderr, "Uploading...");
  for (i = 0; i < TOTAL; i++)
    {
      uris[i] = uploadFile (i + 1);
      CHECK (uris[i] != NULL);
      fprintf (stderr, ".");
    }
  fprintf (stderr, "\nSearching...");
  GNUNET_snprintf (buf, 128, "localhost:%u", 2077 + PEER_COUNT * 10);
  GNUNET_GC_set_configuration_value_string (cfg, ectx, "NETWORK", "HOST",
                                            buf);

  GNUNET_ECRS_search (ectx,
                      cfg, key, 1, &searchCB, NULL, &testTerminate, NULL);
  fprintf (stderr, "\n");
  CHECK (found > (TOTAL * 90) / 100);
FAILURE:
#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif
  GNUNET_ECRS_uri_destroy (key);
  GNUNET_GC_free (cfg);
  return ret;
}

/* end of test_multi_results.c */
