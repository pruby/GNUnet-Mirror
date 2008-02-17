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
 * @file applications/gap/test_linear_topology.c
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

#define PEER_COUNT 4

#define SIZE (1024 * 32 * 10)

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static int
testTerminate (void *unused)
{
  return GNUNET_OK;
}

static void
uprogress (unsigned long long totalBytes,
           unsigned long long completedBytes, GNUNET_CronTime eta,
           void *closure)
{
  fprintf (stderr, totalBytes == completedBytes ? "\n" : ".");
}

static void
dprogress (unsigned long long totalBytes,
           unsigned long long completedBytes,
           GNUNET_CronTime eta,
           unsigned long long lastBlockOffset,
           const char *lastBlock, unsigned int lastBlockSize, void *closure)
{
  fprintf (stderr, totalBytes == completedBytes ? "\n" : ".");
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
uploadFile (unsigned int size)
{
  int ret;
  char *name;
  int fd;
  char *buf;
  struct GNUNET_ECRS_URI *uri;
  int i;

  name = makeName (size);
  fd =
    GNUNET_disk_file_open (ectx, name, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
  buf = GNUNET_malloc (size);
  memset (buf, size / 253, sizeof (GNUNET_HashCode));
  for (i = 0; i < size - sizeof (GNUNET_HashCode);
       i += sizeof (GNUNET_HashCode))
    GNUNET_hash (&buf[i], sizeof (GNUNET_HashCode),
                 (GNUNET_HashCode *) & buf[i + sizeof (GNUNET_HashCode)]);
  WRITE (fd, buf, size);
  GNUNET_free (buf);
  GNUNET_disk_file_close (ectx, name, fd);
  ret = GNUNET_ECRS_file_upload (ectx, cfg, name, GNUNET_YES,   /* index */
                                 1,     /* anon */
                                 0,     /* prio */
                                 GNUNET_get_time () + 100 * GNUNET_CRON_MINUTES,        /* expire */
                                 &uprogress,    /* progress */
                                 NULL, &testTerminate, NULL, &uri);
  if (ret != GNUNET_SYSERR)
    {
      struct GNUNET_ECRS_MetaData *meta;
      struct GNUNET_ECRS_URI *key;
      const char *keywords[2];

      keywords[0] = name;
      keywords[1] = NULL;

      meta = GNUNET_ECRS_meta_data_create ();
      key = GNUNET_ECRS_keyword_strings_to_uri (keywords);
      ret = GNUNET_ECRS_publish_under_keyword (ectx, cfg, key, 0, 0, GNUNET_get_time () + 100 * GNUNET_CRON_MINUTES,    /* expire */
                                               uri, meta);
      GNUNET_ECRS_meta_data_destroy (meta);
      GNUNET_ECRS_uri_destroy (uri);
      GNUNET_free (name);
      if (ret == GNUNET_OK)
        {
          return key;
        }
      else
        {
          GNUNET_ECRS_uri_destroy (key);
          return NULL;
        }
    }
  else
    {
      GNUNET_free (name);
      return NULL;
    }
}

static int
searchCB (const GNUNET_ECRS_FileInfo * fi,
          const GNUNET_HashCode * key, int isRoot, void *closure)
{
  struct GNUNET_ECRS_URI **my = closure;
  char *tmp;

  tmp = GNUNET_ECRS_uri_to_string (fi->uri);
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Search found URI `%s'\n", tmp);
  GNUNET_free (tmp);
  GNUNET_GE_ASSERT (ectx, NULL == *my);
  *my = GNUNET_ECRS_uri_duplicate (fi->uri);
  return GNUNET_SYSERR;         /* abort search */
}

/**
 * @param *uri In: keyword URI, out: file URI
 * @return GNUNET_OK on success
 */
static int
searchFile (struct GNUNET_ECRS_URI **uri)
{
  int ret;
  struct GNUNET_ECRS_URI *myURI;

  myURI = NULL;
  ret = GNUNET_ECRS_search (ectx,
                            cfg,
                            *uri, 1, &searchCB, &myURI, &testTerminate, NULL);
  GNUNET_ECRS_uri_destroy (*uri);
  *uri = myURI;
  if ((ret != GNUNET_SYSERR) && (myURI != NULL))
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}

static int
downloadFile (unsigned int size, const struct GNUNET_ECRS_URI *uri)
{
  int ret;
  char *tmpName;
  int fd;
  char *buf;
  char *in;
  int i;
  char *tmp;

  tmp = GNUNET_ECRS_uri_to_string (uri);
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Starting download of `%s'\n", tmp);
  GNUNET_free (tmp);
  tmpName = makeName (0);
  unlink (tmpName);
  ret = GNUNET_SYSERR;
  if (GNUNET_OK == GNUNET_ECRS_file_download (ectx,
                                              cfg,
                                              uri,
                                              tmpName,
                                              1, &dprogress, NULL,
                                              &testTerminate, NULL))
    {

      fd = GNUNET_disk_file_open (ectx, tmpName, O_RDONLY);
      buf = GNUNET_malloc (size);
      in = GNUNET_malloc (size);
      memset (buf, size / 253, sizeof (GNUNET_HashCode));
      for (i = 0; i < size - sizeof (GNUNET_HashCode);
           i += sizeof (GNUNET_HashCode))
        GNUNET_hash (&buf[i], sizeof (GNUNET_HashCode),
                     (GNUNET_HashCode *) & buf[i + sizeof (GNUNET_HashCode)]);
      if (size != READ (fd, in, size))
        ret = GNUNET_SYSERR;
      else if (0 == memcmp (buf, in, size))
        ret = GNUNET_OK;
      GNUNET_free (buf);
      GNUNET_free (in);
      GNUNET_disk_file_close (ectx, tmpName, fd);
    }
  UNLINK (tmpName);
  GNUNET_free (tmpName);
  return ret;
}

static int
unindexFile (unsigned int size)
{
  int ret;
  char *name;

  name = makeName (size);
  ret =
    GNUNET_ECRS_file_unindex (ectx, cfg, name, NULL, NULL, &testTerminate,
                              NULL);
  if (0 != UNLINK (name))
    ret = GNUNET_SYSERR;
  GNUNET_free (name);
  return ret;
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
  struct GNUNET_ECRS_URI *uri;
  int i;
  char buf[128];
  GNUNET_CronTime start;

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
                                        "/tmp/gnunet-gap-linear-test",
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

  printf ("Uploading...\n");
  uri = uploadFile (SIZE);
  CHECK (NULL != uri);
  GNUNET_snprintf (buf, 128, "localhost:%u", 2077 + PEER_COUNT * 10);
  GNUNET_GC_set_configuration_value_string (cfg, ectx, "NETWORK", "HOST",
                                            buf);
  CHECK (GNUNET_OK == searchFile (&uri));
  printf ("Search successful!\n");
  start = GNUNET_get_time ();
  printf ("Downloading...\n");
  CHECK (GNUNET_OK == downloadFile (SIZE, uri));
  printf ("Download successful at %llu kbps!\n",
          (SIZE * GNUNET_CRON_SECONDS / 1024) /
          ((1 + GNUNET_get_time () - start)));
  GNUNET_ECRS_uri_destroy (uri);
  GNUNET_GC_set_configuration_value_string (cfg,
                                            ectx,
                                            "NETWORK", "HOST",
                                            "localhost:2087");
  CHECK (GNUNET_OK == unindexFile (SIZE));

FAILURE:
#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif

  GNUNET_GC_free (cfg);
  return ret;
}

/* end of test_linear_topology.c */
