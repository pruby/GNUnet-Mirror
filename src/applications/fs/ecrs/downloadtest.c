/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/downloadtest.c
 * @brief testcase for download (partial, in particular)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "tree.h"

#define START_DAEMONS 1

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(NULL, 0); goto FAILURE; }

/**
 * Must be a multiple of 16k.
 */
#define SIZE (1024 * 1024 * 2)

static int
testTerminate (void *unused)
{
  return GNUNET_OK;
}

static void progress_check
  (unsigned long long totalBytes,
   unsigned long long completedBytes,
   GNUNET_CronTime eta,
   unsigned long long lastBlockOffset,
   const char *lastBlock, unsigned int lastBlockSize, void *closure)
{
#if 0
  printf ("Completed: %llu - Now: at %llu got %u bytes\n",
          completedBytes, lastBlockOffset, lastBlockSize);
#endif
}


static struct GNUNET_GC_Configuration *cfg;

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = GNUNET_malloc (strlen ("/tmp/gnunet-ecrstest/ECRSTEST") + 14);
  GNUNET_snprintf (fn,
                   strlen ("/tmp/gnunet-ecrstest/ECRSTEST") + 14,
                   "/tmp/gnunet-ecrstest/ECRSTEST%u", i);
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
    GNUNET_disk_file_open (NULL, name, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
  if (fd == -1)
    {
      GNUNET_free (name);
      return NULL;
    }
  buf = GNUNET_malloc (size);
  memset (buf, size + size / 253, size);
  for (i = 0; i < (int) (size - 42 - 2 * sizeof (GNUNET_HashCode));
       i += sizeof (GNUNET_HashCode))
    GNUNET_hash (&buf[i], 42,
                 (GNUNET_HashCode *) & buf[i + sizeof (GNUNET_HashCode)]);
  WRITE (fd, buf, size);
  GNUNET_free (buf);
  CLOSE (fd);
  ret = GNUNET_ECRS_file_upload (NULL, cfg, name, GNUNET_YES,   /* index */
                                 0,     /* anon */
                                 0,     /* priority */
                                 GNUNET_get_time () + 10 * GNUNET_CRON_MINUTES, /* expire */
                                 NULL,  /* progress */
                                 NULL, &testTerminate, NULL, &uri);
  GNUNET_free (name);
  return uri;
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
  int j;
  char *tmp;

  tmp = GNUNET_ECRS_uri_to_string (uri);
  GNUNET_GE_LOG (NULL,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Starting download of `%s'\n", tmp);
  GNUNET_free (tmp);
  tmpName = makeName (0);
  ret = GNUNET_OK;
  buf = GNUNET_malloc (size);
  in = GNUNET_malloc (size);
  memset (buf, size + size / 253, size);
  for (i = 0; i < (int) (size - 42 - 2 * sizeof (GNUNET_HashCode));
       i += sizeof (GNUNET_HashCode))
    GNUNET_hash (&buf[i], 42,
                 (GNUNET_HashCode *) & buf[i + sizeof (GNUNET_HashCode)]);
  for (j = SIZE - 16 * 1024; j >= 0; j -= 16 * 1024)
    {
      fprintf (stderr, ".");
      if (GNUNET_OK == GNUNET_ECRS_file_download_partial (NULL,
                                                          cfg,
                                                          uri,
                                                          tmpName,
                                                          j,
                                                          16 * 1024,
                                                          0,
                                                          GNUNET_NO,
                                                          &progress_check,
                                                          NULL,
                                                          &testTerminate,
                                                          NULL))
        {
          fd = GNUNET_disk_file_open (NULL, tmpName, O_RDONLY);
          if ((size != READ (fd, in, size)) ||
              (0 != memcmp (&buf[j], &in[j], 16 * 1024)))
            {
              ret = GNUNET_SYSERR;
              CLOSE (fd);
              break;
            }
          CLOSE (fd);
        }
    }
  GNUNET_free (buf);
  GNUNET_free (in);
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
    GNUNET_ECRS_file_unindex (NULL, cfg, name, NULL, NULL, &testTerminate,
                              NULL);
  if (0 != UNLINK (name))
    ret = GNUNET_SYSERR;
  GNUNET_free (name);
  return ret;
}

int
main (int argc, char *argv[])
{
#if START_DAEMONS
  pid_t daemon;
#endif
  int ok;
  struct GNUNET_ClientServerConnection *sock = NULL;
  struct GNUNET_ECRS_URI *uri;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_DAEMONS
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg,
                                         30 * GNUNET_CRON_SECONDS));
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */
#endif
  ok = GNUNET_YES;
  sock = GNUNET_client_connection_create (NULL, cfg);
  CHECK (sock != NULL);

  /* ACTUAL TEST CODE */
  fprintf (stderr, "Uploading...\n");
  uri = uploadFile (SIZE);
  CHECK (NULL != uri);
  fprintf (stderr, "Downloading...");
  CHECK (GNUNET_OK == downloadFile (SIZE, uri));
  GNUNET_ECRS_uri_destroy (uri);
  fprintf (stderr, "\nUnindexing...\n");
  CHECK (GNUNET_OK == unindexFile (SIZE));
  fprintf (stderr, "Ok.\n");


  /* END OF TEST CODE */
FAILURE:
  if (sock != NULL)
    GNUNET_client_connection_destroy (sock);
#if START_DAEMONS
  GNUNET_GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
#endif
  GNUNET_GC_free (cfg);
  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of ecrstest.c */
