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
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "tree.h"

#define CHECK(a) if (!(a)) { ok = NO; GE_BREAK(NULL, 0); goto FAILURE; }

/**
 * Must be a multiple of 16k.
 */
#define SIZE (1024 * 1024 * 2)

static int
testTerminate (void *unused)
{
  return OK;
}

static void progress_check
  (unsigned long long totalBytes,
   unsigned long long completedBytes,
   cron_t eta,
   unsigned long long lastBlockOffset,
   const char *lastBlock, unsigned int lastBlockSize, void *closure)
{
#if 0
  printf ("Completed: %llu - Now: at %llu got %u bytes\n",
          completedBytes, lastBlockOffset, lastBlockSize);
#endif
}


static struct GC_Configuration *cfg;

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = MALLOC (strlen ("/tmp/gnunet-ecrstest/ECRSTEST") + 14);
  SNPRINTF (fn,
            strlen ("/tmp/gnunet-ecrstest/ECRSTEST") + 14,
            "/tmp/gnunet-ecrstest/ECRSTEST%u", i);
  disk_directory_create_for_file (NULL, fn);
  return fn;
}

static struct ECRS_URI *
uploadFile (unsigned int size)
{
  int ret;
  char *name;
  int fd;
  char *buf;
  struct ECRS_URI *uri;
  int i;

  name = makeName (size);
  fd = disk_file_open (NULL, name, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
  buf = MALLOC (size);
  memset (buf, size + size / 253, size);
  for (i = 0; i < (int) (size - 42 - sizeof (HashCode512));
       i += sizeof (HashCode512))
    hash (&buf[i], 42, (HashCode512 *) & buf[i + sizeof (HashCode512)]);
  WRITE (fd, buf, size);
  FREE (buf);
  CLOSE (fd);
  ret = ECRS_uploadFile (NULL, cfg, name, YES,  /* index */
                         0,     /* anon */
                         0,     /* prio */
                         get_time () + 10 * cronMINUTES,        /* expire */
                         NULL,  /* progress */
                         NULL, &testTerminate, NULL, &uri);
  FREE (name);
  return uri;
}

static int
downloadFile (unsigned int size, const struct ECRS_URI *uri)
{
  int ret;
  char *tmpName;
  int fd;
  char *buf;
  char *in;
  int i;
  int j;
  char *tmp;

  tmp = ECRS_uriToString (uri);
  GE_LOG (NULL,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Starting download of `%s'\n", tmp);
  FREE (tmp);
  tmpName = makeName (0);
  ret = SYSERR;
  for (j = SIZE - 16 * 1024; j >= 0; j -= 16 * 1024)
    {
      if (OK == ECRS_downloadPartialFile (NULL,
                                          cfg,
                                          uri,
                                          tmpName,
                                          j,
                                          16 * 1024,
                                          0,
                                          NO,
                                          &progress_check,
                                          NULL, &testTerminate, NULL))
        {
          fd = disk_file_open (NULL, tmpName, O_RDONLY);
          buf = MALLOC (size);
          in = MALLOC (size);
          memset (buf, size + size / 253, size);
          for (i = 0; i < (int) (size - 42 - sizeof (HashCode512));
               i += sizeof (HashCode512))
            hash (&buf[i], 42,
                  (HashCode512 *) & buf[i + sizeof (HashCode512)]);
          if (size != READ (fd, in, size))
            ret = SYSERR;
          else if (0 == memcmp (&buf[j], &in[j], 16 * 1024))
            ret = OK;
          FREE (buf);
          FREE (in);
          CLOSE (fd);
        }
    }
  UNLINK (tmpName);
  FREE (tmpName);
  return ret;
}


static int
unindexFile (unsigned int size)
{
  int ret;
  char *name;

  name = makeName (size);
  ret = ECRS_unindexFile (NULL, cfg, name, NULL, NULL, &testTerminate, NULL);
  if (0 != UNLINK (name))
    ret = SYSERR;
  FREE (name);
  return ret;
}

int
main (int argc, char *argv[])
{
  pid_t daemon;
  int ok;
  struct ClientServerConnection *sock;
  struct ECRS_URI *uri;

  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
  daemon = os_daemon_start (NULL, cfg, "peer.conf", NO);
  GE_ASSERT (NULL, daemon > 0);
  sock = NULL;
  CHECK (OK == connection_wait_for_running (NULL, cfg, 30 * cronSECONDS));
  ok = YES;
  PTHREAD_SLEEP (5 * cronSECONDS);      /* give apps time to start */
  sock = client_connection_create (NULL, cfg);
  CHECK (sock != NULL);

  /* ACTUAL TEST CODE */
  uri = uploadFile (SIZE);
  CHECK (NULL != uri);
  CHECK (OK == downloadFile (SIZE, uri));
  ECRS_freeUri (uri);
  CHECK (OK == unindexFile (SIZE));
  fprintf (stderr, " Ok.\n");


  /* END OF TEST CODE */
FAILURE:
  if (sock != NULL)
    connection_destroy (sock);
  GE_ASSERT (NULL, OK == os_daemon_stop (NULL, daemon));
  GC_free (cfg);
  return (ok == YES) ? 0 : 1;
}

/* end of ecrstest.c */
