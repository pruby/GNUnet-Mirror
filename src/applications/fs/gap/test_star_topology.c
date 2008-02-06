/*
     This file is part of GNUnet.
     (C) 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/gap/gaptest3.c
 * @brief GAP economy testcase, download from star topology
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_identity_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util.h"
#include "gnunet_stats_lib.h"

#define PEER_COUNT 10

#define START_PEERS 1

#define SIZE 1024*1024*2

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
  buf = GNUNET_malloc_large (size);
  memset (buf, size + size / 253, size);
  for (i = 0; i < (int) (size - 42 - sizeof (GNUNET_HashCode));
       i += sizeof (GNUNET_HashCode))
    GNUNET_hash (&buf[i + sizeof (GNUNET_HashCode)], 42,
                 (GNUNET_HashCode *) & buf[i]);
  WRITE (fd, buf, size);
  GNUNET_free (buf);
  GNUNET_disk_file_close (ectx, name, fd);
  ret = GNUNET_ECRS_file_upload (ectx, cfg, name, GNUNET_YES,   /* index */
                                 1,     /* anon */
                                 0,     /* prio */
                                 GNUNET_get_time () + 100 * GNUNET_CRON_MINUTES,        /* expire */
                                 &uprogress, NULL, &testTerminate, NULL,
                                 &uri);
  GNUNET_free (name);
  if (ret != GNUNET_SYSERR)
    return uri;
  return NULL;
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
      memset (buf, size + size / 253, size);
      for (i = 0; i < (int) (size - 42 - sizeof (GNUNET_HashCode));
           i += sizeof (GNUNET_HashCode))
        GNUNET_hash (&buf[i + sizeof (GNUNET_HashCode)], 42,
                     (GNUNET_HashCode *) & buf[i]);
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

#define CHECK(a) if (!(a)) { ret = 1; GNUNET_GE_BREAK(ectx, 0); goto FAILURE; }

static GNUNET_PeerIdentity goodPeers[PEER_COUNT];
static unsigned int goodPeerPos;

static int
infoCallback (void *data,
              const GNUNET_PeerIdentity * identity,
              const void *address,
              unsigned int addr_len,
              GNUNET_CronTime last_seen, unsigned int trust,
              unsigned int bpmFromPeer)
{
  int i;
  int good;
  GNUNET_EncName enc;

  good = 0;
  for (i = 0; i < goodPeerPos; i++)
    if (0 == memcmp (&goodPeers[i], identity, sizeof (GNUNET_PeerIdentity)))
      good = 1;
  GNUNET_hash_to_enc (&identity->hashPubKey, &enc);
  if (good)
    printf ("Good peer `%8s' has trust %u and bandwidth %u\n",
            (const char *) &enc, trust, bpmFromPeer);
  else
    printf ("Poor peer `%8s' has trust %u and bandwidth %u\n",
            (const char *) &enc, trust, bpmFromPeer);
  return GNUNET_OK;
}

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
  GNUNET_MessageHello *hello;
  struct GNUNET_ClientServerConnection *sock;
  GNUNET_CronTime start;
  GNUNET_EncName enc;

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
                                        "/tmp/gnunet-gap-test3",
                                        2087, 10, PEER_COUNT);
  if (peers == NULL)
    {
      fprintf (stderr, "Failed to start the gnunetd daemons!\n");
      GNUNET_GC_free (cfg);
      return -1;
    }
#endif
  /* connect as star-topology */
  for (i = 1; i < PEER_COUNT; i++)
    {
      if (GNUNET_OK != GNUNET_TESTING_connect_daemons (2087, 2087 + 10 * i))
        {
          GNUNET_TESTING_stop_daemons (peers);
          fprintf (stderr, "Failed to connect the peers!\n");
          GNUNET_GC_free (cfg);
          return -1;
        }
    }

  uri = NULL;
  goodPeerPos = 0;
  for (i = 1; i < PEER_COUNT; i += 2)
    {
      GNUNET_snprintf (buf, 128, "localhost:%u", 2087 + i * 10);
      GNUNET_GC_set_configuration_value_string (cfg, ectx, "NETWORK", "HOST",
                                                buf);
      sock = GNUNET_client_connection_create (NULL, cfg);
      if (GNUNET_OK != GNUNET_IDENTITY_get_self (sock, &hello))
        {
          GNUNET_client_connection_destroy (sock);
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      GNUNET_client_connection_destroy (sock);
      if (uri != NULL)
        GNUNET_ECRS_uri_destroy (uri);
      GNUNET_hash_to_enc (&hello->senderIdentity.hashPubKey, &enc);
      printf ("Uploading to peer `%8s'\n", (const char *) &enc);
      uri = uploadFile (SIZE);
      CHECK (NULL != uri);

      goodPeers[goodPeerPos++] = hello->senderIdentity;
      GNUNET_free (hello);

    }
  GNUNET_GC_set_configuration_value_string (cfg,
                                            ectx,
                                            "NETWORK", "HOST",
                                            "localhost:2087");
  printf ("Downloading...\n");
  start = GNUNET_get_time ();
  CHECK (GNUNET_OK == downloadFile (SIZE, uri));
  printf ("Download complete - %f kbps.\n",
          SIZE / 1024 * 1.0 * GNUNET_CRON_SECONDS / (1 + GNUNET_get_time () -
                                                     start));
  /* verify trust values have developed as expected */

  sock = GNUNET_client_connection_create (NULL, cfg);
  GNUNET_IDENTITY_request_peer_infos (sock, &infoCallback, NULL);
  GNUNET_client_connection_destroy (sock);

FAILURE:
#if START_PEERS
  GNUNET_TESTING_stop_daemons (peers);
#endif
  GNUNET_GC_free (cfg);
  return ret;
}

/* end of gaptest3.c */
