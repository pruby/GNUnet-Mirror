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
#include "gnunet_util_crypto.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_stats_lib.h"

#define PEER_COUNT 10

#define START_PEERS 1

#define SIZE 1024*1024*2

static struct GE_Context *ectx;

static struct GC_Configuration *cfg;

static int
testTerminate (void *unused)
{
  return OK;
}

static void
uprogress (unsigned long long totalBytes,
           unsigned long long completedBytes, cron_t eta, void *closure)
{
  fprintf (stderr, totalBytes == completedBytes ? "\n" : ".");
}

static void
dprogress (unsigned long long totalBytes,
           unsigned long long completedBytes,
           cron_t eta,
           unsigned long long lastBlockOffset,
           const char *lastBlock, unsigned int lastBlockSize, void *closure)
{
  fprintf (stderr, totalBytes == completedBytes ? "\n" : ".");
}

static char *
makeName (unsigned int i)
{
  char *fn;

  fn = MALLOC (strlen ("/tmp/gnunet-gaptest/GAPTEST") + 14);
  SNPRINTF (fn,
            strlen ("/tmp/gnunet-gaptest/GAPTEST") + 14,
            "/tmp/gnunet-gaptest/GAPTEST%u", i);
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
  fd = disk_file_open (ectx, name, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
  buf = MALLOC_LARGE (size);
  memset (buf, size + size / 253, size);
  for (i = 0; i < (int) (size - 42 - sizeof (HashCode512));
       i += sizeof (HashCode512))
    hash (&buf[i + sizeof (HashCode512)], 42, (HashCode512 *) & buf[i]);
  WRITE (fd, buf, size);
  FREE (buf);
  disk_file_close (ectx, name, fd);
  ret = ECRS_uploadFile (ectx, cfg, name, YES,  /* index */
                         1,     /* anon */
                         0,     /* prio */
                         get_time () + 100 * cronMINUTES,       /* expire */
                         &uprogress, NULL, &testTerminate, NULL, &uri);
  FREE (name);
  if (ret != SYSERR)
    return uri;
  return NULL;
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
  char *tmp;

  tmp = ECRS_uriToString (uri);
  GE_LOG (ectx,
          GE_DEBUG | GE_REQUEST | GE_USER,
          "Starting download of `%s'\n", tmp);
  FREE (tmp);
  tmpName = makeName (0);
  ret = SYSERR;
  if (OK == ECRS_downloadFile (ectx,
                               cfg,
                               uri,
                               tmpName,
                               1, &dprogress, NULL, &testTerminate, NULL))
    {

      fd = disk_file_open (ectx, tmpName, O_RDONLY);
      buf = MALLOC (size);
      in = MALLOC (size);
      memset (buf, size + size / 253, size);
      for (i = 0; i < (int) (size - 42 - sizeof (HashCode512));
           i += sizeof (HashCode512))
        hash (&buf[i + sizeof (HashCode512)], 42, (HashCode512 *) & buf[i]);
      if (size != READ (fd, in, size))
        ret = SYSERR;
      else if (0 == memcmp (buf, in, size))
        ret = OK;
      FREE (buf);
      FREE (in);
      disk_file_close (ectx, tmpName, fd);
    }
  UNLINK (tmpName);
  FREE (tmpName);
  return ret;
}

#define CHECK(a) if (!(a)) { ret = 1; GE_BREAK(ectx, 0); goto FAILURE; }

static PeerIdentity goodPeers[PEER_COUNT];
static unsigned int goodPeerPos;

static int
infoCallback (void *data,
              const PeerIdentity * identity,
              const void *address,
              unsigned int addr_len,
              cron_t last_seen, unsigned int trust, unsigned int bpmFromPeer)
{
  int i;
  int good;
  EncName enc;

  good = 0;
  for (i = 0; i < goodPeerPos; i++)
    if (0 == memcmp (&goodPeers[i], identity, sizeof (PeerIdentity)))
      good = 1;
  hash2enc (&identity->hashPubKey, &enc);
  if (good)
    printf ("Good peer `%8s' has trust %u and bandwidth %u\n",
            (const char *) &enc, trust, bpmFromPeer);
  else
    printf ("Poor peer `%8s' has trust %u and bandwidth %u\n",
            (const char *) &enc, trust, bpmFromPeer);
  return OK;
}

/**
 * Testcase to test gap routing (2 peers only).
 * @return 0: ok, -1: error
 */
int
main (int argc, char **argv)
{
  struct DaemonContext *peers;
  int ret;
  struct ECRS_URI *uri;
  int i;
  char buf[128];
  P2P_hello_MESSAGE *hello;
  struct ClientServerConnection *sock;
  cron_t start;
  EncName enc;

  ret = 0;
  cfg = GC_create_C_impl ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
#if START_PEERS
  peers = gnunet_testing_start_daemons ("tcp",
                                        "advertising topology fs stats",
                                        "/tmp/gnunet-gap-test3",
                                        2087, 10, PEER_COUNT);
  if (peers == NULL)
    {
      fprintf (stderr, "Failed to start the gnunetd daemons!\n");
      GC_free (cfg);
      return -1;
    }
#endif
  /* connect as star-topology */
  for (i = 1; i < PEER_COUNT; i++)
    {
      if (OK != gnunet_testing_connect_daemons (2087, 2087 + 10 * i))
        {
          gnunet_testing_stop_daemons (peers);
          fprintf (stderr, "Failed to connect the peers!\n");
          GC_free (cfg);
          return -1;
        }
    }

  uri = NULL;
  goodPeerPos = 0;
  for (i = 1; i < PEER_COUNT; i += 2)
    {
      SNPRINTF (buf, 128, "localhost:%u", 2087 + i * 10);
      GC_set_configuration_value_string (cfg, ectx, "NETWORK", "HOST", buf);
      sock = client_connection_create (NULL, cfg);
      if (OK != gnunet_identity_get_self (sock, &hello))
        {
          connection_destroy (sock);
          GE_BREAK (NULL, 0);
          break;
        }
      connection_destroy (sock);
      if (uri != NULL)
        ECRS_freeUri (uri);
      hash2enc (&hello->senderIdentity.hashPubKey, &enc);
      printf ("Uploading to peer `%8s'\n", (const char *) &enc);
      uri = uploadFile (SIZE);
      CHECK (NULL != uri);

      goodPeers[goodPeerPos++] = hello->senderIdentity;
      FREE (hello);

    }
  GC_set_configuration_value_string (cfg,
                                     ectx,
                                     "NETWORK", "HOST", "localhost:2087");
  printf ("Downloading...\n");
  start = get_time ();
  CHECK (OK == downloadFile (SIZE, uri));
  printf ("Download complete - %f kbps.\n",
          SIZE / 1024 * 1.0 * cronSECONDS / (1 + get_time () - start));
  /* verify trust values have developed as expected */

  sock = client_connection_create (NULL, cfg);
  gnunet_identity_request_peer_infos (sock, &infoCallback, NULL);
  connection_destroy (sock);

FAILURE:
#if START_PEERS
  gnunet_testing_stop_daemons (peers);
#endif
  GC_free (cfg);
  return ret;
}

/* end of gaptest3.c */
