/*
     This file is part of GNUnet.
     (C) 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/identity/identitytest.c
 * @brief testcase for identity.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_identity_service.h"
#include "gnunet_identity_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_core.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "core.h"

static struct GNUNET_CronManager *cron;

static struct GC_Configuration *cfg;


#define ASSERT(cond) do { \
  if (!cond) { \
   printf("Assertion failed at %s:%d\n", \
          __FILE__, __LINE__); \
   GNUNET_cron_stop(cron); \
   releaseService(identity); \
   releaseService(transport); \
   return GNUNET_SYSERR; \
  } \
} while (0)

static int
runTest ()
{
  Identity_ServiceAPI *identity;
  Transport_ServiceAPI *transport;
  GNUNET_PeerIdentity pid;
  const GNUNET_RSA_PublicKey *pkey;
  GNUNET_RSA_Signature sig;
  GNUNET_MessageHello *hello;

  transport = requestService ("transport");
  identity = requestService ("identity");
  GNUNET_cron_start (cron);
  /* give cron job chance to run */
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);
  hello = transport->createhello (ANY_PROTOCOL_NUMBER);
  if (NULL == hello)
    {
      printf ("Cannot run test, failed to create any hello.\n");
      GNUNET_cron_stop (cron);
      releaseService (identity);
      releaseService (transport);
      return GNUNET_SYSERR;
    }
  identity->addHost (hello);
  pid = hello->senderIdentity;
  GNUNET_free (hello);

  identity->changeHostTrust (&pid, -identity->getHostTrust (&pid));
  ASSERT (4 == identity->changeHostTrust (&pid, 4));
  releaseService (identity);

  identity = requestService ("identity");
  ASSERT (4 == identity->getHostTrust (&pid));
  ASSERT (5 == identity->changeHostTrust (&pid, 5));
  ASSERT (-2 == identity->changeHostTrust (&pid, -2));
  ASSERT (7 == identity->getHostTrust (&pid));
  ASSERT (-7 == identity->changeHostTrust (&pid, -40));
  pkey = identity->getPublicPrivateKey ();
  identity->getPeerIdentity (pkey, &pid);
  ASSERT (0 == identity->getHostTrust (&pid));

  pkey = identity->getPublicPrivateKey ();
  ASSERT (GNUNET_OK == identity->signData ("TestData", 8, &sig));
  ASSERT (GNUNET_OK == GNUNET_RSA_verify ("TestData", 8, &sig, pkey));

  /* to test:
     hello verification, temporary storage,
     permanent storage, blacklisting, etc. */
  GNUNET_cron_stop (cron);
  releaseService (identity);
  releaseService (transport);
  return GNUNET_OK;
}

static int
hcb (void *data,
     const GNUNET_PeerIdentity * identity,
     const void *address,
     unsigned int addr_len,
     GNUNET_CronTime last_message, unsigned int trust,
     unsigned int bpmFromPeer)
{
  /* TODO: do something meaningful */
  return GNUNET_OK;
}

static int
runClientTest ()
{
  struct GNUNET_ClientServerConnection *sock;
  int ret;

  ret = GNUNET_OK;
  sock = GNUNET_client_connection_create (NULL, cfg);
  GNUNET_IDENTITY_request_peer_infos (sock, &hcb, &ret);
  GNUNET_client_connection_destroy (sock);
  return ret;
}

int
main (int argc, char *argv[])
{
  int err;

  cfg = GC_create ();
  if (-1 == GC_parse_configuration (cfg, "check.conf"))
    {
      GC_free (cfg);
      return -1;
    }
  cron = cron_create (NULL);
  initCore (NULL, cfg, cron, NULL);
  err = 0;
  if (GNUNET_OK != runTest ())
    err = 1;
  if (GNUNET_OK != runClientTest ())
    err = 1;
  doneCore ();
  GNUNET_cron_destroy (cron);
  GC_free (cfg);
  return err;
}

/* end of identitytest.c */
