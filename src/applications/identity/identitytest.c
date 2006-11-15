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
#include "gnunet_transport_service.h"
#include "gnunet_core.h"
#include "gnunet_util_config_impl.h"
#include "core.h"

static struct CronManager * cron;

#define ASSERT(cond) do { \
  if (!cond) { \
   printf("Assertion failed at %s:%d\n", \
          __FILE__, __LINE__); \
   cron_stop(cron); \
   releaseService(identity); \
   releaseService(transport); \
   return SYSERR; \
  } \
} while (0)

static int runTest() {
  Identity_ServiceAPI * identity;
  Transport_ServiceAPI * transport;
  PeerIdentity pid;
  const PublicKey * pkey;
  Signature sig;
  P2P_hello_MESSAGE * helo;

  transport = requestService("transport");
  identity = requestService("identity");
  cron_start(cron);
  /* give cron job chance to run */
  PTHREAD_SLEEP(5 * cronSECONDS);
  helo = transport->createhello(ANY_PROTOCOL_NUMBER);
  if (NULL == helo) {
    printf("Cannot run test, failed to create any hello.\n");
    cron_stop(cron);
    releaseService(identity);
    releaseService(transport);
    return SYSERR;
  }
  identity->addHost(helo);
  pid = helo->senderIdentity;
  FREE(helo);

  identity->changeHostTrust
    (&pid,
     -identity->getHostTrust(&pid));
  ASSERT(4 == identity->changeHostTrust
	 (&pid, 4));
  releaseService(identity);

  identity = requestService("identity");
  ASSERT(4 == identity->getHostTrust(&pid));
  ASSERT(5 == identity->changeHostTrust
	 (&pid, 5));
  ASSERT(-2 == identity->changeHostTrust
	 (&pid, -2));
  ASSERT(7 == identity->getHostTrust(&pid));
  ASSERT(-7 == identity->changeHostTrust
	 (&pid, -40));
  pkey = identity->getPublicPrivateKey();
  identity->getPeerIdentity(pkey,
			    &pid);
  ASSERT(0 == identity->getHostTrust(&pid));

  pkey = identity->getPublicPrivateKey();
  ASSERT(OK == identity->signData("TestData",
				  8,
				  &sig));
  ASSERT(OK == verifySig("TestData",
			 8,
			 &sig,
			 pkey));

  /* to test:
     hello verification, temporary storage,
     permanent storage, blacklisting, etc. */
  cron_stop(cron);
  releaseService(identity);
  releaseService(transport);
  return OK;
}

int main(int argc, char *argv[]) {
  int err;
  struct GC_Configuration * cfg;

  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;
  }
  cron = cron_create(NULL);
  initCore(NULL,
	   cfg,
	   cron,
	   NULL);
  err = 0;
  if (OK != runTest())
    err = 1;
  doneCore();
  cron_destroy(cron);
  GC_free(cfg);
  return err;
}

/* end of identitytest.c */
