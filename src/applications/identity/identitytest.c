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
#include "core.h"

#define ASSERT(cond) do { \
  if (!cond) { \
   printf("Assertion failed at %s:%d\n", \
          __FILE__, __LINE__); \
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
  helo = transport->createhello(ANY_PROTOCOL_NUMBER);
  if (NULL == helo) {
    printf("Cannot run test, failed to create any hello.\n");
    releaseService(identity);
    releaseService(transport);
    return OK;
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
  releaseService(identity);
  releaseService(transport);
  return OK;
}

/**
 * Perform option parsing from the command line.
 */
static int parser(int argc,
		  char * argv[]) {
  FREENONNULL(setConfigurationString("FILES",
				     "gnunet.conf",
				     "check.conf"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  return OK;
}

int main(int argc, char *argv[]) {
  int err;

  if (OK != initUtil(argc, argv, &parser))
    return SYSERR;
  initCore();
  err = 0;
  if (OK != runTest())
    err = 1;

  doneCore();
  doneUtil();
  return err;
}

/* end of identitytest.c */
