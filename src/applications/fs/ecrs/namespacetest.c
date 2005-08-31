/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/namespacetest.c
 * @brief Test for namespace.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }
#define CHECK(c) { do { if (!(c)) ABORT(); } while(0); }

#define CHECKNAME "gnunet-namespace-test"

static int testNamespace() {
  HashCode512 root;
  HashCode512 thisId;
  HashCode512 nextId;
  struct ECRS_URI * adv;
  struct ECRS_URI * uri;
  struct ECRS_URI * advURI;
  struct ECRS_URI * rootURI;
  struct ECRS_MetaData * meta;
  const char * keys[] = {
    "testNamespace",
    NULL,
  };


  ECRS_deleteNamespace(CHECKNAME); /* make sure old one is deleted */
  meta = ECRS_createMetaData();
  adv = ECRS_keywordsToUri(keys);
  hash("root", 4, &root);
  rootURI =
    ECRS_createNamespace(CHECKNAME,
			 meta,
			 0,
			 0,
			 cronTime(NULL) + 5 * cronMINUTES,
			 adv,
			 &root);
  CHECK(NULL != rootURI);
  hash("this", 4, &thisId);
  hash("next", 4, &nextId);
  uri = rootURI; /* just for fun: NS::this advertises NS::root */
  advURI = ECRS_addToNamespace(CHECKNAME,
			       0,
			       0,
			       TIME(NULL) + 300,
			       TIME(NULL),
			       1 * cronMINUTES,
			       &thisId,
			       &nextId,
			       uri,
			       meta);
  CHECK(NULL != advURI);
  CHECK(OK == ECRS_deleteNamespace(CHECKNAME));
  CHECK(SYSERR == ECRS_deleteNamespace(CHECKNAME));
  ECRS_freeMetaData(meta);
  ECRS_freeUri(rootURI);
  ECRS_freeUri(advURI);
  return 0;
}

static int parseCommandLine(int argc,
			    char * argv[]) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "NO"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNET",
				     "LOGLEVEL",
				     "ERROR"));
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "check.conf"));
  return OK;
}

int main(int argc, char * argv[]) {
  pid_t daemon;
  int failureCount = 0;

  if (OK != initUtil(argc,
		     argv,
		     &parseCommandLine))
    return -1;
  daemon = startGNUnetDaemon(NO);
  GNUNET_ASSERT(daemon > 0);
  GNUNET_ASSERT(OK == waitForGNUnetDaemonRunning(30 * cronSECONDS));
  gnunet_util_sleep(30 * cronSECONDS);

  failureCount += testNamespace();

  GNUNET_ASSERT(OK == stopGNUnetDaemon());
  GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon));
  doneUtil();
  return (failureCount == 0) ? 0 : 1;
}

/* end of namespacetest.c */
