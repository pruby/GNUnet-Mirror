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
#include <sys/wait.h>

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
  CHECK(OK ==
	ECRS_createNamespace(CHECKNAME,
			     meta,
			     0,
			     0,
			     cronTime(NULL) + 5 * cronMINUTES,
			     adv,
			     &root,
			     &rootURI));
  hash("this", 4, &thisId);
  hash("next", 4, &nextId);
  uri = rootURI; /* just for fun: NS::this advertises NS::root */  
  CHECK(OK == ECRS_addToNamespace(CHECKNAME,
				  0,
				  0,
				  cronTime(NULL) + 5 * cronMINUTES,
				  cronTime(NULL),
				  1 * cronMINUTES,
				  &thisId,
				  &nextId,
				  uri,
				  meta,
				  &advURI));
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
				     "DEBUG"));
  return OK;
}

int main(int argc, char * argv[]) {
  pid_t daemon;
  int status;
  int failureCount = 0; 

  daemon = fork();
  if (daemon == 0) {
    if (0 != execlp("gnunetd", /* what binary to execute, must be in $PATH! */
		    "gnunetd", /* arg0, path to gnunet binary */
		    "-d",  /* do not daemonize so we can easily kill you */
		    /* "-L", "NOTHING", */
		    "-c",
		    "check.conf", /* configuration file */
		    NULL)) {
      fprintf(stderr,
	      _("'%s' failed: %s\n"),
	      "execlp",
	      STRERROR(errno));
      return -1;
    }
  }
  initUtil(argc, argv, &parseCommandLine);

  
  failureCount += testNamespace();


  doneUtil();
  if (daemon != -1) {
    if (0 != kill(daemon, SIGTERM))
      DIE_STRERROR("kill");
    if (daemon != waitpid(daemon, &status, 0))
      DIE_STRERROR("waitpid");

    if (WEXITSTATUS(status) != 0)
      failureCount++;
  }
  if (failureCount == 0)
    return 0;
  else
    return 1;
}

/* end of namespacetest.c */
