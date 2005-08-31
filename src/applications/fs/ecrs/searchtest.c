/*
     This file is part of GNUnet.
     (C) 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/searchtest.c
 * @brief testcase for search
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "tree.h"

#define CHECK(a) if (!(a)) { ok = NO; BREAK(); goto FAILURE; }

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
				     "NOTHING"));
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "check.conf"));
  return OK;
}

static int testTerminate(void * unused) {
  return OK;
}

static int searchCB(const ECRS_FileInfo * fi,
		    const HashCode512 * key,
		    int isRoot,
		    void * closure) {
  int * cnt = closure;
#if 0
  char * st;

  st = ECRS_uriToString(fi->uri);
  printf("Got result `%s'\n",
	 st);
  FREE(st);
#endif
  (*cnt)--;
  if (0 == *cnt)
    return SYSERR; /* abort search */
  else
    return OK;
}

/**
 * @param *uri In: keyword URI
 * @return OK on success, SYSERR on error
 */
static int searchFile(const struct ECRS_URI * uri,
		      int resultCount) {
  ECRS_search(uri,
	      0,
	      60 * 15 * cronSECONDS,
	      &searchCB,
	      &resultCount,
	      &testTerminate,
	      NULL);
  if (resultCount <= 0)
    return OK;
  else
    return SYSERR;
}

int main(int argc, char * argv[]){
  pid_t daemon;
  int ok;
  GNUNET_TCP_SOCKET * sock;
  struct ECRS_URI * uri;
  struct ECRS_MetaData * meta;
  struct ECRS_URI * key;
  const char * keywords[6];

  if (OK != initUtil(argc,
		     argv,
		     &parseCommandLine))
    return -1;
  daemon = startGNUnetDaemon(NO);
  GNUNET_ASSERT(daemon > 0);
  ok = YES;
  startCron();
  GNUNET_ASSERT(OK == waitForGNUnetDaemonRunning(30 * cronSECONDS));
  gnunet_util_sleep(5 * cronSECONDS); /* give apps time to start */
  sock = getClientSocket();
  CHECK(sock != NULL);

  /* ACTUAL TEST CODE */
  /* first, simple insertion => one result */
#if 0
  printf("Testing search for 'XXtest' with one result.\n");
#endif
  uri = ECRS_stringToUri("gnunet://ecrs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test");
  meta = ECRS_createMetaData();
  keywords[0] = "XXtest";
  keywords[1] = NULL;

  key = ECRS_keywordsToUri(keywords);
  CHECK(OK == ECRS_addToKeyspace(key,
				 0,
				 0,
				 cronTime(NULL) + 10 * cronMINUTES, /* expire */
				 uri,
				 meta));
  CHECK(OK == searchFile(key,
			 1));
  ECRS_freeUri(key);
  ECRS_freeUri(uri);

  /* inserting another URI under the 'XXtest' keyword and under 'binary'
     should give both URIs since ECRS knows nothing about 'AND'ing: */
#if 0
  printf("Testing search for 'XXtest AND binary' with two results.\n");
#endif
  uri = ECRS_stringToUri("gnunet://ecrs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test-different");
  keywords[1] = "binary";
  keywords[2] = NULL;
  key = ECRS_keywordsToUri(keywords);
  CHECK(OK == ECRS_addToKeyspace(key,
				 0,
				 0,
				 cronTime(NULL) + 10 * cronMINUTES, /* expire */
				 uri,
				 meta));
  CHECK(OK == searchFile(key,
			 2));
  ECRS_freeUri(key);
  ECRS_freeUri(uri);
  ECRS_freeMetaData(meta);

  /* now searching just for 'XXtest' should again give 2 results! */
#if 0
  printf("Testing search for 'XXtest' with two results.\n");
#endif
  keywords[1] = NULL;
  key = ECRS_keywordsToUri(keywords);
  CHECK(OK == searchFile(key,
			 2));
  ECRS_freeUri(key);

  /* END OF TEST CODE */
 FAILURE:
  if (sock != NULL)
    releaseClientSocket(sock);
  stopCron();
  GNUNET_ASSERT(OK == stopGNUnetDaemon());
  GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon));
  doneUtil();
  return (ok == YES) ? 0 : 1;
}

/* end of searchtest.c */
