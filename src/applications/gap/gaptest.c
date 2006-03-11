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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file applications/gap/gaptest.c
 * @brief GAP routing testcase
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_stats_lib.h"

static int parseOptions(int argc,
			char ** argv) {
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGLEVEL",
				     "DEBUG"));
  return OK;
}

/**
 * Identity of peer 2 (hardwired).
 */
static PeerIdentity peer2;

static int waitForConnect(const char * name,
			  unsigned long long value,
			  void * cls) {
  if ( (value > 0) &&
       (0 == strcmp(_("# of connected peers"),
		    name)) )
    return SYSERR;
  return OK;
}


static int testTerminate(void * unused) {
  return OK;
}

static char * makeName(unsigned int i) {
  char * name;
  char * fn;

  fn = STRDUP("/tmp/gnunet-ecrstest");
  name = expandFileName(fn);
  mkdirp(name);
  FREE(fn);
  fn = MALLOC(strlen(name) + 40);
  SNPRINTF(fn,
	   strlen(name) + 40,
	   "%s%sECRSTEST%u",
	   DIR_SEPARATOR_STR,
	   name,
	   i);
  FREE(name);
  return fn;
}

static struct ECRS_URI * uploadFile(unsigned int size) {
  int ret;
  char * name;
  int fd;
  char * buf;
  struct ECRS_URI * uri;
  int i;

  name = makeName(size);
  fd = fileopen(name, O_WRONLY|O_CREAT, S_IWUSR|S_IRUSR);
  buf = MALLOC(size);
  memset(buf, size + size / 253, size);
  for (i=0;i<(int) (size - 42 - sizeof(HashCode512));i+=sizeof(HashCode512))
    hash(&buf[i+sizeof(HashCode512)],
	 42,
	 (HashCode512*) &buf[i]);
  WRITE(fd, buf, size);
  FREE(buf);
  closefile(fd);
  ret = ECRS_uploadFile(name,
			YES, /* index */
			0, /* anon */
			0, /* prio */
			cronTime(NULL) + 10 * cronMINUTES, /* expire */
			NULL, /* progress */
			NULL,
			&testTerminate,
			NULL,
			&uri);
  if (ret != SYSERR) {
    struct ECRS_MetaData * meta;
    struct ECRS_URI * key;
    const char * keywords[2];

    keywords[0] = name;
    keywords[1] = NULL;

    meta = ECRS_createMetaData();
    key = ECRS_keywordsToUri(keywords);
    ret = ECRS_addToKeyspace(key,
			     0,
			     0,
			     cronTime(NULL) + 10 * cronMINUTES, /* expire */
			     uri,
			     meta);
    ECRS_freeMetaData(meta);
    ECRS_freeUri(uri);
    FREE(name);
    if (ret == OK) {
      return key;
    } else {
      ECRS_freeUri(key);
      return NULL;
    }
  } else {
    FREE(name);
    return NULL;
  }
}

static int searchCB(const ECRS_FileInfo * fi,
		    const HashCode512 * key,
		    int isRoot,
		    void * closure) {
  struct ECRS_URI ** my = closure;
  char * tmp;

  tmp = ECRS_uriToString(fi->uri);
  LOG(LOG_DEBUG,
      "Search found URI `%s'\n",
      tmp);
  FREE(tmp);
  GNUNET_ASSERT(NULL == *my);
  *my = ECRS_dupUri(fi->uri);
  return SYSERR; /* abort search */
}

/**
 * @param *uri In: keyword URI, out: file URI
 * @return OK on success
 */
static int searchFile(struct ECRS_URI ** uri) {
  int ret;
  struct ECRS_URI * myURI;

  myURI = NULL;
  ret = ECRS_search(*uri,
		    0,
		    15 * cronSECONDS,
		    &searchCB,
		    &myURI,
		    &testTerminate,
		    NULL);
  ECRS_freeUri(*uri);
  *uri = myURI;
  if ( (ret != SYSERR) &&
       (myURI != NULL) )
    return OK;
  else
    return SYSERR;
}

static int downloadFile(unsigned int size,
			const struct ECRS_URI * uri) {
  int ret;
  char * tmpName;
  int fd;
  char * buf;
  char * in;
  int i;
  char * tmp;

  tmp = ECRS_uriToString(uri);
  LOG(LOG_DEBUG,
      "Starting download of `%s'\n",
      tmp);
  FREE(tmp);
  tmpName = makeName(0);
  ret = SYSERR;
  if (OK == ECRS_downloadFile(uri,
			      tmpName,
			      0,
			      NULL,
			      NULL,
			      &testTerminate,
			      NULL)) {

    fd = fileopen(tmpName, O_RDONLY);
    buf = MALLOC(size);
    in = MALLOC(size);
    memset(buf, size + size / 253, size);
    for (i=0;i<(int) (size - 42 - sizeof(HashCode512));i+=sizeof(HashCode512))
      hash(&buf[i+sizeof(HashCode512)],
	   42,
	   (HashCode512*) &buf[i]);
    if (size != READ(fd, in, size))
      ret = SYSERR;
    else if (0 == memcmp(buf,
			 in,
			 size))
      ret = OK;
    FREE(buf);
    FREE(in);
    closefile(fd);
  }
  UNLINK(tmpName);
  FREE(tmpName);
  return ret;
}

static int unindexFile(unsigned int size) {
  int ret;
  char * name;

  name = makeName(size);
  ret = ECRS_unindexFile(name,
			 NULL,
			 NULL,
			 &testTerminate,
			 NULL);
  if (0 != UNLINK(name))
    ret = SYSERR;
  FREE(name);
  return ret;
}

#define CHECK(a) if (!(a)) { ret = 1; BREAK(); goto FAILURE; }

/**
 * Testcase to test gap routing (2 peers only).
 * @return 0: ok, -1: error
 */
int main(int argc, char ** argv) {
  pid_t daemon1;
  pid_t daemon2;
  int ret;
  GNUNET_TCP_SOCKET * sock;
  int left;
  struct ECRS_URI * uri;

  GNUNET_ASSERT(OK ==
		enc2hash("BV3AS3KMIIBVIFCGEG907N6NTDTH26B7T6FODUSLSGK"
			 "5B2Q58IEU1VF5FTR838449CSHVBOAHLDVQAOA33O77F"
			 "OPDA8F1VIKESLSNBO",
			 &peer2.hashPubKey));
  /* set to 0 if you want to start gnunetd's by hand for debugging */

  if (OK != initUtil(argc,
		     argv,
		     &parseOptions))
    return -1;
#if 1
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer1.conf"));
  daemon1 = startGNUnetDaemon(NO);
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer2.conf"));
  daemon2 = startGNUnetDaemon(NO);
  /* in case existing hellos have expired */
  sleep(5);
  system("cp ./peer1/data/hosts/* peer2/data/hosts/");
  system("cp ./peer2/data/hosts/* peer1/data/hosts/");
  if (daemon1 != -1) {
    if (! termProcess(daemon1))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon1));
  }
  if (daemon2 != -1) {
    if (! termProcess(daemon2))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon2));
  }

  /* re-start, this time we're sure up-to-date hellos are available */
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer1.conf"));
  daemon1 = startGNUnetDaemon(NO);
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "peer2.conf"));
  daemon2 = startGNUnetDaemon(NO);
  sleep(5);

  /* wait for connection or abort with error */
#else
  daemon1 = -1;
  daemon2 = -1;
#endif
  ret = 0;
  left = 5;
  do {
    sock = getClientSocket();
    if (sock == NULL) {
      printf(_("Waiting for gnunetd to start (%u iterations left)...\n"),
	     left);
      sleep(1);
      left--;
      CHECK(left > 0);
    }
  } while (sock == NULL);

  left = 30; /* how many iterations should we wait? */
  while (OK == requestStatistics(sock,
				 &waitForConnect,
				 NULL)) {
    printf(_("Waiting for peers to connect (%u iterations left)...\n"),
	   left);
    sleep(5);
    left--;
    CHECK(left > 0);
  }
  releaseClientSocket(sock);


  uri = uploadFile(12345);
  CHECK(NULL != uri);
  CHECK(OK == searchFile(&uri));
  setConfigurationInt("NETWORK",
		      "PORT",
		      12087);
  CHECK(OK == downloadFile(12345, uri));
  ECRS_freeUri(uri);
  setConfigurationInt("NETWORK",
		      "PORT",
		      2087);
  CHECK(OK == unindexFile(12345));

 FAILURE:

  if (daemon1 != -1) {
    if (! termProcess(daemon1))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon1));
  }
  if (daemon2 != -1) {
    if (! termProcess(daemon2))
      DIE_STRERROR("kill");
    GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon2));
  }
  doneUtil();
  return ret;
}

/* end of gaptest.c */
