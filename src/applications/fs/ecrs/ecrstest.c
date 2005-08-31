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
 * @file applications/fs/ecrs/ecrstest.c
 * @brief testcase for ecrs (upload-download)
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
    hash(&buf[i],
	 42,
	 (HashCode512*) &buf[i+sizeof(HashCode512)]);
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
      hash(&buf[i],
	   42,
	   (HashCode512*) &buf[i+sizeof(HashCode512)]);
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

int main(int argc, char * argv[]){
  static unsigned int filesizes[] = {
    DBLOCK_SIZE - 1,
    DBLOCK_SIZE,
    DBLOCK_SIZE + 1,
    DBLOCK_SIZE * CHK_PER_INODE - 1,
    DBLOCK_SIZE * CHK_PER_INODE,
    DBLOCK_SIZE * CHK_PER_INODE + 1,
    1,
    2,
    4,
    16,
    32,
    1024,
    0
  };
  pid_t daemon;
  int ok;
  GNUNET_TCP_SOCKET * sock;
  struct ECRS_URI * uri;
  int i;

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
  i = 0;
  while (filesizes[i] != 0) {
    fprintf(stderr,
	    "Testing filesize %u",
	    filesizes[i]);
    uri = uploadFile(filesizes[i]);
    CHECK(NULL != uri);
    CHECK(OK == searchFile(&uri));
    CHECK(OK == downloadFile(filesizes[i], uri));
    ECRS_freeUri(uri);
    CHECK(OK == unindexFile(filesizes[i]));
    fprintf(stderr,
	    " Ok.\n");
    i++;
  }

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

/* end of ecrstest.c */
