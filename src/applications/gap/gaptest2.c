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
 * @file applications/gap/gaptest2.c
 * @brief GAP routing testcase, linear topology
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_stats_lib.h"
#include "gnunet_util_crypto.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_stats_lib.h"


#define START_PEERS 1

#define PEER_COUNT 4

#define SIZE 1024 * 1024 * 2

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

static int testTerminate(void * unused) {
  return OK;
}

static void uprogress(unsigned long long totalBytes,
		      unsigned long long completedBytes,
		      cron_t eta,
		      void * closure) {
  fprintf(stderr,
	  totalBytes == completedBytes ? "\n" : ".");
}

static void dprogress(unsigned long long totalBytes,
		      unsigned long long completedBytes,
		      cron_t eta,
		      unsigned long long lastBlockOffset,
		      const char * lastBlock,
		      unsigned int lastBlockSize,
		      void * closure) {
  fprintf(stderr,
	  totalBytes == completedBytes ? "\n" : ".");
}

static char * makeName(unsigned int i) {
  char * fn;

  fn = MALLOC(strlen("/tmp/gnunet-gaptest/GAPTEST") + 14);
  SNPRINTF(fn,
	   strlen("/tmp/gnunet-gaptest/GAPTEST") + 14,
	   "/tmp/gnunet-gaptest/GAPTEST%u",
	   i);
  disk_directory_create_for_file(NULL, fn);
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
  fd = disk_file_open(ectx,
		      name,
		      O_WRONLY|O_CREAT, S_IWUSR|S_IRUSR);
  buf = MALLOC(size);
  memset(buf, size / 253, sizeof(HashCode512));
  for (i=0;i<size - sizeof(HashCode512);i+=sizeof(HashCode512))
    hash(&buf[i],
	 sizeof(HashCode512),
	 (HashCode512*) &buf[i+sizeof(HashCode512)]);
  WRITE(fd, buf, size);
  FREE(buf);
  disk_file_close(ectx, name, fd);
  ret = ECRS_uploadFile(ectx,
			cfg,
			name,
			YES, /* index */
			1, /* anon */
			0, /* prio */
			get_time() + 100 * cronMINUTES, /* expire */
			&uprogress, /* progress */
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
    ret = ECRS_addToKeyspace(ectx,
			     cfg,
			     key,
			     0,
			     0,
			     get_time() + 100 * cronMINUTES, /* expire */
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
  GE_LOG(ectx, GE_DEBUG | GE_REQUEST | GE_USER,
      "Search found URI `%s'\n",
      tmp);
  FREE(tmp);
  GE_ASSERT(ectx, NULL == *my);
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
  ret = ECRS_search(ectx,
		    cfg,
		    *uri,
		    1,
		    1450 * cronSECONDS,
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
  GE_LOG(ectx,
	 GE_DEBUG | GE_REQUEST | GE_USER,
	 "Starting download of `%s'\n",
	 tmp);
  FREE(tmp);
  tmpName = makeName(0);
  ret = SYSERR;
  if (OK == ECRS_downloadFile(ectx,
			      cfg,
			      uri,
			      tmpName,
			      1,
			      &dprogress,
			      NULL,
			      &testTerminate,
			      NULL)) {

    fd = disk_file_open(ectx,
			tmpName,
			O_RDONLY);
    buf = MALLOC(size);
    in = MALLOC(size);
    memset(buf, size / 253, sizeof(HashCode512));
    for (i=0;i<size - sizeof(HashCode512);i+=sizeof(HashCode512))
      hash(&buf[i],
	   sizeof(HashCode512),
	   (HashCode512*) &buf[i+sizeof(HashCode512)]);
    if (size != READ(fd, in, size))
      ret = SYSERR;
    else if (0 == memcmp(buf,
			 in,
			 size))
      ret = OK;
    FREE(buf);
    FREE(in);
    disk_file_close(ectx, tmpName, fd);
  }
  UNLINK(tmpName);
  FREE(tmpName);
  return ret;
}

static int unindexFile(unsigned int size) {
  int ret;
  char * name;

  name = makeName(size);
  ret = ECRS_unindexFile(ectx,
			 cfg,
			 name,
			 NULL,
			 NULL,
			 &testTerminate,
			 NULL);
  if (0 != UNLINK(name))
    ret = SYSERR;
  FREE(name);
  return ret;
}

#define CHECK(a) if (!(a)) { ret = 1; GE_BREAK(ectx, 0); goto FAILURE; }

/**
 * Testcase to test gap routing (2 peers only).
 * @return 0: ok, -1: error
 */
int main(int argc, char ** argv) {
  struct DaemonContext * peers;
  int ret;
  struct ECRS_URI * uri;
  int i;
  char buf[128];
  cron_t start;

  ret = 0;
  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;
  }
#if START_PEERS
  peers = gnunet_testing_start_daemons("tcp",
				       "advertising topology fs stats",
				       "/tmp/gnunet-gap-test2",
				       2087,
				       10,
				       PEER_COUNT);
  if (peers == NULL) {
    fprintf(stderr,
	    "Failed to start the gnunetd daemons!\n");
    GC_free(cfg);
    return -1;
  }
#endif
  for (i=1;i<PEER_COUNT;i++) {
    if (OK != gnunet_testing_connect_daemons(2077 + (10*i),
					     2087 + (10*i))) {
      gnunet_testing_stop_daemons(peers);
      fprintf(stderr,
	      "Failed to connect the peers!\n");
      GC_free(cfg);
      return -1;
    }
  }

  printf("Uploading...\n");
  uri = uploadFile(SIZE);
  CHECK(NULL != uri);
  SNPRINTF(buf,
	   128,
	   "localhost:%u",
	   2077 + PEER_COUNT * 10);
  GC_set_configuration_value_string(cfg,
				    ectx,
				    "NETWORK",
				    "HOST",
				    buf);
  CHECK(OK == searchFile(&uri));
  printf("Search successful!\n");
  start = get_time();
  printf("Downloading...\n");
  CHECK(OK == downloadFile(SIZE, uri));
  printf("Download successful at %llu kbps!\n",
	 (SIZE / 1024) / ((get_time() - start) / cronSECONDS));
  ECRS_freeUri(uri);
  GC_set_configuration_value_string(cfg,
				    ectx,
				    "NETWORK",
				    "HOST",
				    "localhost:2087");
  CHECK(OK == unindexFile(SIZE));

 FAILURE:
#if START_PEERS
  gnunet_testing_stop_daemons(peers);
#endif

  GC_free(cfg);
  return ret;
}

/* end of gaptest2.c */
