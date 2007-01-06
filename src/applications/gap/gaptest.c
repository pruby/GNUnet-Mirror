/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util_crypto.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_stats_lib.h"

/**
 * Identity of peer 2 (hardwired).
 */
static PeerIdentity peer2;

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

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
  memset(buf, size + size / 253, size);
  for (i=0;i<(int) (size - 42 - sizeof(HashCode512));i+=sizeof(HashCode512))
    hash(&buf[i+sizeof(HashCode512)],
	 42,
	 (HashCode512*) &buf[i]);
  WRITE(fd, buf, size);
  FREE(buf);
  disk_file_close(ectx, name, fd);
  ret = ECRS_uploadFile(ectx,
			cfg,
			name,
			YES, /* index */
			0, /* anon */
			0, /* prio */
			get_time() + 10 * cronMINUTES, /* expire */
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
    ret = ECRS_addToKeyspace(ectx,
			     cfg,
			     key,
			     0,
			     0,
			     get_time() + 10 * cronMINUTES, /* expire */
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
			      0,
			      NULL,
			      NULL,
			      &testTerminate,
			      NULL)) {

    fd = disk_file_open(ectx,
			tmpName,
			O_RDONLY);
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

#define START_PEERS 1

/**
 * Testcase to test gap routing (2 peers only).
 * @return 0: ok, -1: error
 */
int main(int argc, char ** argv) {
  pid_t daemon1;
  pid_t daemon2;
  int ret;
  struct ClientServerConnection * sock;
  int left;
  struct ECRS_URI * uri;

  enc2hash("BV3AS3KMIIBVIFCGEG907N6NTDTH26B7T6FODUSLSGK"
	   "5B2Q58IEU1VF5FTR838449CSHVBOAHLDVQAOA33O77F"
	   "OPDA8F1VIKESLSNBO",
	   &peer2.hashPubKey);
  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;
  }
#if START_PEERS
  daemon1  = os_daemon_start(NULL,
			     cfg,
			     "peer1.conf",
			     NO);
  daemon2 = os_daemon_start(NULL,
			    cfg,
			    "peer2.conf",
			    NO);
#endif
  /* in case existing hellos have expired */
  PTHREAD_SLEEP(30 * cronSECONDS);
  system("cp peer1/data/hosts/* peer2/data/hosts/");
  system("cp peer2/data/hosts/* peer1/data/hosts/");
  ret = 0;
#if START_PEERS
  if (daemon1 != -1) {
    if (os_daemon_stop(NULL, daemon1) != YES)
      ret = 1;
  }
  if (daemon2 != -1) {
    if (os_daemon_stop(NULL, daemon2) != YES)
      ret = 1;
  }
  if (ret != 0)
    return 1;
  daemon1  = os_daemon_start(NULL,
			     cfg,
			     "peer1.conf",
			     NO);
  daemon2 = os_daemon_start(NULL,
			    cfg,
			    "peer2.conf",
			    NO);
#endif
  if (OK == connection_wait_for_running(NULL,
					cfg,
					30 * cronSECONDS)) {
    sock = client_connection_create(NULL,
				    cfg);
    left = 30; /* how many iterations should we wait? */
    while (OK == requestStatistics(NULL,
				   sock,
				   &waitForConnect,
				   NULL)) {
      printf("Waiting for peers to connect (%u iterations left)...\n",
	     left);
      sleep(5);
      left--;
      if (left == 0) {
	ret = 1;
	break;
      }
    }
    connection_destroy(sock);
  } else {
    printf("Could not establish connection with peer.\n");
    ret = 1;
  }


  uri = uploadFile(12345);
  CHECK(NULL != uri);
  CHECK(OK == searchFile(&uri));
  GC_set_configuration_value_string(cfg,
				    ectx,
				    "NETWORK",
				    "HOSTNAME",
				    "localhost:12087");
  CHECK(OK == downloadFile(12345, uri));
  ECRS_freeUri(uri);
  GC_set_configuration_value_string(cfg,
				    ectx,
				    "NETWORK",
				    "HOSTNAME",
				    "localhost:2087");
  CHECK(OK == unindexFile(12345));

 FAILURE:
#if START_PEERS
  if (daemon1 != -1) {
    if (os_daemon_stop(NULL, daemon1) != YES)
      ret = 1;
  }
  if (daemon2 != -1) {
    if (os_daemon_stop(NULL, daemon2) != YES)
      ret = 1;
  }
#endif

  GC_free(cfg);
  return ret;
}

/* end of gaptest.c */
