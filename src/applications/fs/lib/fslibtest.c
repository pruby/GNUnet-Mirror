/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/lib/fslibtest.c
 * @brief testcase for fslib
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_cron.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_network_client.h"
#include "gnunet_fs_lib.h"
#include "gnunet_protocols.h"
#include "ecrs_core.h"

#define CHECK(a) if (!(a)) { ok = NO; GE_BREAK(NULL, 0); goto FAILURE; }

static struct CronManager * cron;

static cron_t now;

static struct PTHREAD * mainThread;

static Datastore_Value * makeBlock(int i) {
  Datastore_Value * block;
  DBlock * db;

  block = MALLOC(sizeof(Datastore_Value) +
		 sizeof(DBlock) + i);
  block->size = htonl(sizeof(Datastore_Value) +
		      sizeof(DBlock) + i);
  block->type = htonl(D_BLOCK);
  block->prio = htonl(0);
  block->anonymityLevel = htonl(0);
  block->expirationTime = htonll(now + 1 * cronHOURS);
  db = (DBlock*) &block[1];
  db->type = htonl(D_BLOCK);
  memset(&db[1],
	 i + (i /253),
	 i);
  return block;
}

static Datastore_Value * makeKBlock(unsigned int i,
				    const HashCode512 * key,
				    HashCode512 * query) {
  Datastore_Value * block;
  KBlock * db;
  struct PrivateKey * kkey;

  block = MALLOC(sizeof(Datastore_Value) +
		 sizeof(KBlock) + i);
  block->size = htonl(sizeof(Datastore_Value) +
		      sizeof(KBlock) + i);
  block->type = htonl(K_BLOCK);
  block->prio = htonl(0);
  block->anonymityLevel = htonl(0);
  block->expirationTime = htonll(now + 1 * cronHOURS);
  db = (KBlock*) &block[1];
  db->type = htonl(K_BLOCK);
  memset(&db[1],
	 i + (i /253),
	 i);
  kkey = makeKblockKey(key);
  sign(kkey,
       i,
       &db[1],
       &db->signature);
  getPublicKey(kkey,
	       &db->keyspace);
  hash(&db->keyspace,
       sizeof(PublicKey),
       query);
  freePrivateKey(kkey);
  return block;
}


typedef struct {
  struct SEMAPHORE * sem;
  int found;
  int i;
} TSC;

static void abortSem(void * cls) {
  struct SEMAPHORE * sem = cls;
  SEMAPHORE_UP(sem);
}

/**
 * Search result callback that just counts down
 * a counter.
 */
static int countCallback(const HashCode512 * key,
			 const Datastore_Value * value,
			 void * cls) {
  int * cnt = cls;
  (*cnt)--;
  fprintf(stderr, "*");
  if (*cnt <= 0)
    PTHREAD_STOP_SLEEP(mainThread);
  return OK;
}


static int searchResultCB(const HashCode512 * key,
			  const Datastore_Value * value,
			  TSC * cls) {
  HashCode512 ekey;
  Datastore_Value * blk;
  Datastore_Value * eblk;
  int ret;

  blk = makeBlock(cls->i);
  fileBlockGetQuery((DBlock*) &blk[1],
		    ntohl(blk->size) - sizeof(Datastore_Value),
		    &ekey);
  GE_ASSERT(NULL, OK ==
	    fileBlockEncode((DBlock*) &blk[1],
			    ntohl(blk->size) - sizeof(Datastore_Value),
			    &ekey,
			    &eblk));
  if ( (equalsHashCode512(&ekey,
			  key)) &&
       (value->size == blk->size) &&
       (0 == memcmp(&value[1],
		    &eblk[1],
		    ntohl(value->size) - sizeof(Datastore_Value))) ) {
    cls->found = YES;
    SEMAPHORE_UP(cls->sem);
    ret = SYSERR;
  } else {
    GE_BREAK(NULL, 0);
    printf("Received unexpected result.\n");
    ret = OK;
  }
  FREE(eblk);
  FREE(blk);
  return ret;
}

static int trySearch(struct FS_SEARCH_CONTEXT * ctx,
		     int i) {
  struct FS_SEARCH_HANDLE * handle;
  cron_t now;
  HashCode512 query;
  TSC closure;
  Datastore_Value * dv;
  DBlock * db;

  dv = makeBlock(i);
  db = (DBlock*) &dv[1];
  fileBlockGetQuery(db,
		    ntohl(dv->size) - sizeof(Datastore_Value),
		    &query);
  FREE(dv);
  closure.found = NO;
  closure.i = i;
  closure.sem = SEMAPHORE_CREATE(0);
  now = get_time();
  handle = FS_start_search(ctx,
			   NULL,
			   D_BLOCK,
			   1,
			   &query,
			   0,
			   0,
			   now + 30 * cronSECONDS,
			   (Datum_Iterator)&searchResultCB,
			   &closure);
  cron_add_job(cron,
	       &abortSem,
	       30 * cronSECONDS,
	       0,
	       closure.sem);
  SEMAPHORE_DOWN(closure.sem, YES);
  FS_stop_search(ctx,
		 handle);
  cron_suspend(cron, NO);
  cron_del_job(cron,
	       &abortSem, 0, closure.sem);
  cron_resume_jobs(cron, NO);
  SEMAPHORE_DESTROY(closure.sem);
  return closure.found;
}

#define START_DAEMON 1

int main(int argc, char * argv[]){
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  struct FS_SEARCH_CONTEXT * ctx = NULL;
  struct FS_SEARCH_HANDLE * hnd;
  struct MUTEX * lock;
  struct ClientServerConnection * sock;
  Datastore_Value * block;
  Datastore_Value * eblock;
  HashCode512 hc;
  HashCode512 query;
  int i;
  char * tmpName;
  int fd;
  struct GC_Configuration * cfg;

  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;
  }
  now = get_time();
  cron = cron_create(NULL);
#if START_DAEMON
  daemon = os_daemon_start(NULL,
			   cfg,
			   "peer.conf",
			   NO);
  GE_ASSERT(NULL, daemon > 0);
#endif
  ok = YES;
  cron_start(cron);
  lock = MUTEX_CREATE(NO);
  GE_ASSERT(NULL,
	    OK == connection_wait_for_running(NULL,
					      cfg,
					      60 * cronSECONDS));
  PTHREAD_SLEEP(5 * cronSECONDS); /* give apps time to start */
  sock = client_connection_create(NULL, cfg);
  CHECK(sock != NULL);
  ctx = FS_SEARCH_makeContext(NULL,
			      cfg,
			      lock);
  CHECK(ctx != NULL);

  /* ACTUAL TEST CODE */
  for (i=1;i<32;i++) {
    fprintf(stderr, ".");
    block = makeBlock(i);
    fileBlockGetQuery((DBlock*) &block[1],
		      ntohl(block->size) - sizeof(Datastore_Value),
		      &query);
    CHECK(OK == fileBlockEncode((DBlock*) &block[1],
				ntohl(block->size) - sizeof(Datastore_Value),
				&query,
				&eblock));
    eblock->expirationTime = block->expirationTime;
    eblock->prio = block->prio;
    CHECK(OK == FS_insert(sock,
			  eblock));
    CHECK(OK == trySearch(ctx, i));
    CHECK(SYSERR != FS_delete(sock,
			      eblock));
    FREE(eblock);
    hash(&((DBlock*)&block[1])[1],
	 ntohl(block->size) - sizeof(Datastore_Value) - sizeof(DBlock),
	 &hc);
    /* indexing without symlink */
    CHECK(OK == FS_index(sock,
			 &hc,
			 block,
			 0));
    CHECK(OK == trySearch(ctx, i));
    CHECK(OK == FS_unindex(sock,
			   MAX_BUFFER_SIZE,
			   &hc));
    /* indexing with symlink */
    tmpName = STRDUP("/tmp/symlinkTestXXXXXX");
    CHECK(-1 != (fd = mkstemp(tmpName)));
    CHECK(-1 != WRITE(fd,
		      &((DBlock*)&block[1])[1],
		      ntohl(block->size) - sizeof(Datastore_Value) - sizeof(DBlock)));
    CLOSE(fd);
    CHECK(FS_initIndex(sock,
		       &hc,
		       tmpName) == YES);
    CHECK(OK == FS_index(sock,
			 &hc,
			 block,
			 0));
    CHECK(OK == trySearch(ctx, i));
    CHECK(OK == FS_unindex(sock,
			   MAX_BUFFER_SIZE,
			   &hc));
    UNLINK(tmpName);
    FREE(tmpName);
    FREE(block);
  }
  fprintf(stderr, "\n");
  for (i=32;i<MAX_BUFFER_SIZE;i*=2) {
    fprintf(stderr, ".");
    block = makeBlock(i);
    fileBlockGetQuery((DBlock*) &block[1],
		      ntohl(block->size) - sizeof(Datastore_Value),
		      &query);
    CHECK(OK == fileBlockEncode((DBlock*) &block[1],
				ntohl(block->size) - sizeof(Datastore_Value),
				&query,
				&eblock));
    eblock->expirationTime = block->expirationTime;
    eblock->prio = block->prio;
    CHECK(OK == FS_insert(sock,
			  eblock));
    CHECK(OK == trySearch(ctx, i));
    CHECK(1 == FS_delete(sock,
			 eblock));
    FREE(eblock);
    hash(&((DBlock*)&block[1])[1],
	 ntohl(block->size) - sizeof(Datastore_Value) - sizeof(DBlock),
	 &hc);
    CHECK(OK == FS_index(sock,
			 &hc,
			 block,
			 0));
    CHECK(OK == trySearch(ctx, i));
    CHECK(OK == FS_unindex(sock,
			   MAX_BUFFER_SIZE,
			   &hc));
    FREE(block);
  }
  fprintf(stderr, "\n");

  /* multiple search results test */
  makeRandomId(&hc);
  block = makeKBlock(40, &hc, &query);
  CHECK(OK == FS_insert(sock,
			block));
  FREE(block);
  block = makeKBlock(60, &hc, &query);
  CHECK(OK == FS_insert(sock,
			block));
  FREE(block);
  i = 2;
  mainThread = PTHREAD_GET_SELF();
  hnd = FS_start_search(ctx,
			NULL,
			ANY_BLOCK,
			1,
			&query,
			0,
			0,
			10 * cronSECONDS,
			&countCallback,
			&i);
  CHECK(hnd != NULL);
  PTHREAD_SLEEP(10 * cronSECONDS);
  FS_stop_search(ctx, hnd);
  PTHREAD_REL_SELF(mainThread);
  CHECK(i <= 0);
		

  /* just to check if it crashes... */
  FS_getAveragePriority(sock);
  /* END OF TEST CODE */

 FAILURE:
  fprintf(stderr, "\n");
  if (ctx != NULL)
    FS_SEARCH_destroyContext(ctx);
  if (sock != NULL)
    connection_destroy(sock);
  MUTEX_DESTROY(lock);
  cron_stop(cron);
  cron_destroy(cron);
#if START_DAEMON
  GE_ASSERT(NULL, OK == os_daemon_stop(NULL, daemon));
#endif
  GC_free(cfg);
  return (ok == YES) ? 0 : 1;
}

/* end of fslibtest.c */
