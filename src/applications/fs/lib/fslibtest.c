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
 * @file applications/fs/lib/fslibtest.c
 * @brief testcase for fslib
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fs_lib.h"
#include "gnunet_protocols.h"
#include "ecrs_core.h"

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
				     "ERROR"));
  FREENONNULL(setConfigurationString("GNUNET",
				     "GNUNETD-CONFIG",
				     "check.conf"));
  return OK;
}

static cron_t now;

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
  Semaphore * sem;
  int found;
  int i;
} TSC;

static void abortSem(Semaphore * sem) {
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
  blk->prio = htonl(0);
  blk->anonymityLevel = htonl(0);
  blk->expirationTime = htonll(0);
  fileBlockGetQuery((DBlock*) &blk[1],
		    ntohl(blk->size) - sizeof(Datastore_Value),
		    &ekey);
  GNUNET_ASSERT(OK ==
		fileBlockEncode((DBlock*) &blk[1],
				ntohl(blk->size) - sizeof(Datastore_Value),
				&ekey,
				&eblk));
  if ( (equalsHashCode512(&ekey,
			  key)) &&
       (value->size == blk->size) &&
       (0 == memcmp(value,
		    eblk,
		    ntohl(value->size))) ) {
    cls->found = YES;
    SEMAPHORE_UP(cls->sem);
    ret = SYSERR;
  } else {
    BREAK();
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
  closure.sem = SEMAPHORE_NEW(0);
  cronTime(&now);
  handle = FS_start_search(ctx,
			   D_BLOCK,
			   1,
			   &query,
			   0,
			   0,
			   now + 30 * cronSECONDS,
			   (Datum_Iterator)&searchResultCB,
			   &closure);
  addCronJob((CronJob) &abortSem,
	     30 * cronSECONDS,
	     0,
	     closure.sem);
  SEMAPHORE_DOWN(closure.sem);
  FS_stop_search(ctx,
		 handle);
  suspendCron();
  delCronJob((CronJob) &abortSem, 0, closure.sem);
  resumeCron();
  SEMAPHORE_FREE(closure.sem);
  return closure.found;
}


int main(int argc, char * argv[]){
  pid_t daemon;
  int ok;
  struct FS_SEARCH_CONTEXT * ctx = NULL;
  struct FS_SEARCH_HANDLE * hnd;
  Mutex lock;
  GNUNET_TCP_SOCKET * sock;
  Datastore_Value * block;
  Datastore_Value * eblock;
  HashCode512 hc;
  HashCode512 query;
  int i;
  char * tmpName;
  int fd;

  cronTime(&now);
  if (OK != initUtil(argc,
		     argv,
		     &parseCommandLine))
    return -1;
  daemon = startGNUnetDaemon(NO);
  GNUNET_ASSERT(daemon > 0);
  ok = YES;
  startCron();
  MUTEX_CREATE(&lock);
  GNUNET_ASSERT(OK == waitForGNUnetDaemonRunning(60 * cronSECONDS));
  gnunet_util_sleep(5 * cronSECONDS); /* give apps time to start */
  sock = getClientSocket();
  CHECK(sock != NULL);
  ctx = FS_SEARCH_makeContext(&lock);
  CHECK(ctx != NULL);

  /* ACTUAL TEST CODE */
  for (i=1;i<32;i++) {
    block = makeBlock(i);
    fileBlockGetQuery((DBlock*) &block[1],
		      ntohl(block->size) - sizeof(Datastore_Value),
		      &query);
    CHECK(OK == fileBlockEncode((DBlock*) &block[1],
				ntohl(block->size) - sizeof(Datastore_Value),
				&query,
				&eblock));
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
    closefile(fd);
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
    FREE(block);
  }
  for (i=32;i<MAX_BUFFER_SIZE;i*=2) {
    block = makeBlock(i);
    fileBlockGetQuery((DBlock*) &block[1],
		      ntohl(block->size) - sizeof(Datastore_Value),
		      &query);
    CHECK(OK == fileBlockEncode((DBlock*) &block[1],
				ntohl(block->size) - sizeof(Datastore_Value),
				&query,
				&eblock));
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
  hnd = FS_start_search(ctx,
			ANY_BLOCK,
			1,
			&query,
			0,
			0,
			10 * cronSECONDS,
			&countCallback,
			&i);
  CHECK(hnd != NULL);
  gnunet_util_sleep(10 * cronSECONDS);
  FS_stop_search(ctx, hnd);
  CHECK(i <= 0);
		

  /* just to check if it crashes... */
  FS_getAveragePriority(sock);
  /* END OF TEST CODE */

 FAILURE:
  if (ctx != NULL)
    FS_SEARCH_destroyContext(ctx);
  if (sock != NULL)
    releaseClientSocket(sock);
  MUTEX_DESTROY(&lock);
  stopCron();
  GNUNET_ASSERT(OK == stopGNUnetDaemon());
  GNUNET_ASSERT(OK == waitForGNUnetDaemonTermination(daemon));
  doneUtil();
  return (ok == YES) ? 0 : 1;
}

/* end of fslibtest.c */
