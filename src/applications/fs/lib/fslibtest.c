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
#include <sys/wait.h>

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
				     "WARNING"));
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

typedef struct {
  Semaphore * sem;
  int found; 
  int i;
} TSC;

static void abortSem(Semaphore * sem) {
  SEMAPHORE_UP(sem);
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
  int status;
  int ok;
  struct FS_SEARCH_CONTEXT * ctx;
  Mutex lock;
  GNUNET_TCP_SOCKET * sock;
  Datastore_Value * block;
  Datastore_Value * eblock;
  HashCode512 hc;
  HashCode512 query;
  int i;

  cronTime(&now);
  daemon = fork();
  if (daemon == 0) {
    /* FIXME: would be nice to be able to tell
       gnunetd to use the check/debug DB and not
       any real DB! */
    if (0 != execlp("gnunetd", /* what binary to execute, must be in $PATH! */
		    "gnunetd", /* arg0, path to gnunet binary */
		    "-d",  /* do not daemonize so we can easily kill you */
		    "-L", 
		    "NOTHING",  /* gnunetd loglevel */
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
  ok = YES;
  initUtil(argc, argv, &parseCommandLine);
  startCron();
  MUTEX_CREATE(&lock);
  gnunet_util_sleep(5 * cronSECONDS); /* give gnunetd time to start */
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
  doneUtil();
  if (daemon != -1) {
    if (0 != kill(daemon, SIGTERM))
      DIE_STRERROR("kill");
    if (daemon != waitpid(daemon, &status, 0)) 
      DIE_STRERROR("waitpid");
  
    if ( (WEXITSTATUS(status) == 0) && 
	 (ok == YES) )
      return 0;
    else
      return 1;    
  } else
    return 0;
}

/* end of fslibtest.c */
