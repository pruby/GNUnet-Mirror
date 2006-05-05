/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/download.c
 * @brief Download helper methods (which do the real work).
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "ecrs_core.h"
#include "ecrs.h"
#include "tree.h"

#define DEBUG_DOWNLOAD NO 

/**
 * Highest TTL allowed? (equivalent of 25-50 HOPS distance!)
 */
#define MAX_TTL (100 * TTL_DECREMENT)

/**
 * After how many retries do we print a warning?
 */
#define MAX_TRIES 500


/* ****************** IO context **************** */

/**
 * @brief IO context for reading-writing file blocks.
 *
 * In GNUnet, files are stored in the form of a balanced tree, not
 * unlike INodes in unix filesystems. When we download files, the
 * inner nodes of the tree are stored under FILENAME.X (where X
 * characterizes the level of the node in the tree). If the download
 * is aborted and resumed later, these .X files can be used to avoid
 * downloading the inner blocks again.  The successfully received leaf
 * nodes in FILENAME (the target file) are of course also not
 * downloaded again.<p>
 *
 * The IOContext struct presents an easy api to access the various
 * dot-files. It uses function pointers to allow implementors to
 * provide a different mechanism (other than files on the drive) to
 * cache the IBlocks.
 */
typedef struct IOContext {

  /**
   * The depth of the file-tree.
   */
  unsigned int treedepth;

  /**
   * A lock for synchronizing access.
   */
  Mutex lock;

  /**
   * The file handles for each level in the tree.
   */
  int * handles;

  /**
   * The base-filename
   */
  char * filename;

} IOContext;

/**
 * Close the files in the IOContext and free
 * the associated resources. Does NOT free
 * the memory occupied by the IOContext struct
 * itself.
 *
 * @param this reference to the IOContext
 * @param unlinkTreeFiles if YES, the non-level 0 files
 *     are unlinked (removed), set to NO if the download
 *     is not complete and may be resumed later.
 */
static void freeIOC(IOContext * this,
		    int unlinkTreeFiles) {
  int i;
  char * fn;

  for (i=0;i<=this->treedepth;i++) {
    if (this->handles[i] != -1) {
      closefile(this->handles[i]);
      this->handles[i] = -1;
    }
  }
  MUTEX_DESTROY(&this->lock);
  if (YES == unlinkTreeFiles) {
    for (i=1;i<= this->treedepth;i++) {
      fn = MALLOC(strlen(this->filename) + 3 + strlen(GNUNET_DIRECTORY_EXT));
      strcpy(fn, this->filename);
      if (fn[strlen(fn)-1] == '/') {
	fn[strlen(fn)-1] = '\0';
	strcat(fn, GNUNET_DIRECTORY_EXT);
      }
      strcat(fn, ".A");
      fn[strlen(fn)-1]+=i;
      if (0 != UNLINK(fn))
	LOG(LOG_WARNING,
	    _("Could not unlink temporary file `%s': %s\n"),
	    fn, STRERROR(errno));
      FREE(fn);
    }
  }
  FREE(this->filename);
  FREE(this->handles);
}

/**
 * Initialize an IOContext.
 *
 * @param this the context to initialize
 * @param filesize the size of the file
 * @param filename the name of the level-0 file
 * @return OK on success, SYSERR on failure
 */
static int createIOContext(IOContext * this,
			   unsigned long long filesize,
			   const char * filename) {
  int i;
  char * fn;
  struct stat st;

  GNUNET_ASSERT(filename != NULL);
  this->treedepth = computeDepth(filesize);
  MUTEX_CREATE(&this->lock);
  this->handles = MALLOC(sizeof(int) * (this->treedepth+1));
  this->filename = STRDUP(filename);

  if ( (0 == STAT(filename, &st)) &&
       ((size_t)st.st_size > filesize ) ) {
    /* if exists and oversized, truncate */
    if (truncate(filename, filesize) != 0) {
      LOG_FILE_STRERROR(LOG_FAILURE,
			"truncate",
			filename);
      return SYSERR;
    }
  }
  for (i=0;i<=this->treedepth;i++)
    this->handles[i] = -1;

  for (i=0;i<=this->treedepth;i++) {
    fn = MALLOC(strlen(filename) + 3 + strlen(GNUNET_DIRECTORY_EXT));
    strcpy(fn, filename);
    if (fn[strlen(fn)-1] == '/') {
      fn[strlen(fn)-1] = '\0';
      strcat(fn, GNUNET_DIRECTORY_EXT);
    }
    if (i > 0) {
      strcat(fn, ".A");
      fn[strlen(fn)-1] += i;
    }
    this->handles[i] = fileopen(fn,
				O_CREAT|O_RDWR,
				S_IRUSR|S_IWUSR );
    if (this->handles[i] < 0) {
      LOG_FILE_STRERROR(LOG_FAILURE,
			"open",
			fn);
      freeIOC(this, NO);
      FREE(fn);
      return SYSERR;
    }
    FREE(fn);
  }
  return OK;
}

/**
 * Read method.
 *
 * @param this reference to the IOContext
 * @param level level in the tree to read/write at
 * @param pos position where to read or write
 * @param buf where to read from or write to
 * @param len how many bytes to read or write
 * @return number of bytes read, SYSERR on error
 */
int readFromIOC(IOContext * this,
		unsigned int level,
		unsigned long long pos,
		void * buf,
		unsigned int len) {
  int ret;
  size_t lpos;

  lpos = pos;
  for (ret=0;ret<level;ret++)
    lpos /= CHK_PER_INODE;
  MUTEX_LOCK(&this->lock);
  lseek(this->handles[level],
	lpos,
	SEEK_SET);
  ret = READ(this->handles[level],
	     buf,
	     len);
  MUTEX_UNLOCK(&this->lock);
  return ret;
}

/**
 * Write method.
 *
 * @param this reference to the IOContext
 * @param level level in the tree to write to
 * @param pos position where to  write
 * @param buf where to write to
 * @param len how many bytes to write
 * @return number of bytes written, SYSERR on error
 */
int writeToIOC(IOContext * this,
	       unsigned int level,
	       unsigned long long pos,
	       void * buf,
	       unsigned int len) {
  int ret;
  size_t lpos;

  lpos = pos;
  for (ret=0;ret<level;ret++)
    lpos /= CHK_PER_INODE;
  MUTEX_LOCK(&this->lock);
  lseek(this->handles[level],
	lpos,
	SEEK_SET);
  ret = WRITE(this->handles[level],
	      buf,
	      len);
  if (ret != len) {
    LOG(LOG_WARNING,
	_("Write(%d, %p, %d) failed: %s\n"),
	this->handles[level],
	buf,
	len,
	STRERROR(errno));
  }
  MUTEX_UNLOCK(&this->lock);
  return ret;
}

/* ********************* request manager **************** */

/**
 * Node-specific data (not shared, keep small!). 56 bytes.
 */
typedef struct {
  /**
   * Pointer to shared data between all nodes (request manager,
   * progress data, etc.).
   */
  struct CommonCtx * ctx;
  /**
   * What is the CHK for this block?
   */
  CHK chk;
  /**
   * At what offset (on the respective level!) is this
   * block?
   */
  unsigned long long offset;
  /**
   * 0 for dblocks, >0 for iblocks.
   */
  unsigned int level;
} NodeClosure;

/**
 * @brief Format of a request as tracked by the RequestManager.
 *
 * This structure together with the NodeContext determine the memory
 * requirements, so try keeping it as small as possible!  (currently
 * 32 bytes, plus 56 in the NodeContext => roughly 88 byte per block!)
 *
 * Estimate: max ~12 MB memory for a 4 GB file in the end (assuming
 * maximum parallelism, which is likely, so we are really going to use
 * about 12 MB, but that should be acceptable).
 *
 * Design question: why not union RequestEntry and NodeClosure (would
 * save yet another 4 bytes / entry)?
 */
typedef struct RequestEntry {

  /**
   * The node for which this entry keeps data.
   */
  NodeClosure * node;

  /**
   * Last time the query was send.
   */
  cron_t lasttime;

  /**
   * Timeout used for the last search (ttl in request is
   * = lastTimeout - lasttime modulo corrections in gap
   * with respect to priority cap).
   */
  cron_t lastTimeout;

  /**
   * How long have we been actively trying this one?
   */
  unsigned int tries;

  /**
   * Priority used for the last request.
   */
  unsigned int lastPriority;

  /**
   * Search handle of the last request (NULL if never
   * requested).
   */
  struct FS_SEARCH_HANDLE * searchHandle;

} RequestEntry;

/**
 * @brief structure that keeps track of currently pending requests for
 *        a download
 *
 * Handle to the state of a request manager.  Here we keep track of
 * which queries went out with which priorities and which nodes in
 * the merkle-tree are waiting for the replies.
 */
typedef struct RequestManager {

  /**
   * Mutex for synchronizing access to this struct
   */
  Mutex lock;

  /**
   * Current list of all pending requests
   */
  RequestEntry ** requestList;

  /**
   * Number of pending requests (highest used index)
   */
  unsigned int requestListIndex;

  /**
   * Number of entries allocated for requestList
   */
  unsigned int requestListSize;

  /**
   * Current "good" TTL (initial) [64s].  In HOST byte order.
   */
  unsigned int initialTTL;

  /**
   * Congestion window.  How many messages
   * should be pending concurrently?
   */
  unsigned int congestionWindow;

  /**
   * Slow-start threshold (see RFC 2001)
   */
  unsigned int ssthresh;

  /**
   * What was the last time we updated ssthresh?
   */
  TIME_T lastDET;

  /**
   * Abort?  Flag that can be set at any time
   * to abort the RM as soon as possible.
   */
  int abortFlag;

  struct FS_SEARCH_CONTEXT * sctx;

  PTHREAD_T requestThread;

} RequestManager;

static int nodeReceive(const HashCode512 * query,
		       const Datastore_Value * reply,
		       NodeClosure * node);

/**
 * Create a request manager.  Will create the request manager
 * datastructures. Use destroyRequestManager to abort and/or to free
 * resources after the download is complete.
 *
 * @return NULL on error
 */
static RequestManager * createRequestManager() {
  RequestManager * rm;

  rm = MALLOC(sizeof(RequestManager));
  PTHREAD_GET_SELF(&rm->requestThread);
  rm->abortFlag
    = NO;
  rm->lastDET
    = 0;
  MUTEX_CREATE_RECURSIVE(&rm->lock);
  rm->sctx = FS_SEARCH_makeContext(&rm->lock);
  rm->requestListIndex
    = 0;
  rm->requestListSize
    = 0;
  rm->requestList
    = NULL;
  GROW(rm->requestList,
       rm->requestListSize,
       256);
  rm->initialTTL
    = 5 * cronSECONDS;
  /* RFC 2001 suggests to use 1 segment size initially;
     Given 1500 octets per message in GNUnet, we would
     have 2-3 queries of maximum size (552); but since
     we are multi-casting to many peers at the same
     time AND since queries can be much smaller,
     we do WHAT??? */
  rm->congestionWindow
    = 1; /* RSS is 1 */
  rm->ssthresh
    = 65535;
#ifdef DEBUG_DOWNLOAD
  LOG(LOG_DEBUG,
      "created request manager %p\n",
      rm);
#endif
  return rm;
}

/**
 * Destroy the resources associated with a request manager.
 * Invoke this method to abort the download or to clean up
 * after the download is complete.
 *
 * @param rm the request manager struct from createRequestManager
 */
static void destroyRequestManager(RequestManager * rm) {
  int i;

#ifdef DEBUG_DOWNLOAD
  LOG(LOG_DEBUG,
      "destroying request manager %p\n",
      rm);
#endif
  MUTEX_LOCK(&rm->lock);
  for (i=0;i<rm->requestListIndex;i++) {
    if (rm->requestList[i]->searchHandle != NULL)
      FS_stop_search(rm->sctx,
		     rm->requestList[i]->searchHandle);
    FREE(rm->requestList[i]->node);
    FREE(rm->requestList[i]);
  }
  GROW(rm->requestList,
       rm->requestListSize,
       0);
  MUTEX_UNLOCK(&rm->lock);
  FS_SEARCH_destroyContext(rm->sctx);
  MUTEX_DESTROY(&rm->lock);
  PTHREAD_REL_SELF(&rm->requestThread);
  FREE(rm);
}

/**
 * We are approaching the end of the download.  Cut
 * all TTLs in half.
 */
static void requestManagerEndgame(RequestManager * rm) {
  int i;

  MUTEX_LOCK(&rm->lock);
  for (i=0;i<rm->requestListIndex;i++) {
    RequestEntry * entry = rm->requestList[i];
    /* cut TTL in half */
    entry->lasttime
      += (entry->lasttime + entry->lastTimeout) / 2;
  }
  MUTEX_UNLOCK(&rm->lock);
}

/**
 * Queue a request for execution.
 *
 * @param rm the request manager struct from createRequestManager
 * @param node the node to call once a reply is received
 */
static void addRequest(RequestManager * rm,
		       NodeClosure * node) {
  RequestEntry * entry;
#if DEBUG_DOWNLOAD
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&node->chk.query,
		 &enc));
  LOG(LOG_DEBUG,
      "Queuing request (query: %s)\n",
      &enc);
#endif

  GNUNET_ASSERT(node != NULL);
  entry
    = MALLOC(sizeof(RequestEntry));
  entry->node
    = node;
  entry->lasttime
    = 0; /* never sent */
  entry->lastTimeout
    = 0;
  entry->tries
    = 0; /* not tried so far */
  entry->lastPriority
    = 0;
  entry->searchHandle
    = NULL;
  MUTEX_LOCK(&rm->lock);
  GNUNET_ASSERT(rm->requestListSize > 0);
  if (rm->requestListSize == rm->requestListIndex)
    GROW(rm->requestList,
	 rm->requestListSize,
	 rm->requestListSize*2);
  rm->requestList[rm->requestListIndex++] = entry;
  MUTEX_UNLOCK(&rm->lock);
}


/**
 * Cancel a request.
 *
 * @param this the request manager struct from createRequestManager
 * @param node the block for which the request is canceled
 */
static void delRequest(RequestManager * rm,
		       NodeClosure * node) {
  int i;
  RequestEntry * re;

  MUTEX_LOCK(&rm->lock);
  for (i=0;i<rm->requestListIndex;i++) {
    re = rm->requestList[i];
    if (re->node == node) {
      rm->requestList[i]
	= rm->requestList[--rm->requestListIndex];
      rm->requestList[rm->requestListIndex]
	= NULL;
      MUTEX_UNLOCK(&rm->lock);
      if (NULL != re->searchHandle)
	FS_stop_search(rm->sctx,
		       re->searchHandle);
      FREE(re);
      return;
    }
  }
  MUTEX_UNLOCK(&rm->lock);
  BREAK(); /* uh uh - at least a memory leak... */
}


/* ****************** tree nodes ***************** */

/**
 * Data shared between all tree nodes.
 * Design Question: integrate with IOContext?
 */
typedef struct CommonCtx {
  RequestManager * rm;
  IOContext * ioc;
  unsigned long long total;
  unsigned long long completed;
  ECRS_DownloadProgressCallback dpcb;
  void * dpcbClosure;
  cron_t startTime;
  unsigned int anonymityLevel;
  cron_t TTL_DECREMENT;
} CommonCtx;

/**
 * Compute how many bytes of data are stored in
 * this node.
 */
static unsigned int getNodeSize(const NodeClosure * node) {
  unsigned int i;
  unsigned int ret;
  unsigned long long rsize;
  unsigned long long spos;
  unsigned long long epos;

  GNUNET_ASSERT(node->offset < node->ctx->total);
  if (node->level == 0) {
    ret = DBLOCK_SIZE;
    if (node->offset + (unsigned long long) ret
	> node->ctx->total)
      ret = (unsigned int) (node->ctx->total - node->offset);
#if 0
    PRINTF("Node at offset %llu and level %d has size %u\n",
	   node->offset,
	   node->level,
	   ret);
#endif
    return ret;
  }
  rsize = DBLOCK_SIZE;
  for (i=0;i<node->level-1;i++)
    rsize *= CHK_PER_INODE;
  spos = rsize * CHK_PER_INODE * (node->offset / sizeof(CHK));
  epos = spos + rsize * CHK_PER_INODE;
  if (epos > node->ctx->total)
    epos = node->ctx->total;
  ret = (epos - spos) / rsize;
  if (ret * rsize < epos - spos)
    ret++; /* need to round up! */
#if 0
  PRINTF("Node at offset %llu and level %d has size %u\n",
	 node->offset,
	 node->level,
	 ret * sizeof(CHK));
#endif
  return ret * sizeof(CHK);
}

/**
 * Update progress information. Also updates
 * request manager structures, like ttl.
 */
static void updateProgress(const NodeClosure * node,
			   const char * data,
			   unsigned int size) {
  RequestManager * rm;
  RequestEntry * entry;
  int pos;
  int i;

  /* locking? */
  if (node->level == 0) {
    cron_t eta;

    node->ctx->completed += size;
    cronTime(&eta); /* now */
    if (node->ctx->completed > 0) {
      eta = (cron_t) (node->ctx->startTime +
		      (((double)(eta - node->ctx->startTime)/(double)node->ctx->completed))
		      * (double)node->ctx->total);
    }
    if (node->ctx->dpcb != NULL) {
      node->ctx->dpcb(node->ctx->total,
		      node->ctx->completed,
		      eta,
		      node->offset,
		      data,
		      size,
		      node->ctx->dpcbClosure);
    }
  }
  rm = node->ctx->rm;

  /* check type of reply msg, fill in query */
  pos = -1;
  /* find which query matches the reply, call the callback
     and recycle the slot */
  for (i=0;i<rm->requestListIndex;i++)
    if (rm->requestList[i]->node == node)
      pos = i;
  if (pos == -1) {
    /* BREAK(); */ /* should never happen */
    return;
  }
  entry = rm->requestList[pos];

  if ( (entry->lasttime < cronTime(NULL)) &&
       (entry->lasttime != 0) ) {
    unsigned int weight = 15;
    unsigned int ettl = entry->lastTimeout - entry->lasttime;
    if ( (ettl > 4 * rm->initialTTL) &&
	 ( (cronTime(NULL) - entry->lasttime) < rm->initialTTL) ) {
      weight = 127;
      /* eTTL is MUCH bigger than what we currently expect AND the time
	 between the last query and the reply was in the range of the
	 expected TTL => don't take ettl too much into account! */
    }
    rm->initialTTL = ((rm->initialTTL) * weight + ettl) / (weight+1);

    /* RFC 2001: increase cwnd; note that we can't really discriminate between
       slow-start and cong. control mode since our RSS is too small... */
    if (rm->congestionWindow < rm->ssthresh)
      rm->congestionWindow += 2; /* slow start */
    else
      rm->congestionWindow += 1; /* slower start :-) */
  }
  if (entry->tries > 1) {
    TIME_T nowTT;

    TIME(&nowTT);
    if ( (nowTT - rm->initialTTL) > rm->lastDET) {
      /* only consider congestion control every
	 "average" TTL seconds, otherwise the system
	 reacts to events that are far too old! */
      /* we performed retransmission, treat as congestion (RFC 2001) */
      rm->ssthresh
	= rm->congestionWindow / 2;
      if (rm->ssthresh < 2)
	rm->ssthresh = 2;
      rm->congestionWindow
	= rm->ssthresh + 1;
      rm->lastDET = nowTT;
    }
  }
}


/**
 * Download children of this IBlock.
 *
 * @param rm the node that should downloaded
 */
static void iblock_download_children(NodeClosure * node,
				     char * data,
				     unsigned int size);

/**
 * Check if this block is already present on the drive.  If the block
 * is a dblock and present, the ProgressModel is notified. If the
 * block is present and it is an iblock, downloading the children is
 * triggered.
 *
 * @param node that is checked for presence
 * @return YES if present, NO if not.
 */
static int checkPresent(NodeClosure * node) {
  int res;
  char * data;
  unsigned int size;

  size = getNodeSize(node);
  data = MALLOC(size);
  res = readFromIOC(node->ctx->ioc,
		    node->level,
		    node->offset,
		    data,
		    size);
  if (res == size) {
    HashCode512 hc;

    hash(data,
	 size,
	 &hc);
    if (equalsHashCode512(&hc,
			  &node->chk.key)) {
      updateProgress(node, data, size);
      if (node->level > 0)
	iblock_download_children(node,
				 data,
				 size);

      FREE(data);
      return YES;
    }
  }
  FREE(data);
  return NO;
}

/**
 * Download children of this IBlock.
 *
 * @param this the node that should downloaded
 */
static void iblock_download_children(NodeClosure * node,
				     char * data,
				     unsigned int size) {
  int i;
  NodeClosure * child;
  unsigned int childcount;
  CHK * chks;
  unsigned int levelSize;
  unsigned long long baseOffset;

  GNUNET_ASSERT(node->level > 0);
  childcount = size / sizeof(CHK);
  if (size != childcount * sizeof(CHK)) {
    BREAK();
    return;
  }
  if (node->level == 1) {
    levelSize = DBLOCK_SIZE;
    baseOffset = node->offset / sizeof(CHK) * CHK_PER_INODE * DBLOCK_SIZE;
  } else {
    levelSize = sizeof(CHK);
    baseOffset = node->offset * CHK_PER_INODE;
  }
  chks = (CHK*) data;
  for (i=0;i<childcount;i++) {
    child = MALLOC(sizeof(NodeClosure));
    child->ctx = node->ctx;
    child->chk = chks[i];
    child->offset = baseOffset + i * levelSize;
    GNUNET_ASSERT(child->offset < node->ctx->total);
    child->level = node->level - 1;
    GNUNET_ASSERT( (child->level != 0) ||
		   ( (child->offset % DBLOCK_SIZE) == 0) );
    if (NO == checkPresent(child))
      addRequest(node->ctx->rm,
		 child);
    else
      FREE(child); /* done already! */
  }
}


/**
 * Decrypts a given data block
 *
 * @param data represents the data block
 * @param hashcode represents the key concatenated with the initial
 *        value used in the alg
 * @param result where to store the result (encrypted block)
 * @returns OK on success, SYSERR on error
 */
static int decryptContent(const char * data,
			  unsigned int size,
			  const HashCode512 * hashcode,
			  char * result){
  INITVECTOR iv;
  SESSIONKEY skey;

  GNUNET_ASSERT((data!=NULL) && (hashcode != NULL) && (result != NULL));
  /* get key and init value from the hash code */
  hashToKey(hashcode,
	    &skey,
	    &iv);
  return decryptBlock(&skey,
		      data,
		      size,
		      &iv,
		      result);
}


/**
 * We received a CHK reply for a block. Decrypt.
 *
 * @param node the node for which the reply is given, freed in
 *        this function!
 * @param query the query for which reply is the answer
 * @param reply the reply
 * @return OK if the reply was valid, SYSERR on error
 */
static int nodeReceive(const HashCode512 * query,
		       const Datastore_Value * reply,
		       NodeClosure * node) {
  HashCode512 hc;
  unsigned int size;
  int i;
  char * data;
#if DEBUG_DOWNLOAD
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(query,
		 &enc));
  LOG(LOG_DEBUG,
      "Receiving reply to query `%s'\n",
      &enc);
#endif

  GNUNET_ASSERT(equalsHashCode512(query,
				  &node->chk.query));
  size = ntohl(reply->size) - sizeof(Datastore_Value);
  if ( (size <= sizeof(DBlock)) ||
       (size - sizeof(DBlock) != getNodeSize(node)) ) {
    BREAK();
    return SYSERR; /* invalid size! */
  }
  size -= sizeof(DBlock);
  data = MALLOC(size);
  if (SYSERR == decryptContent((char*)&((DBlock*)&reply[1])[1],
			       size,
			       &node->chk.key,
			       data))
    GNUNET_ASSERT(0);
  hash(data,
       size,
       &hc);
  if (!equalsHashCode512(&hc,
			 &node->chk.key)) {
    delRequest(node->ctx->rm,
	       node);
    FREE(data);
    BREAK();
    LOG(LOG_ERROR,
	_("Decrypted content does not match key. "
	  "This is either a bug or a maliciously inserted "
	  "file. Download aborted.\n"));
    node->ctx->rm->abortFlag = YES;
    return SYSERR;
  }
  if (size != writeToIOC(node->ctx->ioc,
			 node->level,
			 node->offset,
			 data,
			 size)) {
    LOG_STRERROR(LOG_ERROR, "WRITE");
    node->ctx->rm->abortFlag = YES;
    return SYSERR;
  }
  updateProgress(node,
		 data,
		 size);
  if (node->level > 0)
    iblock_download_children(node,
			     data,
			     size);
  /* request satisfied, stop requesting! */
  delRequest(node->ctx->rm,
	     node);

  for (i=0;i<10;i++) {
    if ( (node->ctx->completed * 10000L >
	  node->ctx->total * (10000L - (1024 >> i)) ) &&
	 ( (node->ctx->completed-size) * 10000L <=
	   node->ctx->total * (10000L - (1024 >> i)) ) ) {
      /* end-game boundary crossed, slaughter TTLs */
      requestManagerEndgame(node->ctx->rm);
    }
  }
  PTHREAD_KILL(&node->ctx->rm->requestThread,
	       SIGALRM);
  FREE(data);
  FREE(node);
  return OK;
}


/**
 * Send the request from the requestList[requestIndex] out onto
 * the network.
 *
 * @param this the RequestManager
 * @param requestIndex the index of the Request to issue
 */
static void issueRequest(RequestManager * rm,
			 int requestIndex) {
  static unsigned int lastmpriority;
  static cron_t lastmpritime;
  RequestEntry * entry;
  cron_t now;
  unsigned int priority;
  unsigned int mpriority;
  cron_t timeout;
  unsigned int ttl;
  int TTL_DECREMENT;
#if DEBUG_DOWNLOAD
  EncName enc;
#endif

  cronTime(&now);
  entry = rm->requestList[requestIndex];

  /* compute priority */
  if (lastmpritime + 10 * cronSECONDS < now) {
    /* only update avg. priority at most every
       10 seconds */
    GNUNET_TCP_SOCKET * sock;

    sock = getClientSocket();
    lastmpriority = FS_getAveragePriority(sock);
    lastmpritime = now;
    releaseClientSocket(sock);
  }
  mpriority = lastmpriority;
  priority
    = entry->lastPriority + weak_randomi(1 + entry->tries);
  if (priority > mpriority) {
    /* mpriority is (2 * (current average priority + 2)) and
       is used as the maximum priority that we use; if the
       calculated tpriority is above it, we reduce tpriority
       to random value between the average (mpriority/2) but
       bounded by mpriority */
    priority = 1 + mpriority / 2 + (weak_randomi(2+mpriority/2));
  }
  if (priority > 0x0FFFFFF)
    priority = weak_randomi(0xFFFFFF); /* bound! */

  /* compute TTL */

  TTL_DECREMENT
    = entry->node->ctx->TTL_DECREMENT;

  if (entry->lastTimeout + TTL_DECREMENT > now)
    BREAK();
  if (entry->lasttime == 0) {
    timeout = now + rm->initialTTL;
  } else {
    ttl = entry->lastTimeout - entry->lasttime;
    if (ttl > MAX_TTL) {
      ttl = MAX_TTL + weak_randomi(2*TTL_DECREMENT);
    } else if (ttl > rm->initialTTL) {
      /* switch to slow back-off */
      unsigned int rd;
      if (rm->initialTTL == 0)
	rd = ttl;
      else
	rd = ttl / rm->initialTTL;
      if (rd == 0)
	rd = 1; /* how? */
      rd = TTL_DECREMENT / rd;
      if (rd == 0)
	rd = 1;
      ttl += weak_randomi(50 * cronMILLIS + rd);
      /* rd == TTL_DECREMENT / (con->ttl / rm->initialTTL) + saveguards
	 50ms: minimum increment */
    } else {
      ttl += weak_randomi(ttl + 2 * TTL_DECREMENT); /* exponential backoff with random factor */
    }
    if (ttl > (priority+8)* TTL_DECREMENT)
      ttl = (priority+8) * TTL_DECREMENT; /* see adjustTTL in gap */
    timeout = now + ttl;
  }

#if DEBUG_DOWNLOAD
  IFLOG(LOG_DEBUG,
	hash2enc(&entry->node->chk.query,
		 &enc));
  LOG(LOG_DEBUG,
      "Starting FS search for %s\n",
      &enc);
#endif

  if (entry->searchHandle != NULL)
    FS_stop_search(rm->sctx,
		   entry->searchHandle);
  entry->searchHandle
    = FS_start_search(rm->sctx,
		      D_BLOCK,
		      1,
		      &entry->node->chk.query,
		      entry->node->ctx->anonymityLevel,
		      priority,
		      timeout,
		      (Datum_Iterator) &nodeReceive,
		      entry->node);
  if (entry->searchHandle != NULL) {
    entry->lastPriority = priority;
    entry->lastTimeout = timeout;
    entry->lasttime = now + 2 * TTL_DECREMENT;
    if (weak_randomi(1+entry->tries) > 1) {
      /* do linear (in tries) extra back-off (in addition to ttl)
	 to avoid repeatedly tie-ing with other peers; rm is somewhat
	 equivalent to what ethernet is doing, only that 'tries' is our
	 (rough) indicator for collisions.  For ethernet back-off, see:
	 http://www.industrialethernetuniversity.com/courses/101_4.htm
      */
      entry->lasttime += weak_randomi(TTL_DECREMENT * (1+entry->tries));
    }
    entry->tries++;
  }
  /* warn if number of attempts goes too high */
  if ( (0 == (entry->tries % MAX_TRIES)) &&
       (entry->tries > 0) )  {
    EncName enc;
    IFLOG(LOG_WARNING,
	  hash2enc(&entry->node->chk.key,
		   &enc));
    LOG(LOG_WARNING,
	_("Content `%s' seems to be not available on the network (tried %u times).\n"),
	&enc,
	entry->tries);
  }
}

/**
 * Cron job that re-issues requests. Should compute how long to sleep
 * (min ttl until next job is ready) and re-schedule itself
 * accordingly!
 */
static cron_t processRequests(RequestManager * rm) {
  cron_t minSleep;
  cron_t now;
  cron_t delta;
  int i;
  unsigned int pending;
  int * perm;
  unsigned int TTL_DECREMENT;

  MUTEX_LOCK(&rm->lock);
  if (rm->requestListIndex == 0) {
    MUTEX_UNLOCK(&rm->lock);
    return 0;
  }
  cronTime(&now);
  pending = 0;
  TTL_DECREMENT = 0;
  if (rm->requestListIndex > 0)
    TTL_DECREMENT = rm->requestList[0]->node->ctx->TTL_DECREMENT;

  for (i=0;i<rm->requestListIndex;i++) {
    if (rm->requestList[i]->lastTimeout >= now - TTL_DECREMENT) {
      pending++;
    } else if (rm->requestList[i]->searchHandle != NULL) {
      FS_stop_search(rm->sctx,
		     rm->requestList[i]->searchHandle);
      rm->requestList[i]->searchHandle = NULL;
    }
  }

  minSleep = 5000 * cronMILLIS; /* max-sleep! */
  perm = permute(WEAK, rm->requestListIndex);
  for (i=0;i<rm->requestListIndex;i++) {
    int j = perm[i];
    if (rm->requestList[j]->lastTimeout + TTL_DECREMENT < now) {
      int pOCWCubed;
      int pendingOverCWin = pending - rm->congestionWindow;
      if (pendingOverCWin <= 0)
	pendingOverCWin = -1; /* avoid 0! */
      pOCWCubed = pendingOverCWin *
	pendingOverCWin *
	pendingOverCWin;
      if ( (pOCWCubed <= 0) ||
	   (pOCWCubed * rm->requestListIndex <= 0) /* see #642 */ ||
	   /* avoid no-start: override congestionWindow occasionally... */
	   (0 == weak_randomi(rm->requestListIndex *
			      pOCWCubed)) ) {
	issueRequest(rm, j);
	delta = (rm->requestList[j]->lastTimeout - now) + TTL_DECREMENT;
	pending++;
      } else {	
	delta = 0;
      }
    } else {
      delta = (rm->requestList[j]->lastTimeout + TTL_DECREMENT - now);
    }
    if (delta < minSleep )
      minSleep = delta;
  }
  FREE(perm);
  if (minSleep < cronMILLIS * 100)
    minSleep = cronMILLIS * 100; /* maximum resolution: 100ms */
  MUTEX_UNLOCK(&rm->lock);
  return minSleep;
}



/* ***************** main method **************** */

/**
 * Download a file.
 *
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file
 */
int ECRS_downloadFile(const struct ECRS_URI * uri,
		      const char * filename,
		      unsigned int anonymityLevel,
		      ECRS_DownloadProgressCallback dpcb,
		      void * dpcbClosure,
		      ECRS_TestTerminate tt,
		      void * ttClosure) {
  IOContext ioc;
  RequestManager * rm;
  int ret;
  CommonCtx ctx;
  NodeClosure * top;
  FileIdentifier fid;
  cron_t minSleep;

#if DEBUG_DOWNLOAD
  LOG(LOG_DEBUG,
      "`%s' running for file `%s'\n",
      __FUNCTION__,
      filename);
#endif
  if (0 == ECRS_fileSize(uri)) {
    ret = fileopen(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR|S_IWUSR);
    if (ret == -1) {
      LOG_FILE_STRERROR(LOG_ERROR, "open", filename);
      return SYSERR;
    }
    CLOSE(ret);
    dpcb(0, 0, cronTime(NULL), 0, NULL, 0, dpcbClosure);
    return OK;
  }
  GNUNET_ASSERT(filename != NULL);
  fid = uri->data.chk;
  if (! ECRS_isFileUri(uri)) {
    BREAK();
    return SYSERR;
  }

  if (OK != createIOContext(&ioc,
			    ntohll(fid.file_length),
			    filename)) {
#if DEBUG_DOWNLOAD
    LOG(LOG_DEBUG,
	"`%s' aborted for file `%s'\n",
	__FUNCTION__,
	filename);
#endif
    return SYSERR;
  }
  rm = createRequestManager();

  cronTime(&ctx.startTime);
  ctx.anonymityLevel = anonymityLevel;
  ctx.TTL_DECREMENT = 5 * cronSECONDS; /* HACK! */
  ctx.rm = rm;
  ctx.ioc = &ioc;
  ctx.dpcb = dpcb;
  ctx.dpcbClosure = dpcbClosure;
  ctx.total = ntohll(fid.file_length);
  ctx.completed = 0;
  top = MALLOC(sizeof(NodeClosure));
  top->ctx = &ctx;
  top->chk = fid.chk;
  top->offset = 0;
  top->level = computeDepth(ctx.total);
  addRequest(rm, top);
  while ( (OK == tt(ttClosure)) &&
	  (rm->abortFlag == NO) &&
	  (rm->requestListIndex != 0) ) {
    minSleep = processRequests(rm);
    if ( (OK == tt(ttClosure)) &&
	  (rm->abortFlag == NO) &&
	  (rm->requestListIndex != 0) ) 
      gnunet_util_sleep(minSleep);
  }
  
  if ( (rm->requestListIndex == 0) &&
       (ctx.completed == ctx.total) &&
       (rm->abortFlag == NO) ) {
    ret = OK;
  } else {
#if 0
    LOG(LOG_ERROR,
	"Download ends prematurely: %d %llu == %llu %d TT: %d\n",
	rm->requestListIndex,
	ctx.completed,
	ctx.total,
	rm->abortFlag,
	tt(ttClosure));
#endif
    ret = SYSERR;
  }
  destroyRequestManager(rm);
  if (ret == OK)
    freeIOC(&ioc, YES);
  else
    freeIOC(&ioc, NO); /* aborted */
#if DEBUG_DOWNLOAD
  LOG(LOG_DEBUG,
      "`%s' terminating for file `%s' with result %s\n",
      __FUNCTION__,
      filename,
      ret == OK ? "SUCCESS" : "INCOMPLETE");
#endif
  return ret;
}

/* end of download.c */
