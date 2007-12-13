/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @brief GNUNET_ND_DOWNLOAD helper methods (which do the real work).
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_ecrs_lib.h"
#include "gnunet_fs_lib.h"
#include "gnunet_identity_lib.h"
#include "ecrs_core.h"
#include "ecrs.h"
#include "tree.h"

#define DEBUG_DOWNLOAD GNUNET_NO

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
typedef struct IOContext
{

  struct GNUNET_GE_Context *ectx;

  /**
   * A lock for synchronizing access.
   */
  struct GNUNET_Mutex *lock;

  /**
   * The file handles for each level in the tree.
   */
  int *handles;

  /**
   * The base-filename
   */
  char *filename;

  /**
   * The depth of the file-tree.
   */
  unsigned int treedepth;

} IOContext;

/**
 * Close the files in the IOContext and free
 * the associated resources. Does NOT free
 * the memory occupied by the IOContext struct
 * itself.
 *
 * @param this reference to the IOContext
 * @param unlinkTreeFiles if GNUNET_YES, the non-level 0 files
 *     are unlinked (removed), set to GNUNET_NO if the download
 *     is not complete and may be resumed later.
 */
static void
freeIOC (IOContext * this, int unlinkTreeFiles)
{
  int i;
  char *fn;

  for (i = 0; i <= this->treedepth; i++)
    {
      if (this->handles[i] != -1)
        {
          CLOSE (this->handles[i]);
          this->handles[i] = -1;
        }
    }
  GNUNET_mutex_destroy (this->lock);
  if (GNUNET_YES == unlinkTreeFiles)
    {
      for (i = 1; i <= this->treedepth; i++)
        {
          fn = GNUNET_malloc (strlen (this->filename) + 3);
          strcpy (fn, this->filename);
          strcat (fn, ".A");
          fn[strlen (fn) - 1] += i;
          if (0 != UNLINK (fn))
            GNUNET_GE_LOG (this->ectx,
                           GNUNET_GE_WARNING | GNUNET_GE_BULK |
                           GNUNET_GE_USER,
                           _("Could not unlink temporary file `%s': %s\n"),
                           fn, STRERROR (errno));
          GNUNET_free (fn);
        }
    }
  GNUNET_free (this->filename);
  GNUNET_free (this->handles);
}

/**
 * Initialize an IOContext.
 *
 * @param this the context to initialize
 * @param no_temporaries disallow creation of temp files
 * @param filesize the size of the file
 * @param filename the name of the level-0 file
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
createIOContext (struct GNUNET_GE_Context *ectx,
                 IOContext * this,
                 int no_temporaries,
                 unsigned long long filesize, const char *filename)
{
  int i;
  char *fn;
  struct stat st;

  this->ectx = ectx;
  GNUNET_GE_ASSERT (ectx, filename != NULL);
  this->treedepth = GNUNET_ECRS_compute_depth (filesize);
  this->lock = GNUNET_mutex_create (GNUNET_NO);
  this->handles = GNUNET_malloc (sizeof (int) * (this->treedepth + 1));
  this->filename = GNUNET_strdup (filename);

  if ((0 == STAT (filename, &st)) && ((size_t) st.st_size > filesize))
    {
      /* if exists and oversized, truncate */
      if (truncate (filename, filesize) != 0)
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                       GNUNET_GE_BULK, "truncate", filename);
          return GNUNET_SYSERR;
        }
    }
  for (i = 0; i <= this->treedepth; i++)
    this->handles[i] = -1;

  for (i = 0; i <= this->treedepth; i++)
    {
      if ((i == 0) || (no_temporaries != GNUNET_YES))
        {
          fn = GNUNET_malloc (strlen (filename) + 3);
          strcpy (fn, filename);
          if (i > 0)
            {
              strcat (fn, ".A");
              fn[strlen (fn) - 1] += i;
            }
          this->handles[i] = GNUNET_disk_file_open (ectx,
                                                    fn,
                                                    O_CREAT | O_RDWR,
                                                    S_IRUSR | S_IWUSR);
          if (this->handles[i] < 0)
            {
              freeIOC (this, GNUNET_YES);
              GNUNET_free (fn);
              return GNUNET_SYSERR;
            }
          GNUNET_free (fn);
        }
    }
  return GNUNET_OK;
}

/**
 * Read method.
 *
 * @param this reference to the IOContext
 * @param level level in the tree to read/write at
 * @param pos position where to read or write
 * @param buf where to read from or write to
 * @param len how many bytes to read or write
 * @return number of bytes read, GNUNET_SYSERR on error
 */
static int
readFromIOC (IOContext * this,
             unsigned int level,
             unsigned long long pos, void *buf, unsigned int len)
{
  int ret;

  GNUNET_mutex_lock (this->lock);
  if (this->handles[level] == -1)
    {
      GNUNET_mutex_unlock (this->lock);
      return GNUNET_SYSERR;
    }
  LSEEK (this->handles[level], pos, SEEK_SET);
  ret = READ (this->handles[level], buf, len);
  GNUNET_mutex_unlock (this->lock);
#if DEBUG_DOWNLOAD
  GNUNET_GE_LOG (this->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "IOC read at level %u offset %llu wanted %u got %d\n",
                 level, pos, len, ret);
#endif
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
 * @return number of bytes written, GNUNET_SYSERR on error
 */
static int
writeToIOC (IOContext * this,
            unsigned int level,
            unsigned long long pos, void *buf, unsigned int len)
{
  int ret;

  GNUNET_mutex_lock (this->lock);
  if ((this->handles[level] == -1) && (level > 0))
    {
      GNUNET_mutex_unlock (this->lock);
      return len;               /* lie -- no temps allowed... */
    }
  LSEEK (this->handles[level], pos, SEEK_SET);
  ret = WRITE (this->handles[level], buf, len);
  if (ret != len)
    {
      GNUNET_GE_LOG (this->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Write(%d, %p, %d) failed: %s\n"),
                     this->handles[level], buf, len, STRERROR (errno));
    }
  GNUNET_mutex_unlock (this->lock);
#if DEBUG_DOWNLOAD
  GNUNET_GE_LOG (this->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "IOC write at level %u offset %llu writes %u\n", level, pos,
                 len);
#endif
  return ret;
}

/* ********************* request manager **************** */

/**
 * Node-specific data (not shared, keep small!). 56 bytes.
 */
typedef struct
{
  /**
   * Pointer to shared data between all nodes (request manager,
   * progress data, etc.).
   */
  struct CommonCtx *ctx;

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
typedef struct RequestEntry
{

  /**
   * The node for which this entry keeps data.
   */
  NodeClosure *node;

  /**
   * Search handle of the last request (NULL if never
   * requested).
   */
  struct GNUNET_FS_SearchHandle *searchHandle;

  /**
   * Last time the query was send.
   */
  GNUNET_CronTime lasttime;

  /**
   * Timeout used for the last search (ttl in request is
   * = lastTimeout - lasttime modulo corrections in gap
   * with respect to priority cap).
   */
  GNUNET_CronTime lastTimeout;

  /**
   * How long have we been actively trying this one?
   */
  unsigned int tries;

  /**
   * Priority used for the last request.
   */
  unsigned int lastPriority;

} RequestEntry;

/**
 * @brief structure that keeps track of currently pending requests for
 *        a download
 *
 * Handle to the state of a request manager.  Here we keep track of
 * which queries went out with which priorities and which nodes in
 * the merkle-tree are waiting for the replies.
 */
typedef struct RequestManager
{

  /**
   * Mutex for synchronizing access to this struct
   */
  struct GNUNET_Mutex *lock;

  /**
   * Current list of all pending requests
   */
  RequestEntry **requestList;

  struct GNUNET_FS_SearchContext *sctx;

  struct GNUNET_ThreadHandle *requestThread;

  struct GNUNET_GE_Context *ectx;

  struct GNUNET_GC_Configuration *cfg;

  GNUNET_PeerIdentity target;

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
  GNUNET_Int32Time lastDET;

  /**
   * Abort?  Flag that can be set at any time
   * to abort the RM as soon as possible.
   */
  int abortFlag;

  /**
   * Is the request manager being destroyed?
   * (if so, accessing the request list is illegal!)
   */
  int shutdown;

  /**
   * Do we have a specific peer from which we download
   * from?
   */
  int have_target;

} RequestManager;

/**
 * Create a request manager.  Will create the request manager
 * datastructures. Use destroyRequestManager to abort and/or to free
 * resources after the download is complete.
 *
 * @return NULL on error
 */
static RequestManager *
createRequestManager (struct GNUNET_GE_Context *ectx,
                      struct GNUNET_GC_Configuration *cfg)
{
  RequestManager *rm;

  rm = GNUNET_malloc (sizeof (RequestManager));
  rm->shutdown = GNUNET_NO;
  rm->lock = GNUNET_mutex_create (GNUNET_YES);
  rm->sctx = GNUNET_FS_create_search_context (ectx, cfg, rm->lock);
  if (rm->sctx == NULL)
    {
      GNUNET_mutex_destroy (rm->lock);
      GNUNET_free (rm);
      return NULL;
    }
  rm->ectx = ectx;
  rm->cfg = cfg;
  rm->requestThread = GNUNET_thread_get_self ();
  rm->abortFlag = GNUNET_NO;
  rm->lastDET = 0;
  rm->requestListIndex = 0;
  rm->requestListSize = 0;
  rm->requestList = NULL;
  rm->have_target = GNUNET_NO;
  GNUNET_array_grow (rm->requestList, rm->requestListSize, 256);
  rm->initialTTL = 5 * GNUNET_CRON_SECONDS;
  /* RFC 2001 suggests to use 1 segment size initially;
     Given 1500 octets per message in GNUnet, we would
     have 2-3 queries of maximum size (552); but since
     we are multi-casting to many peers at the same
     time AND since queries can be much smaller,
     we do WHAT??? */
  rm->congestionWindow = 1;     /* RSS is 1 */
  rm->ssthresh = 65535;
#if DEBUG_DOWNLOAD
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "created request manager %p\n", rm);
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
static void
destroyRequestManager (RequestManager * rm)
{
  int i;

#if DEBUG_DOWNLOAD
  GNUNET_GE_LOG (rm->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "destroying request manager %p\n", rm);
#endif
  GNUNET_mutex_lock (rm->lock);
  /* cannot hold lock during shutdown since
     fslib may have to aquire it; but we can
     flag that we are in the shutdown process
     and start to ignore fslib events! */
  rm->shutdown = GNUNET_YES;
  GNUNET_mutex_unlock (rm->lock);
  for (i = 0; i < rm->requestListIndex; i++)
    {
      if (rm->requestList[i]->searchHandle != NULL)
        GNUNET_FS_stop_search (rm->sctx, rm->requestList[i]->searchHandle);
      GNUNET_free (rm->requestList[i]->node);
      GNUNET_free (rm->requestList[i]);
    }
  GNUNET_array_grow (rm->requestList, rm->requestListSize, 0);
  GNUNET_FS_destroy_search_context (rm->sctx);
  rm->sctx = NULL;
  GNUNET_mutex_destroy (rm->lock);
  GNUNET_thread_release_self (rm->requestThread);
  GNUNET_free (rm);
}

/**
 * We are approaching the end of the download.  Cut
 * all TTLs in half.
 */
static void
requestManagerEndgame (RequestManager * rm)
{
  int i;

  GNUNET_mutex_lock (rm->lock);
  if (rm->shutdown == GNUNET_NO)
    {
      for (i = 0; i < rm->requestListIndex; i++)
        {
          RequestEntry *entry = rm->requestList[i];
          /* cut TTL in half */
          entry->lasttime += (entry->lasttime + entry->lastTimeout) / 2;
        }
    }
  GNUNET_mutex_unlock (rm->lock);
}

/**
 * Queue a request for execution.
 *
 * @param rm the request manager struct from createRequestManager
 * @param node the node to call once a reply is received
 */
static void
addRequest (RequestManager * rm, NodeClosure * node)
{
  RequestEntry *entry;
#if DEBUG_DOWNLOAD
  GNUNET_EncName enc;

  IF_GELOG (rm->ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&node->chk.query, &enc));
  GNUNET_GE_LOG (rm->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Queuing request (query: %s)\n", &enc);
#endif

  GNUNET_GE_ASSERT (rm->ectx, node != NULL);
  entry = GNUNET_malloc (sizeof (RequestEntry));
  entry->node = node;
  entry->lasttime = 0;          /* never sent */
  entry->lastTimeout = 0;
  entry->tries = 0;             /* not tried so far */
  entry->lastPriority = 0;
  entry->searchHandle = NULL;
  GNUNET_mutex_lock (rm->lock);
  if (rm->shutdown == GNUNET_NO)
    {
      GNUNET_GE_ASSERT (rm->ectx, rm->requestListSize > 0);
      if (rm->requestListSize == rm->requestListIndex)
        GNUNET_array_grow (rm->requestList, rm->requestListSize,
                           rm->requestListSize * 2);
      rm->requestList[rm->requestListIndex++] = entry;
    }
  else
    {
      GNUNET_GE_BREAK (rm->ectx, 0);
      GNUNET_free (entry);
    }
  GNUNET_mutex_unlock (rm->lock);
}


/**
 * Cancel a request.
 *
 * @param this the request manager struct from createRequestManager
 * @param node the block for which the request is canceled
 */
static void
delRequest (RequestManager * rm, NodeClosure * node)
{
  int i;
  RequestEntry *re;

  GNUNET_mutex_lock (rm->lock);
  if (rm->shutdown == GNUNET_NO)
    {
      for (i = 0; i < rm->requestListIndex; i++)
        {
          re = rm->requestList[i];
          if (re->node == node)
            {
              rm->requestList[i] = rm->requestList[--rm->requestListIndex];
              rm->requestList[rm->requestListIndex] = NULL;
              GNUNET_mutex_unlock (rm->lock);
              if (NULL != re->searchHandle)
                GNUNET_FS_stop_search (rm->sctx, re->searchHandle);
              GNUNET_free (re);
              return;
            }
        }
    }
  GNUNET_mutex_unlock (rm->lock);
  GNUNET_GE_BREAK (rm->ectx, 0);        /* uh uh - at least a memory leak... */
}


/* ****************** tree nodes ***************** */

/**
 * Data shared between all tree nodes.
 * Design Question: integrate with IOContext?
 */
typedef struct CommonCtx
{
  unsigned long long total;
  unsigned long long completed;
  unsigned long long offset;
  unsigned long long length;
  GNUNET_CronTime startTime;
  GNUNET_CronTime TTL_DECREMENT;
  RequestManager *rm;
  IOContext *ioc;
  GNUNET_ECRS_DownloadProgressCallback dpcb;
  void *dpcbClosure;
  unsigned int anonymityLevel;
} CommonCtx;

/**
 * Compute how many bytes of data are stored in
 * this node.
 */
static unsigned int
getNodeSize (const NodeClosure * node)
{
  unsigned int i;
  unsigned int ret;
  unsigned long long rsize;
  unsigned long long spos;
  unsigned long long epos;

  GNUNET_GE_ASSERT (node->ctx->rm->ectx, node->offset < node->ctx->total);
  if (node->level == 0)
    {
      ret = DBLOCK_SIZE;
      if (node->offset + (unsigned long long) ret > node->ctx->total)
        ret = (unsigned int) (node->ctx->total - node->offset);
#if DEBUG_DOWNLOAD
      GNUNET_GE_LOG (node->ctx->rm->ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "Node at offset %llu and level %d has size %u\n",
                     node->offset, node->level, ret);
#endif
      return ret;
    }
  rsize = DBLOCK_SIZE;
  for (i = 0; i < node->level - 1; i++)
    rsize *= CHK_PER_INODE;
  spos = rsize * (node->offset / sizeof (CHK));
  epos = spos + rsize * CHK_PER_INODE;
  if (epos > node->ctx->total)
    epos = node->ctx->total;
  ret = (epos - spos) / rsize;
  if (ret * rsize < epos - spos)
    ret++;                      /* need to round up! */
#if DEBUG_DOWNLOAD
  GNUNET_GE_LOG (node->ctx->rm->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Node at offset %llu and level %d has size %u\n",
                 node->offset, node->level, ret * sizeof (CHK));
#endif
  return ret * sizeof (CHK);
}

/**
 * Update progress information. Also updates
 * request manager structures, like ttl.
 */
static void
updateProgress (const NodeClosure * node, const char *data, unsigned int size)
{
  RequestManager *rm;
  RequestEntry *entry;
  int pos;
  int i;

  /* locking? */
  if (node->level == 0)
    {
      GNUNET_CronTime eta;

      node->ctx->completed += size;
      eta = GNUNET_get_time ();
      if (node->ctx->completed > 0)
        {
          eta = (GNUNET_CronTime) (node->ctx->startTime +
                                   (((double) (eta - node->ctx->startTime) /
                                     (double) node->ctx->completed)) *
                                   (double) node->ctx->length);
        }
      if (node->ctx->dpcb != NULL)
        {
          node->ctx->dpcb (node->ctx->length,
                           node->ctx->completed,
                           eta,
                           node->offset, data, size, node->ctx->dpcbClosure);
        }
    }
  rm = node->ctx->rm;
  GNUNET_mutex_lock (rm->lock);
  if (rm->shutdown == GNUNET_YES)
    {
      GNUNET_mutex_unlock (rm->lock);
      return;
    }

  /* check type of reply msg, fill in query */
  pos = -1;
  /* find which query matches the reply, call the callback
     and recycle the slot */
  for (i = 0; i < rm->requestListIndex; i++)
    if (rm->requestList[i]->node == node)
      pos = i;
  if (pos == -1)
    {
      /* GNUNET_GE_BREAK(ectx, 0); *//* should never happen */
      GNUNET_mutex_unlock (rm->lock);
      return;
    }
  entry = rm->requestList[pos];

  if ((entry->lasttime < GNUNET_get_time ()) && (entry->lasttime != 0))
    {
      unsigned int weight = 15;
      unsigned int ettl = entry->lastTimeout - entry->lasttime;
      if ((ettl > 4 * rm->initialTTL) &&
          ((GNUNET_get_time () - entry->lasttime) < rm->initialTTL))
        {
          weight = 127;
          /* eTTL is MUCH bigger than what we currently expect AND the time
             between the last query and the reply was in the range of the
             expected TTL => don't take ettl too much into account! */
        }
      rm->initialTTL = ((rm->initialTTL) * weight + ettl) / (weight + 1);

      /* RFC 2001: increase cwnd; note that we can't really discriminate between
         slow-start and cong. control mode since our RSS is too small... */
      if (rm->congestionWindow < rm->ssthresh)
        rm->congestionWindow += 2;      /* slow start */
      else
        rm->congestionWindow += 1;      /* slower start :-) */
    }
  if (entry->tries > 1)
    {
      GNUNET_Int32Time nowTT;

      GNUNET_get_time_int32 (&nowTT);
      if ((nowTT - rm->initialTTL) > rm->lastDET)
        {
          /* only consider congestion control every
             "average" TTL seconds, otherwise the system
             reacts to events that are far too old! */
          /* we performed retransmission, treat as congestion (RFC 2001) */
          rm->ssthresh = rm->congestionWindow / 2;
          if (rm->ssthresh < 2)
            rm->ssthresh = 2;
          rm->congestionWindow = rm->ssthresh + 1;
          rm->lastDET = nowTT;
        }
    }
  GNUNET_mutex_unlock (rm->lock);
}


/**
 * GNUNET_ND_DOWNLOAD children of this IBlock.
 *
 * @param rm the node that should downloaded
 */
static void iblock_download_children (NodeClosure * node,
                                      char *data, unsigned int size);

/**
 * Check if this block is already present on the drive.  If the block
 * is a dblock and present, the ProgressModel is notified. If the
 * block is present and it is an iblock, downloading the children is
 * triggered.
 *
 * Also checks if the block is within the range of blocks
 * that we are supposed to download.  If not, the method
 * returns as if the block is present but does NOT signal
 * progress.
 *
 * @param node that is checked for presence
 * @return GNUNET_YES if present, GNUNET_NO if not.
 */
static int
checkPresent (NodeClosure * node)
{
  int res;
  int ret;
  char *data;
  unsigned int size;
  GNUNET_HashCode hc;

  size = getNodeSize (node);

  /* first check if node is within range.
     For now, keeping it simple, we only do
     this for level-0 nodes */
  if ((node->level == 0) &&
      ((node->offset + size < node->ctx->offset) ||
       (node->offset >= node->ctx->offset + node->ctx->length)))
    return GNUNET_YES;

  data = GNUNET_malloc (size);
  res = readFromIOC (node->ctx->ioc, node->level, node->offset, data, size);
  if (res == size)
    {
      GNUNET_hash (data, size, &hc);
      if (0 == memcmp (&hc, &node->chk.key, sizeof (GNUNET_HashCode)))
        {
          updateProgress (node, data, size);
          if (node->level > 0)
            iblock_download_children (node, data, size);

          ret = GNUNET_YES;
        }
      else
        ret = GNUNET_NO;
    }
  else
    ret = GNUNET_NO;
  GNUNET_free (data);
#if DEBUG_DOWNLOAD
  GNUNET_GE_LOG (node->ctx->rm->ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Checked presence of block at %llu level %u.  Result: %s\n",
                 node->offset, node->level, ret == GNUNET_YES ? "YES" : "NO");
#endif

  return ret;
}

/**
 * GNUNET_ND_DOWNLOAD children of this IBlock.
 *
 * @param this the node that should downloaded
 */
static void
iblock_download_children (NodeClosure * node, char *data, unsigned int size)
{
  struct GNUNET_GE_Context *ectx = node->ctx->rm->ectx;
  int i;
  NodeClosure *child;
  unsigned int childcount;
  CHK *chks;
  unsigned int levelSize;
  unsigned long long baseOffset;

  GNUNET_GE_ASSERT (ectx, node->level > 0);
  childcount = size / sizeof (CHK);
  if (size != childcount * sizeof (CHK))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return;
    }
  if (node->level == 1)
    {
      levelSize = DBLOCK_SIZE;
      baseOffset = node->offset / sizeof (CHK) * DBLOCK_SIZE;
    }
  else
    {
      levelSize = sizeof (CHK) * CHK_PER_INODE;
      baseOffset = node->offset * CHK_PER_INODE;
    }
  chks = (CHK *) data;
  for (i = 0; i < childcount; i++)
    {
      child = GNUNET_malloc (sizeof (NodeClosure));
      child->ctx = node->ctx;
      child->chk = chks[i];
      child->offset = baseOffset + i * levelSize;
      GNUNET_GE_ASSERT (ectx, child->offset < node->ctx->total);
      child->level = node->level - 1;
      GNUNET_GE_ASSERT (ectx, (child->level != 0) ||
                        ((child->offset % DBLOCK_SIZE) == 0));
      if (GNUNET_NO == checkPresent (child))
        addRequest (node->ctx->rm, child);
      else
        GNUNET_free (child);    /* done already! */
    }
}


/**
 * Decrypts a given data block
 *
 * @param data represents the data block
 * @param hashcode represents the key concatenated with the initial
 *        value used in the alg
 * @param result where to store the result (encrypted block)
 * @returns GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
decryptContent (const char *data,
                unsigned int size, const GNUNET_HashCode * hashcode,
                char *result)
{
  GNUNET_AES_InitializationVector iv;
  GNUNET_AES_SessionKey skey;

  GNUNET_GE_ASSERT (NULL, (data != NULL) && (hashcode != NULL)
                    && (result != NULL));
  /* get key and init value from the GNUNET_hash code */
  GNUNET_hash_to_AES_key (hashcode, &skey, &iv);
  return GNUNET_AES_decrypt (&skey, data, size, &iv, result);
}


/**
 * We received a CHK reply for a block. Decrypt.  Note
 * that the caller (fslib) has already aquired the
 * RM lock (we sometimes aquire it again in callees,
 * mostly because our callees could be also be theoretically
 * called from elsewhere).
 *
 * @param node the node for which the reply is given, freed in
 *        this function!
 * @param query the query for which reply is the answer
 * @param reply the reply
 * @return GNUNET_OK if the reply was valid, GNUNET_SYSERR on error
 */
static int
nodeReceive (const GNUNET_HashCode * query,
             const GNUNET_DatastoreValue * reply, void *cls,
             unsigned long long uid)
{
  NodeClosure *node = cls;
  struct GNUNET_GE_Context *ectx = node->ctx->rm->ectx;
  GNUNET_HashCode hc;
  unsigned int size;
  int i;
  char *data;
#if DEBUG_DOWNLOAD
  GNUNET_EncName enc;

  IF_GELOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (query, &enc));
  GNUNET_GE_LOG (ectx, GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Receiving reply to query `%s'\n", &enc);
#endif
  GNUNET_GE_ASSERT (ectx,
                    0 == memcmp (query, &node->chk.query,
                                 sizeof (GNUNET_HashCode)));
  size = ntohl (reply->size) - sizeof (GNUNET_DatastoreValue);
  if ((size <= sizeof (DBlock)) ||
      (size - sizeof (DBlock) != getNodeSize (node)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return GNUNET_SYSERR;     /* invalid size! */
    }
  size -= sizeof (DBlock);
  data = GNUNET_malloc (size);
  if (GNUNET_SYSERR == decryptContent ((char *) &((DBlock *) & reply[1])[1],
                                       size, &node->chk.key, data))
    GNUNET_GE_ASSERT (ectx, 0);
  GNUNET_hash (data, size, &hc);
  if (0 != memcmp (&hc, &node->chk.key, sizeof (GNUNET_HashCode)))
    {
      delRequest (node->ctx->rm, node);
      GNUNET_free (data);
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_GE_LOG (ectx, GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Decrypted content does not match key. "
                       "This is either a bug or a maliciously inserted "
                       "file. Download aborted.\n"));
      node->ctx->rm->abortFlag = GNUNET_YES;
      return GNUNET_SYSERR;
    }
  if (size != writeToIOC (node->ctx->ioc,
                          node->level, node->offset, data, size))
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_USER | GNUNET_GE_BULK, "WRITE");
      node->ctx->rm->abortFlag = GNUNET_YES;
      return GNUNET_SYSERR;
    }
  updateProgress (node, data, size);
  if (node->level > 0)
    iblock_download_children (node, data, size);
  /* request satisfied, stop requesting! */
  delRequest (node->ctx->rm, node);

  for (i = 0; i < 10; i++)
    {
      if ((node->ctx->completed * 10000L >
           node->ctx->length * (10000L - (1024 >> i))) &&
          ((node->ctx->completed - size) * 10000L <=
           node->ctx->length * (10000L - (1024 >> i))))
        {
          /* end-game boundary crossed, slaughter TTLs */
          requestManagerEndgame (node->ctx->rm);
        }
    }
  GNUNET_GE_ASSERT (node->ctx->rm->ectx,
                    node->ctx->rm->requestThread != NULL);
  GNUNET_thread_stop_sleep (node->ctx->rm->requestThread);
  GNUNET_free (data);
  GNUNET_free (node);
  return GNUNET_OK;
}


/**
 * Send the request from the requestList[requestIndex] out onto
 * the network.
 *
 * @param this the RequestManager
 * @param requestIndex the index of the Request to issue
 */
static void
issueRequest (RequestManager * rm, int requestIndex)
{
  static unsigned int lastmpriority;
  static GNUNET_CronTime lastmpritime;
  RequestEntry *entry;
  GNUNET_CronTime now;
  unsigned int priority;
  unsigned int mpriority;
  GNUNET_CronTime timeout;
  unsigned int ttl;
  int TTL_DECREMENT;
#if DEBUG_DOWNLOAD
  GNUNET_EncName enc;
#endif

  now = GNUNET_get_time ();
  entry = rm->requestList[requestIndex];

  /* compute priority */
  if (lastmpritime + 10 * GNUNET_CRON_SECONDS < now)
    {
      /* only update avg. priority at most every
         10 seconds */
      struct GNUNET_ClientServerConnection *sock;

      sock = GNUNET_client_connection_create (rm->ectx, rm->cfg);
      lastmpriority = GNUNET_FS_get_current_average_priority (sock);
      lastmpritime = now;
      GNUNET_client_connection_destroy (sock);
    }
  mpriority = lastmpriority;
  priority =
    entry->lastPriority + GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                             1 + entry->tries);
  if (priority > mpriority)
    {
      /* mpriority is (2 * (current average priority + 2)) and
         is used as the maximum priority that we use; if the
         calculated tpriority is above it, we reduce tpriority
         to random value between the average (mpriority/2) but
         bounded by mpriority */
      priority =
        1 + mpriority / 2 +
        (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 2 + mpriority / 2));
    }
  if (priority > 0x0FFFFFF)
    priority = GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 0xFFFFFF);        /* bound! */

  /* compute TTL */

  TTL_DECREMENT = entry->node->ctx->TTL_DECREMENT;

  if (entry->lastTimeout + TTL_DECREMENT > now)
    GNUNET_GE_BREAK (rm->ectx, 0);
  if (entry->lasttime == 0)
    {
      timeout = now + rm->initialTTL;
    }
  else
    {
      ttl = entry->lastTimeout - entry->lasttime;
      if (ttl > MAX_TTL)
        {
          ttl =
            MAX_TTL + GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                         2 * TTL_DECREMENT);
        }
      else if (ttl > rm->initialTTL)
        {
          /* switch to slow back-off */
          unsigned int rd;
          if (rm->initialTTL == 0)
            rd = ttl;
          else
            rd = ttl / rm->initialTTL;
          if (rd == 0)
            rd = 1;             /* how? */
          rd = TTL_DECREMENT / rd;
          if (rd == 0)
            rd = 1;
          ttl +=
            GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                               50 * GNUNET_CRON_MILLISECONDS + rd);
          /* rd == TTL_DECREMENT / (con->ttl / rm->initialTTL) + saveguards
             50ms: minimum increment */
        }
      else
        {
          ttl += GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, ttl + 2 * TTL_DECREMENT);       /* exponential backoff with random factor */
        }
      if (ttl > (priority + 8) * TTL_DECREMENT)
        ttl = (priority + 8) * TTL_DECREMENT;   /* see adjustTTL in gap */
      timeout = now + ttl;
    }

#if DEBUG_DOWNLOAD
  IF_GELOG (ectx,
            GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
            GNUNET_hash_to_enc (&entry->node->chk.query, &enc));
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "Starting FS search for %s:%llu:%u `%s'\n",
                 entry->node->ctx->ioc->filename,
                 entry->node->offset, entry->node->level, &enc);
#endif

  if (entry->searchHandle != NULL)
    GNUNET_FS_stop_search (rm->sctx, entry->searchHandle);
  entry->searchHandle
    = GNUNET_FS_start_search (rm->sctx,
                              rm->have_target ==
                              GNUNET_NO ? NULL : &rm->target,
                              GNUNET_ECRS_BLOCKTYPE_DATA, 1,
                              &entry->node->chk.query,
                              entry->node->ctx->anonymityLevel, priority,
                              timeout, &nodeReceive, entry->node);
  if (entry->searchHandle != NULL)
    {
      entry->lastPriority = priority;
      entry->lastTimeout = timeout;
      entry->lasttime = now + 2 * TTL_DECREMENT;
      if (GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK, 1 + entry->tries) >
          1)
        {
          /* do linear (in tries) extra back-off (in addition to ttl)
             to avoid repeatedly tie-ing with other peers; rm is somewhat
             equivalent to what ethernet is doing, only that 'tries' is our
             (rough) indicator for collisions.  For ethernet back-off, see:
             http://www.industrialethernetuniversity.com/courses/101_4.htm
           */
          entry->lasttime +=
            GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                               TTL_DECREMENT * (1 + entry->tries));
        }
      entry->tries++;
    }
  /* warn if number of attempts goes too high */
  if ((0 == (entry->tries % MAX_TRIES)) && (entry->tries > 0))
    {
      GNUNET_EncName enc;
      IF_GELOG (rm->ectx,
                GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                GNUNET_hash_to_enc (&entry->node->chk.key, &enc));
      GNUNET_GE_LOG (rm->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _
                     ("Content `%s' seems to be not available on the network (tried %u times).\n"),
                     &enc, entry->tries);
    }
}

/**
 * Cron job that re-issues requests. Should compute how long to sleep
 * (min ttl until next job is ready) and re-schedule itself
 * accordingly!
 */
static GNUNET_CronTime
processRequests (RequestManager * rm)
{
  GNUNET_CronTime minSleep;
  GNUNET_CronTime now;
  GNUNET_CronTime delta;
  int i;
  unsigned int pending;
  unsigned int *perm;
  unsigned int TTL_DECREMENT;

  GNUNET_mutex_lock (rm->lock);
  if ((rm->shutdown == GNUNET_YES) || (rm->requestListIndex == 0))
    {
      GNUNET_mutex_unlock (rm->lock);
      return 0;
    }
  now = GNUNET_get_time ();
  pending = 0;
  TTL_DECREMENT = 0;
  if (rm->requestListIndex > 0)
    TTL_DECREMENT = rm->requestList[0]->node->ctx->TTL_DECREMENT;

  for (i = 0; i < rm->requestListIndex; i++)
    {
      if (rm->requestList[i]->lastTimeout >= now - TTL_DECREMENT)
        {
          pending++;
        }
      else if (rm->requestList[i]->searchHandle != NULL)
        {
          GNUNET_FS_stop_search (rm->sctx, rm->requestList[i]->searchHandle);
          rm->requestList[i]->searchHandle = NULL;
        }
    }

  minSleep = 5000 * GNUNET_CRON_MILLISECONDS;   /* max-sleep! */
  perm = GNUNET_permute (GNUNET_RANDOM_QUALITY_WEAK, rm->requestListIndex);
  for (i = 0; i < rm->requestListIndex; i++)
    {
      int j = perm[i];
      if (rm->requestList[j]->lastTimeout + TTL_DECREMENT < now)
        {
          int pOCWCubed;
          int pendingOverCWin = pending - rm->congestionWindow;
          if (pendingOverCWin <= 0)
            pendingOverCWin = -1;       /* avoid 0! */
          pOCWCubed = pendingOverCWin * pendingOverCWin * pendingOverCWin;
          if ((pOCWCubed <= 0) ||
              (pOCWCubed * rm->requestListIndex <= 0) /* see #642 */  ||
              /* avoid no-start: override congestionWindow occasionally... */
              (0 ==
               GNUNET_random_u32 (GNUNET_RANDOM_QUALITY_WEAK,
                                  rm->requestListIndex * pOCWCubed)))
            {
              issueRequest (rm, j);
              delta = (rm->requestList[j]->lastTimeout - now) + TTL_DECREMENT;
              pending++;
            }
          else
            {
              delta = 0;
            }
        }
      else
        {
          delta = (rm->requestList[j]->lastTimeout + TTL_DECREMENT - now);
        }
      if (delta < minSleep)
        minSleep = delta;
    }
  GNUNET_free (perm);
  if (minSleep < GNUNET_CRON_MILLISECONDS * 100)
    minSleep = GNUNET_CRON_MILLISECONDS * 100;  /* maximum resolution: 100ms */
  GNUNET_mutex_unlock (rm->lock);
  return minSleep;
}



/* ***************** main method **************** */

/**
 * GNUNET_ND_DOWNLOAD a file.
 *
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file
 */
int
GNUNET_ECRS_file_download (struct GNUNET_GE_Context *ectx,
                           struct GNUNET_GC_Configuration *cfg,
                           const struct GNUNET_ECRS_URI *uri,
                           const char *filename,
                           unsigned int anonymityLevel,
                           GNUNET_ECRS_DownloadProgressCallback dpcb,
                           void *dpcbClosure, GNUNET_ECRS_TestTerminate tt,
                           void *ttClosure)
{
  return GNUNET_ECRS_file_download_partial (ectx,
                                            cfg,
                                            uri,
                                            filename,
                                            0,
                                            GNUNET_ECRS_uri_get_file_size
                                            (uri), anonymityLevel, GNUNET_NO,
                                            dpcb, dpcbClosure, tt, ttClosure);
}


/**
 * GNUNET_ND_DOWNLOAD parts of a file.  Note that this will store
 * the blocks at the respective offset in the given file.
 * Also, the download is still using the blocking of the
 * underlying ECRS encoding.  As a result, the download
 * may *write* outside of the given boundaries (if offset
 * and length do not match the 32k ECRS block boundaries).
 * <p>
 *
 * This function should be used to focus a download towards a
 * particular portion of the file (optimization), not to strictly
 * limit the download to exactly those bytes.
 *
 * @param uri the URI of the file (determines what to download)
 * @param filename where to store the file
 * @param no_temporaries set to GNUNET_YES to disallow generation of temporary files
 * @param start starting offset
 * @param length length of the download (starting at offset)
 */
int
GNUNET_ECRS_file_download_partial (struct GNUNET_GE_Context *ectx,
                                   struct GNUNET_GC_Configuration *cfg,
                                   const struct GNUNET_ECRS_URI *uri,
                                   const char *filename,
                                   unsigned long long offset,
                                   unsigned long long length,
                                   unsigned int anonymityLevel,
                                   int no_temporaries,
                                   GNUNET_ECRS_DownloadProgressCallback dpcb,
                                   void *dpcbClosure,
                                   GNUNET_ECRS_TestTerminate tt,
                                   void *ttClosure)
{
  IOContext ioc;
  RequestManager *rm;
  int ret;
  CommonCtx ctx;
  NodeClosure *top;
  FileIdentifier fid;
  GNUNET_CronTime minSleep;
  char *realFN;
  char *path;
  char *pos;
  struct stat buf;

#if DEBUG_DOWNLOAD
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "`%s' running for file `%s'\n", __FUNCTION__, filename);
#endif
  GNUNET_GE_ASSERT (ectx, filename != NULL);
  if ((filename[strlen (filename) - 1] == '/') ||
      (filename[strlen (filename) - 1] == '\\'))
    {
      realFN =
        GNUNET_malloc (strlen (filename) + strlen (GNUNET_DIRECTORY_EXT));
      strcpy (realFN, filename);
      realFN[strlen (filename) - 1] = '\0';
      strcat (realFN, GNUNET_DIRECTORY_EXT);
    }
  else
    {
      realFN = GNUNET_strdup (filename);
    }
  path = GNUNET_malloc (strlen (realFN) * strlen (GNUNET_DIRECTORY_EXT) + 1);
  strcpy (path, realFN);
  pos = path;
  while (*pos != '\0')
    {
      if (*pos == DIR_SEPARATOR)
        {
          *pos = '\0';
          if ((0 == STAT (path, &buf)) && (!S_ISDIR (buf.st_mode)))
            {
              *pos = DIR_SEPARATOR;
              memmove (pos + strlen (GNUNET_DIRECTORY_EXT),
                       pos, strlen (pos));
              memcpy (pos,
                      GNUNET_DIRECTORY_EXT, strlen (GNUNET_DIRECTORY_EXT));
              pos += strlen (GNUNET_DIRECTORY_EXT);
            }
          else
            {
              *pos = DIR_SEPARATOR;
            }
        }
      pos++;
    }
  GNUNET_free (realFN);
  realFN = path;

  if (GNUNET_SYSERR == GNUNET_disk_directory_create_for_file (ectx, realFN))
    {
      GNUNET_free (realFN);
      return GNUNET_SYSERR;
    }
  if (0 == GNUNET_ECRS_uri_get_file_size (uri))
    {
      ret = GNUNET_disk_file_open (ectx,
                                   realFN,
                                   O_CREAT | O_WRONLY | O_TRUNC,
                                   S_IRUSR | S_IWUSR);
      GNUNET_free (realFN);
      if (ret == -1)
        return GNUNET_SYSERR;
      CLOSE (ret);
      dpcb (0, 0, GNUNET_get_time (), 0, NULL, 0, dpcbClosure);
      return GNUNET_OK;
    }
  fid = uri->data.fi;

  if ((!GNUNET_ECRS_uri_test_chk (uri)) && (!GNUNET_ECRS_uri_test_loc (uri)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_free (realFN);
      return GNUNET_SYSERR;
    }

  if (GNUNET_OK != createIOContext (ectx,
                                    &ioc,
                                    no_temporaries,
                                    GNUNET_ntohll (fid.file_length), realFN))
    {
#if DEBUG_DOWNLOAD
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                     "`%s' aborted for file `%s'\n", __FUNCTION__, realFN);
#endif
      GNUNET_free (realFN);
      return GNUNET_SYSERR;
    }
  rm = createRequestManager (ectx, cfg);
  if (rm == NULL)
    {
      freeIOC (&ioc, GNUNET_YES);
      GNUNET_free (realFN);
      return GNUNET_SYSERR;
    }
  if (GNUNET_ECRS_uri_test_loc (uri))
    {
      GNUNET_hash (&uri->data.loc.peer, sizeof (GNUNET_RSA_PublicKey),
                   &rm->target.hashPubKey);
      rm->have_target = GNUNET_YES;
    }

  ctx.startTime = GNUNET_get_time ();
  ctx.anonymityLevel = anonymityLevel;
  ctx.offset = offset;
  ctx.length = length;
  ctx.TTL_DECREMENT = 5 * GNUNET_CRON_SECONDS;  /* HACK! */
  ctx.rm = rm;
  ctx.ioc = &ioc;
  ctx.dpcb = dpcb;
  ctx.dpcbClosure = dpcbClosure;
  ctx.total = GNUNET_ntohll (fid.file_length);
  ctx.completed = 0;
  top = GNUNET_malloc (sizeof (NodeClosure));
  top->ctx = &ctx;
  top->chk = fid.chk;
  top->offset = 0;
  top->level = GNUNET_ECRS_compute_depth (ctx.total);
  if (GNUNET_NO == checkPresent (top))
    addRequest (rm, top);
  else
    GNUNET_free (top);
  while ((GNUNET_OK == tt (ttClosure)) &&
         (rm->abortFlag == GNUNET_NO) && (rm->requestListIndex != 0))
    {
      minSleep = processRequests (rm);
      if ((GNUNET_OK == tt (ttClosure)) &&
          (rm->abortFlag == GNUNET_NO) && (rm->requestListIndex != 0))
        GNUNET_thread_sleep (minSleep);
    }

  if ((rm->requestListIndex == 0) &&
      ((ctx.completed == ctx.total) ||
       ((ctx.total != ctx.length) &&
        (ctx.completed >= ctx.length))) && (rm->abortFlag == GNUNET_NO))
    {
      ret = GNUNET_OK;
    }
  else
    {
#if 0
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "Download ends prematurely: %d %llu == %llu %d TT: %d\n",
                     rm->requestListIndex,
                     ctx.completed, ctx.total, rm->abortFlag, tt (ttClosure));
#endif
      ret = GNUNET_SYSERR;
    }
  destroyRequestManager (rm);
  if (ret == GNUNET_OK)
    {
      freeIOC (&ioc, GNUNET_YES);
    }
  else if (tt (ttClosure) == GNUNET_SYSERR)
    {
      freeIOC (&ioc, GNUNET_YES);
      if (0 != UNLINK (realFN))
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_WARNING | GNUNET_GE_USER |
                                       GNUNET_GE_BULK, "unlink", realFN);
        }
      else
        {                       /* delete empty directories */
          char *rdir;
          int len;

          rdir = GNUNET_strdup (realFN);
          len = strlen (rdir);
          do
            {
              while ((len > 0) && (rdir[len] != DIR_SEPARATOR))
                len--;
              rdir[len] = '\0';
            }
          while ((len > 0) && (0 == rmdir (rdir)));
          GNUNET_free (rdir);
        }
    }
  else
    {
      freeIOC (&ioc, GNUNET_NO);        /* aborted */
    }
#if DEBUG_DOWNLOAD
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "`%s' terminating for file `%s' with result %s\n",
                 __FUNCTION__, filename,
                 ret == GNUNET_OK ? "SUCCESS" : "INCOMPLETE");
#endif
  GNUNET_free (realFN);
  return ret;
}

/* end of download.c */
