/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @brief DOWNLOAD helper methods (which do the real work).
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
 * Node-specific data (not shared, keep small!). 152 bytes.
 * Nodes are kept in a doubly-linked list.
 */
struct Node
{
  /**
   * Pointer to shared data between all nodes (request manager,
   * progress data, etc.).
   */
  struct GNUNET_ECRS_DownloadContext *ctx;

  /**
   * Previous entry in DLL.
   */
  struct Node *prev;

  /**
   * Next entry in DLL.
   */
  struct Node *next;

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

};

/**
 * @brief structure that keeps track of currently pending requests for
 *        a download
 *
 * Handle to the state of a request manager.  Here we keep track of
 * which queries went out with which priorities and which nodes in
 * the merkle-tree are waiting for the replies.
 */
struct GNUNET_ECRS_DownloadContext
{

  /**
   * Total number of bytes in the file.
   */
  unsigned long long total;

  /**
   * Number of bytes already obtained
   */
  unsigned long long completed;

  /**
   * Starting-offset in file (for partial download)
   */
  unsigned long long offset;

  /**
   * Length of the download (starting at offset).
   */
  unsigned long long length;

  /**
   * Time download was started.
   */
  GNUNET_CronTime startTime;

  /**
   * Mutex for synchronizing access to this struct
   */
  struct GNUNET_Mutex *lock;

  /**
   * Doubly linked list of all pending requests (head)
   */
  struct Node *head;

  /**
   * Doubly linked list of all pending requests (tail)
   */
  struct Node *tail;

  /**
   * FSLIB context for issuing requests.
   */
  struct GNUNET_FS_SearchContext *sctx;

  /**
   * Context for error reporting.
   */
  struct GNUNET_GE_Context *ectx;

  /**
   * Configuration information.
   */
  struct GNUNET_GC_Configuration *cfg;

  /**
   * The file handles for each level in the download-tree.
   */
  int *handles;

  /**
   * The base-filename
   */
  char *filename;

  /**
   * Main thread running the operation.
   */
  struct GNUNET_ThreadHandle *main;

  /**
   * Function to call when we make progress.
   */
  GNUNET_ECRS_DownloadProgressCallback dpcb;

  /**
   * Extra argument to dpcb.
   */
  void *dpcbClosure;

  /**
   * Identity of the peer having the content, or all-zeros
   * if we don't know of such a peer.
   */
  GNUNET_PeerIdentity target;

  /**
   * Abort?  Flag that can be set at any time
   * to abort the RM as soon as possible.
   */
  int abortFlag;

  /**
   * Do we have a specific peer from which we download
   * from?
   */
  int have_target;

  /**
   * Desired anonymity level for the download.
   */
  unsigned int anonymityLevel;

  /**
   * The depth of the file-tree.
   */
  unsigned int treedepth;

};


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
free_request_manager (struct GNUNET_ECRS_DownloadContext *rm,
                      int unlinkTreeFiles)
{
  int i;
  char *fn;
  struct Node *pos;

  GNUNET_mutex_lock (rm->lock);
  /* cannot hold lock during shutdown since
     fslib may have to aquire it; but we can
     flag that we are in the shutdown process
     and start to ignore fslib events! */
  rm->abortFlag = GNUNET_YES;
  GNUNET_mutex_unlock (rm->lock);
  GNUNET_FS_destroy_search_context (rm->sctx);
  rm->sctx = NULL;
  while (rm->head != NULL)
    {
      pos = rm->head;
      rm->head = pos->next;
      GNUNET_free (pos);
    }
  rm->tail = NULL;
  for (i = 0; i <= rm->treedepth; i++)
    {
      if (rm->handles[i] != -1)
        {
          CLOSE (rm->handles[i]);
          rm->handles[i] = -1;
        }
    }
  if (rm->lock != NULL)
    GNUNET_mutex_destroy (rm->lock);
  if (rm->main != NULL)
    GNUNET_thread_release_self (rm->main);
  if (GNUNET_YES == unlinkTreeFiles)
    {
      for (i = 1; i <= rm->treedepth; i++)
        {
          fn = GNUNET_malloc (strlen (rm->filename) + 3);
          strcpy (fn, rm->filename);
          strcat (fn, ".A");
          fn[strlen (fn) - 1] += i;
          if (0 != UNLINK (fn))
            GNUNET_GE_LOG (rm->ectx,
                           GNUNET_GE_WARNING | GNUNET_GE_BULK |
                           GNUNET_GE_USER,
                           _("Could not unlink temporary file `%s': %s\n"),
                           fn, STRERROR (errno));
          GNUNET_free (fn);
        }
    }
  GNUNET_free_non_null (rm->filename);
  GNUNET_free_non_null (rm->handles);
  GNUNET_free (rm);
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
read_from_files (struct GNUNET_ECRS_DownloadContext *this,
                 unsigned int level,
                 unsigned long long pos, void *buf, unsigned int len)
{
  int ret;

  if (this->handles[level] == -1)
    return GNUNET_SYSERR;
  LSEEK (this->handles[level], pos, SEEK_SET);
  ret = READ (this->handles[level], buf, len);
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
write_to_files (struct GNUNET_ECRS_DownloadContext *this,
                unsigned int level,
                unsigned long long pos, void *buf, unsigned int len)
{
  int ret;

  if ((this->handles[level] == -1) && (level > 0))
    return len;                 /* lie -- no temps allowed... */
  LSEEK (this->handles[level], pos, SEEK_SET);
  ret = WRITE (this->handles[level], buf, len);
  if (ret != len)
    {
      GNUNET_GE_LOG (this->ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Write(%d, %p, %d) failed: %s\n"),
                     this->handles[level], buf, len, STRERROR (errno));
    }
  return ret;
}

static int
content_receive_callback (const GNUNET_HashCode * query,
                          const GNUNET_DatastoreValue * reply, void *cls,
                          unsigned long long uid);

/**
 * Queue a request for execution.
 *
 * @param rm the request manager struct from createRequestManager
 * @param node the node to call once a reply is received
 */
static void
addRequest (struct Node *node)
{
  struct GNUNET_ECRS_DownloadContext *rm = node->ctx;

  node->next = rm->head;
  if (node->next != NULL)
    node->next->prev = node;
  node->prev = NULL;
  rm->head = node;
  if (rm->tail == NULL)
    rm->tail = node;
  GNUNET_FS_start_search (rm->sctx,
                          rm->have_target == GNUNET_NO ? NULL : &rm->target,
                          GNUNET_ECRS_BLOCKTYPE_DATA, 1,
                          &node->chk.query,
                          rm->anonymityLevel,
                          &content_receive_callback, node);
}

static void
signal_abort (struct GNUNET_ECRS_DownloadContext *rm, const char *msg)
{
  rm->abortFlag = GNUNET_YES;
  if ((rm->head != NULL) && (rm->dpcb != NULL))
    rm->dpcb (rm->length + 1, 0, 0, 0, msg, 0, rm->dpcbClosure);
  GNUNET_thread_stop_sleep (rm->main);
}

/**
 * Dequeue a request.
 *
 * @param this the request manager struct from createRequestManager
 * @param node the block for which the request is canceled
 */
static void
delete_node (struct Node *node)
{
  struct GNUNET_ECRS_DownloadContext *rm = node->ctx;

  if (node->prev == NULL)
    rm->head = node->next;
  else
    node->prev->next = node->next;
  if (node->next == NULL)
    rm->tail = node->prev;
  else
    node->next->prev = node->prev;
  GNUNET_free (node);
  if (rm->head == NULL)
    signal_abort (rm, NULL);
}

/**
 * Compute how many bytes of data are stored in
 * this node.
 */
static unsigned int
get_node_size (const struct Node *node)
{
  unsigned int i;
  unsigned int ret;
  unsigned long long rsize;
  unsigned long long spos;
  unsigned long long epos;

  GNUNET_GE_ASSERT (node->ctx->ectx, node->offset < node->ctx->total);
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
 * Notify client about progress.
 */
static void
notify_client_about_progress (const struct Node *node, const char *data,
                              unsigned int size)
{
  struct GNUNET_ECRS_DownloadContext *rm = node->ctx;
  GNUNET_CronTime eta;

  if ((rm->abortFlag == GNUNET_YES) || (node->level != 0))
    return;
  rm->completed += size;
  eta = GNUNET_get_time ();
  if (rm->completed > 0)
    eta = (GNUNET_CronTime) (rm->startTime +
                             (((double) (eta - rm->startTime) /
                               (double) rm->completed)) *
                             (double) rm->length);
  if (rm->dpcb != NULL)
    rm->dpcb (rm->length,
              rm->completed, eta, node->offset, data, size, rm->dpcbClosure);
}


/**
 * DOWNLOAD children of this IBlock.
 *
 * @param rm the node that should downloaded
 */
static void iblock_download_children (struct Node *node,
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
check_node_present (struct Node *node)
{
  int res;
  int ret;
  char *data;
  unsigned int size;
  GNUNET_HashCode hc;

  size = get_node_size (node);
  /* first check if node is within range.
     For now, keeping it simple, we only do
     this for level-0 nodes */
  if ((node->level == 0) &&
      ((node->offset + size < node->ctx->offset) ||
       (node->offset >= node->ctx->offset + node->ctx->length)))
    return GNUNET_YES;
  data = GNUNET_malloc (size);
  res = read_from_files (node->ctx, node->level, node->offset, data, size);
  if (res == size)
    {
      GNUNET_hash (data, size, &hc);
      if (0 == memcmp (&hc, &node->chk.key, sizeof (GNUNET_HashCode)))
        {
          notify_client_about_progress (node, data, size);
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
  return ret;
}

/**
 * DOWNLOAD children of this IBlock.
 *
 * @param this the node that should downloaded
 */
static void
iblock_download_children (struct Node *node, char *data, unsigned int size)
{
  struct GNUNET_GE_Context *ectx = node->ctx->ectx;
  int i;
  struct Node *child;
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
      child = GNUNET_malloc (sizeof (struct Node));
      child->ctx = node->ctx;
      child->chk = chks[i];
      child->offset = baseOffset + i * levelSize;
      GNUNET_GE_ASSERT (ectx, child->offset < node->ctx->total);
      child->level = node->level - 1;
      GNUNET_GE_ASSERT (ectx, (child->level != 0) ||
                        ((child->offset % DBLOCK_SIZE) == 0));
      if (GNUNET_NO == check_node_present (child))
        addRequest (child);
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
decrypt_content (const char *data,
                 unsigned int size, const GNUNET_HashCode * hashcode,
                 char *result)
{
  GNUNET_AES_InitializationVector iv;
  GNUNET_AES_SessionKey skey;

  /* get key and init value from the GNUNET_HashCode */
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
content_receive_callback (const GNUNET_HashCode * query,
                          const GNUNET_DatastoreValue * reply, void *cls,
                          unsigned long long uid)
{
  struct Node *node = cls;
  struct GNUNET_ECRS_DownloadContext *rm = node->ctx;
  struct GNUNET_GE_Context *ectx = rm->ectx;
  GNUNET_HashCode hc;
  unsigned int size;
  char *data;

  GNUNET_mutex_lock (rm->lock);
  if (rm->abortFlag != GNUNET_NO)
    {
      GNUNET_mutex_unlock (rm->lock);
      return GNUNET_SYSERR;
    }
  GNUNET_GE_ASSERT (ectx,
                    0 == memcmp (query, &node->chk.query,
                                 sizeof (GNUNET_HashCode)));
  size = ntohl (reply->size) - sizeof (GNUNET_DatastoreValue);
  if ((size <= sizeof (DBlock)) ||
      (size - sizeof (DBlock) != get_node_size (node)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      GNUNET_mutex_unlock (rm->lock);
      return GNUNET_SYSERR;     /* invalid size! */
    }
  size -= sizeof (DBlock);
  data = GNUNET_malloc (size);
  if (GNUNET_SYSERR == decrypt_content ((char *) &((DBlock *) & reply[1])[1],
                                        size, &node->chk.key, data))
    GNUNET_GE_ASSERT (ectx, 0);
  GNUNET_hash (data, size, &hc);
  if (0 != memcmp (&hc, &node->chk.key, sizeof (GNUNET_HashCode)))
    {
      GNUNET_free (data);
      GNUNET_GE_BREAK (ectx, 0);
      signal_abort (rm,
                    _("Decrypted content does not match key. "
                      "This is either a bug or a maliciously inserted "
                      "file. Download aborted.\n"));
      GNUNET_mutex_unlock (rm->lock);
      return GNUNET_SYSERR;
    }
  if (size != write_to_files (rm, node->level, node->offset, data, size))
    {
      GNUNET_GE_LOG_STRERROR (ectx,
                              GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                              GNUNET_GE_USER | GNUNET_GE_BULK, "WRITE");
      signal_abort (rm, _("IO error."));
      GNUNET_mutex_unlock (rm->lock);
      return GNUNET_SYSERR;
    }
  notify_client_about_progress (node, data, size);
  if (node->level > 0)
    iblock_download_children (node, data, size);
  /* request satisfied, stop requesting! */
  delete_node (node);
  GNUNET_free (data);
  GNUNET_mutex_unlock (rm->lock);
  return GNUNET_OK;
}


/**
 * Helper function to sanitize filename
 * and create necessary directories.
 */
static char *
get_real_download_filename (struct GNUNET_GE_Context *ectx,
                            const char *filename)
{
  struct stat buf;
  char *realFN;
  char *path;
  char *pos;

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
  return path;
}

/* ***************** main method **************** */


/**
 * Download parts of a file.  Note that this will store
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
struct GNUNET_ECRS_DownloadContext *
GNUNET_ECRS_file_download_partial_start (struct GNUNET_GE_Context *ectx,
                                         struct GNUNET_GC_Configuration *cfg,
                                         const struct GNUNET_ECRS_URI *uri,
                                         const char *filename,
                                         unsigned long long offset,
                                         unsigned long long length,
                                         unsigned int anonymityLevel,
                                         int no_temporaries,
                                         GNUNET_ECRS_DownloadProgressCallback
                                         dpcb, void *dpcbClosure)
{
  struct GNUNET_ECRS_DownloadContext *rm;
  struct stat buf;
  struct Node *top;
  char *fn;
  int ret;
  int i;

  if ((!GNUNET_ECRS_uri_test_chk (uri)) && (!GNUNET_ECRS_uri_test_loc (uri)))
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  rm = GNUNET_malloc (sizeof (struct GNUNET_ECRS_DownloadContext));
  memset (rm, 0, sizeof (struct GNUNET_ECRS_DownloadContext));
  rm->ectx = ectx;
  rm->cfg = cfg;
  rm->startTime = GNUNET_get_time ();
  rm->anonymityLevel = anonymityLevel;
  rm->offset = offset;
  rm->length = length;
  rm->dpcb = dpcb;
  rm->dpcbClosure = dpcbClosure;
  rm->main = GNUNET_thread_get_self ();
  rm->total = GNUNET_ntohll (uri->data.fi.file_length);
  rm->filename = get_real_download_filename (ectx, filename);

  if (GNUNET_SYSERR ==
      GNUNET_disk_directory_create_for_file (ectx, rm->filename))
    {
      free_request_manager (rm, GNUNET_NO);
      return NULL;
    }
  if (0 == rm->total)
    {
      ret = GNUNET_disk_file_open (ectx,
                                   rm->filename,
                                   O_CREAT | O_WRONLY | O_TRUNC,
                                   S_IRUSR | S_IWUSR);
      if (ret == -1)
        {
          free_request_manager (rm, GNUNET_NO);
          return NULL;
        }
      CLOSE (ret);
      dpcb (0, 0, rm->startTime, 0, NULL, 0, dpcbClosure);
      free_request_manager (rm, GNUNET_NO);
      return NULL;
    }
  rm->treedepth = GNUNET_ECRS_compute_depth (rm->total);
  rm->handles = GNUNET_malloc (sizeof (int) * (rm->treedepth + 1));
  for (i = 0; i <= rm->treedepth; i++)
    rm->handles[i] = -1;
  if ((0 == STAT (rm->filename, &buf)) && ((size_t) buf.st_size > rm->total))
    {
      /* if exists and oversized, truncate */
      if (truncate (rm->filename, rm->total) != 0)
        {
          GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                       GNUNET_GE_ERROR | GNUNET_GE_ADMIN |
                                       GNUNET_GE_BULK, "truncate",
                                       rm->filename);
          free_request_manager (rm, GNUNET_NO);
          return NULL;
        }
    }
  for (i = 0; i <= rm->treedepth; i++)
    {
      if ((i == 0) || (no_temporaries != GNUNET_YES))
        {
          fn = GNUNET_malloc (strlen (rm->filename) + 3);
          strcpy (fn, rm->filename);
          if (i > 0)
            {
              strcat (fn, ".A");
              fn[strlen (fn) - 1] += i;
            }
          rm->handles[i] = GNUNET_disk_file_open (ectx,
                                                  fn,
                                                  O_CREAT | O_RDWR,
                                                  S_IRUSR | S_IWUSR);
          GNUNET_free (fn);
          if (rm->handles[i] < 0)
            {
              free_request_manager (rm, GNUNET_NO);
              return NULL;
            }
        }
    }
  rm->lock = GNUNET_mutex_create (GNUNET_YES);
  rm->sctx = GNUNET_FS_create_search_context (ectx, cfg, rm->lock);
  if (rm->sctx == NULL)
    {
      free_request_manager (rm, GNUNET_NO);
      return NULL;
    }
  if (GNUNET_ECRS_uri_test_loc (uri))
    {
      GNUNET_hash (&uri->data.loc.peer, sizeof (GNUNET_RSA_PublicKey),
                   &rm->target.hashPubKey);
      rm->have_target = GNUNET_YES;
    }

  top = GNUNET_malloc (sizeof (struct Node));
  memset (top, 0, sizeof (struct Node));
  top->ctx = rm;
  top->chk = uri->data.fi.chk;
  top->offset = 0;
  top->level = rm->treedepth;

  GNUNET_mutex_lock (rm->lock);
  if (GNUNET_NO == check_node_present (top))
    addRequest (top);
  else
    GNUNET_free (top);
  GNUNET_mutex_unlock (rm->lock);
  return rm;
}

int
GNUNET_ECRS_file_download_partial_stop (struct GNUNET_ECRS_DownloadContext
                                        *rm)
{
  int ret;
  char *rdir;
  int len;

  if ((rm->head == NULL) &&
      ((rm->completed == rm->total) ||
       ((rm->total != rm->length) && (rm->completed >= rm->length))))
    {
      ret = GNUNET_OK;
    }
  else
    {
#if 0
      GNUNET_GE_LOG (rm->ectx,
                     GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                     "Download ends prematurely: %d %llu == %llu %d TT: %d\n",
                     rm->requestListIndex,
                     rm->completed, rm->total, rm->abortFlag, tt (ttClosure));
#endif
      if (0 != UNLINK (rm->filename))
        {
          GNUNET_GE_LOG_STRERROR_FILE (rm->ectx,
                                       GNUNET_GE_WARNING | GNUNET_GE_USER |
                                       GNUNET_GE_BULK, "unlink",
                                       rm->filename);
        }
      else
        {
          /* delete empty directories */
          rdir = GNUNET_strdup (rm->filename);
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
      ret = GNUNET_SYSERR;
    }
#if DEBUG_DOWNLOAD
  GNUNET_GE_LOG (ectx,
                 GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                 "`%s' terminating for file `%s' with result %s\n",
                 __FUNCTION__, filename,
                 ret == GNUNET_OK ? "SUCCESS" : "INCOMPLETE");
#endif
  free_request_manager (rm, (ret == GNUNET_OK) ? GNUNET_YES : GNUNET_NO);
  return ret;
}

/**
 * Download parts of a file.  Note that this will store
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
  struct GNUNET_ECRS_DownloadContext *rm;

  rm = GNUNET_ECRS_file_download_partial_start (ectx,
                                                cfg,
                                                uri,
                                                filename,
                                                offset,
                                                length,
                                                anonymityLevel,
                                                no_temporaries,
                                                dpcb, dpcbClosure);
  if (rm == NULL)
    return (length == 0) ? GNUNET_OK : GNUNET_SYSERR;
  while ((GNUNET_OK == tt (ttClosure)) &&
         (GNUNET_YES != GNUNET_shutdown_test ()) &&
         (rm->abortFlag == GNUNET_NO) && (rm->head != NULL))
    GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);
  return GNUNET_ECRS_file_download_partial_stop (rm);
}

/**
 * Download a file (simplified API).
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

/* end of download.c */
