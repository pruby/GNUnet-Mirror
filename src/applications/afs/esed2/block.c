/*
     This file is part of GNUnet
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/esed2/block.c
 * @brief Merkle-tree-CHK file encoding for anonymous file sharing
 * @author Christian Grothoff
 *
 * Note that the current implementation no longer uses the exact
 * scheme from the ESED paper. Extensive documentation is forthcoming,
 * for now see http://www.ovmj.org/GNUnet/encoding.php3
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

#define DEBUG_BLOCK NO

#define MIN(a,b) (((a)<(b))?(a):(b))

static Block_VTBL dblock_vtbl;
static Block_VTBL iblock_vtbl;

/**
 * Compute the depth of the tree.
 * @param flen file length for which to compute the depth
 * @return depth of the tree
 */
static unsigned short computeDepth(size_t flen) {
  unsigned short treeDepth;
  unsigned long long fl;

  treeDepth = 0;
  fl = CONTENT_SIZE;
  while (fl < (unsigned long long)flen) {
    treeDepth++;
    fl = fl * CHK_PER_INODE;
  }  
  return treeDepth;
}

/**
 * Initialize an IOContext.
 *
 * @param this the context to initialize
 * @param filesize the size of the file
 * @param filename the name of the level-0 file
 * @param rdOnly use YES for read-only IOC
 * @return OK on success, SYSERR on failure
 */
int createIOContext(IOContext * this,
		    size_t filesize,
		    const char * filename,
		    int rdOnly) {
  int i;
  char * fn;

  this->treedepth = computeDepth(filesize);
  this->locks = MALLOC(sizeof(Mutex) * (this->treedepth+1));
  this->handles = MALLOC(sizeof(int) * (this->treedepth+1));
  this->filename = STRDUP(filename);
  if (NO == rdOnly) {
    struct stat st;

    if ( (0 == STAT(filename, &st)) &&
         ((size_t)st.st_size > filesize ) ) { /* if exists and oversized, truncate */
      if (truncate(filename, filesize) != 0) {
	LOG_FILE_STRERROR(LOG_FAILURE, "truncate", filename);
        return SYSERR;
      }
    }
  }
  for (i=0;i<=this->treedepth;i++) 
    this->handles[i] = -1;
  for (i=0;i<=this->treedepth;i++) 
    MUTEX_CREATE(&this->locks[i]);

  for (i=0;i<=this->treedepth;i++) {
    fn = MALLOC(strlen(filename) + 3);
    strcpy(fn, filename);
    if (i > 0) {
      strcat(fn, ".A");
      fn[strlen(fn)-1] += i;
    }
    if (rdOnly) 
      this->handles[i] = OPEN(fn,
			      O_RDONLY);
    else
      this->handles[i] = OPEN(fn,
			      O_CREAT|O_RDWR,
			      S_IRUSR|S_IWUSR );
    if ( (this->handles[i] < 0) &&
	 ( (rdOnly == NO) || 
	   (i==0) ) ) {
      LOG(LOG_FAILURE,
	  "could not open file %s (%s)\n",
	  fn, 
	  STRERROR(errno));
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
		int level,
		size_t pos,
		void * buf,
		int len) {
  int ret;
  size_t lpos;
  
  lpos = pos;
  for (ret=0;ret<level;ret++)
    lpos /= CHK_PER_INODE;  
  MUTEX_LOCK(&this->locks[level]);
  lseek(this->handles[level],
	lpos,
	SEEK_SET);
  ret = READ(this->handles[level],
	     buf, 
	     len);
  MUTEX_UNLOCK(&this->locks[level]);
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
	       int level,
	       size_t pos,
	       void * buf,
	       int len) {
  int ret;
  size_t lpos;
  
  lpos = pos;  
  for (ret=0;ret<level;ret++)
    lpos /= CHK_PER_INODE;  
  MUTEX_LOCK(&this->locks[level]);
  lseek(this->handles[level],
	lpos,
	SEEK_SET);
  ret = WRITE(this->handles[level],
	      buf, 
	      len);
  if (ret != len) {
    LOG(LOG_WARNING,
	"write(%d, %p, %d failed)!\n",
	this->handles[level],
	buf,
	len);
  }
  MUTEX_UNLOCK(&this->locks[level]);
  return ret;
}

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
void freeIOC(struct IOContext * this,
	     int unlinkTreeFiles) {
  int i;
  char * fn;
  
  for (i=0;i<=this->treedepth;i++) {
    if (this->handles[i] != -1) {
      CLOSE(this->handles[i]);
      this->handles[i] = -1;
    } 
    MUTEX_DESTROY(&this->locks[i]);    
  }
  if (YES == unlinkTreeFiles) {
    for (i=1;i<= this->treedepth;i++) {
      fn = MALLOC(strlen(this->filename) + 3);
      strcpy(fn, this->filename);
      strcat(fn, ".A");
      fn[strlen(fn)-1]+=i;    
      if (0 != UNLINK(fn))
	LOG(LOG_WARNING,
	    " could not unlink temporary file %s: %s\n",
	    fn, STRERROR(errno));
      FREE(fn);
    }
  }
  FREE(this->filename);
  FREE(this->handles);
  FREE(this->locks);
}

/**
 * Allocate space for children.
 */
static void allocateChildren(IBlock * this);

/**
 * Insert a CHK block (insert, not index!)
 *
 * @param eblock the block to insert
 * @param priority the priority to use
 * @param sock the socket to talk to gnunetd
 * @return OK on success, SYSERR on error
 */
static int insertCHKBlock(GNUNET_TCP_SOCKET * sock,
			  void * eblock,
			  int priority) {
  int res;
  AFS_CS_INSERT_CHK * request;

  if (sock == NULL)
    return OK; /* "fake" insert */
  request = MALLOC(sizeof(AFS_CS_INSERT_CHK));
  request->header.size 
    = htons(sizeof(AFS_CS_INSERT_CHK));
  request->header.type 
    = htons(AFS_CS_PROTO_INSERT_CHK);
  request->importance 
    = htonl(priority);
  memcpy(&request->content,
	 eblock,
	 sizeof(CONTENT_Block));

  if (SYSERR == writeToSocket(sock,
			      &request->header)) {
    LOG(LOG_WARNING, 
	_("Could not send '%s' request to gnunetd. Is gnunetd running?\n"),
	"index");  
    res = SYSERR;
  } else if (SYSERR == readTCPResult(sock,
				     &res)) {
    LOG(LOG_WARNING, 
	_("Server did not send confirmation of insertion.\n"));
    res = SYSERR;
  } else if (res == SYSERR)
      LOG(LOG_WARNING, 
	  _("Server could not perform insertion.\n"));
  FREE(request);
  return res;
}

/**
 * Delete a CHK block.
 *
 * @param eblock the block to insert
 * @param priority the priority to use
 * @param sock the socket to talk to gnunetd
 * @return OK on success, SYSERR on error
 */
static int deleteCHKBlock(GNUNET_TCP_SOCKET * sock,
			  void * eblock,
			  int priority) {
  int res;
  AFS_CS_INSERT_CHK * request;

  if (sock == NULL)
    return OK; /* "fake" insert */
  request = MALLOC(sizeof(AFS_CS_INSERT_CHK));
  request->header.size 
    = htons(sizeof(AFS_CS_INSERT_CHK));
  request->header.type 
    = htons(AFS_CS_PROTO_DELETE_CHK);
  request->importance 
    = htonl(priority);
  memcpy(&request->content,
	 eblock,
	 sizeof(CONTENT_Block));

  if (SYSERR == writeToSocket(sock,
			      &request->header)) {
    LOG(LOG_WARNING, 
	_("Could not send '%s' request to gnunetd. Is gnunetd running?\n"),
	"delete");  
    res = SYSERR;
  } else if (SYSERR == readTCPResult(sock,
			      &res)) {
    LOG(LOG_WARNING, 
	_("Server did not send confirmation of deletion.\n"));
    res = SYSERR;
  } else if (res == SYSERR)
      LOG(LOG_WARNING, 
	  _("Server could not perform deletion.\n"));
  FREE(request);
  return res;
}

/**
 * Encrypt this block and initialize
 * this->chk and return the encrpyted data (edata)
 */
static void * block_encrypt(Block * this) {
  void * edata;

  hash(this->data,
       this->len,
       &this->chk.key);
  memset(&((char*)this->data)[this->len],
	 0,
	 sizeof(CONTENT_Block) - this->len);
  edata = MALLOC(sizeof(CONTENT_Block));
  if (SYSERR == encryptContent(this->data,
			       &this->chk.key,
			       edata))
    GNUNET_ASSERT(0);
  hash(edata,
       sizeof(CONTENT_Block),
       &this->chk.query);
  return edata;
}

/**
 * Insert a block (send appropriate message to gnunetd).
 * This method encrypts the block and then sends an
 * index or insertion request to gnunetd, depending on
 * the configuration.
 *
 * @param this the block to insert
 * @param nc the context (gives us the priority)
 * @param sock the socket to talk to gnunetd
 * @return OK on success, SYSERR on error
 */
static int block_insert(Block * this,
			NodeContext * nc,
			GNUNET_TCP_SOCKET * sock) {
  int res;
  void * edata;

  edata = block_encrypt(this);
  if (sock == NULL) {
    FREENONNULL(edata);
    return OK; /* fake insert only */
  }
  if (nc->index != 0) {
    AFS_CS_INDEX_BLOCK request;    

    FREE(edata);
    request.header.size 
      = htons(sizeof(AFS_CS_INDEX_BLOCK));
    request.header.type 
      = htons(AFS_CS_PROTO_INDEX_BLOCK);
    request.contentIndex.importance 
      = htonl(nc->priority);
    request.contentIndex.type
      = htons(LOOKUP_TYPE_CHKS);
    request.contentIndex.fileNameIndex
      = htons(nc->index);
    {
      unsigned int fo = (unsigned int) this->pos;
      request.contentIndex.fileOffset = htonl(fo);
    }
    memcpy(&request.contentIndex.hash,
	   &this->chk.query,
	   sizeof(HashCode160));
    if (SYSERR == writeToSocket(sock,
				&request.header)) {
      LOG(LOG_WARNING, 
	  _("Could not send '%s' request to gnunetd. Is gnunetd running?\n"),
	  "index");  
      res = SYSERR;
    } else if (SYSERR == readTCPResult(sock,
				&res)) {
      LOG(LOG_WARNING, 
	  _("Server did not send confirmation for indexing request.\n"));
      res = SYSERR;
    } else if (res == SYSERR)
	LOG(LOG_WARNING, 
	    _("Server could not perform indexing\n"));    
    return res;
  } else {
    res = insertCHKBlock(sock,
			 edata,
			 nc->priority);
    FREE(edata);
    return res;
  }
}

/**
 * Delete a block (send appropriate message to gnunetd).
 *
 * @param this the block to delete
 * @param nc the context 
 * @param sock the socket to talk to gnunetd
 * @return OK on success, SYSERR on error
 */
static int block_delete(Block * this,
			NodeContext * nc,
			GNUNET_TCP_SOCKET * sock) {
  int res;
  void * edata;

  edata = block_encrypt(this);
  if (sock == NULL) {
    FREENONNULL(edata);
    return OK; /* fake insert only */
  }
  if (nc->index != 0) {
    AFS_CS_INDEX_BLOCK request;    

    FREE(edata);
    request.header.size 
      = htons(sizeof(AFS_CS_INDEX_BLOCK));
    request.header.type 
      = htons(AFS_CS_PROTO_UNINDEX_BLOCK);
    request.contentIndex.importance 
      = htonl(nc->priority);
    request.contentIndex.type
      = htons(LOOKUP_TYPE_CHKS);
    request.contentIndex.fileNameIndex
      = htons(nc->index);
    {
      unsigned int fo = (unsigned int) this->pos;
      request.contentIndex.fileOffset = htonl(fo);
    }
    memcpy(&request.contentIndex.hash,
	   &this->chk.query,
	   sizeof(HashCode160));
    if (SYSERR == writeToSocket(sock,
				&request.header)) {
      LOG(LOG_WARNING, 
	  _("Could not send '%s' request to gnunetd. Is gnunetd running?\n"),
	  "unindex");  
      res = SYSERR;
    } else if (SYSERR == readTCPResult(sock,
				       &res)) {
      LOG(LOG_WARNING, 
	  _("Server did not send confirmation for unindex request.\n"));
      res = SYSERR;
    } else if (res == SYSERR)
	LOG(LOG_DEBUG, 
	    _("Server could not perform unindexing (content already removed?).\n"));    
    return res;
  } else {
    res = deleteCHKBlock(sock,
			 edata,
			 nc->priority);
    FREE(edata);
    return res;
  }
}

/**
 * Insert the current block into the network. Implementations
 * are also responsible for updating the corresponding fields
 * of the parent node (of course, except if the parent is
 * NULL in the case of the top-node in the tree).<p>
 *
 * Inner nodes first call the respective inserter methods for
 * their children.<p>
 * 
 * @param this the node that should be inserted or indexed
 * @param nc the context (gives us the priority)
 * @param sock the socket to use to talk to the core
 * @return OK on success, SYSERR on error
 */
static int dblock_insert(DBlock * this,
			 NodeContext * nc,
			 GNUNET_TCP_SOCKET * sock) {
  int res;
#if DEBUG_BLOCK
  EncName enc;
#endif
   
  if (this->common.data != NULL)
    return OK;
  this->common.data = MALLOC(sizeof(CONTENT_Block));
  memset(this->common.data, 
	 0, 
	 sizeof(CONTENT_Block));
  res = readFromIOC(&nc->ioc,
		    0,
		    this->common.pos,
		    this->common.data,
		    this->common.len);
  if (res != (int)this->common.len) {
    FREE(this->common.data);
    this->common.data = NULL;
    if (sock != NULL)
      BREAK();
    return SYSERR;
  } 
#if DEBUG_BLOCK
  else
    LOG(LOG_EVERYTHING,
	"Read %d bytes from IOC for insertion.\n",
	res);
#endif

  nc->stats.progress += this->common.len;
  
  if (nc->pmodel != NULL)
    nc->pmodel(&nc->stats,
	       nc->data);
  res = block_insert(&this->common,
		     nc,
		     sock);
#if DEBUG_BLOCK
  IFLOG(LOG_DEBUG,
	hash2enc(&this->common.chk.query,
		 &enc));
  LOG(LOG_DEBUG,
      "inserting dblock %u of len %u under query %s\n",
      this->common.pos,
      this->common.len, 
      &enc);
#endif
  return res;
}


/**
 * Delete the current block from the local peer. Works just
 * like dblock_insert.
 * 
 * @param this the node that should be deleted
 * @param nc the context (gives us the priority)
 * @param sock the socket to use to talk to the core
 * @return OK on success, SYSERR on error
 */
static int dblock_delete(DBlock * this,
			 NodeContext * nc,
			 GNUNET_TCP_SOCKET * sock) {
  int res;
#if DEBUG_BLOCK
  EncName enc;
#endif
   
  if (this->common.data != NULL)
    return OK;
  this->common.data = MALLOC(sizeof(CONTENT_Block));
  memset(this->common.data, 
	 0, 
	 sizeof(CONTENT_Block));
  res = readFromIOC(&nc->ioc,
		    0,
		    this->common.pos,
		    this->common.data,
		    this->common.len);
  if (res != (int)this->common.len) {
    FREE(this->common.data);
    this->common.data = NULL;
    if (sock != NULL)
      BREAK();
    return SYSERR;
  } 
#if DEBUG_BLOCK
  else
    LOG(LOG_EVERYTHING,
	"read %d bytes from IOC for insertion\n",
	res);
#endif

  nc->stats.progress += this->common.len;
  if (nc->pmodel != NULL)
    nc->pmodel(&nc->stats,
	       nc->data);
  res = block_delete(&this->common,
		     nc,
		     sock);
#if DEBUG_BLOCK
  IFLOG(LOG_DEBUG,
	hash2enc(&this->common.chk.query,
		 &enc));
  LOG(LOG_DEBUG,
      "inserting dblock %u of len %u under query %s\n",
      this->common.pos,
      this->common.len, 
      &enc);
#endif
  return res;
}
 
/**
 * Send the super-request that groups the queries for all
 * child-nodes in one large query. Note that recursion and
 * updates are checked by the "superState" field of IBlock.
 *
 * @param nc the context (gives us the priority)
 * @param rm reference to the RequestManager for requests
 */
static void iblock_do_superrequest(IBlock * this,
				   NodeContext * nc,
				   RequestManager * rm);

/**
 * We received a CHK reply for a block. Decrypt.
 *
 * @param this the block that we received the reply for
 * @param query the query for which reply is the answer
 * @param reply the reply
 * @return OK if the reply was valid, SYSERR on error
 */
static int chk_block_receive(Block * this,
			     HashCode160 * query,
			     AFS_CS_RESULT_CHK * reply) {
  HashCode160 hc;
  void * edata;

  GNUNET_ASSERT(equalsHashCode160(query,
				  &this->chk.query));
  edata = &((AFS_CS_RESULT_CHK*)reply)->result;
  this->data 
    = MALLOC(sizeof(CONTENT_Block));
  if (SYSERR == decryptContent(edata,
			       &this->chk.key,
			       this->data)) 
    GNUNET_ASSERT(0);
  hash(this->data,
       this->len,
       &hc);
  if (!equalsHashCode160(&hc,
			 &this->chk.key)) {
    FREE(this->data);
    this->data = NULL;
    BREAK();
    LOG(LOG_ERROR,
	_("Decrypted content does not match key. "
	  "This is either a bug or a maliciously inserted "
	  "file. Download aborted.\n"));
    return SYSERR;
  } 
  return OK;
}

/**
 * Function that is called when a message matching a
 * request for a DBlock is received. Decrypts the received
 * block and writes it to the file. Notifies the parent
 * and the ProgressModel.
 *
 * @param this the node in the tree for which the request
 *       was issued
 * @param query the query that was sent out
 * @param reply the reply that was received
 * @param rm the handle for the request manager
 * @param nc the context (gives us the priority)
 * @return SYSERR the request manager should abort the download,
 *         OK if everything is fine
 */
static int dblock_download_receive(DBlock * this,
				   HashCode160 * query,
				   AFS_CS_RESULT_CHK * reply,
				   RequestManager * rm,
				   NodeContext * nc) {
  size_t filesize;
  int i;

#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "dblock_download_receive %p\n",
      this);
#endif
  if (this->common.status != BLOCK_PENDING)
    errexit(" dblock_download_receive called, but no request was pending\n");
  if (SYSERR == chk_block_receive(&this->common,
				  query,
				  reply)) {
    ProgressStats pstats;

    memset(&pstats, 0, sizeof(ProgressStats));
    nc->pmodel(&pstats,
	       nc->data);  
    return SYSERR;
  }
  if ((int)this->common.len != writeToIOC(&nc->ioc,
					  0,
					  this->common.pos,
					  this->common.data,
					  this->common.len)) {
    ProgressStats pstats;
    memset(&pstats, 0, sizeof(ProgressStats));
    nc->pmodel(&pstats,
	       nc->data);  
    LOG(LOG_ERROR,
	" writing to file failed (%s)!\n",
	STRERROR(errno));
    return SYSERR;
  }

  for (i=0;i<10;i++) {
    if ( (nc->stats.progress * 10000L >
	  nc->stats.filesize * (10000L - (1024 >> i)) ) &&
	 ( (nc->stats.progress-this->common.len) * 10000L <=
	   nc->stats.filesize * (10000L - (1024 >> i)) ) ) {
      /* end-game boundary crossed, slaughter TTLs */
      requestManagerEndgame(rm);
    }
  }

  this->common.status = BLOCK_PRESENT; 
  /* request satisfied, remove from RM */
  filesize = this->common.filesize;
  nc->stats.progress += this->common.len;
  if (this->common.parent != NULL) {
    /* child, must tell parent to adjust requests */
    childDownloadCompleted(this->common.parent,
			   &this->common,
			   nc,
			   rm);
    iblock_do_superrequest(this->common.parent,
			   nc,
			   rm);
  } else {
    /* top block, must cancel my own request */
    requestManagerUpdate(rm, 
			 &this->common, 
			 NULL);
  }
  /* leaf, done when download complete */
  this->common.status = BLOCK_DONE;
  this->common.vtbl->done(this, rm);  
  nc->pmodel(&nc->stats,
	     nc->data);  
  return OK; 
}

/**
 * Check if this dblock is already present on the drive.
 * If the block is present, the parent and the
 * ProgressModel are notified.
 *
 * @param this the DBlock that is checked for presence
 * @param nc the context (gives us the priority)
 * @return YES if present, NO if not.
 */
static int dblock_isPresent(DBlock * this,
			    NodeContext * nc) {
  int res;

#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "dblock_isPresent %p\n",
      this);
#endif
  /* first check if its already present */
  this->common.data = MALLOC(sizeof(CONTENT_Block));
  res = readFromIOC(&nc->ioc,
		    0,
		    this->common.pos,
		    this->common.data,
		    this->common.len);
  if (res == (int)this->common.len) {
    HashCode160 hc;
    
    hash(this->common.data,
	 this->common.len,
	 &hc);
    if (equalsHashCode160(&hc,
			  &this->common.chk.key)) {

      this->common.status = BLOCK_PRESENT;
      nc->stats.filesize = this->common.filesize;
      nc->stats.progress += this->common.len;
      nc->pmodel(&nc->stats,
		 nc->data);
      return YES;
    }    
  }
  FREE(this->common.data);
  this->common.data = NULL;
  return NO;
}

/**
 * Send a single query via the RequestManager to gnunetd.
 *
 * @param rm the rm used to issue the query
 * @param node the node for which to issue the query
 * @param receiver the receiver to call on the reply
 * @param nc the context
 * @param query the query to perform
 */
static void issueQuery(RequestManager * rm,
		       Block * node,
		       Listener receiver,
		       NodeContext * nc,
		       HashCode160 * query) {
  AFS_CS_QUERY * msg;

  msg = MALLOC(sizeof(AFS_CS_QUERY) + sizeof(HashCode160));
  msg->header.size
    = htons(sizeof(AFS_CS_QUERY) + sizeof(HashCode160));
  msg->header.type
    = htons(AFS_CS_PROTO_QUERY);
  msg->priority 
    = htonl(1);
  msg->ttl 
    = htonl(1);
  memcpy(&((AFS_CS_QUERY_GENERIC*)msg)->queries[0],
	 query,
	 sizeof(HashCode160));

  requestManagerRequest(rm,
			node,
			receiver,
			nc,
			msg);
}	       

/**
 * Download this node (and the children below). Note that the
 * processing is asynchronous until the pmodel is called with position
 * == total (and thus no more requests are pending) or the request
 * manager is aborted by the user.
 * 
 * @param this the node that should be inserted or indexed
 * @param nc the context (gives us the priority)
 * @param rm the request manager
 */
static void dblock_download(DBlock * this,
			    NodeContext * nc,
			    RequestManager * rm) {
#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "dblock_download %p\n",
      this);
#endif

  if (YES == dblock_isPresent(this, nc)) {
    if (this->common.parent != NULL) {
      childDownloadCompleted(this->common.parent,
			     &this->common,
			     nc,
			     rm);    
    } 
    /* leaf node, we're done when present */
    this->common.status = BLOCK_DONE;
    this->common.vtbl->done(this, rm); 
    return;
  }
  /* not present, either request ourselves or let the parent
     do it automagically when we return... */
  this->common.status = BLOCK_PENDING;
  if (this->common.parent == NULL) {
    issueQuery(rm, 
	       &this->common,
	       (Listener)&dblock_download_receive,
	       nc,
	       &this->common.chk.query);
  }
}

/**
 * Free the associated resources of this Block. DOES ALSO free the
 * memory occupied by the Block struct itself!
 *
 * @param this reference to the Block
 * @param rm reference to the RequestManager for requests
 */
static void block_done(Block * this,
		       RequestManager * rm) {
  unsigned int i;
  unsigned int live;

  /* better make sure that we have no request pending... */
  if (rm != NULL) { /* rm == NULL for gnunet-insert! */
    requestManagerAssertDead(rm, this);
    if (rm->top == this)
      rm->top = NULL;
  }
  live = 0;
  if (this->parent != NULL) {
    if (this->parent->children != NULL) {
      for (i=0;i<this->parent->childcount;i++) {
	if (this->parent->children[i] == this)
	  this->parent->children[i] = NULL;  
	if (this->parent->children[i] != NULL)
	  live++;
      }
    }
    if ( (live == 0) && 
	 (this->parent->common.status != BLOCK_PERSISTENT) )
      this->parent->common.vtbl->done(this->parent, rm);
  }
  FREENONNULL(this->data);
  FREE(this);
}

/**
 * Free the associated resources of this Block. DOES ALSO free the
 * memory occupied by the Block struct itself!
 *
 * @param this reference to the Block
 * @param rm reference to the RequestManager for requests
 */
static void dblock_done(DBlock * this,
			RequestManager * rm) {
#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "dblock_done %p\n",
      this);
#endif
  block_done(&this->common, rm);
}

/**
 * Print a block to log.
 */
static void dblock_print(DBlock * this,
			 int ident) {
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&this->common.chk.query,
		 &enc));
  LOG(LOG_DEBUG,
      "%*s, DBLOCK (0) %u %s\n",
      ident, 
      "", 
      this->common.pos, 
      &enc);      
}

/**
 * Insert the current block into the network. Implementations
 * are also responsible for updating the corresponding fields
 * of the parent node (of course, except if the parent is
 * NULL in the case of the top-node in the tree).<p>
 *
 * Inner nodes first call the respective inserter methods for
 * their children.<p>
 * 
 * @param this the node that should be inserted or indexed
 * @param nc the context (gives us the priority)
 * @param sock the socket to use to talk to the core
 * @return OK on success, SYSERR on error
 */
static int iblock_insert(IBlock * this,
			 NodeContext * nc,
			 GNUNET_TCP_SOCKET * sock) {
  int i;
  unsigned int ui;
  size_t childCover;
  Block * child;
  IBlockData * ibd;
  AFS_CS_INDEX_SUPER req;
  int ret;
  void * edata;
 
  this->common.status = BLOCK_PERSISTENT;
  ibd = MALLOC(sizeof(IBlockData));
  this->common.data = ibd;
  childCover = sizeof(CONTENT_Block);
  for (ui=0;ui<this->depth-1;ui++)
    childCover *= CHK_PER_INODE;
  allocateChildren(this);
  for (ui=0;ui<this->childcount;ui++) {
    child = this->children[ui];
    if (SYSERR == child->vtbl->insert(child,
				      nc, 
				      sock)) {
      if (sock != NULL)
	BREAK();
      return SYSERR; /* abort! */
    }
    this->crcs[ui] = crc32N(child->data,
			    child->len);
    memcpy(&ibd->chks[ui],
	   &child->chk,
	   sizeof(CHK_Hashes));
    child->vtbl->done(child, NULL);
    this->children[ui] = NULL;
  }
  hash(&ibd->chks,
       sizeof(CHK_Hashes) * this->childcount,
       &ibd->superHash);
  if ( (nc->index != 0) &&
       (sock != NULL) ) {    
    req.header.size = htons(sizeof(AFS_CS_INDEX_SUPER));
    req.header.type = htons(AFS_CS_PROTO_INDEX_SUPER);
    req.importance = htonl(nc->priority);
    memcpy(&req.superHash,
	   &ibd->superHash,
	   sizeof(HashCode160));
    ret = writeToSocket(sock,
			&req.header);
    if (ret == OK) {
      i = readTCPResult(sock, &ret);
      if (i == SYSERR) {
	ret = SYSERR;
	LOG(LOG_WARNING, 
	    _("Server did not send confirmation of insertion.\n"));
      } else if (ret == SYSERR)
	LOG(LOG_WARNING, 
	    _("Server could not perform insertion.\n"));
    } else
      LOG(LOG_WARNING, 
	  _("Could not send '%s' request to gnunetd. Is gnunetd running?\n"),
	  "super-index");  
    if (ret == SYSERR)
      return SYSERR;
  }
  ibd->crc32 = crc32N(&this->crcs[0],
		      sizeof(int) * this->childcount);
  this->crc32 = ibd->crc32;
  edata = block_encrypt(&this->common);
  ret = insertCHKBlock(sock,
		       edata,
		       nc->priority);
  FREE(edata);
  return ret;
}

/**
 * Remove the current block from the local AFS storage.
 * 
 * @param this the node that should be removed
 * @param nc the context (gives us the priority)
 * @param sock the socket to use to talk to the core
 * @return OK on success, SYSERR on error
 */
static int iblock_delete(IBlock * this,
			 NodeContext * nc,
			 GNUNET_TCP_SOCKET * sock) {
  int i;
  unsigned int ui;
  size_t childCover;
  Block * child;
  IBlockData * ibd;
  AFS_CS_INDEX_SUPER req;
  int ret;
  void * edata;
 
  this->common.status = BLOCK_PERSISTENT;
  ibd = MALLOC(sizeof(IBlockData));
  this->common.data = ibd;
  childCover = sizeof(CONTENT_Block);
  for (ui=0;ui<this->depth-1;ui++)
    childCover *= CHK_PER_INODE;
  allocateChildren(this);
  for (ui=0;ui<this->childcount;ui++) {
    child = this->children[ui];
    if (SYSERR == child->vtbl->delete(child,
				      nc, 
				      sock)) {
      if (sock != NULL)
	BREAK();
    }
    this->crcs[ui] = crc32N(child->data,
			    child->len);
    memcpy(&ibd->chks[ui],
	   &child->chk,
	   sizeof(CHK_Hashes));
    child->vtbl->done(child, NULL);
    this->children[ui] = NULL;
  }
  hash(&ibd->chks,
       sizeof(CHK_Hashes) * this->childcount,
       &ibd->superHash);
  if (sock != NULL) {
    req.header.size = htons(sizeof(AFS_CS_INDEX_SUPER));
    req.header.type = htons(AFS_CS_PROTO_UNINDEX_SUPER);
    req.importance = htonl(nc->priority);
    memcpy(&req.superHash,
	   &ibd->superHash,
	   sizeof(HashCode160));
    ret = writeToSocket(sock,
			&req.header);
    if (ret == OK) {
      i = readTCPResult(sock, &ret);
      if (i == SYSERR) {
	ret = SYSERR;
	LOG(LOG_WARNING, 
	    _("Server did not send confirmation of deletion.\n"));
      } else if (ret == SYSERR)
	ret = OK; /* super blocks don't matter! */
    } else
      LOG(LOG_WARNING, 
	  _("Could not send '%s' request to gnunetd. Is gnunetd running?\n"),
	  "super-unindex");  
    if (ret == SYSERR)
      return SYSERR;
  }
  ibd->crc32 = crc32N(&this->crcs[0],
		      sizeof(int) * this->childcount);
  edata = block_encrypt(&this->common);
  ret = deleteCHKBlock(sock,
		       edata,
		       nc->priority);
  FREE(edata);
  return ret;
}

/**
 * The request manager got a reply for one of the childs
 * we were looking after. Update the RM query, call 
 * receive on the appropriate child, etc.
 *
 * @param this the node in the tree for which the request
 *       was issued
 * @param query the query that was sent out
 * @param reply the reply that was received
 * @param rm the handle for the request manager
 * @param nc the context (gives us the priority)
 * @return SYSERR the request manager should abort the download
 */
static int iblock_download_receive_child(IBlock * this,
					 HashCode160 * query,
					 AFS_CS_RESULT_CHK * reply,
					 RequestManager * rm,
					 NodeContext * nc) {
  unsigned int i;
  IBlockData * ibd;

#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "iblock_download_receive_child %p\n",
      this);
#endif
  if (this->common.status != BLOCK_SUPERQUERY_PENDING)
    errexit(" iblock_download_receive_child called, "
	    "but no superquery is pending\n");
#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "iblock %p receives message for child\n",
      this);
#endif
  ibd = this->common.data;
  allocateChildren(this);
  for (i=0;i<this->childcount;i++) {    
    if (equalsHashCode160(query,
			  &ibd->chks[i].query)) {
      if ( (this->children[i] != NULL) &&
	   (this->children[i]->status == BLOCK_PENDING) ) {
	return this->children[i]->vtbl->receive(this->children[i],
						query,
						reply,
						rm,
						nc);      
      }
    }
  }
  return OK; /* we may receive replies twice, 
		just ignore those */
}

/**
 * Initialize IBlock fields (helper for createTopIBlock
 * and createIBlock)
 */
static void initializeIBlock(IBlock * this);

/**
 * Call download on the children to test if they are present.
 * 
 * @param this the node that should be inserted or indexed
 * @param nc the context (gives us the priority)
 * @param rm the request manager
 */
static void iblock_download_children(IBlock * this,
				     NodeContext * nc,
				     RequestManager * rm) {
  unsigned int i;
  IBlockData * ibd;
  Block * child;

#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "iblock_download_children %p\n",
      this);
#endif
  GNUNET_ASSERT(this->childcount <= CHK_PER_INODE);
  ibd = this->common.data;
  allocateChildren(this);
  for (i=0;i<this->childcount;i++) {
    child = this->children[i];
    if (child != NULL) {
      memcpy(&child->chk,
	     &ibd->chks[i],
	     sizeof(CHK_Hashes));
      child->vtbl->download(child,
			    nc,
			    rm);  
    }
  }
}

/**
 * Send the super-request that groups the queries for all
 * child-nodes in one large query. Note that recursion and
 * updates are checked by the "superState" field of IBlock.
 *
 * @param this IBlock that contains the hash codes for the
 *        super-request
 * @param rm reference to the RequestManager for requests
 * @param nc the context (gives us the priority)
 */
static void iblock_do_superrequest(IBlock * this,
				   NodeContext * nc,
				   RequestManager * rm) {
  IBlockData * ibd;
  AFS_CS_QUERY * msg;
  unsigned int liveChildren;
  unsigned int i;

#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "iblock_do_superrequest %p\n",
      this);
#endif
  liveChildren = 0;
  allocateChildren(this);
  for (i=0;i<this->childcount;i++) 
    if (this->children[i] != NULL) 
      if (this->children[i]->status == BLOCK_PENDING) 
	liveChildren++;    
  if (liveChildren == 0) {
#if DEBUG_BLOCK
    LOG(LOG_DEBUG,
	"iblock %p cancels request, all children done (%d)\n",
	this,
	this->common.status);
#endif      
    /* finally drop remaining requests, all satisfied! */
    if (this->common.status == BLOCK_SUPERQUERY_PENDING)
      requestManagerUpdate(rm, 
			   &this->common, 
			   NULL);
    this->common.status = BLOCK_CHILDREN_PRESENT;
    return; /* we are done here! */  
  }
  ibd = this->common.data;
  msg = MALLOC(sizeof(AFS_CS_QUERY) + 
	       sizeof(HashCode160)*(1+liveChildren));
  msg->header.size
    = htons(sizeof(AFS_CS_QUERY) + 
	    sizeof(HashCode160)*(1+liveChildren));
  msg->header.type
    = htons(AFS_CS_PROTO_QUERY);
  msg->priority 
    = htonl(1);
  msg->ttl 
    = htonl(1);
  memcpy(&((AFS_CS_QUERY_GENERIC*)msg)->queries[0],
	 &ibd->superHash,
	 sizeof(HashCode160));
  liveChildren = 0;
  allocateChildren(this);
  for (i=0;i<this->childcount;i++)
    if (this->children[i] != NULL) 
      if (this->children[i]->status == BLOCK_PENDING) {
	memcpy(&((AFS_CS_QUERY_GENERIC*)msg)->queries[liveChildren+1],
	       &ibd->chks[i].query,
	       sizeof(HashCode160));
	liveChildren++;
      }
  if (this->common.status == BLOCK_SUPERQUERY_PENDING) {
#if DEBUG_BLOCK
    LOG(LOG_DEBUG,
	"iblock %p updates request, %d children pending\n",
	this, 
	liveChildren);
#endif
    requestManagerUpdate(rm,
			 &this->common,
			 msg);
  } else {
#if DEBUG_BLOCK
    LOG(LOG_DEBUG,
	"iblock %p starts request, %d children pending\n",
	this, 
	liveChildren);
#endif
    this->common.status = BLOCK_SUPERQUERY_PENDING;
    requestManagerRequest(rm,
			  &this->common,
			  (Listener)&iblock_download_receive_child,
			  nc,
			  msg);  
  }
}

/**
 * Type of a method that is called by the RequestManager
 * whenever a reply to a query has been received.
 *
 * @param this the node in the tree for which the request
 *       was issued
 * @param query the query that was sent out
 * @param reply the reply that was received
 * @param rm the handle for the request manager
 * @param nc the context (gives us the priority)
 * @return SYSERR the request manager should abort the download
 */
static int iblock_download_receive(IBlock * this,
				   HashCode160 * query,
				   AFS_CS_RESULT_CHK * reply,
				   RequestManager * rm,
				   NodeContext * nc) {
#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "iblock_download_receive %p\n",
      this);
#endif
  if (this->common.status != BLOCK_PENDING) {
    /* As far as I can tell, this should never happen */
    BREAK();
    return OK;
  }
#if DEBUG_BLOCK
  else
    LOG(LOG_DEBUG,
	"iblock %p receives reply\n",
	this);
#endif
  if (SYSERR == chk_block_receive(&this->common,
				  query,
				  reply)) {
    ProgressStats pstats;
    memset(&pstats, 0, sizeof(ProgressStats));
    nc->pmodel(&pstats,
	       nc->data);  
    return SYSERR; 
  }
  if ((int)this->common.len != writeToIOC(&nc->ioc,
					  this->depth,
					  this->common.pos,
					  this->common.data,
					  this->common.len)) {
    ProgressStats pstats;
    memset(&pstats, 0, sizeof(ProgressStats));
    nc->pmodel(&pstats,
	       nc->data);  
    LOG_STRERROR(LOG_ERROR, "write");
    return SYSERR;
  }
  this->crc32 = ((IBlockData*) this->common.data)->crc32;
  this->common.status = BLOCK_PRESENT;
  if (this->common.parent == NULL) {
    /* our request, stop doing it */
    requestManagerUpdate(rm, 
			 &this->common,
			 NULL);
  } else {
    childDownloadCompleted(this->common.parent,
			   &this->common,
			   nc, 
			   rm);    
    iblock_do_superrequest(this->common.parent, 
			   nc,
			   rm);
  }
  this->common.status = BLOCK_PERSISTENT;
  iblock_download_children(this, 
			   nc,
			   rm);
  iblock_do_superrequest(this,
			 nc, 
			 rm);
  return OK;
}

/**
 * Check if an IBlock is already present.
 *
 * @param this the IBlock that is tested for presence
 * @param nc the context (gives us the priority)
 * @return YES if it is present, NO if not.
 */
static int iblock_isPresent(IBlock * this,
			    NodeContext * nc) {
  int res;

#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "iblock_isPresent %p\n",
      this);
#endif
  /* first check if its already present */
  this->common.data = MALLOC(sizeof(CONTENT_Block));
  res = readFromIOC(&nc->ioc,
		    this->depth,
		    this->common.pos,
		    this->common.data,
		    this->common.len);
  if (res == (int)this->common.len) {
    HashCode160 hc;
    
    hash(this->common.data,
	 this->common.len,
	 &hc);
    if (equalsHashCode160(&hc,
			  &this->common.chk.key)) {
      this->crc32 = ((IBlockData*) this->common.data)->crc32;
      return YES;    
    }
  }
  FREE(this->common.data);
  this->common.data = NULL;
  return NO;
}


/**
 * Very lazy progress model for the insert that is
 * actually just checking if the block that we are trying
 * to download is already present...
 */
static void noModel(ProgressStats * stats,
		    void * data) {
}

/**
 * Download this node (and the children below). Note that the
 * processing is asynchronous until the pmodel is called with position
 * == total (and thus no more requests are pending) or the request
 * manager is aborted by the user.
 * 
 * @param this the node that should be inserted or indexed
 * @param rm the request manager
 * @param nc the context (gives us the priority)
 */
static void iblock_download(IBlock * this,
			    NodeContext * nc,
			    RequestManager * rm) {
  int isPresent;
  
#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "iblock_download %p\n",
      this);
#endif
  isPresent = iblock_isPresent(this, nc);
  if (YES != isPresent) {
    NodeContext fakeContext;
    IBlock * fakeThis;
    
    memcpy(&fakeContext.ioc,
	   &nc->ioc,
	   sizeof(IOContext));
    fakeContext.priority = 0;
    fakeContext.index = -1;
    fakeContext.pmodel = &noModel;
    fakeContext.data = NULL;
    fakeContext.stats.progress = 0;
    fakeThis = MALLOC(sizeof(IBlock));
    memcpy(fakeThis,
	   this,
	   sizeof(IBlock));
    initializeIBlock(fakeThis);
    fakeThis->common.parent = NULL;
    memcpy(&fakeThis->common.chk,
	   &this->common.chk,
	   sizeof(CHK_Hashes));
    fakeThis->common.status = BLOCK_PERSISTENT; 
    if (OK == fakeThis->common.vtbl->insert(&fakeThis->common, 
					    &fakeContext,
					    NULL))
      if (0 == memcmp(&fakeThis->common.chk,
		      &this->common.chk,
		      sizeof(CHK_Hashes))) {
	this->common.status = BLOCK_PRESENT;
	this->common.data = fakeThis->common.data;
	this->crc32 = fakeThis->crc32;
	
	fakeThis->common.data = NULL;
	isPresent = YES;
      }
    fakeThis->common.vtbl->done(&fakeThis->common, NULL);    
  }
  if (YES == isPresent) {
    if (this->common.parent != NULL) {
      childDownloadCompleted(this->common.parent,
			     &this->common,
			     nc, 
			     rm);
      iblock_do_superrequest(this->common.parent,
			     nc,
			     rm);
    }
    this->common.status = BLOCK_PERSISTENT;
    iblock_download_children(this, 
			     nc,
			     rm);
    iblock_do_superrequest(this,
			   nc,
			   rm);
    return;
  }
  /* not present, either request ourselves or let the parent
     do it automagically when we return... */
  this->common.status = BLOCK_PENDING;
  if (this->common.parent == NULL) {
    issueQuery(rm,
	       &this->common,
	       (Listener)&iblock_download_receive,
	       nc,
	       &this->common.chk.query);
  }
}

static void iblock_print(IBlock * this,
			 int ident) {
  unsigned int i;
  EncName enc;

  IFLOG(LOG_DEBUG,
	hash2enc(&this->common.chk.query,
		 &enc));
  LOG(LOG_DEBUG,
      "%*s, IBLOCK (%d) %u %s (%d children)\n",
      ident, 
      "", 
      this->depth,
      this->common.pos, 
      &enc,
      this->childcount);
  if (this->children != NULL)
    for (i=0;i<this->childcount;i++) 
      if (this->children[i] != NULL)
	this->children[i]->vtbl->print(this->children[i],
				       ident + 2);  
}

/**
 * Initialize DBlock fields (helper for createTopDBlock
 * and createDBlock).
 */
static void initializeDBlock(DBlock * this) {
  static int once = 1;
  if (once) {
    once = 0;
    dblock_vtbl.done 
      = (Block_Destructor) &dblock_done;
    dblock_vtbl.insert 
      = (Inserter) &dblock_insert;
    dblock_vtbl.delete
      = (Inserter) &dblock_delete;
    dblock_vtbl.download 
      = (Downloader) &dblock_download;
    dblock_vtbl.isPresent
      = (PresentChecker) &dblock_isPresent;
    dblock_vtbl.receive
      = (Listener) &dblock_download_receive;
    dblock_vtbl.print
      = (BlockPrinter) &dblock_print;  
  }
  this->common.vtbl = &dblock_vtbl;
}

/**
 * Create a top-DBlock for files <= 1k where there is no parent
 * IBlock. Note that you must set the chk field before calling
 * download.
 *
 * @param filesize the size of the file 
 * @return the DBlock on success, NULL on failure
 */
Block * createTopDBlock(size_t filesize) {
  DBlock * res;

  if (filesize > sizeof(CONTENT_Block)) {
    BREAK();
    return NULL; /* invalid! */
  }
  res = MALLOC(sizeof(DBlock));
  memset(res, 0, sizeof(DBlock));
  res->common.filesize 
    = filesize;
  initializeDBlock(res);
  res->common.len 
    = filesize;
  return &res->common;
}

/**
 * Free the associated resources of this Block. DOES ALSO free the
 * memory occupied by the Block struct itself!
 *
 * @param this reference to the Block
 * @param rm reference to the RequestManager for requests
 */
static void iblock_done(IBlock * this,		       
			RequestManager * rm) {
  unsigned int i;

#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "iblock_done %p\n",
      this);
#endif
  this->common.status 
    = BLOCK_PERSISTENT; /* last child would otherwise call done on us! */
  if (this->children != NULL) {
    for (i=0;i<this->childcount;i++)
      if (this->children[i] != NULL)
	this->children[i]->vtbl->done(this->children[i], rm);
    FREE(this->children);
    this->children = NULL;
  }
  block_done(&this->common, rm);
}

/**
 * Initialize IBlock fields (helper for createTopIBlock
 * and createIBlock)
 */
static void initializeIBlock(IBlock * this) {
  static int once = 1;
  unsigned int i;
  unsigned int childCover;
  int myCover;

  if (once) {
    once = 0;
    iblock_vtbl.done 
      = (Block_Destructor) &iblock_done;
    iblock_vtbl.insert 
      = (Inserter) &iblock_insert;
    iblock_vtbl.delete
      = (Inserter) &iblock_delete;
    iblock_vtbl.download 
      = (Downloader) &iblock_download;
    iblock_vtbl.isPresent
      = (PresentChecker) &iblock_isPresent;
    iblock_vtbl.receive
      = (Listener) &iblock_download_receive;
    iblock_vtbl.print
      = (BlockPrinter) &iblock_print;
  }
  this->common.vtbl = &iblock_vtbl;
  /* compute childcount, len */
  childCover = sizeof(CONTENT_Block);
  for (i=0;i<this->depth-1;i++)
    childCover *= CHK_PER_INODE;
  myCover = MIN(this->common.filesize - this->common.pos,
		CHK_PER_INODE * childCover);
  this->childcount = 0;
  this->common.len = sizeof(HashCode160) + sizeof(int); /* superhash + crc */
  while (myCover > 0) {
    myCover -= childCover;
    this->childcount++;
    this->common.len += sizeof(CHK_Hashes);
  }
  this->children = NULL;
}

/**
 * Allocate space for children.
 */
static void allocateChildren(IBlock * this) {
  unsigned int childCover;
  int i;

  if (this->children != NULL)
    return;
  childCover = sizeof(CONTENT_Block);
  for (i=0;i<this->depth-1;i++)
    childCover *= CHK_PER_INODE;
  this->children 
    = MALLOC(this->childcount * sizeof(Block*));
  /* create child-nodes */
  for (i=0;i<this->childcount;i++) {
    if (this->depth > 1)
      this->children[i] 
	= createIBlock(this->common.pos+i*childCover,
		       this);
    else
      this->children[i] 
	= createDBlock(this->common.pos+i*childCover,
		       this);
  }    
}
			 
/**
 * Create an IBlock. Use createTopIBlock for the
 * node on top of the file-tree.
 *
 * @param pos the position of the IBlock in the file
 * @param parent the parent block (may not be NULL)
 * @return the IBlock 
 */
Block * createIBlock(size_t pos,
		     IBlock * parent) {
  IBlock * res;

  res = MALLOC(sizeof(IBlock));
  memset(res, 0, sizeof(IBlock));
  res->common.filesize 
    = parent->common.filesize;
  res->common.pos 
    = pos;
  res->common.parent 
    = parent;
  res->depth 
    = parent->depth - 1;
  initializeIBlock(res);
  return &res->common;
}

/**
 * Create a DBlock. Note that this method can NOT be used for files <=
 * 1k since parent may not be NULL (which it would be for the
 * top-block). Use createTopDBlock for files <= 1k.
 *
 * @param pos the offset of this block in the file
 * @param parent the parent block
 * @return the DBlock on success, NULL on failure
 */
Block * createDBlock(size_t pos,
		     IBlock * parent) {
  DBlock * res;

  res = MALLOC(sizeof(DBlock));
  memset(res, 0, sizeof(DBlock));
  res->common.filesize 
    = parent->common.filesize;
  initializeDBlock(res);
  res->common.pos 
    = pos;
  res->common.parent 
    = parent;
  res->common.len 
    = MIN(sizeof(CONTENT_Block), 
	  res->common.filesize - pos);
  GNUNET_ASSERT(res->common.filesize > pos);
  return &res->common;
}
	
/**
 * Create a top-IBlock for the root of the file tree.
 * Note that you must set the chk field before calling
 * download. 
 * @param filesize the size of the file
 */
Block * createTopIBlock(size_t filesize) {
  IBlock * res;
  
  res = MALLOC(sizeof(IBlock));
  memset(res, 
	 0, 
	 sizeof(IBlock));
  res->common.filesize
    = filesize;
  res->depth 
    = computeDepth(filesize);
  initializeIBlock(res);
  return &res->common;
}

/**
 * A child has been completely downloaded. Perform the
 * appropriate CRC checks in the parent node.
 * Since the only errors are either
 * bugs or hash-crc-collisions (probability 1:2^160), we
 * always die on errors (return values do not work well for
 * async calls anyway).<p>
 * 
 * Note that the leaves update the ProgressModel, so we do
 * not have to worry about that. If all children of a node
 * are complete, this method calls itself recursively to
 * notify the parent of the parent.
 *
 * @param parent the IBlock
 * @param child the completed child block
 * @param nc the context
 * @param rm the request manager
 */
void childDownloadCompleted(IBlock * parent,
			    Block * child,
			    NodeContext * nc,
			    RequestManager * rm) {
  unsigned int i;
  unsigned int pendingChildren;
#if DEBUG_BLOCK
  LOG(LOG_DEBUG,
      "childDownloadCompleted %p %p\n",
      parent, 
      child);
#endif
  GNUNET_ASSERT(parent->children != NULL);
  for (i=0;i<parent->childcount;i++) 
    if (parent->children[i] == child) 
      break;
  GNUNET_ASSERT(i != parent->childcount);
  parent->crcs[i] = crc32N(child->data, child->len);

  pendingChildren = 0;
  for (i=0;i<parent->childcount;i++) 
    if ( (parent->children[i] != NULL) &&
	 (parent->children[i]->status != BLOCK_PRESENT) )
      pendingChildren++;

  /* check if this IBlock is complete, if yes,
     go to our parent and notify that we are done! */
  if (parent->common.parent != NULL) {
    if (pendingChildren == 0) {
      if (crc32N(&parent->crcs[0], 
		 sizeof(int) * parent->childcount)
	  != parent->crc32) {
	LOG(LOG_FAILURE,
	    _("File corrupted (or bug)."));
	BREAK();
      }
      childDownloadCompleted(parent->common.parent,
			     &parent->common,
			     nc, 
			     rm);
    }
  } else { /* parent == NULL */
    if (pendingChildren == 0) {
      if ( (crc32N(&parent->crcs[0], 
		   sizeof(int) * parent->childcount)
	    != parent->crc32) ||
	   (crc32N(parent->common.data,
		   parent->common.len) 
	    != rm->topCrc32) ) {
	LOG(LOG_FAILURE,
	    _("File corrupted (or bug)."));
	GNUNET_ASSERT(0);
      }
    } /* end if no pending children */
  } /* end if top-block */

  /* free memory as early as possible! */
  if (pendingChildren == 0) {
    FREENONNULL(parent->common.data);
    parent->common.data = NULL;
  }
}

  
/**
 * Convert a root-node to a string (to display it
 * to the user).
 */
char * rootNodeToString(const RootNode * root) {
  char * ret;
  char * fstring;
  char * filename;

  switch (ntohs(root->header.major_formatVersion)) {
  case ROOT_MAJOR_VERSION:
    ret = MALLOC(1024+32);
   
    fstring = createFileURI(&root->header.fileIdentifier);

    if (0 == strcmp(&root->header.mimetype[0],
    		    GNUNET_DIRECTORY_MIME))
      filename = expandDirectoryName(&root->header.filename[0]);
    else
      filename = STRDUP(&root->header.filename[0]);

    SNPRINTF(ret,
	     1024+32,
	     _("File '%s': %s of mime-type '%s' (size %u)\n%s"),
	     filename,
	     &root->header.description[0],
	     &root->header.mimetype[0],
	     (unsigned int) ntohl(root->header.fileIdentifier.file_length),
	     fstring);
    FREE(filename);
    FREE(fstring);
    break;
  case SBLOCK_MAJOR_VERSION: {
    EncName enc;
    HashCode160 ns;
    SBlock * sb = (SBlock*) root;

    hash(&sb->subspace,
	 sizeof(PublicKey),
	 &ns);
    hash2enc(&ns, &enc);
    ret = MALLOC(1024+32);
    
    if (0 == strcmp(&sb->mimetype[0],
    		    GNUNET_DIRECTORY_MIME))
      filename = expandDirectoryName(&sb->filename[0]);
    else
      filename = STRDUP(&sb->filename[0]);

    /* FIXME: add creation time & update frequency */
    fstring = createFileURI(&sb->fileIdentifier);
    SNPRINTF(ret,
	     1024+32,
	     _("File '%s': %s of mime-type '%s'\n\tSize is %u bytes, from namespace '%s'\n\t%s"),
	     filename,
	     &sb->description[0],
	     &sb->mimetype[0],	   
	     (unsigned int) ntohl(sb->fileIdentifier.file_length),
	     (char*)&enc,
	     fstring);
    FREE(filename);
    FREE(fstring);
    break;
  }
  case NBLOCK_MAJOR_VERSION: {
    EncName enc;
    EncName r;
    const NBlock * sb = (const NBlock*) root;
    HashCode160 zero;

    memset(&zero, 0, sizeof(HashCode160));
    hash2enc(&sb->namespace, &enc);
    hash2enc(&sb->rootEntry, &r);
    ret = MALLOC(2048);
    
    if (equalsHashCode160(&zero,
			  &sb->rootEntry)) {
      SNPRINTF(ret,
	       2048,
	       _("Namespace %s (called '%.*s'):\n"
		 "\t'%.*s' with files of type '%.*s'\n"
		 "\t(Contact: '%.*s', URI: '%.*s', owner: '%.*s')"),
	       (char*) &enc,
	       MAX_NAME_LEN-8,
	       sb->nickname,
	       MAX_DESC_LEN/2,
	       sb->description,
	       MAX_MIMETYPE_LEN/2,
	       sb->mimetype,
	       MAX_CONTACT_LEN,
	       sb->contact,
	       MAX_CONTACT_LEN,
	       sb->uri,
	       MAX_NAME_LEN,
	       sb->realname);
    } else {
      SNPRINTF(ret,
	       2048,
	       _("Namespace %s (called '%.*s'):\n"
		 "\t'%.*s' with files of type '%.*s'\n"
		 "\t(Contact: '%.*s', URI: '%.*s', owner: '%.*s', root: '%s')"),
	       (char*) &enc,
	       MAX_NAME_LEN-8,
	       sb->nickname,
	       MAX_DESC_LEN/2,
	       sb->description,
	       MAX_MIMETYPE_LEN/2,
	       sb->mimetype,
	       MAX_CONTACT_LEN,
	       sb->contact,
	       MAX_CONTACT_LEN,
	       sb->uri,
	       MAX_NAME_LEN,
	       sb->realname,
	       (char*) &r);
    }
    break;
  }
  default:
    ret = MALLOC(64);
    SNPRINTF(ret, 
	     64,
	     _("Unknown format with ID %d:%d"),
	     ntohs(root->header.major_formatVersion),
	     ntohs(root->header.minor_formatVersion));
    break;
  }
  return ret;
}

/**
 * Obtain the description from a RootNode or SBlock.
 * 
 * @param root the node with meta-data
 * @return a copy of the description (client must free!)
 */
char * getDescriptionFromNode(const RootNode * root) {
  switch (ntohs(root->header.major_formatVersion)) {
  case ROOT_MAJOR_VERSION:
    return STRNDUP(&root->header.description[0],
		   MAX_DESC_LEN);
  case SBLOCK_MAJOR_VERSION: {
    SBlock * sb = (SBlock*) root;
    return STRNDUP(&sb->description[0],
		   MAX_DESC_LEN);
  }
  case NBLOCK_MAJOR_VERSION: {
    NBlock * sb = (NBlock*) root;
    return STRNDUP(&sb->description[0],
		   MAX_DESC_LEN/2);
  }
  default:
    return STRDUP(_("Unsupported node type."));
  }
}

/**
 * Obtain the mime-type from a RootNode or SBlock.
 * 
 * @param root the node with meta-data
 * @return a copy of the mime-type (client must free!)
 */
char * getMimetypeFromNode(const RootNode * root) {
  switch (ntohs(root->header.major_formatVersion)) {
  case ROOT_MAJOR_VERSION:
    return STRNDUP(&root->header.mimetype[0],
		   MAX_MIMETYPE_LEN);
  case SBLOCK_MAJOR_VERSION: {
    SBlock * sb = (SBlock*) root;
    return STRNDUP(&sb->mimetype[0],
		   MAX_MIMETYPE_LEN/2);
  }
  case NBLOCK_MAJOR_VERSION: {
    NBlock * sb = (NBlock*) root;
    return STRNDUP(&sb->mimetype[0],
		   MAX_MIMETYPE_LEN/2);
  }
  default:
    return STRDUP(_("unknown"));
  }
}
 
/**
 * Obtain the filename from a RootNode or SBlock.  For
 * NBlocks the nickname of the namespace is returned.
 * 
 * @param root the node with meta-data
 * @return a copy of the filename (client must free!)
 */
char * getFilenameFromNode(const RootNode * root) {
  switch (ntohs(root->header.major_formatVersion)) {
  case ROOT_MAJOR_VERSION:
    return STRNDUP(&root->header.filename[0],
		   MAX_FILENAME_LEN);
  case SBLOCK_MAJOR_VERSION: {
    SBlock * sb = (SBlock*) root;
    return STRNDUP(&sb->filename[0],
		   MAX_FILENAME_LEN/2);
  }
  case NBLOCK_MAJOR_VERSION: {
    NBlock * sb = (NBlock*) root;
    return STRNDUP(&sb->nickname[0],
		   MAX_NAME_LEN-8);
  }
  default:
    return STRDUP(_("Unsupported node type."));
  }
}



/* end of block.c */
