/*
     This file is part of GNUnet

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
 * @file include/gnunet_afs_esed2.h
 * @brief support for ESED2 encoding of files 
 * @author Christian Grothoff
 */

#ifndef GNUNET_AFS_ESED2_H
#define GNUNET_AFS_ESED2_H

#include "gnunet_util.h"
#include "gnunet_core.h"


/**
 * Just the version number of the AFS implementation.
 * History:
 *
 * 1.x.x: initial version with triple hash and merkle tree
 * 2.x.x: root node with mime-type, filename and version number
 * 2.1.x: combined CHK/3HASH encoding with 25:1 super-nodes
 * 2.2.x: with directories
 * 3.0.x: with namespaces
 * 3.1.x: with namespace meta-data
 * 3.2.x: with collections
 * 4.x.x: with expiration (future work)
 */

#define AFS_VERSION "3.2.0"

/* size of the Blocks we slice file data into 
   (DBlocks and IBlocks). Never change this! */
#define CONTENT_SIZE 1024

/**
 * @brief basic transmission unit for content in GNUnet
 *
 * A CONTENT_Block, representative of the structure
 * of the leaf nodes (a simple chunk of 1 kb of data)
 */
typedef struct {
  unsigned char content[CONTENT_SIZE]; 
} CONTENT_Block;

/**
 * @brief Pair of Hashcodes for CHK encoded blocks.
 *
 * Every DBlock and IBlock is represented by two
 * hashcodes, one is the key used to encrypt or
 * decrypt the block; the other one is used to
 * search for the block without reveiling the key.
 * See also Freenet's CHK keys.<p>
 * 
 * Note that GNUnet uses a different encoding for
 * the RBlocks (root-nodes) in order to make searches
 * possible.
 */
typedef struct {

  /**
   * The hash of the plaintext is the key to decrypt.
   */
  HashCode160 key;

  /**
   * The hash of the encrypted block is the query.
   */
  HashCode160 query;

} CHK_Hashes;

/* ********* IOContext for encapsulation of IO ********** */

/**
 * @brief IO context for reading-writing AFS file blocks.
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
  int treedepth;
  
  /**
   * A lock for each file-handle for synchronizing access.
   */
  Mutex * locks;

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
		    int rdOnly);

/**
 * Read method.
 *
 * @param this reference to the IOContext
 * @param level level in the tree to read/write at
 * @param pos position where to read or write
 * @param buf where to read from or write to
 * @param len how many bytes to read or write
 * @return number of bytes read or written, SYSERR on error  
 */
int readFromIOC(struct IOContext * this,
		int level,
		size_t pos,
		void * buf,
		int len);

/**
 * Write method.
 *
 * @param this reference to the IOContext
 * @param level level in the tree to read/write at
 * @param pos position where to read or write
 * @param buf where to read from or write to
 * @param len how many bytes to read or write
 * @return number of bytes read or written, SYSERR on error  
 */
int writeToIOC(struct IOContext * this,
	       int level,
	       size_t pos,
	       void * buf,
	       int len);

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
	     int unlinkTreeFiles);

/* ******************* the request manager ************* */

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
  struct RequestEntry ** requestList;

  /**
   * Number of pending requests (highest used index)
   */
  int requestListIndex;

  /**
   * Number of entries allocated for requestList
   */
  int requestListSize;

  /**
   * Current "good" TTL (initial) [64s].  In HOST byte order.
   */
  unsigned int initialTTL;

  /**
   * Congestion window.  How many messages
   * should be pending concurrently?
   */
  int congestionWindow;

  /**
   * Slow-start threshold (see RFC 2001)
   */
  int ssthresh;

  /**
   * Current estimate of "duplication" rate (amount of
   * duplicate replies we get).
   */
  int duplicationEstimate;

  /**
   * Socket used to talk to gnunetd.
   */
  GNUNET_TCP_SOCKET * sock;

  /**
   * The thread that receives results from gnunetd.
   */
  PTHREAD_T receiveThread_;

  TIME_T lastDET;

  struct RequestContinuation * start;

  /**
   * CRC of the top-IBlock, see downloadutil.c and
   * block.c::childDownloadCompleted.
   */ 
  int topCrc32;

  /**
   * The top block.
   */
  struct Block * top;

} RequestManager;


/**
 * @brief client-server message for search results
 *
 * Used in the CS-TCP communication: search result content send back
 * by gnunetd
 */
typedef struct {

  /**
   * The TCP header (values: sizeof(AFS_CS_RESULT_CHK), AFS_CS_PROTO_RESULT_CHK) 
   */ 
  CS_HEADER header;

  /**
   * The search result.
   */
  CONTENT_Block result;

} AFS_CS_RESULT_CHK;

/**
 * @brief type of callback used by nodes in the merkle tree to receive
 * content-arrived notifications from the RequestManager
 *
 * Type of a method that is called by the RequestManager
 * whenever a reply to a query has been received.
 *
 * @param this the node in the tree for which the request
 *       was issued
 * @param query the query that was sent out
 * @param reply the reply that was received
 * @param rm the handle for the request manager
 * @param data an opaque handle that is passed along,
 *        typically used to pass the NodeContext
 * @return SYSERR the request manager should abort the download
 */
typedef int (*Listener)(void * this,
			const HashCode160 * query,
			AFS_CS_RESULT_CHK * reply,
			struct RequestManager * rm,
			void * data); 


/**
 * @brief peer-to-peer message containing a set of queries.
 */
typedef struct {

  /** 
   * The TCP header (values: sizeof(AFS_CS_QUERY), AFS_CS_PROTO_QUERY) 
   */ 
  CS_HEADER header; 

  /**
   * how important is this request (network byte order) 
   */  
  unsigned int priority; 

  /**
   * time to live in cronMILLIS (network byte order) 
   */
  int ttl;      

} AFS_CS_QUERY;

typedef struct {
  AFS_CS_QUERY afs_cs_query;

  /**
   * Hashcodes of the file(s) we're looking for. If multiple queries
   * are given, the first query is the super-query for the bloom
   * filter.
   */
  HashCode160 queries[1];

} AFS_CS_QUERY_GENERIC;

/**
 * @brief Format of a request as tracked by the RequestManager.
 */
typedef struct RequestEntry {

  /**
   * The message that is send to gnunetd.
   */
  AFS_CS_QUERY * message;
  
  /**
   * Last time the query was send.
   */
  cron_t lasttime;

  /**
   * Whom to call once we get a reply?
   */
  Listener receiver;

  /**
   * The node to pass to the receiver method.
   */
  struct Block * receiverNode;

  /**
   * Opaque data handle to pass to the Listener.
   */
  void * data;

  /**
   * How long have we been actively trying this one?
   */
  int tries;

  /**
   * How many replies have we received for this entry?
   * (for super-queries, thus always in [0,25]).
   * [reset for each retransmission; used
   *  to NOT increment the TTL if we got a reply]
   */
  unsigned int successful_replies;

} RequestEntry;

/* ************* context and Block **************** */

/**
 * @brief statistics about the progress
 *
 * Progress of the current operation. Used for passing
 * data to callbacks. Some of these make sense only for 
 * downloading.
 */
typedef struct ProgressStats {

  unsigned long long progress;			/* bytes processed */
  unsigned long long filesize;			/* total file size */
  int requestsSent;
  int requestsPending;
  int currentRetries;
  int totalRetries;
  int currentTTL;
  int duplicationEstimate;

} ProgressStats;


/**
 * @brief callback for updates on the progress of an operation
 *
 * Called whenever we make progress. Callback methods
 * of this type are used during insertion and download to notify the
 * user interface of the progress we're making. If the model is called
 * with position == total, the download is complete. If the model
 * is called with position == total == 0, then there was a fatal error
 * and the download was aborted.
 * 
 * @param current progress statistics
 * @param data a context passed around for use by the PM
 *        implementation
 */
typedef void (*ProgressModel)(ProgressStats * stats,
			      void * data);

/**
 * @brief context information for the merkle-tree objects
 *
 * The NodeContext groups the IOC and the progress model
 * into a single struct.
 */
typedef struct NodeContext {
  
  /**
   * The IO context for IO operations.
   */
  IOContext ioc;

  /**
   * Priority
   */
  unsigned int priority;

  /**
   * Index of the file that we are indexing, 0 for insertion
   */
  unsigned short index;
 
  /**
   * The ProgressModel to communicate status updates.
   */
  ProgressModel pmodel;

  /**
   * Data argument to the ProgressModel.
   */
  void * data;

  /**
   * Current progress so far.
   */
  ProgressStats stats;

} NodeContext;

typedef struct RequestContinuation {
  NodeContext * nc;
  RequestEntry * entry;
  /* in HOST byte order! */
  unsigned int ttl;
  /* in HOST byte order! */
  unsigned int prevttl;
  unsigned int prevpri;
  cron_t prevlt;  
  struct RequestContinuation * next;
} RequestContinuations;



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
 * @param ioc the IO context
 * @param sock the socket to use to talk to the core, NULL if
 *        we just do a "fake" insert to compute the tree in memory
 * @return OK on success, SYSERR on error
 */
typedef int (*Inserter)(void * this,
			NodeContext * nc,
			GNUNET_TCP_SOCKET * sock);

/**
 * Download this node (and the children below). Note that the
 * processing is asynchronous until the pmodel is called with position
 * == total (and thus no more requests are pending) or the request
 * manager is aborted by the user.
 * 
 * @param this the node that should be inserted or indexed
 * @param nc the context
 * @param rm the request manager
 */
typedef void (*Downloader)(void * this,
			   NodeContext * nc,
			   struct RequestManager * rm);

/**
 * Check if this block is already present, if yes,
 * loads it.
 *
 * @param this the block to check
 * @param nc the context
 * @return YES if the block is present, NO if not
 */
typedef int (*PresentChecker)(void * this,
			      NodeContext * nc);

/**
 * Print the block summary (for debugging)
 */
typedef void (*BlockPrinter)(void * this,
			     int ident);

/**
 * Free the associated resources of this Block. DOES ALSO free the
 * memory occupied by the Block struct itself!
 *
 * @param this reference to the Block
 */
typedef void (*Block_Destructor)(void * this,
				 RequestManager * rm);

typedef struct {
  /**
   * Free resources of the Block.
   */
  Block_Destructor done;
  
  /**
   * Insert the block.
   */
  Inserter insert;

  /**
   * Delete the block (same type as insert since totally symmetric).
   */
  Inserter delete;

  /**
   * Download the block.
   */
  Downloader download;

  /**
   * Listener method to receive a reply for the block.
   */
  Listener receive;

  /**
   * Check if the block is present.
   */
  PresentChecker isPresent;

  /**
   * Print the node to the logger.
   */
  BlockPrinter print;

} Block_VTBL;

/**
 * @brief Shared structure used in the internal objectish representation
 *        of all blocks (DBlocks and IBlocks) in the merkle-tree.
 */
typedef struct Block {

  Block_VTBL * vtbl;

  /**
   * The total size of the file.
   */
  size_t filesize;

  /**
   * Position of the block relative to the beginning of the file.
   */
  size_t pos;

  /**
   * Hashes of the plaintext block (key) and the encrypted block
   * (query).
   */
  CHK_Hashes chk;

  /**
   * How many bytes in data are actual data (not padding)?
   * Set to 0 to indicate that the download of this block
   * is complete.
   */
  unsigned int len;

  /**
   * Pointer to the data of this block, NULL if the data is not yet
   * available.
   */
  void * data;

  /**
   * The parent node in the file-tree, NULL for the node on top of the
   * file-tree.
   */
  struct IBlock * parent;

  /**
   * See BLOCK_XXX constants.
   */
  short status;

} Block; /* total: 94 bytes, 24 bytes could be saved by using a shared-VTBL 
	    and status-bits to indicate which one is used */

/**
 * Block is freshly created, nothing has been done.
 */
#define BLOCK_CREATED 0

/**
 * We know the correct block data and is is on the drive
 * (and in memory if data != NULL)
 */
#define BLOCK_PRESENT 1

/**
 * We do not know the correct data, but we have not done a
 * request yet. It may be that we can construct the data from
 * the children (if they are present).
 */
#define BLOCK_NOT_PRESENT 2

/**
 * We have a request pending for this block (either with the
 * parent if parent != NULL) or a direct request if 
 * parent == NULL.
 */
#define BLOCK_PENDING 3

/**
 * This block is present and all children (transitively)
 * are also present.
 */
#define BLOCK_CHILDREN_PRESENT 4

/**
 * This iblock has a super-query pending.
 */
#define BLOCK_SUPERQUERY_PENDING 5

/**
 * This block is done (about to be freed).
 */
#define BLOCK_DONE 6

/**
 * This block shall not be freed, even if all children
 * are dead.
 */
#define BLOCK_PERSISTENT 7

/* ****************** Leaf struct ************************ */

/**
 * @brief leaf (level-zero node) in the merkle-tree. 
 */
typedef struct DBlock {

  /**
   * The shared properties of all types of blocks.
   */
  Block common;

} DBlock;
		
/**
 * Create a top-DBlock for files <= 1k where there is no parent
 * IBlock. Note that you must set the chk field before calling
 * download.
 *
 * @param filesize the size of the file 
 * @return the DBlock on success, NULL on failure
 */
Block * createTopDBlock(size_t filesize);
			 
 
/* ******************** Inner nodes ********************* */

/**
 * Number of CHK_Hashes per IBlock. The value must be 25 since
 * 25*40+20+4 is 1024. The other values are 40=sizeof(CHK_Hashes),
 * 20=sizeof(HashCode160) for the super-hash and 4=sizeof(int) for the
 * CRC32.
 */
#define CHK_PER_INODE 25

/**
 * @brief format of an IBlock.
 */
typedef struct IBlockData {

  /**
   * The super-Hashcode for retrieving all CHK_PER_INODE sub-nodes in one
   * big lookup. This hash is the hash of the concatenation
   * of all encrypted CHK_PER_INODE children of this node.
   */
  HashCode160 superHash;

  /**
   * The CRC32 checksum of the sub-blocks (crc32N of
   * the concatenation of the individual crc32N's over
   * the plaintext-data (without padding) of each block).
   */
  int crc32;

  /**
   * The keys and queries for the nodes one level below.
   * This entry must be at the end since it is variable
   * size!
   */
  CHK_Hashes chks[CHK_PER_INODE];

} IBlockData;

/**
 * @brief internal OO representation of an IBlock (inner node) in the
 * merkle-tree. 
 */
typedef struct IBlock {

  /**
   * The shared properties of all types of blocks.
   */
  Block common;

  /**
   * The depth of this node in the file tree.
   * At depth 0 we have the leaves, since this is
   * an IBlock, depth is always > 0.
   */
  unsigned int depth;

  /**
   * Number of children [1-CHK_PER_INODE] of this node.
   */
  unsigned int childcount;

  /**
   * CRC (if (data != NULL): ((IBlockData)data)->crc32).
   */
  unsigned int crc32;

  /**
   * References to the children (IBlocks or DBlocks, 
   * depending on if depth > 1 or not).
   */
  Block ** children;

  /**
   * CRC of each of the children.
   */
  int crcs[CHK_PER_INODE];

  /**
   * Pointer to the parent IBlock.
   */
  struct IBlock * parent;

} IBlock;

/**
 * Create an IBlock. Use createTopIBlock for the
 * node on top of the file-tree.
 *
 * @param pos the position of the IBlock in the file
 * @param parent the parent block (may not be NULL)
 * @return the IBlock 
 */
Block * createIBlock(size_t pos,
		     IBlock * parent);

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
		     IBlock * parent);
	
/**
 * Create a top-IBlock for the root of the file tree.
 * Note that you must set the chk field before calling
 * download. 
 * @param filesize the size of the file
 */
Block * createTopIBlock(size_t filesize);

/**
 * A child has been completely downloaded. Perform the
 * appropriate checks in the parent node and free associated
 * resources if possible. Since the only errors are either
 * bugs or hash-crc-collisions (probability 1:2^160), we
 * always die on errors (return values do not work well for
 * async calls anyway).<p>
 * 
 * Note that the leaves update the ProgressModel, so we do
 * not have to worry about that.
 *
 * @param parent the IBlock
 * @param child the completed child block
 * @param nc the context (IO, priority, etc.)
 * @param rm request manager to schedule queries
 */
void childDownloadCompleted(struct IBlock * parent,
			    Block * child,
			    NodeContext * nc,
			    RequestManager * rm);


/* ***************** the root **************************** */

#define MAX_DESC_LEN     256
#define MAX_FILENAME_LEN 128
#define MAX_MIMETYPE_LEN 128
#define MAX_NAME_LEN 64
#define MAX_CONTACT_LEN 64

/* major/minor format versions (current) */
#define ROOT_MINOR_VERSION 0
#define ROOT_MAJOR_VERSION 1
#define SBLOCK_MINOR_VERSION 0
#define SBLOCK_MAJOR_VERSION 2
#define NBLOCK_MINOR_VERSION 0
#define NBLOCK_MAJOR_VERSION 3

/**
 * @brief information required to download a file from GNUnet
 *
 * A FileIdentifier groups the information
 * required to download (and check) a file.
 */
typedef struct {
  
  /**
   * Total size of the file in bytes. (network byte order (!)) 
   * FIXME: Change to unsigned long long once we break
   * backwards compatibility (to ensure correctness on 64-bit
   * size_t-systems).
   */
  unsigned int file_length;

  /**
   * Top CRC of the tree-encoding. (network byte order (!)) 
   */
  int crc;

  /**
   * Query and key of the top IBlock.
   */
  CHK_Hashes chk;
} FileIdentifier;

/**
 * @brief header of the RootNode (search result with meta-data)
 * 
 * The structure of the root node - contains pertinent information for
 * the file (file length, checksum, hashcode of main indirection node,
 * description length, and description.
 */
typedef struct {
   
  /**
   * Major format version, in network byte order 
   */
  unsigned short major_formatVersion;
  
  /**
   * Minor format version, in network byte order 
   */
  unsigned short minor_formatVersion;
  
  /**
   * Information required for the download.
   */
  FileIdentifier fileIdentifier;

  /**
   * description of the contents, padded with zeros.
   */
  char description[MAX_DESC_LEN];

  /**
   * suggested filename, padded with zeros. 
   */
  char filename[MAX_FILENAME_LEN];
  
  /**
   * mime-type (as claimed by insertion!) 
   */
  char mimetype[MAX_MIMETYPE_LEN];

} RootNodeHeader;

/**
 * @brief full CONTENT_SIZE'ed root node
 *
 * The structure of the root node, including padding to make
 * it to 1k.
 */
typedef struct {

  /**
   * The real data in the root-node 
   */
  RootNodeHeader header;

  /**
   * Padding 
   */
  char padding[CONTENT_SIZE - sizeof(RootNodeHeader)];

} RootNode;

/**
 * Convert a root-node to a string (to display it
 * to the user).
 */
char * rootNodeToString(const RootNode * root);


/**
 * Obtain the description from a RootNode or SBlock.
 * 
 * @param root the node with meta-data
 * @return a copy of the description (client must free!)
 */
char * getDescriptionFromNode(const RootNode * root);

/**
 * Obtain the mime-type from a RootNode or SBlock.
 * 
 * @param root the node with meta-data
 * @return a copy of the mime-type (client must free!)
 */
char * getMimetypeFromNode(const RootNode * root);
 
/**
 * Obtain the filename from a RootNode or SBlock.
 * 
 * @param root the node with meta-data
 * @return a copy of the filename (client must free!)
 */
char * getFilenameFromNode(const RootNode * root);

/**
 * @brief data structure SBlock
 */
typedef struct {
  /* ENCRYPTED portion (with H(keyword) == identifier): */
  /**
   * Major format version, in network byte order 
   */
  unsigned short major_formatVersion;
  
  /**
   * Minor format version, in network byte order 
   */
  unsigned short minor_formatVersion;

  FileIdentifier fileIdentifier; /* 48 b */
  char description[MAX_DESC_LEN]; /* 256 b */
  char filename[MAX_FILENAME_LEN/2]; /* 64 b */
  char mimetype[MAX_MIMETYPE_LEN/2]; /* 64 b */
  TIME_T creationTime; /* in network byte order */
  TIME_T updateInterval; /* in network byte order, see below */
  HashCode160 nextIdentifier; /* N,  20 b */
  HashCode160 identifierIncrement; /* I, 20 b */

  /* NOT ENCRYPTED starting here! */
  HashCode160 identifier; /* R = H(N-I)^S */
  /* NOT SIGNED, starting here! */
  Signature signature; /* 256 b */
  PublicKey subspace; /* S = H(subspace); 264 b */
} SBlock; /* total: 1024 bytes */

/**
 * @brief data structure for namespace information (NBlock).
 * An NBlock is a very special kind of SBlock that does not
 * refer to a file but rather describes a namespace.  It is
 * published to advertise the namespace and helps users manage
 * namespaces by associating more meaningful descriptions with
 * the public key.  NBlocks are encrypted, verified and routed
 * just like SBlocks.
 */
typedef struct {
  /* ENCRYPTED portion (with H(keyword) == identifier): */   
  /**
   * Major format version, in network byte order
   */
  unsigned short major_formatVersion;
  
  /**
   * Minor format version, in network byte order 
   */
  unsigned short minor_formatVersion;
  
  /**
   * Identifier of the namespace
   */
  HashCode160 namespace;

  /**
   * Key of an (optional) root entry into the namespace
   * (use all-zeros for not given).
   */
  HashCode160 rootEntry;
  
  /**
   * description of the contents, padded with zeros.
   */
  char description[MAX_DESC_LEN/2];

  /**
   * suggested nickname for the namespace, padded with zeros. 
   * (Note that -8 is used to achieve a struct of exactly 1k).
   */
  char nickname[MAX_NAME_LEN-8];

  /**
   * Claimed 'real' name of the owner of the 
   * namespace, padded with zeros.
   */
  char realname[MAX_NAME_LEN];
  
  /**
   * mime-type for the content in the namespace
   * (as claimed by insertion!); use 'any' for
   * namespaces with different types of files.
   */
  char mimetype[MAX_MIMETYPE_LEN/2];

  /**
   * URI with additional description about the
   * namespace (free format)
   */
  char uri[MAX_CONTACT_LEN];

  /**
   * Contact information about the namespace owner.
   * (free format, i.e. E-mail address)
   */
  char contact[MAX_CONTACT_LEN];  

  /* NOT ENCRYPTED starting here! */
  /**
   * This identifies this entry as the official 
   * namespace description.  Must be all zeros.
   */
  HashCode160 identifier;

  /* NOT SIGNED, starting here! */
  Signature signature; /* 256 b */

  PublicKey subspace; /* S = H(subspace); 264 b */

} NBlock;


/**
 * Fixed SBlock updateInterval codes. Positive values 
 * are interpreted as durations (in seconds) for periodical 
 * updates.
 */
#define SBLOCK_UPDATE_SPORADIC  -1 
#define SBLOCK_UPDATE_NONE       0

/**
 * Verify that a given SBlock is well-formed.
 */
int verifySBlock(const SBlock * sb);

/**
 * Compute the "current" ID of an updateable SBlock.  Will set the ID
 * of the sblock itself for non-updateable content, the ID of the next
 * identifier for sporadically updated SBlocks and the ID computed from
 * the timing function for periodically updated SBlocks.
 *
 * @param sb the SBlock (must be in plaintext)
 * @param c the resulting current ID (set)
 */
void computeIdAtTime(const SBlock * sb,
		     TIME_T now,
		     HashCode160 * c);

/**
 * Build an SBlock.
 *
 * @param interval the update frequency (0: never, -1: sporadic)
 * @param k the key for this SBlock
 * @param n the key for the next SBlock (if updateable)
 */
SBlock * buildSBlock(const PrivateKey pseudonym,
		     const FileIdentifier * fi,
		     const char * description,
		     const char * filename,
		     const char * mimetype,
		     TIME_T creationTime,
		     TIME_T interval,
		     const HashCode160 * k,
		     const HashCode160 * n);
	
/**
 * Insert the SBlock
 *
 * @return OK on success, SYSERR on error
 */
int insertSBlock(GNUNET_TCP_SOCKET * sock,
		 const SBlock * sb);

/**
 * Method to test if the receive-thread should
 * terminate.
 */
typedef int (*TestTerminateThread)(void * context);

/**
 * Type of a callback method for results that have
 * been received.
 *
 * @param sb the plaintext of the SBlock that has been received
 * @param data the opaque handle (context for the callee)
 */
typedef void (*NSSearchResultCallback)(const SBlock * sb,
				       void * data);

/**
 * Retrieve an SBlock.
 * 
 * @param sock socket to use to contact gnunetd
 * @param s namespace which namespace to search
 * @param k key to decrypt the SBlock in the namespace (query
 *        to identify the block is derived from k)
 * @param testTerminate function to poll for abort
 * @param ttContext argument for testTerminate
 * @param resultCallback function to call for results
 * @param closure argument to pass to resultCallback
 * @return OK on success, SYSERR on error
 */
int searchSBlock(GNUNET_TCP_SOCKET * sock,
		 const HashCode160 * s,
		 const HashCode160 * k,
		 TestTerminateThread testTerminate,
		 void * ttContext,
		 NSSearchResultCallback resultCallback,
		 void * closure);

/**
 * Print the information contained in an SBlock.
 *
 * @param stream where to print the information to (of type FILE*)
 * @param sb the SBlock -- in plaintext.
 */
void printSBlock(void * stream,
		 const SBlock * sb);

void decryptSBlock(const HashCode160 * k,
		   const SBlock * in,
		   SBlock * out);


/**
 * Message types for the GNUnet AFS.
 */

/**
 * by which amount do we decrement the TTL for simple forwarding /
 * indirection of the query; in milli-seconds.  Set somewhat in
 * accordance to your network latency (above the time it'll take you
 * to send a packet and get a reply).
 */
#define TTL_DECREMENT 5 * cronSECONDS

/* *********** STRUCTS for the p2p protocol *********** */

/**
 * Request for content. The number of queries can
 * be determined from the header size.
 */
typedef struct {
  p2p_HEADER header; 

  /**
   * How important is this request (network byte order) 
   */
  int priority;         

  /**
   * Time to live in cronMILLIS (network byte order)  
   */
  int ttl;              

  /**
   * To whom to return results? 
   */
  PeerIdentity returnTo;

} AFS_p2p_QUERY;

typedef struct {

  AFS_p2p_QUERY afs_p2p_query;

  /**
   * Hashcodes of the file(s) we're looking for. If multiple queries
   * are given, the first query is the super-query for the bloom
   * filter. If only one query is given, the bloom filter should NOT
   * be used since it does not contain summaries for simple 1k
   * blocks. It is not possible to group multiple queries with this
   * message type if they are not dominated by the same super-query.
   */
  HashCode160 queries[1]; 

} AFS_p2p_QUERY_GENERIC;

/**
 * Request for content from a namespace.
 */
typedef struct {
  /* the header must be identical to an AFS_p2p_QUERY
     (except that the type field is different).
     Note that the queries[] is always considered
     "empty", instead, we have the namespace and
     the identifier */
  AFS_p2p_QUERY hdr; 

  /**
   * Namespace that we are restricted to
   */
  HashCode160 namespace; 

  /**
   * Identifier that we are looking for.
   */
  HashCode160 identifier; 

} AFS_p2p_NSQUERY;

/**
 * Return message for search result (with double-hash proof).
 */
typedef struct {
  p2p_HEADER header;   

  /**
   * The double-hash
   */
  HashCode160 hash;

  /**
   * The search result.
   */
  RootNode result;

} AFS_p2p_3HASH_RESULT;

/**
 * Return message for content download (CHK style)
 */
typedef struct {
  p2p_HEADER header;   

  /**
   * The search result.
   */
  CONTENT_Block result;

} AFS_p2p_CHK_RESULT;

/**
 * Return message for SBlock download
 */
typedef struct {
  p2p_HEADER header;   

  /**
   * The search result.
   */
  SBlock result;

} AFS_p2p_SBLOCK_RESULT;

/* ************************* CS messages ********************** */
/* these messages are exchanged between gnunetd and the clients */

/**
 * TCP communication: search result content send back by gnunetd
 */
typedef struct {

  /**
   * The TCP header (values: sizeof(AFS_CS_RESULT_3HASH), AFS_CS_PROTO_RESULT_3HASH) 
   */ 
  CS_HEADER header;

  /**
   * The double-hash 
   */
  HashCode160 hash;

  /**
   * The search result.
   */
  RootNode result;

} AFS_CS_RESULT_3HASH;

/* NOTE: AFS_CS_QUERY and AFS_CS_RESULT_CHK
   had to be defined in encoding/block.h */

/**
 * @brief client-server message for SBlock results
 *
 * Used in the CS-TCP communication: SBlock result content send back
 * by gnunetd
 */
typedef struct {

  /**
   * The TCP header (values: sizeof(AFS_CS_RESULT_SBLOCK), AFS_CS_PROTO_RESULT_SBLOCK) 
   */ 
  CS_HEADER header;

  /**
   * The search result.
   */
  SBlock result;

} AFS_CS_RESULT_SBLOCK;


/**
 * @brief peer-to-peer message containing a namespace-query
 */
typedef struct {

  /** 
   * The TCP header (values: sizeof(AFS_CS_NSQUERY), AFS_CS_PROTO_NSQUERY) 
   */ 
  CS_HEADER header; 

  /**
   * how important is this request (network byte order) 
   */  
  unsigned int priority; 

  /**
   * time to live in cronMILLIS (network byte order) 
   */
  int ttl;      

  /**
   * ID of the Namespace that we are searching in
   */
  HashCode160 namespace;

  /**
   * ID (in the namespace) that we're looking for
   */
  HashCode160 identifier;

} AFS_CS_NSQUERY;

/**
 * Structure for an incoming request messages from the local TCP link
 * to add content to the node.
 */
typedef struct {

  /**
   * The TCP header (values: sizeof(AFS_CS_INSERT_SBLOCK), AFS_CS_PROTO_INSERT_SBLOCK) 
   */ 
  CS_HEADER header; 

  /**
   * The (initial) priority of the data  (network byte order)
   */
  unsigned int importance;

  /**
   * The data to insert 
   */
  SBlock content;  

} AFS_CS_INSERT_SBLOCK;

/**
 * Structure for an incoming request messages from the local TCP link
 * to add content to the node.
 */
typedef struct {

  /**
   * The TCP header (values: sizeof(AFS_CS_INSERT_CHK), AFS_CS_PROTO_INSERT_CHK) 
   */ 
  CS_HEADER header; 

  /**
   * The (initial) priority of the data  (network byte order)
   */
  unsigned int importance;

  /**
   * The data to insert 
   */
  CONTENT_Block content;  

} AFS_CS_INSERT_CHK;

/**
 * Structure for an incoming request messages from the local TCP link
 * to add content to the node.
 */
typedef struct {

  /**
   * The TCP header (values: sizeof(AFS_CS_INSERT_3HASH), AFS_CS_PROTO_INSERT_3HASH) 
   */ 
  CS_HEADER header; 

  /**
   * The (initial) priority of the data  (network byte order)
   */
  unsigned int importance;

  /**
   * The doubleHash of the plaintext.
   */
  HashCode160 doubleHash;

  /**
   * The data to insert 
   */
  CONTENT_Block content;  

} AFS_CS_INSERT_3HASH;



/**
 * Free entry. Historical.
 */
#define LOOKUP_TYPE_FREE 0

/**
 * Historical.
 */
#define LOOKUP_TYPE_DELETED 1

/**
 * (migrated) CHK content.
 */
#define LOOKUP_TYPE_CHK 2

/**
 * Search result, never indexed (always inserted).
 */
#define LOOKUP_TYPE_3HASH 3

/**
 * Super-query. Add to superBloomFilter, does not
 * refer to any content in particular.
 */
#define LOOKUP_TYPE_SUPER 4

/**
 * CHK content covered by super-query (treat like CHK
 * except do not add to singleBloomFilter).
 */
#define LOOKUP_TYPE_CHKS 5

/**
 * SBlock content.
 */
#define LOOKUP_TYPE_SBLOCK 6



/**
 * Type of the content index file entries. The size of this
 * struct dominates the database size, so keep it as small
 * as possible. 32 byte should be enough!
 *
 * This structure is also used as a convenience struct to
 * pass arguments around the db. Perhaps not a good idea.
 *
 */
typedef struct {
  /**
   * The double-hash (hash of the hash of the plaintext) of this entry
   * for 3HASH entries, or the CHK query hash (hash of the encrypted
   * content) for CHK entries. Which is the case can be determined by
   * looking at fileNameIndex and fileOffset.
   */
  HashCode160 hash;

  /**
   * The current rating of this content (in network byte order).
   */
  unsigned int importance;

  /**
   * The type of the entry. See LOOKUP_TYPE_XXX
   *
   * The field is always in network byte order.
   */
  unsigned short type;

  /**
   * This field gives the index of the file into the
   * file-index module if the value is >0. If the
   * value is 0, the file is in the contentdatabase.
   *
   * The field is always in network byte order.
   */
  unsigned short fileNameIndex;

  /**
   * The offset in the file for on-demand-encoded files
   * where fileNameIndex is >0.<p>
   *
   * The field is always in network byte order.
   *
   * FIXME: change to unsigned long long once we break
   * compatibility to ensure correctness on 64-bit systems.
   */
  unsigned int fileOffset;
} ContentIndex;

/**
 * Structure for an incoming request messages from the local TCP link
 * to add content to the INDEX of the node.
 */
typedef struct {

  /**
   * The TCP header (values: sizeof(AFS_CS_INDEX_BLOCK), AFS_CS_PROTO_INDEX_BLOCK) 
   */ 
  CS_HEADER header; 

  /**
   * indexing information 
   */
  ContentIndex contentIndex;

} AFS_CS_INDEX_BLOCK;

#define CS_FILE_LIST_FILENAME 1024

/**
 * Structure for an incoming request messages from the local TCP link
 * to add a filename to the list of directly shared files
 */
typedef struct {

  /**
   * The TCP header (values: sizeof(AFS_CS_INDEX_FILE), AFS_CS_PROTO_INDEX_FILE) 
   */ 
  CS_HEADER header; 

  /**
   * Size of the file (NBO).
   */
  unsigned int filesize;

  /**
   * RIPE160MD hash of the entire file (to avoid duplicates!)
   */
  HashCode160 hash;

} AFS_CS_INDEX_FILE;

/**
 * Structure for uploading a file for AFS.
 */
typedef struct {

  /**
   * The TCP header (values: size, AFS_CS_PROTO_UPLOAD_FILE) 
   */ 
  CS_HEADER header; 

  /**
   * Position in the file (NBO)
   */
  unsigned int pos;

  /**
   * RIPE160MD hash of the entire file (to avoid duplicates!)
   */
  HashCode160 hash;

} AFS_CS_UPLOAD_FILE;

/**
 * Structure for uploading a file for AFS.
 */
typedef struct {

  AFS_CS_UPLOAD_FILE afs_cs_upload_file;

  /**
   * Data.
   */
  char data[1];

} AFS_CS_UPLOAD_FILE_GENERIC;

/**
 * Structure for uploading a file for AFS.
 */
typedef struct {

  /**
   * The TCP header (values: size, AFS_CS_PROTO_LINK_FILE) 
   */ 
  CS_HEADER header; 

  /**
   * RIPE160MD hash of the entire file (to avoid duplicates!)
   */
  HashCode160 hash;

} AFS_CS_LINK_FILE;

/**
 * Structure for linking to a file for AFS.
 */
typedef struct {

  AFS_CS_LINK_FILE afs_cs_link_file;

  /**
   * The filename.
   */
  char data[1];

} AFS_CS_LINK_FILE_GENERIC;

/**
 * Structure for an incoming request messages from the local TCP link
 * to add a super-query to the bloom filter.
 */
typedef struct {

  /**
   * The TCP header (values: sizeof(AFS_CS_INDEX_SUPER), AFS_CS_PROTO_INDEX_SUPER) 
   */ 
  CS_HEADER header; 

  /**
   * The super-hash for the bloom-filter.
   */
  HashCode160 superHash;

  /**
   * The (initial) priority of the data  (network byte order)
   */
  unsigned int importance;

} AFS_CS_INDEX_SUPER;

/**
 * @brief functions for building directories
 */

/* what is the context in which a root-node was discovered? */
#define DIR_CONTEXT_SEARCH    1
#define DIR_CONTEXT_INSERT    2
#define DIR_CONTEXT_DIRECTORY 4
#define DIR_CONTEXT_INSERT_SB 8

#define DIR_CONTEXT_ALL (DIR_CONTEXT_SEARCH|DIR_CONTEXT_INSERT|DIR_CONTEXT_DIRECTORY|DIR_CONTEXT_INSERT_SB)

/* see also: http://www.w3.org/TR/PNG#R.PNG-file-signature */
#define GNUNET_DIRECTORY_MAGIC "\211GND\r\n\032\n"
#define GNUNET_DIRECTORY_EXT ".gnd"
#define GNUNET_DIRECTORY_MIME "application/gnunet-directory"

/**
 * Format of a GNUnet directory (both in memory and on the drive).
 */ 
typedef struct {
  char MAGIC[8];

  /* in network byte order */
  unsigned int version;

  /* number of files in the directory */
  unsigned int number_of_files;

  /* description/filename of the directory */
  char description[MAX_DESC_LEN]; 

  /* must be zero for now */
  char reserved[sizeof(RootNode) - MAX_DESC_LEN - 16]; 

} GNUnetDirectory;

typedef struct {

  GNUnetDirectory gnunet_directory;

  /* number_of_files root-nodes */
  RootNode contents[1];

} GNUnetDirectory_GENERIC;  

/**
 * Makes a root-node available for directory building.
 *
 * This function is called whenever a root-node is encountered.  This
 * can either be because the user inserted a file locally; because we
 * received a search result or because the user retrieved a directory
 * with root-nodes.  From which context the root node was encountered
 * is specified in the context parameters.<p>
 *
 * makeRootNodeAvailable adds the node to the list of files that
 * we can build a directory from later.  The context is used to allow
 * the user to filter on root-node sources.
 * 
 * @param root the file identifier that was encountered
 * @param context the context in which the identifier was encountered (may not be a bitmask)
 */
void makeRootNodeAvailable(const RootNode * root,
			   unsigned int context);

/**
 * Remove all of the root-nodes of a particular type
 * from the directory database.
 *
 * @param context bitmask of the databases that should be emptied.
 */ 
void emptyDirectoryDatabase(unsigned int contexts);

/**
 * Callback function.
 * @param root a root-node
 * @param closure a closure
 */
typedef void (*RootNodeCallback)(const RootNode * root, 
				 void * closure);

/**
 * Iterate over all entries that match the given context
 * mask.
 *
 * @param contexts context bitmask for the entries to iterate over
 * @param callback function to call on each entry, may be NULL
 * @param closure extra argument to the callback
 * @return number of entries found
 */
int iterateDirectoryDatabase(unsigned int contexts,
			     RootNodeCallback callback,
			     void * closure);

/**
 * Build a GNUnet directory in memoy.
 * 
 * @param numberOfEntries how many files are in the directory
 * @param name what is the name of the directory
 * @param entries the entries in the directory
 * @return the directory
 */
GNUnetDirectory * buildDirectory(int numberOfEntries,
				 const char * name,
				 const RootNode * entries);

/**
 * Write a directory to a file.
 * 
 * @param dir the directory
 * @param fn the filename
 * @return OK on success, SYSERR on error
 */
int writeGNUnetDirectory(const GNUnetDirectory * dir,
			 const char * fn);

/**
 * Read a directory from a file.
 * 
 * @param fn the filename
 * @return the directory on success, NULL on error
 */
GNUnetDirectory * readGNUnetDirectory(const char * fn);


/**
 * Appends a suffix ".gnd" to a given string if the suffix
 * doesn't exist already. Existing suffix '/' is replaced if
 * encountered.
 *
 * @param dn the directory name (string)
 * @return the converted name on success, caller must free
 */
char * expandDirectoryName(const char * dn);


/**
 * deleteutil, helper methods for file deletion.
 */

/**
 * Deletes a file under the given name into the local GNUnet node.
 *
 * @param sock the socket to use to talk to gnunetd
 * @param filename the name of the (incoming/source) file
 * @param model the delete model used to
 *        update status information; points to NULL if
 *        no status updates shall be given, otherwise 
 *        to a method that takes two size_t arguments
 *        (retrieved so far, total).
 * @param model_data pointer that is passed to the model method
 * @return OK on success, SYSERR on error
 */
int deleteFile(GNUNET_TCP_SOCKET * sock,
	       const char * filename,
	       ProgressModel model,
	       void * model_data); 

/**
 * Insertutil, helper methods for file insertion.
 */

/**
 * Default priority for locally indexed content ("infty")
 */
#define LOCAL_INDEXED_CONTENT_PRIO 0xFFFF

/**
 * Inserts a file under the given name into the local GNUnet node.
 *
 * @param sock the socket to use to talk to gnunetd
 * @param filename the name of the (incoming/source) file
 * @param model the insert model used to
 *        update status information; points to NULL if
 *        no status updates shall be given, otherwise 
 *        to a method that takes two size_t arguments
 *        (retrieved so far, total).
 * @param model_data pointer that is passed to the model method
 * @return top IBlock on success, NULL on error
 */
Block * insertFile(GNUNET_TCP_SOCKET * sock,
		   const char * filename,
		   ProgressModel model,
		   void * model_data); 

/**
 * @param top the top block of the file
 * @param keywords the keywords that shall be used to retrieve the file
 * @param num_keys the number of keywords to be associated with the file
 * @param rootNode output, the root node (must be alloc'd by caller)
 * @return OK on success, SYSERR on error
 */
int insertRoot(GNUNET_TCP_SOCKET * sock,
	       const Block * top,
	       const char * description,
	       const char * filenameRoot,
	       const char * mimetype,
	       unsigned int num_keys,
	       const char ** keywords,
	       RootNode * rootNode);


/**
 * Creates root node for the tree and writes the top-level tree node.
 *
 * @param sock connection to gnunetd
 * @param rn the RootNode to insert
 * @param keyword the keyword under which the rn is inserted
 * @param contentPriority priority of the inserted content
 */
int insertRootWithKeyword(GNUNET_TCP_SOCKET * sock,
			  const RootNode * rn,
			  const char * keyword,
			  int contentPriority);

RootNode * createRootNode(const FileIdentifier * fid,
			  const char * description,
			  const char * shortFN,
			  const char * mimetype);

/**
 * Wrapper around insertFile that gives the user the appropriate
 * feedback.  The insertWrapper is expected to update fid at the
 * end of the insertion.  See "gnunet-insert.c::doFile()" for
 * a possible implementation.
 */
typedef int (*InsertWrapper)(GNUNET_TCP_SOCKET * sock,
			     const char * filename,
			     const FileIdentifier * fid,
			     void * closure);


/**
 * Build an RBlock for a directory (and insert the RBlock
 * into GNUnet under all applicable keywords). 
 *
 * @param fid the identifier for the file
 * @param dirName the name of the last component of the path to the directory
 * @param description the description for the file
 * @return the RBlock
 */
RootNode * buildDirectoryRBlock(GNUNET_TCP_SOCKET * sock,
				const FileIdentifier * fid,
				const char * dirName,
				const char * description,
				const char ** gloKeywords,
				unsigned int gloKeywordCnt);


/**
 * Inserts a directory.  Sets the file-identifier that can afterwards
 * be used to retrieve the directory.  Does NOT insert any RBlocks or
 * SBlocks.
 *
 * @param nodeCount how many rootNodes in the directory
 * @param rootNodes the actual nodes
 * @param dirName name of this directory
 * @param fid resulting file identifier for the directory
 * @returns SYSERR on failure, OK on success
 */
int insertDirectory(GNUNET_TCP_SOCKET * sock,
		    unsigned int nodeCount, 
		    const RootNode * rootNodes, 
		    const char * dirName,
		    FileIdentifier * fid,
		    ProgressModel model,
		    void * pmArg);




/**
 * Index or insert a file or directory.  Creates and inserts RootNodes
 * for the file if applicable.  Recursively processes directory if
 * applicable.  If directories are build or if filename refers to a
 * single file, a plaintext RootNode that identifies the inserted
 * object is returned and the FileIdentifier fid is set.  If we do not
 * create directories and a directory is given or if there was an
 * error, NULL is returned.  Every file encountered is inserted with
 * all specified global keywords and (if applicable) additional keywords
 * are extracted with the extractors.
 * 
 * @param filename the name of the file or directory
 * @param fid the identifier of the file or directory (set on success)
 * @param insert callback used to insert individual (leaf) files
 * @return RootNode that identifies the single file or directory or
 *      NULL on error or NULL if filename is a directory and we don't
 *      create directories.
 */
RootNode * insertRecursively(GNUNET_TCP_SOCKET * sock,
			     const char * filename,
			     FileIdentifier * fid,
			     const char ** gloKeywords,
			     unsigned int gloKeywordCnt,
			     void * extractors_,
			     ProgressModel model,
			     void * pmArg,
			     InsertWrapper insert,
			     void * iwArg);


/**
 * Layer to encapsulate the keyword extraction API and
 * make it accessible to gnunet-insert.
 */


/**
 * Extract keywords, mime-type and description from a file
 * @param filename the name of the file
 * @param description the description (the user may have
 *        supplied a description already (*description != NULL),
 *        in that case, append, mind the maximum size!
 * @param mimetype the mimetype, again, the user may
 *        have supplied one
 * @param keywords the list of keywords, allocate space at
 *        another location if required, copy existing keywords
 *        over to that space!
 * @param num_keywords the number of keywords in the
 *        existing *keywords array that was passed in.
 *        Set *num_keywords to the new number of keywords!
 */
void extractKeywords(const char * filename,
		     char ** description,
		     char ** mimetype,
		     char *** keywords,
		     int * num_keywords);


void * getExtractors();

/**
 * Extract keywords, mime-type and description from a file
 * @param filename the name of the file
 * @param description the description (the user may have
 *        supplied a description already (*description != NULL),
 *        in that case, append, mind the maximum size!
 * @param mimetype the mimetype, again, the user may
 *        have supplied one
 * @param keywords the list of keywords, allocate space at
 *        another location if required, copy existing keywords
 *        over to that space! Do NEVER free *keywords!
 * @param num_keywords the number of keywords in the
 *        existing *keywords array that was passed in.
 *        Set *num_keywords to the new number of keywords!
 * @param exList list of libextractor plugins, NULL if 
 *        libextractor is not used.  Of type EXTRACTOR_ExtractorList*
 */
void extractKeywordsMulti(const char * filename,
			  char ** description,
			  char ** mimetype,
			  char *** keywords,
			  int * num_keywords,
			  void * exList);

/**
 * @brief functions for handling pseudonyms
 */

/**
 * Create a new pseudonym. 
 *
 * @param name the name of the pseudonym
 * @param password passphrase to encrypt the pseudonym on disk (may be NULL)
 * @return NULL on error (e.g. pseudonym exists), otherwise the secret key
 */
PrivateKey createPseudonym(const char * name,
			const char * password);

/**
 * Delete a pseudonym.
 * 
 * @param name the name of the pseudonym
 * @return OK on success, SYSERR on error
 */
int deletePseudonym(const char * name);

/**
 * Read pseudonym.
 * 
 * @param name the name of the pseudonym
 * @param password passphrase to encrypt the pseudonym on disk (may be NULL)
 * @return NULL on error (e.g. password invalid, pseudonym does not exist), otherwise the secret key
 */
PrivateKey readPseudonym(const char * name,
		      const char * password);

/**
 * Test if we have any pseudonyms.
 *
 * @return YES if we do have pseudonyms, otherwise NO.
 */
int havePseudonyms();

/**
 * Build a list of all available pseudonyms.
 *
 * @param list where to store the pseudonyms (is allocated, caller frees)
 * @return SYSERR on error, otherwise the number of pseudonyms in list
 */
int listPseudonyms(char *** list);

/** 
 * @brief The RequestManager keeps track of queries and re-issues 
 *        requests if no reply is received.
 */ 

/**
 * Create a request manager. Will create the request manager
 * datastructures and also connect to gnunetd. Creates thread that
 * listens to gnunetd replies and another thread that periodically
 * re-issues the queries. Use destroyRequestManager to abort and/or to
 * free resources after the download is complete. The callback method
 * in nc will be invoked to notify the caller of the download progress
 * such that it is possible to tell when we are done.
 *
 * @return NULL on error
 */
RequestManager * createRequestManager();

/**
 * Destroy the resources associated with a request manager.
 * Invoke this method to abort the download or to clean up
 * after the download is complete.
 *
 * @param this the request manager struct from createRequestManager
 */
void destroyRequestManager(RequestManager * this);

/**
 * For debugging.
 */
void printRequestManager(RequestManager * this);

/**
 * Assert that there are no pending requests for this node.
 */
void requestManagerAssertDead(RequestManager * this,
			      Block * node);

/**
 * We are approaching the end of the download.  Cut
 * all TTLs in half.
 */
void requestManagerEndgame(RequestManager * this);

/**
 * Queue a request for execution.
 * 
 * @param this the request manager struct from createRequestManager
 * @param node the node to call once a reply is received
 * @param callback the method to invoke
 * @param data the data argument to the Listener
 * @param message the query to send to gnunetd, freed by callee!
 */
void requestManagerRequest(RequestManager * this,
			   Block * node,
			   Listener callback,
			   void * data,
			   AFS_CS_QUERY * message);


/**
 * Update a request. This method is used to selectively
 * change a query or drop it entirely.
 *
 * @param this the request manager struct from createRequestManager
 * @param node the block for which the request is updated
 * @param msg the new query message for that node, NULL for 
 *        none (then the request is dropped)
 */
void requestManagerUpdate(RequestManager * this,
			  Block * node,
			  AFS_CS_QUERY * msg);


/**
 * Helper functions for searching.
 */

/**
 * Type of a callback method for results that have
 * been received.
 *
 * @param root the RootNode of the result that has been received
 * @param data the opaque handle (context for the callee)
 */
typedef void (*SearchResultCallback)(RootNode * root,
				     void * data);


/**
 * Perform a namespace search.
 */
int searchRBlock(GNUNET_TCP_SOCKET * sock,
		 char ** keyStrings,
		 int keywordCount,
		 SearchResultCallback handler,
		 void * handlerArgs,
		 TestTerminateThread testTerminate,
		 void * ttContext);

/**
 * Helper functions for downloading.
 */

/**
 * Download a file.
 *
 * @param fi the file identifier 
 * @param fileName the name of the file
 * @param model the download model used to
 *        update status information; points to NULL if
 *        no status updates shall be given
 * @param data pointer that is passed to the model method.
 * @return a request manager that can be used to abort on 
 *         success, NULL on error
 */
RequestManager * downloadFile(const FileIdentifier * fi,
			      const char * fileName,
			      ProgressModel model,
			      void * data);




/**
 * Encrypts a given data block
 *
 * @param data represents the data block
 * @param hashcode represents the key concatenated with the initial
 *        value used in the alg
 * @param result where to store the result (encrypted block)
 * @returns OK on success, SYSERR on error
 */
int encryptContent(const CONTENT_Block * data,
		   const HashCode160 * hashcode,
		   CONTENT_Block * result);

/**
 * Decrypts a given data block
 *
 * @param data represents the data block
 * @param hashcode represents the key concatenated with the initial
 *        value used in the alg
 * @param result where to store the result (encrypted block)
 * @returns OK on success, SYSERR on error
 */
int decryptContent(const CONTENT_Block * data,
		   const HashCode160 * hashcode,
		   CONTENT_Block * result);


/**
 * Initialize the module.
 */
void initAnonymityPolicy(CoreAPIForApplication * capi);

/**
 * Shutdown the module.
 */
void doneAnonymityPolicy();

/**
 * Check if the anonymity policy will be violated if
 * a message of the given type will be send.
 * @param type the request type of the message that will be
 *        transmitted
 * @param size the size of the message that will be
 *        transmitted
 * @return YES if this is ok for the policy, NO if not
 */
int checkAnonymityPolicy(unsigned short type,
			 unsigned short size);

/* ************* URI handling **************** */

#define AFS_URI_PREFIX "gnunet://afs/"

/** 
 * Parses an AFS search URI.
 *
 * @param uri an uri string
 * @param keyword will be set to an array with the keywords
 * @return SYSERR if this is not a search URI, otherwise
 *  the number of keywords placed in the array
 */
int parseKeywordURI(const char * uri,
		    char *** keywords);

/** 
 * Parses an AFS namespace / subspace identifier URI.
 *
 * @param uri an uri string
 * @param namespace set to the namespace ID
 * @param identifier set to the ID in the namespace
 * @return OK on success, SYSERR if this is not a namespace URI
 */
int parseSubspaceURI(const char * uri,
		     HashCode160 * namespace,
		     HashCode160 * identifier);

/** 
 * Parses an URI that identifies a file
 *
 * @param uri an uri string
 * @param fi the file identifier
 * @return OK on success, SYSERR if this is not a file URI
 */
int parseFileURI(const char * uri,
		 FileIdentifier * fi);

/**
 * Generate a keyword URI.
 * @return NULL on error (i.e. keywordCount == 0)
 */
char * createKeywordURI(char ** keywords,
			unsigned int keywordCount);

/**
 * Generate a subspace URI.
 */ 
char * createSubspaceURI(const HashCode160 * namespace,
			 const HashCode160 * identifier);

/**
 * Generate a file URI.
 */ 
char * createFileURI(const FileIdentifier * fi);

/**
 * This method must be called to start the priority
 * tracker.
 */
void startAFSPriorityTracker();

/**
 * This method must be called to stop the priority
 * tracker.  Call after cron has been stopped.
 */
void stopAFSPriorityTracker();

/**
 * What is the highest priority that AFS clients should
 * use for requests at this point in time?
 */
unsigned int getMaxPriority();

/**
 * Change our evaluation of a namespace.
 * @param delta by how much should the evaluation be changed?
 * @return the new ranking for this namespace
 */
int evaluateNamespace(const HashCode160 * ns,
		      int delta);

/**
 * Verify that a given NBlock is well-formed.
 * @param sb the nblock
 */
int verifyNBlock(const NBlock * sb);

/**
 * Build an (encrypted) NBlock.
 */
NBlock * buildNBlock(const PrivateKey pseudonym,
		     const char * nickname,
		     const char * description,
		     const char * realname,
		     const char * mimetype,
		     const char * uri,
		     const char * contact,
		     const HashCode160 * rootEntry);

/**
 * Print the information contained in an NBlock.
 * 
 * @param stream where to print the information to
 * @param sb the NBlock -- in plaintext.
 */
void printNBlock(void * swrap,
		 const NBlock * sb);


/**
 * Build a list of all known namespaces.
 *
 * @param list where to store the names of the namespaces
 * @return SYSERR on error, otherwise the number of known namespaces
 */
int listNamespaces(NBlock ** list);

/**
 * Add a namespace to the set of known namespaces.
 * 
 * @param ns the namespace identifier
 */
void addNamespace(const NBlock * ns);


/**
 * Change our evaluation of a namespace.
 * @param delta by how much should the evaluation be changed?
 * @return the new ranking for this namespace
 */
int evaluateNamespace(const HashCode160 * ns,
		      int delta);

/**
 * Get the nickname of the given namespace.  If the
 * nickname is not unique within our database, append
 * the namespace identifier to make it unique.
 */
char * getUniqueNickname(const HashCode160 * ns);

void encryptSBlock(const HashCode160 * k,
		   const SBlock * in,
		   SBlock * out);

void decryptNBlock(NBlock * sb);


/**
 * Makes a root-node available to the current collection.
 * If we are currently not collecting, this function does
 * nothing.
 *
 * @param root the file identifier that was produced
 */
void publishToCollection(const RootNode * root);


/**
 * Start a new collection.  Creates a fresh pseudonym
 * and starts collecting data into the corresponding
 * collection.  Note that calling startCollection will
 * affect GNUnet until the next time startCollection or
 * stopCollection is called -- and this is independent of
 * the process that called startCollection exiting!
 * Starting a collection automatically stops the
 * previous collection.  There can only be one collection
 * at a time for each GNUnet user.
 *
 * @param name the name for the collection
 * @param desc the description of the collection
 * @param realname the real name of the user hosting the collection
 * @param uri a URI associated with the collection
 * @param contact a contact address for contacting the host
 * @return OK on success, SYSERR on error
 */ 
int startCollection(const char * name,
		    const char * desc,
		    const char * realname,
		    const char * uri,
		    const char * contact);

/**
 * Close the current collection.  Future insertions
 * are no longer collected.
 */
int stopCollection();
 



/**
 * @brief ptr to a function which downloads a specific URI
 */
typedef void (*TDownloadURI) (char *uri, char *fn);

/**
 * @brief Add a download to the list of unfinished downloads
 * @param uri GNUnet AFS URI
 * @param fileName the filename (max MAX_FILENAME_LEN)
 * @return SYSERR on error, YES on success
 **/
int storeResumeInfo(char *uri, char *fileName);

/**
 * @brief Resume all aborted downloads
 * @param dl download function
 * @return SYSERR on error, YES on success
 */
int resumeDownloads(TDownloadURI dl);

/**
 * @brief Remove a download from the list of unfinished downloads
 * @param uri the download's GNUnet AFS uri
 * @return SYSERR on error, YES on success
 */
int removeResumeInfo(char *uri);

#endif
/* end of gnunet_afs_esed2.h */
