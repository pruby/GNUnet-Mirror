/*
     This file is part of GNUnet.
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
 * @file applications/afs/module/handler.c
 * @brief Handlers for incoming AFS requests (p2p and CS).
 * @author Christian Grothoff
 */

#include "afs.h"
#include "bloomfilter.h"
#include "fileindex.h"
#include "manager.h"
#include "routing.h"
#include "policy.h"
#include "routing.h"

/* ********************* p2p handlers ****************** */

static int stat_p2p_query_count;
static int stat_p2p_superquery_count;
static int stat_p2p_chk_replies;
static int stat_p2p_3hash_replies;
#if VERBOSE_STATS
static int stat_cs_query_count;
static int stat_cs_insert_chk_count;
static int stat_cs_insert_3hash_count;
static int stat_cs_index_block_count;
static int stat_cs_index_file_count;
static int stat_cs_index_super_count;
static int stat_cs_delete_chk_count;
static int stat_cs_delete_3hash_count;
static int stat_cs_unindex_block_count;
static int stat_cs_unindex_file_count;
static int stat_cs_unindex_super_count;
static int stat_cs_upload_file_count;

static int stat_cs_insert_sblock_count;
static int stat_cs_nsquery_count;
#endif
static int stat_p2p_nsquery_count;
static int stat_p2p_sblock_replies;


#define DEBUG_HANDLER NO

/**
 * Initialize the handler module. Registers counters
 * with the statistics module.
 *
 * @return OK on success, SYSERR on failure
 */
int initAFSHandler() {
  stat_p2p_query_count 
    = statHandle(_("# p2p queries received"));
  stat_p2p_superquery_count
    = statHandle(_("# p2p super queries received"));
  stat_p2p_chk_replies 
    = statHandle(_("# p2p CHK content received (kb)"));
  stat_p2p_3hash_replies 
    = statHandle(_("# p2p search results received (kb)"));
#if VERBOSE_STATS
  stat_cs_query_count 
    = statHandle(_("# client queries received"));
  stat_cs_insert_chk_count 
    = statHandle(_("# client CHK content inserted (kb)"));
  stat_cs_insert_3hash_count 
    = statHandle(_("# client 3HASH search results inserted (kb)"));
  stat_cs_index_block_count 
    = statHandle(_("# client file index requests received"));
  stat_cs_index_file_count 
    = statHandle(_("# file index requests received"));
  stat_cs_index_super_count 
    = statHandle(_("# super query index requests received"));
  stat_cs_delete_chk_count 
    = statHandle(_("# client CHK content deleted (kb)"));
  stat_cs_delete_3hash_count 
    = statHandle(_("# client 3HASH search results deleted (kb)"));
  stat_cs_unindex_block_count 
    = statHandle(_("# client file unindex requests received"));
  stat_cs_unindex_file_count 
    = statHandle(_("# file unindex requests received"));
  stat_cs_unindex_super_count 
    = statHandle(_("# super query unindex requests received"));
  stat_cs_insert_sblock_count
    = statHandle(_("# client SBlock insert requests received"));
  stat_cs_nsquery_count
    = statHandle(_("# client namespace queries received"));
  stat_cs_upload_file_count
    = statHandle(_("# client file upload requests"));
#endif
  stat_p2p_nsquery_count
    = statHandle(_("# p2p namespace queries received"));
  stat_p2p_sblock_replies
    = statHandle(_("# p2p SBlocks received"));
  return OK;
}

/**
 * Handle query for content. Depending on how we like the sender,
 * lookup, forward or even indirect.
 */
int handleQUERY(const PeerIdentity * sender,
		const p2p_HEADER * msg) {
  QUERY_POLICY qp;
  AFS_p2p_QUERY * qmsg;
#if DEBUG_HANDLER
  EncName enc;
  EncName enc2;
#endif
  int queries;
  int ttl;
  unsigned int prio;
  double preference;
      

  queries = (ntohs(msg->size) - sizeof(AFS_p2p_QUERY)) / sizeof(HashCode160);
  if ( (queries <= 0) || 
       (ntohs(msg->size) != sizeof(AFS_p2p_QUERY) + queries * sizeof(HashCode160)) ) {
    LOG(LOG_WARNING,
	"Query received was malformed\n");
    return SYSERR;
  }
  if (queries>1)
    statChange(stat_p2p_superquery_count,1);
  statChange(stat_p2p_query_count, 1);
  qmsg = (AFS_p2p_QUERY*) msg;

#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&((AFS_p2p_QUERY_GENERIC*)qmsg)->queries[0],
		 &enc));
  IFLOG(LOG_EVERYTHING,
	hash2enc(&sender->hashPubKey,
		 &enc2));
  LOG(LOG_EVERYTHING,
      "Received query '%s' (%d) TTL %d PR %u from peer '%s'.\n",
      &enc,
      queries,
      ntohl(qmsg->ttl),
      ntohl(qmsg->priority),
      &enc2);
#endif

  /* decrement ttl (always) */
  ttl = ntohl(qmsg->ttl);
#if DEBUG_HANDLER
  LOG(LOG_DEBUG,
      "Received query for '%s' with ttl %d.\n",
      &enc,
      ttl);
#endif
  if (ttl < 0) {
    ttl = ttl - 2*TTL_DECREMENT - randomi(TTL_DECREMENT);
    if (ttl > 0)
      return OK; /* just abort */
  } else
    ttl = ttl - 2*TTL_DECREMENT - randomi(TTL_DECREMENT);
  qp = evaluateQuery(sender,
		     ntohl(qmsg->priority));  
  if ((qp & QUERY_DROPMASK) == 0)
    return OK; /* straight drop. */

  preference = (double) (qp & QUERY_PRIORITY_BITMASK);
  if (preference < QUERY_BANDWIDTH_VALUE)
    preference = QUERY_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);

  /* adjust priority */
  prio = ntohl(qmsg->priority);
  if ( (qp & QUERY_PRIORITY_BITMASK) < prio) {
    prio = qp & QUERY_PRIORITY_BITMASK;
    qmsg->priority = htonl(prio);
  }  
  prio = prio / queries; /* effective priority for ttl */
  
  /* adjust TTL */
  if ( (ttl > 0) &&
       (ttl > (int)(prio+3)*TTL_DECREMENT) ) 
    ttl = (int) (prio+3)*TTL_DECREMENT; /* bound! */
  qmsg->ttl = htonl(ttl);

  execQuery(qp, qmsg, NULL);
  return OK;
}
 
/**
 * Receive content, do something with it!  There are 3 basic
 * possiblilities. Either our node did the request and we should send
 * the result to a client via TCP, or the content was requested by
 * another node and we forwarded the request (and thus we now have to
 * fwd the reply) or 3rd somebody just send us some content we did NOT
 * ask for - and we can choose to store it or just discard it.
 */
int handleCHK_CONTENT(const PeerIdentity * sender, 
		      const p2p_HEADER * msg) {
  int prio;
  HashCode160 queryHash;
  ContentIndex ce;
  AFS_p2p_CHK_RESULT * cmsg;
  int ret;
  int dupe;
  double preference;

  if (ntohs(msg->size) != sizeof(AFS_p2p_CHK_RESULT)) {
    EncName enc;

    hash2enc(&sender->hashPubKey, &enc);
    LOG(LOG_WARNING,
	_("'%s' message received from peer '%s' was malformed.\n"),
	"CHK content",
	&enc);
    return SYSERR;
  }
  statChange(stat_p2p_chk_replies, 1);
  cmsg = (AFS_p2p_CHK_RESULT*) msg;
  hash(&cmsg->result,
       CONTENT_SIZE,
       &queryHash);
  prio = useContent(sender,
		    &queryHash,
		    msg);
  if (sender == NULL) /* no migration, this is already content
			 from the local node */
    return OK;  
  preference = (double) prio;
  prio = evaluateContent(&queryHash,
			 prio);
  if (prio != SYSERR)
    preference += (double) prio;
  if (preference < CONTENT_BANDWIDTH_VALUE)
    preference = CONTENT_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);

  if (prio == SYSERR)
    return OK; /* straight drop */
  ce.hash          = queryHash;
  ce.importance    = htonl(prio);
  ce.type          = htons(LOOKUP_TYPE_CHK);
  ce.fileNameIndex = htonl(0);
  ce.fileOffset    = htonl(0);
  ret = insertContent(&ce, 
		      sizeof(CONTENT_Block),
		      &cmsg->result, 
		      sender,
		      &dupe);
  if ( (ret == OK) &&
       (dupe == NO) )
    addToBloomfilter(singleBloomFilter,
		     &queryHash);
  return OK;
}

/**
 * Receive content, do something with it!  There are 3 basic
 * possiblilities. Either our node did the request and we should send
 * the result to a client via TCP, or the content was requested by
 * another node and we forwarded the request (and thus we now have to
 * fwd the reply) or 3rd somebody just send us some content we did NOT
 * ask for - and we can choose to store it or just discard it.
 */
int handle3HASH_CONTENT(const PeerIdentity * sender, 
			const p2p_HEADER * msg) {
  int prio;
  AFS_p2p_3HASH_RESULT * cmsg;
  HashCode160 tripleHash;
  ContentIndex ce;
  EncName enc;
  int ret;
  int dupe;
  double preference;

  if (ntohs(msg->size) != sizeof(AFS_p2p_3HASH_RESULT)) {
    hash2enc(&sender->hashPubKey, &enc);
    LOG(LOG_WARNING,
	_("'%s' message received from peer '%s' was malformed.\n"),
	"3HASH content",
	&enc);
    return SYSERR;
  }
  statChange(stat_p2p_3hash_replies, 1);
  cmsg = (AFS_p2p_3HASH_RESULT*) msg;
  hash(&cmsg->hash,
       sizeof(HashCode160),
       &tripleHash);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&tripleHash,
		 &enc));
  LOG(LOG_DEBUG,
      "Received 3HASH search result for %s from peer\n",
      &enc);
#endif
  prio = useContent(sender,
		    &tripleHash,
		    msg);
  if (sender == NULL) { /* no migration, this is already content
			   from the local node */
#if DEBUG_HANDLER
    LOG(LOG_DEBUG,
	"Content migration not needed, content is local\n");
#endif
    return OK;  
  }
  preference = (double) prio;
#if DEBUG_HANDLER
  LOG(LOG_DEBUG,
      "Content migration with preference %d\n",
      prio);
#endif
  prio = evaluateContent(&tripleHash,
			 prio);
  if (prio != SYSERR)
    preference += (double) prio;
  if (preference < CONTENT_BANDWIDTH_VALUE)
    preference = CONTENT_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);


  if (prio == SYSERR) {
#if DEBUG_HANDLER
    LOG(LOG_DEBUG,
	"Content not important enough, not replicated\n");
#endif
    return OK; /* straight drop */
  } 
#if DEBUG_HANDLER
  else
    LOG(LOG_DEBUG,
	"Content replicated with total preference %d\n",
	prio);
#endif
  ce.hash          = cmsg->hash;
  ce.importance    = htonl(prio);
  ce.type          = htons(LOOKUP_TYPE_3HASH);
  ce.fileNameIndex = htonl(0);
  ce.fileOffset    = htonl(0);
  
  ret = insertContent(&ce, 
		      sizeof(CONTENT_Block),
             	      &cmsg->result, 
                      sender,
		      &dupe);
  if ( (ret == OK) &&
       (dupe == NO) )
      addToBloomfilter(singleBloomFilter,
	               &tripleHash);
  return OK;
}

/* *********************** CS handlers ***************** */

/**
 * Process a query from the client. Forwards to the network.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */ 
int csHandleRequestQuery(ClientHandle sock,
			 const AFS_CS_QUERY * queryRequest) {
  QUERY_POLICY qp = QUERY_ANSWER|QUERY_FORWARD|QUERY_INDIRECT|QUERY_PRIORITY_BITMASK; 
  AFS_p2p_QUERY * msg;
#if DEBUG_HANDLER
  EncName enc;
#endif
  int queries;
  int ttl;
  int ret;

  queries = (ntohs(queryRequest->header.size) - sizeof(AFS_CS_QUERY)) / sizeof(HashCode160);
  if ( (queries <= 0) ||
       (ntohs(queryRequest->header.size) != 
	sizeof(AFS_CS_QUERY) + queries * sizeof(HashCode160)) ) {
    LOG(LOG_WARNING,
	_("Received malformed '%s' request from client.\n"),
	"query");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_query_count, 1);
#endif
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&((AFS_CS_QUERY_GENERIC*)queryRequest)->queries[0], 
		 &enc));
  LOG(LOG_DEBUG, 
      "Received %d queries '%s' with ttl %d and priority %u.\n",
      queries,
      &enc,
      ntohl(queryRequest->ttl),
      ntohl(queryRequest->priority));
#endif
  msg = MALLOC(sizeof(AFS_p2p_QUERY)+queries * sizeof(HashCode160));
  msg->header.size 
    = htons(sizeof(AFS_p2p_QUERY)+queries * sizeof(HashCode160));
  msg->header.type 
    = htons(AFS_p2p_PROTO_QUERY);
  memcpy(&((AFS_p2p_QUERY_GENERIC*)msg)->queries[0],
	 &((AFS_CS_QUERY_GENERIC*)queryRequest)->queries[0],
	 sizeof(HashCode160) * queries);
  msg->priority 
    = queryRequest->priority; /* no htonl here: is already in network byte order! */
  /* adjust TTL */
  ttl = ntohl(queryRequest->ttl);
  if ( (ttl > 0) &&
       (ttl > (int)(ntohl(msg->priority)+8)*TTL_DECREMENT) ) 
    ttl = (int) (ntohl(msg->priority)+8)*TTL_DECREMENT; /* bound! */
  msg->ttl = htonl(ttl);
  msg->returnTo = *coreAPI->myIdentity;
  ret = execQuery(qp, msg, sock);   
#if DEBUG_HANDLER
  LOG(LOG_DEBUG, 
      "Executed %d queries with result %d.\n",
      queries,
      ret);
#endif
  FREE(msg);
  return coreAPI->sendTCPResultToClient(sock, ret);
}

/**
 * Process a request to insert content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
int csHandleRequestInsertCHK(ClientHandle sock,
			     const AFS_CS_INSERT_CHK * insertRequest) {
  ContentIndex entry;
#if DEBUG_HANDLER
  EncName enc;
#endif
  int ret;
  int dupe;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_CHK)) {
    LOG(LOG_WARNING,
	_("Received malformed '%s' request from client\n"),
	"CHK insert");
    return SYSERR;
  } 
#if VERBOSE_STATS
  statChange(stat_cs_insert_chk_count, 1);
#endif
  hash(&insertRequest->content,
       sizeof(CONTENT_Block),
       &entry.hash);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&entry.hash,
		 &enc));
  LOG(LOG_DEBUG,
      "Received CHK insert request for block %s\n",
      &enc);
#endif
  entry.type
    = htons(LOOKUP_TYPE_CHK);
  entry.importance
    = insertRequest->importance; /* both are in network byte order! */
  entry.fileNameIndex 
    = 0; /* database */
  entry.fileOffset 
    = 0; /* data/content */

  ret = insertContent(&entry,
     	              sizeof(CONTENT_Block),
		      &insertRequest->content,
		      NULL,
		      &dupe);
  if ( (ret == OK) &&
       (dupe == NO) )
      addToBloomfilter(singleBloomFilter,
	               &entry.hash);
  return coreAPI->sendTCPResultToClient(sock, ret);
}

/**
 * Process a request to insert content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
int csHandleRequestInsert3HASH(ClientHandle sock,
			       const AFS_CS_INSERT_3HASH * insertRequest) {
  ContentIndex entry;
  HashCode160 tripleHash;
#if DEBUG_HANDLER
  EncName enc;
#endif
  int dupe;
  int ret;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_3HASH)) {
    LOG(LOG_WARNING,
	_("Received malformed '%s' request from client.\n"),
	"3HASH insert");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_insert_3hash_count, 1);
#endif
  entry.hash = insertRequest->doubleHash;
  hash(&insertRequest->doubleHash,
       sizeof(HashCode160),
       &tripleHash);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&tripleHash,
		 &enc));
  LOG(LOG_DEBUG,
      "Received 3HASH insert request for '%s' from client.\n",
      &enc);
#endif
  entry.type
    = htons(LOOKUP_TYPE_3HASH);
  entry.importance
    = insertRequest->importance; /* both are in network byte order! */
  entry.fileNameIndex 
    = 0; /* database */
  entry.fileOffset 
    = 0; /* data/content */
  ret = insertContent(&entry,
		      sizeof(CONTENT_Block),
		      &insertRequest->content,
	   	      NULL,
		      &dupe);
  if ( (ret == OK) &&
       (dupe == NO) )
    addToBloomfilter(singleBloomFilter,
		     &tripleHash);
  return coreAPI->sendTCPResultToClient(sock, ret);
}

/**
 * Process a request to index content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
int csHandleRequestIndexBlock(ClientHandle sock,
			      const AFS_CS_INDEX_BLOCK * indexingRequest) {
  int dupe;
#if DEBUG_HANDLER
  EncName enc;
#endif
  ContentIndex ce;

  if (ntohs(indexingRequest->header.size) != 
      sizeof(AFS_CS_INDEX_BLOCK)) {
    LOG(LOG_WARNING, 
	_("Received malformed '%s' request from client.\n"),
	"block indexing");
    return SYSERR;
  }
  ce = indexingRequest->contentIndex;
#if DEBUG_HANDLER
  hash2enc(&ce.hash,
	   &enc);
  LOG(LOG_DEBUG,
      "Indexing content %s at offset %u\n",
      (char*)&enc,
      ntohl(ce.fileOffset));
#endif  
  

#if VERBOSE_STATS
  statChange(stat_cs_index_block_count, 1);
#endif
  return coreAPI->sendTCPResultToClient
    (sock,
     insertContent(&ce,
		   0, 
		   NULL, 
		   NULL, 
		   &dupe));
}

/**
 * Process a query to list a file as on-demand encoded from the client.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
int csHandleRequestIndexFile(ClientHandle sock,
			     const AFS_CS_INDEX_FILE * listFileRequest) {
  EncName enc;
  char * filename;
  char * prefix;
  int ret;
  unsigned long long quota;
  unsigned long long usage;

  if (ntohs(listFileRequest->header.size) != 
      sizeof(AFS_CS_INDEX_FILE)) {
    LOG(LOG_WARNING, 
	_("Received malformed '%s' request from client.\n"),
	"file indexing");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_index_file_count, 1);
#endif
  hash2enc(&listFileRequest->hash,
	   &enc);
  filename = getConfigurationString("AFS",
				    "INDEX-DIRECTORY");
  if (filename == NULL) {
    LOG(LOG_WARNING,
	_("Rejecting '%s' request, '%s' option not set!\n"),
	"content-unindex"
	"INDEX-DIRECTORY");
    return coreAPI->sendTCPResultToClient(sock, 
					  -1);
  }
  prefix = expandFileName(filename);
  quota = getConfigurationInt("AFS",
			      "INDEX-QUOTA") * 1024 * 1024;
  if (quota != 0) {
    usage = getFileSizeWithoutSymlinks(prefix);
    if (usage + ntohl(listFileRequest->filesize) > quota) {
      LOG(LOG_WARNING,
	  _("Rejecting file index request, quota exeeded: %d of %d (MB)\n"),
	  usage / 1024 / 1024,
	  quota / 1024 / 1024);
      FREE(filename);
      return coreAPI->sendTCPResultToClient(sock, 
					    -1);
    }
  }

  FREE(filename);
  filename = MALLOC(strlen(prefix) + 42);
  strcpy(filename, prefix);
  FREE(prefix);
  strcat(filename, "/");
  strcat(filename, (char*) &enc);
  ret = appendFilename(filename);
  if (ret == 0)
    ret = -1;
  FREE(filename);
  return coreAPI->sendTCPResultToClient(sock, 
					ret);
}

/**
 * Process a client request to upload a file (indexing).
 */
int csHandleRequestUploadFile(ClientHandle sock,
			      const AFS_CS_UPLOAD_FILE * uploadRequest) {
  EncName enc;
  char * filename;
  char * prefix;
  int ret;
  int fd;

  if (ntohs(uploadRequest->header.size) <
      sizeof(AFS_CS_UPLOAD_FILE)) {
    LOG(LOG_WARNING, 
	_("Received malformed '%s' request from client.\n"),
	"file upload");
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_upload_file_count, 1);
#endif
  hash2enc(&uploadRequest->hash,
	   &enc);
  filename = getConfigurationString("AFS",
				    "INDEX-DIRECTORY");
  if (filename == NULL) {
    LOG(LOG_WARNING,
	_("Rejecting '%s' request, '%s' option not set!\n"),
	"content-upload"
	"INDEX-DIRECTORY");
    return coreAPI->sendTCPResultToClient(sock, 
					  SYSERR);
  }
  prefix = expandFileName(filename);
  mkdirp(prefix);

  FREE(filename);
  filename = MALLOC(strlen(prefix) + 42);
  strcpy(filename, prefix);
  FREE(prefix);
  strcat(filename, "/");
  strcat(filename, (char*) &enc);
  fd = OPEN(filename, 
	    O_CREAT|O_WRONLY,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); /* 644 */
  if(fd == -1) {
    LOG_FILE_STRERROR(LOG_ERROR, "open", filename);
    return coreAPI->sendTCPResultToClient(sock, 
					  SYSERR);
  }
  
  lseek(fd, 
	ntohl(uploadRequest->pos),
	SEEK_SET);
  ret = WRITE(fd,
	      &((AFS_CS_UPLOAD_FILE_GENERIC*)uploadRequest)->data[0],
	      ntohs(uploadRequest->header.size) - sizeof(AFS_CS_UPLOAD_FILE));
  if (ret == ntohs(uploadRequest->header.size) - sizeof(AFS_CS_UPLOAD_FILE))
    ret = OK;
  else
    ret = SYSERR;
  CLOSE(fd);  

  FREE(filename);
  return coreAPI->sendTCPResultToClient(sock, 
					ret);
}

/**
 * Process a client request to extend our super-query bloom
 * filter.
 */
int csHandleRequestIndexSuper(ClientHandle sock,
			      const AFS_CS_INDEX_SUPER * superIndexRequest) {
  ContentIndex entry;
  int dupe;

  if (ntohs(superIndexRequest->header.size) != 
      sizeof(AFS_CS_INDEX_SUPER)) {
    BREAK();
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_index_super_count, 1);
#endif
  addToBloomfilter(superBloomFilter,
		   &superIndexRequest->superHash);
  entry.type
    = htons(LOOKUP_TYPE_SUPER);
  entry.importance
    = superIndexRequest->importance; /* both are in network byte order */ 
  entry.fileNameIndex 
    = 0; /* database */
  entry.fileOffset 
    = 0; /* data/content */
  entry.hash 
    = superIndexRequest->superHash;
  return coreAPI->sendTCPResultToClient(sock, 
					insertContent(&entry,
						      0, 
						      NULL, 
						      NULL, 
						      &dupe));
}

/**
 * Process a request from the client to delete content.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
int csHandleRequestDeleteCHK(ClientHandle sock,
			     const AFS_CS_INSERT_CHK * insertRequest) {
  HashCode160 hc;
#if DEBUG_HANDLER
  EncName enc;
#endif
  int ret;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_CHK)) {
    BREAK();
    return SYSERR;
  } 
#if VERBOSE_STATS
  statChange(stat_cs_delete_chk_count, 1);
#endif
  hash(&insertRequest->content,
       sizeof(CONTENT_Block),
       &hc);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&hc,
		 &enc));
  LOG(LOG_DEBUG,
      "Received CHK remove request for block %s\n",
      &enc);
#endif
  ret = removeContent(&hc,
                      -1);
  if (ret == OK)
    if (YES == testBloomfilter(singleBloomFilter,
			       &hc))
      delFromBloomfilter(singleBloomFilter,
			 &hc);
  return coreAPI->sendTCPResultToClient(sock, ret);
}

/**
 * Process a request from the client to delete content.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
int csHandleRequestDelete3HASH(ClientHandle sock,
			       const AFS_CS_INSERT_3HASH * insertRequest) {
  HashCode160 tripleHash;
#if DEBUG_HANDLER
  EncName enc;
#endif
  int ret;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_3HASH)) {
    BREAK();
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_delete_3hash_count, 1);
#endif
  hash(&insertRequest->doubleHash,
       sizeof(HashCode160),
       &tripleHash);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&tripleHash,
		 &enc));
  LOG(LOG_DEBUG,
      " received 3HASH delete request for %s from client\n",
      &enc);
#endif
  ret = removeContent(&tripleHash,
                      -1);
  if (ret == OK)     
    delFromBloomfilter(singleBloomFilter,
		       &tripleHash);
		     
  return coreAPI->sendTCPResultToClient(sock, ret);
}

/**
 * Process a request from the client to unindex content.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
int csHandleRequestUnindexBlock(ClientHandle sock,
				const AFS_CS_INDEX_BLOCK * indexingRequest) {
  if (ntohs(indexingRequest->header.size) != 
      sizeof(AFS_CS_INDEX_BLOCK)) {
    BREAK();
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_unindex_block_count, 1);
#endif
  return coreAPI->sendTCPResultToClient(sock,
					removeContent(&indexingRequest->contentIndex.hash,
						      -1));
}

/**
 * Callback used to select the file in the fileindex
 * that is to be removed.
 */
static int removeMatch(const char * fn,
		       int i,
		       const char * search) {
  if (strcmp(fn, search) == 0)
    return SYSERR;
  else
    return OK;     
}

/**
 * Process a query from the client to remove an on-demand encoded file.
 * n.b. This function just zeroes the correct row in the list of 
 * on-demand encoded files, if match (deletion is done by forEachIndexedFile). 
 * The index of the filename that was removed is returned to the client.
 *
 * FIXME: It lookslike if listFileRequest->filename was NOT in database.list, 
 * it gets appended to it, removed from it, and client gets a false idx. 
 * This unnecessarily bloats the database.list by one empty line.
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
int csHandleRequestUnindexFile(ClientHandle sock,
			       const AFS_CS_INDEX_FILE * listFileRequest) {
  int idx;
  EncName enc;
  char * filename;
  char * prefix;

  if (ntohs(listFileRequest->header.size) != 
      sizeof(AFS_CS_INDEX_FILE)) {
    BREAK();
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_unindex_file_count, 1);
#endif
  hash2enc(&listFileRequest->hash,
	  &enc);
  filename = getConfigurationString("AFS",
				    "INDEX-DIRECTORY");
  if (filename == NULL) {
    LOG(LOG_WARNING,
	_("Rejecting '%s' request, '%s' option not set!\n"),
	"unindex-file"
	"INDEX-DIRECTORY");
    return coreAPI->sendTCPResultToClient(sock, 
					  -1);  
  }
  prefix = expandFileName(filename);
  FREE(filename);
  filename = MALLOC(strlen(prefix) + 42);
  strcpy(filename, prefix);
  FREE(prefix);
  strcat(filename, "/");
  strcat(filename, (char*) &enc);
  idx = appendFilename(filename);
  if (idx == -1) {
    FREE(filename);
    return coreAPI->sendTCPResultToClient(sock, 
					  -1);  
  }  
  GNUNET_ASSERT(idx != 0);
  forEachIndexedFile((IndexedFileNameCallback)&removeMatch,
		     filename);
  if (0 != UNLINK(filename)) {
    LOG_FILE_STRERROR(LOG_WARNING, "unlink", filename);
    idx = -1; /* remove failed!? */
  }
  FREE(filename);
  return coreAPI->sendTCPResultToClient(sock, 
					idx);  
}

/**
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
int csHandleRequestLinkFile(ClientHandle sock,
			    const AFS_CS_LINK_FILE * linkFileRequest) {
  EncName enc;
  char * filename;
  char * tname;
  char * prefix;
  HashCode160 hc;
  size_t len;

  if (ntohs(linkFileRequest->header.size) <=
      sizeof(AFS_CS_LINK_FILE)) {
    BREAK();
    return SYSERR;
  }
#if VERBOSE_STATS
  /* statChange(stat_cs_link_file_count, 1); */
#endif
  len = ntohs(linkFileRequest->header.size) - sizeof(AFS_CS_LINK_FILE);
  tname = MALLOC(len + 1);
  strncpy(tname,
	  &((AFS_CS_LINK_FILE_GENERIC*)linkFileRequest)->data[0],
	  len);
  tname[len] = '\0';
  if ( (SYSERR == getFileHash(tname,
			      &hc)) ||
       (0 != memcmp(&hc,
		    &linkFileRequest->hash,
		    sizeof(HashCode160))) ) {   
    LOG(LOG_WARNING, 
	_("File link request '%s' from client pointed to file with the wrong data!\n"),
	tname);
    FREE(tname);
    return coreAPI->sendTCPResultToClient(sock, 
					  SYSERR);    
  }
  hash2enc(&linkFileRequest->hash,
	   &enc);
  filename = getConfigurationString("AFS",
				    "INDEX-DIRECTORY");
  if (filename == NULL) {
    LOG(LOG_WARNING,
	_("Rejecting '%s' request, '%s' option not set!\n"),
	"link-file"
	"INDEX-DIRECTORY");
    return coreAPI->sendTCPResultToClient(sock, 
					  SYSERR);  
  }
  prefix = expandFileName(filename);
  FREE(filename);
  filename = MALLOC(strlen(prefix) + 42);
  strcpy(filename, prefix);
  FREE(prefix);
  mkdirp(filename);
  strcat(filename, DIR_SEPARATOR_STR);
  strcat(filename, (char*) &enc);
 
  /* trash any previous entry so that SYMLINK() 
   * on existing won't cause retry attempts to fail */
  UNLINK(filename);
  
  if (0 == SYMLINK(tname,
		   filename)) {
    FREE(filename);
    FREE(tname);
    return coreAPI->sendTCPResultToClient(sock, 
					  OK);  
  } else {
    LOG(LOG_WARNING,
	_("Could not create symlink from '%s' to '%s': %s\n"),
	tname,
	filename,
	STRERROR(errno));
    FREE(filename);
    FREE(tname);
    return coreAPI->sendTCPResultToClient(sock, 
					  SYSERR);  
  }
}

/**
 * Process a client request to limit our super-query bloom
 * filter.
 */
int csHandleRequestUnindexSuper(ClientHandle sock,
				const AFS_CS_INDEX_SUPER * superIndexRequest) {
  if (ntohs(superIndexRequest->header.size) != 
      sizeof(AFS_CS_INDEX_SUPER)) {
    BREAK();
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_unindex_super_count, 1);
#endif
  delFromBloomfilter(superBloomFilter,
		     &superIndexRequest->superHash);
  return coreAPI->sendTCPResultToClient(sock, 
		       removeContent(&superIndexRequest->superHash,
		       -1));
}

/* *************************** SBlock stuff ***************************** */

int csHandleRequestInsertSBlock(ClientHandle sock,
				const AFS_CS_INSERT_SBLOCK * insertRequest) {
  ContentIndex entry;
#if DEBUG_HANDLER
  EncName enc1;
  EncName enc2;
  HashCode160 ns;
#endif
  int dupe;
  int ret;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_SBLOCK)) {
    BREAK();
    return SYSERR;
  }
  if (OK != verifySBlock(&insertRequest->content)) {
    BREAK();
    return SYSERR;
  }

#if VERBOSE_STATS
  statChange(stat_cs_insert_sblock_count, 1);
#endif
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&insertRequest->content.identifier,
		 &enc1);
	hash(&insertRequest->content.subspace,
	     sizeof(PublicKey),
	     &ns);
	hash2enc(&ns,
		 &enc2));
  LOG(LOG_DEBUG,
      "Received SBlock for namespace %s with routing ID %s.\n",
      &enc2,
      &enc1);
#endif
  entry.type
    = htons(LOOKUP_TYPE_SBLOCK);
  entry.importance
    = insertRequest->importance; /* both are in network byte order! */
  entry.fileNameIndex 
    = 0; /* database */
  entry.fileOffset 
    = 0; /* data/content */
  entry.hash
    = insertRequest->content.identifier;
  dupe = NO;
  ret = insertContent(&entry,
		      sizeof(CONTENT_Block),
		      &insertRequest->content,
	   	      NULL,
		      &dupe);
#if DEBUG_HANDLER
  LOG(LOG_DEBUG,
      "Received SBlock insert is dupe: %s (insert %s)\n",
      dupe == NO ? "NO" : "YES",
      ret == SYSERR ? "SYSERR" : "OK");
#endif
  if ( (ret == OK) &&
       (dupe == NO) )
    addToBloomfilter(singleBloomFilter,
		     &insertRequest->content.identifier);
  return coreAPI->sendTCPResultToClient(sock, ret);
}

int csHandleRequestNSQuery(ClientHandle sock,
			   const AFS_CS_NSQUERY * queryRequest) {
  QUERY_POLICY qp = QUERY_ANSWER|QUERY_FORWARD|QUERY_INDIRECT|QUERY_PRIORITY_BITMASK; 
  AFS_p2p_NSQUERY * msg;
#if DEBUG_HANDLER
  EncName enc1;
  EncName enc2;
#endif

  if (ntohs(queryRequest->header.size) != 
      sizeof(AFS_CS_NSQUERY)) {
    BREAK();
    return SYSERR;
  }
#if VERBOSE_STATS
  statChange(stat_cs_nsquery_count, 1);
#endif
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&queryRequest->identifier, 
		 &enc1));
  IFLOG(LOG_DEBUG,
	hash2enc(&queryRequest->namespace, 
		 &enc2));
  LOG(LOG_DEBUG, 
      "Received NS query (%s/%s) with ttl %d and priority %u.\n",
      &enc2,
      &enc1,
      ntohl(queryRequest->ttl),
      ntohl(queryRequest->priority));
#endif
  msg = MALLOC(sizeof(AFS_p2p_NSQUERY));
  msg->hdr.header.size 
    = htons(sizeof(AFS_p2p_NSQUERY));
  msg->hdr.header.type 
    = htons(AFS_p2p_PROTO_NSQUERY);
  msg->hdr.priority 
    = queryRequest->priority; /* no htonl here: is already in network byte order! */
  msg->hdr.ttl 
    = queryRequest->ttl; /* no htonl here: is already in network byte order! */
  msg->identifier
    = queryRequest->identifier;
  msg->namespace
    = queryRequest->namespace;
  msg->hdr.returnTo
    = *(coreAPI->myIdentity);
  execQuery(qp, &msg->hdr, sock);   
  FREE(msg);
  return OK;
}

int handleNSQUERY(const PeerIdentity * sender,
		  const p2p_HEADER * msg) {
  QUERY_POLICY qp;
  AFS_p2p_NSQUERY * qmsg;
#if DEBUG_HANDLER
  EncName enc;
#endif
  int ttl;
  unsigned int prio;
  double preference;
  
  if (ntohs(msg->size) != sizeof(AFS_p2p_NSQUERY)) {
    BREAK();
    return SYSERR;
  }
  statChange(stat_p2p_nsquery_count, 1);
  qmsg = (AFS_p2p_NSQUERY*) msg;
  /* decrement ttl */
  ttl = ntohl(qmsg->hdr.ttl);
#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&qmsg->identifier,
		 &enc));
  LOG(LOG_DEBUG,
      "Received NS query for %s with ttl %d\n",
      &enc,
      ttl);
#endif
  if (ttl < 0) {
    ttl = ttl - 2*TTL_DECREMENT - randomi(TTL_DECREMENT);
    if (ttl > 0)
      return OK; /* just abort */
  } else
    ttl = ttl - 2*TTL_DECREMENT - randomi(TTL_DECREMENT);
  qp = evaluateQuery(sender,
		     ntohl(qmsg->hdr.priority));  
  if ((qp & QUERY_DROPMASK) == 0)
    return OK; /* straight drop. */

  preference = (double) (qp & QUERY_PRIORITY_BITMASK);
  if (preference < QUERY_BANDWIDTH_VALUE)
    preference = QUERY_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);

  /* adjust priority */
  prio = ntohl(qmsg->hdr.priority);
  if ( (qp & QUERY_PRIORITY_BITMASK) < prio) {
    prio = qp & QUERY_PRIORITY_BITMASK;
    qmsg->hdr.priority = htonl(prio);
  }  
  
  /* adjust TTL */
  if ( (ttl > 0) &&
       (ttl > (int)(prio+3)*TTL_DECREMENT) ) 
    ttl = (int) (prio+3)*TTL_DECREMENT; /* bound! */
  qmsg->hdr.ttl = htonl(ttl);

  execQuery(qp, &qmsg->hdr, NULL);
  return OK;
}


int handleSBLOCK_CONTENT(const PeerIdentity * sender, 
			 const p2p_HEADER * msg) {
  int prio;
  AFS_p2p_SBLOCK_RESULT * cmsg;
  ContentIndex ce;
#if DEBUG_HANDLER
  EncName enc;
#endif
  int ret;
  int dupe;
  double preference;

  if (ntohs(msg->size) != sizeof(AFS_p2p_SBLOCK_RESULT)) {
    BREAK();
    return SYSERR;
  }
  statChange(stat_p2p_sblock_replies, 1);
  cmsg = (AFS_p2p_SBLOCK_RESULT*) msg;

  if ( (OK != verifySBlock(&cmsg->result)) &&
       (OK != verifyNBlock((const NBlock *) &cmsg->result)) )
    return SYSERR;

#if DEBUG_HANDLER
  IFLOG(LOG_DEBUG,
	hash2enc(&cmsg->result.identifier,
		 &enc));
  LOG(LOG_DEBUG,
      "Received SBLOCK search result for '%s' from peer.\n",
      &enc);
#endif
  prio = useContent(sender,
		    &cmsg->result.identifier,
		    msg);
  if (sender == NULL) { /* no migration, this is already content
			   from the local node */
#if DEBUG_HANDLER
    LOG(LOG_DEBUG,
	"Content migration not needed, content is local.\n");
#endif
    return OK;  
  }
#if DEBUG_HANDLER
  else
    LOG(LOG_DEBUG,
	"Content migration with preference %d.\n",
	prio);
#endif
  preference = (double) prio;
  prio = evaluateContent(&cmsg->result.identifier,
			 prio);
  if (prio == SYSERR) {
#if DEBUG_HANDLER
    LOG(LOG_DEBUG,
	"Content not important enough, not replicated.\n");
#endif
    return OK; /* straight drop */
  } 
#if DEBUG_HANDLER
  else
    LOG(LOG_DEBUG,
	"Content replicated with total preference %d.\n",
	prio);
#endif
  if (prio != SYSERR)
    preference += (double) prio;
  if (preference < CONTENT_BANDWIDTH_VALUE)
    preference = CONTENT_BANDWIDTH_VALUE;
  coreAPI->preferTrafficFrom(sender,
			     preference);
  ce.hash          = cmsg->result.identifier;
  ce.importance    = htonl(prio);
  ce.type          = htons(LOOKUP_TYPE_SBLOCK);
  ce.fileNameIndex = htonl(0);
  ce.fileOffset    = htonl(0);
  
  ret = insertContent(&ce, 
		      sizeof(CONTENT_Block),
             	      &cmsg->result, 
                      sender,
		      &dupe);
  if ( (ret == OK) &&
       (dupe == NO) )
      addToBloomfilter(singleBloomFilter,
	               &cmsg->result.identifier);
  return OK;
}


/* end of handler.c */
