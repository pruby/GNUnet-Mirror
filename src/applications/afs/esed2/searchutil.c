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
 * @file applications/afs/esed2/searchutil.c 
 * @brief Helper functions for searching.
 * @author Christian Grothoff
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

/**
 * Context of the sendQueries cron-job.
 */
typedef struct {
  /**
   * Time when the cron-job was first started.
   */
  cron_t start;

  /**
   * How many cron-units may we run (total)?
   */
  cron_t timeout;

  /**
   * Socket for communication with gnunetd
   */
  GNUNET_TCP_SOCKET * sock;

  /**
   * Number of queries.
   */
  unsigned int queryCount;

  /**
   * queryCount query messages
   */
  AFS_CS_QUERY ** messages;
} SendQueriesContext;


typedef struct {
  /**
   * the results we've got so far (hash of root-node) 
   */
  HashCode160 * resultsReceived;

  /**
   * the number of valid entries in resultsReceived 
   */
  unsigned int countResultsReceived;

  /**
   * size of the resultsReceived array 
   */
  unsigned int sizeRR;

  /**
   * unmatched ("AND") results so far, list of root-node hashes that
   * were received for each keyword
   */
  HashCode160 ** key2hash;  

  /**
   * number of entries in the key2hash (for each dimension) 
   */
  unsigned int * key2hashCount;

  /**
   * allocated space in the key2hash (for each dimension) 
   */
  unsigned int * key2hashSize;

  /**
   * which method should be called for each result (print method),
   * called with the root-node as the argument 
   */
  SearchResultCallback resultHandler;

  /**
   * argument to the result handler 
   */
  void * resultHandlerArgs;

} ResultContext;

/**
 * Display the result, but make sure that
 * every file is only displayed once.
 */
static void processResult(RootNode * rootNode,
			  ResultContext * rc) {
  unsigned int i;
  
  /* this check should be redundant... */
  for (i=0;i<rc->countResultsReceived;i++) {
    if (equalsHashCode160(&rc->resultsReceived[i],
			  &rootNode->header.fileIdentifier.chk.query)) {
      LOG(LOG_DEBUG,
	  " we have seen this result before (processResult)\n");
      return; /* seen before */
    }
  }
  /* directory support... */
  makeRootNodeAvailable(rootNode, DIR_CONTEXT_SEARCH);
  if (rc->countResultsReceived == rc->sizeRR) 
    GROW(rc->resultsReceived,
	 rc->sizeRR,
	 rc->sizeRR*2);
  memcpy(&rc->resultsReceived[rc->countResultsReceived++],
	 &rootNode->header.fileIdentifier.chk.query,
	 sizeof(HashCode160));
  rc->resultHandler(rootNode,
		    rc->resultHandlerArgs);
}

/**
 * Filter results that do not match ALL keywords.
 * @param rootNode the new reply
 * @param keyIndex for which key this result matches
 * @param keyCount the number of keys that are ANDed
 * @param rc the context to keep track of which replies we got so far
 */
static void filterResult(RootNode * rootNode,
			 unsigned int keyIndex,
			 unsigned int keyCount,
			 ResultContext * rc) {
  unsigned int i;
  unsigned int j;

  for (i=0;i<rc->key2hashCount[keyIndex];i++)
    if (equalsHashCode160(&rc->key2hash[keyIndex][i],
			  &rootNode->header.fileIdentifier.chk.query)) {
      LOG(LOG_DEBUG,
	  "We have seen this result before (filterResult).\n");
      return; /* seen before */
    }
  /* maybe we have to grow key2hash */
  if (rc->key2hashSize[keyIndex] == rc->key2hashCount[keyIndex]) 
    GROW(rc->key2hash[keyIndex],
	 rc->key2hashSize[keyIndex],
	 rc->key2hashSize[keyIndex] * 2);
  /* add to the matching files for this key */
  memcpy(&rc->key2hash[keyIndex][rc->key2hashCount[keyIndex]++],
	 &rootNode->header.fileIdentifier.chk.query,
	 sizeof(HashCode160));
  /* check if the file now matches all keys */
  for (i=0;i<keyCount;i++) {
    for (j=0;j<rc->key2hashCount[i];j++)
      if (equalsHashCode160(&rc->key2hash[i][j],
			    &rootNode->header.fileIdentifier.chk.query))
	break; /* break inner for-loop */
    if (j == rc->key2hashCount[i]) {
      LOG(LOG_DEBUG,
	  "Not (yet) enough results for the AND query.\n");
      return; /* not found, exit! */
    }
  }
  /*ok, rootNode matches all the AND criteria, display */
  processResult(rootNode, rc);
}

/**
 * Initialize a result context.
 * @param rc the context to initialize
 * @param keyCount the number of keywords
 * @param handler the method to call for results
 * @param handlerArgs the arguments to the result handler method
 */
static void initResultContext(ResultContext * rc,
			      unsigned int keyCount,
			      void * handler,
			      void * handlerArgs) {
  unsigned int i;
    
  rc->countResultsReceived = 0;
  rc->sizeRR = 16;
  rc->resultsReceived = MALLOC(sizeof(HashCode160)*rc->sizeRR);
  rc->key2hash = MALLOC(sizeof(HashCode160*)*keyCount);
  rc->key2hashCount = MALLOC(sizeof(int)*keyCount);
  rc->key2hashSize = MALLOC(sizeof(int)*keyCount);
  for (i=0;i<keyCount;i++) {
    rc->key2hash[i] = MALLOC(sizeof(HashCode160)*16);
    rc->key2hashCount[i] = 0;
    rc->key2hashSize[i] = 16;
  }	
  rc->resultHandler = handler;
  rc->resultHandlerArgs = handlerArgs;
}

/**
 * Destroy a result context.
 * @param rc the context to destroy
 * @param keyCount the number of keywords
 */
static void destroyResultContext(ResultContext * rc,
				 unsigned int keyCount) {
  unsigned int i;
    
  FREE(rc->resultsReceived);
  for (i=0;i<keyCount;i++)
    FREE(rc->key2hash[i]);
  FREE(rc->key2hash);
  FREE(rc->key2hashCount);
  FREE(rc->key2hashSize);
}

/**
 * Start retrieving results from GNUnet. This method terminates only
 * if the testTerminate-method returns YES after a result was received
 * or there is an error with reading from the socket.
 *
 * @param sock socket we should receive from
 * @param keyCount the number of keywords
 * @param keywords the keywords (for decryption)
 * @param messages the queries (to match against)
 * @param handler the method to call on each result matching all keywords
 * @param handlerArgs the arguments to the result handler method
 * @param testTerminate method used to check if we should termiante
 * @param ttContext argument for testTerminate
 */
static void receiveResults(GNUNET_TCP_SOCKET * sock,
			   unsigned int keyCount,
			   HashCode160 * keywords,
			   AFS_CS_QUERY ** messages,
			   SearchResultCallback handler,
			   void * handlerArgs,
			   TestTerminateThread testTerminate,
			   void * ttContext) {
  ResultContext rc;
  CS_HEADER * buffer;
  AFS_CS_RESULT_3HASH * reply;
  CONTENT_Block * result;
  RootNode * rootNode;
  unsigned int i;
  HashCode160 tripleHash;
  
  result = MALLOC(sizeof(CONTENT_Block));
  initResultContext(&rc, 
		    keyCount, 
		    handler, 
		    handlerArgs);
  while (NO == testTerminate(ttContext)) {
    buffer = NULL;
    if (SYSERR == readFromSocket(sock,
				 (CS_HEADER **) &buffer)) {
      if (YES == testTerminate(ttContext))
	break;
      sleep(1);
      continue;
    }
    LOG(LOG_DEBUG,
	"Received message from gnunetd.\n");
    switch (ntohs(buffer->type)) {
    case CS_PROTO_RETURN_VALUE:
      /* ignore: confirmation of gnunetd that it received
	 a search request from the other thread */
      break;
    case AFS_CS_PROTO_RESULT_3HASH:
      if (ntohs(buffer->size) != sizeof(AFS_CS_RESULT_3HASH)) {
	closeSocketTemporarily(sock);
	BREAK();
	break;
      }
      reply = (AFS_CS_RESULT_3HASH*)buffer;
      /* now decrypt the reply & call a method to use it */
      hash(&reply->hash,
	   sizeof(HashCode160),
	   &tripleHash);
      for (i=0;i<keyCount;i++) {
	if (equalsHashCode160(&tripleHash,
			      &((AFS_CS_QUERY_GENERIC*)messages[i])->queries[0])) {
	  if (SYSERR == decryptContent((CONTENT_Block*)&reply->result,
				       &keywords[i],
				       result)) {
	    BREAK();
	    continue;
	  }
	  rootNode = (RootNode*) result;
	  switch (htons(rootNode->header.major_formatVersion)) {
	  case ROOT_MAJOR_VERSION:
	    if (htons(rootNode->header.minor_formatVersion) != ROOT_MINOR_VERSION) {
	      LOG(LOG_WARNING, 
		  _("Received RBlock has unsupported minor version %d.\n"),
		  htons(rootNode->header.minor_formatVersion));
	      continue;
	    }
	    break;
	  case SBLOCK_MAJOR_VERSION:
	    LOG(LOG_WARNING, 
		_("Received SBlock in keyword search, that is not unsupported.\n"));
	    continue; /* bah! */	    
	  case NBLOCK_MAJOR_VERSION:
	    if (htons(rootNode->header.minor_formatVersion) != NBLOCK_MINOR_VERSION) {
	      LOG(LOG_WARNING, 
		  _("Received NBlock has unsupported minor version %d.\n"),
		  htons(rootNode->header.minor_formatVersion));
	      continue;
	    }
	    break;
	  default:
	    LOG(LOG_INFO, 
		_("Received reply has unsupported version %d.%d.\n"),
		htons(rootNode->header.major_formatVersion),
		htons(rootNode->header.minor_formatVersion));
	    continue; /* bah! */
	  }
	  LOG(LOG_DEBUG,
	      "Received result from gnunetd, filtering\n");
	  filterResult(rootNode, 
		       i,
		       keyCount,
		       &rc);
	} else {
	  HexName expect;
	  HexName got;

	  hash2hex(&reply->hash,
		   &got);
	  hash2hex(&((AFS_CS_QUERY_GENERIC*)messages[i])->queries[0],
		   &expect);
	  LOG(LOG_WARNING,
	      _("Reply '%s' does not match expected hash '%s'.\n"),
	      &got, &expect);
	}
      }
      break;
    default:     
      LOG(LOG_WARNING,
	  _("Message from server is of unexpected type %d.\n"),
	  ntohs(buffer->type));
      closeSocketTemporarily(sock); /* protocol violation! */
      break;
    }
    FREE(buffer);
  }
  destroyResultContext(&rc, 
  		       keyCount);
  FREE(result);
}

/**
 * Repeatedly send out the queries to GNUnet.
 *
 * @param sqc the context
 */
static void sendQueries(SendQueriesContext * sqc) {
  cron_t now;
  unsigned int i;  
  int remTime;
  unsigned int ttl = 0;
  unsigned int new_ttl;
  unsigned int new_priority;

  cronTime(&now);
  if (sqc->timeout != 0) {
    remTime = sqc->start - now + sqc->timeout;
    if (remTime <= 0) 
      return;
  } else
    remTime = 0x7FFFFFFF; /* max signed int */

  ttl = 0;
  for (i=0;i<sqc->queryCount;i++) {
    LOG(LOG_DEBUG,
	" sending query with ttl %d\n",
	ntohl(sqc->messages[i]->ttl));
    ttl = 1+randomi(TTL_DECREMENT);
    if (NO == checkAnonymityPolicy(AFS_CS_PROTO_QUERY,
				   ntohs(sqc->messages[i]->header.size)
				   + sizeof(PeerIdentity))) {
      break;
    } 
    if (OK == writeToSocket(sqc->sock,
			    &sqc->messages[i]->header)) {
      /* successful transmission to GNUnet,
	 increase ttl/priority for the next time */
      new_ttl = ntohl(sqc->messages[i]->ttl);
      if (new_ttl > ttl)
	ttl = new_ttl; /* ttl = max(all query ttls) */
      if (new_ttl > 0xFFFFFF)
	new_ttl = randomi(0xFFFFFF); /* if we get to large, reduce! */
      sqc->messages[i]->ttl 
	= htonl(randomi(1+4*new_ttl));
      new_priority = ntohl(sqc->messages[i]->priority);
      if (new_priority > 0xFFFFFF)
	new_priority = randomi(0xFFFFFF); /* if we get to large, reduce! */
      sqc->messages[i]->priority 
	= htonl(randomi(1+4*new_priority));
    } 
  }
  ttl = ttl + randomi(1+ttl); /* sleep approximately the time the longest ttl will take */

  /* Don't repeat a search faster than 0.5 seconds */;
  if (ttl < TTL_DECREMENT)
    ttl = TTL_DECREMENT;

  LOG(LOG_DEBUG,
      "Will wait for min(%d, %d) ms\n",
      ttl, 
      remTime);

  /* Do not sleep longer than the amount of time we have until
     we shut down */
  if (ttl >= (unsigned int)remTime)
    ttl = remTime; 


  if (remTime > 0)
    addCronJob((CronJob)&sendQueries,
	       ttl,
	       0,
	       sqc);	     
}

/**
 * Build an initial set of query messages
 * from the list of keywords.
 * @param keyCount the number of keywords
 * @param keywords the keywords (or keys)
 * @param messages the resulting query messages
 */
static void buildMessages(unsigned int keyCount,
			  HashCode160 * keywords,
			  AFS_CS_QUERY *** messages) {
  unsigned int i;
  HashCode160 doubleHash;

  *messages = MALLOC(keyCount * sizeof(AFS_CS_QUERY*));
  for (i=0;i<keyCount;i++) {
    (*messages)[i] = MALLOC(sizeof(AFS_CS_QUERY)+sizeof(HashCode160));
    (*messages)[i]->header.size 
      = htons(sizeof(AFS_CS_QUERY)+sizeof(HashCode160));
    (*messages)[i]->header.type 
      = htons(AFS_CS_PROTO_QUERY);
    (*messages)[i]->ttl 
      = htonl(TTL_DECREMENT * 4 + randomi(keyCount * 5 * cronSECONDS));
    (*messages)[i]->priority 
      = htonl(5+randomi(20));
    hash(&keywords[i],
	 sizeof(HashCode160),
	 &doubleHash);
    hash(&doubleHash,
	 sizeof(HashCode160),
	 &(((AFS_CS_QUERY_GENERIC*)((*messages)[i]))->queries[0]));
  }
}

/**
 * Parse the keywords (join at spaces, separate at AND).
 * @param num_keywords the number of ascii-keywords
 * @param keywords the list of ascii-keywords
 * @param keys the hashs of the keywords to set (= the keys, not the queries!)
 * @return -1 on error, 0 if we should exit without error, number of keys if we actually are going to do something
 */
static int parseKeywords(unsigned int num_keywords,
			 char ** keywords,
			 HashCode160 ** keys) { 
  unsigned int keyCount;
  unsigned int i;
  char * tmp;

  keyCount = 0;
  *keys = MALLOC(sizeof(HashCode160) * (num_keywords+1));
  for (i=0;i<num_keywords;i++) {
    if ( (i == num_keywords-1) ||
	 (0 == strcmp(keywords[i+1],"AND")) ) {
      keywords[keyCount] = keywords[i];
      hash(keywords[i],
	   strlen(keywords[i]),
	   &((*keys)[keyCount++]));
      i++; /* skip the "AND" */
    } else {
      tmp = MALLOC(strlen(keywords[i])+
		   strlen(keywords[i+1])+2);
      tmp[0] = '\0';
      strcat(tmp, keywords[i]);
      strcat(tmp, " ");
      strcat(tmp, keywords[i+1]);      
      keywords[i+1] = tmp;
    }
  }
  return keyCount;
}


/**
 * Perform a namespace search.
 */
int searchRBlock(GNUNET_TCP_SOCKET * sock,
		 char ** keyStrings,
		 int keywordCount,
		 SearchResultCallback handler,
		 void * handlerArgs,
		 TestTerminateThread testTerminate,
		 void * ttContext) {
  int i;
  SendQueriesContext sqc;
  HashCode160 * keywords;
  AFS_CS_QUERY ** messages;

  keywordCount = parseKeywords(keywordCount,
			       keyStrings,
			       &keywords);
  buildMessages(keywordCount,
		keywords,
		&messages);  
  cronTime(&sqc.start);
  sqc.timeout    = getConfigurationInt("AFS",
				       "SEARCHTIMEOUT") * cronSECONDS;
  sqc.sock       = sock;
  sqc.queryCount = keywordCount;
  sqc.messages   = messages;
  addCronJob((CronJob)&sendQueries,
	     0,
	     0,
	     &sqc);
  receiveResults(sock,
		 keywordCount,
		 keywords,
		 messages,
		 handler,
		 handlerArgs,
		 testTerminate,
		 ttContext);
  delCronJob((CronJob)&sendQueries,
	     0,
	     &sqc);
  FREE(keywords);
  for (i=0;i<keywordCount;i++) 
    FREE(messages[i]);  
  FREE(messages);

  return OK;
}


/* end of searchutil.c */
