/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * @file applications/afs/module/gnunet-check.c
 * @brief Little tool to do consistency check of the AFS databases.
 * @author Christian Grothoff
 *
 * FIXME: If some database bucket has entries that do not belong
 * there, the current code will just delete them. It'd be nice if they
 * could be moved instead.
 * 
 */

#include "gnunet_util.h"
#include "gnunet_afs_esed2.h"

#include "fileindex.c"
#include "large_file_support.c"
#include "manager.c"
#include "bloomfilter.c"

static DatabaseAPI * dbAPI;

/* configuration: do we fix problems? */
static int do_fix = YES;
/* configuration: do we reset bloomfilters? */
static int do_reset = NO;

/* priority of fixed content */
static unsigned int fixedPriority;
/* priority of reindexed content */
static unsigned int indexPriority;

/* tcp server result: were all the requests satisfied? */
static int tcp_verifies;

static int be_verbose = NO;
static int be_quiet = NO;

static void PRINTQ(char * format,
		   ...) {
  va_list args;
  if (be_quiet == YES)
    return;
  va_start(args, format);
  vfprintf(stdout, format, args);
  va_end(args);
}

static void PRINTV(char * format,
		   ...) {
  va_list args;
  if (be_verbose == NO)
    return;
  va_start(args, format);
  vfprintf(stdout, format, args);
  va_end(args);
}


/**
 * Check that the content at the given offset/file
 * has the given double hash.
 */
static int checkHashMatch(unsigned short fileNameIndex,
			  size_t offset,
			  HashCode160 * chkquery) {
  CONTENT_Block result;
  CONTENT_Block eresult;
  char * fn;
  HashCode160 hc;
  HashCode160 dhc;
  int fileHandle;
  size_t blen;
  /* check that the specified file at the specified
     offset actually contains the content that we
     are looking for */

  fn = getIndexedFileName(fileNameIndex);
  if (fn == NULL)
    return SYSERR;
  fileHandle = OPEN(fn, O_EXCL, S_IRUSR);
  if (fileHandle == -1) {
    LOG_FILE_STRERROR(LOG_WARNING, "open", fn);
    FREE(fn);
    return SYSERR;
  }
  lseek(fileHandle, 
	offset, SEEK_SET);
  memset(&result, 
	 0, 
	 sizeof(CONTENT_Block));
  blen = READ(fileHandle, 
	      &result,
	      sizeof(CONTENT_Block));
  CLOSE(fileHandle);
  hash(&result, 
       blen, 
       &hc);
  encryptContent(&result,
		 &hc,
		 &eresult);
  hash(&eresult,
       sizeof(CONTENT_Block),
       &dhc);
  if (!equalsHashCode160(&dhc,
			 chkquery)) {
    LOG(LOG_WARNING, 
	_("Content found in file '%s' at %d does not match expected hash.\n"),
	fn,
	offset);    
    FREE(fn);
    return SYSERR;
  } else {
    FREE(fn);
    return OK;
  }
}

typedef struct {
  HashCode160 hc;
  int bucket;
} RemoveList ;

static RemoveList * removeList = NULL;
static int removeCount = 0;

/**
 * We can't remove the bogus content instantly since that would be a
 * concurrent modification while using the iterator. Thus we remember
 * the keys to remove and do it later.
 */
static void deferredRemove() {
  int i;
  EncName enc;

  for (i=0;i<removeCount;i++)
    if (OK != removeContent(&removeList[i].hc,
			    removeList[i].bucket)) {
      hash2enc(&removeList[i].hc,
	       &enc);
      PRINTQ(_("Deferred content removal of '%s' failed!\n"),
	     &enc);
    }
  GROW(removeList,
       removeCount,
       0);
}

/**
 * If we are fixing problems, remove this content and
 * print the appropriate messages.
 */
static void ifFixRemove(HashCode160 * query, 
 	  	        int bucket) {
  if (do_fix == YES) {    
    GROW(removeList,
	 removeCount,
	 removeCount+1);
    memcpy(&removeList[removeCount-1].hc,
	   query,
	   sizeof(HashCode160));
    removeList[removeCount-1].bucket = bucket;
    PRINTQ(_("Will fix (deferred).\n"));
  } else
    PRINTQ("\n");	  
}

/**
 * This function is called for each entry in the
 * content/index/lookup database.
 */
static void checkDatabaseContent(HashCode160 * query,
				 ContentIndex * ce,
				 int bucket,
				 void * result,
				 int len) {
  EncName hn;
  
  hash2enc(query,
	   &hn);  

  if (computeBucketGlobal(query) != (unsigned int)bucket) {
    PRINTQ(_("Entry '%s' is in wrong bucket %d (expected %d). "),
	   (char*)&hn,
	   bucket,
	   computeBucketGlobal(query));
    ifFixRemove(query,
		bucket);
    return;
  }
  switch(ntohs(ce->type)) {
  case LOOKUP_TYPE_CHK:
    if (len != 0) {
      if (len != sizeof(CONTENT_Block)) {
	PRINTQ(_("Bad content stored for '%s' (bad length %d). "),
	       (char*)&hn, 
	       len);
	ifFixRemove(query,
		    bucket); 
	break;
      }
    } else {
      if (SYSERR == checkHashMatch(ntohs(ce->fileNameIndex),
				   ntohl(ce->fileOffset),
				   query)) {
	PRINTQ(_("Bad CHK content indexed for '%s' "),
	       (char*)&hn);
	ifFixRemove(query,
	            bucket); 
	break;
      }
    }
    if (do_reset == YES) {
	addToBloomfilter(singleBloomFilter,
			 query);
    } else {
      if (testBloomfilter(singleBloomFilter,
			  query) == NO) {
	PRINTQ(_("Bloomfilter test failed for '%s' content '%s' "),
	       "CHK",
	       (char*)&hn);
	if (do_fix == YES) {
	  addToBloomfilter(singleBloomFilter,
			   query);
	  PRINTQ(_("Fixed.\n"));
	} else
	  PRINTQ("\n");	
      }
    }
    break;
  case LOOKUP_TYPE_CHKS:
    if (len != 0) {
      if (len != sizeof(CONTENT_Block)) {
	PRINTQ("Bad content stored for %s (bad length %d) ",
	       (char*)&hn, 
	       len);
	ifFixRemove(query,
		    bucket); 
	break;
      }
    } else {
      if (SYSERR == checkHashMatch(ntohs(ce->fileNameIndex),
				   ntohl(ce->fileOffset),
				   query)) {
	PRINTQ(_("Bad CHKS content indexed for '%s' "),
	       (char*)&hn);
	ifFixRemove(query,
	            bucket);
	break;
      }
    }
    break;
  case LOOKUP_TYPE_3HASH:
    if (do_reset == YES) {
	addToBloomfilter(singleBloomFilter,
			 query);
    } else {
      if (testBloomfilter(singleBloomFilter,
			  query) == NO) {
	PRINTQ(_("Bloomfilter test failed for '%s' content '%s' "),
	       "3HASH",
	       (char*)&hn);
	if (do_fix == YES) {
	  addToBloomfilter(singleBloomFilter,
			   query);
	  PRINTQ(_("Fixed.\n"));
	} else
	  PRINTQ("\n");	
      }
    }
    break;
  case LOOKUP_TYPE_SUPER:
    if (do_reset == YES) {
	addToBloomfilter(superBloomFilter,
			 query);
    } else {
      if (testBloomfilter(superBloomFilter,
			  query) == NO) {
	PRINTQ(_("Bloomfilter test failed for '%s' content '%s' "),
	       "SUPER hash",
	       (char*)&hn);
	if (do_fix == YES) {
	  addToBloomfilter(superBloomFilter,
			   query);
	  PRINTQ(_("Fixed.\n"));
	} else
	  PRINTQ("\n");	
      }
    }
    break;
  case LOOKUP_TYPE_SBLOCK:
    if (do_reset == YES) {
	addToBloomfilter(singleBloomFilter,
			 query);
    } else {
      if (testBloomfilter(singleBloomFilter,
			  query) == NO) {
        PRINTQ(_("Bloomfilter test failed for '%s' content '%s' "),
	       "SBLOCK",
	       (char*)&hn);
	if (do_fix == YES) {
	  addToBloomfilter(singleBloomFilter,
			   query);
	  PRINTQ(_("Fixed.\n"));
	} else
	  PRINTQ("\n");	
      }
    }
    break;
  default:
    PRINTQ(_("Unexpected content type %d. "),
	   ntohs(ce->type));
    ifFixRemove(query,
		bucket);
    break;
  }
}

/**
 * Check that for each entry in the contentdatabase
 * there is an entry in the lookup-database.
 */
static void checkDatabase() {
  void * iterState;
  int count;
  HashCode160 hc;
  ContentIndex ce;
  void * data;
  int len;
  int bucket;
  
  PRINTQ(_("Checking Content Database\n"));
  count = 0;
  iterState = makeDatabaseIteratorState();
  data = NULL;
  while (OK == databaseIterator(iterState,
				&hc,
				&ce,
				&bucket,
				&data,
				&len)) {
    checkDatabaseContent(&hc,
			 &ce,
			 bucket,
			 data,
			 len);
    count++;
    FREENONNULL(data);
    data = NULL;
  } 
  deferredRemove();
  PRINTQ(_("\n==> Done checking %d entries in content database.\n"), 
	 count);
}

/**
 * Process a request to insert content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int checkInsertCHK(GNUNET_TCP_SOCKET * sock,
			  AFS_CS_INSERT_CHK * insertRequest) {
  CONTENT_Block * block;
  int len;
  int dup;
  ContentIndex entry;
  HashCode160 hc;
  EncName hn;

  if (ntohs(insertRequest->header.size) != 
      sizeof(AFS_CS_INSERT_CHK)) {
    sendTCPResult(sock, SYSERR);
    return SYSERR;
  }

  memset(&entry,
  	 0,
	 sizeof(ContentIndex));

  block = NULL;
  hash(&insertRequest->content,
       sizeof(CONTENT_Block),
       &hc);
  hash2enc(&hc,
	   &hn);
  PRINTV("* %s (ins)\n",
	 (char*)&hn);
  len = retrieveContent(&hc,
			&entry,
			(void**)&block,
			0,
			NO);
  if(len == sizeof(CONTENT_Block)) 
    if (0 != memcmp(&insertRequest->content,
  	  	    block,
		    sizeof(CONTENT_Block)) )      
      len = SYSERR;
  FREENONNULL(block);
  if (ntohs(entry.type) != LOOKUP_TYPE_CHK) 
    len = SYSERR;
  
  if (len == SYSERR || ntohl(entry.importance)<fixedPriority) {
    PRINTQ((len == SYSERR) 
	   ? _("Content '%s' malformed or missing in database. ") 
	   : _("Content '%s' has low priority in database. "),	   
	   (char*) &hn);
    if (do_fix == YES) {
      entry.type = htons(LOOKUP_TYPE_CHK); /* CHK or CHKS? How can we tell? FIXME! */
      entry.importance = htonl(fixedPriority); 
      memcpy(&entry.hash,
	     &hc,
	     sizeof(HashCode160));
      entry.fileNameIndex = htons(0);
      entry.fileOffset    = htonl(0);
      if (OK == insertContent(&entry, 
			      sizeof(CONTENT_Block),
			      &insertRequest->content,
			      NULL, /* sender = localhost */
			      &dup)) {
	PRINTQ(_("Fixed.\n"));
      } else {
	PRINTQ(_(" cannot fix (database full?)\n"));
      }
    } else 
      PRINTQ("\n");
  }      

  sendTCPResult(sock, OK);
  return OK;
}

/**
 * Process a request to insert content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int checkInsert3HASH(GNUNET_TCP_SOCKET * sock,
			    AFS_CS_INSERT_3HASH * insertRequest) {
  BREAK();
  sendTCPResult(sock, OK);
  return OK;
}

static int checkSuper(GNUNET_TCP_SOCKET * sock,
		      AFS_CS_INDEX_SUPER * superIndexRequest) {
  ContentIndex entry;
  ContentIndex entry2;
  void * result;
  int len;  
  int dup;

  if (ntohs(superIndexRequest->header.size) != 
      sizeof(AFS_CS_INDEX_SUPER)) {
    BREAK();
    return SYSERR;
  }
  if (NO == testBloomfilter(superBloomFilter,
			    &superIndexRequest->superHash)) { 
    if (do_reset == NO)
      PRINTQ(_("Super-Hash not listed in super-hash bloom filter "));
    if (do_fix == YES) {
      addToBloomfilter(superBloomFilter,
		       &superIndexRequest->superHash);
      if (do_reset == NO)
        PRINTQ(_("Fixed.\n"));
    } else
      if (do_reset == NO)
        PRINTQ("\n");
  }
  entry.type
    = htons(LOOKUP_TYPE_SUPER);
  entry.importance
    = htonl(fixedPriority); 
  entry.fileNameIndex 
    = 0; /* database */
  entry.fileOffset 
    = 0; /* data/content */
  memcpy(&entry.hash,
	 &superIndexRequest->superHash,
	 sizeof(HashCode160));
  result = NULL;
  memset(&entry2,
  	 0,
	 sizeof(ContentIndex));
  len = retrieveContent(&superIndexRequest->superHash,
			&entry2,
			&result,
			0,
			NO);
  FREENONNULL(result);
  if (SYSERR == len || ntohl(entry2.importance)<fixedPriority) {
    EncName expect;
    
    hash2enc(&superIndexRequest->superHash,
	     &expect);
    PRINTQ(_("Did not find super-hash entry in "
	     "lookup database for hash %s (or had low priority). "),
	   (char*)&expect);    
    if (do_fix == YES) {
      if (OK == insertContent(&entry, 
			      0,
			      NULL,
			      NULL,
			      &dup)) {
	PRINTQ(_("Fixed.\n"));
      } else {
	PRINTQ(_("Failed to fix.\n"));
      }
    } else
      PRINTQ("\n"); 
  } else {
    entry2.importance = entry.importance;
    if (0 != memcmp(&entry, 
		    &entry2, 
		    sizeof(ContentIndex))) {
      EncName have;
      EncName expect;
      
      hash2enc(&entry2.hash,
	       &have);
      hash2enc(&entry.hash,
	       &expect);
      PRINTQ(_("Entry in database for super-hash does not "
	       "match expectations (have: %s, %u, %u, %u; "
	       "expected: %s, %u, %u, %u). "),
	     (char*)&have, 
	     ntohl(entry2.importance),
	     ntohs(entry2.fileNameIndex), 
	     ntohl(entry2.fileOffset),
	     (char*)&expect,
	     ntohl(entry.importance), 
	     ntohs(entry.fileNameIndex), 
	     ntohl(entry.fileOffset));    
      if (do_fix == YES) {
	if (OK == insertContent(&entry, 
				0,
				NULL,
				NULL,
				&dup)) {
	  PRINTQ(_("Fixed.\n"));
	} else {
	  PRINTQ(_("Failed to fix.\n"));
	}
      } else
 	PRINTQ("\n");
    }
  }
  return sendTCPResult(sock, 
		       OK);
}

/**
 * Process a request to index content from the client.
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int checkIndex(GNUNET_TCP_SOCKET * sock,
		      AFS_CS_INDEX_BLOCK * indexingRequest) {
  HashCode160 triple;
  HashCode160 * query;
  ContentIndex res;
  EncName hn;
  void * data;
  int len;
  int dup;

  hash2enc(&indexingRequest->contentIndex.hash,
	   &hn);
  PRINTV("* %s (idx)\n",
	 (char*)&hn);
  switch (ntohs(indexingRequest->contentIndex.type)) {
  case LOOKUP_TYPE_3HASH:
    hash(&indexingRequest->contentIndex.hash,
	 sizeof(HashCode160),
	 &triple);
    query = &triple;
    break;
  case LOOKUP_TYPE_CHK:
  case LOOKUP_TYPE_CHKS:
    query = &indexingRequest->contentIndex.hash;
    break;
  default:  
    LOG(LOG_ERROR,
	_("Unexpected content index type: %d.\n"),
	ntohs(indexingRequest->contentIndex.type));
    return SYSERR; 
  }
  if (ntohs(indexingRequest->header.size) != 
      sizeof(AFS_CS_INDEX_BLOCK)) {
    BREAK();
    sendTCPResult(sock, SYSERR);
    return SYSERR;
  }
  /* check if everything is already in place, and if not and 
     we are allowed to fix, do the write-actions: */
  memset(&res,
  	 0,
	 sizeof(ContentIndex));

  data = NULL;
  len = retrieveContent(query,
			&res,
			&data,
			0,
			NO);
  FREENONNULL(data);
  indexingRequest->contentIndex.importance 
    = htonl(indexPriority);
  if ( (len == SYSERR) || 
       (ntohl(res.importance) < indexPriority)) {
    PRINTQ((len == SYSERR) 
	   ? ("Content '%s' not indexed in lookup database. ")
	   : _("Content '%s' had low priority in lookup database. "),
	   (char*) &hn);
    if (do_fix == YES) {
      if (SYSERR ==
	  insertContent(&indexingRequest->contentIndex,
			0,
			NULL,
			NULL,
			&dup)) {
	PRINTQ(_("Could not fix, insertion failed.\n"));
      } else {
	PRINTQ(_("Fixed.\n"));
      }
    } else
      PRINTQ("\n");
  } else { /* test if correct */
    if (0 != memcmp(&res.hash, 
		    &indexingRequest->contentIndex.hash,
		    sizeof(HashCode160))) {
      PRINTQ(_("Bad value (hash) stored in database "));
      if (do_fix == YES) {
	if (SYSERR ==
	    insertContent(&indexingRequest->contentIndex,
			  0,
			  NULL,
			  NULL,
			  &dup)) {
	  PRINTQ(_("Could not fix, insertion failed.\n"));
	} else {
	  PRINTQ(_("Fixed.\n"));
	}
      } else
	PRINTQ("\n");
    }
  }
  sendTCPResult(sock, OK);
  return OK;
}


/**
 * Process a query to list a file as on-demand encoded from the client.
 * (code copied from afs/handler.c).
 *
 * @return SYSERR if the TCP connection should be closed, otherwise OK
 */
static int csHandleRequestIndexFile(GNUNET_TCP_SOCKET * sock,
				    AFS_CS_INDEX_FILE * listFileRequest) {
  HexName hex;
  char * filename;
  char * prefix;
  int ret;

  if (ntohs(listFileRequest->header.size) != 
      sizeof(AFS_CS_INDEX_FILE)) {
    BREAK();
    return SYSERR;
  }
  hash2hex(&listFileRequest->hash,
	   &hex);
  filename = getConfigurationString("AFS",
				    "INDEX-DIRECTORY");
  if (filename == NULL) {
    BREAK();
    return -1;
  }
  prefix = expandFileName(filename);
  FREE(filename);
  filename = MALLOC(strlen(prefix) + 42);
  strcpy(filename, prefix);
  FREE(prefix);
  strcat(filename, "/");
  strcat(filename, (char*) &hex);

  ret = sendTCPResult(sock, 
		      appendFilename(filename));
  FREE(filename);
  return ret;
}


/**
 * Handle data available on the TCP socket descriptor;
 * check that the request is already fullfilled.
 */
static void checkProcessor(int * sockptr) {
  CS_HEADER * hdr;
  GNUNET_TCP_SOCKET sock;
  int i;
  int sockDescriptor;

  sockDescriptor = *sockptr;

  /* register the socket */
  initGNUnetServerSocket(sockDescriptor,
			 &sock);
  while (1) {
    hdr = NULL;    
    if (SYSERR == readFromSocket(&sock,
				 &hdr) )
      break; /* connection closed */
    /* demultiplex */
    switch (ntohs(hdr->type)) {
    case AFS_CS_PROTO_INDEX_FILE:
      i = csHandleRequestIndexFile(&sock,
				   (AFS_CS_INDEX_FILE*)hdr);
      break;
    case AFS_CS_PROTO_UPLOAD_FILE:
      /* for now: just ignore */
      i = sendTCPResult(&sock, 
			OK);
      break;
    case AFS_CS_PROTO_INSERT_3HASH:
      i = checkInsert3HASH(&sock,
			   (AFS_CS_INSERT_3HASH*)hdr);
      break;
    case AFS_CS_PROTO_INSERT_CHK:
      i = checkInsertCHK(&sock,
			 (AFS_CS_INSERT_CHK*)hdr);
      break;
    case AFS_CS_PROTO_INDEX_BLOCK:
      i = checkIndex(&sock,
		     (AFS_CS_INDEX_BLOCK*) hdr);
      break;
    case AFS_CS_PROTO_INDEX_SUPER: 
      i = checkSuper(&sock,
		     (AFS_CS_INDEX_SUPER*) hdr);
      break;
    default:
      i = SYSERR;
      break;
    } /* end of switch */
    if (OK != i) {
      break;
    }
    FREE(hdr);
  }
  destroySocket(&sock);
}

/**
 * Check that the given file is properly indexed
 * (and fix if appropriate). Also return SYSERR
 * if the file is gone and should thus be removed
 * from the list.
 */
int checkIndexedFile(char * name,
		     int index,
		     GNUNET_TCP_SOCKET * sock) {
  int result;
  Block * top;

  PRINTQ("* %s\n",
	 name);
  top = insertFile(sock,
		   name,
		   NULL,
		   NULL);
  if (top != NULL) {
    top->vtbl->done(top, NULL);
    result = tcp_verifies;
  } else
    result = SYSERR;
  if (result == SYSERR) {
    PRINTQ(_("Problem checking indexing of file '%s' "),
	   name);
    if (do_fix == YES) {
      PRINTQ(_("Removing file from list.\n"));
      return SYSERR; /* remove file, there was a problem */
    } else {
      PRINTQ("\n");
      return OK;
    }
  }
  return OK;
}

/**
 * Check that all files that are listed in
 * the list of indexed files actually exist
 * and that they are properly indexed in the
 * lookup (triple->double hash) database.
 */
static void checkIndexedFileList() {
  GNUNET_TCP_SOCKET * sock;
  int count;

  sock = getClientSocket();
  if (sock == NULL)
    DIE_STRERROR("getClientSocket");
  PRINTQ(_("Checking indexed files\n"));
  count = forEachIndexedFile((IndexedFileNameCallback)&checkIndexedFile,
			     sock);
  PRINTQ(_("==> Done with %d indexed files.\n"),
	 count);
  releaseClientSocket(sock);
}

/**
 * Print a list of the options we offer.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    { 'a', "all", NULL,
      gettext_noop("check everything") },
    { 'D', "data", NULL,
      gettext_noop("only check the content database") },
    { 'f', "files", NULL,
      gettext_noop("only check the indexed files") },
    HELP_HELP,
    HELP_LOGLEVEL,
    { 'n', "nofix", NULL,
      gettext_noop("do not fix problems, only report") },
    { 'p', "prio", "PRIORITY",
      gettext_noop("specifies the priority of the restored content") },
    { 'q', "quiet", NULL,
      gettext_noop("be quiet") },
      { 'r', "reset", NULL,
      gettext_noop("reset bloom-filters (requires 'a' option, slow)") },
    { 'u', "update", NULL,
      gettext_noop("perform AFS database-updates necessary after GNUnet version change") },
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-check [OPTIONS]",
	     _("Check GNUnet AFS databases.\n"
	       "Never run gnunet-check while gnunetd is running!"),
	     help);
}
  
/**
 * Perform option parsing from the command line. 
 */
static int parseCommandLine(int argc, 
			    char * argv[]) {
  int c;

  /* set the 'magic' code that indicates that
     this process is 'gnunetd' (and not any of
     the user-tools).  Needed such that we use
     the right configuration file... */
  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  FREENONNULL(setConfigurationString("GNUNETD",
				     "LOGFILE",
				     NULL));
  FREENONNULL(setConfigurationString("GNUNET-INSERT",
				     "INDEX-CONTENT",
				     "YES"));
  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "all",     0, 0, 'a' },
      { "data",    0, 0, 'D' },
      { "files",   0, 0, 'f' },
      { "nofix",   0, 0, 'n' },
      { "prio",    1, 0, 'p' },
      { "reset",   0, 0, 'r' },
      { "update",  0, 0, 'u' },
      { "verbose", 0, 0, 'V' },
      { "quiet",   0, 0, 'q' },
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "vhdc:nDp:faVqruL:", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;    
    switch(c) {
    case 'L':
      FREENONNULL(setConfigurationString("GNUNETD",
					 "LOGLEVEL",
					 GNoptarg));
     break;
    case 'q':
      be_quiet = YES;
      break;
    case 'a':
      FREENONNULL(setConfigurationString("GNUNET-CHECK",
					 "MODE",
					 "a"));
      break;
    case 'D':
      FREENONNULL(setConfigurationString("GNUNET-CHECK",
					 "MODE",
					 "d"));
      break;
    case 'f':
      FREENONNULL(setConfigurationString("GNUNET-CHECK",
					 "MODE",
					 "f"));
      break;
    case 'h': 
      printhelp(); 
      return SYSERR;
    case 'r':
      FREENONNULL(setConfigurationString("GNUNET-CHECK",
			      		 "RESETBLOOMFILTERS",
					 "YES"));
      do_reset = YES;
      break;
    case 'u':
      FREENONNULL(setConfigurationString("GNUNET-CHECK",
			      		 "UPDATE",
					 "YES"));
      do_reset = YES;
      break;
    case 'p': {
      unsigned int prio;
      
      if (1 != sscanf(GNoptarg, "%ud", &prio)) {
	LOG(LOG_FAILURE,
	    "You must pass a number to the '%s' option.\n",
	    "-p");
	return SYSERR;
      }
      setConfigurationInt("GNUNET-CHECK",
			  "FIXED-PRIORITY",
			  prio);
      break;
    }
    case 'n':
     do_fix = NO;
      break;
    case 'v': 
      printf("GNUnet v%s, gnunet-check v%s\n",
	     VERSION, AFS_VERSION);
      return SYSERR;
    case 'V':
      be_verbose = YES;
      break;
    default:
      printf(_("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  }
  if (GNoptind < argc) {
    printf(_("Invalid arguments: "));
    while (GNoptind < argc)
      printf("%s ", argv[GNoptind++]);
    printf(_("\nExiting.\n"));
    return SYSERR;
  }
  if (do_fix == NO) 
    PRINTQ(_("You selected verification only, will not fix problems!\n"));
  return OK;
}

typedef struct {
  int fd;
  PTHREAD_T pt;
} CSPair;


static Semaphore * serverSignal;
static int listenerFD;

/**
 * Initialize the TCP port and listen for incoming connections.
 */
static void * tcpListenMain() {
  CSPair * clients = NULL;
  int clientsSize = 0;

  int incomingFD;
  int lenOfIncomingAddr;
  int listenerPort;
  struct sockaddr_in serverAddr, clientAddr;
  const int on = 1;

  listenerPort = getGNUnetPort(); 
  /* create the socket */
  if ( (listenerFD = SOCKET(PF_INET, SOCK_STREAM, 0)) < 0) 
    DIE_STRERROR("socket");
 
  /* fill in the inet address structure */
  memset((char *) &serverAddr, 0, sizeof(serverAddr));
  serverAddr.sin_family 
    = AF_INET;
  serverAddr.sin_addr.s_addr
    = htonl(INADDR_ANY);
  serverAddr.sin_port   
    = htons(listenerPort);
 
  if ( SETSOCKOPT(listenerFD, 
		  SOL_SOCKET, 
		  SO_REUSEADDR, 
		  &on, sizeof(on)) < 0 )
    DIE_STRERROR("setsockopt");
  
  if (BIND(listenerFD, 
	   (struct sockaddr *) &serverAddr,
	   sizeof(serverAddr)) < 0) {
    printf(_("Could not bind to port %d.  Is gnunetd running?\n"),
	   listenerPort);
    DIE_STRERROR("bind");
  }
  
  /* start listening for new connections */
  LISTEN(listenerFD, 1); 
  SEMAPHORE_UP(serverSignal);
  /* process incoming data */
  while (listenerFD != -1) {
    /* wait for a connection and process it */
    lenOfIncomingAddr = sizeof(clientAddr);
    incomingFD = ACCEPT(listenerFD,
			(struct sockaddr *)&clientAddr, 
			&lenOfIncomingAddr);
    if (incomingFD < 0) {
      if (listenerFD != -1)
	LOG_STRERROR(LOG_ERROR, "accept");
      continue;
    }
    LOG(LOG_DEBUG, 
	"TCP: starting server\n");
    GROW(clients,
	 clientsSize,
	 clientsSize+1);
    clients[clientsSize-1].fd = incomingFD;
    if ((PTHREAD_CREATE(&clients[clientsSize-1].pt,
			(PThreadMain) &checkProcessor, 
			(void *)&incomingFD,
			16*1024)) != 0) 
      DIE_STRERROR("pthread_create");
  } /* while (listenerFD != -1) */
  while (clientsSize > 0) {
    void * unused;

    SHUTDOWN(clients[clientsSize-1].fd, 2);
    PTHREAD_JOIN(&clients[clientsSize-1].pt, &unused);
    GROW(clients,
	 clientsSize,
	 clientsSize-1);
  }
  return NULL;
} 

/**
 * Maximum length of the name of an indexed file (with path).
 */ 
#define MAX_LINE_SIZE 1024

/**
 * Update from 0.6.1b to 0.6.2.  Difference is that
 * now all files listed in the index-list must
 * be in INDEX-DIRECTORY and have the hash of the
 * contents for the name.  This code adds the
 * correct links and updates the list.
 */
static int update061b() {
  char * filename;
  char * indexDir;
  FILE * handle;
  char * result;
  char * line;
  char * fil;
  char * afsdir;
  int fix_count;
  char ** lines;
  int line_count;
  int i;
 
  afsdir = getFileName("AFS",
		       "AFSDIR",
		       "Configuration file must specify filename for"\
		       " storing AFS data in section"\
		       " %s under %s.\n");
  fil = MALLOC(strlen(afsdir)+
	       strlen(DATABASELIST)+2);
  strcpy(fil, afsdir);
  mkdirp(fil); /* important: the directory may not exist yet! */
  strcat(fil, "/");
  strcat(fil, DATABASELIST);
  FREE(afsdir);

  handle = FOPEN(fil, "r+");
  if (handle == NULL) {
    /* no indexed files, nothing to do! */
    FREE(fil);
    return OK;
  }
  filename = getConfigurationString("AFS",
				    "INDEX-DIRECTORY");
  if (filename == NULL) {
    LOG(LOG_WARNING,
	_("Cannot fix indexed content, '%s' option not set!\n"),
	"INDEX-DIRECTORY");
    FREE(fil);
    return SYSERR;
  }
  indexDir = expandFileName(filename);
  mkdirp(indexDir);
  FREE(filename);  


  fseek(handle, 0, SEEK_SET);
  line = MALLOC(MAX_LINE_SIZE);
  result = line;
  lines = NULL;
  line_count = 0;
  fix_count = 0;
  while (1) {    
    result = fgets(line, MAX_LINE_SIZE - 1, handle);
    if (result == NULL)
      break;
    GROW(lines,
	 line_count,
	 line_count+1);
    if (strlen(result) > 1) {
      lines[line_count-1] = STRDUP(result);
      if (0 != strncmp(result,
		       indexDir,
		       strlen(indexDir))) 
	fix_count++;
    }
  }
  if (fix_count == 0) {
    fclose(handle);
    FREE(indexDir);
    for (i=0;i<line_count;i++)
      FREENONNULL(lines[i]);
    GROW(lines,
	 line_count,
	 0);
    FREE(fil);
    FREE(line);
    FREE(indexDir);
    return OK;
  }  
  fseek(handle, 0, SEEK_SET);
  truncate(fil, 0);
  
  for (i=0;i<line_count;i++) {
    if ( ( lines[i] != NULL) &&
	 (0 != strncmp(lines[i],
		       indexDir,
		       strlen(indexDir))) ) {
      HashCode160 hc;
      if (OK != getFileHash(lines[i],
			    &hc)) {
	fprintf(handle,
		"\n");
      } else {
	HexName hex;
	char * lname;
	hash2hex(&hc,
		 &hex);
	lname = MALLOC(strlen(indexDir) + sizeof(HexName) + 1);
	strcpy(lname,
	       indexDir);
	strcat(lname,
	       "/");
	strcat(lname,
	       (char*)&hex);
	if (0 != SYMLINK(lines[i], lname)) {
	  DIE_STRERROR("symlink");
	} else {
	  fprintf(handle,
		  "%s\n",
		  lname);
	}
	FREE(lname);
      }
    } else {
      fprintf(handle,
	      "%s\n",
	      lines[i] == NULL ? "" : lines[i]);
    }
    FREENONNULL(lines[i]);
  }
  GROW(lines,
       line_count,
       0);
  FREE(fil);
  FREE(line);
  FREE(indexDir);
  fclose(handle);  
  return OK;
}

int main(int argc, char * argv[]) {
  PTHREAD_T tcpPseudoServer;
  char * checkString;
  char check;
  int i;
  void * unused;
  
  if (SYSERR == initUtil(argc, argv, &parseCommandLine))
    return 0;

  if (testConfigurationString("GNUNET-CHECK",
			      "UPDATE",
			      "YES")) {
    int * sbit;
    int version;
    int val;

    sbit = NULL;
    if (sizeof(int) == stateReadContent("VERSION",
					(void**)&sbit)) {
      version = *sbit;
      FREE(sbit);
      switch (ntohl(version)) {
      case 0x061b: /* need to add links for indexed files */
	printf(_("Updating from version %x\n"),
	       version);
	if (SYSERR == update061b())
	  errexit(_("Errors while updating version!\n"));
	/* finally, update version to current */
	val = htonl(0x0620);
	stateWriteContent("VERSION",
			  sizeof(int),
			  &val);
	break;
      case 0x0620:
	printf(_("State is current, no update required.\n"));
	break;
      default:
	printf(_("Unknown GNUnet version %x.\n"),
	       version);
      }
    } else {
      FREENONNULL(sbit);
      version = 0; /* first start */
    }
  }
  
  checkString = getConfigurationString("GNUNET-CHECK", 
				       "MODE");
  if (checkString != NULL)
    check = checkString[0];
  else
    check = 'n';
  FREENONNULL(checkString);
  if (check == 'n') {
    if (testConfigurationString("GNUNET-CHECK",
				"UPDATE",
				"YES")) {
      doneUtil();
      return 0;
    }
    fprintf(stderr,
	    _("You must choose what to check (specify '%s', '%s', or '%s').\n"),
	    "-D", "-f", "-a");
    doneUtil();
    return -1;
  }

  fixedPriority = getConfigurationInt("GNUNET-CHECK",
		 	              "FIXED-PRIORITY");
  if (fixedPriority <= 0) {
    LOG(LOG_DEBUG, 
        "GNUNET-CHECK/FIXED-PRIORITY in conf either <= 0 or missing\n");
    fixedPriority = 0;
  }

  indexPriority = getConfigurationInt("GNUNET-INSERT",
		 	              "CONTENT-PRIORITY");
  if (indexPriority <= 0) {
    LOG(LOG_DEBUG,
    	"GNUNET-INSERT/CONTENT-PRIORITY in conf either <= 0 or missing\n");
    indexPriority = 65536;
  }

  initManager();
  initFileIndex();
  initBloomfilters();

  serverSignal = SEMAPHORE_NEW(0);
  if (0 != PTHREAD_CREATE(&tcpPseudoServer,
			  (PThreadMain) &tcpListenMain, 
			  NULL,
			  16*1024))
    DIE_STRERROR("pthread_create");
  SEMAPHORE_DOWN(serverSignal);
  SEMAPHORE_FREE(serverSignal);

  if ( (do_reset == YES) && 
       (check != 'a') ) {
    errexit(_("Cannot use option '%s' without option '%s'.\n"),
	    "--reset", "-a");
  }
  if ( (do_reset == YES) && 
       (check == 'a') &&
       (do_fix == YES) ) {
    resetBloomfilter(singleBloomFilter);
    resetBloomfilter(superBloomFilter);
  }
  if ((check == 'a') || (check == 'f'))
    checkIndexedFileList();
  if ((check == 'a') || (check == 'd'))
    checkDatabase(); 

  i = listenerFD;
  listenerFD = -1;
  SHUTDOWN(i, 2);
  CLOSE(i);
  PTHREAD_JOIN(&tcpPseudoServer, &unused);
  doneBloomfilters();
  doneManager();
  doneFileIndex();
  doneUtil();
  return 0;
}


/* end of gnunet-check.c */
