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
 * @file applications/afs/esed2/insertutil.c
 * @brief Break file that is inserted into blocks and encrypts
 *        them according to the CHK-triple-hash-tree scheme (ESED II).
 * @see http://www.ovmj.org/GNUnet/encoding.php3
 * @author Krista Bennett
 * @author Christian Grothoff
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"
#if USE_LIBEXTRACTOR
#include <extractor.h>
#endif

/**
 * Ask gnunetd to receive and store a file in
 * on the server side.
 * 
 * @param sock connection to gnunetd
 * @param filename the name to add to fileindex.c
 * @return the index, -1 on error
 */
static int transferFile(GNUNET_TCP_SOCKET * sock,
			const char * fn) {
  AFS_CS_INDEX_FILE * request;
  AFS_CS_UPLOAD_FILE * upload;
  char * filename;
  int result;
  int index;
  int ret;
  unsigned int pos;
  unsigned int fsize;
  unsigned int delta;
  int handle;
  HashCode160 hc;

  /* first: request index */
  filename 
    = expandFileName(fn);   
  getFileHash(filename,
	      &hc);
  fsize
    = (unsigned int) getFileSize(filename);
  request
    = MALLOC(sizeof(AFS_CS_INDEX_FILE));
  request->header.size 
    = htons(sizeof(AFS_CS_INDEX_FILE));
  request->header.type 
    = htons(AFS_CS_PROTO_INDEX_FILE);
  request->hash
    = hc;
  request->filesize
    = htonl(fsize);
  if ( (SYSERR == writeToSocket(sock,
			      &request->header)) ||
       (SYSERR == readTCPResult(sock,
				&index)) ) {
    LOG(LOG_WARNING, 
	_("Could not request or receive data"
	  " from gnunetd.  Is gnunetd running?\n"));
    FREE(filename);
    FREE(request);
    return -1;
  }
  FREE(request);
  if (index == -1) {
    LOG(LOG_WARNING,
	_("gnunetd refused to index file (consult gnunetd logs).\n"));
    FREE(filename);
    return -1;
  }
  if (index == 0) {
    BREAK();
    FREE(filename);
    return -1;
  }

  if (testConfigurationString("GNUNET-INSERT",
			      "LINK",
			      "YES")) {
    AFS_CS_LINK_FILE * req;
    int ret;

    req = MALLOC(sizeof(AFS_CS_LINK_FILE)+strlen(filename)+1);
    req->header.type
      = htons(AFS_CS_PROTO_LINK_FILE);   
    req->header.size 
      = htons(sizeof(AFS_CS_LINK_FILE)+strlen(filename)+1);
    memcpy(&req->hash,
	   &hc,
	   sizeof(HashCode160));
    memcpy(&((AFS_CS_LINK_FILE_GENERIC*)req)->data[0],
	   filename,
	   strlen(filename)+1);
    if ( (SYSERR == writeToSocket(sock,
				  &req->header)) ||
	 (SYSERR == readTCPResult(sock,
				  &ret)) ||
	 (ret != OK) ) {
      LOG(LOG_WARNING,
	  " link request to gnunetd failed. "
	  "Trying to, make copy instead.\n");
      FREE(req);
    } else {
      /* link successful */
      FREE(req);
      return index;
    }
  }

  /* Do not create link: transfer the file! */
  handle
    = OPEN(filename, O_RDONLY);
  if (handle == -1) {
    LOG(LOG_ERROR,
	"Could not open file: %s\n",
	STRERROR(errno));
    FREE(filename);
    return -1;
  }
  upload 
    = MALLOC(65536);
  upload->header.type 
    = htons(AFS_CS_PROTO_UPLOAD_FILE);
  upload->hash
    = hc;
  pos 
    = 0;
  while (pos < fsize) {
    delta = 65532 - sizeof(AFS_CS_UPLOAD_FILE);
    if (fsize - pos < delta)
      delta = fsize - pos;
    upload->header.size 
      = htons(delta + sizeof(AFS_CS_UPLOAD_FILE));
    upload->pos
      = htonl(pos);
    ret = READ(handle,
	       &((AFS_CS_UPLOAD_FILE_GENERIC*)upload)->data[0],
	       delta);
    if (ret != delta) {
      if (ret == -1) {
	LOG(LOG_ERROR,
	    " could not read file: %s\n",
	    STRERROR(errno));
	index = -1;
	break;
      } else
	GNUNET_ASSERT(0);
    }
    
    if ( (SYSERR == writeToSocket(sock,
				  &upload->header)) ||	 
	 (SYSERR == readTCPResult(sock,
				  &result)) ) {
      LOG(LOG_WARNING, 
	  _("Could not receive data from gnunetd. "
	    "Is gnunetd running?\n"));
      index = -1;
    }
    if (result == -1)
      index = -1;
    if (index == -1)
      break;
    pos += delta;
  }
  FREE(upload);
  CLOSE(handle);
  FREE(filename);
  return index;  
}
  
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
			  int contentPriority) {
  HashCode160 hc;
  AFS_CS_INSERT_3HASH * msg;
  int res;
  
  hash(keyword, 
       strlen(keyword), 
       &hc);
  msg = MALLOC(sizeof(AFS_CS_INSERT_3HASH));
  if (SYSERR == encryptContent((CONTENT_Block*)rn,
			       &hc,
			       &msg->content)) 
    errexit("Encryption failed.\n"); 

  hash(&hc,
       sizeof(HashCode160),
       &msg->doubleHash);
  msg->importance 
    = htonl(contentPriority);
  msg->header.type 
    = htons(AFS_CS_PROTO_INSERT_3HASH);
  msg->header.size 
    = htons(sizeof(AFS_CS_INSERT_3HASH));
  if (SYSERR == writeToSocket(sock,
			      &msg->header)) {
    LOG(LOG_WARNING, 
	_("Could not send data to gnunetd. "
	  "Is gnunetd running?\n"));
    FREE(msg);
    return SYSERR;
  }
  FREE(msg);
  if (SYSERR == readTCPResult(sock,
			      &res)) {
    LOG(LOG_WARNING, 
	_("Server did not send confirmation of insertion.\n"));
    return SYSERR;
  } else {
    if (res == SYSERR)
      LOG(LOG_WARNING, 
	  _("Server could not perform insertion.\n"));
  }
  /* FIXME: somehow I sometimes get a random number back
     here (like 102).  I've instrumented the gnunetd handler
     and the code there was returning '1' (== OK), so this is
     a bit odd... (note that this is rare and only a warning
     is printed; valgrind is happy.  */
  return res;
}

/**
 * Insert (or index) a file under the given name into the local GNUnet
 * node.
 *
 * @param sock connection to gnunetd
 * @param filename the name of the file to insert
 * @param model the insert model used to
 *        update status information; points to NULL if
 *        no status updates shall be given, otherwise 
 *        to a method that takes two size_t arguments
 *        (retrieved so far, total).
 * @param model_data pointer that is passed to the model method
 * @return NULL on error, otherwise the top block
 */
Block * insertFile(GNUNET_TCP_SOCKET * sock,
		   const char * fn, 
		   ProgressModel model,
		   void * model_data) {
  char * filename;
  NodeContext nc;
  size_t filesize;
  Block * top;
  char * restore;
  int ret;

  filename = expandFileName(fn);
  filesize = (size_t) getFileSize(filename);
  restore = getConfigurationString("GNUNET-INSERT",
				   "INDEX-CONTENT");
  if (filesize <= sizeof(CONTENT_Block))
    FREENONNULL(setConfigurationString("GNUNET-INSERT",
				       "INDEX-CONTENT",
				       "NO"));
  nc.pmodel = model;
  nc.data = model_data;
  memset(&nc.stats, 0, sizeof(ProgressStats));
  nc.stats.filesize = filesize;
  nc.priority = getConfigurationInt("GNUNET-INSERT",
				    "CONTENT-PRIORITY");
  if (nc.priority == 0)
    nc.priority = LOCAL_INDEXED_CONTENT_PRIO;
  if (YES == testConfigurationString("GNUNET-INSERT",
				     "INDEX-CONTENT",
				     "YES")) {
    ret = transferFile(sock, filename);
    GNUNET_ASSERT(ret != 0);
    if (ret == -1) {
      LOG(LOG_WARNING,
	  _("Adding to index list failed, trying insertion!\n"));
      nc.index = 0; 
    } else {
      nc.index = ret;
    }
  } else {
    nc.index = 0; /* 0: no indexing */
  }
  if (SYSERR == createIOContext(&nc.ioc,
				filesize,
				filename,
				YES)) {    
    FREE(filename);
    FREENONNULL(setConfigurationString("GNUNET-INSERT",
				       "INDEX-CONTENT",
				       restore));
    FREE(restore);
    return NULL;
  }
  if (filesize <= sizeof(CONTENT_Block))
    top = createTopDBlock(filesize);
  else
    top = createTopIBlock(filesize);
  if (SYSERR == top->vtbl->insert(top, &nc, sock)) {
    top->vtbl->done(top, NULL);
    freeIOC(&nc.ioc, NO);
    FREE(filename);
    FREENONNULL(setConfigurationString("GNUNET-INSERT",
				       "INDEX-CONTENT",
				       restore));
    FREE(restore);
    return NULL;
  }
  freeIOC(&nc.ioc, NO);

  FREE(filename);
  FREENONNULL(setConfigurationString("GNUNET-INSERT",
				     "INDEX-CONTENT",
				     restore));
  FREE(restore);
  return top;
}

#define MIN(a,b)  ( ((a) < (b)) ? (a) : (b))

RootNode * createRootNode(const FileIdentifier * fid,
			  const char * description,
			  const char * shortFN,
			  const char * mimetype) {
  RootNode * rn;

  rn = MALLOC(sizeof(RootNode));
  memset(rn, 0, sizeof(RootNode));
  rn->header.major_formatVersion 
    = htons(ROOT_MAJOR_VERSION);
  rn->header.minor_formatVersion 
    = htons(ROOT_MINOR_VERSION);
  rn->header.fileIdentifier
    = *fid;
  memcpy(&rn->header.description[0],
	 description,
	 MIN(strlen(description)+1, MAX_DESC_LEN-1));
  memcpy(&rn->header.filename[0],
	 shortFN,
	 MIN(strlen(shortFN)+1, MAX_FILENAME_LEN-1));
  memcpy(&rn->header.mimetype[0],
	 mimetype,
	 MIN(strlen(mimetype)+1, MAX_MIMETYPE_LEN));
  return rn;
}

/**
 * Insert a root-block into GNUnet. 
 *
 * @param sock connection to gnunetd
 * @param top the top block of the file
 * @param description description to use
 * @param filenameRoot filename to use
 * @param mimetype mimetype to use
 * @param num_keys the number of keywords to be associated with the file
 * @param keywords the keywords that shall be used to retrieve the file
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
	       RootNode * rootNode) {
  unsigned int i;
  unsigned int priority;
  RootNode * rn;
  int res;
  FileIdentifier fid;

  priority = getConfigurationInt("GNUNET-INSERT",
				 "CONTENT-PRIORITY");
  fid.crc = htonl(crc32N(top->data, top->len));
  fid.file_length = (unsigned int) htonl(top->filesize);
  fid.chk = top->chk;
  rn = createRootNode(&fid, 
		      description, 
		      filenameRoot,
		      mimetype);
  res = OK;
  for (i=0;i<num_keys;i++) 
    if (SYSERR == insertRootWithKeyword(sock,
					rn, 
					keywords[i], 
					priority))
      res = SYSERR;
  /* directory support... */
  makeRootNodeAvailable(rn, DIR_CONTEXT_INSERT);
  publishToCollection(rn);
  if(rootNode != NULL)
    *rootNode = *rn;
  FREE(rn);
  return res;
}




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
		    void * modelArg) {
  char * fileName;
  GNUnetDirectory * dir;
  int handle;
  Block * top;
  char * oldval;
  
  dir = buildDirectory(nodeCount, 
                       dirName,
  	               rootNodes);
  fileName = MALLOC(strlen("/tmp/gnunetdir_") + 
		    strlen(".XXXXXX") + 1);
  strcpy(fileName, "/tmp/gnunetdir_");
  strcat(fileName, ".XXXXXX");
  handle = mkstemp(fileName);
  if (handle == -1)
    DIE_STRERROR("mkstemp");
  
  if (SYSERR == writeGNUnetDirectory(dir, fileName)) {
    LOG(LOG_WARNING,
        "Could not write directory to temporary file '%s'.\n",
	fileName);
    UNLINK(fileName);
    FREE(fileName);
    CLOSE(handle);
    FREE(dir);
    return SYSERR;
  }
  FREE(dir);

  /* ok, insert the directory */
  oldval = setConfigurationString("GNUNET-INSERT",
                	          "INDEX-CONTENT",
				  "NO");
  top = insertFile(sock,
                   fileName,
                   model,
                   modelArg);
  CLOSE(handle);
  UNLINK(fileName);
  FREENONNULL(setConfigurationString("GNUNET-INSERT",
                         	     "INDEX-CONTENT",
				     oldval));
  FREENONNULL(oldval);
  if (top == NULL) {
    LOG(LOG_ERROR,
	_("Error inserting directory %s.\n"
	  "You may want to check whether or not you are out of space.\n"
	  "Run gnunet-stats | grep \"AFS storage left\" to check.\n"),
	fileName);
    FREE(fileName);
    return SYSERR;
  } else {
    memcpy(&fid->chk, &top->chk, sizeof(CHK_Hashes));
    fid->crc = htonl(crc32N(top->data, top->len));
    { 
      unsigned int fs = (unsigned int) top->filesize;
      fid->file_length = htonl(fs);
    }
    FREE(fileName);
    top->vtbl->done(top, NULL);
    return OK;
  }
}

/**
 * Build an RBlock for the given file and insert
 * it into GNUnet under all applicable keywords.
 *
 * @param fid the identifier for the file
 * @param filename the full filename (complete path)
 * @return the RootNode
 */
static RootNode * buildFileRBlock(GNUNET_TCP_SOCKET * sock,
				  const FileIdentifier * fid,
				  const char * filename,
				  const char ** gloKeywords,
				  unsigned int gloKeywordCnt,
				  void * extractors_) {
  RootNode * result;
  int i;
  char * description;
  char * mimetype;
  char * shortFN;
  int nodirectindex;
#if USE_LIBEXTRACTOR
  char ** keywords;
  int num_keywords;
  EXTRACTOR_ExtractorList * extractors = extractors_;
#endif

  mimetype = getConfigurationString("GNUNET-INSERT",
				    "MIMETYPE");
  description = getConfigurationString("GNUNET-INSERT",
				       "DESCRIPTION");
  shortFN = getConfigurationString("GNUNET-INSERT",
				   "FILENAME");
  nodirectindex = testConfigurationString("GNUNET-INSERT",
					  "ADDITIONAL-RBLOCKS",
					  "NO");
  if (shortFN == NULL) {
    const char * tmp;
    tmp = &filename[strlen(filename)-1];
    while (tmp[-1] != DIR_SEPARATOR)
      tmp--;
    shortFN = STRDUP(tmp);
  }
#if USE_LIBEXTRACTOR
  num_keywords = 0;
  keywords = NULL;
  if (!testConfigurationString("GNUNET-INSERT",
			       "EXTRACT-KEYWORDS",
			       "NO")) {
    extractKeywordsMulti(filename,
			 &description,
			 &mimetype,
			 &keywords,
			 &num_keywords,
			 extractors);
  }
#endif
  if (mimetype == NULL)
    mimetype = STRDUP("unknown");
  if (description == NULL)
    description = STRDUP(shortFN);
  result = createRootNode(fid,
			  description,
			  shortFN,
			  mimetype);
  publishToCollection(result);		    
  for (i=0;i<gloKeywordCnt;i++)
    if (OK != insertRootWithKeyword(sock,
				    result, 
				    gloKeywords[i],
				    getConfigurationInt("GNUNET-INSERT",
							"CONTENT-PRIORITY"))) {
      LOG(LOG_ERROR,
	  _("Failed to insert RBlock. "
	    "Is gnunetd running and space available?\n"));
      break;
    }
  
#if USE_LIBEXTRACTOR
  for (i=0;i<num_keywords;i++) {
    if (! nodirectindex) {
      if (OK != insertRootWithKeyword(sock,
				      result, 
				      keywords[i],
				      getConfigurationInt("GNUNET-INSERT",
							  "CONTENT-PRIORITY"))) {
	LOG(LOG_ERROR,
	    _("Failed to insert RBlock. "
	      "Is gnunetd running and space available?\n"));
      }
    }
    FREE(keywords[i]);
  }
  GROW(keywords, num_keywords, 0);
#endif
  FREE(mimetype);
  FREE(description);
  FREE(shortFN);
  return result;
}

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
				unsigned int gloKeywordCnt) {
  RootNode * result;
  int i;
  char * dn;

  dn = MALLOC(strlen(dirName) + strlen(GNUNET_DIRECTORY_EXT) + 1);
  strcpy(dn, dirName);
  if ( (strlen(dn) < strlen(GNUNET_DIRECTORY_EXT)+1) ||
       (0 != strcmp(&dn[strlen(dn)-strlen(GNUNET_DIRECTORY_EXT)],
		    GNUNET_DIRECTORY_EXT)) ) {
    strcat(dn, GNUNET_DIRECTORY_EXT);
  }

  result = createRootNode(fid,
			  description,
			  dn,
			  GNUNET_DIRECTORY_MIME);
  FREE(dn);
  for (i=0;i<gloKeywordCnt;i++) {
    if (OK != insertRootWithKeyword(sock,
				    result, 
				    gloKeywords[i],
				    getConfigurationInt("GNUNET-INSERT",
							"CONTENT-PRIORITY"))) {
      LOG(LOG_ERROR,
	  _("Failed to insert RBlock. "
	    "Is gnunetd running and space available?\n"));
    }
  }
  return result;
}

typedef struct {
  FileIdentifier * fid;
  int fiCount;
  RootNode * rbs;
  int rbCount;
  GNUNET_TCP_SOCKET * sock;
  const char ** gloKeywords;
  unsigned int gloKeywordCnt;
  void * extractors_;
  ProgressModel model;
  void * model_arg;
  InsertWrapper insert;
  void * insert_arg;
} DECData;

static void dirEntryCallback(char * filename,
			     char * dirName,
			     DECData * data) {
  char * fn;
  RootNode * rb;
  
  GROW(data->fid,
       data->fiCount,
       data->fiCount+1);
  GROW(data->rbs,
       data->rbCount,
       data->rbCount+1);
  fn = MALLOC(strlen(filename) + strlen(dirName) + 2);
  strcpy(fn, dirName);
  strcat(fn, "/");
  strcat(fn, filename);
  rb = insertRecursively(data->sock,
			 fn,
			 &data->fid[data->fiCount-1],
			 (const char**) data->gloKeywords,
			 data->gloKeywordCnt,
			 data->extractors_,
			 data->model,
			 data->model_arg,
			 data->insert,
			 data->insert_arg);
  if (rb != NULL) {
    memcpy(&data->rbs[data->rbCount-1],
	   rb,
	   sizeof(RootNode));    
    FREE(rb);
  } else {
    GROW(data->fid,
	 data->fiCount,
	 data->fiCount-1);
    GROW(data->rbs,
	 data->rbCount,
	 data->rbCount-1);
  }
  FREE(fn);
}

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
			     void * modelArg,
			     InsertWrapper insert,
			     void * insertArg) {
  int ret;
  int processRecursive;

  if (NO == isDirectory(filename)) {
    if (SYSERR == insert(sock,
			 filename,
			 fid,
			 insertArg)) 
      return NULL;
    return buildFileRBlock(sock,
			   fid,
			   filename,
			   gloKeywords,
			   gloKeywordCnt,
			   extractors_);
  }

  processRecursive = testConfigurationString("GNUNET-INSERT",
					     "RECURSIVE",
					     "YES");
  if (processRecursive) {      
    DECData dec;
    int builddir;

    builddir = testConfigurationString("GNUNET-INSERT",
				       "BUILDDIR",
				       "YES");

    dec.fiCount = 0;
    dec.fid = NULL;
    dec.rbCount = 0;
    dec.rbs = NULL;
    dec.sock = sock;
    dec.gloKeywords = gloKeywords;
    dec.gloKeywordCnt = gloKeywordCnt;
    dec.extractors_ = extractors_;
    dec.model = model;
    dec.model_arg = modelArg;
    dec.insert = insert;
    dec.insert_arg = insertArg;
    ret = scanDirectory(filename,
			(DirectoryEntryCallback)&dirEntryCallback,
			&dec);
    if (ret == -1)
      return NULL;
    if (dec.rbCount != dec.fiCount) {
      BREAK();
      GROW(dec.fid, dec.fiCount, 0);
      GROW(dec.rbs, dec.rbCount, 0);
      return NULL;
    }       
    if (builddir) {
      const char * dirName;

      dirName = &filename[strlen(filename)-1];
      while (dirName[-1] != DIR_SEPARATOR)
	dirName--;
      ret = insertDirectory(sock,
			    dec.rbCount,
			    dec.rbs,
			    dirName, 
			    fid,
			    model,
			    modelArg);
      GROW(dec.fid, dec.fiCount, 0);
      GROW(dec.rbs, dec.rbCount, 0);
      return buildDirectoryRBlock(sock,
				  fid,
				  dirName,
				  dirName,
				  gloKeywords,
				  gloKeywordCnt);
    }
    GROW(dec.fid, dec.fiCount, 0);
    GROW(dec.rbs, dec.rbCount, 0);
    return NULL;
  }
  return NULL;
}




/* end of insertutil.c */
