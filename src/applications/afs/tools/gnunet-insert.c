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
 * @file applications/afs/tools/gnunet-insert.c 
 * @brief Tool to insert or index files into GNUnet's AFS.
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"
#if USE_LIBEXTRACTOR
#include <extractor.h>
#endif

/* hmm. Man says time.h, but that doesn't yield the
   prototype.  Strange... */
extern char *strptime(const char *s, const char *format, struct tm *tm);

/**
 * Print progess message.
 */
static void printstatus(ProgressStats * stats,
			void * verboselevel) {
  if (*(int*)verboselevel == YES) {
    printf(_("%8u of %8u bytes inserted"),
	   (unsigned int) stats->progress,
	   (unsigned int) stats->filesize);  
    printf("\r");
  }
}

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 */
static void printhelp() {
  static Help help[] = {
    { 'b', "builddir", NULL,
      gettext_noop("build a directory listing all processed files") },
    HELP_CONFIG,
    { 'D', "desc", gettext_noop("DESCRIPTION"),
      gettext_noop("set description for all files") },
    { 'e', "sprev", "FILENAME",
      gettext_noop("filename of the SBlock of a previous version of the content"
		   " (for namespace insertions only)") },
    { 'E', "extract", NULL,
      gettext_noop("print list of extracted keywords that would be used, but do not perform insertion or indexing") },
    { 'f', "name", "NAME",
      gettext_noop("publish NAME as the name of the file or directory") },
    HELP_HELP,
    HELP_HOSTNAME,
    { 'i', "interval", "SECONDS",
      gettext_noop("set interval for availability of updates to SECONDS"
		   " (for namespace insertions only)") },
    { 'k', "key", "KEYWORD",
      gettext_noop("add an additional keyword for the top-level file or directory"
		   " (this option can be specified multiple times)") },
    { 'K', "global-key", "KEYWORD",
      gettext_noop("add an additional keyword for all files and directories"
		   " (this option can be specified multiple times)") },   
    { 'l', "link", NULL,
      gettext_noop("if gnunetd is running on the local machine, create a link instead of making a copy in the GNUnet share directory") },
    HELP_LOGLEVEL,
    { 'm', "mime", "MIMETYPE",
      gettext_noop("set the mimetype for the file to be MIMETYPE") },
    { 'n', "noindex", NULL,
      gettext_noop("do not index, perform full insertion (stores entire "
		   "file in encrypted form in GNUnet database)") },
    { 'N', "next", "ID",
      gettext_noop("specify ID of an updated version to be published in the future"
		   " (for namespace insertions only)") },
    { 'o', "sout", "FILENAME",
      gettext_noop("write the created SBlock in plaintext to FILENAME" 
		   " (for namespace insertions only)") },
    { 'p', "prio", "PRIORITY",
      gettext_noop("specify the priority of the content") },
    { 'P', "pass", "PASSWORD",
      gettext_noop("use PASSWORD to decrypt the secret key of the pseudonym" 
		   " (for namespace insertions only)") },
    { 'R', "recursive", NULL,
      gettext_noop("process directories recursively") },
    { 's', "pseudonym", "NAME",
      gettext_noop("publish the files under the pseudonym NAME (place file into namespace)") },
    { 'S', "sporadic", NULL,
      gettext_noop("specifies this as an aperiodic but updated publication"
		   " (for namespace insertions only)") },
    { 't', "this", "ID",
      gettext_noop("set the ID of this version of the publication"
		   " (for namespace insertions only)") },
    { 'T', "time", "TIME",
      gettext_noop("specify creation time for SBlock (see man-page for format)") },
    { 'u', "url", NULL,
      gettext_noop("print the GNUnet URL of the inserted file(s)") },
    HELP_VERSION,
    HELP_VERBOSE,
    { 'x', "noextraction", NULL,
      gettext_noop("disable automatic metadata extraction") },
    { 'X', "nodirectindex", NULL,
      gettext_noop("disable generation of RBlocks for keywords extracted from each file") },
    HELP_END,
  };
  formatHelp("gnunet-insert [OPTIONS] FILENAME*",
	     _("Make files available to GNUnet for sharing."),
	     help);
}

/**
 * Insert a single file.
 *
 * @param filename the name of the file to insert
 * @param fid resulting file identifier for the node
 * @returns OK on success, SYSERR on error
 */
static int doFile(GNUNET_TCP_SOCKET * sock,
		  char * filename,
		  FileIdentifier * fid,
		  int * verbose) {
  Block * top;
  cron_t startTime;

  cronTime(&startTime);
  if (YES == *verbose)
    printf(_("Working on file '%s'.\n"),
	   filename); 
  top = insertFile(sock,
		   filename, 
		   &printstatus,
		   verbose);
  if (top == NULL) {
    printf(_("Error inserting file '%s'.\n"
	     "You may want to check whether or not you are out of space.\n"
	     "Run gnunet-stats | grep \"AFS storage left\" to check.\n"),
	   filename);
    return SYSERR;
  } else {
    memcpy(&fid->chk, 
	   &top->chk, 
	   sizeof(CHK_Hashes));
    fid->crc = htonl(crc32N(top->data, top->len));
    fid->file_length = htonl(top->filesize);
    if (testConfigurationString("GNUNET-INSERT",
				"PRINTURL",
				"YES")) {
      char * fstring;
      fstring = createFileURI(fid);	
      printf("%s\n",
	     fstring);
      FREE(fstring);
    }
    if (*verbose == YES) {
      char * fstring;

      fstring = createFileURI(fid);	    
      printf(_("File '%s' successfully indexed -- %s\n"),
	     filename,
	     fstring);
      printf(_("Speed was %8.3f kilobyte per second.\n"),
	     (top->filesize/1024.0) / 
	     (((double)(cronTime(NULL)-startTime)) / (double)cronSECONDS) );
      FREE(fstring);
    }
    top->vtbl->done(top, NULL);
    return OK;
  }
}

static char ** topKeywords = NULL;
int topKeywordCnt = 0;
static char ** gloKeywords = NULL;
int gloKeywordCnt = 0;

static int parseOptions(int argc,
			char ** argv) {
  int c;
  int printAndReturn = NO;

  FREENONNULL(setConfigurationString("GNUNET-INSERT",
	  		 	     "INDEX-CONTENT",
			             "YES"));
  while (1) {
    int option_index=0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "builddir",      0, 0, 'b' },
      { "sprev",         1, 0, 'e' },
      { "desc",          1, 0, 'D' },
      { "sporadic",      0, 0, 'S' },
      { "name",          1, 0, 'f' },
      { "interval",      1, 0, 'i' },
      { "extract",       0, 0, 'E' },
      { "link",          0, 0, 'l' },
      { "global-key",    1, 0, 'K' },
      { "key",           1, 0, 'k' },
      { "mime",          1, 0, 'm' },
      { "noindex",       0, 0, 'n' },
      { "next",          1, 0, 'N' },
      { "sout",          1, 0, 'o' },
      { "prio",          1, 0, 'p' },
      { "pass",          1, 0, 'P' },
      { "recursive",     0, 0, 'R' },
      { "pseudonym",     1, 0, 's' },
      { "this",          1, 0, 't' },
      { "time",          1, 0, 'T' },
      { "url",           0, 0, 'u' },
      { "verbose",       0, 0, 'V' },
      { "noextraction",  1, 0, 'x' },
      { "nodirectindex", 1, 0, 'X' },     
      { 0,0,0,0 }
    };    
    c = GNgetopt_long(argc,
		      argv, 
		      "bc:dD:e:Ef:hH:i:lL:k:K:m:nN:o:p:P:Rs:St:T:uvVxX", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'b':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "BUILDDIR",
					 "YES"));
      break;
    case 'e':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
      					 "PREVIOUS_SBLOCK",
					 GNoptarg));
      break;
    case 'D':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "DESCRIPTION",
					 GNoptarg));
      break;
    case 'E': 
      printAndReturn = YES;
      break;
    case 'f': {
      char * root;
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "FILENAME",
					 GNoptarg));
      root = getConfigurationString("GNUNET-INSERT",
				    "FILENAMEROOT");
      if (root == NULL) {
	/* if filename is '/home/user/foo', use 'foo' as the filenameRoot */
	unsigned int i;
	root = GNoptarg;
	for (i=0;i<strlen(GNoptarg);i++)
	  if (GNoptarg[i] == DIR_SEPARATOR)
	    root = &GNoptarg[i+1];
	root = STRDUP(root);
      }
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "FILENAMEROOT",
					 root));
      FREE(root);
      break;
    }
    case 'h': 
      printhelp(); 
      return SYSERR;
    case 'i': {
      unsigned int interval;
      if (1 != sscanf(GNoptarg, "%ud", &interval)) {
        LOG(LOG_FAILURE,
	    _("You must pass a positive number to the '%s' option.\n"),
	    "-i");
	return -1;
      } else
	setConfigurationInt("GNUNET-INSERT",
			    "INTERVAL",
			    interval);
      break;    
    }      
    case 'k':
      GROW(topKeywords,
	   topKeywordCnt,
	   topKeywordCnt+1);
      topKeywords[topKeywordCnt-1] = STRDUP(GNoptarg);
      break;
    case 'K':
      GROW(gloKeywords,
	   gloKeywordCnt,
	   gloKeywordCnt+1);
      gloKeywords[gloKeywordCnt-1] = STRDUP(GNoptarg);
      break;
    case 'l':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "LINK",
					 "YES"));
      break;
    case 'm':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "MIMETYPE",
					 GNoptarg));
      break;
    case 'N': {
      HexName hex;
      HashCode160 nextId;
      
      if (tryhex2hash(GNoptarg,
		      &nextId) == SYSERR) 
	hash(GNoptarg,
	     strlen(GNoptarg),
	     &nextId);
      hash2hex(&nextId, &hex);
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "NEXTHASH",
					 (char*)&hex));
      break;
    }
    case 'o':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
      					 "OUTPUT_SBLOCK",
					 GNoptarg));
      break;
    case 'p': {
      unsigned int contentPriority;
      
      if (1 != sscanf(GNoptarg, "%ud", &contentPriority)) {
	LOG(LOG_FAILURE,
	    _("You must pass a number to the '%s' option.\n"),
	    "-p");
	return SYSERR;
      }
      setConfigurationInt("GNUNET-INSERT",
			  "CONTENT-PRIORITY",
			  contentPriority);
      break;
    }
    case 'P':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "PASSWORD",
					 GNoptarg));
      break;
    case 'R':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "RECURSIVE",
					 "YES"));
      break;
    case 's':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "PSEUDONYM",
					 GNoptarg));
      break;
    case 'S':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "SPORADIC",
					 "YES"));
      break;
    case 't': {
      HexName hex;
      HashCode160 thisId;

      if (tryhex2hash(GNoptarg,
		      &thisId) == SYSERR) 
	hash(GNoptarg,
	     strlen(GNoptarg),
	     &thisId);
      hash2hex(&thisId, &hex);
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "THISHASH",
					 (char*)&hex));
      break;
    }
    case 'T':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "INSERTTIME",
					 GNoptarg));
      break;
    case 'u':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "PRINTURL",
					 "YES"));
      break;
    case 'V':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "VERBOSE",
					 "YES"));
      break;
    case 'v': 
      printf("GNUnet v%s, gnunet-insert v%s\n",
	     VERSION, 
	     AFS_VERSION);
      return SYSERR;
    case 'n':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "INDEX-CONTENT",
					 "NO"));
      break;
    case 'x':
#if USE_LIBEXTRACTOR
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "EXTRACT-KEYWORDS",
					 "NO"));
#else
      LOG(LOG_INFO,
      	  "compiled without libextractor, '%s' automatic\n",
	  "-x");
#endif
      break;
    case 'X':
#if USE_LIBEXTRACTOR
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "ADDITIONAL-RBLOCKS",
					 "NO"));
#else
      LOG(LOG_INFO,
      	  "compiled without libextractor, '%s' automatic\n",
	  "-X");
#endif
      break;
    default: 
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  } /* while (1) */
  if (argc == GNoptind) {
    printf(_("You must specify a list of files to insert.\n"));
    return SYSERR;
  }
  if (printAndReturn) {
#if USE_LIBEXTRACTOR
    EXTRACTOR_ExtractorList * l;
    l = getExtractors();
    for (c=GNoptind;c<argc;c++) {
      EXTRACTOR_KeywordList * list 
	= EXTRACTOR_getKeywords(l, argv[c]);
      printf(_("Keywords for file '%s':\n"),
	     argv[c]);
      EXTRACTOR_printKeywords(stdout,
			      list);
      EXTRACTOR_freeKeywords(list);
    }
    EXTRACTOR_removeAll(l);
#else
    printf(_("libextractor not used, no keywords will be extracted.\n"));
#endif
    return SYSERR;
  }
  setConfigurationStringList(&argv[GNoptind],
			     argc - GNoptind);


  return OK;
}

/**
 * Insert the given RBlock into GNUnet.
 * @param rb the root node
 * @param keyword the keyword to use
 */
static void insertRBlock(GNUNET_TCP_SOCKET * sock,
			 RootNode * rb,
			 char * keyword) {
  if (OK != insertRootWithKeyword(sock,
				  rb,
				  keyword,
				  getConfigurationInt("GNUNET-INSERT",
						      "CONTENT-PRIORITY")))
    printf(_("Error inserting RBlock. "
	     "Is gnunetd running and space available?\n"));
}



/**
 * The main function to insert files into GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return 0 for ok, -1 on error
 */   
int main(int argc, char ** argv) {
  RootNode * roots;
  int i;
  int j;
  char * pname;
  PrivateKey pseudonym;
  HashCode160 hc;
  char ** fileNames;
  char * fileName;
  int fileNameCount;
  FileIdentifier fid;
  RootNode * r;
  char * description;
  char * mimetype;
  char * shortFN;
#if USE_LIBEXTRACTOR
  EXTRACTOR_ExtractorList * extractors;
#endif
  int interval = 0; /* make gcc happy */
  int skip;
  GNUNET_TCP_SOCKET * sock;
  int verbose;
  char * timestr;
  SBlock pb; 	
  char * prevname;
  
  if (SYSERR == initUtil(argc, argv, &parseOptions)) 
    return 0;

  verbose = testConfigurationString("GNUNET-INSERT",
				    "VERBOSE",
				    "YES");
 
  /* check arguments */
  pname = getConfigurationString("GNUNET-INSERT",
				 "PSEUDONYM");
  if (pname != NULL) {
    char * password 
      = getConfigurationString("GNUNET-INSERT",
			       "PASSWORD");
    pseudonym = readPseudonym(pname,
			      password);
    if (pseudonym == NULL) {
      printf(_("Could not read pseudonym '%s' (does not exist or password invalid).\n"),
	     pname);
      FREE(pname);
      FREENONNULL(password);
      doneUtil();
      return -1;
    }
    FREENONNULL(password);
    FREE(pname);
  } else {
    pseudonym = NULL;
  }
  fileNameCount = getConfigurationStringList(&fileNames);

  if (pseudonym == NULL) {
    if (NULL != getConfigurationString("GNUNET-INSERT",
				       "NEXTHASH"))
      errexit(_("Option '%s' makes no sense without option '%s'.\n"),
	      "-N", "-s");
    if (NULL != getConfigurationString("GNUNET-INSERT",
				       "THISHASH"))
      errexit(_("Option '%s' makes no sense without option '%s'.\n"),
	      "-t", "-s");
    if (NULL != getConfigurationString("GNUNET-INSERT",
				       "PASSWORD"))
      errexit(_("Option '%s' makes no sense without option '%s'.\n"),
	      "-P", "-s");
    if (0 != getConfigurationInt("GNUNET-INSERT",
				 "INTERVAL"))
      errexit(_("Option '%s' makes no sense without option '%s'.\n"),
	      "-i", "-s");
    if (testConfigurationString("GNUNET-INSERT",
				"SPORADIC",
				"YES"))
      errexit(_("Option '%s' makes no sense without option '%s'.\n"),
	      "-S", "-s");
  } else { /* have namespace (pseudonym != NULL) */
    if ( (fileNameCount > 1) && 
	 (! testConfigurationString("GNUNET-INSERT",
				    "BUILDDIR",
				    "YES")) ) 
      errexit(_("Cannot insert multiple files into namespace in one pass without using directory."));    

    timestr = getConfigurationString("GNUNET-INSERT",
                    		     "INSERTTIME");
    if (timestr != NULL) {
      struct tm t;
      if ((NULL == strptime(timestr, 
			    "%j-%m-%Y %R", 
			    &t))) {
	LOG_STRERROR(LOG_FATAL, "strptime");
        errexit(_("Parsing time failed. Use 'DD-MM-YY HH:MM' format.\n"));
      }
      FREE(timestr);
    }
    
    prevname = getConfigurationString("GNUNET-INSERT",
    				      "PREVIOUS_SBLOCK");
    if (prevname != NULL) {
      /* options from the previous sblock override */
      PublicKey pkey;
      
      if (sizeof(SBlock) != readFile(prevname,
      				     sizeof(SBlock),
				     &pb) ) {
        errexit(_("SBlock in file '%s' either does not exist or is malformed.\n"),
		prevname);
      }
      /* check that it matches the selected pseudonym */
      getPublicKey(pseudonym,
      		   &pkey);
      if (0 != memcmp(&pkey,
      	  	      &pb.subspace,
		      sizeof(PublicKey)))
        errexit(_("The given SBlock does not belong to the namespace of the selected pseudonym."));
      
      if (SYSERR == verifySBlock(&pb)) {
        errexit(_("Verification of SBlock in file '%s' failed\n"), 
		prevname);
      }
      FREE(prevname);
      interval = ntohl(pb.updateInterval);

      if (interval == SBLOCK_UPDATE_NONE) 
	errexit(_("Trying to update nonupdatable SBlock.\n")); 
    }
  }
#if USE_LIBEXTRACTOR
  if (testConfigurationString("GNUNET-INSERT",
			      "EXTRACT-KEYWORDS",
			      "NO") &&
      testConfigurationString("GNUNET-INSERT",
			      "ADDITIONAL-RBLOCKS",
			      "NO") )
    printf(_("Option '%s' is implied by option '%s'.\n"),
	   "-X", "-x");
  extractors = getExtractors();
#endif
  
  /* fixme: other sanity checks here? */


  
  /* fundamental init */
  sock = getClientSocket();
  if (sock == NULL)
    errexit(_("Could not connect to gnunetd.\n"));

  
  /* first insert all of the top-level files or directories */
  roots = MALLOC(sizeof(RootNode) * fileNameCount);
  skip = 0; /* number of failed insertions... */
  for (i=0;i<fileNameCount;i++) {
    fileName = expandFileName(fileNames[i]);
    r = insertRecursively(sock,
			  fileName,
			  &fid,
			  (const char**) gloKeywords,
			  gloKeywordCnt,
#if USE_LIBEXTRACTOR
			  extractors,
#else
			  NULL,
#endif
			  &printstatus,
			  &verbose,
			  (InsertWrapper)&doFile,
			  &verbose);    
    if (r != NULL) {
      roots[i-skip] = *r;
      FREE(r);
    } else {
      FREE(fileNames[i]);
      for (j=i;j<fileNameCount-1;j++)
	fileNames[j] = fileNames[j+1];
      skip++;
    }
    FREE(fileName);
  }
  GROW(roots,
       fileNameCount,
       fileNameCount - skip);

  /* if build directory option given and we have more than one file,
     build directory and reduce to directory containing these files */
  if ( (fileNameCount > 1 || isDirectory(fileNames[0])) &&
       testConfigurationString("GNUNET-INSERT",
			       "BUILDDIR",
			       "YES") ) {
    fileName = getConfigurationString("GNUNET-INSERT",
				      "FILENAMEROOT");
    if (fileName == NULL)
      fileName = STRDUP(_("no filename specified"));
    i = insertDirectory(sock,
			fileNameCount,
			roots,
			fileName,
			&fid,
			&printstatus,
			&verbose);
    for (j=0;j<fileNameCount;j++)
      FREE(fileNames[j]);
    if (i == SYSERR) {
      /* oops */
      GROW(fileNames,	   
	   fileNameCount,
	   0); 
      FREE(roots);
      roots = NULL;
    } else { 
      GROW(fileNames,	   
	   fileNameCount,
	   1); 
      fileNames[0] = STRDUP(fileName);
      if (testConfigurationString("GNUNET-INSERT",
				  "PRINTURL",
				  "YES")) {
	char * fstring;
	fstring = createFileURI(&fid);	
	printf("%s\n",
	       fstring);
	FREE(fstring);
      }
      if (verbose == YES) {
	char * fstring;
	fstring = createFileURI(&fid);	
	printf(_("Directory %s successfully indexed -- %s\n"),
	       fileName,
	       fstring);
	FREE(fstring);
      }    
      description = getConfigurationString("GNUNET-INSERT",
					   "DESCRIPTION");
      if (description == NULL)
        description = STRDUP("No description supplied.");
      r = buildDirectoryRBlock(sock,
			       &fid,
			       fileName,
			       description,
			       (const char**) gloKeywords,
			       gloKeywordCnt);
      FREE(description);
      GROW(roots,
	   fileNameCount, 
	   1);
      roots[0] = *r;
      FREE(r);
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "MIMETYPE",
					 GNUNET_DIRECTORY_MIME));
    }
    FREE(fileName);
  }


  /* create and insert RBlocks for all "-k", "-K" and LE keywords */
  for (i=0;i<fileNameCount;i++) {
#if USE_LIBEXTRACTOR
    char ** keywords = NULL;
    int num_keywords = 0;
#endif

    fileName = expandFileName(fileNames[i]);

    if (! testConfigurationString("GNUNET-INSERT",
				  "BUILDDIR",
				  "YES")) {
      shortFN = getConfigurationString("GNUNET-INSERT",
				       "FILENAMEROOT");
      if ( (fileNameCount > 1) &&
	   (shortFN != NULL) &&
	   (i == 0) ) {
	LOG(LOG_WARNING,
	    _("Filename (option '%s') specified but multiple files given on the command line and not building directory.  Will use the same filename for multiple files."),
	    "-f");
      }
      if ( (shortFN == NULL) && (fileName != NULL)) {
	shortFN = &fileName[strlen(fileName)-1];
	while ( (shortFN[-1] != DIR_SEPARATOR) &&
		(shortFN != fileName) )
	  shortFN--;
	shortFN = STRDUP(shortFN);
      }
    } else {
      shortFN = &fileName[strlen(fileName)-1];
      while ( (shortFN[-1] != DIR_SEPARATOR) &&
	      (shortFN != fileName) )
	shortFN--;
      shortFN = STRDUP(shortFN);      
    }

    mimetype = getConfigurationString("GNUNET-INSERT",
				      "MIMETYPE");
    description = getConfigurationString("GNUNET-INSERT",
					 "DESCRIPTION");
#if USE_LIBEXTRACTOR
    extractKeywordsMulti(fileName,
			 &description,
			 &mimetype,
			 &keywords,
			 &num_keywords,
			 extractors);
#endif   
    if (mimetype == NULL)
      mimetype = STRDUP("unknown");
    if (description == NULL)
      description = STRDUP("No description supplied.");  

    r = createRootNode(&roots[i].header.fileIdentifier,
		       description,
		       shortFN,
		       mimetype);

    /* if a directory, add mimetype as key unless forbidden */
    if ( (! testConfigurationString("GNUNET-INSERT",
				    "ADDITIONAL-RBLOCKS",
				    "NO")) &&
	 (0 != strcmp(mimetype, "unknown")) ) {
      insertRBlock(sock,
		   r,
		   mimetype);
      printf(_("Inserting file '%s' (%s, %s) under keyword '%s'.\n"),
	     shortFN, description, mimetype, mimetype);
    }

#if USE_LIBEXTRACTOR
    for (j=0;j<num_keywords;j++) {
      insertRBlock(sock,
		   r,
		   keywords[j]);    
      printf(_("Inserting file '%s' (%s, %s) under keyword '%s'.\n"),
	     shortFN, description, mimetype, keywords[j]);
    }
    for (j=0;j<num_keywords;j++) 
      FREE(keywords[j]);
    GROW(keywords, num_keywords, 0);    
#endif
    for (j=0;j<gloKeywordCnt;j++) {
      insertRBlock(sock, 
		   r, 
		   gloKeywords[j]);    
      printf(_("Inserting file '%s' (%s, %s) under keyword '%s'.\n"),
	     shortFN, description, mimetype, gloKeywords[j]);
    }
    for (j=0;j<topKeywordCnt;j++) {
      insertRBlock(sock,
		   r,
		   topKeywords[j]);    
      printf(_("Inserting file '%s' (%s, %s) under keyword '%s'.\n"),
	     shortFN, description, mimetype, topKeywords[j]);
    }
    FREE(r);
    FREE(shortFN);
    FREE(fileName);
    FREE(mimetype);
    FREE(description);
  } /* end top-level processing for all files (for i=0;i<fileNameCount;i++) */


  description = getConfigurationString("GNUNET-INSERT",
				       "DESCRIPTION");
  if (description == NULL)
    description = STRDUP("No description supplied.");  
  
  mimetype = getConfigurationString("GNUNET-INSERT",
				    "MIMETYPE");
  if (mimetype == NULL)
    mimetype = STRDUP("unknown");
  

  /* if SBlock requested and just one file left here, create SBlock */
  if (pseudonym != NULL) {
    HashCode160 thisId;
    HashCode160 nextId;
    char * hx;
    SBlock * sb;
    TIME_T creationTime;
    TIME_T now;

    GNUNET_ASSERT(fileNameCount == 1);
    shortFN = getConfigurationString("GNUNET-INSERT",
				     "FILENAME");
    fileName = expandFileName(fileNames[0]);
    if ( (shortFN == NULL) && (fileName != NULL)) {
      shortFN = &fileName[strlen(fileName)-1];
      while ( (shortFN[-1] != DIR_SEPARATOR) &&
	      (shortFN != fileName) )
	shortFN--;
      shortFN = STRDUP(shortFN);
    }  
    FREENONNULL(fileName);
    timestr = getConfigurationString("GNUNET-INSERT",
                    		     "INSERTTIME");
    if (timestr != NULL) {
      struct tm t;

      /* we can assert here: input was verified earlier! */
      GNUNET_ASSERT(NULL != strptime(timestr, "%j-%m-%Y %R", &t));
      now = mktime(&t);
      FREE(timestr);
      /* On my system, the printed time is in advance +1h 
	 to what was specified? -- It is in UTC! */
      timestr = GN_CTIME(&now);
      LOG(LOG_DEBUG, 
          "Read time '%s'.\n", 
	  timestr);
      FREE(timestr);
    } else {
      /* use current time */
      TIME(&now);
    }

    /* determine update frequency / policy */
    prevname = getConfigurationString("GNUNET-INSERT",
    				      "PREVIOUS_SBLOCK");
    if (prevname != NULL) {
      FREE(prevname);
      /* now, compute CURRENT ID and next ID from SBlock 'pb' */
      computeIdAtTime(&pb,
      	              now,
		      &thisId); 
      /* interval was read and verified earlier... */
      if (interval != SBLOCK_UPDATE_SPORADIC) {  
        int delta;
	
        /* periodic update */
        delta = now - ntohl(pb.creationTime);
        delta = delta / ntohl(pb.updateInterval);
        if (delta <= 0)
          delta = 1; /* force to be in the future from the updated block! */
        creationTime = ntohl(pb.creationTime) + delta * ntohl(pb.updateInterval);

        /* periodic update, compute _next_ ID as increment! */
        addHashCodes(&thisId,
		     &pb.identifierIncrement,
		     &nextId); /* n = k + inc */
      } else { /* interval == SBLOCK_UPDATE_SPORADIC */
        creationTime = now;
	LOG(LOG_DEBUG,
	    "Sporadic update in sblock.\n");
	hx = getConfigurationString("GNUNET-INSERT",
				    "NEXTHASH");
	if (hx == NULL) {
	  makeRandomId(&nextId);
	} else {
	  tryhex2hashOrHashString(hx, &nextId);
	  FREE(hx);
	}
      }
    } else {
      /* no previous sblock specified */
      creationTime = now;
      interval = getConfigurationInt("GNUNET-INSERT",
	  	 	  	     "INTERVAL");
      hx = getConfigurationString("GNUNET-INSERT",
 	 	 	  	  "THISHASH");
      tryhex2hashOrHashString(hx, &thisId);
      FREENONNULL(hx);
      hx = getConfigurationString("GNUNET-INSERT",
 	  	 	  	  "NEXTHASH");
      if (hx == NULL) {
        if (interval == SBLOCK_UPDATE_NONE) {
	  /* no next id and no interval specified, to be    */
	  /* consistent with gnunet-gtk, nextId == thisId   */
	  memcpy(&nextId,
	  	 &thisId,
		 sizeof(HashCode160));
	} else {
          makeRandomId(&nextId);
	}
      } else {
        tryhex2hashOrHashString(hx, &nextId);
        if (interval == SBLOCK_UPDATE_NONE) {
	  /* if next was specified, aperiodic is default */
  	  interval = SBLOCK_UPDATE_SPORADIC; 
	}
        FREE(hx); 
      }
      if (testConfigurationString("GNUNET-INSERT",
  	 	 	  	  "SPORADIC",
				  "YES"))
        interval = SBLOCK_UPDATE_SPORADIC;
    }
  
    /* finally we can create the SBlock */
    sb = buildSBlock(pseudonym,
		     &fid,
		     description,
		     shortFN,
		     mimetype,
		     creationTime,
		     interval,
		     &thisId,
		     &nextId);
    freePrivateKey(pseudonym);
    hash(&sb->subspace,
	 sizeof(PublicKey),
	 &hc);
    if (OK == insertSBlock(sock,
			   sb)) {
      char * outname;
      char * uri;
      
      outname = getConfigurationString("GNUNET-INSERT",
      				       "OUTPUT_SBLOCK");
      if (outname != NULL) {
        SBlock plainSBlock;

	decryptSBlock(&thisId,
		      sb,
                      &plainSBlock);
        writeFile(outname, 
	          &plainSBlock,
		  sizeof(SBlock),
		  "600");
	FREE(outname);
      } 
      uri = createSubspaceURI(&hc,
			      &thisId);
      printf(_("File '%s' (%s, %s) successfully inserted into namespace under\n"
	       "\t'%s'\n"),
	     shortFN,
	     description, 
	     mimetype,
	     uri);
      FREE(uri);
    } else {
      printf(_("Insertion of file into namespace failed.\n"));
    }
    FREE(sb);
    FREE(shortFN);
  }

  /* shutdown */
#if USE_LIBEXTRACTOR
  EXTRACTOR_removeAll(extractors);
#endif
  for (i=0;i<fileNameCount+skip;i++)
    FREE(fileNames[i]);
  FREE(fileNames);
  for (i=0;i<topKeywordCnt;i++) 
    FREE(topKeywords[i]);
  GROW(topKeywords, topKeywordCnt, 0);
  for (i=0;i<gloKeywordCnt;i++) 
    FREE(gloKeywords[i]);
  GROW(gloKeywords, gloKeywordCnt, 0);
  FREE(mimetype);
  FREE(description);
  FREE(roots);
  releaseClientSocket(sock); 
  doneUtil();
  return 0;
}  

/* end of gnunet-insert.c */
