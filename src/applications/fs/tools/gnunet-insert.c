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
 * @file applications/fs/tools/gnunet-insert.c 
 * @brief Tool to insert or index files into GNUnet's FS.
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 *
 *
 * Todo:
 * - implement namespace insertion
 * - check that the various options still work
 * - allow any kind of meta-data attribute (currently only
 *   description, filename and mime-type can be specified)
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"

#include <langinfo.h>


/* hmm. Man says time.h, but that doesn't yield the
   prototype.  Strange... */
extern char *strptime(const char *s,
		      const char *format, 
		      struct tm *tm);

static Semaphore * exitSignal;

static int errorCode = 0;

/**
 * Meta-data for the main file.
 */
static struct ECRS_MetaData * meta;

static struct FSUI_Context * ctx;


static char ** topKeywords = NULL;
int topKeywordCnt = 0;
static char ** gloKeywords = NULL;
int gloKeywordCnt = 0;




/**
 * We're done with the upload of the file, do the
 * post-processing.
 */
static void postProcess(const struct ECRS_URI * uri) {
  char * pname;
  HashCode160 prevId;
  HashCode160 thisId;
  HashCode160 nextId;
  char * pid;
  char * tid;
  char * nid;
  struct ECRS_URI * nsuri;
  unsigned int updateInterval;

  pname = getConfigurationString("GNUNET-INSERT",
				 "PSEUDONYM");
  if (pname == NULL)
    return;
  pid = NULL; /* FIXME */
  if (pid != NULL)
    enc2hash(pid, &prevId);
  tid = getConfigurationString("GNUNET-INSERT",
			       "THISHASH");
  if (tid != NULL)
    enc2hash(tid, &thisId);
  nid = getConfigurationString("GNUNET-INSERT",
			       "NEXTHASH");
  if (nid != NULL)
    enc2hash(nid, &nextId);   
  updateInterval = getConfigurationInt("GNUNET-INSERT",
				       "INTERVAL");

  FSUI_addToNamespace(ctx,
		      pname,
		      updateInterval,
		      pid == NULL ? NULL : &prevId,
		      tid == NULL ? NULL : &thisId,
		      nid == NULL ? NULL : &nextId,
		      uri,
		      meta,
		      &nsuri);
  FREE(pname);
  FREENONNULL(pid);
  FREENONNULL(tid);
  FREENONNULL(nid);
  pname = ECRS_uriToString(nsuri);
  ECRS_freeUri(nsuri);
  printf(_("Created namespace entry '%s'\n"),
	 pname);
  FREE(pname);
}


/**
 * Print progess message.
 */
static void printstatus(int * verboselevel,
			const FSUI_Event * event) {
  unsigned long long delta;
  
  switch(event->type) {
  case upload_progress:
    if (*verboselevel == YES) {
      delta = event->data.UploadProgress.eta - cronTime(NULL);
      printf(_("%16llu of %16llu bytes inserted (estimating %llu seconds to completion)"),
	     event->data.UploadProgress.main_completed,
	     event->data.UploadProgress.main_total,
	     delta / cronSECONDS);      
      printf("\r");
    }
    break;
  case upload_complete:
    if (*verboselevel == YES) {
      delta = event->data.UploadProgress.eta - event->data.UploadProgress.start_time;
      printf(_("\nUpload of '%s' complete, %llu bytes took %llu seconds (%8.3f kbps).\n"),
	     event->data.UploadProgress.filename,
	     event->data.UploadProgress.main_total,
	     delta / cronSECONDS,
	     (delta == 0)
	     ? (double) (-1.0)
	     : (double) (event->data.UploadProgress.main_total / 1024.0 * cronSECONDS / delta));
    }
    if (testConfigurationString("GNUNET-INSERT",
				"PRINTURL",
				"YES")) {
      char * fstring;
      fstring = ECRS_uriToString(event->data.UploadComplete.uri);	
      printf(_("File '%s' has URI: %s\n"),
	     event->data.UploadComplete.filename,
	     fstring);
      FREE(fstring);
    }
    if (0 == strcmp(event->data.DownloadProgress.main_filename,
		    event->data.DownloadProgress.filename)) {
      postProcess(event->data.DownloadProgress.main_uri);
      SEMAPHORE_UP(exitSignal);
    }

    break;
  case upload_error:
    printf(_("\nError uploading file: %s\n"),
	   event->data.message);
    errorCode = 1;
    SEMAPHORE_UP(exitSignal); /* always exit main? */
    break;
  default:
    BREAK();
    break;
  }
}

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 */
static void printhelp() {
  static Help help[] = {
    HELP_CONFIG,
    { 'D', "desc", gettext_noop("DESCRIPTION"),
      gettext_noop("set description for all files") },
    { 'E', "extract", NULL,
      gettext_noop("print list of extracted keywords that would be used, but do not perform upload") },
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
      gettext_noop("if gnunetd is running on the local machine, create a"
		   " link instead of making a copy in the GNUnet share directory") },
    HELP_LOGLEVEL,
    { 'm', "mime", "MIMETYPE",
      gettext_noop("set the mimetype for the file to be MIMETYPE") },
    { 'n', "noindex", NULL,
      gettext_noop("do not index, perform full insertion (stores entire "
		   "file in encrypted form in GNUnet database)") },
    { 'N', "next", "ID",
      gettext_noop("specify ID of an updated version to be published in the future"
		   " (for namespace insertions only)") },
    { 'o', "out", "FILENAME",
      gettext_noop("write the created SBlock in plaintext to FILENAME" 
		   " (for namespace insertions only)") },
    { 'p', "prio", "PRIORITY",
      gettext_noop("specify the priority of the content") },
    { 'P', "pseudonym", "NAME",
      gettext_noop("publish the files under the pseudonym NAME (place file into namespace)") },
    { 'R', "recursive", NULL,
      gettext_noop("process directories recursively") },
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
    { 'U', "update", "FILENAME",
      gettext_noop("filename of the SBlock of a previous version of the content"
		   " (for namespace update only)") },
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-insert [OPTIONS] FILENAME*",
	     _("Make files available to GNUnet for sharing."),
	     help);
}

static int parseOptions(int argc,
			char ** argv) {
  int c;
  int printAndReturn = NO;
  char * tmp;

  FREENONNULL(setConfigurationString("GNUNET-INSERT",
	  		 	     "INDEX-CONTENT",
			             "YES"));
  while (1) {
    int option_index=0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "desc",          1, 0, 'D' },
      { "name",          1, 0, 'f' },
      { "extract",       0, 0, 'E' },
      { "interval",      1, 0, 'i' },
      { "key",           1, 0, 'k' },
      { "global-key",    1, 0, 'K' },
      { "link",          0, 0, 'l' },
      { "mime",          1, 0, 'm' },
      { "noindex",       0, 0, 'n' },
      { "next",          1, 0, 'N' },
      { "out",           1, 0, 'o' },
      { "prio",          1, 0, 'p' },
      { "pseudonym",     1, 0, 'P' },
      { "recursive",     0, 0, 'R' },
      { "sporadic",      0, 0, 'S' },
      { "this",          1, 0, 't' },
      { "time",          1, 0, 'T' },
      { "url",           0, 0, 'u' },
      { "update",        1, 0, 'U' },
      { "verbose",       0, 0, 'V' },
      { 0,0,0,0 }
    };    
    c = GNgetopt_long(argc,
		      argv, 
		      "c:dD:Ef:hH:i:lL:k:K:m:nN:o:p:Rs:St:T:uU:vV", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'e':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
      					 "PREVIOUS_SBLOCK",
					 GNoptarg));
      break;
    case 'D': 
      tmp = convertToUtf8(GNoptarg,
			  strlen(GNoptarg),
			  nl_langinfo(CODESET));
      ECRS_addToMetaData(meta,
			 EXTRACTOR_DESCRIPTION,
			 tmp);
      FREE(tmp);
      break;
    case 'E': 
      printAndReturn = YES;
      break;
    case 'f': 
      tmp = convertToUtf8(GNoptarg,
			  strlen(GNoptarg),
			  nl_langinfo(CODESET));
      ECRS_addToMetaData(meta,
			 EXTRACTOR_FILENAME,
			 tmp);
      FREE(tmp);
      break;
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
      topKeywords[topKeywordCnt-1]
	= convertToUtf8(GNoptarg,
			strlen(GNoptarg),
			nl_langinfo(CODESET));
      break;
    case 'K':
      GROW(gloKeywords,
	   gloKeywordCnt,
	   gloKeywordCnt+1);
      gloKeywords[gloKeywordCnt-1] 
	= convertToUtf8(GNoptarg,
			strlen(GNoptarg),
			nl_langinfo(CODESET));
      break;
    case 'l':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "LINK",
					 "YES"));
      break;
    case 'm':
      tmp = convertToUtf8(GNoptarg,
			  strlen(GNoptarg),
			  nl_langinfo(CODESET));     
      ECRS_addToMetaData(meta,
			 EXTRACTOR_MIMETYPE,
			 tmp);
      FREE(tmp);
      break;
    case 'n':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "INDEX-CONTENT",
					 "NO"));
      break;
    case 'N': {
      EncName enc;
      HashCode160 nextId;
      
      if (enc2hash(GNoptarg,
		   &nextId) == SYSERR) 
	hash(GNoptarg,
	     strlen(GNoptarg),
	     &nextId);
      hash2enc(&nextId, &enc);
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "NEXTHASH",
					 (char*)&enc));
      break;
    }
    case 'o':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
      					 "OUTPUT_SBLOCK",
					 GNoptarg));
      break;
    case 'p': {
      unsigned int contentPriority;
      
      if (1 != sscanf(GNoptarg, 
		      "%ud",
		      &contentPriority)) {
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
					 "PSEUDONYM",
					 GNoptarg));
      break;
    case 'R':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "RECURSIVE",
					 "YES"));
      break;
    case 'S':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "SPORADIC",
					 "YES"));
      break;
    case 't': {
      EncName enc;
      HashCode160 thisId;
      
      if (enc2hash(GNoptarg,
		   &thisId) == SYSERR) 
	hash(GNoptarg,
	     strlen(GNoptarg),
	     &thisId);
      hash2enc(&thisId, &enc);
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "THISHASH",
					 (char*)&enc));
      break;
    }
    case 'T':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "CREATION-TIME",
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
    EXTRACTOR_ExtractorList * l;
    char * ex;

    ex = getConfigurationString("GNUNET-INSERT",
				"EXTRACTORS");
#ifdef EXTRACTOR_DEFAULT_LIBRARIES
    if (ex == NULL)
      ex = STRDUP(EXTRACTOR_DEFAULT_LIBRARIES);
#endif
    if (ex == NULL)
      l = NULL;
    else
      l = EXTRACTOR_loadConfigLibraries(NULL,
					ex);
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
    return SYSERR;
  }
  if (argc - GNoptind > 1) {
    printf(_("Only one file or directory can be specified at a time.\n"));
    return SYSERR;
  }
  if (argc - GNoptind < 1) {
    printf(_("You must specify a file or directory to upload.\n"));
    return SYSERR;
  }
  setConfigurationString("GNUNET-INSERT",
			 "MAIN-FILE",
			 argv[GNoptind]);
  return OK;
}



/**
 * The main function to insert files into GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return 0 for ok, -1 on error
 */   
int main(int argc, char ** argv) {
  int i;
  char * pname;
  char * filename;
  char * tmp;
  int verbose;
  char * timestr;
  char * prevname;
  int doIndex;
  int ret;
  char * extractors;
  
  meta = ECRS_createMetaData();
  if (SYSERR == initUtil(argc, argv, &parseOptions)) {
    ECRS_freeMetaData(meta);
    return 0;
  }

  verbose = testConfigurationString("GNUNET-INSERT",
				    "VERBOSE",
				    "YES");


  /* check arguments */
  pname = getConfigurationString("GNUNET-INSERT",
				 "PSEUDONYM");
  if (pname != NULL) {
    if (OK != ECRS_testNamespaceExists(pname, NULL)) {
      printf(_("Could not access namespace '%s' (does not exist?).\n"),
	     pname);
      FREE(pname);
      doneUtil();
      ECRS_freeMetaData(meta);
      return -1;
    }
    timestr = getConfigurationString("GNUNET-INSERT",
                    		     "INSERTTIME");
    if (timestr != NULL) {
      struct tm t;
      if ((NULL == strptime(timestr, 
			    nl_langinfo(D_T_FMT),
			    &t))) {
	LOG_STRERROR(LOG_FATAL, "strptime");
        errexit(_("Parsing time failed. Use '%s' format.\n"),
		nl_langinfo(D_T_FMT));
      }
      FREE(timestr);
    }    
    prevname = getConfigurationString("GNUNET-INSERT",
    				      "PREVIOUS_SBLOCK");
    if (prevname != NULL) {
      /* FIXME: read SBlock & get options from the previous sblock */
#if 0
      if (SYSERR == verifySBlock(&pb)) 
        errexit(_("Verification of SBlock in file '%s' failed\n"), 
		prevname);     
      /* check that it matches the selected pseudonym */
      if (OK != ECRS_testNamespaceExists(pname, 
					 &pb.subspace)) 
	errexit(_("The given SBlock does not belong to the namespace of the selected pseudonym."));      
      FREE(prevname);
      interval = ntohl(pb.updateInterval);
      if (interval == SBLOCK_UPDATE_NONE) 
	errexit(_("Trying to update nonupdatable SBlock.\n")); 
#endif
    }
  } else { /* ordinary insertion checks */
    if (NULL != getConfigurationString("GNUNET-INSERT",
				       "NEXTHASH"))
      errexit(_("Option '%s' makes no sense without option '%s'.\n"),
	      "-N", "-s");
    if (NULL != getConfigurationString("GNUNET-INSERT",
				       "THISHASH"))
      errexit(_("Option '%s' makes no sense without option '%s'.\n"),
	      "-t", "-s");
    if (0 != getConfigurationInt("GNUNET-INSERT",
				 "INTERVAL"))
      errexit(_("Option '%s' makes no sense without option '%s'.\n"),
	      "-i", "-s");
    if (testConfigurationString("GNUNET-INSERT",
				"SPORADIC",
				"YES"))
      errexit(_("Option '%s' makes no sense without option '%s'.\n"),
	      "-S", "-s");
  }

  exitSignal = SEMAPHORE_NEW(0);
  /* fundamental init */
  ctx = FSUI_start((FSUI_EventCallback) &printstatus,
		   &verbose);
  
  /* first insert all of the top-level files or directories */
  tmp = getConfigurationString("GNUNET-INSERT",
			       "MAIN-FILE");
  filename = expandFileName(tmp);  
  FREE(tmp);
  if (testConfigurationString("GNUNET-INSERT",
			      "INDEX-CONTENT",
			      "NO"))
    doIndex = NO;
  else
    doIndex = YES;
  extractors = getConfigurationString("GNUNET-INSERT",
				      "EXTRACTORS");
#ifdef EXTRACTOR_DEFAULT_LIBRARIES
  if (extractors == NULL)
      extractors = STRDUP(EXTRACTOR_DEFAULT_LIBRARIES);
#endif

  if (testConfigurationString("GNUNET-INSERT",
			      "RECURSIVE",
			      "YES")) {
    ret = FSUI_uploadAll(ctx,
			 filename,
			 doIndex,
			 meta,
			 extractors,
			 gloKeywordCnt,
			 (const char**) gloKeywords,
			 topKeywordCnt,
			 (const char**) topKeywords);
  } else {
    ret = FSUI_upload(ctx,
		      filename,
		      doIndex,
		      meta,
		      topKeywordCnt,
		      (const char**) topKeywords);
  }
  FREE(filename);

  /* wait for completion */
  SEMAPHORE_DOWN(exitSignal);
  SEMAPHORE_FREE(exitSignal);
  
  /* shutdown */
  FREE(filename);
  for (i=0;i<topKeywordCnt;i++) 
    FREE(topKeywords[i]);
  GROW(topKeywords, topKeywordCnt, 0);
  for (i=0;i<gloKeywordCnt;i++) 
    FREE(gloKeywords[i]);
  GROW(gloKeywords, gloKeywordCnt, 0);
  ECRS_freeMetaData(meta);
  FSUI_stop(ctx);
  doneUtil();
  return errorCode;
}  

/* end of gnunet-insert.c */
