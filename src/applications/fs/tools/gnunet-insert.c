/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"

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
static unsigned int topKeywordCnt = 0;

static char ** gloKeywords = NULL;
static unsigned int gloKeywordCnt = 0;




/**
 * We're done with the upload of the file, do the
 * post-processing.
 */
static void postProcess(const struct ECRS_URI * uri) {
  char * pname;
  HashCode512 prevId;
  HashCode512 thisId;
  HashCode512 nextId;
  char * pid;
  char * tid;
  char * nid;
  struct ECRS_URI * nsuri;
  TIME_T updateInterval;
  char * us;

  pname = getConfigurationString("GNUNET-INSERT",
				 "PSEUDONYM");
  if (pname == NULL)
    return;
  pid = getConfigurationString("GNUNET-INSERT",
			       "PREVHASH");
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

  nsuri = FSUI_addToNamespace(ctx,
			      getConfigurationInt("FS",
						  "ANONYMITY-SEND"),
			      pname,
			      updateInterval,
			      pid == NULL ? NULL : &prevId,
			      tid == NULL ? NULL : &thisId,
			      nid == NULL ? NULL : &nextId,
			      uri,
			      meta);
  FREENONNULL(pid);
  FREENONNULL(tid);
  FREENONNULL(nid);
  if (nsuri != NULL) {
    us = ECRS_uriToString(nsuri);
    ECRS_freeUri(nsuri);
    printf(_("Created entry `%s' in namespace `%s'\n"),
	   us,
	   pname);
    FREE(us);
  } else {
    printf(_("Failed to add entry to namespace `%s' (does it exist?)\n"),
	   pname);
  }
  FREE(pname);
}

/**
 * Print progess message.
 */
static void printstatus(int * verboselevel,
			const FSUI_Event * event) {
  unsigned long long delta;
  char * fstring;

  switch(event->type) {
  case FSUI_upload_progress:
    if (*verboselevel == YES) {
      char * ret;

      delta = event->data.UploadProgress.main_eta - cronTime(NULL);
      ret = timeIntervalToFancyString(delta);
      PRINTF(_("%16llu of %16llu bytes inserted "
	       "(estimating %s to completion)\n"),
	     event->data.UploadProgress.main_completed,
	     event->data.UploadProgress.main_total,
	     ret);
      FREE(ret);
    }
    break;
  case FSUI_upload_complete:
    if (*verboselevel == YES) {
      if (0 == strcmp(event->data.UploadComplete.filename,
		      event->data.UploadComplete.main_filename)) {
	delta = event->data.UploadComplete.eta
	  - event->data.UploadComplete.start_time;
	PRINTF(_("Upload of `%s' complete, "
		 "%llu bytes took %llu seconds (%8.3f kbps).\n"),
	       event->data.UploadComplete.filename,
	       event->data.UploadComplete.total,
	       delta / cronSECONDS,
	       (delta == 0)
	       ? (double) (-1.0)
	       : (double) (event->data.UploadComplete.total
			   / 1024.0 * cronSECONDS / delta));
      } else {
	cron_t now;

	cronTime(&now);
	delta = now - event->data.UploadComplete.start_time;
	PRINTF(_("Upload of `%s' complete, "
		 "current average speed is %8.3f kbps.\n"),
	       event->data.UploadComplete.filename,
	       (delta == 0)
	       ? (double) (-1.0)
	       : (double) (event->data.UploadComplete.completed
			   / 1024.0 * cronSECONDS / delta));	
      }
    }
    fstring = ECRS_uriToString(event->data.UploadComplete.uri);	
    printf(_("File `%s' has URI: %s\n"),
	   event->data.UploadComplete.filename,
	   fstring);
    FREE(fstring);
    if (0 == strcmp(event->data.UploadComplete.main_filename,
		    event->data.UploadComplete.filename)) {
      postProcess(event->data.UploadComplete.uri);
      if (exitSignal != NULL)
	SEMAPHORE_UP(exitSignal);
    }

    break;
  case FSUI_upload_error:
    printf(_("\nError uploading file: %s\n"),
	   event->data.message);
    errorCode = 1;
    if (exitSignal != NULL)
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
    { 'a', "anonymity", "LEVEL",
      gettext_noop("set the desired LEVEL of sender-anonymity") },
    HELP_CONFIG,
    { 'C', "copy", NULL,
      gettext_noop("even if gnunetd is running on the local machine, force the"
		   " creation of a copy instead of making a link to the GNUnet share directory") },
    { 'D', "direct", NULL,
      gettext_noop("use libextractor to add additional direct references to directory entries") },
    { 'e', "extract", NULL,
      gettext_noop("print list of extracted keywords that would be used, but do not perform upload") },
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
    HELP_LOGLEVEL,
    { 'm', "meta", "TYPE:VALUE",
      gettext_noop("set the meta-data for the given TYPE to the given VALUE") },
    { 'n', "noindex", NULL,
      gettext_noop("do not index, perform full insertion (stores entire "
		   "file in encrypted form in GNUnet database)") },
    { 'N', "next", "ID",
      gettext_noop("specify ID of an updated version to be published in the future"
		   " (for namespace insertions only)") },
    { 'p', "priority", "PRIORITY",
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
    { 'u', "update", "ID",
      gettext_noop("ID of the previous version of the content"
		   " (for namespace update only)") },
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-insert [OPTIONS] FILENAME*",
	     _("Make files available to GNUnet for sharing."),
	     help);
}

static int printAndReturn = NO;

static int parseOptions(int argc,
			char ** argv) {
  int c;
  char * tmp;

  FREENONNULL(setConfigurationString("GNUNET-INSERT",
	  		 	     "INDEX-CONTENT",
			             "YES"));
  setConfigurationInt("FS",
		      "ANONYMITY-SEND",
		      1);
  while (1) {
    int option_index=0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "anonymity",     1, 0, 'a' },
      { "copy",          0, 0, 'C' },
      { "direct",        0, 0, 'D' },
      { "extract",       0, 0, 'e' },
      { "interval",      1, 0, 'i' },
      { "key",           1, 0, 'k' },
      { "global-key",    1, 0, 'K' },
      { "meta",          1, 0, 'm' },
      { "noindex",       0, 0, 'n' },
      { "next",          1, 0, 'N' },
      { "priority",      1, 0, 'p' },
      { "pseudonym",     1, 0, 'P' },
      { "recursive",     0, 0, 'R' },
      { "sporadic",      0, 0, 'S' },
      { "this",          1, 0, 't' },
      { "time",          1, 0, 'T' },
      { "update",        1, 0, 'u' },
      { "verbose",       0, 0, 'V' },
      { 0,0,0,0 }
    };
    c = GNgetopt_long(argc,
		      argv,
		      "a:c:CDehH:i:L:k:K:m:nN:p:P:RSt:T:u:vV",
		      long_options,
		      &option_index);
    if (c == -1)
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'a': {
      unsigned int receivePolicy;

      if (1 != sscanf(GNoptarg,
		      "%ud",
		      &receivePolicy)) {
        LOG(LOG_FAILURE,
	  _("You must pass a number to the `%s' option.\n"),
	    "-a");
        return -1;
      }
      setConfigurationInt("FS",
                          "ANONYMITY-SEND",
                          receivePolicy);
      break;
    }
    case 'C':
      FREENONNULL(setConfigurationString("FS",
					 "DISABLE-SYMLINKING",
					 "YES"));
      break;
    case 'D':
      FREENONNULL(setConfigurationString("FS",
					 "DIRECT-KEYWORDS",
					 "YES"));
      break;
    case 'e':
      printAndReturn = YES;
      break;
    case 'h':
      printhelp();
      return SYSERR;
    case 'i': {
      unsigned int interval;
      if (1 != sscanf(GNoptarg, "%ud", &interval)) {
        LOG(LOG_FAILURE,
	    _("You must pass a positive number to the `%s' option.\n"),
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
#if ENABLE_NLS
			nl_langinfo(CODESET)
#else
			"utf-8"
#endif
			);
      break;
    case 'K':
      GROW(gloKeywords,
	   gloKeywordCnt,
	   gloKeywordCnt+1);
      gloKeywords[gloKeywordCnt-1]
	= convertToUtf8(GNoptarg,
			strlen(GNoptarg),
#if ENABLE_NLS
			nl_langinfo(CODESET)
#else
			"utf-8"
#endif
        );
      break;
    case 'm': {
      EXTRACTOR_KeywordType type;
      const char * typename;
      const char * typename_i18n;

      tmp = convertToUtf8(GNoptarg,
			  strlen(GNoptarg),
#if ENABLE_NLS
			nl_langinfo(CODESET)
#else
			"utf-8"
#endif
      );
      type = EXTRACTOR_getHighestKeywordTypeNumber();
      while (type > 0) {
	type--;
	typename = EXTRACTOR_getKeywordTypeAsString(type);
	typename_i18n = dgettext("libextractor", typename);
	if  ( (strlen(tmp) >= strlen(typename)+1) &&
	      (tmp[strlen(typename)] == ':') &&
	      (0 == strncmp(typename,
			    tmp,
			    strlen(typename))) ) {
	  ECRS_addToMetaData(meta,
			     type,
			     &tmp[strlen(typename)+1]);
	  FREE(tmp);
	  tmp = NULL;
	  break;
	}
	if ( (strlen(tmp) >= strlen(typename_i18n)+1) &&
	     (tmp[strlen(typename_i18n)] == ':') &&
	     (0 == strncmp(typename_i18n,
			   tmp,
			   strlen(typename_i18n))) ) {
	  ECRS_addToMetaData(meta,
			     type,
			     &tmp[strlen(typename_i18n)+1]);
	  FREE(tmp);
	  tmp = NULL;
	  break;
	}
      }
      if (tmp != NULL) {
	ECRS_addToMetaData(meta,
			   EXTRACTOR_UNKNOWN,
			   tmp);
	FREE(tmp);
	printf(_("Unknown metadata type in metadata option `%s'.  Using metadata type `unknown' instead.\n"),
	       GNoptarg);
      }
      break;
    }
    case 'n':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "INDEX-CONTENT",
					 "NO"));
      break;
    case 'N': {
      EncName enc;
      HashCode512 nextId;

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
    case 'p': {
      unsigned int contentPriority;

      if (1 != sscanf(GNoptarg,
		      "%ud",
		      &contentPriority)) {
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-p");
	return SYSERR;
      }
      setConfigurationInt("FS",
			  "INSERT-PRIORITY",
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
      HashCode512 thisId;

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
    case 'u': {
      EncName enc;
      HashCode512 nextId;

      if (enc2hash(GNoptarg,
		   &nextId) == SYSERR)
	hash(GNoptarg,
	     strlen(GNoptarg),
	     &nextId);
      hash2enc(&nextId, &enc);
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "PREVHASH",
					 (char*)&enc));
      break;
    }
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
  int doIndex;
  int ret;
  Semaphore * es;

  meta = ECRS_createMetaData();
  if (SYSERR == initUtil(argc, argv, &parseOptions)) {
    ECRS_freeMetaData(meta);
    return 0;
  }

  if (printAndReturn) {
    EXTRACTOR_ExtractorList * l;
    char * ex;
    EXTRACTOR_KeywordList * list;
	    
    filename = getConfigurationString("GNUNET-INSERT",
				      "MAIN-FILE");
    l = EXTRACTOR_loadDefaultLibraries();
    ex = getConfigurationString("FS",
				"EXTRACTORS");
    if (ex != NULL) {
      l = EXTRACTOR_loadConfigLibraries(l,
					ex);
      FREE(ex);
    }
    list
      = EXTRACTOR_getKeywords(l, filename);
    printf(_("Keywords for file `%s':\n"),
	   filename);
    EXTRACTOR_printKeywords(stdout,
			    list);
    EXTRACTOR_freeKeywords(list);
    EXTRACTOR_removeAll(l);
    FREE(filename);
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
      printf(_("Could not access namespace `%s' (does not exist?).\n"),
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
#if ENABLE_NLS
			    nl_langinfo(D_T_FMT),
#else
			    "%Y-%m-%d",
#endif
			    &t))) {
	LOG_STRERROR(LOG_FATAL, "strptime");
        errexit(_("Parsing time failed. Use `%s' format.\n"),
#if ENABLE_NLS
		nl_langinfo(D_T_FMT)
#else
		"%Y-%m-%d"
#endif
		);
      }
      FREE(timestr);
    }
  } else { /* ordinary insertion checks */
    if (NULL != getConfigurationString("GNUNET-INSERT",
				       "NEXTHASH"))
      errexit(_("Option `%s' makes no sense without option `%s'.\n"),
	      "-N", "-P");
    if (NULL != getConfigurationString("GNUNET-INSERT",
				       "PREVHASH"))
      errexit(_("Option `%s' makes no sense without option `%s'.\n"),
	      "-u", "-P");
    if (NULL != getConfigurationString("GNUNET-INSERT",
				       "THISHASH"))
      errexit(_("Option `%s' makes no sense without option `%s'.\n"),
	      "-t", "-P");
    if (0 != getConfigurationInt("GNUNET-INSERT",
				 "INTERVAL"))
      errexit(_("Option `%s' makes no sense without option `%s'.\n"),
	      "-i", "-P");
    if (testConfigurationString("GNUNET-INSERT",
				"SPORADIC",
				"YES"))
      errexit(_("Option `%s' makes no sense without option `%s'.\n"),
	      "-S", "-P");
  }

  exitSignal = SEMAPHORE_NEW(0);
  /* fundamental init */
  ctx = FSUI_start("gnunet-insert",
		   NO,
		   (FSUI_EventCallback) &printstatus,
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
  if (! testConfigurationString("FS",
				"DISABLE-CREATION-TIME",
				"YES"))
    ECRS_addPublicationDateToMetaData(meta);
  if (testConfigurationString("GNUNET-INSERT",
			      "RECURSIVE",
			      "YES")) {
    struct ECRS_URI * topURI;
    struct ECRS_URI * gloURI;

    gloURI = FSUI_parseListKeywordURI(gloKeywordCnt,
				      (const char**) gloKeywords);
    topURI = FSUI_parseListKeywordURI(topKeywordCnt,
				      (const char**) topKeywords);
    ret = FSUI_uploadAll(ctx,
			 filename,
			 getConfigurationInt("FS",
					     "ANONYMITY-SEND"),
			 doIndex,
			 !testConfigurationString("FS",
						 "DIRECT-KEYWORDS",
						 "NO"),
			 meta,
			 gloURI,
			 topURI);
    ECRS_freeUri(gloURI);
    ECRS_freeUri(topURI);
  } else {
    struct ECRS_URI * topURI;

    topURI = FSUI_parseListKeywordURI(topKeywordCnt,
				      (const char**) topKeywords);
    ret = FSUI_upload(ctx,
		      filename,
		      getConfigurationInt("FS",
					  "ANONYMITY-SEND"),
		      doIndex,
		      !testConfigurationString("FS",
					      "TOP-KEYWORDS",
					      "NO"),
		      meta,
		      topURI);
    ECRS_freeUri(topURI);
  }
  /* wait for completion */
  SEMAPHORE_DOWN(exitSignal);
  es = exitSignal;
  exitSignal = NULL;
  SEMAPHORE_FREE(es);

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
