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
 * @file applications/afs/tools/gnunet-search.c 
 * @brief Main function to search for files on GNUnet.
 * @author Christian Grothoff
 */

#include "gnunet_afs_esed2.h"
#include "platform.h"

typedef struct {
  unsigned int resultCount;
  unsigned int max;
} SearchClosure;

/**
 * Handle the search result.
 */
static void handleNormalResult(const RootNode * rootNode,
			       SearchClosure * sc) {
  char * fstring;
  char * fname;
  char * prefix;  

  /* write rblock to file? */
  prefix = getConfigurationString("GNUNET-SEARCH",
  				  "OUTPUT_PREFIX");
  if (prefix != NULL) {
    char * outfile;
    size_t n;

    n = strlen(prefix)+16;
    outfile = MALLOC(n);
    SNPRINTF(outfile, 
	     n,
	     "%s.%03d", 
	     prefix, 
	     sc->resultCount++);
    writeFile(outfile,
    	      rootNode,
	      sizeof(RootNode),
	      "600");
    FREE(outfile);
    FREE(prefix);
  }

  switch (ntohs(rootNode->header.major_formatVersion)) {
  case ROOT_MAJOR_VERSION:
    sc->max--;  
    fstring = createFileURI(&rootNode->header.fileIdentifier);
    if (0 == strcmp(rootNode->header.mimetype,
		    GNUNET_DIRECTORY_MIME)) {
      char * tmp;
      tmp = STRNDUP(rootNode->header.filename, MAX_FILENAME_LEN);
      fname = expandDirectoryName(tmp);
      FREE(tmp);
    } else 
      fname = STRNDUP(rootNode->header.filename, MAX_FILENAME_LEN);
    
    printf(_("%s '%s' (description: '%.*s', mimetype: '%.*s')\n"),
	   (0 == strcmp(rootNode->header.mimetype,
			GNUNET_DIRECTORY_MIME)) ? _("Directory") : _("File"),
	   fname,
	   MAX_DESC_LEN,
	   rootNode->header.description,
	   MAX_MIMETYPE_LEN,
	   rootNode->header.mimetype);
    printf("\tgnunet-download -o \"%s\" %s\n",
	   fname,
	   fstring); 
    FREE(fstring);
    FREE(fname);
    break;
  case SBLOCK_MAJOR_VERSION:
    if (OK == verifySBlock((const SBlock*) rootNode)) {
      printSBlock(stdout,
		  (const SBlock*) rootNode);
    }
    break;
  case NBLOCK_MAJOR_VERSION:
    if (OK == verifyNBlock((const NBlock*)rootNode)) {
      addNamespace((const NBlock*) rootNode);
      printNBlock(stdout,
		  (const NBlock*) rootNode);
    } else
      LOG(LOG_WARNING,
	  _("Received invalid NBlock.\n"));
    break;
  default:
    LOG(LOG_WARNING,
	_("Received reply of unknown type %d.\n"),
	ntohs(rootNode->header.major_formatVersion));
    break;
  }

  if (0 == sc->max)
    run_shutdown(0);
}

typedef struct {
  HashCode160 * results;
  unsigned int resultCount;
  unsigned int max;
} NSSearchClosure;

/**
 * Handle namespace result.
 */   
static void handleNamespaceResult(SBlock * sb,
				  NSSearchClosure * sqc) {
  HashCode160 curK;
  int i;
  char * prefix;

  hash(sb, sizeof(SBlock), &curK);
  for (i=0;i<sqc->resultCount;i++)
    if (equalsHashCode160(&curK,
        &sqc->results[i])) {
      LOG(LOG_DEBUG, 
	  "SBlock already seen\n");
      return; /* displayed already */
    }
  GROW(sqc->results,
       sqc->resultCount,
       sqc->resultCount+1);
  memcpy(&sqc->results[sqc->resultCount-1],
         &curK,
         sizeof(HashCode160));

  switch (ntohs(sb->major_formatVersion)) {
  case ROOT_MAJOR_VERSION:
    LOG(LOG_WARNING,
	_("Received RBlock in namespace search.\n"));
    break;
  case SBLOCK_MAJOR_VERSION:
    printSBlock(stdout,
		sb);
    sqc->max--;  
    break;
  case NBLOCK_MAJOR_VERSION:
    addNamespace((const NBlock*) sb);
    printNBlock(stdout,
		(const NBlock*) sb);
    sqc->max--;
    break;
  default:
    LOG(LOG_WARNING,
	_("Received reply of unknown type %d.\n"),
	ntohs(sb->major_formatVersion));
    break;
  }  
  /* write sblock to file */
  prefix = getConfigurationString("GNUNET-SEARCH",
  				  "OUTPUT_PREFIX");
  if (prefix != NULL) {
    char * outfile;
    size_t n;

    n = strlen(prefix)+16;
    outfile = MALLOC(n);
    SNPRINTF(outfile, 
	     n,
	     "%s.%03d", 
	     prefix, 
	     sqc->resultCount-1);
    writeFile(outfile,
    	      sb,
	      sizeof(SBlock),
	      "600");
    FREE(outfile);
    FREE(prefix);
  }
  if (0 == sqc->max)
     run_shutdown(0);
}

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 */
static void printhelp() {
  static Help help[] = {
    { 'a', "anonymity", "LEVEL",
      gettext_noop("set the desired LEVEL of receiver-anonymity") },
    HELP_CONFIG,
    HELP_HELP,
    HELP_HOSTNAME,
    HELP_LOGLEVEL,
    { 'm', "max", "LIMIT",
      gettext_noop("exit after receiving LIMIT results") },
    { 'n', "namespace", "HEX",
      gettext_noop("only search the namespace identified by HEX") },
    { 'o', "output", "PREFIX",
      gettext_noop("write encountered (decrypted) search results to the file PREFIX") },
    { 't', "timeout", "TIMEOUT",
      gettext_noop("wait TIMEOUT seconds for search results before aborting") },
    { 'u', "uri", NULL,
      gettext_noop("take a GNUnet URI as an argument (instead of keyword)") },
    HELP_VERSION,
    HELP_END,
  };
  formatHelp("gnunet-search [OPTIONS] KEYWORD [AND KEYWORD]",
	     _("Search GNUnet for files."),
	     help);
}

/**
 * Parse the options, set the timeout.
 * @param argc the number of options
 * @param argv the option list (including keywords)
 * @return SYSERR if we should exit, OK otherwise
 */
static int parseOptions(int argc,
			char ** argv) {
  int c;  

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "anonymity", 1, 0, 'a' }, 
      { "max",       1, 0, 'm' },
      { "namespace", 1, 0, 'n' },
      { "output",    1, 0, 'o' },
      { "timeout",   1, 0, 't' },
      { "uri",       0, 0, 'u' },
      { 0,0,0,0 }
    };    
    c = GNgetopt_long(argc,
		      argv, 
		      "a:vhdc:L:H:t:o:n:m:u", 
		      long_options, 
		      &option_index);    
    if (c == -1) 
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'a': {
      unsigned int receivePolicy;

      if (1 != sscanf(GNoptarg, "%ud", &receivePolicy)) {
        LOG(LOG_FAILURE,
	  _("You must pass a number to the '%s' option.\n"),
	    "-a");
        return -1;
      }
      setConfigurationInt("AFS",
                          "ANONYMITY-RECEIVE",
                          receivePolicy);
      break;
    }
    case 'h': 
      printhelp(); 
      return SYSERR;
    case 'm': {
      unsigned int max;
      if (1 != sscanf(GNoptarg, "%ud", &max)) {
	LOG(LOG_FAILURE, 
	    _("You must pass a number to the '%s' option.\n"),
	    "-m");
	return SYSERR;
      } else {
	setConfigurationInt("AFS",
			    "MAXRESULTS",
			    max);
	if (max == 0) 
	  return SYSERR; /* exit... */	
      }
      break;
    }
    case 'n':
      FREENONNULL(setConfigurationString("GNUNET-SEARCH",
      					 "NAMESPACE",
					 GNoptarg));
      break;
    case 'o':
      FREENONNULL(setConfigurationString("GNUNET-SEARCH",
      					 "OUTPUT_PREFIX",
					 GNoptarg));
      break;
    case 't': {
      unsigned int timeout;
      if (1 != sscanf(GNoptarg, "%ud", &timeout)) {
	LOG(LOG_FAILURE, 
	    _("You must pass a number to the '%s' option.\n"),
	    "-t");
	return SYSERR;
      } else {
	setConfigurationInt("AFS",
			    "SEARCHTIMEOUT",
			    timeout);
      }
      break;
    }
    case 'u': 
      FREENONNULL(setConfigurationString("GNUNET-SEARCH",
					 "HAVEURI",
					 "YES"));
      break;    
    case 'v': 
      printf("GNUnet v%s, gnunet-search v%s\n",
	     VERSION, 
	     AFS_VERSION);
      return SYSERR;
    default: 
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  } /* while (1) */
  if (argc - GNoptind <= 0) {
    LOG(LOG_FAILURE, 
	_("Not enough arguments. "
	  "You must specify a keyword or identifier.\n"));
    printhelp();
    return SYSERR;
  }
  setConfigurationStringList(&argv[GNoptind],
			     argc-GNoptind);
  return OK;
}

/**
 * Perform a normal (non-namespace) search.
 */
static void * normalSearchMain(GNUNET_TCP_SOCKET * sock) {
  SearchClosure max;
  int i;
  int keywordCount;
  char ** keyStrings;
  char * uri;

  uri = getConfigurationString("GNUNET-SEARCH",
			       "URI");
  keywordCount = parseKeywordURI(uri,
				 &keyStrings);
  if (keywordCount <= 0) {
    printf(_("Invalid URI specified!\n"));
    FREE(uri);
    return NULL;
  }
  FREE(uri);
  max.max = getConfigurationInt("AFS",
				"MAXRESULTS");
  max.resultCount = 0;
  if (max.max == 0)
    max.max = (unsigned int)-1; /* infty */
  searchRBlock(sock,
	       keyStrings,
	       keywordCount,
	       (SearchResultCallback)&handleNormalResult,
	       &max,
	       &testShutdown,
	       NULL);
  for (i=0;i<keywordCount;i++) 
    FREE(keyStrings[i]);  
  FREE(keyStrings);
  return NULL;
}

/**
 * Perform a namespace search.
 */
static int namespaceSearchMain(GNUNET_TCP_SOCKET * sock) {
  int ret;
  NSSearchClosure sqc;
  HashCode160 namespace;
  HashCode160 identifier;
  char * uri;

  uri = getConfigurationString("GNUNET-SEARCH", 
			       "URI"); 
  parseSubspaceURI(uri,
		   &namespace,
		   &identifier);
  FREE(uri);
  sqc.max = getConfigurationInt("AFS",
				"MAXRESULTS");
  if (sqc.max == 0)
    sqc.max = (unsigned int)-1; /* infty */
  
  sqc.results = NULL;
  sqc.resultCount = 0;
  ret = searchSBlock(sock,
		     &namespace,
		     &identifier,
		     &testShutdown, 
		     NULL,
		     (NSSearchResultCallback)&handleNamespaceResult,
		     &sqc);
  if (ret == SYSERR) 
    printf(_("Sorry, nothing was found.\n"));
 
  FREENONNULL(sqc.results);
  return ret;
}

/**
 * The main function to search for files on GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunet-search: 0: ok, -1: error
 */   
int main(int argc,
	 char ** argv) {
  GNUNET_TCP_SOCKET * sock;
  PTHREAD_T searchThread;
  void * unused;
  PThreadMain type;
  char * uri;
  HashCode160 ns;
  HashCode160 id;
  
  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;


  argc = getConfigurationStringList(&argv);

  if (testConfigurationString("GNUNET-SEARCH",
			      "HAVEURI",
			      "YES")) {
    if (argc - GNoptind != 1) {
      LOG(LOG_FAILURE,
	  _("Only one URI may be passed.\n"));
      return SYSERR;
    }
    FREENONNULL(setConfigurationString("GNUNET-SEARCH",
				       "URI",
				       argv[GNoptind]));
  } else {    
    char * uri;
    char * ns = getConfigurationString("GNUNET-SEARCH",
				       "NAMESPACE");
    if (ns != NULL) {
      HashCode160 hc;
      HashCode160 id;
   
      if (OK != enc2hash(ns,
			 &hc)) {
	NBlock * list;
	int cnt;
	int i;
	int found;

	found = NO;
	list = NULL;
	cnt = listNamespaces(&list);
	for (i=0;i<cnt;i++) {
	  char * nick = getUniqueNickname(&list[i].namespace);
	  if (0 == strcmp(nick, ns)) {
	    hc = list[i].namespace;
	    found = YES;
	  }
	  FREE(nick);
	}
	if (found == NO) {
	  LOG(LOG_FAILURE,
	      _("Invalid namespace identifier '%s' specified.\n"),
	      ns);
	  for (i=0;i<cnt;i++) {
	    char * nick = getUniqueNickname(&list[i].namespace);
	    LOG(LOG_FAILURE,
		_("Valid choices are: '%s'\n"), nick);
	    FREE(nick);
	  }
	  FREENONNULL(list);
	  return SYSERR;
	}
	FREENONNULL(list);
      }
      if (argc != 1) {
	LOG(LOG_FAILURE,
	    _("Only one identifier in the namespace may be passed.\n"));
	return SYSERR;
      }
      if (OK != enc2hash(argv[0],
			 &id)) {
	if ( (strlen(argv[0]) == sizeof(EncName)-1) &&
	     (argv[0][sizeof(EncName)-2] == '/') )
	  argv[0][sizeof(EncName)-2] = '\0';
	hash(argv[0],
	     strlen(argv[0]),
	     &id);	     
      }
      uri = createSubspaceURI(&hc,
			      &id);      
    } else {
      /* keyword search */
      if (argc < 1) {
	LOG(LOG_FAILURE,
	    _("You must specify a keyword.\n"));
	return SYSERR;
      }
      uri = createKeywordURI(&argv[0],
			     argc);
    }
    FREENONNULL(setConfigurationString("GNUNET-SEARCH",
				       "URI",
				       uri));
    FREE(uri);    
  }

  while (argc > 0)
    FREE(argv[--argc]);
  FREE(argv);




  sock = getClientSocket();
  if (sock == NULL)
    errexit(_("Could not connect to gnunetd.\n"));
  initAnonymityPolicy(NULL);
  initializeShutdownHandlers();

  /* order of cron-jobs is important, thus '- cronMILLIS' */
  addCronJob((CronJob)&run_shutdown,
	     cronSECONDS * getConfigurationInt("AFS",
					       "SEARCHTIMEOUT") - cronMILLIS,
	     0, /* no need to repeat */
	     NULL);
  startAFSPriorityTracker();
  startCron();
  
  uri = getConfigurationString("GNUNET-SEARCH", 
			       "URI");
  if (OK == parseSubspaceURI(uri,
			     &ns,
			     &id)) {
    type = (PThreadMain) &namespaceSearchMain;
  } else {
    type = (PThreadMain) &normalSearchMain;
  }
  FREE(uri);

  if (0 != PTHREAD_CREATE(&searchThread, 
			  type,
			  sock,
			  8 * 1024)) 
    DIE_STRERROR("pthread_create");
  wait_for_shutdown();
  closeSocketTemporarily(sock);
  stopCron();
  stopAFSPriorityTracker();
  delCronJob((CronJob)&run_shutdown,
	     0,
	     NULL);
  PTHREAD_JOIN(&searchThread, &unused);
  doneAnonymityPolicy();
  releaseClientSocket(sock);
  doneShutdownHandlers();
  doneUtil();
  return 0;
}

/* end of gnunet-search.c */
