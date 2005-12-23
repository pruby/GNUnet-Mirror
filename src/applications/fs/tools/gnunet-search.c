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
 * @file applications/fs/tools/gnunet-search.c
 * @brief Main function to search for files on GNUnet.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"

typedef struct {
  unsigned int resultCount;
  unsigned int max;
  ECRS_FileInfo * fis;
  unsigned int fiCount;
} SearchClosure;


static int itemPrinter(EXTRACTOR_KeywordType type,
		       const char * data,
		       void * closure) {
  printf("\t%20s: %s\n",
	 EXTRACTOR_getKeywordTypeAsString(type),
	 data);
  return OK;
}

static void printMeta(const struct ECRS_MetaData * meta) {
  ECRS_getMetaData(meta,
		   &itemPrinter,
		   NULL);
}

/**
 * Handle the search result.
 */
static void eventCallback(SearchClosure * sc,
			  const FSUI_Event * event) {
  char * uri;
  char * filename;

  if (event->type != FSUI_search_result)
    return;

  /* retain URIs for possible directory dump later */
  GROW(sc->fis,
       sc->fiCount,
       sc->fiCount+1);
  sc->fis[sc->fiCount-1].uri
    = ECRS_dupUri(event->data.SearchResult.fi.uri);
  sc->fis[sc->fiCount-1].meta
    = ECRS_dupMetaData(event->data.SearchResult.fi.meta);

  uri = ECRS_uriToString(event->data.SearchResult.fi.uri);
  printf("%s:\n",
	 uri);
  filename = ECRS_getFromMetaData(event->data.SearchResult.fi.meta,
				  EXTRACTOR_FILENAME);
  if (filename != NULL) {
    char *dotdot;
    
    while (NULL != (dotdot = strstr(filename, "..")))
      dotdot[0] = dotdot[1] = '_';
    
    printf("gnunet-download -o \"%s\" %s\n",
	   filename,
	   uri);
  }
  else
    printf("gnunet-download %s\n",
	   uri);
  printMeta(event->data.SearchResult.fi.meta);
  printf("\n");
  FREENONNULL(filename);
  FREE(uri);
  if (0 == --sc->max)
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
    { 'o', "output", "FILENAME",
      gettext_noop("write encountered (decrypted) search results to FILENAME") },
    { 't', "timeout", "TIMEOUT",
      gettext_noop("wait TIMEOUT seconds for search results before aborting") },
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

  setConfigurationInt("FS",
		      "ANONYMITY-RECEIVE",
		      1);
  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "anonymity", 1, 0, 'a' },
      { "max",       1, 0, 'm' },
      { "output",    1, 0, 'o' },
      { "timeout",   1, 0, 't' },
      { 0,0,0,0 }
    };
    c = GNgetopt_long(argc,
		      argv,
		      "a:c:dhH:L:m:o:t:v",
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
	    _("You must pass a number to the `%s' option.\n"),
	    "-m");
	return SYSERR;
      } else {
	setConfigurationInt("FS",
			    "MAXRESULTS",
			    max);
	if (max == 0)
	  return SYSERR; /* exit... */	
      }
      break;
    }
    case 'o':
      FREENONNULL(setConfigurationString("GNUNET-SEARCH",
      					 "OUTPUT_PREFIX",
					 GNoptarg));
      break;
    case 't': {
      unsigned int timeout;
      if (1 != sscanf(GNoptarg, "%ud", &timeout)) {
	LOG(LOG_FAILURE,
	    _("You must pass a number to the `%s' option.\n"),
	    "-t");
	return SYSERR;
      } else {
	setConfigurationInt("FS",
			    "SEARCHTIMEOUT",
			    timeout);
      }
      break;
    }
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
static int runSearch() {
  struct FSUI_Context * ctx;
  SearchClosure sc;
  char * suri;
  struct ECRS_URI * uri;
  int i;
  char * prefix;

  suri = getConfigurationString("GNUNET-SEARCH",
				"URI");
  if (suri == NULL) {
    BREAK();
    return SYSERR;
  }
  uri = ECRS_stringToUri(suri);
  if (uri == NULL)
    uri = FSUI_parseCharKeywordURI(suri);
  FREE(suri);

  memset(&sc, 0, sizeof(SearchClosure));
  sc.max = getConfigurationInt("FS",
			       "MAXRESULTS");
  sc.resultCount = 0;
  if (sc.max == 0)
    sc.max = (unsigned int)-1; /* infty */
  ctx = FSUI_start("gnunet-search",
		   NO,
		   (FSUI_EventCallback) &eventCallback,
		   &sc);
  if (ctx == NULL) {
    ECRS_freeUri(uri);
    return SYSERR;
  }
  if (OK !=
      FSUI_startSearch(ctx,
		       getConfigurationInt("FS",
					   "ANONYMITY-RECEIVE"),
		       uri)) {
    printf(_("Starting search failed. Consult logs.\n"));
  } else {
    wait_for_shutdown();
    FSUI_stopSearch(ctx,
		    uri);
  }
  ECRS_freeUri(uri);
  FSUI_stop(ctx);

  prefix = getConfigurationString("GNUNET-SEARCH",
  				  "OUTPUT_PREFIX");
  if (prefix != NULL) {
    char * outfile;
    unsigned long long n;
    char * data;
    struct ECRS_MetaData * meta;

    meta = ECRS_createMetaData();
    /* ?: anything here to put into meta? */
    if (OK == ECRS_createDirectory(&data,
				   &n,
				   sc.fiCount,
				   sc.fis,
				   meta)) {
      outfile = expandFileName(prefix);
      writeFile(outfile,
		data,
		n,
		"600");
      FREE(outfile);
      FREE(data);
    }
    FREE(prefix);
  }
  for (i=0;i<sc.fiCount;i++) {
    ECRS_freeUri(sc.fis[i].uri);
    ECRS_freeMetaData(sc.fis[i].meta);
  }
  GROW(sc.fis,
       sc.fiCount,
       0);
  return OK;
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
  int ret;
  char * suri;
  struct ECRS_URI * uri;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;

  /* convert args to URI */
  argc = getConfigurationStringList(&argv);
  uri = NULL;
  if (argc == 1)
    uri = ECRS_stringToUri(argv[0]);
  if (uri == NULL)
    uri = FSUI_parseArgvKeywordURI(argc,
				   (const char**) argv);
  while (argc > 0)
    FREE(argv[--argc]);
  FREE(argv);
  if (uri != NULL) {
    suri = ECRS_uriToString(uri);
    ECRS_freeUri(uri);
  } else {
    printf(_("Error converting arguments to URI!\n"));
    return -1;
  }
  FREENONNULL(setConfigurationString("GNUNET-SEARCH",
				     "URI",
				     suri));
  FREE(suri);


  initializeShutdownHandlers();
  addCronJob((CronJob)&run_shutdown,
	     cronSECONDS * getConfigurationInt("FS",
					       "SEARCHTIMEOUT"),
	     0, /* no need to repeat */
	     NULL);
  startCron();
  ret = runSearch();
  stopCron();
  delCronJob((CronJob)&run_shutdown,
	     0,
	     NULL);
  doneShutdownHandlers();
  doneUtil();
  if (ret == OK)
    return 0;
  else
    return -1;
}

/* end of gnunet-search.c */
