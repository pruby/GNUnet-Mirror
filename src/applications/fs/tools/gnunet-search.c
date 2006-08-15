/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 *
 * TODO:
 * - make sure all (search related) FSUI events are handled correctly!
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_cron.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

static unsigned int anonymity = 1;

static unsigned int delay = 300;

static unsigned int max_results;

static char * output_filename;

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
	 dgettext("libextractor",
		  EXTRACTOR_getKeywordTypeAsString(type)),
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
static void * eventCallback(void * cls,
			    const FSUI_Event * event) {
  SearchClosure * sc = cls;
  char * uri;
  char * filename;

  if (0 == sc->max)
    return NULL;
  if (event->type != FSUI_search_result)
    return NULL;

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
    char * dotdot;
    
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
    GNUNET_SHUTDOWN_INITIATE();
  return NULL;
}

/**
 * All gnunet-search command line options
 */
static struct CommandLineOption gnunetsearchOptions[] = {
  { 'a', "anonymity", "LEVEL",
    gettext_noop("set the desired LEVEL of sender-anonymity"),
    1, &gnunet_getopt_configure_set_uint, &anonymity }, 
  COMMAND_LINE_OPTION_CFG_FILE, /* -c */
  COMMAND_LINE_OPTION_HELP(gettext_noop("Create new pseudonyms, delete pseudonyms or list existing pseudonyms.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  { 'm', "max", "LIMIT",
    gettext_noop("exit after receiving LIMIT results"),
    1, &gnunet_getopt_configure_set_uint, &max_results },  
  { 'o', "output", "FILENAME",
    gettext_noop("write encountered (decrypted) search results to FILENAME"),
    1, &gnunet_getopt_configure_set_string, &output_filename },
  { 't', "timeout", "DELAY",
    gettext_noop("wait DELAY seconds for search results before aborting"),
    0, &gnunet_getopt_configure_set_uint, &delay },
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
};

static void run_shutdown(void * unused) {
  GNUNET_SHUTDOWN_INITIATE();
}

/**
 * Perform a normal (non-namespace) search.
 */
static int runSearch(const char * suri) {
  struct FSUI_Context * ctx;
  SearchClosure sc;
  struct ECRS_URI * uri;
  struct FSUI_SearchList * s;
  int i;

  if (suri == NULL) {
    GE_BREAK(ectx, 0);
    return SYSERR;
  }
  uri = ECRS_stringToUri(ectx,
			 suri);
  memset(&sc, 0, sizeof(SearchClosure));
  sc.max = max_results;
  sc.resultCount = 0;
  if (sc.max == 0)
    sc.max = (unsigned int)-1; /* infty */
  ctx = FSUI_start(ectx,
		   cfg,
		   "gnunet-search",
		   4,
		   NO,
		   &eventCallback,
		   &sc);
  if (ctx == NULL) {
    ECRS_freeUri(uri);
    return SYSERR;
  }
  s = FSUI_startSearch(ctx,
		       anonymity,
		       uri);
  if (s == NULL) {
    printf(_("Starting search failed. Consult logs.\n"));
  } else {
    GNUNET_SHUTDOWN_WAITFOR();
    FSUI_stopSearch(ctx,
		    s);
  }
  ECRS_freeUri(uri);
  FSUI_stop(ctx);

  if (output_filename != NULL) {
    char * outfile;
    unsigned long long n;
    char * data;
    struct ECRS_MetaData * meta;

    meta = ECRS_createMetaData();
    /* ?: anything here to put into meta? */
    if (OK == ECRS_createDirectory(ectx,
				   &data,
				   &n,
				   sc.fiCount,
				   sc.fis,
				   meta)) {
      outfile = string_expandFileName(ectx,
				      output_filename);
      disk_file_write(ectx,
		      outfile,
		      data,
		      n,
		      "600");
      FREE(outfile);
      FREE(data);
    }
    FREE(output_filename);
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
	 const char ** argv) {
  int ret;
  char * suri;
  struct ECRS_URI * uri;
  int i;
  struct CronManager * cron;

  /* startup */
  ectx = GE_create_context_stderr(NO, 
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  i = gnunet_parse_options("gnunet-search [OPTIONS] [KEYWORDS]",
			   ectx,
			   cfg,
			   gnunetsearchOptions,
			   (unsigned int) argc,
			   argv);
  if (i == SYSERR) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;  
  }

  /* convert args to URI */
  uri = ECRS_parseArgvKeywordURI(ectx,
				 argc - i,
				 (const char**) &argv[i]);
  if (uri != NULL) {
    suri = ECRS_uriToString(uri);
    ECRS_freeUri(uri);
  } else {
    printf(_("Error converting arguments to URI!\n"));
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;
  }

  cron = cron_create(ectx);
  cron_add_job(cron,
	       &run_shutdown,
	       cronSECONDS * delay,
	       0, /* no need to repeat */
	       NULL);
  cron_start(cron);
  ret = runSearch(suri);
  FREE(suri);

  cron_stop(cron);
  cron_del_job(cron,
	       &run_shutdown,
	       0,
	       NULL);
  cron_destroy(cron);

  GC_free(cfg);
  GE_free_context(ectx);
  if (ret == OK)
    return 0;
  else
    return -1;
}

/* end of gnunet-search.c */
