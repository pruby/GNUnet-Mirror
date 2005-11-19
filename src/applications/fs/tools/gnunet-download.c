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
 * @file applications/fs/tools/gnunet-download.c
 * @brief Main function to download files from GNUnet.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"


static int verbose = NO;

static Semaphore * signalFinished;

/**
 * Prints the usage information for this command if the user errs.
 * Aborts the program.
 */
static void printhelp() {
  static Help help[] = {
    { 'a', "anonymity", gettext_noop("LEVEL"),
      gettext_noop("set the desired LEVEL of receiver-anonymity") },
    HELP_CONFIG,
    HELP_HELP,
    HELP_HOSTNAME,
    HELP_LOGLEVEL,
    { 'o', "output", gettext_noop("FILENAME"),
      gettext_noop("write the file to FILENAME") },
    { 'R', "recursive", NULL,
      gettext_noop("download a GNUnet directory recursively") },
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-download [OPTIONS] GNUNET-URI",
	     _("Download files from GNUnet."),
	     help);
}

/**
 * ParseOptions for gnunet-download.
 * @return SYSERR to abort afterwards, OK to continue
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
      { "output",    1, 0, 'o' },
      { "recursive", 0, 0, 'R' },
      { "verbose",   0, 0, 'V' },
      { 0,0,0,0 }
    };
    c = GNgetopt_long(argc,
		      argv,
		      "a:c:dhH:L:o:RvV",
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
    case 'o':
      FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
					 "FILENAME",
					 GNoptarg));
      break;
    case 'R':
      FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
					 "RECURSIVE",
					 "YES"));
      break;
    case 'v':
      printf("GNUnet v%s, gnunet-download v%s\n",
	     VERSION,
	     AFS_VERSION);
      return SYSERR;
    case 'V':
      FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
					 "VERBOSE",
					 "YES"));
      break;
    default:
      LOG(LOG_FAILURE,
	  _("Use --help to get a list of options.\n"));
      return SYSERR;
    } /* end of parsing commandline */
  } /* while (1) */
  if (argc - GNoptind != 1) {
    LOG(LOG_WARNING,
	_("Not enough arguments. "
	  "You must specify a GNUnet file URI\n"));
    printhelp();
    return SYSERR;
  }
  FREENONNULL(setConfigurationString("GNUNET-DOWNLOAD",
				     "URI",
				     argv[GNoptind++]));
  return OK;
}

/**
 * This method is called whenever data is received.
 * The current incarnation just ensures that the main
 * method exits once the download is complete.
 */
static void progressModel(void * okVal,
			  const FSUI_Event * event) {
  int * ok = okVal;

  switch (event->type) {
  case FSUI_download_progress:
    if (YES == verbose) {
      PRINTF(_("Download of file `%s' at "
	       "%16llu out of %16llu bytes (%8.3f kbps)\n"),
	     event->data.DownloadProgress.filename,
	     event->data.DownloadProgress.completed,
	     event->data.DownloadProgress.total,
	     (event->data.DownloadProgress.completed/1024.0) /
	     (((double)(cronTime(NULL)-(event->data.DownloadProgress.start_time - 1)))
	      / (double)cronSECONDS) );
    }
    break;
  case FSUI_download_aborted:
    if (FSUI_getDownloadParent(event->data.DownloadError.pos) == NULL) {
      /* top-download aborted */
      PRINTF(_("Error downloading: %s\n"),
	     event->data.DownloadError.message);
      *ok = SYSERR;
      SEMAPHORE_UP(signalFinished);
    } else {
      /* child aborted, maybe FSUI thread
	 policy, ignore?  How can this
	 happen anyway with gnunet-download? */
    }
    break;
  case FSUI_download_error:
    printf(_("Error downloading: %s\n"),
	   event->data.DownloadError.message);
    *ok = SYSERR;
    SEMAPHORE_UP(signalFinished);
    break;
  case FSUI_download_complete:
    if ( (event->data.DownloadProgress.completed ==
	  event->data.DownloadProgress.total) ) {
      PRINTF(_("Download of file `%s' complete.  "
	       "Speed was %8.3f kilobyte per second.\n"),
	     event->data.DownloadProgress.filename,
	     (event->data.DownloadProgress.completed/1024.0) /
	     (((double)(cronTime(NULL)-(event->data.DownloadProgress.start_time - 1)))
	      / (double)cronSECONDS) );
      if (ECRS_equalsUri(event->data.DownloadProgress.main_uri,
			 event->data.DownloadProgress.uri)) {
	*ok = OK;
	SEMAPHORE_UP(signalFinished);
      }
    }
    break;
  default:
    BREAK();
    break;
  }
}

/**
 * Main function to download files from GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from download file: 0: ok, -1, 1: error
 */
int main(int argc,
	 char ** argv) {
  struct ECRS_URI * uri;
  char * fstring;
  char * filename;
  int ok;
  int try_rename;
  struct FSUI_Context * ctx;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;

  verbose = testConfigurationString("GNUNET-DOWNLOAD", "VERBOSE", "YES");
  fstring = getConfigurationString("GNUNET-DOWNLOAD",
  				   "URI");
  uri = ECRS_stringToUri(fstring);
  if ( (NULL == uri) ||
       (! (ECRS_isLocationUri(uri) ||
	   ECRS_isFileUri(uri)) ) ) {
    LOG(LOG_ERROR,
        _("URI `%s' invalid for gnunet-download.\n"),
	fstring);
    FREE(fstring);
    return -1;
  }

  try_rename = NO;
  filename = getConfigurationString("GNUNET-DOWNLOAD",
				    "FILENAME");
  if (filename == NULL) {
    GNUNET_ASSERT(strlen(fstring) >
		  strlen(ECRS_URI_PREFIX) +
		  strlen(ECRS_FILE_INFIX));
    filename = expandFileName(&fstring[strlen(ECRS_URI_PREFIX)+
				       strlen(ECRS_FILE_INFIX)]);
    LOG(LOG_DEBUG,
	"No filename specified, using `%s' instead (for now).\n",
	filename);
    try_rename = YES;
  }
  FREE(fstring);
  signalFinished = SEMAPHORE_NEW(0);
  ctx = FSUI_start("gnunet-download",
		   NO,
		   &progressModel,
		   &ok);
  startCron();
  if (testConfigurationString("GNUNET-DOWNLOAD",
			      "RECURSIVE",
			      "YES"))
    ok = FSUI_startDownloadAll(ctx,
			       getConfigurationInt("FS",
						   "ANONYMITY-RECEIVE"),
			       uri,
			       filename);
  else
    ok = FSUI_startDownload(ctx,
			    getConfigurationInt("FS",
						"ANONYMITY-RECEIVE"),
			    uri,
			    filename);
  if (OK == ok)
    SEMAPHORE_DOWN(signalFinished);
  FSUI_stop(ctx);
  SEMAPHORE_FREE(signalFinished);

  if ( (ok == OK) && (try_rename == YES) ) {
    char * newname = ECRS_suggestFilename(filename);

    if (newname != NULL) {
      fprintf(stdout,
	      _("File stored as `%s'.\n"),
	      newname);
      FREE(newname);
    }
  }
  FREE(filename);
  ECRS_freeUri(uri);

  stopCron();
  doneUtil();

  if (ok == OK)
    return 0;
  else
    return 1;
}

/* end of gnunet-download.c */
