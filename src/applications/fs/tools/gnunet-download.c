/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_directories.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_boot.h"

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

static unsigned long long verbose;

static int do_recursive;

static char * cfgFilename = DEFAULT_CLIENT_CONFIG_FILE;

static char * filename;

static unsigned int anonymity = 1;

static cron_t start_time;

static struct FSUI_DownloadList * dl;

static int errorCode;

/**
 * All gnunet-download command line options
 */
static struct CommandLineOption gnunetdownloadOptions[] = {
  { 'a', "anonymity", "LEVEL",
    gettext_noop("set the desired LEVEL of sender-anonymity"),
    1, &gnunet_getopt_configure_set_uint, &anonymity },
  COMMAND_LINE_OPTION_CFG_FILE(&cfgFilename), /* -c */
  COMMAND_LINE_OPTION_HELP(gettext_noop("Download files from GNUnet.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  { 'o', "output", "FILENAME",
    gettext_noop("write encountered (decrypted) search results to FILENAME"),
    1, &gnunet_getopt_configure_set_string, &filename },
  { 'R', "recursive", NULL,
    gettext_noop("download a GNUnet directory recursively"),
    1, &gnunet_getopt_configure_set_one, &do_recursive },
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
};

/**
 * This method is called whenever data is received.
 * The current incarnation just ensures that the main
 * method exits once the download is complete.
 */
static void * progressModel(void * unused,
			    const FSUI_Event * event) {
  switch (event->type) {
  case FSUI_download_progress:
    if (verbose) {
      PRINTF(_("Download of file `%s' at "
	       "%16llu out of %16llu bytes (%8.3f KiB/s)\n"),
	     event->data.DownloadProgress.filename,
	     event->data.DownloadProgress.completed,
	     event->data.DownloadProgress.total,
	     (event->data.DownloadProgress.completed/1024.0) /
	     (((double)(get_time()-(start_time - 1)))
	      / (double)cronSECONDS) );
    }
    break;
  case FSUI_download_aborted:
    if (dl == event->data.DownloadError.dc.pos) {
      /* top-download aborted */
      printf(_("Download aborted.\n"));
      errorCode = 2;
      GNUNET_SHUTDOWN_INITIATE();
    }
    break;
  case FSUI_download_error:
    printf(_("Error downloading: %s\n"),
	   event->data.DownloadError.message);
    errorCode = 3;
    GNUNET_SHUTDOWN_INITIATE();
    break;
  case FSUI_download_completed:
    PRINTF(_("Download of file `%s' complete.  "
	     "Speed was %8.3f KiB per second.\n"),
	   event->data.DownloadCompleted.filename,
	   (event->data.DownloadCompleted.total/1024.0) /
	   (((double)(get_time()-(start_time - 1)))
	    / (double)cronSECONDS) );
    if (dl == event->data.DownloadCompleted.dc.pos) {
      errorCode = 0;
      GNUNET_SHUTDOWN_INITIATE();
    }
    break;
  case FSUI_download_started:
  case FSUI_download_stopped:
    break;
  default:
    GE_BREAK(ectx, 0);
    break;
  }
  return NULL;
}

/**
 * Main function to download files from GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from download file: 0: ok, -1, 1: error
 */
int main(int argc,
	 const char ** argv) {
  int ok;
  int try_rename;
  struct FSUI_Context * ctx;
  struct ECRS_URI * uri;
  struct ECRS_MetaData * meta;
  int i;

  i = GNUNET_init(argc,
		  argv,
		  "gnunet-download [OPTIONS] [KEYWORDS]",
		  &cfgFilename,
		  gnunetdownloadOptions,
		  &ectx,
		  &cfg);
  if (i == -1) {
    errorCode = -1;
    goto quit;
  }
  if (i == argc) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Not enough arguments. "
	     "You must specify a GNUnet file URI\n"));
    errorCode = -1;
    goto quit;
  }
  GC_get_configuration_value_number(cfg,
				    "GNUNET",
				    "VERBOSE",
				    0,
				    9999,
				    0,
				    &verbose);
  uri = ECRS_stringToUri(ectx,
			 argv[i]);
  if ( (NULL == uri) ||
       (! (ECRS_isLocationUri(uri) ||
	   ECRS_isFileUri(uri)) ) ) {
    GE_LOG(ectx,
	   GE_ERROR | GE_BULK | GE_USER,
	   _("URI `%s' invalid for gnunet-download.\n"),
	   argv[i]);
    errorCode = -1;
    goto quit;
  }

  try_rename = NO;
  if (filename == NULL) {
    GE_ASSERT(ectx,
	      strlen(argv[i]) >
	      strlen(ECRS_URI_PREFIX) +
	      strlen(ECRS_FILE_INFIX));
    filename = string_expandFileName(ectx,
				     &argv[i][strlen(ECRS_URI_PREFIX)+
					      strlen(ECRS_FILE_INFIX)]);
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "No filename specified, using `%s' instead (for now).\n",
	   filename);
    try_rename = YES;
  }
  ok = NO;
  ctx = FSUI_start(ectx,
		   cfg,
		   "gnunet-download",
		   32, /* FIXME: support option! */
		   NO,
		   &progressModel,
		   NULL);
  start_time = get_time();
  errorCode = 1;
  meta = ECRS_createMetaData();
  dl = FSUI_startDownload(ctx,
			  anonymity,
			  do_recursive,
			  uri,
			  meta,
			  filename,
			  NULL,
			  NULL);
  ECRS_freeMetaData(meta);
  if (dl == NULL) {
    FSUI_stop(ctx);
    goto quit;
  }
  GNUNET_SHUTDOWN_WAITFOR();
  if (errorCode == 1)
    FSUI_abortDownload(ctx, dl);
  FSUI_stopDownload(ctx, dl);
  FSUI_stop(ctx);

  if ( (errorCode == 0) &&
       (dl != NULL) &&
       (try_rename == YES) ) {
    char * newname = ECRS_suggestFilename(ectx,
					  filename);

    if (newname != NULL) {
      fprintf(stdout,
	      _("File stored as `%s'.\n"),
	      newname);
      FREE(newname);
    }
  }
  FREE(filename);
  ECRS_freeUri(uri);
 quit:
  GNUNET_fini(ectx, cfg);
  return errorCode;
}

/* end of gnunet-download.c */
