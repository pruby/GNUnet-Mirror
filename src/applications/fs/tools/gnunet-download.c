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
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

static unsigned long long verbose;

static int do_recursive;

static char * cfgFilename = DEFAULT_CLIENT_CONFIG_FILE;

static char * filename;

static unsigned int anonymity = 1;

static cron_t start_time;

static struct FSUI_DownloadList * dl;

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
static void * progressModel(void * okVal,
			    const FSUI_Event * event) {
  int * ok = okVal;

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
      PRINTF(_("Download aborted.\n"));
    }
    break;
  case FSUI_download_error:
    printf(_("Error downloading: %s\n"),
	   event->data.DownloadError.message);
    *ok = SYSERR;
    GNUNET_SHUTDOWN_INITIATE();
    break;
  case FSUI_download_completed:
    if ( (event->data.DownloadProgress.completed ==
	  event->data.DownloadProgress.total) ) {
      PRINTF(_("Download of file `%s' complete.  "
	       "Speed was %8.3f KiB per second.\n"),
	     event->data.DownloadProgress.filename,
	     (event->data.DownloadProgress.completed/1024.0) /
	     (((double)(get_time()-(start_time - 1)))
	      / (double)cronSECONDS) );
      if (dl == event->data.DownloadProgress.dc.pos) {
	*ok = OK;
	GNUNET_SHUTDOWN_INITIATE();
      }
    }
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
  int i;

  /* startup */
  ectx = GE_create_context_stderr(NO, 
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  os_init(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  i = gnunet_parse_options("gnunet-download [OPTIONS] [KEYWORDS]",
			   ectx,
			   cfg,
			   gnunetdownloadOptions,
			   (unsigned int) argc,
			   argv);
  if ( (i == SYSERR) ||
       (0 != GC_parse_configuration(cfg,
				    cfgFilename)) ) {	 
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;  
  }
  if (i == argc) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Not enough arguments. "
	     "You must specify a GNUnet file URI\n"));
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;
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
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;
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
		   &ok);
  start_time = get_time();
  dl = FSUI_startDownload(ctx,
			  anonymity,
			  do_recursive,
			  uri,
			  filename);
  GNUNET_SHUTDOWN_WAITFOR();
  if (OK != ok)
    FSUI_abortDownload(ctx, dl);
  FSUI_stopDownload(ctx, dl);
  FSUI_stop(ctx);

  if ( (OK == ok) &&
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
  GC_free(cfg);
  GE_free_context(ectx);
  if (ok != OK)
    return 1;
  return 0;
}

/* end of gnunet-download.c */
