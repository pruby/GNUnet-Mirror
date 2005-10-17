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
 * @file applications/fs/tools/gnunet-unindex.c
 * @brief Tool to unindex files.
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"

static Semaphore * exitSignal;

static int errorCode;

static struct FSUI_Context * ctx;

/**
 * Print progess message.
 */
static void printstatus(int * verboselevel,
			const FSUI_Event * event) {
  unsigned long long delta;

  switch(event->type) {
  case FSUI_unindex_progress:
    if (*verboselevel == YES) {
      delta = event->data.UnindexProgress.eta - cronTime(NULL);
      PRINTF(_("%16llu of %16llu bytes unindexed (estimating %llu seconds to completion)                "),
	     event->data.UnindexProgress.completed,
	     event->data.UnindexProgress.total,
	     delta / cronSECONDS);
      printf("\r");
    }
    break;
  case FSUI_unindex_complete:
    if (*verboselevel == YES) {
      delta = cronTime(NULL) - event->data.UnindexComplete.start_time;
      PRINTF(
      _("\nUnindexing of `%s' complete, %llu bytes took %llu seconds (%8.3f kbps).\n"),
      event->data.UnindexComplete.filename,
      event->data.UnindexComplete.total,
      delta / cronSECONDS,
      (delta == 0)
      ? (double) (-1.0)
      : (double) (event->data.UnindexComplete.total / 1024.0 * cronSECONDS / delta));
    }
    SEMAPHORE_UP(exitSignal);
    break;
  case FSUI_unindex_error:
    printf(_("\nError unindexing file: %s\n"),
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
    HELP_HELP,
    HELP_HOSTNAME,
    HELP_LOGLEVEL,
    HELP_VERSION,
    HELP_VERBOSE,
    HELP_END,
  };
  formatHelp("gnunet-unindex [OPTIONS] FILENAME*",
	     _("Unindex files."),
	     help);
}

static int parseOptions(int argc,
			char ** argv) {
  int c;

  FREENONNULL(setConfigurationString("GNUNET-INSERT",
	  		 	     "INDEX-CONTENT",
			             "YES"));
  while (1) {
    int option_index=0;
    static struct GNoption long_options[] = {
      LONG_DEFAULT_OPTIONS,
      { "verbose",       0, 0, 'V' },
      { 0,0,0,0 }
    };
    c = GNgetopt_long(argc,
		      argv,
		      "hHLvV",
		      long_options,
		      &option_index);
    if (c == -1)
      break;  /* No more flags to process */
    if (YES == parseDefaultOptions(c, GNoptarg))
      continue;
    switch(c) {
    case 'h':
      printhelp();
      return SYSERR;
    case 'V':
      FREENONNULL(setConfigurationString("GNUNET-INSERT",
					 "VERBOSE",
					 "YES"));
      break;
    case 'v':
      printf("GNUnet v%s, gnunet-unindex v%s\n",
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
  if (argc - GNoptind != 1) {
    printf(_("You must specify one and only one file to unindex.\n"));
    return SYSERR;
  }
  setConfigurationString("GNUNET-INSERT",
			 "MAIN-FILE",
			 argv[GNoptind]);
  return OK;
}

/**
 * The main function to unindex files.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return 0 for ok, -1 on error
 */
int main(int argc, char ** argv) {
  char * filename;
  int verbose;
  char * tmp;

  if (SYSERR == initUtil(argc, argv, &parseOptions))
    return 0;

  verbose = testConfigurationString("GNUNET-INSERT",
				    "VERBOSE",
				    "YES");
  exitSignal = SEMAPHORE_NEW(0);
  /* fundamental init */
  ctx = FSUI_start("gnunet-unindex",
		   NO,
		   (FSUI_EventCallback) &printstatus,
		   &verbose);

  /* first insert all of the top-level files or directories */
  tmp = getConfigurationString("GNUNET-INSERT",
			       "MAIN-FILE");
  filename = expandFileName(tmp);
  FREE(tmp);
  if (OK != FSUI_unindex(ctx,
			 filename)) {
    printf(_("`%s' failed.  Is `%s' a file?\n"),
	   "FSUI_unindex",
	   filename);
    errorCode = 1;
  } else {
    /* wait for completion */
    SEMAPHORE_DOWN(exitSignal);
    SEMAPHORE_FREE(exitSignal);
  }
  FREE(filename);
  FSUI_stop(ctx);
  doneUtil();
  return errorCode;
}

/* end of gnunet-unindex.c */
