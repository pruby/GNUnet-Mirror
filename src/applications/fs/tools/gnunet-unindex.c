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
 * @file applications/fs/tools/gnunet-unindex.c
 * @brief Tool to unindex files.
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 *
 * TODO: fix message handling, signal handling
 */

#include "platform.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_config_impl.h"
#include "gnunet_util_error_loggers.h"

static struct GE_Context * ectx;

static struct GC_Configuration * cfg;

static struct SEMAPHORE * exitSignal;

static int errorCode;

/**
 * Print progess message.
 */
static void * printstatus(void * cls,
			  const FSUI_Event * event) {
  unsigned long long * verboselevel = cls;
  unsigned long long delta;

  switch(event->type) {
  case FSUI_unindex_progress:
    if (*verboselevel) {
      delta = event->data.UnindexProgress.eta - get_time();
      PRINTF(_("%16llu of %16llu bytes unindexed (estimating %llu seconds to completion)                "),
	     event->data.UnindexProgress.completed,
	     event->data.UnindexProgress.total,
	     delta / cronSECONDS);
      printf("\r");
    }
    break;
  case FSUI_unindex_complete:
    if (*verboselevel) {
      delta = get_time() - event->data.UnindexComplete.start_time;
      PRINTF(
      _("\nUnindexing of `%s' complete, %llu bytes took %llu seconds (%8.3f KiB/s).\n"),
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
    GE_BREAK(ectx, 0);
    break;
  }
  return NULL;
}

/**
 * All gnunet-unindex command line options
 */
static struct CommandLineOption gnunetunindexOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE, /* -c */
  COMMAND_LINE_OPTION_HELP(gettext_noop("Unindex files.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING, /* -L */
  COMMAND_LINE_OPTION_VERSION(PACKAGE_VERSION), /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
};

/**
 * The main function to unindex files.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return 0 for ok, -1 on error
 */
int main(int argc, 
	 const char ** argv) {
  static struct FSUI_Context * ctx;
  char * filename;
  int i;
  unsigned long long verbose;
  struct FSUI_UnindexList * ul;

  /* startup */
  ectx = GE_create_context_stderr(NO, 
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  cfg = GC_create_C_impl();
  GE_ASSERT(ectx, cfg != NULL);
  i = gnunet_parse_options("gnunet-unindex [OPTIONS] FILENAME",
			   ectx,
			   cfg,
			   gnunetunindexOptions,
			   (unsigned int) argc,
			   argv);
  if (i == SYSERR) {
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;  
  }
  if (i == argc) {
    GE_LOG(ectx,
	   GE_WARNING | GE_BULK | GE_USER,
	   _("Not enough arguments. "
	     "You must specify a filename.\n"));
    GC_free(cfg);
    GE_free_context(ectx);
    return -1;
  }
  GC_get_configuration_value_number(cfg,
				    "GNUNET-INSERT",
				    "VERBOSE",
				    0,
				    9999,
				    0,
				    &verbose);
  exitSignal = SEMAPHORE_CREATE(0);
  /* fundamental init */
  ctx = FSUI_start(ectx,
		   cfg,
		   "gnunet-unindex",
		   2,
		   NO,
		   &printstatus,
		   &verbose);
  filename = string_expandFileName(ectx,
				   argv[i]);
  ul = FSUI_unindex(ctx,
		    filename);
  if (ul == NULL) {
    printf(_("`%s' failed.  Is `%s' a file?\n"),
	   "FSUI_unindex",
	   argv[i]);
    errorCode = 1;
  } else {
    /* wait for completion */
    SEMAPHORE_DOWN(exitSignal, YES);
  }
  FREE(filename);
  FSUI_stop(ctx);
  SEMAPHORE_DESTROY(exitSignal);
  GC_free(cfg);
  GE_free_context(ectx);
  return errorCode;
}

/* end of gnunet-unindex.c */
