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
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_boot.h"

static struct GE_Context *ectx;

static struct GC_Configuration *cfg;

static cron_t start_time;

static int errorCode;

static char *cfgFilename = DEFAULT_CLIENT_CONFIG_FILE;

/**
 * Print progess message.
 */
static void *
printstatus (void *cls, const FSUI_Event * event)
{
  unsigned long long *verboselevel = cls;
  unsigned long long delta;

  switch (event->type)
    {
    case FSUI_unindex_progress:
      if (*verboselevel)
        {
          delta = event->data.UnindexProgress.eta - get_time ();
          PRINTF (_
                  ("%16llu of %16llu bytes unindexed (estimating %llu seconds to completion)                "),
                  event->data.UnindexProgress.completed,
                  event->data.UnindexProgress.total, delta / cronSECONDS);
          printf ("\r");
        }
      break;
    case FSUI_unindex_completed:
      if (*verboselevel)
        {
          delta = get_time () - start_time;
          PRINTF (_
                  ("\nUnindexing of `%s' complete, %llu bytes took %llu seconds (%8.3f KiB/s).\n"),
                  event->data.UnindexCompleted.filename,
                  event->data.UnindexCompleted.total, delta / cronSECONDS,
                  (delta ==
                   0) ? (double) (-1.0) : (double) (event->data.
                                                    UnindexCompleted.total /
                                                    1024.0 * cronSECONDS /
                                                    delta));
        }
      errorCode = 0;
      GNUNET_SHUTDOWN_INITIATE ();
      break;
    case FSUI_unindex_error:
      printf (_("\nError unindexing file: %s\n"),
              event->data.UnindexError.message);
      errorCode = 3;
      GNUNET_SHUTDOWN_INITIATE ();
      break;
    case FSUI_unindex_started:
    case FSUI_unindex_stopped:
      break;
    default:
      GE_BREAK (ectx, 0);
      break;
    }
  return NULL;
}

/**
 * All gnunet-unindex command line options
 */
static struct CommandLineOption gnunetunindexOptions[] = {
  COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),  /* -c */
  COMMAND_LINE_OPTION_HELP (gettext_noop ("Unindex files.")),   /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING,  /* -L */
  COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION),        /* -v */
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
int
main (int argc, char *const *argv)
{
  static struct FSUI_Context *ctx;
  char *filename;
  int i;
  unsigned long long verbose;
  struct FSUI_UnindexList *ul;

  i = GNUNET_init (argc,
                   argv,
                   "gnunet-unindex [OPTIONS] FILENAME",
                   &cfgFilename, gnunetunindexOptions, &ectx, &cfg);
  if (i == -1)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  if (i == argc)
    {
      GE_LOG (ectx,
              GE_WARNING | GE_BULK | GE_USER,
              _("Not enough arguments. " "You must specify a filename.\n"));
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  GC_get_configuration_value_number (cfg,
                                     "GNUNET",
                                     "VERBOSE", 0, 9999, 0, &verbose);
  /* fundamental init */
  ctx = FSUI_start (ectx,
                    cfg, "gnunet-unindex", 2, NO, &printstatus, &verbose);
  errorCode = 1;
  start_time = get_time ();
  filename = string_expandFileName (ectx, argv[i]);
  ul = FSUI_startUnindex (ctx, filename);
  if (ul == NULL)
    {
      printf (_("`%s' failed.  Is `%s' a file?\n"), "FSUI_unindex", filename);
      errorCode = 2;
    }
  else
    {
      GNUNET_SHUTDOWN_WAITFOR ();
      if (errorCode == 1)
        FSUI_abortUnindex (ctx, ul);
      FSUI_stopUnindex (ctx, ul);
    }
  FREE (filename);
  FSUI_stop (ctx);
  GNUNET_fini (ectx, cfg);
  return errorCode;
}

/* end of gnunet-unindex.c */
