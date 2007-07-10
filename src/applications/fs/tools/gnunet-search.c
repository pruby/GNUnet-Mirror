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
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util_cron.h"
#include "gnunet_util_boot.h"


static struct GE_Context *ectx;

static struct GC_Configuration *cfg;

static unsigned int anonymity = 1;

static unsigned int delay = 300;

static unsigned int max_results;

static char *cfgFilename = DEFAULT_CLIENT_CONFIG_FILE;

static char *output_filename;

static int errorCode;

static ECRS_FileInfo *fis;

static unsigned int fiCount;


static int
itemPrinter (EXTRACTOR_KeywordType type, const char *data, void *closure)
{
  printf ("\t%20s: %s\n",
          dgettext ("libextractor",
                    EXTRACTOR_getKeywordTypeAsString (type)), data);
  return OK;
}

static void
printMeta (const struct ECRS_MetaData *meta)
{
  ECRS_getMetaData (meta, &itemPrinter, NULL);
}

/**
 * Handle the search result.
 */
static void *
eventCallback (void *cls, const FSUI_Event * event)
{
  char *uri;
  char *filename;

  switch (event->type)
    {
    case FSUI_search_error:
      errorCode = 3;
      GNUNET_SHUTDOWN_INITIATE ();
      break;
    case FSUI_search_aborted:
      errorCode = 4;
      GNUNET_SHUTDOWN_INITIATE ();
      break;
    case FSUI_search_completed:
      errorCode = 0;
      GNUNET_SHUTDOWN_INITIATE ();
      break;
    case FSUI_search_result:
      /* retain URIs for possible directory dump later */
      GROW (fis, fiCount, fiCount + 1);
      fis[fiCount - 1].uri = ECRS_dupUri (event->data.SearchResult.fi.uri);
      fis[fiCount - 1].meta
        = ECRS_dupMetaData (event->data.SearchResult.fi.meta);

      uri = ECRS_uriToString (event->data.SearchResult.fi.uri);
      printf ("%s:\n", uri);
      filename = ECRS_getFromMetaData (event->data.SearchResult.fi.meta,
                                       EXTRACTOR_FILENAME);
      if (filename != NULL)
        {
          char *dotdot;

          while (NULL != (dotdot = strstr (filename, "..")))
            dotdot[0] = dotdot[1] = '_';

          printf ("gnunet-download -o \"%s\" %s\n", filename, uri);
        }
      else
        printf ("gnunet-download %s\n", uri);
      printMeta (event->data.SearchResult.fi.meta);
      printf ("\n");
      FREENONNULL (filename);
      FREE (uri);
      break;
    case FSUI_search_started:
    case FSUI_search_stopped:
      break;
    default:
      GE_BREAK (NULL, 0);
      break;
    }
  return NULL;
}

/**
 * All gnunet-search command line options
 */
static struct CommandLineOption gnunetsearchOptions[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of sender-anonymity"),
   1, &gnunet_getopt_configure_set_uint, &anonymity},
  COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),  /* -c */
  COMMAND_LINE_OPTION_HELP (gettext_noop ("Search GNUnet for files.")), /* -h */
  COMMAND_LINE_OPTION_HOSTNAME, /* -H */
  COMMAND_LINE_OPTION_LOGGING,  /* -L */
  {'m', "max", "LIMIT",
   gettext_noop ("exit after receiving LIMIT results"),
   1, &gnunet_getopt_configure_set_uint, &max_results},
  {'o', "output", "FILENAME",
   gettext_noop ("write encountered (decrypted) search results to FILENAME"),
   1, &gnunet_getopt_configure_set_string, &output_filename},
  {'t', "timeout", "DELAY",
   gettext_noop ("wait DELAY seconds for search results before aborting"),
   1, &gnunet_getopt_configure_set_uint, &delay},
  COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION),        /* -v */
  COMMAND_LINE_OPTION_VERBOSE,
  COMMAND_LINE_OPTION_END,
};

/**
 * The main function to search for files on GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from gnunet-search: 0: ok, -1: error
 */
int
main (int argc, char *const *argv)
{
  struct ECRS_URI *uri;
  int i;
  struct FSUI_Context *ctx;
  struct FSUI_SearchList *s;

  i = GNUNET_init (argc,
                   argv,
                   "gnunet-search [OPTIONS] [KEYWORDS]",
                   &cfgFilename, gnunetsearchOptions, &ectx, &cfg);
  if (i == SYSERR)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  /* convert args to URI */
  uri = ECRS_parseArgvKeywordURI (ectx, argc - i, (const char **) &argv[i]);
  if (uri == NULL)
    {
      printf (_("Error converting arguments to URI!\n"));
      errorCode = -1;
      goto quit;
    }
  if (max_results == 0)
    max_results = (unsigned int) -1;    /* infty */
  ctx = FSUI_start (ectx, cfg, "gnunet-search", 4, NO, &eventCallback, NULL);
  if (ctx == NULL)
    {
      ECRS_freeUri (uri);
      GNUNET_fini (ectx, cfg);
      return SYSERR;
    }
  errorCode = 1;
  s = FSUI_startSearch (ctx,
                        anonymity, max_results, delay * cronSECONDS, uri);
  ECRS_freeUri (uri);
  if (s == NULL)
    {
      errorCode = 2;
      FSUI_stop (ctx);
      goto quit;
    }
  GNUNET_SHUTDOWN_WAITFOR ();
  if (errorCode == 1)
    FSUI_abortSearch (ctx, s);
  FSUI_stopSearch (ctx, s);
  FSUI_stop (ctx);

  if (output_filename != NULL)
    {
      char *outfile;
      unsigned long long n;
      char *data;
      struct ECRS_MetaData *meta;

      meta = ECRS_createMetaData ();
      /* ?: anything here to put into meta? */
      if (OK == ECRS_createDirectory (ectx, &data, &n, fiCount, fis, meta))
        {
          outfile = string_expandFileName (ectx, output_filename);
          disk_file_write (ectx, outfile, data, n, "600");
          FREE (outfile);
          FREE (data);
        }
      FREE (output_filename);
    }
  for (i = 0; i < fiCount; i++)
    {
      ECRS_freeUri (fis[i].uri);
      ECRS_freeMetaData (fis[i].meta);
    }
  GROW (fis, fiCount, 0);
quit:
  GNUNET_fini (ectx, cfg);
  return errorCode;
}

/* end of gnunet-search.c */
