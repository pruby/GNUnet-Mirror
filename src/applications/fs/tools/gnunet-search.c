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
#include "gnunet_util.h"


static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static unsigned int anonymity = 1;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static char *output_filename;

static int errorCode;

static GNUNET_ECRS_FileInfo *fis;

static unsigned int fiCount;


static int
itemPrinter (EXTRACTOR_KeywordType type, const char *data, void *closure)
{
  printf ("\t%20s: %s\n",
          dgettext ("libextractor",
                    EXTRACTOR_getKeywordTypeAsString (type)), data);
  return GNUNET_OK;
}

static void
printMeta (const struct GNUNET_MetaData *meta)
{
  GNUNET_meta_data_get_contents (meta, &itemPrinter, NULL);
}

/**
 * Handle the search result.
 */
static void *
eventCallback (void *cls, const GNUNET_FSUI_Event * event)
{
  char *uri;
  char *filename;

  switch (event->type)
    {
    case GNUNET_FSUI_search_aborted:
      errorCode = 4;
      GNUNET_shutdown_initiate ();
      break;
    case GNUNET_FSUI_search_result:
      /* retain URIs for possible directory dump later */
      GNUNET_array_grow (fis, fiCount, fiCount + 1);
      fis[fiCount - 1].uri =
        GNUNET_ECRS_uri_duplicate (event->data.SearchResult.fi.uri);
      fis[fiCount - 1].meta =
        GNUNET_meta_data_duplicate (event->data.SearchResult.fi.meta);

      uri = GNUNET_ECRS_uri_to_string (event->data.SearchResult.fi.uri);
      printf ("%s:\n", uri);
      filename =
        GNUNET_meta_data_get_by_type (event->data.SearchResult.fi.meta,
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
      GNUNET_free_non_null (filename);
      GNUNET_free (uri);
      break;
    case GNUNET_FSUI_search_started:
    case GNUNET_FSUI_search_stopped:
    case GNUNET_FSUI_search_update:
      break;
    default:
      GNUNET_GE_BREAK (NULL, 0);
      break;
    }
  return NULL;
}

/**
 * All gnunet-search command line options
 */
static struct GNUNET_CommandLineOption gnunetsearchOptions[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of sender-anonymity"),
   1, &GNUNET_getopt_configure_set_uint, &anonymity},
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Search GNUnet for files.")),  /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'o', "output", "FILENAME",
   gettext_noop ("write encountered (decrypted) search results to FILENAME"),
   1, &GNUNET_getopt_configure_set_string, &output_filename},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
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
  struct GNUNET_ECRS_URI *uri;
  int i;
  struct GNUNET_FSUI_Context *ctx;
  struct GNUNET_FSUI_SearchList *s;

  i = GNUNET_init (argc,
                   argv,
                   "gnunet-search [OPTIONS] [KEYWORDS]",
                   &cfgFilename, gnunetsearchOptions, &ectx, &cfg);
  if (i == GNUNET_SYSERR)
    {
      GNUNET_fini (ectx, cfg);
      return -1;
    }
  /* convert args to URI */
  uri =
    GNUNET_ECRS_keyword_command_line_to_uri (ectx, argc - i,
                                             (const char **) &argv[i]);
  if (uri == NULL)
    {
      printf (_("Error converting arguments to URI!\n"));
      errorCode = -1;
      goto quit;
    }
  ctx =
    GNUNET_FSUI_start (ectx, cfg, "gnunet-search", 4, GNUNET_NO,
                       &eventCallback, NULL);
  if (ctx == NULL)
    {
      GNUNET_ECRS_uri_destroy (uri);
      GNUNET_fini (ectx, cfg);
      return GNUNET_SYSERR;
    }
  errorCode = 1;
  s = GNUNET_FSUI_search_start (ctx, anonymity, uri);
  GNUNET_ECRS_uri_destroy (uri);
  if (s == NULL)
    {
      errorCode = 2;
      GNUNET_FSUI_stop (ctx);
      goto quit;
    }
  GNUNET_shutdown_wait_for ();
  if (errorCode == 1)
    GNUNET_FSUI_search_abort (s);
  GNUNET_FSUI_search_stop (s);
  GNUNET_FSUI_stop (ctx);

  if (output_filename != NULL)
    {
      char *outfile;
      unsigned long long n;
      char *data;
      struct GNUNET_MetaData *meta;

      meta = GNUNET_meta_data_create ();
      /* ?: anything here to put into meta? */
      if (GNUNET_OK ==
          GNUNET_ECRS_directory_create (ectx, &data, &n, fiCount, fis, meta))
        {
          outfile = GNUNET_expand_file_name (ectx, output_filename);
          GNUNET_disk_file_write (ectx, outfile, data, n, "600");
          GNUNET_free (outfile);
          GNUNET_free (data);
        }
      GNUNET_free (output_filename);
    }
  for (i = 0; i < fiCount; i++)
    {
      GNUNET_ECRS_uri_destroy (fis[i].uri);
      GNUNET_meta_data_destroy (fis[i].meta);
    }
  GNUNET_array_grow (fis, fiCount, 0);
quit:
  GNUNET_fini (ectx, cfg);
  return errorCode;
}

/* end of gnunet-search.c */
