/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/tools/gnunet-insert.c
 * @brief Tool to insert or index files into GNUnet's FS.
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_namespace_lib.h"
#include "gnunet_util.h"

static int errorCode;

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_FSUI_Context *ctx;

static struct GNUNET_FSUI_UploadList *ul;

static GNUNET_CronTime start_time;

/* ************ config options ******** */

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static struct GNUNET_MetaData *meta;

static struct GNUNET_ECRS_URI *topKeywords;

static struct GNUNET_ECRS_URI *gloKeywords;

static struct GNUNET_MetaData *meta;

static unsigned int anonymity = 1;

static unsigned int priority = 365;

static char *uri_string;

static char *next_id;

static char *this_id;

static char *pseudonym;

static int do_insert;

static int do_no_direct_references;

static int do_copy;

static int do_simulate;

static int extract_only;

static int do_disable_creation_time;

/**
 * We're done with the upload of the file, do the
 * post-processing.
 */
static void
postProcess (const struct GNUNET_ECRS_URI *uri)
{
  GNUNET_HashCode nsid;
  struct GNUNET_ECRS_URI *nsuri;
  char *us;

  if (pseudonym == NULL)
    return;
  if (GNUNET_OK != GNUNET_pseudonym_name_to_id (ectx, cfg, pseudonym, &nsid))
    {
      printf (_("\tUnknown namespace `%s'\n"), pseudonym);
      return;
    }
  nsuri = GNUNET_NS_add_to_namespace (ectx,
                                      cfg,
                                      anonymity,
                                      priority,
                                      GNUNET_get_time () +
                                      2 * GNUNET_CRON_YEARS, &nsid,
                                      this_id, next_id, uri, meta);
  if (nsuri != NULL)
    {
      us = GNUNET_ECRS_uri_to_string (nsuri);
      GNUNET_ECRS_uri_destroy (nsuri);
      printf (_("Created entry `%s' in namespace `%s'\n"), us, pseudonym);
      GNUNET_free (us);
    }
  else
    {
      printf (_("Failed to add entry to namespace `%s' (does it exist?)\n"),
              pseudonym);
    }
  GNUNET_free (pseudonym);
  pseudonym = NULL;
}

static int
listKeywords (const char *fn, const char *dir, void *cls)
{
  EXTRACTOR_ExtractorList *l = cls;
  char *fullName;
  struct stat buf;
  EXTRACTOR_KeywordList *list;

  fullName = GNUNET_malloc (strlen (dir) + strlen (fn) + 2);
  strcpy (fullName, dir);
  if (dir[strlen (dir) - 1] != DIR_SEPARATOR)
    strcat (fullName, DIR_SEPARATOR_STR);
  strcat (fullName, fn);
  printf (_("Keywords for file `%s':\n"), fullName);
  if (0 != STAT (fullName, &buf))
    {
      GNUNET_free (fullName);
      return GNUNET_OK;
    }
  if (S_ISDIR (buf.st_mode))
    {
      printf ("%s - %s\n", dgettext ("libextractor", "filename"), fn);
      printf ("%s - %s\n",
              dgettext ("libextractor", "mimetype"),
              "application/gnunet-directory");
      GNUNET_disk_directory_scan (NULL, fullName, &listKeywords, cls);
    }
  else
    {
      list = EXTRACTOR_getKeywords (l, fullName);
      list = EXTRACTOR_removeDuplicateKeywords (list,
                                                EXTRACTOR_DUPLICATES_TYPELESS);
      list = EXTRACTOR_removeKeywordsOfType (list, EXTRACTOR_THUMBNAIL_DATA);
      EXTRACTOR_printKeywords (stdout, list);
      EXTRACTOR_freeKeywords (list);
    }
  GNUNET_free (fullName);
  return GNUNET_OK;
}


/**
 * Print progess message.
 */
static void *
printstatus (void *ctx, const GNUNET_FSUI_Event * event)
{
  unsigned long long *verboselevel = ctx;
  unsigned long long delta;
  char *fstring;

  switch (event->type)
    {
    case GNUNET_FSUI_upload_progress:
      if (*verboselevel)
        {
          char *ret;
          GNUNET_CronTime now;

          now = GNUNET_get_time ();
          delta = event->data.UploadProgress.eta - now;
          if (event->data.UploadProgress.eta < now)
            delta = 0;
          ret = GNUNET_get_time_interval_as_fancy_string (delta);
          PRINTF (_("%16llu of %16llu bytes inserted "
                    "(estimating %6s to completion) - %s\n"),
                  event->data.UploadProgress.completed,
                  event->data.UploadProgress.total,
                  ret, event->data.UploadProgress.filename);
          GNUNET_free (ret);
        }
      break;
    case GNUNET_FSUI_upload_completed:
      if (*verboselevel)
        {
          delta = GNUNET_get_time () - start_time;
          PRINTF (_("Upload of `%s' complete, "
                    "%llu bytes took %llu seconds (%8.3f KiB/s).\n"),
                  event->data.UploadCompleted.filename,
                  event->data.UploadCompleted.total,
                  delta / GNUNET_CRON_SECONDS,
                  (delta == 0)
                  ? (double) (-1.0)
                  : (double) (event->data.UploadCompleted.total
                              / 1024.0 * GNUNET_CRON_SECONDS / delta));
        }
      fstring = GNUNET_ECRS_uri_to_string (event->data.UploadCompleted.uri);
      printf (_("File `%s' has URI: %s\n"),
              event->data.UploadCompleted.filename, fstring);
      GNUNET_free (fstring);
      if (ul == event->data.UploadCompleted.uc.pos)
        {
          postProcess (event->data.UploadCompleted.uri);
          errorCode = 0;
          GNUNET_shutdown_initiate ();
        }
      break;
    case GNUNET_FSUI_upload_aborted:
      printf (_("\nUpload aborted.\n"));
      errorCode = 2;
      GNUNET_shutdown_initiate ();
      break;
    case GNUNET_FSUI_upload_error:
      printf (_("\nError uploading file: %s"),
              event->data.UploadError.message);
      errorCode = 3;
      GNUNET_shutdown_initiate ();
      break;
    case GNUNET_FSUI_upload_started:
    case GNUNET_FSUI_upload_stopped:
      break;
    default:
      printf (_("\nUnexpected event: %d\n"), event->type);
      GNUNET_GE_BREAK (ectx, 0);
      break;
    }
  return NULL;
}

/**
 * All gnunet-insert command line options
 */
static struct GNUNET_CommandLineOption gnunetinsertOptions[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of sender-anonymity"),
   1, &GNUNET_getopt_configure_set_uint, &anonymity},
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  {'C', "copy", NULL,
   gettext_noop ("even if gnunetd is running on the local machine, force the"
                 " creation of a copy instead of making a link to the GNUnet share directory"),
   0, &GNUNET_getopt_configure_set_one, &do_copy},
  {'d', "disable-creation-time", NULL,
   gettext_noop
   ("disable adding the creation time to the metadata of the uploaded file"),
   0, &GNUNET_getopt_configure_set_one, &do_disable_creation_time},
  {'D', "disable-direct", NULL,
   gettext_noop
   ("do not use libextractor to add additional references to directory entries and/or the published file"),
   0, &GNUNET_getopt_configure_set_one, &do_no_direct_references},
  {'e', "extract", NULL,
   gettext_noop
   ("print list of extracted keywords that would be used, but do not perform upload"),
   0, &GNUNET_getopt_configure_set_one, &extract_only},
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Make files available to GNUnet for sharing.")),       /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  {'k', "key", "KEYWORD",
   gettext_noop
   ("add an additional keyword for the top-level file or directory"
    " (this option can be specified multiple times)"),
   1, &GNUNET_ECRS_getopt_configure_set_keywords, &topKeywords},
  {'K', "global-key", "KEYWORD",
   gettext_noop ("add an additional keyword for all files and directories"
                 " (this option can be specified multiple times)"),
   1, &GNUNET_ECRS_getopt_configure_set_keywords, &gloKeywords},
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'m', "meta", "TYPE:VALUE",
   gettext_noop ("set the meta-data for the given TYPE to the given VALUE"),
   1, &GNUNET_ECRS_getopt_configure_set_metadata, &meta},
  {'n', "noindex", NULL,
   gettext_noop ("do not index, perform full insertion (stores entire "
                 "file in encrypted form in GNUnet database)"),
   0, &GNUNET_getopt_configure_set_one, &do_insert},
  {'N', "next", "ID",
   gettext_noop
   ("specify ID of an updated version to be published in the future"
    " (for namespace insertions only)"),
   1, &GNUNET_getopt_configure_set_string, &next_id},
  {'p', "priority", "PRIORITY",
   gettext_noop ("specify the priority of the content"),
   1, &GNUNET_getopt_configure_set_uint, &priority},
  {'P', "pseudonym", "NAME",
   gettext_noop
   ("publish the files under the pseudonym NAME (place file into namespace)"),
   1, &GNUNET_getopt_configure_set_string, &pseudonym},
  {'s', "simulate-only", NULL,
   gettext_noop ("only simulte the process but do not do any "
                 "actual publishing (useful to compute URIs)"),
   0, &GNUNET_getopt_configure_set_one, &do_simulate},
  {'t', "this", "ID",
   gettext_noop ("set the ID of this version of the publication"
                 " (for namespace insertions only)"),
   1, &GNUNET_getopt_configure_set_string, &this_id},
  {'u', "uri", "URI",
   gettext_noop ("URI to be published (can be used instead of passing a "
                 "file to add keywords to the file with the respective URI)"),
   1, &GNUNET_getopt_configure_set_string, &uri_string},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

/**
 * The main function to insert files into GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return 0 for ok, -1 on error
 */
int
main (int argc, char *const *argv)
{
  const char *filename;
  int i;
  char *tmp;
  unsigned long long verbose;
  GNUNET_HashCode pid;

  meta = GNUNET_meta_data_create ();
  i = GNUNET_init (argc,
                   argv,
                   "gnunet-insert [OPTIONS] FILENAME",
                   &cfgFilename, gnunetinsertOptions, &ectx, &cfg);
  if (i == -1)
    {
      errorCode = -1;
      goto quit;
    }
  if (((uri_string == NULL) || (extract_only)) && (i != argc - 1))
    {
      printf (_
              ("You must specify one and only one filename for insertion.\n"));
      errorCode = -1;
      goto quit;
    }
  if ((uri_string != NULL) && (i != argc))
    {
      printf (_("You must NOT specify an URI and a filename.\n"));
      errorCode = -1;
      goto quit;
    }
  if ((uri_string != NULL) && (extract_only))
    {
      printf (_("Cannot extract metadata from a URI!\n"));
      errorCode = -1;
      goto quit;
    }
  if (uri_string == NULL)
    filename = argv[i];
  else
    filename = NULL;

  if (extract_only)
    {
      EXTRACTOR_ExtractorList *l;
      char *ex;
      char *dirname;
      char *fname;

      l = EXTRACTOR_loadDefaultLibraries ();
      ex = NULL;
      GNUNET_GC_get_configuration_value_string (cfg, "FS", "EXTRACTORS", "",
                                                &ex);
      if (strlen (ex) > 0)
        l = EXTRACTOR_loadConfigLibraries (l, ex);
      GNUNET_free (ex);
      dirname = GNUNET_expand_file_name (ectx, filename);
      GNUNET_GE_ASSERT (ectx, dirname != NULL);
      while ((strlen (dirname) > 0) &&
             (dirname[strlen (dirname) - 1] == DIR_SEPARATOR))
        dirname[strlen (dirname) - 1] = '\0';
      fname = dirname;
      while (strstr (fname, DIR_SEPARATOR_STR) != NULL)
        fname = strstr (fname, DIR_SEPARATOR_STR) + 1;
      GNUNET_GE_ASSERT (ectx, fname != dirname);
      fname[-1] = '\0';
      listKeywords (fname, dirname, l);
      GNUNET_free (dirname);
      EXTRACTOR_removeAll (l);
      GNUNET_meta_data_destroy (meta);
      meta = NULL;

      errorCode = 0;
      goto quit;
    }


  GNUNET_GC_get_configuration_value_number (cfg,
                                            "GNUNET",
                                            "VERBOSE", 0, 9999, 0, &verbose);
  /* check arguments */
  if (pseudonym != NULL)
    {
      if ((GNUNET_OK !=
           GNUNET_pseudonym_name_to_id (ectx, cfg,
                                        pseudonym, &pid)) ||
          (GNUNET_OK != GNUNET_ECRS_namespace_test_exists (ectx, cfg, &pid)))
        {
          printf (_("Could not access namespace `%s' (does not exist?).\n"),
                  pseudonym);
          errorCode = -1;
          goto quit;
        }
    }
  else
    {                           /* ordinary insertion checks */
      if (NULL != next_id)
        {
          fprintf (stderr,
                   _("Option `%s' makes no sense without option `%s'.\n"),
                   "-N", "-P");
          errorCode = -1;
          goto quit;
        }
      if (NULL != this_id)
        {
          fprintf (stderr,
                   _("Option `%s' makes no sense without option `%s'.\n"),
                   "-t", "-P");
          errorCode = -1;
          goto quit;
        }
    }

  if (uri_string != NULL)
    {
      struct GNUNET_ECRS_URI *us
        = GNUNET_ECRS_string_to_uri (ectx, uri_string);
      if (us == NULL)
        {
          errorCode = -1;
          goto quit;
        }
      postProcess (us);
      if (gloKeywords != NULL)
        GNUNET_ECRS_publish_under_keyword (ectx,
                                           cfg,
                                           gloKeywords,
                                           anonymity,
                                           priority,
                                           start_time + 2 * GNUNET_CRON_YEARS,
                                           us, meta);
      if (topKeywords != NULL)
        GNUNET_ECRS_publish_under_keyword (ectx,
                                           cfg,
                                           topKeywords,
                                           anonymity,
                                           priority,
                                           start_time + 2 * GNUNET_CRON_YEARS,
                                           us, meta);
      GNUNET_ECRS_uri_destroy (us);
      goto quit;
    }

  /* fundamental init */
  ctx = GNUNET_FSUI_start (ectx, cfg, "gnunet-insert", GNUNET_NO, 32,   /* make configurable */
                           &printstatus, &verbose);

  /* first insert all of the top-level files or directories */
  tmp = GNUNET_expand_file_name (ectx, filename);
  if (!do_disable_creation_time)
    GNUNET_meta_data_add_publication_date (meta);
  start_time = GNUNET_get_time ();
  errorCode = 1;
  ul = GNUNET_FSUI_upload_start (ctx,
                                 tmp,
                                 (GNUNET_FSUI_DirectoryScanCallback) &
                                 GNUNET_disk_directory_scan, ectx, anonymity,
                                 priority,
                                 do_simulate ? GNUNET_SYSERR : (!do_insert),
                                 GNUNET_YES, !do_no_direct_references,
                                 start_time + 2 * GNUNET_CRON_YEARS, meta,
                                 gloKeywords, topKeywords);
  GNUNET_free (tmp);
  if (ul != NULL)
    {
      GNUNET_shutdown_wait_for ();
      if (errorCode == 1)
        GNUNET_FSUI_upload_abort (ul);
      GNUNET_FSUI_upload_stop (ul);
    }
  GNUNET_FSUI_stop (ctx);
quit:
  if (meta != NULL)
    GNUNET_meta_data_destroy (meta);
  if (gloKeywords != NULL)
    GNUNET_ECRS_uri_destroy (gloKeywords);
  if (topKeywords != NULL)
    GNUNET_ECRS_uri_destroy (topKeywords);
  GNUNET_fini (ectx, cfg);
  return errorCode;
}

/* end of gnunet-insert.c */
