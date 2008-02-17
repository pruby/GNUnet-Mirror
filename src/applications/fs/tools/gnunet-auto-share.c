/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/tools/gnunet-auto-share.c
 * @brief Tool to share directories
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_directories.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util.h"
#include <extractor.h>

static int upload_done;

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_GC_Configuration *meta_cfg;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_FSUI_Context *ctx;

static struct GNUNET_FSUI_UploadList *ul;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static struct GNUNET_ECRS_URI *gloKeywords;

static unsigned int anonymity = 1;

static unsigned int priority = 365;

static int do_no_direct_references;

/**
 * Print progess message.
 */
static void *
printstatus (void *ctx, const GNUNET_FSUI_Event * event)
{
  unsigned long long *verboselevel = ctx;
  char *fstring;

  switch (event->type)
    {
    case GNUNET_FSUI_upload_progress:
      break;
    case GNUNET_FSUI_upload_completed:
      if (*verboselevel)
        {
          fstring =
            GNUNET_ECRS_uri_to_string (event->data.UploadCompleted.uri);
          printf (_("Upload of `%s' complete, URI is `%s'.\n"),
                  event->data.UploadCompleted.filename, fstring);
          GNUNET_free (fstring);
        }
      if (ul == event->data.UploadCompleted.uc.pos)
        upload_done = GNUNET_YES;
      break;
    case GNUNET_FSUI_upload_aborted:
      printf (_("\nUpload aborted.\n"));
      upload_done = GNUNET_YES;
      break;
    case GNUNET_FSUI_upload_error:
      printf (_("\nError uploading file: %s"),
              event->data.UploadError.message);
      upload_done = GNUNET_YES;
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
 * All gnunet-auto-share command line options
 */
static struct GNUNET_CommandLineOption gnunetauto_shareOptions[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of sender-anonymity"),
   1, &GNUNET_getopt_configure_set_uint, &anonymity},
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  {'D', "disable-direct", NULL,
   gettext_noop
   ("do not use libextractor to add additional references to directory entries and/or the published file"),
   0, &GNUNET_getopt_configure_set_one, &do_no_direct_references},
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Automatically share a directory.")),  /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  {'K', "global-key", "KEYWORD",
   gettext_noop ("add an additional keyword for all files and directories"
                 " (this option can be specified multiple times)"),
   1, &GNUNET_ECRS_getopt_configure_set_keywords, &gloKeywords},
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'p', "priority", "PRIORITY",
   gettext_noop ("specify the priority of the content"),
   1, &GNUNET_getopt_configure_set_uint, &priority},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

static int
find_latest (const char *filename, const char *dirName, void *cls)
{
  time_t *latest = cls;
  struct stat buf;
  char *fn;

  if (filename[0] == '.')
    return GNUNET_OK;
  if (ul != NULL)
    return GNUNET_SYSERR;
  fn = GNUNET_malloc (strlen (filename) + strlen (dirName) + 2);
  strcpy (fn, dirName);
  strcat (fn, DIR_SEPARATOR_STR);
  strcat (fn, filename);
  if (0 != stat (fn, &buf))
    {
      printf ("Could not stat `%s': %s\n", fn, strerror (errno));
      GNUNET_free (fn);
      return GNUNET_OK;
    }
  if (*latest < buf.st_mtime)
    *latest = buf.st_mtime;
  if (S_ISDIR (buf.st_mode))
    GNUNET_disk_directory_scan (ectx, fn, &find_latest, latest);
  GNUNET_free (fn);
  return GNUNET_OK;
}

struct AddMetadataClosure
{
  const char *filename;
  struct GNUNET_ECRS_MetaData *meta;
};


static int
add_meta_data (void *cls,
               struct GNUNET_GC_Configuration *cfg,
               struct GNUNET_GE_Context *ectx,
               const char *section, const char *option)
{
  struct AddMetadataClosure *amc = cls;
  EXTRACTOR_KeywordType type;
  EXTRACTOR_KeywordType max;
  char *value;

  if (0 != strcmp (amc->filename, section))
    return GNUNET_OK;
  max = EXTRACTOR_getHighestKeywordTypeNumber ();
  for (type = 0; type < max; type++)
    {
      if (0 == strcasecmp (option, EXTRACTOR_getKeywordTypeAsString (type)))
        break;
    }
  if (type == max)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_USER | GNUNET_GE_WARNING | GNUNET_GE_BULK,
                     _
                     ("Unknown keyword type `%s' in metadata configuration\n"),
                     option);
      return GNUNET_OK;
    }
  value = NULL;
  GNUNET_GC_get_configuration_value_string (cfg,
                                            section, option, NULL, &value);
  if (value != NULL)
    {
      GNUNET_ECRS_meta_data_insert (amc->meta, type, value);
      GNUNET_free (value);
    }
  return GNUNET_OK;
}


static int
probe_directory (const char *filename, const char *dirName, void *cls)
{
  time_t *last = cls;
  time_t latest;
  struct stat buf;
  struct AddMetadataClosure amc;
  char *fn;

  if (filename[0] == '.')
    return GNUNET_OK;
  if (ul != NULL)
    return GNUNET_SYSERR;
  fn = GNUNET_malloc (strlen (filename) + strlen (dirName) + 2);
  strcpy (fn, dirName);
  strcat (fn, DIR_SEPARATOR_STR);
  strcat (fn, filename);
  if (0 != stat (fn, &buf))
    {
      printf ("Could not stat `%s': %s\n", fn, strerror (errno));
      GNUNET_free (fn);
      return GNUNET_OK;
    }
  if ((buf.st_mtime < *last) && (!S_ISDIR (buf.st_mode)))
    {
      GNUNET_free (fn);
      return GNUNET_OK;
    }
  latest = buf.st_mtime;
  if (S_ISDIR (buf.st_mode))
    GNUNET_disk_directory_scan (ectx, fn, &find_latest, &latest);
  if (latest < *last)
    {
      GNUNET_free (fn);
      return GNUNET_OK;
    }
  amc.meta = GNUNET_ECRS_meta_data_create ();
  amc.filename = filename;
  /* attaching a listener will prompt iteration
     over all config values! */
  GNUNET_GC_attach_change_listener (meta_cfg, &add_meta_data, &amc);
  GNUNET_GC_detach_change_listener (meta_cfg, &add_meta_data, &amc);
  ul = GNUNET_FSUI_upload_start (ctx,
                                 fn,
                                 (GNUNET_FSUI_DirectoryScanCallback) &
                                 GNUNET_disk_directory_scan, ectx, anonymity,
                                 priority, GNUNET_YES, GNUNET_YES,
                                 !do_no_direct_references,
                                 GNUNET_get_time () + 2 * GNUNET_CRON_YEARS,
                                 amc.meta, gloKeywords, NULL);
  GNUNET_ECRS_meta_data_destroy (amc.meta);
  GNUNET_free (fn);
  return GNUNET_SYSERR;
}

/**
 * The main function to auto share directories with GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return 0 for ok, -1 on error
 */
int
main (int argc, char *const *argv)
{
  char *dirname;
  int i;
  int errorCode;
  unsigned long long verbose;
  time_t last;
  time_t start;
  GNUNET_CronTime delay;
  char *metafn;

  errorCode = 0;
  i = GNUNET_init (argc,
                   argv,
                   "gnunet-auto-share [OPTIONS] DIRECTORY",
                   &cfgFilename, gnunetauto_shareOptions, &ectx, &cfg);
  if (i == -1)
    {
      errorCode = -1;
      goto quit;
    }
  if (i != argc - 1)
    {
      printf (_
              ("You must specify one and only one directory for sharing.\n"));
      errorCode = -1;
      goto quit;
    }
  dirname = GNUNET_expand_file_name (ectx, argv[i]);
  GNUNET_GC_get_configuration_value_number (cfg,
                                            "GNUNET",
                                            "VERBOSE", 0, 9999, 0, &verbose);
  metafn = NULL;
  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "FS",
                                              "METADATA",
                                              GNUNET_DEFAULT_HOME_DIRECTORY
                                              "/metadata.conf", &metafn);
  meta_cfg = GNUNET_GC_create ();
  if (GNUNET_YES == GNUNET_disk_file_test (NULL, metafn))
    GNUNET_GC_parse_configuration (meta_cfg, metafn);
  /* fundamental init */
  ctx = GNUNET_FSUI_start (ectx, cfg, "gnunet-auto-share", GNUNET_NO, 32,
                           &printstatus, &verbose);
  /* first insert all of the top-level files or directories */

  last = 0;
  while (GNUNET_NO == GNUNET_shutdown_test ())
    {
      start = time (NULL);
      GNUNET_disk_directory_scan (ectx, dirname, &probe_directory, &last);
      if (ul == NULL)
        last = start;
      if (GNUNET_YES == upload_done)
        {
          GNUNET_FSUI_upload_abort (ctx, ul);
          GNUNET_FSUI_upload_stop (ctx, ul);
          upload_done = GNUNET_NO;
          ul = NULL;
        }
      if ((ul == NULL) && (GNUNET_NO == GNUNET_shutdown_test ()))
        {
          GNUNET_thread_sleep (delay);
          delay *= 2;
          if (delay > GNUNET_CRON_HOURS)
            delay = GNUNET_CRON_HOURS;
        }
      else
        delay = 5 * GNUNET_CRON_SECONDS;
    }
  GNUNET_FSUI_stop (ctx);
  if (gloKeywords != NULL)
    GNUNET_ECRS_uri_destroy (gloKeywords);
  GNUNET_free (dirname);
quit:
  if (meta_cfg != NULL)
    GNUNET_GC_free (meta_cfg);
  GNUNET_fini (ectx, cfg);
  return errorCode;
}

/* end of gnunet-auto-share.c */
