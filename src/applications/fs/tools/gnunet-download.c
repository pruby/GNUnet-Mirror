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
#include "gnunet_util.h"

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_GC_Configuration *cfg;

static unsigned long long verbose;

static int do_recursive;

static int do_directory;

static int do_delete_incomplete;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static char *filename;

static unsigned int anonymity = 1;

static unsigned int parallelism = 32;

static GNUNET_CronTime start_time;

static struct GNUNET_FSUI_DownloadList *dl;

#define EC_ARGUMENTS -1
#define EC_COMPLETED 0
#define EC_INCOMPLETE 1
#define EC_ABORTED 2
#define EC_DOWNLOAD_ERROR 3

static int errorCode;

static unsigned int downloads_running;

static struct GNUNET_FSUI_DownloadList **downloads;

static unsigned int downloads_size;

static struct GNUNET_Mutex *lock;

/**
 * All gnunet-download command line options
 */
static struct GNUNET_CommandLineOption gnunetdownloadOptions[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of sender-anonymity"),
   1, &GNUNET_getopt_configure_set_uint, &anonymity},
  GNUNET_COMMAND_LINE_OPTION_CFG_FILE (&cfgFilename),   /* -c */
  {'d', "directory", NULL,
   gettext_noop
   ("download a GNUnet directory that has already been downloaded.  Requires that a filename of an existing file is specified instead of the URI.  The download will only download the top-level files in the directory unless the `-R' option is also specified."),
   0, &GNUNET_getopt_configure_set_one, &do_directory},
  {'D', "delete-incomplete", NULL,
   gettext_noop ("delete incomplete downloads (when aborted with CTRL-C)"),
   0, &GNUNET_getopt_configure_set_one, &do_delete_incomplete},
  GNUNET_COMMAND_LINE_OPTION_HELP (gettext_noop ("Download files from GNUnet.")),       /* -h */
  GNUNET_COMMAND_LINE_OPTION_HOSTNAME,  /* -H */
  GNUNET_COMMAND_LINE_OPTION_LOGGING,   /* -L */
  {'o', "output", "FILENAME",
   gettext_noop ("write the file to FILENAME"),
   1, &GNUNET_getopt_configure_set_string, &filename},
  {'p', "parallelism", "DOWNLOADS",
   gettext_noop
   ("set the maximum number of parallel downloads that are allowed"),
   1, &GNUNET_getopt_configure_set_uint, &parallelism},
  {'R', "recursive", NULL,
   gettext_noop ("download a GNUnet directory recursively"),
   0, &GNUNET_getopt_configure_set_one, &do_recursive},
  GNUNET_COMMAND_LINE_OPTION_VERSION (PACKAGE_VERSION), /* -v */
  GNUNET_COMMAND_LINE_OPTION_VERBOSE,
  GNUNET_COMMAND_LINE_OPTION_END,
};

/**
 * This method is called whenever data is received.
 * The current incarnation just ensures that the main
 * method exits once the download is complete.
 */
static void *
progressModel (void *unused, const GNUNET_FSUI_Event * event)
{
  GNUNET_mutex_lock (lock);
  switch (event->type)
    {
    case GNUNET_FSUI_download_progress:
      if (verbose)
        {
          PRINTF (_("Download of file `%s' at "
                    "%16llu out of %16llu bytes (%8.3f KiB/s)\n"),
                  event->data.DownloadProgress.filename,
                  event->data.DownloadProgress.completed,
                  event->data.DownloadProgress.total,
                  (event->data.DownloadProgress.completed / 1024.0) /
                  (((double) (GNUNET_get_time () - (start_time - 1)))
                   / (double) GNUNET_CRON_SECONDS));
        }
      break;
    case GNUNET_FSUI_download_aborted:
      if (dl == event->data.DownloadError.dc.pos)
        {
          /* top-download aborted */
          printf (_("Download aborted.\n"));
          errorCode = EC_ABORTED;
          GNUNET_shutdown_initiate ();
        }
      break;
    case GNUNET_FSUI_download_error:
      printf (_("Error downloading: %s\n"),
              event->data.DownloadError.message);
      errorCode = EC_DOWNLOAD_ERROR;
      GNUNET_shutdown_initiate ();
      break;
    case GNUNET_FSUI_download_completed:
      PRINTF (_("Download of file `%s' complete.  "
                "Speed was %8.3f KiB per second.\n"),
              event->data.DownloadCompleted.filename,
              (event->data.DownloadCompleted.total / 1024.0) /
              (((double) (GNUNET_get_time () - (start_time - 1)))
               / (double) GNUNET_CRON_SECONDS));
      downloads_running--;
      if (downloads_running == 0)
        {
          errorCode = 0;
          GNUNET_shutdown_initiate ();
        }
      break;
    case GNUNET_FSUI_download_started:
      downloads_running++;
      GNUNET_array_append (downloads, downloads_size,
                           event->data.DownloadStarted.dc.pos);
    case GNUNET_FSUI_download_stopped:
      break;
    default:
      GNUNET_GE_BREAK (ectx, 0);
      break;
    }
  GNUNET_mutex_unlock (lock);
  return NULL;
}

static int
directoryIterator (const GNUNET_ECRS_FileInfo * fi,
                   const GNUNET_HashCode * key, int isRoot, void *cls)
{
  struct GNUNET_FSUI_Context *ctx = cls;
  struct GNUNET_MetaData *meta;
  char *fn;
  char *f;

  f = GNUNET_meta_data_get_first_by_types (fi->meta,
                                           EXTRACTOR_FILENAME,
                                           EXTRACTOR_TITLE,
                                           EXTRACTOR_ARTIST,
                                           EXTRACTOR_AUTHOR,
                                           EXTRACTOR_PUBLISHER,
                                           EXTRACTOR_CREATOR,
                                           EXTRACTOR_PRODUCER,
                                           EXTRACTOR_UNKNOWN, -1);
  if (f == NULL)
    f = GNUNET_strdup (_("no name given"));
  fn = GNUNET_malloc (strlen (filename) + strlen (f) + 4);
  strcpy (fn, filename);
  strcat (fn, "/");
  strcat (fn, f);
  if (verbose > 1)
    printf (_("Starting download `%s'\n"), f);
  GNUNET_free (f);
  meta = GNUNET_meta_data_create ();
  GNUNET_FSUI_download_start (ctx,
                              anonymity, do_recursive, fi->uri, meta, fn,
                              NULL, NULL);
  GNUNET_meta_data_destroy (meta);
  GNUNET_free (fn);
  return GNUNET_OK;
}


/**
 * Main function to download files from GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return value from download file: 0: ok, -1, 1: error
 */
int
main (int argc, char *const *argv)
{
  int ok;
  int try_rename;
  struct GNUNET_FSUI_Context *ctx;
  struct GNUNET_ECRS_URI *uri;
  struct GNUNET_MetaData *meta;
  int i;

  i = GNUNET_init (argc,
                   argv,
                   "gnunet-download [OPTIONS] URI",
                   &cfgFilename, gnunetdownloadOptions, &ectx, &cfg);
  if (i == -1)
    {
      errorCode = EC_ARGUMENTS;
      goto quit;
    }
  if (i == argc)
    {
      GNUNET_GE_LOG (ectx,
                     GNUNET_GE_WARNING | GNUNET_GE_BULK | GNUNET_GE_USER,
                     _("Not enough arguments. "
                       "You must specify a GNUnet file URI\n"));
      errorCode = EC_ARGUMENTS;
      goto quit;
    }
  GNUNET_GC_get_configuration_value_number (cfg,
                                            "GNUNET",
                                            "VERBOSE", 0, 9999, 0, &verbose);
  uri = NULL;
  if (!do_directory)
    {
      uri = GNUNET_ECRS_string_to_uri (ectx, argv[i]);
      if ((NULL == uri) ||
          (!(GNUNET_ECRS_uri_test_loc (uri)
             || GNUNET_ECRS_uri_test_chk (uri))))
        {
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_BULK | GNUNET_GE_USER,
                         _("URI `%s' invalid for gnunet-download.\n"),
                         argv[i]);
          errorCode = EC_ARGUMENTS;
          goto quit;
        }
    }

  try_rename = GNUNET_NO;
  if (filename == NULL)
    {
      if (do_directory)
        {
          if (NULL != strstr (argv[i], GNUNET_DIRECTORY_EXT))
            {
              filename = GNUNET_strdup (argv[i]);
              strstr (filename, GNUNET_DIRECTORY_EXT)[0] = '\0';
            }
          else
            {
              filename =
                GNUNET_malloc (strlen (argv[i]) +
                               strlen (GNUNET_DIRECTORY_EXT) + 2);
              strcpy (filename, argv[i]);
              strcat (filename, DIR_SEPARATOR_STR);
              strcat (filename, GNUNET_DIRECTORY_EXT);
            }
          try_rename = GNUNET_NO;
        }
      else
        {
          GNUNET_GE_ASSERT (ectx,
                            strlen (argv[i]) >
                            strlen (GNUNET_ECRS_URI_PREFIX) +
                            strlen (GNUNET_ECRS_FILE_INFIX));
          filename =
            GNUNET_expand_file_name (ectx,
                                     &argv[i][strlen (GNUNET_ECRS_URI_PREFIX)
                                              +
                                              strlen
                                              (GNUNET_ECRS_FILE_INFIX)]);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_DEBUG | GNUNET_GE_REQUEST | GNUNET_GE_USER,
                         _
                         ("No filename specified, using `%s' instead (for now).\n"),
                         filename);
          try_rename = GNUNET_YES;
        }
    }
  ok = GNUNET_NO;
  lock = GNUNET_mutex_create (GNUNET_NO);
  ctx = GNUNET_FSUI_start (ectx,
                           cfg,
                           "gnunet-download",
                           parallelism == 0 ? 1 : parallelism,
                           GNUNET_NO, &progressModel, NULL);
  start_time = GNUNET_get_time ();
  errorCode = EC_INCOMPLETE;
  if (do_directory)
    {
      void *data;
      struct stat sbuf;
      int fd;
      int count;
      char *efn;

      fd = -1;
      efn = GNUNET_expand_file_name (ectx, argv[i]);
      data = NULL;
      if ((0 != STAT (efn,
                      &sbuf)) ||
          (!S_ISREG (sbuf.st_mode)) ||
          (0 != ACCESS (efn,
                        R_OK)) ||
          (-1 == (fd = GNUNET_disk_file_open (ectx,
                                              efn,
                                              O_LARGEFILE | O_RDONLY))) ||
          (MAP_FAILED == (data = MMAP (NULL,
                                       sbuf.st_size,
                                       PROT_READ, MAP_SHARED, fd, 0))))
        {
          if (fd != -1)
            CLOSE (fd);
          GNUNET_GE_LOG (ectx,
                         GNUNET_GE_ERROR | GNUNET_GE_IMMEDIATE |
                         GNUNET_GE_USER,
                         _("Could not access gnunet-directory file `%s'\n"),
                         efn);
          GNUNET_FSUI_stop (ctx);
          GNUNET_mutex_destroy (lock);
          GNUNET_free (efn);
          goto quit;
        }
      meta = GNUNET_meta_data_create ();
      count = GNUNET_ECRS_directory_list_contents (ectx,
                                                   data,
                                                   sbuf.st_size,
                                                   NULL,
                                                   &meta, &directoryIterator,
                                                   ctx);
      GNUNET_meta_data_destroy (meta);
      MUNMAP (data, sbuf.st_size);
      CLOSE (fd);
      GNUNET_free (efn);
      if (verbose > 0)
        {
          if (count > 0)
            printf (_("Downloading %d files from directory `%s'.\n"),
                    count, argv[i]);
          else
            printf (_("Did not find any files in directory `%s'\n"), argv[i]);
        }
    }
  else
    {
      meta = GNUNET_meta_data_create ();
      dl = GNUNET_FSUI_download_start (ctx,
                                       anonymity,
                                       do_recursive, uri, meta, filename,
                                       NULL, NULL);
      GNUNET_meta_data_destroy (meta);
      if (dl == NULL)
        {
          GNUNET_FSUI_stop (ctx);
          GNUNET_mutex_destroy (lock);
          goto quit;
        }
    }
  GNUNET_shutdown_wait_for ();
  if (do_delete_incomplete)
    {
      for (i = 0; i < downloads_size; i++)
        GNUNET_FSUI_download_abort (downloads[i]);
    }
  for (i = 0; i < downloads_size; i++)
    GNUNET_FSUI_download_stop (downloads[i]);
  GNUNET_array_grow (downloads, downloads_size, 0);
  GNUNET_FSUI_stop (ctx);
  GNUNET_mutex_destroy (lock);

  if ((errorCode == EC_COMPLETED) &&
      (dl != NULL) && (try_rename == GNUNET_YES))
    {
      char *newname = GNUNET_ECRS_suggest_better_filename (ectx,
                                                           filename);

      if (newname != NULL)
        {
          fprintf (stdout, _("File stored as `%s'.\n"), newname);
          GNUNET_free (newname);
        }
    }
  GNUNET_free (filename);
  if (uri != NULL)
    GNUNET_ECRS_uri_destroy (uri);
quit:
  GNUNET_fini (ectx, cfg);
  return errorCode;
}

/* end of gnunet-download.c */
