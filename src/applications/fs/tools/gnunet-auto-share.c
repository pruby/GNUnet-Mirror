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
#include "gnunet_fs_lib.h"
#include "gnunet_fsui_lib.h"
#include "gnunet_util.h"
#include <extractor.h>

struct FileRecord
{
  struct FileRecord *next;
  char *filename;
  time_t mtime;
  time_t last_seen;
  off_t size;
  GNUNET_HashCode hc;
};

static int upload_done;

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_GC_Configuration *meta_cfg;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_FSUI_Context *ctx;

static struct GNUNET_FSUI_UploadList *ul;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static struct GNUNET_ECRS_URI *gloKeywords;

static struct GNUNET_ClientServerConnection *sock;

static unsigned int anonymity = 1;

static unsigned int priority = 365;

static int do_no_direct_references;

static struct FileRecord *records;

static int debug_flag;

static FILE *myout;

#ifdef MINGW
/**
 * Windows service information
 */
static SERVICE_STATUS theServiceStatus;
static SERVICE_STATUS_HANDLE hService;
#endif

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
          fprintf (myout,
                   _("Upload of `%s' complete, URI is `%s'.\n"),
                   event->data.UploadCompleted.filename, fstring);
          fflush (myout);
          GNUNET_free (fstring);
        }
      if (ul == event->data.UploadCompleted.uc.pos)
        upload_done = GNUNET_YES;
      break;
    case GNUNET_FSUI_upload_aborted:
      fprintf (myout, _("\nUpload aborted.\n"));
      fflush (myout);
      upload_done = GNUNET_YES;
      break;
    case GNUNET_FSUI_upload_error:
      fprintf (myout,
               _("\nError uploading file: %s"),
               event->data.UploadError.message);
      fflush (myout);
      upload_done = GNUNET_YES;
      break;
    case GNUNET_FSUI_upload_started:
    case GNUNET_FSUI_upload_stopped:
    case GNUNET_FSUI_upload_suspended:
    case GNUNET_FSUI_upload_resumed:
      break;
    default:
      fprintf (myout, _("\nUnexpected event: %d\n"), event->type);
      fflush (myout);
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
  {'d', "debug", NULL,
   gettext_noop ("run in debug mode; gnunet-auto-share will "
                 "not daemonize and error messages will "
                 "be written to stderr instead of a logfile"),
   0, &GNUNET_getopt_configure_set_one, &debug_flag},
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

static struct FileRecord *
find_entry (const char *filename)
{
  struct FileRecord *pos = records;
  while ((pos != NULL) && (0 != strcmp (filename, pos->filename)))
    pos = pos->next;
  return pos;
}

static int
test_run (const char *filename, const char *dirName, void *cls)
{
  GNUNET_HashCode hc;
  int *run = cls;
  struct FileRecord *rec;
  struct stat buf;
  char *fn;

  if (filename[0] == '.')
    return GNUNET_OK;
  if (ul != NULL)
    return GNUNET_SYSERR;
  fn = GNUNET_malloc (strlen (filename) + strlen (dirName) + 1);
  strcpy (fn, dirName);
  strcat (fn, filename);
  if (0 != stat (fn, &buf))
    {
      fprintf (myout, "Could not stat `%s': %s\n", fn, strerror (errno));
      fflush (myout);
      GNUNET_free (fn);
      return GNUNET_OK;
    }
  rec = find_entry (filename);
  if (rec == NULL)
    {
      rec = GNUNET_malloc (sizeof (struct FileRecord));
      rec->next = records;
      rec->filename = fn;
      rec->mtime = buf.st_mtime;
      rec->size = buf.st_size;
      rec->last_seen = time (NULL);
      GNUNET_hash_file (NULL, fn, &rec->hc);
      rec->next = records;
      records = rec;
      if (GNUNET_NO == GNUNET_FS_test_indexed (sock, &rec->hc))
        {
          *run = 1;
          return GNUNET_SYSERR;
        }
    }
  else
    {
      rec->last_seen = time (NULL);
    }
  if ((rec->mtime != buf.st_mtime) || (rec->size != buf.st_size))
    {
      GNUNET_hash_file (NULL, fn, &hc);
      if (0 != memcmp (&hc, &rec->hc, sizeof (GNUNET_HashCode)))
        *run = 1;
      rec->mtime = buf.st_mtime;
      rec->size = buf.st_size;
      rec->hc = hc;
    }
  if (S_ISDIR (buf.st_mode))
    GNUNET_disk_directory_scan (ectx, fn, &test_run, run);
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
    return 0;
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
      return 0;
    }
  value = NULL;
  GNUNET_GC_get_configuration_value_string (cfg,
                                            section, option, NULL, &value);
  if (value != NULL)
    {
      GNUNET_ECRS_meta_data_insert (amc->meta, type, value);
      GNUNET_free (value);
    }
  return 0;
}


static int
probe_directory (const char *filename, const char *dirName, void *unused)
{
  struct stat buf;
  struct AddMetadataClosure amc;
  struct GNUNET_ECRS_URI *kuri;
  char *fn;
  char *keys;
  int run;

  if (filename[0] == '.')
    return GNUNET_OK;
  if (ul != NULL)
    return GNUNET_SYSERR;
  fn = GNUNET_malloc (strlen (filename) + strlen (dirName) + 1);
  strcpy (fn, dirName);
  strcat (fn, filename);
  if (0 != stat (fn, &buf))
    {
      fprintf (myout, "Could not stat `%s': %s\n", fn, strerror (errno));
      fflush (myout);
      GNUNET_free (fn);
      return GNUNET_OK;
    }
  run = 0;
  if (S_ISDIR (buf.st_mode))
    GNUNET_disk_directory_scan (ectx, fn, &test_run, &run);
  else
    test_run (filename, dirName, &run);
  if (0 == run)
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
  keys = GNUNET_ECRS_meta_data_get_by_type (amc.meta, EXTRACTOR_KEYWORDS);
  if (keys != NULL)
    kuri = GNUNET_ECRS_keyword_string_to_uri (NULL, keys);
  else
    kuri = NULL;
  GNUNET_ECRS_meta_data_delete (amc.meta, EXTRACTOR_KEYWORDS, keys);
  GNUNET_free_non_null (keys);
  ul = GNUNET_FSUI_upload_start (ctx,
                                 fn,
                                 (GNUNET_FSUI_DirectoryScanCallback) &
                                 GNUNET_disk_directory_scan, ectx, anonymity,
                                 priority, GNUNET_YES, GNUNET_YES,
                                 !do_no_direct_references,
                                 GNUNET_get_time () + 2 * GNUNET_CRON_YEARS,
                                 amc.meta, gloKeywords, kuri);
  if (kuri != NULL)
    GNUNET_ECRS_uri_destroy (kuri);
  GNUNET_ECRS_meta_data_destroy (amc.meta);
  GNUNET_free (fn);
  return GNUNET_SYSERR;
}


/**
 * Actual main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return return 0 for ok, -1 on error
 */
int
auto_share_main (const char *dirname)
{
  int errorCode;
  unsigned long long verbose;
  GNUNET_CronTime delay;
  char *metafn;
  struct FileRecord *pos;
  int filedes[2];               /* pipe between client and parent */

  errorCode = 0;
  if ((GNUNET_NO == debug_flag)
      && (GNUNET_OK != GNUNET_terminal_detach (ectx, cfg, filedes)))
    return GNUNET_SYSERR;
  sock = GNUNET_client_connection_create (ectx, cfg);
  if (sock == NULL)
    {
      fprintf (myout, _("Failed to connect to gnunetd.\n"));
      fflush (myout);
      errorCode = -1;
      if (GNUNET_NO == debug_flag)
        GNUNET_terminal_detach_complete (ectx, filedes, GNUNET_NO);
      goto quit;
    }
  GNUNET_GC_get_configuration_value_number (cfg,
                                            "GNUNET",
                                            "VERBOSE", 0, 9999, 0, &verbose);
  metafn = NULL;
  GNUNET_GC_get_configuration_value_filename (cfg,
                                              "GNUNET-AUTO-SHARE",
                                              "METADATA",
                                              GNUNET_DEFAULT_HOME_DIRECTORY
                                              "/metadata.conf", &metafn);
  meta_cfg = GNUNET_GC_create ();
  if (GNUNET_YES == GNUNET_disk_file_test (NULL, metafn))
    GNUNET_GC_parse_configuration (meta_cfg, metafn);
  if (GNUNET_NO == debug_flag)
    GNUNET_terminal_detach_complete (ectx, filedes, GNUNET_YES);
  GNUNET_free (metafn);
  /* fundamental init */
  ctx = GNUNET_FSUI_start (ectx, cfg, "gnunet-auto-share", GNUNET_NO, 32,
                           &printstatus, &verbose);
  /* first insert all of the top-level files or directories */
  delay = 5 * GNUNET_CRON_SECONDS;
  while (GNUNET_NO == GNUNET_shutdown_test ())
    {
      GNUNET_thread_sleep (250 * GNUNET_CRON_MILLISECONDS);
      GNUNET_disk_directory_scan (ectx, dirname, &probe_directory, NULL);
      if (GNUNET_YES == upload_done)
        {
          GNUNET_FSUI_upload_abort (ul);
          GNUNET_FSUI_upload_stop (ul);
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
        {
          delay = 5 * GNUNET_CRON_SECONDS;
        }
    }
  GNUNET_FSUI_stop (ctx);
  if (gloKeywords != NULL)
    GNUNET_ECRS_uri_destroy (gloKeywords);
quit:
  while (records != NULL)
    {
      pos = records;
      records = pos->next;
      GNUNET_free (pos->filename);
      GNUNET_free (pos);
    }
  if (meta_cfg != NULL)
    GNUNET_GC_free (meta_cfg);
  if (sock != NULL)
    GNUNET_client_connection_destroy (sock);
  return errorCode;
}

void
auto_share_shutdown_initiate ()
{
  // FIXME
}

/**
 * Shutdown gnunetd
 * @param cfg configuration, may be NULL if in service mode
 * @param sig signal code that causes shutdown, optional
 */
void
auto_share_shutdown_request (struct GNUNET_GC_Configuration *cfg, int sig)
{
#ifdef MINGW
  if (!cfg || GNUNET_GC_get_configuration_value_yesno (cfg,
                                                       "GNUNET-AUTO-SHARE",
                                                       "WINSERVICE",
                                                       GNUNET_NO) ==
      GNUNET_YES)
    {
      /* If GNUnet runs as service, only the
         Service Control Manager is allowed
         to kill us. */
      if (sig != SERVICE_CONTROL_STOP)
        {
          SERVICE_STATUS theStat;

          /* Init proper shutdown through the SCM */
          if (GNControlService (hService, SERVICE_CONTROL_STOP, &theStat))
            {
              /* Success */

              /* The Service Control Manager will call
                 gnunetd.c::ServiceCtrlHandler(), which calls
                 this function again. We then stop the gnunetd. */
              return;
            }
          /* We weren't able to tell the SCM to stop the service,
             but we don't care.
             Just shut the gnunetd process down. */
        }

      /* Acknowledge the shutdown request */
      theServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
      GNSetServiceStatus (hService, &theServiceStatus);
    }
#endif

  auto_share_shutdown_initiate ();
}

#ifdef MINGW
/**
 * This function is called from the Windows Service Control Manager
 * when a service has to shutdown
 */
static void WINAPI
ServiceCtrlHandler (DWORD dwOpcode)
{
  if (dwOpcode == SERVICE_CONTROL_STOP)
    auto_share_shutdown_request (NULL, dwOpcode);
}

/**
 * called by gnunetd.c::ServiceMain()
 */
void
ServiceMain (DWORD argc, LPSTR * argv)
{
  memset (&theServiceStatus, 0, sizeof (theServiceStatus));
  theServiceStatus.dwServiceType = SERVICE_WIN32;
  theServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
  theServiceStatus.dwCurrentState = SERVICE_RUNNING;

  hService =
    GNRegisterServiceCtrlHandler ("GNUnet Auto Share", ServiceCtrlHandler);
  if (!hService)
    return;

  GNSetServiceStatus (hService, &theServiceStatus);

  // FIXME
  auto_share_main ("FIXME");

  theServiceStatus.dwCurrentState = SERVICE_STOPPED;
  GNSetServiceStatus (hService, &theServiceStatus);
}
#endif


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
  int i;
  int errorCode;
  char *log_file_name;
  char *dirname;

  errorCode = 0;
  myout = stdout;
  i = GNUNET_init (argc,
                   argv,
                   "gnunet-auto-share [OPTIONS] DIRECTORY",
                   &cfgFilename, gnunetauto_shareOptions, &ectx, &cfg);
  if (i == -1)
    {
      errorCode = -1;
      goto end;
    }
  if (i != argc - 1)
    {
      fprintf (stderr,
               _
               ("You must specify one and only one directory for sharing.\n"));
      errorCode = -1;
      goto end;
    }
  if (GNUNET_YES != debug_flag)
    {
      GNUNET_GC_get_configuration_value_filename (cfg,
                                                  "GNUNET-AUTO-SHARE",
                                                  "LOGFILE",
                                                  GNUNET_DEFAULT_HOME_DIRECTORY
                                                  "/gnunet-auto-share.log",
                                                  &log_file_name);
      myout = fopen (log_file_name, "a");
      if (myout == NULL)
        {
          fprintf (stderr,
                   "Could not open logfile `%s': %s\n",
                   log_file_name, strerror (errno));
          GNUNET_free (log_file_name);
          errorCode = -1;
          goto end;
        }
      GNUNET_free (log_file_name);

      GNUNET_GC_get_configuration_value_filename (cfg,
                                                  "GNUNET",
                                                  "GNUNET_HOME",
                                                  GNUNET_DEFAULT_HOME_DIRECTORY,
                                                  &log_file_name);
      log_file_name =
        GNUNET_realloc (log_file_name, strlen (log_file_name) + 30);
      strcat (log_file_name, "gnunet-auto-share.pid");
      GNUNET_GC_set_configuration_value_string (cfg,
                                                NULL,
                                                "GNUNETD",
                                                "PIDFILE", log_file_name);
      GNUNET_free (log_file_name);
    }
#ifdef MINGW
  if (GNUNET_GC_get_configuration_value_yesno (cfg,
                                               "GNUNET-AUTO-SHARE",
                                               "WINSERVICE",
                                               GNUNET_NO) == GNUNET_YES)
    {
      SERVICE_TABLE_ENTRY DispatchTable[] =
        { {"gnunet-auto-share", ServiceMain}
      , {NULL, NULL}
      };
      errorCode = (GNStartServiceCtrlDispatcher (DispatchTable) != 0);
    }
  else
#endif
    {
      dirname = GNUNET_expand_file_name (ectx, argv[i]);
      errorCode = auto_share_main (dirname);
      GNUNET_free (dirname);
    }
end:
  GNUNET_fini (ectx, cfg);
  if (myout != stdout)
    fclose (myout);
  return errorCode;
}

/* end of gnunet-auto-share.c */
