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

#define PIDFILE_DATA "GNUNET-AUTO-SHARE", "PIDFILE", GNUNET_DEFAULT_HOME_DIRECTORY DIR_SEPARATOR_STR "gnunet-auto-share.pid"

struct FileRecord
{
  struct FileRecord *next;
  char *filename;
  time_t mtime;
  time_t last_seen;
  off_t size;
  GNUNET_HashCode hc;
};

struct DirectoryRecord
{
  struct DirectoryRecord *next;

  struct FileRecord *records;

  char *dirname;

  int records_changed;

  int run;

};

static struct GNUNET_FSUI_UploadList *ul;

static struct GNUNET_ClientServerConnection *sock;

static struct GNUNET_GC_Configuration *meta_cfg;

static int upload_done;

static struct GNUNET_GC_Configuration *cfg;

static struct GNUNET_GE_Context *ectx;

static struct GNUNET_FSUI_Context *ctx;

static char *cfgFilename = GNUNET_DEFAULT_CLIENT_CONFIG_FILE;

static struct GNUNET_ECRS_URI *gloKeywords;

static unsigned int anonymity = 1;

static unsigned int priority = 365;

static int do_no_direct_references;

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

static char *
get_record_file_name (const char *dirname)
{
  GNUNET_EncName enc;
  GNUNET_HashCode hc;

  GNUNET_hash (dirname, strlen (dirname), &hc);
  GNUNET_hash_to_enc (&hc, &enc);
  return GNUNET_get_home_filename (ectx,
                                   cfg,
                                   GNUNET_NO,
                                   "auto-share-info",
                                   (const char *) &enc, NULL);
}

/**
 * Write the given record to the buffer.
 * @param buf if NULL, only calculate size
 * @return number of bytes written (or number
 *         of bytes that would be written)
 */
static unsigned int
write_file_record (char *buf, unsigned int max, const struct FileRecord *rec)
{
  unsigned int wi;
  unsigned long long wl;

  if ((buf != NULL) &&
      (max <
       sizeof (unsigned long long) * 3 + sizeof (GNUNET_HashCode) +
       strlen (rec->filename) + sizeof (unsigned int)))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return 0;
    }
  if (buf != NULL)
    {
      wi = htonl (strlen (rec->filename));
      memcpy (buf, &wi, sizeof (unsigned int));
      buf += sizeof (unsigned int);
      memcpy (buf, &rec->hc, sizeof (GNUNET_HashCode));
      buf += sizeof (GNUNET_HashCode);
      wl = GNUNET_htonll (rec->mtime);
      memcpy (buf, &wl, sizeof (unsigned long long));
      buf += sizeof (unsigned long long);
      wl = GNUNET_htonll (rec->last_seen);
      memcpy (buf, &wl, sizeof (unsigned long long));
      buf += sizeof (unsigned long long);
      wl = GNUNET_htonll (rec->size);
      memcpy (buf, &wl, sizeof (unsigned long long));
      buf += sizeof (unsigned long long);
      memcpy (buf, rec->filename, strlen (rec->filename));
    }
  return sizeof (unsigned long long) * 3 + sizeof (GNUNET_HashCode) +
    strlen (rec->filename) + sizeof (unsigned int);
}

/**
 * Read a file record.
 * @param head old head of the list, afterwards points to
 *        the new head
 * @param size number of bytes available in buf
 * @return 0 on error, otherwise number of bytes read
 */
static unsigned int
read_file_record (const char *buf,
                  unsigned int size, struct FileRecord **head)
{
  unsigned int wi;
  unsigned long long wl;
  struct FileRecord *r;

  if (size < sizeof (unsigned int))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return 0;
    }
  memcpy (&wi, buf, sizeof (unsigned int));
  if (size <
      ntohl (wi) + sizeof (unsigned long long) * 3 +
      sizeof (GNUNET_HashCode) + sizeof (unsigned int))
    {
      GNUNET_GE_BREAK (NULL, 0);
      return 0;
    }
  buf += sizeof (unsigned int);
  r = GNUNET_malloc (sizeof (struct FileRecord));
  r->next = *head;
  memcpy (&r->hc, buf, sizeof (GNUNET_HashCode));
  buf += sizeof (GNUNET_HashCode);
  memcpy (&wl, buf, sizeof (unsigned long long));
  r->mtime = (time_t) GNUNET_ntohll (wl);
  buf += sizeof (unsigned long long);
  memcpy (&wl, buf, sizeof (unsigned long long));
  r->last_seen = (time_t) GNUNET_ntohll (wl);
  buf += sizeof (unsigned long long);
  memcpy (&wl, buf, sizeof (unsigned long long));
  r->size = (off_t) GNUNET_ntohll (wl);
  buf += sizeof (unsigned long long);
  r->filename = GNUNET_malloc (ntohl (wi) + 1);
  r->filename[ntohl (wi)] = '\0';
  memcpy (r->filename, buf, ntohl (wi));
  *head = r;
  return ntohl (wi) + sizeof (unsigned long long) * 3 +
    sizeof (GNUNET_HashCode) + sizeof (unsigned int);
}

static struct FileRecord *
read_all_records (const char *dir_name)
{
  long off;
  unsigned int d;
  unsigned long long size;
  char *record_fn;
  int fd;
  char *buf;
  struct FileRecord *ret;

  record_fn = get_record_file_name (dir_name);
  if ((GNUNET_OK !=
       GNUNET_disk_file_size (ectx,
                              record_fn,
                              &size,
                              GNUNET_YES)) ||
      (-1 == (fd = GNUNET_disk_file_open (ectx, record_fn, O_RDONLY))))
    {
      GNUNET_free (record_fn);
      return NULL;
    }
  buf = MMAP (NULL, size, PROT_READ, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ADMIN | GNUNET_GE_USER |
                                   GNUNET_GE_ERROR | GNUNET_GE_BULK,
                                   "mmap", record_fn);
      GNUNET_free (record_fn);
      CLOSE (fd);
      return NULL;
    }
  ret = NULL;
  off = 0;
  while (off < size)
    {
      d = read_file_record (&buf[off], size - off, &ret);
      if (d == 0)
        {
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      off += d;
    }
  MUNMAP (buf, size);
  CLOSE (fd);
  return ret;
}

static void
write_all_records (struct DirectoryRecord *dr)
{
  const char dummy;
  long off;
  unsigned int d;
  unsigned long long size;
  char *record_fn;
  int fd;
  char *buf;
  struct FileRecord *pos;

  size = 0;
  pos = dr->records;
  while (pos != NULL)
    {
      size += write_file_record (NULL, 0, pos);
      pos = pos->next;
    }
  record_fn = get_record_file_name (dr->dirname);
  if ((-1 == (fd = GNUNET_disk_file_open (ectx,
                                          record_fn,
                                          O_RDWR | O_CREAT | O_TRUNC,
                                          S_IRUSR | S_IWUSR))))
    {
      GNUNET_free (record_fn);
      return;
    }
  LSEEK (fd, size - 1, SEEK_SET);
  WRITE (fd, &dummy, 1);
  buf = MMAP (NULL, size, PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ADMIN | GNUNET_GE_USER |
                                   GNUNET_GE_ERROR | GNUNET_GE_BULK,
                                   "mmap", record_fn);
      CLOSE (fd);
      UNLINK (record_fn);
      GNUNET_free (record_fn);
      return;
    }
  off = 0;
  pos = dr->records;
  while (pos != NULL)
    {
      d = write_file_record (&buf[off], size - off, pos);
      if (d == 0)
        {
          GNUNET_GE_BREAK (NULL, 0);
          break;
        }
      pos = pos->next;
      off += d;
    }
  MUNMAP (buf, size);
  CLOSE (fd);
}

static struct FileRecord *
find_entry (struct DirectoryRecord *dr, const char *filename)
{
  struct FileRecord *pos = dr->records;
  while ((pos != NULL) && (0 != strcmp (filename, pos->filename)))
    pos = pos->next;
  return pos;
}

static int
test_run (const char *filename, const char *dirName, void *cls)
{
  struct DirectoryRecord *dr = cls;
  GNUNET_HashCode hc;
  struct FileRecord *rec;
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
      fprintf (myout, _("Could not access `%s': %s\n"), fn, strerror (errno));
      fflush (myout);
      GNUNET_free (fn);
      return GNUNET_OK;
    }
  rec = find_entry (dr, fn);
  if (rec == NULL)
    {
      rec = GNUNET_malloc (sizeof (struct FileRecord));
      rec->next = dr->records;
      rec->filename = GNUNET_strdup (fn);
      rec->mtime = buf.st_mtime;
      rec->size = buf.st_size;
      rec->last_seen = time (NULL);
      GNUNET_hash_file (NULL, fn, &rec->hc);
      rec->next = dr->records;
      dr->records = rec;
      dr->records_changed = GNUNET_YES;
      if (GNUNET_NO == GNUNET_FS_test_indexed (sock, &rec->hc))
        {
          dr->run = 1;
          GNUNET_free (fn);
          /* keep iterating to mark all other files in this tree! */
          return GNUNET_OK;
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
        dr->run = 1;
      rec->mtime = buf.st_mtime;
      rec->size = buf.st_size;
      rec->hc = hc;
    }
  if (S_ISDIR (buf.st_mode))
    GNUNET_disk_directory_scan (ectx, fn, &test_run, dr);
  GNUNET_free (fn);
  return GNUNET_OK;
}

struct AddMetadataClosure
{
  const char *filename;
  struct GNUNET_MetaData *meta;
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

  if ((0 != strcmp (amc->filename, section)) &&
      ((0 != strncmp (amc->filename,
                      section,
                      strlen (amc->filename))) ||
       (strlen (section) != strlen (amc->filename) + 1) ||
       ((section[strlen (section) - 1] != '/') &&
        (section[strlen (section) - 1] != '\\'))))
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
      GNUNET_meta_data_insert (amc->meta, type, value);
      GNUNET_free (value);
    }
  return 0;
}

static int
probe_directory (const char *filename, const char *dirName, void *cls)
{
  struct DirectoryRecord *dr = cls;
  struct stat buf;
  struct AddMetadataClosure amc;
  struct GNUNET_ECRS_URI *kuri;
  char *fn;
  char *keys;

  if (GNUNET_shutdown_test ())
    return GNUNET_SYSERR;       /* aborted */
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
      fprintf (myout, "Could not stat `%s': %s\n", fn, STRERROR (errno));
      fflush (myout);
      GNUNET_free (fn);
      return GNUNET_OK;
    }
  dr->run = 0;
  test_run (filename, dirName, dr);
  if (0 == dr->run)
    {
      GNUNET_free (fn);
      return GNUNET_OK;
    }
  amc.meta = GNUNET_meta_data_create ();
  amc.filename = filename;
  /* attaching a listener will prompt iteration
     over all config values! */
  GNUNET_GC_attach_change_listener (meta_cfg, &add_meta_data, &amc);
  GNUNET_GC_detach_change_listener (meta_cfg, &add_meta_data, &amc);
  keys = GNUNET_meta_data_get_by_type (amc.meta, EXTRACTOR_KEYWORDS);
  if (keys != NULL)
    kuri = GNUNET_ECRS_keyword_string_to_uri (NULL, keys);
  else
    kuri = NULL;
  GNUNET_meta_data_delete (amc.meta, EXTRACTOR_KEYWORDS, keys);
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
  GNUNET_meta_data_destroy (amc.meta);
  GNUNET_free (fn);
  return GNUNET_SYSERR;
}


/**
 * Actual main function.
 *
 * @return return 0 for ok, -1 on error
 */
int
auto_share_main ()
{
  int errorCode;
  int work_done;
  unsigned long long verbose;
  GNUNET_CronTime delay;
  char *metafn;
  char *dirs;
  char *dirs_idx1;
  char *dirs_idx2;
  struct FileRecord *rpos;
  int filedes[2];               /* pipe between client and parent */
  struct DirectoryRecord *head;
  struct DirectoryRecord *pos;

  if (GNUNET_SYSERR == GNUNET_pid_file_kill_owner (ectx, cfg, PIDFILE_DATA))
    {
      fprintf (myout, _("Failed to stop running gnunet-auto-share.\n"));
      fflush (myout);
      errorCode = -1;
      if (GNUNET_NO == debug_flag)
        GNUNET_terminal_detach_complete (ectx, filedes, GNUNET_NO);
      return GNUNET_SYSERR;
    }
  errorCode = 0;
  if ((GNUNET_NO == debug_flag)
      && (GNUNET_OK != GNUNET_terminal_detach (ectx, cfg, filedes,
                                               PIDFILE_DATA)))
    return GNUNET_SYSERR;
  if (GNUNET_NO != debug_flag)
    GNUNET_pid_file_write (ectx, cfg, getpid (), PIDFILE_DATA);
  head = NULL;
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
  GNUNET_GC_get_configuration_value_string (cfg,
                                            "GNUNET-AUTO-SHARE",
                                            "DIRS", "", &dirs);
  meta_cfg = GNUNET_GC_create ();
  if (GNUNET_YES == GNUNET_disk_file_test (NULL, metafn))
    GNUNET_GC_parse_configuration (meta_cfg, metafn);
  if (GNUNET_NO == debug_flag)
    GNUNET_terminal_detach_complete (ectx, filedes, GNUNET_YES);
  GNUNET_free (metafn);
  /* fundamental init */
  ctx = GNUNET_FSUI_start (ectx, cfg, "gnunet-auto-share", GNUNET_NO, 32,
                           &printstatus, &verbose);

  dirs_idx1 = dirs_idx2 = dirs;
  while (1)
    if ((*dirs_idx2 == ';') || (*dirs_idx2 == '\0'))
      {
        *dirs_idx2 = 0;

        pos = GNUNET_malloc (sizeof (struct DirectoryRecord));
        pos->dirname = GNUNET_expand_file_name (ectx, dirs_idx1);
        pos->records = read_all_records (pos->dirname);
        pos->records_changed = GNUNET_NO;
        pos->run = 0;
        pos->next = head;
        head = pos;

        if (*dirs_idx2 == 0)
          break;

        dirs_idx1 = ++dirs_idx2;
      }
    else
      dirs_idx2++;

  /* first insert all of the top-level files or directories */
  delay = 5 * GNUNET_CRON_SECONDS;
  while (GNUNET_NO == GNUNET_shutdown_test ())
    {
      work_done = GNUNET_NO;
      GNUNET_thread_sleep (250 * GNUNET_CRON_MILLISECONDS);
      pos = head;
      while ((pos != NULL) && (GNUNET_NO == GNUNET_shutdown_test ()))
        {
          GNUNET_disk_directory_scan (ectx, pos->dirname, &probe_directory,
                                      pos);
          if (GNUNET_YES == upload_done)
            {
              work_done = GNUNET_YES;
              GNUNET_FSUI_upload_abort (ul);
              GNUNET_FSUI_upload_stop (ul);
              upload_done = GNUNET_NO;
              ul = NULL;
            }
          pos = pos->next;
        }
      if ((ul == NULL) &&
          (work_done == GNUNET_NO) && (GNUNET_NO == GNUNET_shutdown_test ()))
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
  while (head != NULL)
    {
      if (head->records_changed)
        write_all_records (head);
      while (head->records != NULL)
        {
          rpos = head->records;
          head->records = rpos->next;
          GNUNET_free (rpos->filename);
          GNUNET_free (rpos);
        }
      pos = head->next;
      GNUNET_free (head->dirname);
      GNUNET_free (head);
      head = pos;
    }

  if (meta_cfg != NULL)
    GNUNET_GC_free (meta_cfg);
  if (sock != NULL)
    GNUNET_client_connection_destroy (sock);
  GNUNET_pid_file_delete (ectx, cfg, PIDFILE_DATA);
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
          if (GNControlService
              ((SC_HANDLE) hService, SERVICE_CONTROL_STOP, &theStat))
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
  auto_share_main ();
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

  if (i < argc)
    {
      char *dirs;
      unsigned int dirs_len;
      char *fullname;
      struct stat stbuf;
      const char *dirs_idx1;
      char *dirs_idx2;
      char *base;
      int seen;
      int added;

      GNUNET_GC_get_configuration_value_string (cfg, "GNUNET-AUTO-SHARE",
                                                "DIRS", "", &dirs);
      dirs_len = strlen (dirs);
      added = 0;
      while (i < argc)
        {
          fullname = GNUNET_expand_file_name (ectx, argv[i]);
          if (0 != STAT (fullname, &stbuf))
            {
              FPRINTF (myout,
                       _("Could not access `%s': %s\n"),
                       fullname, STRERROR (errno));
              errorCode = 1;
              GNUNET_free (fullname);
              GNUNET_free (dirs);
              goto end;
            }
          seen = 0;
          dirs_idx1 = dirs_idx2 = base = GNUNET_strdup (dirs);
          while (1)
            {
              if ((*dirs_idx2 == ';') || (*dirs_idx2 == '\0'))
                {
                  *dirs_idx2 = 0;
                  if (0 == strcmp (dirs_idx1, fullname))
                    {
                      seen = 1;
                      FPRINTF (myout,
                               _
                               ("Directory `%s' is already on the list of shared directories.\n"),
                               fullname);
                      break;
                    }
                  if (*dirs_idx2 == 0)
                    break;
                  dirs_idx1 = ++dirs_idx2;
                }
              else
                dirs_idx2++;
            }
          GNUNET_free (base);
          if (seen == 0)
            {
              dirs = GNUNET_realloc (dirs, dirs_len + strlen (fullname) + 2);
              if (dirs_len > 0)
                strcat (dirs, ";");
              strcat (dirs, fullname);
              GNUNET_free (fullname);
              added = 1;
            }
          i++;
        }
      GNUNET_GC_set_configuration_value_string (cfg, ectx,
                                                "GNUNET-AUTO-SHARE", "DIRS",
                                                dirs);
      GNUNET_free (dirs);
      if (GNUNET_GC_write_configuration (cfg, cfgFilename) != GNUNET_SYSERR)
        {
          if (added)
            {
              FPRINTF (myout,
                       "%s",
                       _
                       ("The specified directories were added to the list of "
                        "shared directories.\n"));
            }
          errorCode = 0;
        }
      else
        {
          errorCode = -1;
          goto end;
        }
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
                   _("Could not open logfile `%s': %s\n"),
                   log_file_name, strerror (errno));
          GNUNET_free (log_file_name);
          errorCode = -1;
          goto end;
        }
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
      errorCode = auto_share_main ();
    }
end:
  GNUNET_fini (ectx, cfg);
  if (myout != stdout)
    fclose (myout);
  return errorCode;
}

/* end of gnunet-auto-share.c */
