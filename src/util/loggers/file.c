/*
     This file is part of GNUnet.
     (C) 2006, 2008 Christian Grothoff (and other contributing authors)

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
 * @file src/util/loggers/file.c
 * @brief logging to files
 *
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_error_loggers.h"
#include "gnunet_util_os.h"
#include "gnunet_util_string.h"
#include "gnunet_util.h"
#include <time.h>

/**
 * Context for file logger.
 */
typedef struct FileContext
{

  /**
   * File handle used for logging.
   */
  FILE *handle;

  /**
   * Filename that we log to (mostly for printing
   * error messages) and rotation.
   */
  char *filename;

  /**
   * Base filename (extended for log rotatation).
   */
  char *basename;

  /**
   * Who should own the log files?
   */
  char *user;

  /**
   * Lock.
   */
  struct GNUNET_Mutex *lock;

  /**
   * Should we log the current date with each message?
   * (0: GNUNET_NO, 1: GNUNET_YES)
   */
  int logdate;

  /**
   * Should log files be rotated? 0: no,
   * otherwise number of days to keep.
   */
  int logrotate;

  /**
   * Last day of year we logged anything.
   */
  int yday;

  /**
   * Is this the first time we log anything for this
   * process?  Used with log rotation to delete old logs.
   */
  int first_start;

  /**
   * When did we start the current logfile?
   */
  GNUNET_Int32Time logstart;

} FileContext;

/**
 * Get the date format we use for logging.
 */
static char *
get_date_format ()
{
  char *datefmt;
  char *idx;
  char c;

#if ENABLE_NLS
  datefmt = GNUNET_strdup (nl_langinfo (D_FMT));
#else
  datefmt = GNUNET_strdup ("%Y-%m-%d");
#endif
  /* Remove slashes */
  idx = datefmt;
  while ('\0' != (c = *idx))
    {
      if ((c == '\\') || (c == '/'))
        *idx = '_';
      idx++;
    }
  return datefmt;
}

/**
 * Remove file if it is an old log
 */
static int
remove_old_log (void *ptr, const char *fullname)
{
  const FileContext *ctx = ptr;
  struct tm t;
  const char *logdate;
  const char *ret;
  time_t curtime;
  struct tm lcltime;
  const char *def;
  char *datefmt;

  time (&curtime);
  lcltime = *localtime (&curtime);
  def = ctx->basename;
  if (0 != strncmp (def, fullname, strlen (def)))
    return GNUNET_OK;
  logdate = &fullname[strlen (def) + 1];
  datefmt = get_date_format ();
  ret = strptime (logdate, datefmt, &t);
  GNUNET_free (datefmt);
  if ((ret == NULL) || (ret[0] != '\0'))
    return GNUNET_OK;           /* not a logfile */
  if (ctx->logrotate
      + t.tm_year * 365 + t.tm_yday
      - lcltime.tm_year * 365 - lcltime.tm_yday <= 0)
    UNLINK (fullname);          /* TODO: add ctx->ectx */
  return GNUNET_OK;
}

/**
 * Get the current day of the year
 * formatted for appending to the filename.
 */
static char *
get_log_file_name (const char *name)
{
  time_t curtime;
  struct tm lcltime;
  char *datefmt;
  char *ret;
  char date[81];
  size_t size;

  time (&curtime);
  lcltime = *localtime (&curtime);
  datefmt = get_date_format ();
#ifdef localtime_r
  localtime_r (&curtime, &lcltime);
#else
  lcltime = *localtime (&curtime);
#endif
  /* Format current date for filename */
  GNUNET_GE_ASSERT (NULL, 0 != strftime (date, 80, datefmt, &lcltime));
  GNUNET_free (datefmt);

  /* Remove special chars */
  GNUNET_disk_filename_canonicalize (date);

  size = strlen (name) + 82;
  ret = GNUNET_malloc (size);
  GNUNET_snprintf (ret, size, "%s-%s", name, date);
  return ret;
}

/**
 * Purge outdated log files.
 */
static void
purge_old_logs (FileContext * fctx, const char *logfilename)
{
  char *dirname;

  dirname = GNUNET_strdup (logfilename);
  while ((strlen (dirname) > 0) &&
         (dirname[strlen (dirname) - 1] != DIR_SEPARATOR))
    dirname[strlen (dirname) - 1] = '\0';
  GNUNET_disk_directory_scan (NULL, dirname, &remove_old_log, fctx);
  GNUNET_free (dirname);

}

static void
file_log_callback (void *cls, GNUNET_GE_KIND kind, const char *date,
                   const char *msg)
{
  FileContext *fctx = cls;
  char *name;
  int ret;

  GNUNET_mutex_lock (fctx->lock);
  if (fctx->logrotate)
    {
      name = get_log_file_name (fctx->basename);
      if ((fctx->first_start == GNUNET_YES)
          || (0 != strcmp (name, fctx->filename)))
        {
          fctx->first_start = GNUNET_NO;
          fclose (fctx->handle);
          fctx->handle = FOPEN (name, "a+");
          if (fctx->handle == NULL)
            {
              fctx->handle = stderr;
              fprintf (stderr,
                       _("Failed to open log-file `%s': %s\n"),
                       name, STRERROR (errno));
            }
          GNUNET_free (fctx->filename);
          fctx->filename = name;
          purge_old_logs (fctx, name);
          if (fctx->user != NULL)
            GNUNET_file_change_owner (NULL, name, fctx->user);
        }
      else
        {
          GNUNET_free (name);
        }
    }

#ifdef WINDOWS
  /* Most tools disband the console window early in the initialization
     process, so we have to create a new one if we're logging to the console. */
  if ((fctx->handle == stderr || fctx->handle == stdout))
    {
      AllocConsole ();
      SetConsoleTitle (_("GNUnet error log"));
    }
#endif

  if (fctx->logdate)
    {
      ret = fprintf (fctx->handle,
                     "%s %s: %s",
                     date,
                     GNUNET_GE_kindToString (kind & GNUNET_GE_EVENTKIND),
                     msg);
    }
  else
    {
      ret = fprintf (fctx->handle,
                     "%s: %s",
                     GNUNET_GE_kindToString (kind & GNUNET_GE_EVENTKIND),
                     msg);
    }
  if (ret < 0)
    fprintf (stderr,
             _("`%s' failed at %s:%d with error: %s\n"),
             "fclose", __FILE__, __LINE__, STRERROR (errno));
  fflush (fctx->handle);
  GNUNET_mutex_unlock (fctx->lock);
}

static void
file_logger_close_callback (void *cls)
{
  FileContext *fctx = cls;

  GNUNET_mutex_destroy (fctx->lock);
  GNUNET_free_non_null (fctx->filename);
  GNUNET_free_non_null (fctx->basename);
  GNUNET_free_non_null (fctx->user);
  if ((fctx->handle != stderr) &&
      (fctx->handle != stdout) && (0 != fclose (fctx->handle)))
    fprintf (stderr,
             _("`%s' failed at %s:%d with error: %s\n"),
             "fclose", __FILE__, __LINE__, STRERROR (errno));
  GNUNET_free (fctx);
}

/**
 * Create a logger that writes events to a file.
 *
 * @param mask which events should be logged?
 * @param filename which file should we log to?
 * @param owner who should own the log file (username)?
 * @param logDate should the context log event dates?
 * @param logrotate after how many days should rotated log
 *        files be deleted (use 0 for no rotation)
 */
struct GNUNET_GE_Context *
GNUNET_GE_create_context_logfile (struct GNUNET_GE_Context *ectx,
                                  GNUNET_GE_KIND mask,
                                  const char *filename,
                                  const char *owner, int logDate,
                                  int logrotate)
{
  FileContext *fctx;
  FILE *fd;
  char *name;
  GNUNET_Int32Time start;

  GNUNET_get_time_int32 (&start);
  if (logrotate != 0)
    {
      name = get_log_file_name (filename);
    }
  else
    {
      name = GNUNET_strdup (filename);
    }
  GNUNET_disk_directory_create_for_file (ectx, name);
  fd = FOPEN (name, "a+");
  if (fd == NULL)
    {
      GNUNET_GE_LOG_STRERROR_FILE (ectx,
                                   GNUNET_GE_ERROR | GNUNET_GE_USER |
                                   GNUNET_GE_ADMIN | GNUNET_GE_IMMEDIATE |
                                   GNUNET_GE_BULK, "fopen", name);
      GNUNET_free (name);
      return NULL;              /* ERROR! */
    }
  if (owner != NULL)
    GNUNET_file_change_owner (NULL, name, owner);
  fctx = GNUNET_malloc (sizeof (FileContext));
  fctx->first_start = GNUNET_YES;
  fctx->logdate = logDate;
  fctx->logrotate = logrotate;
  fctx->handle = fd;
  fctx->filename = name;
  fctx->basename = GNUNET_strdup (filename);
  fctx->user = owner != NULL ? GNUNET_strdup (owner) : NULL;
  fctx->logstart = start;
  fctx->lock = GNUNET_mutex_create (GNUNET_YES);
  purge_old_logs (fctx, name);
  return GNUNET_GE_create_context_callback (mask,
                                            &file_log_callback, fctx,
                                            &file_logger_close_callback,
                                            NULL);
}

/**
 * Create a logger that writes events to the
 * given file (but does not delete or close it
 * and does no logrotation).
 *
 * @param mask which events should be logged?
 */
static struct GNUNET_GE_Context *
create_log_context_fd (int logDate, GNUNET_GE_KIND mask, FILE * fd)
{
  FileContext *fctx;

  fctx = GNUNET_malloc (sizeof (FileContext));
  memset (fctx, 0, sizeof (FileContext));
  fctx->logdate = logDate;
  fctx->handle = fd;
  fctx->lock = GNUNET_mutex_create (GNUNET_YES);
  return GNUNET_GE_create_context_callback (mask,
                                            &file_log_callback, fctx,
                                            &file_logger_close_callback,
                                            NULL);
}


/**
 * Create a logger that writes events to stderr
 *
 * @param mask which events should be logged?
 */
struct GNUNET_GE_Context *
GNUNET_GE_create_context_stderr (int logDate, GNUNET_GE_KIND mask)
{
  return create_log_context_fd (logDate, mask, stderr);
}

/**
 * Create a logger that writes events to stderr
 *
 * @param mask which events should be logged?
 */
struct GNUNET_GE_Context *
GNUNET_GE_create_context_stdout (int logDate, GNUNET_GE_KIND mask)
{
  return create_log_context_fd (logDate, mask, stdout);
}

/* end of file.c */
