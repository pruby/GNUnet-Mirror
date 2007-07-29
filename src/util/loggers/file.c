/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
#define _XOPEN_SOURCE           /* glibc2 needs this */
#include "gnunet_util_error_loggers.h"
#include "gnunet_util_string.h"
#include "gnunet_util.h"
#include "platform.h"
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
   * Lock.
   */
  struct MUTEX *lock;

  /**
   * Should we log the current date with each message?
   * (0: NO, 1: YES)
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
  TIME_T logstart;

} FileContext;

static char *
getDateFormat ()
{
  char *datefmt;
  char *idx;
  char c;

#if ENABLE_NLS
  datefmt = STRDUP (nl_langinfo (D_FMT));
#else
  datefmt = STRDUP ("%Y-%m-%d");
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
removeOldLog (const char *fil, const char *dir, void *ptr)
{
  const FileContext *ctx = ptr;
  struct tm t;
  char *fullname;
  const char *logdate;
  const char *ret;
  time_t curtime;
  struct tm lcltime;
  const char *def;
  char *datefmt;

  time (&curtime);
  lcltime = *localtime (&curtime);
  def = ctx->basename;
  fullname = MALLOC (strlen (dir) + strlen (fil) + 2);
  strcpy (fullname, dir);
  if (dir[strlen (dir) - 1] != DIR_SEPARATOR)
    strcat (fullname, DIR_SEPARATOR_STR);
  strcat (fullname, fil);
  if (0 != strncmp (def, fullname, strlen (def)))
    {
      FREE (fullname);
      return OK;
    }
  logdate = &fullname[strlen (def) + 1];
  datefmt = getDateFormat ();
  ret = strptime (logdate, datefmt, &t);
  FREE (datefmt);
  if ((ret == NULL) || (ret[0] != '\0'))
    {
      FREE (fullname);
      return OK;                /* not a logfile */
    }
  if (ctx->logrotate
      + t.tm_year * 365 + t.tm_yday
      - lcltime.tm_year * 365 - lcltime.tm_yday <= 0)
    UNLINK (fullname);          /* TODO: add ctx->fctx */
  FREE (fullname);
  return OK;
}

/**
 * Get the current day of the year
 * formatted for appending to the filename.
 */
static char *
getLogFileName (const char *name)
{
  time_t curtime;
  struct tm lcltime;
  char *datefmt;
  char *ret;
  char date[81];
  size_t size;

  time (&curtime);
  lcltime = *localtime (&curtime);
  datefmt = getDateFormat ();
#ifdef localtime_r
  localtime_r (&curtime, &lcltime);
#else
  lcltime = *localtime (&curtime);
#endif
  /* Format current date for filename */
  GE_ASSERT (NULL, 0 != strftime (date, 80, datefmt, &lcltime));
  FREE (datefmt);

  /* Remove special chars */
  disk_filename_canonicalize (date);

  size = strlen (name) + 82;
  ret = MALLOC (size);
  SNPRINTF (ret, size, "%s-%s", name, date);
  return ret;
}

static void
purge_old_logs (FileContext * fctx, const char *logfilename)
{
  char *dirname;

  dirname = STRDUP (logfilename);
  while ((strlen (dirname) > 0) &&
         (dirname[strlen (dirname) - 1] != DIR_SEPARATOR))
    dirname[strlen (dirname) - 1] = '\0';
  disk_directory_scan (NULL, dirname, &removeOldLog, fctx);
  FREE (dirname);

}

static void
filelogger (void *cls, GE_KIND kind, const char *date, const char *msg)
{
  FileContext *fctx = cls;
  char *name;
  int ret;

  MUTEX_LOCK (fctx->lock);
  if (fctx->logrotate)
    {
      name = getLogFileName (fctx->basename);
      if ((fctx->first_start == YES) || (0 != strcmp (name, fctx->filename)))
        {
          fctx->first_start = NO;
          fclose (fctx->handle);
          fctx->handle = FOPEN (name, "a+");
          if (fctx->handle == NULL)
            {
              fctx->handle = stderr;
              fprintf (stderr,
                       _("Failed to open log-file `%s': %s\n"),
                       name, STRERROR (errno));
            }
          FREE (fctx->filename);
          fctx->filename = name;
          purge_old_logs (fctx, name);
        }
      else
        {
          FREE (name);
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
                     date, GE_kindToString (kind & GE_EVENTKIND), msg);
    }
  else
    {
      ret = fprintf (fctx->handle,
                     "%s: %s", GE_kindToString (kind & GE_EVENTKIND), msg);
    }
  if (ret < 0)
    fprintf (stderr,
             _("`%s' failed at %s:%d in %s with error: %s\n"),
             "fclose", __FILE__, __LINE__, __FUNCTION__, STRERROR (errno));
  fflush (fctx->handle);
  MUTEX_UNLOCK (fctx->lock);
}

static void
fileclose (void *cls)
{
  FileContext *fctx = cls;

  MUTEX_DESTROY (fctx->lock);
  FREENONNULL (fctx->filename);
  FREENONNULL (fctx->basename);
  if ((fctx->handle != stderr) &&
      (fctx->handle != stdout) && (0 != fclose (fctx->handle)))
    fprintf (stderr,
             _("`%s' failed at %s:%d in %s with error: %s\n"),
             "fclose", __FILE__, __LINE__, __FUNCTION__, STRERROR (errno));
  FREE (fctx);
}

/**
 * Create a logger that writes events to a file.
 *
 * @param mask which events should be logged?
 * @param filename which file should we log to?
 * @param logDate should the context log event dates?
 * @param logrotate after how many days should rotated log
 *        files be deleted (use 0 for no rotation)
 */
struct GE_Context *
GE_create_context_logfile (struct GE_Context *ectx,
                           GE_KIND mask,
                           const char *filename, int logDate, int logrotate)
{
  FileContext *fctx;
  FILE *fd;
  char *name;
  TIME_T start;

  TIME (&start);
  if (logrotate != 0)
    {
      name = getLogFileName (filename);
    }
  else
    {
      name = STRDUP (filename);
    }
  fd = FOPEN (name, "a+");
  if (fd == NULL)
    {
      GE_LOG_STRERROR_FILE (ectx,
                            GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE |
                            GE_BULK, "fopen", name);
      FREE (name);
      return NULL;              /* ERROR! */
    }
  fctx = MALLOC (sizeof (FileContext));
  fctx->first_start = YES;
  fctx->logdate = logDate;
  fctx->logrotate = logrotate;
  fctx->handle = fd;
  fctx->filename = name;
  fctx->basename = STRDUP (filename);
  fctx->logstart = start;
  fctx->lock = MUTEX_CREATE (YES);
  purge_old_logs (fctx, name);
  return GE_create_context_callback (mask,
                                     &filelogger, fctx, &fileclose, NULL);
}


/**
 * Create a logger that writes events to stderr
 *
 * @param mask which events should be logged?
 */
struct GE_Context *
GE_create_context_stderr (int logDate, GE_KIND mask)
{
  FileContext *fctx;

  fctx = MALLOC (sizeof (FileContext));
  fctx->logdate = logDate;
  fctx->logrotate = 0;
  fctx->handle = stderr;
  fctx->filename = NULL;
  fctx->basename = NULL;
  fctx->logstart = 0;
  fctx->first_start = NO;
  fctx->lock = MUTEX_CREATE (YES);
  return GE_create_context_callback (mask,
                                     &filelogger, fctx, &fileclose, NULL);

}

/**
 * Create a logger that writes events to stderr
 *
 * @param mask which events should be logged?
 */
struct GE_Context *
GE_create_context_stdout (int logDate, GE_KIND mask)
{
  FileContext *fctx;

  fctx = MALLOC (sizeof (FileContext));
  fctx->logdate = logDate;
  fctx->logrotate = 0;
  fctx->first_start = NO;
  fctx->handle = stdout;
  fctx->filename = NULL;
  fctx->basename = NULL;
  fctx->logstart = 0;
  fctx->lock = MUTEX_CREATE (YES);
  return GE_create_context_callback (mask,
                                     &filelogger, fctx, &fileclose, NULL);

}
