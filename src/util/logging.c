/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005 Christian Grothoff (and other contributing authors)

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
 * @file util/logging.c
 * @brief basic logging mechanism
 * @author Christian Grothoff
 *
 * This file contains basic logging mechanisms, with log-levels,
 * logging to file or stderr and with or without time-prefixing.
 */

#include "platform.h"
#include "gnunet_util.h"
#include <time.h>

/**
 * Where to write log information to.
 */
static FILE * logfile;

/**
 * Current loglevel.
 */
static LOG_Level loglevel__ = LOG_WARNING;

/**
 * Lock for logging activities.
 */
static Mutex logMutex;

/**
 * Has the logging module been initialized?  If not, logMutex must not
 * be used and logfile is likely NULL.  This is there
 * because code may call logging before initialization.
 */
static int bInited = NO;

/**
 * Callback function for internal logging
 * (i.e. to the user interface)
 */
static TLogProc customLog;

/**
 * Highest legal log level.
 */
static LOG_Level maxLogLevel = LOG_EVERYTHING;

/**
 * Day for which the current logfile is
 * opened (tells us when we need to switch
 * to a new file).
 */
static unsigned int lastlog;

/**
 * How long to keep logs, in days
 */
static int keepLog;

/**
 * Base value for getting configuration options; either "GNUNETD" or
 * "GNUNET", depending on whether or not the code is used by the
 * deamon or a client.
 */
static char * base;

/**
 * The different loglevels.
 */
static char * loglevels[] = {
  gettext_noop("NOTHING"),
  gettext_noop("FATAL"),
  gettext_noop("ERROR"),
  gettext_noop("FAILURE"),
  gettext_noop("WARNING"),
  gettext_noop("MESSAGE"),
  gettext_noop("INFO"),
  gettext_noop("DEBUG"),
  gettext_noop("CRON"),
  gettext_noop("EVERYTHING"),
  NULL,
};

/**
 * Context for removeOldLog
 */
struct logfiledef {
  struct tm curtime;
  char * basename;
};

/**
 * Remove file if it is an old log
 */
static int removeOldLog(const char * fil,
			const char * dir,
			void * ptr) {
  struct logfiledef * def = ptr;
  struct tm t;
  char * fullname;
  const char * logdate;
  const char * ret;

  fullname = MALLOC(strlen(dir) + strlen(fil) + 2);
  strcpy(fullname, dir);
  if (dir[strlen(dir)-1] != DIR_SEPARATOR)
    strcat(fullname, DIR_SEPARATOR_STR);
  strcat(fullname, fil);
  if (0 != strncmp(def->basename,
       fullname,
       strlen(def->basename))) {
    FREE(fullname);
    return OK;
  }
  logdate = &fullname[strlen(def->basename)];
#if ENABLE_NLS
  {
    char *idx;
    char c;
    char *datefmt = STRDUP(nl_langinfo(D_FMT));
  
    /* Remove slashes */
    idx = datefmt;
    while((c = *idx)) {
      if(c == '\\' || c == '/')
        *idx = '_';
      idx++;
    }
  
    ret = strptime(logdate,
       datefmt,
       &t);
       
    FREE(datefmt);
  }
#else
  ret = strptime(logdate, "%Y-%m-%d", &t);
#endif
  if ( (ret == NULL) ||
       (ret[0] != '\0') ) {
    FREE(fullname);
    return OK; /* not a logfile */
  }

  if (t.tm_year*365 + t.tm_yday + keepLog
      < def->curtime.tm_year*365 + def->curtime.tm_yday)
    UNLINK(fullname);

  FREE(fullname);
  return OK;
}

/**
 * Open the logfile
 */
void reopenLogFile() {
  char * logfilename;

  logfilename
    = getConfigurationString(base,
			     "LOGFILE");
  if (logfilename != NULL) {
    char * fn;

    if ( (logfile != stderr) &&
   (logfile != NULL) ) {
      fclose(logfile);
      logfile = NULL;
    }
    fn = expandFileName(logfilename);
    if (keepLog) {
      char * logdir;
      char * end;
      struct logfiledef def;
      char datestr[80];
      time_t curtime;
      const char *datefmt;
      char c;

#if ENABLE_NLS
      datefmt = nl_langinfo(D_FMT);
#else
      datefmt = "%Y-%m-%d";
#endif
      time(&curtime);
#ifdef localtime_r
      localtime_r(&curtime, &def.curtime);
#else
      def.curtime = *localtime(&curtime);
#endif
      lastlog = def.curtime.tm_yday;

      /* Format current date for filename*/
      fn = (char *) realloc(fn, strlen(fn) + 82);
      strcat(fn, "_");
      def.basename = STRDUP(fn);
      GNUNET_ASSERT(0 != strftime(datestr,
          80,
          datefmt,
          &def.curtime));

      /* Remove slashes */
      end = datestr;
      while((c = *end)) {
	if (c == '\\' || c == '/')
	  *end = '_';
	end++;
      }

      strcat(fn, datestr);

      /* Remove old logs */
      logdir = STRDUP(fn);
      end = logdir + strlen(logdir);
      while (*end != DIR_SEPARATOR)
        end--;
      *end = 0;
      scanDirectory(logdir,
		    &removeOldLog,
		    &def);
      FREE(def.basename);
      FREE(logdir);
    }

    logfile = FOPEN(fn, "a+");
    if (logfile == NULL)
      logfile = stderr;
    FREE(fn);
    FREE(logfilename);
  } else
    logfile = stderr;
}

/**
 * Return the current logging level
 */
LOG_Level getLogLevel() {
  return loglevel__;
}

/**
 * Return the logfile
 */
void *getLogfile() {
  return logfile;
}

/**
 * Convert a textual description of a loglevel into an int.
 */
static LOG_Level getLoglevel(const char * log) {
  int i;
  char * caplog;

  GNUNET_ASSERT(log != NULL);
  caplog = strdup(log);
  for (i=strlen(caplog)-1;i>=0;i--)
    caplog[i] = toupper(caplog[i]);
  i = LOG_NOTHING;
  while ( (loglevels[i] != NULL) &&
	  (0 != strcmp(caplog, gettext(loglevels[i]))) &&
	  (0 != strcmp(caplog, loglevels[i])) )
    i++;
  free(caplog);
  if (loglevels[i] == NULL)
    errexit(_("Invalid LOGLEVEL `%s' specified.\n"),
	    log);
  return (LOG_Level) i;
}

/**
 * Re-read the loggig configuration.
 * Call on SIGHUP if the configuration file has changed.
 */
static void resetLogging() {
  char * loglevelname;

  MUTEX_LOCK(&logMutex);
  if (testConfigurationString("GNUNETD",
			      "_MAGIC_",
			      "YES"))
    base = "GNUNETD";
  else
    base = "GNUNET";
  loglevelname
    = getConfigurationString(base,
			     "LOGLEVEL");
  if (loglevelname == NULL)
    loglevelname = strdup("WARNING");
  loglevel__
    = getLoglevel(loglevelname);
  free(loglevelname);
  keepLog
    = getConfigurationInt(base,
			  "KEEPLOG");
  reopenLogFile();
  MUTEX_UNLOCK(&logMutex);
}

/**
 * Initialize the logging module.
 */
void initLogging() {
  MUTEX_CREATE_RECURSIVE(&logMutex);

  bInited = YES;
  registerConfigurationUpdateCallback(&resetLogging);
  resetLogging();
}

/**
 * Shutdown the logging module.
 */
void doneLogging() {
  unregisterConfigurationUpdateCallback(&resetLogging);
  if ( (logfile != NULL) &&
       (logfile != stderr) )
    fclose(logfile);
  logfile = NULL;
  loglevel__ = 0;
  MUTEX_DESTROY(&logMutex);
  bInited = NO;
}


/**
 * Print the current time to logfile without linefeed
 */
static void printTime() {
  if (logfile !=NULL) {
    char timebuf[64];
    time_t timetmp;
    struct tm * tmptr;

    time(&timetmp);
    tmptr = localtime(&timetmp);
    GNUNET_ASSERT(0 != strftime(timebuf,
        64,
        "%b %d %H:%M:%S ",
        tmptr));
    fputs(timebuf,
    logfile);
  }
}

/**
 * Something went wrong, add opportunity to stop gdb at this
 * breakpoint and/or report in the logs that this happened.
 *
 * @param filename where in the code did the problem occur
 * @param linenumber where in the code did the problem occur
 */
void breakpoint_(const char * filename,
                 const int linenumber) {
  if (logfile != NULL) {
    printTime();
    FPRINTF(logfile,
	    _("Failure at %s:%d.\n"),
    	    filename,
	    linenumber);
    fflush(logfile);
  } else
    FPRINTF(stderr,
	    _("Failure at %s:%d.\n"),
    	    filename,
	    linenumber);
}

/**
 * Register an additional logging function which gets
 * called whenever GNUnet LOG()s something
 *
 * @param proc the function to register
 */
void setCustomLogProc(TLogProc proc) {
  if (bInited)
    MUTEX_LOCK(&logMutex);

  if ( (customLog != NULL) &&
       (proc != NULL) ) {
    BREAK();
  }
  customLog = proc;

  if (bInited)
    MUTEX_UNLOCK(&logMutex);
}

/**
 * Log a debug message
 *
 * @param minLogLevel minimum level at which this message should be logged
 * @param format the string describing the error message
 */
void LOG(LOG_Level minLogLevel,
	 const char *format, ...) {
  va_list	args;
  size_t len;

  if (loglevel__ < minLogLevel)
    return;
  if (minLogLevel > maxLogLevel)
    minLogLevel = maxLogLevel;

  if (bInited)
    MUTEX_LOCK(&logMutex);
  va_start(args, format);
  if (logfile != NULL) {
    time_t curtime;
    struct tm *lcltime;

    time(&curtime);
    lcltime = localtime(&curtime);

    if (lcltime->tm_yday != lastlog) {
      reopenLogFile();
      lastlog = lcltime->tm_yday;
    }

    printTime();
    if (format[0] == ' ')
      FPRINTF(logfile, "%s:", gettext(loglevels[minLogLevel]));
    else
      FPRINTF(logfile, "%s: ", gettext(loglevels[minLogLevel]));
    len = VFPRINTF(logfile, format, args);
    fflush(logfile);
  } else
    len = VFPRINTF(stderr, format, args);
  va_end(args);
  if (bInited)
    MUTEX_UNLOCK(&logMutex);
  if (customLog) {
    char * txt;

    txt = MALLOC(len + 1);
    va_start(args, format);
    GNUNET_ASSERT(len == VSNPRINTF(txt, len, format, args));
    va_end(args);
    customLog(txt);
    FREE(txt);
  }
}

/**
 * errexit - log an error message and exit.
 *
 * @param format the string describing the error message
 */
void errexit(const char *format, ...) {
  va_list args;

  /* NO locking here, we're supposed to die,
     and we don't want to take chances on that... */
  if (logfile != NULL) {
    va_start(args, format);
    printTime();
    VFPRINTF(logfile, format, args);
    fflush(logfile);
    va_end(args);
  }
  if (logfile != stderr) {
    va_start(args, format);
#ifdef MINGW
    AllocConsole();
#endif
    VFPRINTF(stderr, format, args);
    va_end(args);
  }
  abort();
  exit(-1); /* just in case... */
}

void LOGHASH(size_t size,
	     const void * data) {
  HashCode512 hc;
  EncName enc;
  hash(data, size, &hc);
  hash2enc(&hc, &enc);
  LOG(LOG_DEBUG,
      "%u: %s\n",
      size,
      &enc);
}



int SNPRINTF(char * buf,
	     size_t size,
	     const char * format,
	     ...) {
  int ret;
  va_list args;

  va_start(args, format);
  ret = VSNPRINTF(buf,
		  size,
		  format,
		  args);
  va_end(args);
  GNUNET_ASSERT(ret <= size);
  return ret;
}



/* end of logging.c */
