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
 * @file util/error/error.c
 * @brief error handling API
 *
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util.h"
#ifdef MINGW
#include <conio.h>
#endif

/**
 * After how many seconds do we always print
 * that "message X was repeated N times"?
 */
#define BULK_DELAY_THRESHOLD (90 * GNUNET_CRON_SECONDS)

/**
 * After how many repetitions do we always print
 * that "message X was repeated N times"? (even if
 * we have not yet reached the delay threshold)
 */
#define BULK_REPEAT_THRESHOLD 1000

/**
 * How many characters do we use for matching of
 * bulk messages?
 */
#define BULK_TRACK_SIZE 256

/**
 * How many characters can a date/time string
 * be at most?
 */
#define DATE_STR_SIZE 64



/**
 * Default context for logging errors; used
 * if NULL is passed to GNUNET_GE_LOG.
 */
static struct GNUNET_GE_Context *defaultContext;

typedef struct GNUNET_GE_Context
{
  /**
   * Mask that determines which events to log.
   */
  GNUNET_GE_KIND mask;

  /**
   * Handler to call for each event.
   */
  GNUNET_GE_LogHandler handler;

  /**
   * Extra argument to handler.
   */
  void *cls;

  /**
   * Function to call to destroy this context.
   */
  GNUNET_GE_CtxFree destruct;

  GNUNET_GE_Confirm confirm;

  /**
   * The last "bulk" error message that we have been logging.
   * Note that this message maybe truncated to the first BULK_TRACK_SIZE
   * characters, in which case it is NOT 0-terminated!
   */
  char last_bulk[BULK_TRACK_SIZE];

  /**
   * Type of the last bulk message.
   */
  GNUNET_GE_KIND last_bulk_kind;

  /**
   * Time of the last bulk error message (0 for none)
   */
  GNUNET_CronTime last_bulk_time;

  /**
   * Number of times that bulk message has been repeated since.
   */
  unsigned int last_bulk_repeat;

} GNUNET_GE_Context;

/**
 * Does the given event match the mask?
 * @param have the event type
 * @param mask the filter mask
 */
int
GNUNET_GE_applies (GNUNET_GE_KIND have, GNUNET_GE_KIND mask)
{
  GNUNET_GE_KIND both = mask & have;
  return ((both & GNUNET_GE_EVENTKIND) &&
          (both & GNUNET_GE_USERKIND) && (both & GNUNET_GE_ROUTEKIND));
}

static void
flush_bulk (struct GNUNET_GE_Context *ctx, const char *datestr)
{
  char msg[DATE_STR_SIZE + BULK_TRACK_SIZE + 256];
  GNUNET_CronTime now;
  int rev;
  char *last;
  
  if ( (ctx == NULL) ||
       (ctx->last_bulk_time == 0) || 
       (ctx->last_bulk_repeat == 0) )
    return;
  now = GNUNET_get_time ();
  rev = 0;
  last = memchr (ctx->last_bulk, '\0', BULK_TRACK_SIZE);
  if (last == NULL)
    last = &ctx->last_bulk[BULK_TRACK_SIZE - 1];
  else if (last != ctx->last_bulk)
    last--;
  if (last[0] == '\n')
    {
      rev = 1;
      last[0] = '\0';
    }
  snprintf (msg,
            sizeof (msg),
            _("Message `%.*s' repeated %u times in the last %llus\n"),
            BULK_TRACK_SIZE,
            ctx->last_bulk,
            ctx->last_bulk_repeat,
            (now - ctx->last_bulk_time) / GNUNET_CRON_SECONDS);
  if (rev == 1)
    last[0] = '\n';
  if (ctx != NULL)
    ctx->handler (ctx->cls, ctx->last_bulk_kind, datestr, msg);
  else
    fprintf (stderr, "%s %s", datestr, msg);
  ctx->last_bulk_time = now;
  ctx->last_bulk_repeat = 0;
}

void
GNUNET_GE_LOG (struct GNUNET_GE_Context *ctx, GNUNET_GE_KIND kind,
               const char *message, ...)
{
  va_list va;
  char date[DATE_STR_SIZE];
  time_t timetmp;
  struct tm *tmptr;
  size_t size;
  char *buf;
  GNUNET_CronTime now;

  if (ctx == NULL)
    ctx = defaultContext;

  if ((ctx != NULL) && (!GNUNET_GE_applies (kind, ctx->mask)))
    return;
  if ((ctx == NULL) &&
      (((kind & (GNUNET_GE_IMMEDIATE | GNUNET_GE_BULK)) == 0) ||
       ((kind & (GNUNET_GE_FATAL | GNUNET_GE_ERROR)) == 0)))
    return;

  va_start (va, message);
  size = VSNPRINTF (NULL, 0, message, va) + 1;
  va_end (va);
  buf = malloc (size);
  if (buf == NULL)
    return;                     /* oops */
  va_start (va, message);
  VSNPRINTF (buf, size, message, va);
  va_end (va);
  time (&timetmp);
  memset (date, 0, DATE_STR_SIZE);
  tmptr = localtime (&timetmp);
  strftime (date, DATE_STR_SIZE, "%b %d %H:%M:%S", tmptr);
  now = GNUNET_get_time ();
  if ((ctx != NULL) &&
      ((kind & GNUNET_GE_BULK) != 0))
    {
      if ((ctx->last_bulk_time != 0) &&
          (0 == strncmp (buf, ctx->last_bulk, sizeof (ctx->last_bulk))))
        {
          ctx->last_bulk_repeat++;
          if ((now - ctx->last_bulk_time > BULK_DELAY_THRESHOLD) ||
              (ctx->last_bulk_repeat > BULK_REPEAT_THRESHOLD))
            flush_bulk (ctx, date);
	  free (buf);
          return;
        }
      else
        {
          if (ctx->last_bulk_time != 0)
            flush_bulk (ctx, date);
          strncpy (ctx->last_bulk, buf, sizeof (ctx->last_bulk));
          ctx->last_bulk_repeat = 0;
          ctx->last_bulk_time = now;
          ctx->last_bulk_kind = kind;
        }
    }
  if ( (ctx != NULL) &&
       ((now - ctx->last_bulk_time > BULK_DELAY_THRESHOLD) ||
	(ctx->last_bulk_repeat > BULK_REPEAT_THRESHOLD)) )
    {
      flush_bulk (ctx, date);
      ctx->last_bulk_time = 0;
    }
  if (ctx != NULL)
    ctx->handler (ctx->cls, kind, date, buf);
  else
    fprintf (stderr, "%s %s", date, buf);
  free (buf);
}

/**
 * @brief Get user confirmation (e.g. before the app shuts down and closes the
 *        error message
 */
void
GNUNET_GE_CONFIRM (struct GNUNET_GE_Context *ctx)
{
  if (ctx == NULL)
    {
      /* @TODO: we probably ought to get confirmations in all graphical
         environments */
#ifdef WINDOWS
      /* Console open? */
      if (GetStdHandle (STD_ERROR_HANDLE) != NULL)
        {
          fprintf (stderr, _("\nPress any key to continue\n"));
          getch ();
        }
#endif
    }
  else if (ctx->confirm)
    ctx->confirm (ctx->cls);
}

/**
 * Create a log context that calls a callback function
 * for matching events.
 *
 * @param mask which events is this handler willing to process?
 *        an event must be non-zero in all 3 GNUNET_GE_KIND categories
 *        to be passed to this handler
 */
struct GNUNET_GE_Context *
GNUNET_GE_create_context_callback (GNUNET_GE_KIND mask,
                                   GNUNET_GE_LogHandler handler,
                                   void *ctx,
                                   GNUNET_GE_CtxFree liberator,
                                   GNUNET_GE_Confirm confirm)
{
  GNUNET_GE_Context *ret;

  ret = malloc (sizeof (GNUNET_GE_Context));
  if (ret == NULL)
    return NULL;
  memset (ret, 0, sizeof (GNUNET_GE_Context));
  ret->mask = mask;
  ret->handler = handler;
  ret->cls = ctx;
  ret->destruct = liberator;
  ret->confirm = confirm;
  return ret;
}

/**
 * Free a log context.
 */
void
GNUNET_GE_free_context (GNUNET_GE_Context * ctx)
{
  char date[DATE_STR_SIZE];
  time_t timetmp;
  struct tm *tmptr;

  if (ctx == NULL)
    return;
  time (&timetmp);
  memset (date, 0, DATE_STR_SIZE);
  tmptr = localtime (&timetmp);
  strftime (date, DATE_STR_SIZE, "%b %d %H:%M:%S", tmptr);
  flush_bulk (ctx, date);
  if (ctx->destruct != NULL)
    ctx->destruct (ctx->cls);
  free (ctx);
}

/**
 * Would an event of this kind be possibly
 * processed by the logger?
 * @param ctx the logger
 * @param have the kind of event
 */
int
GNUNET_GE_isLogged (GNUNET_GE_Context * ctx, GNUNET_GE_KIND kind)
{
  if (ctx == NULL)
    return GNUNET_YES;
  return GNUNET_GE_applies (kind, ctx->mask);
}

/**
 * Convert a textual description of a loglevel
 * to the respective GNUNET_GE_KIND.
 * @returns GNUNET_GE_INVALID if log does not parse
 */
GNUNET_GE_KIND
GNUNET_GE_getKIND (const char *log)
{
  if (0 == strcasecmp (log, _("DEBUG")))
    return GNUNET_GE_DEBUG;
  if (0 == strcasecmp (log, _("STATUS")))
    return GNUNET_GE_STATUS;
  if (0 == strcasecmp (log, _("WARNING")))
    return GNUNET_GE_WARNING;
  if (0 == strcasecmp (log, _("ERROR")))
    return GNUNET_GE_ERROR;
  if (0 == strcasecmp (log, _("FATAL")))
    return GNUNET_GE_FATAL;
  if (0 == strcasecmp (log, _("USER")))
    return GNUNET_GE_USER;
  if (0 == strcasecmp (log, _("ADMIN")))
    return GNUNET_GE_ADMIN;
  if (0 == strcasecmp (log, _("DEVELOPER")))
    return GNUNET_GE_DEVELOPER;
  if (0 == strcasecmp (log, _("REQUEST")))
    return GNUNET_GE_REQUEST;
  if (0 == strcasecmp (log, _("BULK")))
    return GNUNET_GE_BULK;
  if (0 == strcasecmp (log, _("IMMEDIATE")))
    return GNUNET_GE_IMMEDIATE;
  if (0 == strcasecmp (log, _("ALL")))
    return GNUNET_GE_ALL;

  return GNUNET_GE_INVALID;
}

/**
 * Convert KIND to String
 */
const char *
GNUNET_GE_kindToString (GNUNET_GE_KIND kind)
{
  if ((kind & GNUNET_GE_DEBUG) > 0)
    return _("DEBUG");
  if ((kind & GNUNET_GE_STATUS) > 0)
    return _("STATUS");
  if ((kind & GNUNET_GE_INFO) > 0)
    return _("INFO");
  if ((kind & GNUNET_GE_WARNING) > 0)
    return _("WARNING");
  if ((kind & GNUNET_GE_ERROR) > 0)
    return _("ERROR");
  if ((kind & GNUNET_GE_FATAL) > 0)
    return _("FATAL");
  if ((kind & GNUNET_GE_USER) > 0)
    return _("USER");
  if ((kind & GNUNET_GE_ADMIN) > 0)
    return _("ADMIN");
  if ((kind & GNUNET_GE_DEVELOPER) > 0)
    return _("DEVELOPER");
  if ((kind & GNUNET_GE_REQUEST) > 0)
    return _("REQUEST");
  if ((kind & GNUNET_GE_BULK) > 0)
    return _("BULK");
  if ((kind & GNUNET_GE_IMMEDIATE) > 0)
    return _("IMMEDIATE");
  return _("NOTHING");
}


typedef struct
{
  struct GNUNET_GE_Context *c1;
  struct GNUNET_GE_Context *c2;
} CPair;

static void
multiplexer (void *ctx, GNUNET_GE_KIND kind, const char *date,
             const char *msg)
{
  CPair *pair = ctx;

  if (GNUNET_GE_applies (kind, pair->c1->mask))
    pair->c1->handler (pair->c1->cls, kind, date, msg);
  if (GNUNET_GE_applies (kind, pair->c2->mask))
    pair->c2->handler (pair->c2->cls, kind, date, msg);
}

static void
multi_confirm (void *ctx)
{
  CPair *pair = ctx;

  if (pair->c1->confirm)
    pair->c1->confirm (pair->c1->cls);

  if (pair->c2->confirm)
    pair->c2->confirm (pair->c2->cls);
}

static void
pairdestruct (void *ctx)
{
  CPair *pair = ctx;

  GNUNET_GE_free_context (pair->c1);
  GNUNET_GE_free_context (pair->c2);
  free (ctx);
}

/**
 * Create a context that sends events to two other contexts.
 * Note that the client must stop using ctx1/ctx2 henceforth.
 */
struct GNUNET_GE_Context *
GNUNET_GE_create_context_multiplexer (struct GNUNET_GE_Context *ctx1,
                                      struct GNUNET_GE_Context *ctx2)
{
  CPair *cls;
  GNUNET_GE_Context *ret;

  cls = malloc (sizeof (CPair));
  if (cls == NULL)
    return NULL;
  cls->c1 = ctx1;
  cls->c2 = ctx2;
  ret = malloc (sizeof (GNUNET_GE_Context));
  if (ret == NULL)
    {
      free (cls);
      return NULL;
    }
  memset (ret, 0, sizeof (GNUNET_GE_Context));
  ret->cls = cls;
  ret->handler = &multiplexer;
  ret->mask = ctx1->mask | ctx2->mask;
  ret->destruct = &pairdestruct;
  ret->confirm = &multi_confirm;
  return ret;
}


void
GNUNET_GE_setDefaultContext (struct GNUNET_GE_Context *ctx)
{
  defaultContext = ctx;
}

/* end of error.c */
