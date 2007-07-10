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
 * @file util/error/error.c
 * @brief error handling API
 *
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_error.h"
#ifdef MINGW
#include <conio.h>
#endif
/**
 * Default context for logging errors; used
 * if NULL is passed to GE_LOG.
 */
static struct GE_Context *defaultContext;

typedef struct GE_Context
{
  GE_KIND mask;
  GE_LogHandler handler;
  void *cls;
  GE_CtxFree destruct;
  GE_Confirm confirm;
} GE_Context;

/**
 * Does the given event match the mask?
 * @param have the event type
 * @param mask the filter mask
 */
int
GE_applies (GE_KIND have, GE_KIND mask)
{
  GE_KIND both = mask & have;
  return ((both & GE_EVENTKIND) &&
          (both & GE_USERKIND) && (both & GE_ROUTEKIND));
}

void
GE_LOG (struct GE_Context *ctx, GE_KIND kind, const char *message, ...)
{
  va_list va;
  char date[64];
  time_t timetmp;
  struct tm *tmptr;
  size_t size;
  char *buf;

  if (ctx == NULL)
    ctx = defaultContext;

  if ((ctx != NULL) && (!GE_applies (kind, ctx->mask)))
    return;
  if ((ctx == NULL) &&
      (((kind & (GE_IMMEDIATE | GE_BULK)) == 0) ||
       ((kind & (GE_FATAL | GE_ERROR | GE_WARNING)) == 0)))
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
  memset (date, 0, 64);
  tmptr = localtime (&timetmp);
  strftime (date, 64, "%b %d %H:%M:%S", tmptr);
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
GE_CONFIRM (struct GE_Context *ctx)
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
 *        an event must be non-zero in all 3 GE_KIND categories
 *        to be passed to this handler
 */
struct GE_Context *
GE_create_context_callback (GE_KIND mask,
                            GE_LogHandler handler,
                            void *ctx,
                            GE_CtxFree liberator, GE_Confirm confirm)
{
  GE_Context *ret;

  ret = malloc (sizeof (GE_Context));
  if (ret == NULL)
    return NULL;
  memset (ret, 0, sizeof (GE_Context));
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
GE_free_context (GE_Context * ctx)
{
  if (ctx == NULL)
    return;
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
GE_isLogged (GE_Context * ctx, GE_KIND kind)
{
  if (ctx == NULL)
    return YES;
  return GE_applies (kind, ctx->mask);
}

/**
 * Convert a textual description of a loglevel
 * to the respective GE_KIND.
 * @returns GE_INVALID if log does not parse
 */
GE_KIND
GE_getKIND (const char *log)
{
  if (0 == strcasecmp (log, _("DEBUG")))
    return GE_DEBUG;
  if (0 == strcasecmp (log, _("STATUS")))
    return GE_STATUS;
  if (0 == strcasecmp (log, _("WARNING")))
    return GE_WARNING;
  if (0 == strcasecmp (log, _("ERROR")))
    return GE_ERROR;
  if (0 == strcasecmp (log, _("FATAL")))
    return GE_FATAL;
  if (0 == strcasecmp (log, _("USER")))
    return GE_USER;
  if (0 == strcasecmp (log, _("ADMIN")))
    return GE_ADMIN;
  if (0 == strcasecmp (log, _("DEVELOPER")))
    return GE_DEVELOPER;
  if (0 == strcasecmp (log, _("REQUEST")))
    return GE_REQUEST;
  if (0 == strcasecmp (log, _("BULK")))
    return GE_BULK;
  if (0 == strcasecmp (log, _("IMMEDIATE")))
    return GE_IMMEDIATE;
  if (0 == strcasecmp (log, _("ALL")))
    return GE_ALL;

  return GE_INVALID;
}

/**
 * Convert KIND to String
 */
const char *
GE_kindToString (GE_KIND kind)
{
  if ((kind & GE_DEBUG) > 0)
    return _("DEBUG");
  if ((kind & GE_STATUS) > 0)
    return _("STATUS");
  if ((kind & GE_INFO) > 0)
    return _("INFO");
  if ((kind & GE_WARNING) > 0)
    return _("WARNING");
  if ((kind & GE_ERROR) > 0)
    return _("ERROR");
  if ((kind & GE_FATAL) > 0)
    return _("FATAL");
  if ((kind & GE_USER) > 0)
    return _("USER");
  if ((kind & GE_ADMIN) > 0)
    return _("ADMIN");
  if ((kind & GE_DEVELOPER) > 0)
    return _("DEVELOPER");
  if ((kind & GE_REQUEST) > 0)
    return _("REQUEST");
  if ((kind & GE_BULK) > 0)
    return _("BULK");
  if ((kind & GE_IMMEDIATE) > 0)
    return _("IMMEDIATE");
  return _("NOTHING");
}


typedef struct
{
  struct GE_Context *c1;
  struct GE_Context *c2;
} CPair;

static void
multiplexer (void *ctx, GE_KIND kind, const char *date, const char *msg)
{
  CPair *pair = ctx;

  if (GE_applies (kind, pair->c1->mask))
    pair->c1->handler (pair->c1->cls, kind, date, msg);
  if (GE_applies (kind, pair->c2->mask))
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

  GE_free_context (pair->c1);
  GE_free_context (pair->c2);
  free (ctx);
}

/**
 * Create a context that sends events to two other contexts.
 * Note that the client must stop using ctx1/ctx2 henceforth.
 */
struct GE_Context *
GE_create_context_multiplexer (struct GE_Context *ctx1,
                               struct GE_Context *ctx2)
{
  CPair *cls;
  GE_Context *ret;

  cls = malloc (sizeof (CPair));
  if (cls == NULL)
    return NULL;
  cls->c1 = ctx1;
  cls->c2 = ctx2;
  ret = malloc (sizeof (GE_Context));
  if (ret == NULL)
    {
      free (cls);
      return NULL;
    }
  memset (ret, 0, sizeof (GE_Context));
  ret->cls = cls;
  ret->handler = &multiplexer;
  ret->mask = ctx1->mask | ctx2->mask;
  ret->destruct = &pairdestruct;
  ret->confirm = &multi_confirm;
  return ret;
}


void
GE_setDefaultContext (struct GE_Context *ctx)
{
  defaultContext = ctx;
}

const char *
GE_strerror (int errnum)
{
  return STRERROR (errnum);
}
