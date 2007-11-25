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
 * if NULL is passed to GNUNET_GE_LOG.
 */
static struct GNUNET_GE_Context *defaultContext;

typedef struct GNUNET_GE_Context
{
  GNUNET_GE_KIND mask;
  GNUNET_GE_LogHandler handler;
  void *cls;
  GNUNET_GE_CtxFree destruct;
  GNUNET_GE_Confirm confirm;
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

void
GNUNET_GE_LOG (struct GNUNET_GE_Context *ctx, GNUNET_GE_KIND kind,
               const char *message, ...)
{
  va_list va;
  char date[64];
  time_t timetmp;
  struct tm *tmptr;
  size_t size;
  char *buf;

  if (ctx == NULL)
    ctx = defaultContext;

  if ((ctx != NULL) && (!GNUNET_GE_applies (kind, ctx->mask)))
    return;
  if ((ctx == NULL) &&
      (((kind & (GNUNET_GE_IMMEDIATE | GNUNET_GE_BULK)) == 0) ||
       ((kind & (GNUNET_GE_FATAL | GNUNET_GE_ERROR | GNUNET_GE_WARNING)) ==
        0)))
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

const char *
GNUNET_GE_strerror (int errnum)
{
  return STRERROR (errnum);
}
