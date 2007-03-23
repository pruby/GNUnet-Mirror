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
 * @file include/gnunet_util_error.h
 * @brief error handling API
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_UTIL_ERROR_H
#define GNUNET_UTIL_ERROR_H

#define GNUNET_UTIL_ERROR_VERSION 0x00000000

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_common.h"

/**
 * Context required to log messages.
 */
struct GE_Context;

/**
 * Classes of log messages.
 */
typedef enum {
  GE_NOTHING   = 0x00000000,
  /* type of event */
  GE_DEBUG     = 0x00000001, /* DEBUG/CRON/EVERYTHING */
  GE_STATUS    = 0x00000002, /* status message */
  GE_INFO      = 0x00000004, /* normal program response */
  GE_WARNING   = 0x00000008,
  GE_ERROR     = 0x00000010,
  GE_FATAL     = 0x00000020, /* FATAL/FAILURE/NOTHING */
  GE_EVENTKIND = 0x000000FF, /* bitmask */

  /* who should see the message? */
  GE_USER      = 0x01000000, /* current user, if possible */
  GE_ADMIN     = 0x02000000, /* system administrator */
  GE_DEVELOPER = 0x04000000, /* GNUnet developers (bug!) */
  GE_USERKIND  = 0x0F000000, /* bitmask */

  /* how event should be routed */
  GE_REQUEST   = 0x20000000, /* display on request only (i.e. low-priority log, user demands verbose events) */
  GE_BULK      = 0x40000000, /* display in bulk output (i.e. log-file, scroll window, console) */
  GE_IMMEDIATE = 0x80000000, /* display immediately (i.e. pop-up, e-mail) */
  GE_ROUTEKIND = 0xF0000000, /* bitmask */
  GE_ALL       = 0xFFFFFFFF,
  GE_INVALID   = 0x08000000, /* unused bit */
} GE_KIND;

void GE_LOG(struct GE_Context * ctx,
	    GE_KIND kind,
	    const char * message,
	    ...);

/**
 * @brief Get user confirmation (e.g. before the app shuts down and closes the
 *        error message
 */
void GE_CONFIRM(struct GE_Context * ctx);

void GE_setDefaultContext(struct GE_Context * ctx);

/**
 * User-defined handler for Log events.
 */
typedef void (*GE_LogHandler)(void * ctx,
			      GE_KIND kind,
			      const char * date,
			      const char * msg);

/**
 * User-defined method to free handler context.
 */
typedef void (*GE_CtxFree)(void * ctx);

/**
 * User-defined method to wait for user confirmation
 */
typedef void (*GE_Confirm)(void * ctx);

/**
 * Create a log context that calls a callback function
 * for matching events.
 *
 * @param mask which events is this handler willing to process?
 *        an event must be non-zero in all 3 GE_MASK categories
 *        to be passed to this handler
 * @param liberator callback to free ctx, maybe NULL
 */
struct GE_Context *
GE_create_context_callback(GE_KIND mask,
			   GE_LogHandler handler,
			   void * ctx,
			   GE_CtxFree liberator,
			   GE_Confirm confirm);

/**
 * Free a log context.
 */
void GE_free_context(struct GE_Context * ctx);					

/**
 * Does the given event match the mask?
 *
 * @param have the event type
 * @param mask the filter mask
 * @return YES or NO
 */
int GE_applies(GE_KIND have,
	       GE_KIND mask);

/**
 * Would an event of this kind be possibly
 * processed by the logger?
 *
 * @param ctx the logger
 * @param have the kind of event
 * @return YES or NO
 */
int GE_isLogged(struct GE_Context * ctx,
		GE_KIND kind);

/**
 * Convert a textual description of a loglevel
 * to the respective GE_KIND.
 * @returns GE_INVALID if log does not parse
 */
GE_KIND GE_getKIND(const char * log);

/**
 * Convert KIND to String
 */
const char * GE_kindToString(GE_KIND kind);

/**
 * Create a context that sends events to two other contexts.
 * Note that the client must stop using ctx1/ctx2 henceforth.
 */
struct GE_Context *
GE_create_context_multiplexer(struct GE_Context * ctx1,
			      struct GE_Context * ctx2);

const char *GE_strerror(int errnum);

/**
 * If this context would log an event of the given kind,
 * execute statement "a".
 */
#define IF_GELOG(ctx, kind, a) do { if (GE_isLogged(ctx, kind)) { a; } } while(0);

#define GE_ASSERT(ctx, cond) do { if (! (cond)) { GE_LOG(ctx, GE_DEVELOPER | GE_USER | GE_FATAL | GE_IMMEDIATE, _("Internal error: assertion failed at %s:%d in %s.\n"), __FILE__, __LINE__, __FUNCTION__); GE_CONFIRM(ctx); abort(); } } while(0);

#define GE_ASSERT_FLF(ctx, cond, file, line, function) do { if (! (cond)) { GE_LOG(ctx, GE_DEVELOPER | GE_USER | GE_FATAL | GE_IMMEDIATE, _("Internal error: assertion failed at %s:%d in %s.\n"), file, line, function); GE_CONFIRM(ctx); abort(); } } while(0);

#define GE_BREAK(ctx, cond)  do { if (! (cond)) { GE_LOG(ctx, GE_DEVELOPER | GE_USER | GE_FATAL | GE_IMMEDIATE, _("Internal error: assertion failed at %s:%d in %s.\n"), __FILE__, __LINE__, __FUNCTION__); } } while(0);

#define GE_BREAK_FLF(ctx, cond, file, line, function)  do { if (! (cond)) { GE_LOG(ctx, GE_DEVELOPER | GE_USER | GE_FATAL | GE_IMMEDIATE, _("Internal error: assertion failed at %s:%d in %s.\n"), file, line, function); } } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GE_LOG_STRERROR(ctx, level, cmd) do { GE_LOG(ctx, level, _("`%s' failed at %s:%d in %s with error: %s\n"), cmd, __FILE__, __LINE__, __FUNCTION__, STRERROR(errno)); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GE_DIE_STRERROR(ctx, level, cmd) do { GE_LOG(ctx, level, _("`%s' failed at %s:%d in %s with error: %s\n"), cmd, __FILE__, __LINE__, __FUNCTION__, STRERROR(errno)); GE_CONFIRM(ctx); abort(); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GE_DIE_STRERROR_FLF(ctx, level, cmd, file, line, function) do { GE_LOG(ctx, level, _("`%s' failed at %s:%d in %s with error: %s\n"), cmd, file, line, function, STRERROR(errno)); GE_CONFIRM(ctx); abort(); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GE_LOG_STRERROR_FLF(ctx, level, cmd, file, line, function) do { GE_LOG(ctx, level, _("`%s' failed at %s:%d in %s with error: %s\n"), cmd, file, line, function, STRERROR(errno)); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GE_LOG_STRERROR_FILE(ctx, level, cmd, filename) do { GE_LOG(ctx, level, _("`%s' failed on file `%s' at %s:%d in %s with error: %s\n"), cmd, filename,__FILE__, __LINE__, __FUNCTION__, STRERROR(errno)); } while(0);

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define GE_DIE_STRERROR_FILE(ctx, level, cmd, filename) do { GE_LOG(ctx, level, _("`%s' failed on file `%s' at %s:%d in %s with error: %s\n"), cmd, filename,__FILE__, __LINE__, __FUNCTION__, STRERROR(errno)); GE_CONFIRM(ctx); abort(); } while(0);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
