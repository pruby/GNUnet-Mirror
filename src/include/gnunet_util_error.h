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
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_common.h"

/**
 * Context required to log messages.
 */
struct GNUNET_GE_Context;

/**
 * Classes of log messages.
 */
typedef enum
{
  GNUNET_GE_NOTHING = 0x00000000,
  /* type of event */
  GNUNET_GE_FATAL = 0x00000001, /* FATAL/FAILURE/NOTHING */
  GNUNET_GE_ERROR = 0x00000002,
  GNUNET_GE_WARNING = 0x00000004,
  GNUNET_GE_INFO = 0x00000008,  /* normal program response */
  GNUNET_GE_STATUS = 0x00000010,        /* status message */
  GNUNET_GE_DEBUG = 0x00000020, /* DEBUG/CRON/EVERYTHING */
  GNUNET_GE_EVENTKIND = 0x000000FF,     /* bitmask */

  /* who should see the message? */
  /**
   * These messages are sent to the console / UI.
   * Note that when running as an administrative
   * daemon, messages tagged just as GNUNET_GE_USER will
   * be discarded.
   */
  GNUNET_GE_USER = 0x01000000,  /* current user, if possible */
  /**
   * These messages are sent to the logfile for the
   * administrator.  Note that normal users may not
   * always look there.
   */
  GNUNET_GE_ADMIN = 0x02000000, /* system administrator */
  /**
   * These messages are usually not logged or given
   * to the user.  They can be obtained when the tool
   * is run in debug mode.
   */
  GNUNET_GE_DEVELOPER = 0x04000000,     /* GNUnet developers (bug!) */
  /**
   * Mask for the type of user that should see the
   * message.
   */
  GNUNET_GE_USERKIND = 0x0F000000,      /* bitmask */

  /* how event should be routed */
  /**
   * The message should only be shown upon specific
   * request.
   */
  GNUNET_GE_REQUEST = 0x20000000,       /* display on request only (i.e. low-priority log, user demands verbose events) */
  /**
   * This type of message is not urgent and is likely
   * to occur in bulk.  Suitable for logging to a file
   * or in a generic, scrolling message window.
   */
  GNUNET_GE_BULK = 0x40000000,  /* display in bulk output (i.e. log-file, scroll window, console) */
  /**
   * This is a message that is urgent and should be
   * communicated as soon as possible.  Sending an
   * e-mail alert or opening a pop-up window maybe
   * appropriate.
   */
  GNUNET_GE_IMMEDIATE = 0x80000000,     /* display immediately (i.e. pop-up, e-mail) */
  /**
   * Mask for the routing type.
   */
  GNUNET_GE_ROUTEKIND = 0xF0000000,     /* bitmask */
  GNUNET_GE_ALL = 0xFFFFFFFF,
  GNUNET_GE_INVALID = 0x08000000,       /* unused bit */
} GNUNET_GE_KIND;

void GNUNET_GE_LOG (struct GNUNET_GE_Context *ctx, GNUNET_GE_KIND kind,
                    const char *message, ...);

/**
 * @brief Get user confirmation (e.g. before the app shuts down and closes the
 *        error message
 */
void GNUNET_GE_CONFIRM (struct GNUNET_GE_Context *ctx);

void GNUNET_GE_setDefaultContext (struct GNUNET_GE_Context *ctx);

/**
 * User-defined handler for log events.
 */
typedef void (*GNUNET_GE_LogHandler) (void *ctx,
                                      GNUNET_GE_KIND kind,
                                      const char *date, const char *msg);

/**
 * User-defined method to free handler context.
 */
typedef void (*GNUNET_GE_CtxFree) (void *ctx);

/**
 * User-defined method to wait for user confirmation
 */
typedef void (*GNUNET_GE_Confirm) (void *ctx);

/**
 * Create a log context that calls a callback function
 * for matching events.
 *
 * @param mask which events is this handler willing to process?
 *        an event must be non-zero in all 3 GNUNET_GE_MASK categories
 *        to be passed to this handler
 * @param liberator callback to free ctx, maybe NULL
 */
struct GNUNET_GE_Context *GNUNET_GE_create_context_callback (GNUNET_GE_KIND
                                                             mask,
                                                             GNUNET_GE_LogHandler
                                                             handler,
                                                             void *ctx,
                                                             GNUNET_GE_CtxFree
                                                             liberator,
                                                             GNUNET_GE_Confirm
                                                             confirm);

/**
 * Free a log context.
 */
void GNUNET_GE_free_context (struct GNUNET_GE_Context *ctx);

/**
 * Does the given event match the mask?
 *
 * @param have the event type
 * @param mask the filter mask
 * @return GNUNET_YES or GNUNET_NO
 */
int GNUNET_GE_applies (GNUNET_GE_KIND have, GNUNET_GE_KIND mask);

/**
 * Would an event of this kind be possibly
 * processed by the logger?
 *
 * @param ctx the logger
 * @param have the kind of event
 * @return GNUNET_YES or GNUNET_NO
 */
int GNUNET_GE_isLogged (struct GNUNET_GE_Context *ctx, GNUNET_GE_KIND kind);

/**
 * Convert a textual description of a loglevel
 * to the respective GNUNET_GE_KIND.
 * @returns GNUNET_GE_INVALID if log does not parse
 */
GNUNET_GE_KIND GNUNET_GE_getKIND (const char *log);

/**
 * Convert KIND to String
 */
const char *GNUNET_GE_kindToString (GNUNET_GE_KIND kind);

/**
 * Create a context that sends events to two other contexts.
 * Note that the client must stop using ctx1/ctx2 henceforth.
 */
struct GNUNET_GE_Context *GNUNET_GE_create_context_multiplexer (struct
                                                                GNUNET_GE_Context
                                                                *ctx1,
                                                                struct
                                                                GNUNET_GE_Context
                                                                *ctx2);

/**
 * If this context would log an event of the given kind,
 * execute statement "a".
 */
#define IF_GELOG(ctx, kind, a) do { if (GNUNET_GE_isLogged(ctx, kind)) { a; } } while(0)

/**
 * Use this for fatal errors that cannot be handled
 */
#define GNUNET_GE_ASSERT(ctx, cond) do { if (! (cond)) { GNUNET_GE_LOG(ctx, (GNUNET_GE_KIND) (GNUNET_GE_DEVELOPER | GNUNET_GE_USER | GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE), _("Internal error: assertion failed at %s:%d.\n"), __FILE__, __LINE__); GNUNET_GE_CONFIRM(ctx); abort(); } } while(0)

/**
 * Use this for fatal errors that cannot be handled
 */
#define GNUNET_GE_ASSERT_FL(ctx, cond, f, l) do { if (! (cond)) { GNUNET_GE_LOG(ctx, (GNUNET_GE_KIND) (GNUNET_GE_DEVELOPER | GNUNET_GE_USER | GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE), _("Internal error: assertion failed at %s:%d.\n"), f, l); GNUNET_GE_CONFIRM(ctx); abort(); } } while(0)

/**
 * Use this for internal assertion violations that are
 * not fatal (can be handled) but should not occur.
 */
#define GNUNET_GE_BREAK(ctx, cond)  do { if (! (cond)) { GNUNET_GE_LOG(ctx, (GNUNET_GE_KIND) (GNUNET_GE_DEVELOPER | GNUNET_GE_USER | GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE), _("Internal error: assertion failed at %s:%d.\n"), __FILE__, __LINE__); } } while(0)

#define GNUNET_GE_BREAK_RETURN(ctx, cond, retval)  do { if (! (cond)) { GNUNET_GE_LOG(ctx, (GNUNET_GE_KIND) (GNUNET_GE_DEVELOPER | GNUNET_GE_USER | GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE), _("Internal error: assertion failed at %s:%d.\n"), __FILE__, __LINE__); return retval; } } while(0)

/**
 * Use this for assertion violations caused by other
 * peers (i.e. protocol violations).  We do not want to
 * confuse end-users (say, some other peer runs an
 * older, broken or incompatible GNUnet version), but
 * we still want to see these problems during
 * development and testing.  "OP == other peer".
 */
#define GNUNET_GE_BREAK_OP(ctx, cond)  do { if (! (cond)) { GNUNET_GE_LOG(ctx, (GNUNET_GE_KIND) (GNUNET_GE_DEVELOPER | GNUNET_GE_FATAL | GNUNET_GE_IMMEDIATE), _("External protocol violation: assertion failed at %s:%d (no need to panic, we can handle this).\n"), __FILE__, __LINE__); } } while(0)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GNUNET_GE_LOG_STRERROR(ctx, level, cmd) do { GNUNET_GE_LOG(ctx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, STRERROR(errno)); } while(0)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GNUNET_GE_DIE_STRERROR(ctx, level, cmd) do { GNUNET_GE_LOG(ctx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, STRERROR(errno)); GNUNET_GE_CONFIRM(ctx); abort(); } while(0)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GNUNET_GE_DIE_STRERROR_FL(ctx, level, cmd, f, l) do { GNUNET_GE_LOG(ctx, level, _("`%s' failed at %s:%d with error: %s\n"), cmd, f, l, STRERROR(errno)); GNUNET_GE_CONFIRM(ctx); abort(); } while(0)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define GNUNET_GE_LOG_STRERROR_FILE(ctx, level, cmd, filename) do { GNUNET_GE_LOG(ctx, level, _("`%s' failed on file `%s' at %s:%d with error: %s\n"), cmd, filename,__FILE__, __LINE__, STRERROR(errno)); } while(0)

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define GNUNET_GE_DIE_STRERROR_FILE(ctx, level, cmd, filename) do { GNUNET_GE_LOG(ctx, level, _("`%s' failed on file `%s' at %s:%d with error: %s\n"), cmd, filename,__FILE__, __LINE__, STRERROR(errno)); GNUNET_GE_CONFIRM(ctx); abort(); } while(0)


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
