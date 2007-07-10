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
 * @file include/gnunet_util_error_loggers.h
 * @brief error handling, code that provides loggers
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_UTIL_ERROR_LOGGERS_H
#define GNUNET_UTIL_ERROR_LOGGERS_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_error.h"

struct GE_Memory;


/**
 * Create a logger that writes events to a file.
 *
 * @param ectx where to log errors in the logger
 * @param mask which events should be logged?
 * @param filename which file should we log to?
 * @param logDate should the context log event dates?
 * @param logrotate should logs be rotated (if so, this
 *        value specifies after how many days logs should be deleted)
 *        (use 0 for no rotation)
 */
struct GE_Context *GE_create_context_logfile (struct GE_Context *ectx,
                                              GE_KIND mask,
                                              const char *filename,
                                              int logDate, int logrotate);


/**
 * Create a logger that writes events to stderr
 *
 * @param mask which events should be logged?
 */
struct GE_Context *GE_create_context_stderr (int logDate, GE_KIND mask);

/**
 * Create a logger that writes events to stderr
 *
 * @param mask which events should be logged?
 */
struct GE_Context *GE_create_context_stdout (int logDate, GE_KIND mask);

/**
 * Create a logger that keeps events in memory (to be
 * queried later in bulk).
 */
struct GE_Context *GE_create_context_memory (GE_KIND mask,
                                             struct GE_Memory *memory);

#if FICTION
/**
 * @param ectx where to log errors in the logger
 * @param address e-mail address to send the logs to
 * @param server hostname of SMTP gateway, NULL for using local "mail" command
 * @param port port to use for SMTP
 * @param logDate should the date be each of the log lines?
 * @param bulkSize for GE_BULK messages, how many lines of messages
 *        should be accumulated before an e-mail is transmitted?
 */
struct GE_Context *GE_create_context_email (struct GE_Context *ectx,
                                            GE_KIND mask,
                                            const char *address,
                                            const char *server,
                                            unsigned short port,
                                            int logDate,
                                            unsigned int bulkSize);
#endif

/**
 * Create a context to log messages in memory.
 * This is useful if we first need to capture all
 * log messages of an operation to provide the
 * final error in bulk to the client (i.e. as
 * a return value, possibly over the network).
 *
 * @param maxSize the maximum number of messages to keep, 0 for unbounded
 *  (if more than maxSize messages are received, message number maxSize
 *   will be set to a corresponding warning)
 */
struct GE_Memory *GE_memory_create (unsigned int maxSize);

/**
 * For all messages stored in the memory, call the handler.
 * Also clears the memory.
 */
void GE_memory_poll (struct GE_Memory *memory,
                     GE_LogHandler handler, void *ctx);

void GE_memory_reset (struct GE_Memory *memory);

/**
 * Get a particular log message from the store.
 */
const char *GE_memory_get (struct GE_Memory *memory, unsigned int index);

void GE_memory_free (struct GE_Memory *memory);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
