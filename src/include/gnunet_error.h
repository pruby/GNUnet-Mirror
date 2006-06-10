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
 * @file include/gnunet_error.h
 * @brief error handling API
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_ERROR_H
#define GNUNET_ERROR_H

#define GNUNET_ERROR_VERSION 0x00000000

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

struct GE_Context;

struct GE_Memory;

typedef enum {
  /* type of event */
  GE_DEBUG     = 0x00000001, /* DEBUG/CRON/EVERYTHING */
  GE_STATUS    = 0x00000002, /* INFO/MESSAGE */
  GE_WARNING   = 0x00000004,
  GE_ERROR     = 0x00000008,
  GE_FATAL     = 0x00000010, /* FATAL/FAILURE/NOTHING */
  GE_EVENTKIND = 0x000000FF, /* bitmask */

  /* who should see the message? */
  GE_USER      = 0x01000000, /* current user, if possible */
  GE_ADMIN     = 0x02000000, /* system administrator */
  GE_USERKIND  = 0x0F000000, /* bitmask */

  /* how event should be routed */
  GE_REQUEST   = 0x20000000, /* display on request only (i.e. low-priority log, user demands verbose events) */
  GE_BULK      = 0x40000000, /* display in bulk output (i.e. log-file, scroll window, console) */
  GE_IMMEDIATE = 0x80000000, /* display immediately (i.e. pop-up, e-mail) */
  GE_ROUTEKIND = 0xF0000000, /* bitmask */
  GE_ALL       = 0xFFFFFFFF, 
} GE_MASK;


void GE_LOG(struct GE_Context * ctx,
	    GE_KIND kind,
	    const char * message,
	    ...);

/**
 * Create a context that sends events to two other contexts.
 * Note that the client must stop using ctx1/ctx2 henceforth.
 */
struct GE_Context * GE_create_context_multiplexer(struct GE_Context * ctx1,
						  struct GE_Context * ctx2);


/**
 * User-defined handler for Log events.
 */
typedef void (*GE_LogHandler)(void * ctx,
			      GE_MASK kind,
			      const char * date,
			      const char * msg);

/**
 * Create a log context that calls a callback function
 * for matching events.
 *
 * @param mask which events is this handler willing to process?
 *        an event must be non-zero in all 3 GE_MASK categories
 *        to be passed to this handler
 */
struct GE_Context * GE_create_context_callback(GE_MASK mask,
					       GE_LogHandler handler,
					       void * ctx);
				 
/**
 * Create a logger that writes events to a file.
 * 
 * @param mask which events should be logged?
 * @param filename which file should we log to?
 * @param logDate should the context log event dates?
 * @param logrotate after how many seconds should the log
 *        files be rotated (use 0 for no rotation)
 */
struct GE_Context * GE_create_context_logfile(GE_MASK mask,
					      const char * filename,
					      int logDate,
					      unsigned int logrotate);

/**
 * Create a logger that keeps events in memory (to be
 * queried later in bulk).
 */
struct GE_Context * GE_create_context_memory(GE_MASK mask,
					     struct GE_Memory * memory);

/**
 * Free a log context.
 */
void GE_free_context(GE_Context * ctx);					

#if FICTION      
/**
 * @param address e-mail address to send the logs to
 * @param server hostname of SMTP gateway, NULL for using local "mail" command
 * @param port port to use for SMTP
 * @param logDate should the date be each of the log lines?
 * @param bulkSize for GE_BULK messages, how many lines of messages
 *        should be accumulated before an e-mail is transmitted?
 */
struct GE_Context * GE_create_context_email(GE_MASK mask,
					    const char * address,
					    const char * server,
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
struct GE_Memory * GE_create_memory(unsigned int maxSize);

/**
 * For all messages stored in the memory, call the handler.
 */
void GE_poll_memory(struct GE_Memory * memory,
		    GE_LogHandler handler,
		    void * ctx);

void GE_free_memory(struct GE_Memory * memory);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
