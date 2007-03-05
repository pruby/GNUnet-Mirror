/*
     This file is part of GNUnet.
     (C) 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file src/util/loggers/memory.c
 * @brief logging to memory
 *
 * @author Christian Grothoff
 */
#include "gnunet_util_error_loggers.h"
#include "gnunet_util_string.h"
#include "gnunet_util.h"
#include "platform.h"

typedef struct GE_Message {
  char * date;
  char * msg;
  GE_KIND mask;
} GE_Message;

typedef struct GE_Memory {
  GE_Message * messages;
  struct MUTEX * lock;
  unsigned int maxSize;
  unsigned int size;
  unsigned int pos;
} GE_Memory;

static void
memorylogger(void * cls,
	     GE_KIND kind,
	     const char * date,
	     const char * msg) {
  GE_Memory * ctx = cls;
  unsigned int max;

  MUTEX_LOCK(ctx->lock);
  if (ctx->pos == ctx->size) {
    if ( (ctx->maxSize != 0) &&
	 (ctx->size == ctx->maxSize) ) {
      MUTEX_UNLOCK(ctx->lock);
      return;
    }
    max = ctx->pos * 2 + 16;
    if ( (ctx->maxSize == 0) &&
	 (max > ctx->maxSize) )
      max = ctx->maxSize;
    GROW(ctx->messages,
	 ctx->size,
	 max);
  }
  ctx->messages[ctx->pos].date = STRDUP(date);
  if (ctx->pos == ctx->maxSize-1) {
    ctx->messages[ctx->pos].msg = STRDUP(_("Out of memory (for logging)"));
    ctx->messages[ctx->pos].mask = GE_STATUS | GE_USER | GE_BULK;
  } else {
    ctx->messages[ctx->pos].msg = STRDUP(msg);
    ctx->messages[ctx->pos].mask = kind;
  }
  ctx->pos++;
  MUTEX_UNLOCK(ctx->lock);
}

/**
 * Create a logger that keeps events in memory (to be
 * queried later in bulk).
 */
struct GE_Context *
GE_create_context_memory(GE_KIND mask,
			 struct GE_Memory * memory) {
  return GE_create_context_callback(mask,
				    &memorylogger,
				    memory,
				    NULL,
				    NULL);
}

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
struct GE_Memory *
GE_memory_create(unsigned int maxSize) {
  GE_Memory * ret;

  ret = MALLOC(sizeof(GE_Memory));
  ret->maxSize = maxSize;
  ret->size = 0;
  ret->pos = 0;
  ret->messages = NULL;
  ret->lock = MUTEX_CREATE(NO);
  return ret;
}

/**
 * Get a particular log message from the store.
 */
const char *
GE_memory_get(struct GE_Memory * memory,
	      unsigned int index) {
  if (index > memory->pos || memory->messages == NULL)
    return NULL;
  return memory->messages[index].msg;
}

/**
 * For all messages stored in the memory, call the handler.
 * Also clears the memory.
 */
void GE_memory_poll(struct GE_Memory * memory,
		    GE_LogHandler handler,
		    void * ctx) {
  int i;

  MUTEX_LOCK(memory->lock);
  for (i=0;i<memory->pos;i++) {
    handler(ctx,
	    memory->messages[i].mask,
	    memory->messages[i].date,
	    memory->messages[i].msg);
    FREE(memory->messages[i].date);
    FREE(memory->messages[i].msg);
  }
  memory->pos = 0;
  MUTEX_UNLOCK(memory->lock);
}

void GE_memory_reset(struct GE_Memory * memory) {
  int i;

  MUTEX_LOCK(memory->lock);
  for (i=memory->pos-1;i>=0;i--) {
    FREE(memory->messages[i].date);
    FREE(memory->messages[i].msg);
  }
  GROW(memory->messages,
       memory->size,
       0);
  MUTEX_UNLOCK(memory->lock);
}

void GE_memory_free(struct GE_Memory * memory) {
  int i;

  MUTEX_DESTROY(memory->lock);
  for (i=memory->pos-1;i>=0;i--) {
    FREE(memory->messages[i].date);
    FREE(memory->messages[i].msg);
  }
  GROW(memory->messages,
       memory->size,
       0);
  FREE(memory);
}
