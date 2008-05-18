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

typedef struct GNUNET_GE_Message
{
  char *date;
  char *msg;
  GNUNET_GE_KIND mask;
} GNUNET_GE_Message;

typedef struct GNUNET_GE_Memory
{
  GNUNET_GE_Message *messages;
  struct GNUNET_Mutex *lock;
  unsigned int maxSize;
  unsigned int size;
  unsigned int pos;
} GNUNET_GE_Memory;

static void
memorylogger (void *cls, GNUNET_GE_KIND kind, const char *date,
              const char *msg)
{
  GNUNET_GE_Memory *ctx = cls;
  unsigned int max;

  GNUNET_mutex_lock (ctx->lock);
  if (ctx->pos == ctx->size)
    {
      if ((ctx->maxSize != 0) && (ctx->size == ctx->maxSize))
        {
          GNUNET_mutex_unlock (ctx->lock);
          return;
        }
      max = ctx->pos * 2 + 16;
      if ((ctx->maxSize == 0) && (max > ctx->maxSize))
        max = ctx->maxSize;
      GNUNET_array_grow (ctx->messages, ctx->size, max);
    }
  ctx->messages[ctx->pos].date = GNUNET_strdup (date);
  if (ctx->pos == ctx->maxSize - 1)
    {
      ctx->messages[ctx->pos].msg =
        GNUNET_strdup (_("Out of memory (for logging)\n"));
      ctx->messages[ctx->pos].mask =
        GNUNET_GE_STATUS | GNUNET_GE_USER | GNUNET_GE_BULK;
    }
  else
    {
      ctx->messages[ctx->pos].msg = GNUNET_strdup (msg);
      ctx->messages[ctx->pos].mask = kind;
    }
  ctx->pos++;
  GNUNET_mutex_unlock (ctx->lock);
}

/**
 * Create a logger that keeps events in memory (to be
 * queried later in bulk).
 */
struct GNUNET_GE_Context *
GNUNET_GE_create_context_memory (GNUNET_GE_KIND mask,
                                 struct GNUNET_GE_Memory *memory)
{
  return GNUNET_GE_create_context_callback (mask, &memorylogger, memory, NULL,
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
struct GNUNET_GE_Memory *
GNUNET_GE_memory_create (unsigned int maxSize)
{
  GNUNET_GE_Memory *ret;

  ret = GNUNET_malloc (sizeof (GNUNET_GE_Memory));
  ret->maxSize = maxSize;
  ret->size = 0;
  ret->pos = 0;
  ret->messages = NULL;
  ret->lock = GNUNET_mutex_create (GNUNET_NO);
  return ret;
}

/**
 * Get a particular log message from the store.
 */
const char *
GNUNET_GE_memory_get (struct GNUNET_GE_Memory *memory, unsigned int index)
{
  if (index > memory->pos || memory->messages == NULL)
    return NULL;
  return memory->messages[index].msg;
}

/**
 * For all messages stored in the memory, call the handler.
 * Also clears the memory.
 */
void
GNUNET_GE_memory_poll (struct GNUNET_GE_Memory *memory,
                       GNUNET_GE_LogHandler handler, void *ctx)
{
  int i;

  GNUNET_mutex_lock (memory->lock);
  for (i = 0; i < memory->pos; i++)
    {
      handler (ctx,
               memory->messages[i].mask,
               memory->messages[i].date, memory->messages[i].msg);
      GNUNET_free (memory->messages[i].date);
      GNUNET_free (memory->messages[i].msg);
    }
  memory->pos = 0;
  GNUNET_mutex_unlock (memory->lock);
}

void
GNUNET_GE_memory_reset (struct GNUNET_GE_Memory *memory)
{
  int i;

  GNUNET_mutex_lock (memory->lock);
  for (i = memory->pos - 1; i >= 0; i--)
    {
      GNUNET_free (memory->messages[i].date);
      GNUNET_free (memory->messages[i].msg);
    }
  GNUNET_array_grow (memory->messages, memory->size, 0);
  GNUNET_mutex_unlock (memory->lock);
}

void
GNUNET_GE_memory_free (struct GNUNET_GE_Memory *memory)
{
  int i;

  GNUNET_mutex_destroy (memory->lock);
  for (i = memory->pos - 1; i >= 0; i--)
    {
      GNUNET_free (memory->messages[i].date);
      GNUNET_free (memory->messages[i].msg);
    }
  GNUNET_array_grow (memory->messages, memory->size, 0);
  GNUNET_free (memory);
}
