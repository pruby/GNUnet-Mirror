/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/string/xmalloc.c
 * @brief wrapper around malloc/free
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_string.h"
#include "gnunet_util_error.h"

#ifndef INT_MAX
#define INT_MAX 0x7FFFFFFF
#endif

#define RECORD_USAGE 1
#define WRITE_MEM_STATS 1

#if RECORD_USAGE
volatile unsigned long long GNUNET_memory_usage = 0;
#endif

#if WRITE_MEM_STATS
  struct GNUNET_MultiHashMap *map;

  typedef struct
  {
    char *filename;
    int line;
    size_t size;
  } GNUNET_MemBlock;
#endif

#if WRITE_MEM_STATS
static void __attribute__ ((constructor)) xmalloc_init()
  {
    map = GNUNET_multi_hash_map_create (50);
    GNUNET_GE_ASSERT (NULL, map);
  }

static int map_iter (const GNUNET_HashCode *key, void *value, void *cls)
  {
    GNUNET_MemBlock *block;

    block = (GNUNET_MemBlock *) value;

    FPRINTF ((FILE *) cls, "%p;%u;%s:%u\n", key, block->size, block->filename, block->line);
    return GNUNET_YES;
  }

static void __attribute__ ((destructor)) xmalloc_deinit()
  {
    FILE *f;
    char fn[4097], *path;

#ifdef MINGW
    path = getenv ("USERPROFILE");
#else
    path = getenv ("HOME");
#endif

    snprintf (fn, 4096, "%s/gnunet_mem_stats.txt", path);
    f = FOPEN (fn, "w");
    if (!f)
      {
        PRINTF ("Cannot write memory statistics to %s: %s\n", fn, STRERROR(errno));
        return;
      }

    FPRINTF (f, "Total: %llu\n\n", GNUNET_memory_usage);
    fprintf (f, "ptr;size;source\n");
    GNUNET_multi_hash_map_iterate (map, map_iter, f);
    fputs ("\n*** end ***\n", f);

    GNUNET_free (fn);
    fclose (f);
  }
#endif

/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.
 *
 * @param size how many bytes of memory to allocate, do NOT use
 *  this function (or GNUNET_malloc) to allocate more than several MB
 *  of memory, if you are possibly needing a very large chunk use
 *  GNUNET_xmalloc_unchecked_ instead.
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 * @return pointer to size bytes of memory
 */
void *
GNUNET_xmalloc_ (size_t size, const char *filename, int linenumber)
{
  /* As a security precaution, we generally do not allow very large
     allocations using the default 'GNUNET_malloc' macro */
  GNUNET_GE_ASSERT_FL (NULL,
                       size <= GNUNET_MAX_GNUNET_malloc_CHECKED, filename,
                       linenumber);
  return GNUNET_xmalloc_unchecked_ (size, filename, linenumber);
}

void *
GNUNET_xmalloc_unchecked_ (size_t size, const char *filename, int linenumber)
{
  void *result;
#if WRITE_MEM_STATS
  GNUNET_HashCode key;
  GNUNET_MemBlock *block;
#endif

  GNUNET_GE_ASSERT_FL (NULL, size < INT_MAX, filename, linenumber);

#if RECORD_USAGE
  size += sizeof (size_t);
#endif

  result = malloc (size);
  if (result == NULL)
    GNUNET_GE_DIE_STRERROR_FL (NULL,
                               GNUNET_GE_IMMEDIATE | GNUNET_GE_USER |
                               GNUNET_GE_DEVELOPER | GNUNET_GE_FATAL,
                               "malloc", filename, linenumber);

#if RECORD_USAGE
  size -= sizeof (size_t);
  *((size_t *) result) = size;
  result += sizeof (size_t);
  GNUNET_memory_usage += size;
#if WRITE_MEM_STATS
  if (!map)
    xmalloc_init();

  memset (&key, 0, sizeof (GNUNET_HashCode));
  memcpy (&key, result, sizeof (void *));
  block = GNUNET_multi_hash_map_get (map, &key);
  if (block)
    block->size += size;
  else
    {
      block = malloc (sizeof (GNUNET_MemBlock));
      block->filename = strdup (filename);
      block->line = linenumber;
      block->size = size;
      GNUNET_GE_ASSERT (NULL, GNUNET_multi_hash_map_put (map, &key, block, GNUNET_MultiHashMapOption_UNIQUE_ONLY) == GNUNET_YES);
    }
#endif
#endif

  memset (result, 0, size);     /* client code should not rely on this, though... */
  return result;
}

/**
 * Reallocate memory. Checks the return value, aborts if no more
 * memory is available.
 *
 * @ptr the pointer to reallocate
 * @param size how many bytes of memory to allocate, do NOT use
 *  this function (or GNUNET_malloc) to allocate more than several MB
 *  of memory
 * @param filename where in the code was the call to GNUNET_realloc
 * @param linenumber where in the code was the call to GNUNET_realloc
 * @return pointer to size bytes of memory
 */
void *
GNUNET_xrealloc_ (void *ptr,
                  const size_t n, const char *filename, int linenumber)
{
#if RECORD_USAGE
  size_t old;
#if WRITE_MEM_STATS
  GNUNET_HashCode key;
  GNUNET_MemBlock *block;
#endif

  ptr -= sizeof (size_t);
  old = (*((size_t *) ptr));
  GNUNET_memory_usage = GNUNET_memory_usage - old + n;

  memset (&key, 0, sizeof (GNUNET_HashCode));
  memcpy (&key, ptr, sizeof (void *));
  block = GNUNET_multi_hash_map_get (map, &key);
  if (block)
    {
      block->size = block->size - old + n;

      if (!block->size)
        {
          GNUNET_multi_hash_map_remove_all (map, &key);
          free (block->filename);
          free (block);
        }
    }

  *((size_t *) ptr) = n;
  (*((size_t *) & n)) += sizeof (size_t);
#endif

  ptr = realloc (ptr, n);

  if (!ptr)
    GNUNET_GE_DIE_STRERROR_FL (NULL,
                               GNUNET_GE_IMMEDIATE | GNUNET_GE_USER |
                               GNUNET_GE_DEVELOPER | GNUNET_GE_FATAL,
                               "realloc", filename, linenumber);

#if RECORD_USAGE
  ptr += sizeof (size_t);
#endif

  return ptr;
}

/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.
 *
 * @param ptr the pointer to free
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 */
void
GNUNET_xfree_ (void *ptr, const char *filename, int linenumber)
{
#if WRITE_MEM_STATS
  GNUNET_HashCode key;
  GNUNET_MemBlock *block;
#endif

  GNUNET_GE_ASSERT_FL (NULL, ptr != NULL, filename, linenumber);

#if RECORD_USAGE
  ptr -= sizeof (size_t);
  GNUNET_memory_usage -= *((size_t *) ptr);
#endif
#if WRITE_MEM_STATS
  memset (&key, 0, sizeof (GNUNET_HashCode));
  memcpy (&key, ptr, sizeof (void *));
  block = GNUNET_multi_hash_map_get (map, &key);

  if (block)
    {
      GNUNET_multi_hash_map_remove_all (map, &key);
      free (block->filename);
      free (block);
    }
#endif

  free (ptr);
}

/**
 * Dup a string (same semantics as strdup).
 *
 * @param str the string to dup
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 * @return strdup(str)
 */
char *
GNUNET_xstrdup_ (const char *str, const char *filename, int linenumber)
{
  char *res;

  GNUNET_GE_ASSERT_FL (NULL, str != NULL, filename, linenumber);
  res = (char *) GNUNET_xmalloc_ (strlen (str) + 1, filename, linenumber);
  memcpy (res, str, strlen (str) + 1);
  return res;
}

/**
 * Grow an array.  Grows old by (*oldCount-newCount)*elementSize bytes
 * and sets *oldCount to newCount.
 *
 * @param old address of the pointer to the array
 *        *old may be NULL
 * @param elementSize the size of the elements of the array
 * @param oldCount address of the number of elements in the *old array
 * @param newCount number of elements in the new array, may be 0
 * @param filename where in the code was the call to GNUNET_array_grow
 * @param linenumber where in the code was the call to GNUNET_array_grow
 */
void
GNUNET_xgrow_ (void **old,
               size_t elementSize,
               unsigned int *oldCount,
               unsigned int newCount, const char *filename, int linenumber)
{
  void *tmp;
  size_t size;

  GNUNET_GE_ASSERT_FL (NULL,
                       INT_MAX / elementSize > newCount,
                       filename, linenumber);
  size = newCount * elementSize;
  if (size == 0)
    {
      tmp = NULL;
    }
  else
    {
      tmp = GNUNET_xmalloc_ (size, filename, linenumber);
      GNUNET_GE_ASSERT (NULL, tmp != NULL);
      memset (tmp, 0, size);    /* client code should not rely on this, though... */
      if (*oldCount > newCount)
        *oldCount = newCount;   /* shrink is also allowed! */
      memcpy (tmp, *old, elementSize * (*oldCount));
    }

  if (*old != NULL)
    {
      GNUNET_xfree_ (*old, filename, linenumber);
    }
  *old = tmp;
  *oldCount = newCount;
}

/* end of xmalloc.c */
