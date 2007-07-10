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

#include "gnunet_util_string.h"
#include "gnunet_util_error.h"
#include "platform.h"

#ifndef INT_MAX
#define INT_MAX 0x7FFFFFFF
#endif

/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.
 *
 * @param size how many bytes of memory to allocate, do NOT use
 *  this function (or MALLOC) to allocate more than several MB
 *  of memory, if you are possibly needing a very large chunk use
 *  xmalloc_unchecked_ instead.
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 * @return pointer to size bytes of memory
 */
void *
xmalloc_ (size_t size,
          const char *filename, int linenumber, const char *function)
{
  /* As a security precaution, we generally do not allow very large
     allocations using the default 'MALLOC' macro */
  GE_ASSERT_FLF (NULL,
                 size <= MAX_MALLOC_CHECKED, filename, linenumber, function);
  return xmalloc_unchecked_ (size, filename, linenumber, function);
}

void *
xmalloc_unchecked_ (size_t size,
                    const char *filename,
                    int linenumber, const char *function)
{
  void *result;

  GE_ASSERT_FLF (NULL, size < INT_MAX, filename, linenumber, function);
  result = malloc (size);
  if (result == NULL)
    GE_DIE_STRERROR_FLF (NULL,
                         GE_IMMEDIATE | GE_USER | GE_DEVELOPER | GE_FATAL,
                         "malloc", filename, linenumber, function);
  memset (result, 0, size);     /* client code should not rely on this, though... */
  return result;
}

/**
 * Reallocate memory. Checks the return value, aborts if no more
 * memory is available.
 *
 * @ptr the pointer to reallocate
 * @param size how many bytes of memory to allocate, do NOT use
 *  this function (or MALLOC) to allocate more than several MB
 *  of memory
 * @param filename where in the code was the call to REALLOC
 * @param linenumber where in the code was the call to REALLOC
 * @return pointer to size bytes of memory
 */
void *
xrealloc_ (void *ptr,
           const size_t n,
           const char *filename, int linenumber, const char *function)
{
  ptr = realloc (ptr, n);

  if (!ptr)
    GE_DIE_STRERROR_FLF (NULL,
                         GE_IMMEDIATE | GE_USER | GE_DEVELOPER | GE_FATAL,
                         "realloc", filename, linenumber, function);
  return ptr;
}

/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.
 *
 * @param ptr the pointer to free
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 */
void
xfree_ (void *ptr, const char *filename, int linenumber, const char *function)
{
  GE_ASSERT_FLF (NULL, ptr != NULL, filename, linenumber, function);
  free (ptr);
}

/**
 * Dup a string (same semantics as strdup).
 *
 * @param str the string to dup
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 * @return strdup(str)
 */
char *
xstrdup_ (const char *str,
          const char *filename, int linenumber, const char *function)
{
  char *res;

  GE_ASSERT_FLF (NULL, str != NULL, filename, linenumber, function);
  res = (char *) xmalloc_ (strlen (str) + 1, filename, linenumber, function);
  memcpy (res, str, strlen (str) + 1);
  return res;
}

/**
 * Dup a string (same semantics as strdup).
 *
 * @param str the string to dup
 * @param n the maximum number of characters to copy (+1 for 0-termination)
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 * @return strdup(str)
 */
char *
xstrndup_ (const char *str,
           const size_t n,
           const char *filename, int linenumber, const char *function)
{
  char *res;
  size_t min;

  GE_ASSERT_FLF (NULL, str != NULL, filename, linenumber, function);
  min = 0;
  while ((min < n) && (str[min] != '\0'))
    min++;
  res = (char *) xmalloc_ (min + 1, filename, linenumber, function);
  memcpy (res, str, min);
  res[min] = '\0';
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
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 */
void
xgrow_ (void **old,
        size_t elementSize,
        unsigned int *oldCount,
        unsigned int newCount,
        const char *filename, int linenumber, const char *function)
{
  void *tmp;
  size_t size;

  GE_ASSERT_FLF (NULL,
                 INT_MAX / elementSize > newCount,
                 filename, linenumber, function);
  size = newCount * elementSize;
  if (size == 0)
    {
      tmp = NULL;
    }
  else
    {
      tmp = xmalloc_ (size, filename, linenumber, function);
      GE_ASSERT (NULL, tmp != NULL);
      memset (tmp, 0, size);    /* client code should not rely on this, though... */
      if (*oldCount > newCount)
        *oldCount = newCount;   /* shrink is also allowed! */
      memcpy (tmp, *old, elementSize * (*oldCount));
    }

  if (*old != NULL)
    {
      xfree_ (*old, filename, linenumber, function);
    }
  *old = tmp;
  *oldCount = newCount;
}

/* end of xmalloc.c */
