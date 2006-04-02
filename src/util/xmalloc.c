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
 * @file util/xmalloc.c
 * @brief wrapper around malloc/free
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
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
void * xmalloc_(size_t size,
		const char * filename,
		const int linenumber) {
  /* As a security precaution, we generally do not allow very large
     allocations using the default 'MALLOC' macro */
  if (size > 1024 * 1024 * 40)
    errexit(_("Unexpected very large allocation (%u bytes) at %s:%d!\n"),
	    size, filename, linenumber);
  return xmalloc_unchecked_(size, filename, linenumber);
}

void * xmalloc_unchecked_(size_t size,
			  const char * filename,
			  const int linenumber) {
  void * result;

  GNUNET_ASSERT(size < INT_MAX);
  result = malloc(size);
  if (result == NULL)
    DIE_STRERROR_FL(filename, linenumber, "malloc");
  memset(result, 0, size); /* client code should not rely on this, though... */
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
void * xrealloc_(void * ptr,
		 const size_t n,
		 const char * filename,
		 const int linenumber) {
  ptr = realloc(ptr, n);

  if (!ptr)
    DIE_STRERROR_FL(filename, linenumber, "realloc");
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
void xfree_(void * ptr,
	    const char * filename,
	    const int linenumber) {
  GNUNET_ASSERT_FL(ptr != NULL,
		   filename, linenumber);
  free(ptr);
}

/**
 * Dup a string (same semantics as strdup).
 *
 * @param str the string to dup
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 * @return strdup(str)
 */
char * xstrdup_(const char * str,
		const char * filename,
		const int linenumber) {
  char * res;

  GNUNET_ASSERT_FL(str != NULL, filename, linenumber);
  res = (char*)xmalloc_(strlen(str)+1,
		         filename,
		         linenumber);
  memcpy(res, str, strlen(str)+1);
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
char * xstrndup_(const char * str,
		 const size_t n,
		 const char * filename,
		 const int linenumber) {
  char * res;
  size_t min;

  GNUNET_ASSERT_FL(str != NULL, filename, linenumber);
  min = 0;
  while ( (min < n) && (str[min] != '\0'))
    min++;
  res = (char*)xmalloc_(min+1,
			filename,
			linenumber);
  memcpy(res, str, min);
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
void xgrow_(void ** old,
	    size_t elementSize,
	    unsigned int * oldCount,
	    unsigned int newCount,
	    const char * filename,
	    const int linenumber) {
  void * tmp;
  size_t size;

  GNUNET_ASSERT_FL(INT_MAX / elementSize > newCount,
		   filename, linenumber);
  size = newCount * elementSize;
  if (size == 0) {
    tmp = NULL;
  } else {
    tmp = xmalloc_(size,
		   filename,
		   linenumber);
    GNUNET_ASSERT(tmp != NULL);
    memset(tmp, 0, size); /* client code should not rely on this, though... */
    if (*oldCount > newCount)
      *oldCount = newCount; /* shrink is also allowed! */
    memcpy(tmp,
	   *old,
	   elementSize * (*oldCount));
  }

  if (*old != NULL) {
    xfree_(*old,
	   filename,
	   linenumber);
  }
  *old = tmp;
  *oldCount = newCount;
}

/* end of xmalloc.c */
