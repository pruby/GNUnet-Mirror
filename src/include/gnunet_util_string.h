/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_util_string.h
 * @brief string handling functions (including malloc,
 *        command line parsing and --help formatting)
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_UTIL_STRING_H
#define GNUNET_UTIL_STRING_H

/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_error.h"
#include "gnunet_util_config.h"

/**
 * Maximum allocation with MALLOC macro.
 */
#define MAX_MALLOC_CHECKED (1024 * 1024 * 40)

/**
 * Wrapper around malloc. Allocates size bytes of memory.
 *
 * @param size the number of bytes to allocate, must be
 *        smaller than 40 MB.
 * @return pointer to size bytes of memory
 */
#define MALLOC(size) xmalloc_(size, __FILE__, __LINE__, __FUNCTION__)

/**
 * Wrapper around malloc. Allocates size bytes of memory.
 *
 * @param size the number of bytes to allocate
 * @return pointer to size bytes of memory
 */
#define MALLOC_LARGE(size) xmalloc_unchecked_(size, __FILE__, __LINE__, __FUNCTION__)

/**
 * Wrapper around realloc. Rellocates size bytes of memory.
 *
 * @param ptr the pointer to reallocate
 * @param size the number of bytes to reallocate
 * @return pointer to size bytes of memory
 */
#define REALLOC(ptr, size) xrealloc_(ptr, size, __FILE__, __LINE__, __FUNCTION__)

/**
 * Wrapper around free. Frees the memory referred to by ptr.
 * Note that is is generally better to free memory that was
 * allocated with GROW using GROW(mem, size, 0) instead of FREE.
 *
 * @param ptr location where to free the memory. ptr must have
 *     been returned by STRDUP, MALLOC or GROW earlier.
 */
#define FREE(ptr) xfree_(ptr, __FILE__, __LINE__,  __FUNCTION__)

/**
 * Free the memory pointed to by ptr if ptr is not NULL.
 * Equivalent to if (ptr!=null)FREE(ptr).
 *
 * @param ptr the location in memory to free
 */
#define FREENONNULL(ptr) do { void * __x__ = ptr; if (__x__ != NULL) { FREE(__x__); } } while(0)

/**
 * Wrapper around STRDUP.  Makes a copy of the zero-terminated string
 * pointed to by a.
 *
 * @param a pointer to a zero-terminated string
 * @return a copy of the string including zero-termination
 */
#define STRDUP(a) xstrdup_(a,__FILE__,__LINE__, __FUNCTION__)

/**
 * Wrapper around STRNDUP.  Makes a copy of the zero-terminated string
 * pointed to by a.
 *
 * @param a pointer to a zero-terminated string
 * @param n the maximum number of characters to copy (+1 for 0-termination)
 * @return a copy of the string including zero-termination
 */
#define STRNDUP(a,n) xstrndup_(a, n, __FILE__, __LINE__, __FUNCTION__)

/**
 * Grow a well-typed (!) array.  This is a convenience
 * method to grow a vector <tt>arr</tt> of size <tt>size</tt>
 * to the new (target) size <tt>tsize</tt>.
 * <p>
 *
 * Example (simple, well-typed stack):
 *
 * <pre>
 * static struct foo * myVector = NULL;
 * static int myVecLen = 0;
 *
 * static void push(struct foo * elem) {
 *   GROW(myVector, myVecLen, myVecLen+1);
 *   memcpy(&myVector[myVecLen-1], elem, sizeof(struct foo));
 * }
 *
 * static void pop(struct foo * elem) {
 *   if (myVecLen == 0) die();
 *   memcpy(elem, myVector[myVecLen-1], sizeof(struct foo));
 *   GROW(myVector, myVecLen, myVecLen-1);
 * }
 * </pre>
 *
 * @param arr base-pointer of the vector, may be NULL if size is 0;
 *        will be updated to reflect the new address. The TYPE of
 *        arr is important since size is the number of elements and
 *        not the size in bytes
 * @param size the number of elements in the existing vector (number
 *        of elements to copy over)
 * @param tsize the target size for the resulting vector, use 0 to
 *        free the vector (then, arr will be NULL afterwards).
 */
#define GROW(arr,size,tsize) xgrow_((void**)&arr, sizeof(arr[0]), &size, tsize, __FILE__, __LINE__, __FUNCTION__)

/**
 * Append an element to a list (growing the
 * list by one).
 */
#define APPEND(arr,size,element) GROW(arr,size,(size)+1); arr[(size)-1] = (element)

/**
 * Like snprintf, just aborts if the buffer is of insufficient size.
 */
int SNPRINTF(char * buf,
	     size_t size,
	     const char * format,
	     ...);

/**
 * Give relative time in human-readable fancy format.
 * @param delta time in milli seconds
 */
char * string_get_fancy_time_interval(unsigned long long delta);

/**
 * Convert a given filesize into a fancy human-readable format.
 */
char * string_get_fancy_byte_size(unsigned long long size);

/**
 * Convert the len characters long character sequence
 * given in input that is in the given charset
 * to UTF-8.
 *
 * @return the converted string (0-terminated)
 */
char * string_convertToUtf8(struct GE_Context * ectx,
			    const char * input,
			    size_t len,
			    const char * charset);

/**
 * Complete filename (a la shell) from abbrevition.
 *
 * @param fil the name of the file, may contain ~/ or
 *        be relative to the current directory
 * @returns the full file name,
 *          NULL is returned on error
 */
char * string_expandFileName(struct GE_Context * ectx,
			     const char * fil);

/**
 * String functions
 */
#if !HAVE_STRLCPY
size_t strlcpy(char *dest,
	       const char *src,
	       size_t size);
#endif

#if !HAVE_STRLCAT
size_t strlcat(char *dest,
	       const char *src,
	       size_t count);
#endif


/* ************** internal implementations, use macros above! ************** */

/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.  Don't use xmalloc_ directly. Use the
 * MALLOC macro.
 */
void * xmalloc_(size_t size,
		const char * filename,
		int linenumber,
		const char * function);

/**
 * Allocate memory.  This function does not check if the
 * allocation request is within reasonable bounds, allowing
 * allocations larger than 40 MB.  If you don't expect the
 * possibility of very large allocations, use MALLOC instead.
 */
void * xmalloc_unchecked_(size_t size,
			  const char * filename,
			  int linenumber,
			  const char * function);

/**
 * Reallocate memory. Checks the return value, aborts if no more
 * memory is available.
 */
void * xrealloc_(void * ptr,
		 const size_t n,
		 const char * filename,
		 int linenumber,
		 const char * function);

/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.  Don't use xfree_
 * directly. Use the FREE macro.
 */
void xfree_(void * ptr,
	    const char * filename,
	    int linenumber,
	    const char * function);


/**
 * Dup a string. Don't call xstrdup_ directly. Use the STRDUP macro.
 */
char * xstrdup_(const char * str,
		const char * filename,
		int linenumber,
		const char * function);

/**
 * Dup a string. Don't call xstrdup_ directly. Use the STRDUP macro.
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
		 int linenumber,
		 const char * function);

/**
 * Grow an array, the new elements are zeroed out.
 * Grows old by (*oldCount-newCount)*elementSize
 * bytes and sets *oldCount to newCount.
 *
 * Don't call xgrow_ directly. Use the GROW macro.
 *
 * @param old address of the pointer to the array
 *        *old may be NULL
 * @param elementSize the size of the elements of the array
 * @param oldCount address of the number of elements in the *old array
 * @param newCount number of elements in the new array, may be 0 (then *old will be NULL afterwards)
 */
void xgrow_(void ** old,
	    size_t elementSize,
	    unsigned int * oldCount,
	    unsigned int newCount,
	    const char * filename,
	    int linenumber,
	    const char * function);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_STRING_H */
#endif
/* end of gnunet_util_string.h */
