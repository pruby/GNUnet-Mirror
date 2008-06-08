/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_error.h"
#include "gnunet_util_config.h"

/**
 * Maximum allocation with GNUNET_malloc macro.
 */
#define GNUNET_MAX_GNUNET_malloc_CHECKED (1024 * 1024 * 40)

/**
 * Wrapper around malloc. Allocates size bytes of memory.
 *
 * @param size the number of bytes to allocate, must be
 *        smaller than 40 MB.
 * @return pointer to size bytes of memory
 */
#define GNUNET_malloc(size) GNUNET_xmalloc_(size, __FILE__, __LINE__)

/**
 * Wrapper around malloc. Allocates size bytes of memory.
 *
 * @param size the number of bytes to allocate
 * @return pointer to size bytes of memory
 */
#define GNUNET_malloc_large(size) GNUNET_xmalloc_unchecked_(size, __FILE__, __LINE__)

/**
 * Wrapper around realloc. Rellocates size bytes of memory.
 *
 * @param ptr the pointer to reallocate
 * @param size the number of bytes to reallocate
 * @return pointer to size bytes of memory
 */
#define GNUNET_realloc(ptr, size) GNUNET_xrealloc_(ptr, size, __FILE__, __LINE__)

/**
 * Wrapper around free. Frees the memory referred to by ptr.
 * Note that is is generally better to free memory that was
 * allocated with GNUNET_array_grow using GNUNET_array_grow(mem, size, 0) instead of GNUNET_free.
 *
 * @param ptr location where to free the memory. ptr must have
 *     been returned by GNUNET_strdup, GNUNET_malloc or GNUNET_array_grow earlier.
 */
#define GNUNET_free(ptr) GNUNET_xfree_(ptr, __FILE__, __LINE__)

/**
 * Free the memory pointed to by ptr if ptr is not NULL.
 * Equivalent to if (ptr!=null)GNUNET_free(ptr).
 *
 * @param ptr the location in memory to free
 */
#define GNUNET_free_non_null(ptr) do { void * __x__ = ptr; if (__x__ != NULL) { GNUNET_free(__x__); } } while(0)

/**
 * Wrapper around GNUNET_strdup.  Makes a copy of the zero-terminated string
 * pointed to by a.
 *
 * @param a pointer to a zero-terminated string
 * @return a copy of the string including zero-termination
 */
#define GNUNET_strdup(a) GNUNET_xstrdup_(a,__FILE__,__LINE__)

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
 *   GNUNET_array_grow(myVector, myVecLen, myVecLen+1);
 *   memcpy(&myVector[myVecLen-1], elem, sizeof(struct foo));
 * }
 *
 * static void pop(struct foo * elem) {
 *   if (myVecLen == 0) die();
 *   memcpy(elem, myVector[myVecLen-1], sizeof(struct foo));
 *   GNUNET_array_grow(myVector, myVecLen, myVecLen-1);
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
#define GNUNET_array_grow(arr,size,tsize) GNUNET_xgrow_((void**)&arr, sizeof(arr[0]), &size, tsize, __FILE__, __LINE__)

/**
 * Append an element to a list (growing the
 * list by one).
 */
#define GNUNET_array_append(arr,size,element) do { GNUNET_array_grow(arr,size,size+1); arr[size-1] = element; } while(0)

/**
 * Like snprintf, just aborts if the buffer is of insufficient size.
 */
int GNUNET_snprintf (char *buf, size_t size, const char *format, ...);

/**
 * Give relative time in human-readable fancy format.
 * @param delta time in milli seconds
 */
char *GNUNET_get_time_interval_as_fancy_string (unsigned long long delta);

/**
 * Convert a given filesize into a fancy human-readable format.
 */
char *GNUNET_get_byte_size_as_fancy_string (unsigned long long size);

/**
 * Convert the len characters long character sequence
 * given in input that is in the given charset
 * to UTF-8.
 *
 * @return the converted string (0-terminated)
 */
char *GNUNET_convert_string_to_utf8 (struct GNUNET_GE_Context *ectx,
                                     const char *input,
                                     size_t len, const char *charset);

/**
 * Complete filename (a la shell) from abbrevition.
 *
 * @param fil the name of the file, may contain ~/ or
 *        be relative to the current directory
 * @returns the full file name,
 *          NULL is returned on error
 */
char *GNUNET_expand_file_name (struct GNUNET_GE_Context *ectx,
                               const char *fil);

/* ************** internal implementations, use macros above! ************** */

/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.  Don't use GNUNET_xmalloc_ directly. Use the
 * GNUNET_malloc macro.
 */
void *GNUNET_xmalloc_ (size_t size, const char *filename, int linenumber);

/**
 * Allocate memory.  This function does not check if the
 * allocation request is within reasonable bounds, allowing
 * allocations larger than 40 MB.  If you don't expect the
 * possibility of very large allocations, use GNUNET_malloc instead.
 */
void *GNUNET_xmalloc_unchecked_ (size_t size,
                                 const char *filename, int linenumber);

/**
 * Reallocate memory. Checks the return value, aborts if no more
 * memory is available.
 */
void *GNUNET_xrealloc_ (void *ptr,
                        const size_t n, const char *filename, int linenumber);

/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.  Don't use GNUNET_xfree_
 * directly. Use the GNUNET_free macro.
 */
void GNUNET_xfree_ (void *ptr, const char *filename, int linenumber);


/**
 * Dup a string. Don't call GNUNET_xstrdup_ directly. Use the GNUNET_strdup macro.
 */
char *GNUNET_xstrdup_ (const char *str, const char *filename, int linenumber);

/**
 * Grow an array, the new elements are zeroed out.
 * Grows old by (*oldCount-newCount)*elementSize
 * bytes and sets *oldCount to newCount.
 *
 * Don't call GNUNET_xgrow_ directly. Use the GNUNET_array_grow macro.
 *
 * @param old address of the pointer to the array
 *        *old may be NULL
 * @param elementSize the size of the elements of the array
 * @param oldCount address of the number of elements in the *old array
 * @param newCount number of elements in the new array, may be 0 (then *old will be NULL afterwards)
 */
void GNUNET_xgrow_ (void **old,
                    size_t elementSize,
                    unsigned int *oldCount,
                    unsigned int newCount,
                    const char *filename, int linenumber);


/**
 * Fill a buffer of the given size with
 * count 0-terminated strings (given as varargs).
 * If "buffer" is NULL, only compute the amount of
 * space required (sum of "strlen(arg)+1").
 *
 * Unlike using "snprintf" with "%s", this function
 * will add 0-terminators after each string.  The
 * "GNUNET_string_buffer_tokenize" function can be
 * used to parse the buffer back into individual
 * strings.
 *
 * @return number of bytes written to the buffer
 *         (or number of bytes that would have been written)
 */
unsigned int GNUNET_string_buffer_fill (char *buffer,
                                        unsigned int size,
                                        unsigned int count, ...);

/**
 * Given a buffer of a given size, find "count"
 * 0-terminated strings in the buffer and assign
 * the count (varargs) of type "const char**" to the
 * locations of the respective strings in the
 * buffer.
 *
 * @param buffer the buffer to parse
 * @param size size of the buffer
 * @param count number of strings to locate
 * @return offset of the character after the last 0-termination
 *         in the buffer, or 0 on error.
 */
unsigned int GNUNET_string_buffer_tokenize (const char *buffer,
                                            unsigned int size,
                                            unsigned int count, ...);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_STRING_H */
#endif
/* end of gnunet_util_string.h */
