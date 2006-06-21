/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/string/string.c
 * @brief string functions
 * @author Nils Durner
 * @author Christian Grothoff
 */

#include "gnunet_util_string.h"
#include "platform.h"
#include <iconv.h>

#if !HAVE_STRLCPY
/**
 * @brief Copy a %NUL terminated string into a sized buffer
 * @author Linus Torvalds
 * @param dest Where to copy the string to
 * @param src Where to copy the string from
 * @param size size of destination buffer
 * @remarks Compatible with *BSD: the result is always a valid
 *          NUL-terminated string that fits in the buffer (unless,
 *          of course, the buffer size is zero). It does not pad
 *          out the result like strncpy() does.
 */
size_t strlcpy(char * dest, 
	       const char * src, 
	       size_t size) {
  size_t ret;
  
  GE_ASSERT(NULL, dest != NULL);
  GE_ASSERT(NULL, size > 0);
  GE_ASSERT(NULL, src != NULL);
  ret = strlen(src);
  
  if (size) {
    size_t len = (ret >= size) ? size-1 : ret;
    memcpy(dest, src, len);
    dest[len] = '\0';
  }
  return ret;
}
#endif

#if !HAVE_STRLCAT
/**
 * @brief Append a length-limited, %NUL-terminated string to another
 * @author Linus Torvalds
 * @param dest The string to be appended to
 * @param src The string to append to it
 * @param count The size of the destination buffer.
 */
size_t strlcat(char * dest, 
	       const char * src, 
	       size_t count) {
  size_t dsize;
  size_t len;
  size_t res;
  
  GE_ASSERT(NULL, dest != NULL);
  GE_ASSERT(NULL, src != NULL);
  GE_ASSERT(NULL, count > 0);
  dsize = strlen(dest);
  len = strlen(src);
  res = dsize + len;
  GE_ASSERT(NULL, dsize < count);
  
  dest += dsize;
  count -= dsize;
  if (len >= count)
    len = count-1;
  memcpy(dest, src, len);
  dest[len] = 0;
  return res;
}
#endif

/**
 * Give relative time in human-readable fancy format.
 * @param delta time in milli seconds
 */
char * timeIntervalToFancyString(unsigned long long delta) {
  const char * unit = _(/* time unit */ "ms");
  char * ret;

  if (delta > 5 * 1000) {
    delta = delta / 1000;
    unit = _(/* time unit */ "s");
    if (delta > 5 * 60) {
      delta = delta / 60;
      unit = _(/* time unit */ "m");
      if (delta > 5 * 60) {
	delta = delta / 60;
	unit = _(/* time unit */ "h");
	if (delta > 5 * 24) {
	  delta = delta / 24;
	  unit = _(/* time unit */ " days");	
	}	
      }		
    }	
  }	
  ret = MALLOC(32);
  SNPRINTF(ret,
	   32,
	   "%llu%s",
	   delta,
	   unit);
  return ret;
}

/**
 * Convert a given filesize into a fancy human-readable format.
 */
char * fileSizeToFancyString(unsigned long long size) {
const char * unit = _(/* size unit */ "b");
  char * ret;

  if (size > 5 * 1024) {
    size = size / 1024;
    unit = _(/* size unit */ "KiB");
    if (size > 5 * 1024) {
      size = size / 1024;
      unit = _(/* size unit */ "MiB");
      if (size > 5 * 1024) {
	size = size / 1024;
	unit = _(/* size unit */ "GiB");
	if (size > 5 * 1024) {
	  size = size / 1024;
	  unit = _(/* size unit */ "TiB");	
	}	
      }		
    }	
  }	
  ret = MALLOC(32);
  SNPRINTF(ret,
	   32,
	   "%llu%s",
	   size,
	   unit);
  return ret;
}




/**
 * Convert the len characters long character sequence
 * given in input that is in the given charset
 * to UTF-8.
 * @return the converted string (0-terminated),
 *  if conversion fails, a copy of the orignal
 *  string is returned.
 */
char * convertToUtf8(const char * input,
		     size_t len,
		     const char * charset) {
  char * ret;
#if ENABLE_NLS
  size_t tmpSize;
  size_t finSize;
  char * tmp;
  char * itmp;
  iconv_t cd;

  cd = iconv_open("UTF-8", charset);
  if (cd == (iconv_t) -1) {
    ret = MALLOC(len+1);
    memcpy(ret, input, len);
    ret[len] = '\0';
    return ret;
  }
  tmpSize = 3 * len + 4;
  tmp = MALLOC(tmpSize);
  itmp = tmp;
  finSize = tmpSize;
  if (iconv(cd,
	    (char**) &input,
	    &len,
	    &itmp,
	    &finSize) == (size_t)-1) {
    iconv_close(cd);
    FREE(tmp);
    ret = MALLOC(len+1);
    memcpy(ret, input, len);
    ret[len] = '\0';
    return ret;
  }
  ret = MALLOC(tmpSize - finSize + 1);
  memcpy(ret,
	 tmp,
	 tmpSize - finSize);
  ret[tmpSize - finSize] = '\0';
  FREE(tmp);
  iconv_close(cd);
  return ret;
#else
  ret = MALLOC(len+1);
  memcpy(ret, input, len);
  ret[len] = '\0';
  return ret;
#endif
}

/* end of string.c */
