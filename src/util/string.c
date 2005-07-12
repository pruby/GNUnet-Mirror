/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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
 * @file util/string.c
 * @brief string functions
 * @author Nils Durner
 */

#include "gnunet_util.h"
#include "platform.h"

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
size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret;

	GNUNET_ASSERT(dest != NULL);
	GNUNET_ASSERT(size > 0);
	GNUNET_ASSERT(src != NULL);
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
size_t strlcat(char *dest, const char *src, size_t count)
{
	size_t dsize;
	size_t len;
	size_t res;

	GNUNET_ASSERT(dest != NULL);
	GNUNET_ASSERT(src != NULL);
	GNUNET_ASSERT(count > 0);
	dsize = strlen(dest);
	len = strlen(src);
	res = dsize + len;
	/* This would be a bug */
	GNUNET_ASSERT(dsize < count);

	dest += dsize;
	count -= dsize;
	if (len >= count)
		len = count-1;
	memcpy(dest, src, len);
	dest[len] = 0;
	return res;
}
#endif

/* end of string.c */
