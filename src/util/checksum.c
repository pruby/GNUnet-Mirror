/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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

     For the actual CRC code:
     Copyright abandoned; this code is in the public domain.
     Provided to GNUnet by peter@horizon.com
*/

/**
 * @file util/checksum.c
 * @brief implementation of CRC32 and various helper methods
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include <iconv.h>

/* Avoid wasting space on 8-byte longs. */
#if UINT_MAX >= 0xffffffff
 typedef unsigned int uLong;
#elif ULONG_MAX >= 0xffffffff
 typedef unsigned long uLong;
#else
 #error This compiler is not ANSI-compliant!
#endif

#define Z_NULL  0


#define POLYNOMIAL (uLong)0xedb88320
static uLong crc_table[256];

/*
 * This routine writes each crc_table entry exactly once,
 * with the ccorrect final value.  Thus, it is safe to call
 * even on a table that someone else is using concurrently.
 */
static void make_crc_table() {
  unsigned int i, j;
  uLong h = 1;
  crc_table[0] = 0;
  for (i = 128; i; i >>= 1) {
    h = (h >> 1) ^ ((h & 1) ? POLYNOMIAL : 0);
    /* h is now crc_table[i] */
    for (j = 0; j < 256; j += 2*i)
      crc_table[i+j] = crc_table[j] ^ h;
  }
}

/*
 * This computes the standard preset and inverted CRC, as used
 * by most networking standards.  Start by passing in an initial
 * chaining value of 0, and then pass in the return value from the
 * previous crc32() call.  The final return value is the CRC.
 * Note that this is a little-endian CRC, which is best used with
 * data transmitted lsbit-first, and it should, itself, be appended
 * to data in little-endian byte and bit order to preserve the
 * property of detecting all burst errors of length 32 bits or less.
 */
static uLong crc32(uLong crc,
		   const char *buf,
		   size_t len) {
  if (crc_table[255] == 0)
    make_crc_table();
  crc ^= 0xffffffff;
  while (len--)
    crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
  return crc ^ 0xffffffff;
}


/**
 * Compute the CRC32 checksum for the first len bytes of the buffer.
 *
 * @param buf the data over which we're taking the CRC
 * @param len the length of the buffer
 * @return the resulting CRC32 checksum
 */
int crc32N(const void * buf, int len) {
  uLong crc;
  crc = crc32(0L, Z_NULL, 0);
  crc = crc32(crc, (char*)buf, len);
  return crc;
}

/* **************** endian conversion helpers ************* */

/**
 * This method does not really belong here, but where else to put
 * it...
 */
unsigned long long ntohll(unsigned long long n) {
#if __BYTE_ORDER == __BIG_ENDIAN
  return n;
#else
  return (((unsigned long long)ntohl(n)) << 32) + ntohl(n >> 32);
#endif
}

/**
 * This method does not really belong here, but where else to put
 * it...
 */
unsigned long long htonll(unsigned long long n) {
#if __BYTE_ORDER == __BIG_ENDIAN
  return n;
#else
  return (((unsigned long long)htonl(n)) << 32) + htonl(n >> 32);
#endif
}

/* ************* character conversion helpers *********** */

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
    ret = malloc(len+1);
    memcpy(ret, input, len);
    ret[len] = '\0';
    return ret;
  }
  tmpSize = 3 * len + 4;
  tmp = malloc(tmpSize);
  itmp = tmp;
  finSize = tmpSize;
  if (iconv(cd,
	    (char**) &input,
	    &len,
	    &itmp,
	    &finSize) == (size_t)-1) {
    iconv_close(cd);
    free(tmp);
    ret = malloc(len+1);
    memcpy(ret, input, len);
    ret[len] = '\0';
    return ret;
  }
  ret = malloc(tmpSize - finSize + 1);
  memcpy(ret,
	 tmp,
	 tmpSize - finSize);
  ret[tmpSize - finSize] = '\0';
  free(tmp);
  iconv_close(cd);
  return ret;
#else
  ret = malloc(len+1);
  memcpy(ret, input, len);
  ret[len] = '\0';
  return ret;
#endif
}




/* end of checksum.c */
