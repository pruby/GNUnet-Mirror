/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/bincoder.c
 * @brief base64-ish encoder/decoder (this is NOT exactly
 *        the traditional base64 encoding!)
 * @author Christian Grothoff
 */

/**
 * 64 characters for encoding, 6 bits per character
 */
static char * encTable__ = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_=";


static unsigned int getValue__(unsigned char a) {
  if ( (a >= '0') && (a <= '9') )
    return a - '0';
  if ( (a >= 'A') && (a <= 'Z') )
    return (a - 'A' + 10);
  if ( (a >= 'a') && (a <= 'z') )
    return (a - 'a' + 36);
  if (a == '_')
    return 62;
  if (a == '=')
    return 63;
  return -1;
}
/**
 * Convert binary data to a string.
 *
 * @return converted data
 */
static char *
bin2enc(const void * data,
	size_t size) {
  size_t len;
  size_t pos;
  unsigned int bits;
  unsigned int hbits;
  char * ret;

  GE_ASSERT(NULL, strlen(encTable__) == 64);
  len = size * 8 / 6;
  if (((size * 8) % 6) != 0)
    len++;
  ret = MALLOC(len+1);
  ret[len] = '\0';
  len = 0;
  bits = 0;
  hbits = 0;
  for (pos=0;pos<size;pos++) {
    bits |= ((((const unsigned char*)data)[pos]) << hbits);
    hbits += 8;
    while (hbits >= 6) {
      ret[len++] = encTable__[bits & 63];
      bits >>= 6;
      hbits -= 6;
    }
  }
  if (hbits > 0)
    ret[len++] = encTable__[bits & 63];
  return ret;
}


/**
 * Convert string back to binary data.
 *
 * @param input '\0'-terminated string
 * @param data where to write binary data
 * @param size how much data should be converted
 * @return number of characters processed from input,
 *        -1 on error
 */
static int
enc2bin(const char * input,
	void * data,
	size_t size) {
  size_t len;
  size_t pos;
  unsigned int bits;
  unsigned int hbits;

  len = size * 8 / 6;
  if (((size * 8) % 6) != 0)
    len++;
  if (strlen(input) < len)
    return -1; /* error! */
  bits = 0;
  hbits = 0;
  len = 0;
  pos = 0;
  for (pos=0;pos<size;pos++) {
    while (hbits < 8) {
      bits |= (getValue__(input[len++]) << hbits);
      hbits += 6;
    }
    (((unsigned char*)data)[pos]) = (unsigned char) bits;
    bits >>= 8;
    hbits -= 8;
  }
  return len;
}
