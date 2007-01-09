/*
     This file is part of GNUnet.
     (C) 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * Test for hashing.c
 * @author Christian Grothoff
 * @file util/crypto/hashingtest.c
 */

#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "platform.h"

static int test(int number) {
  HashCode512 h1;
  HashCode512 h2;
  EncName enc;

  memset(&h1, 
	 number, 
	 sizeof(HashCode512));
  hash2enc(&h1, &enc);
  if (OK != enc2hash((char*)&enc, &h2)) {
    printf("enc2hash failed!\n");
    return 1;
  }
  if (! equalsHashCode512(&h1, &h2)) 
    return 1;  
  return 0;
}

static int testEncoding() {
  int i;
  for (i=0;i<255;i++)
    if (0 != test(i))
      return 1;
  return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;
  int i;

  for (i=0;i<10;i++)
    failureCount += testEncoding();
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of hashingtest.c */
