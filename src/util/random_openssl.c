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

*/

/**
 * @file util/random_openssl.c
 * @brief functions to gather random numbers
 * @author Christian Grothoff
 */ 
#include "platform.h"
#include "gnunet_util.h"
#include <openssl/rand.h>

/**
 * Initialize Random number generator.
 */
void initRAND() {
  srand((unsigned int)time(NULL));
  RAND_set_rand_method(RAND_SSLeay());
}

/**
 * @return a random value in the interval [0,i[. 
 */
unsigned int randomi(unsigned int i) {
  unsigned int ret;

  GNUNET_ASSERT(i > 0);
  ret = rand(); /* in case RAND_bytes fails, we got at least something! */
  RAND_bytes((unsigned char*)&ret, sizeof(unsigned int));
  ret = ret % i;
  GNUNET_ASSERT((ret >= 0) && (ret < i));
  return ret;
}

/**
 * Get an array with a random permutation of the numbers 0...n-1.
 */
int * permute(int n) {
  int * ret;
  int i;
  int tmp;
  int x;    

  GNUNET_ASSERT(n > 0);
  ret = (int*)MALLOC(n * sizeof(int));
  for (i=0;i<n;i++)
    ret[i] = i;
  for (i=0;i<n;i++) {
    x = randomi(n);
    tmp = ret[x];
    ret[x] = ret[i];
    ret[i] = tmp;
  }
  return ret;
}

/**
 * Random on unsigned 64-bit values.  We break them down into signed
 * 32-bit values and reassemble the 64-bit random value bit-wise.
 */
unsigned long long randomi64(unsigned long long u) {
  unsigned long long ret;

  ret = ((unsigned long long)rand()) << 32 | rand(); /* in case RAND_bytes fails, we got at least something! */
  RAND_bytes((unsigned char*)&ret, 
	     sizeof(unsigned long long));
  return ret % u;
}

