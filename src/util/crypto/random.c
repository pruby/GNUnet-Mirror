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
 * @file util/crypto/random.c
 * @brief functions to gather random numbers
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "locking_gcrypt.h"
#include <gcrypt.h>

/**
 * @return a random value in the interval [0,i[.
 */
unsigned int
randomi (unsigned int i)
{
#ifdef gcry_fast_random_poll
  static unsigned int invokeCount;
#endif
  unsigned int ret;

  GE_ASSERT (NULL, i > 0);
  lockGcrypt ();
  /* see http://lists.gnupg.org/pipermail/gcrypt-devel/2004-May/000613.html */
#ifdef gcry_fast_random_poll
  if ((invokeCount++ % 256) == 0)
    gcry_fast_random_poll ();
#endif
  ret = rand ();                /* in case gcry_randomize fails,
                                   we at least get a pseudo-
                                   random number this way */
  gcry_randomize ((unsigned char *) &ret,
                  sizeof (unsigned int), GCRY_STRONG_RANDOM);
  unlockGcrypt ();
  return ret % i;
}

/**
 * Get an array with a random permutation of the
 * numbers 0...n-1.
 * @param mode STRONG if the strong (but expensive) PRNG should be used, WEAK otherwise
 * @param n the size of the array
 * @return the permutation array (allocated from heap)
 */
int *
permute (int mode, int n)
{
  int *ret;
  int i;
  int tmp;
  unsigned int x;
  unsigned int (*prng) (unsigned int u);

  GE_ASSERT (NULL, n > 0);
  ret = MALLOC (n * sizeof (int));
  prng = (mode == STRONG) ? randomi : weak_randomi;
  for (i = 0; i < n; i++)
    ret[i] = i;
  for (i = 0; i < n; i++)
    {
      x = prng (n);
      tmp = ret[x];
      ret[x] = ret[i];
      ret[i] = tmp;
    }
  return ret;
}

/**
 * Random on unsigned 64-bit values.
 */
unsigned long long
randomi64 (unsigned long long u)
{
  unsigned long long ret;

  GE_ASSERT (NULL, u > 0);
  lockGcrypt ();
  gcry_randomize ((unsigned char *) &ret,
                  sizeof (unsigned long long), GCRY_STRONG_RANDOM);
  unlockGcrypt ();
  return ret % u;
}

/**
 * @return a cryptographically weak random value in the interval [0,i[.
 */
unsigned int
weak_randomi (unsigned int i)
{
  unsigned int ret;

  GE_ASSERT (NULL, i > 0);
  ret = i * ((double) RANDOM () / RAND_MAX);
  if (ret >= i)
    ret = i - 1;
  return ret;
}

unsigned long long
weak_randomi64 (unsigned long long u)
{
  unsigned long long ret;

  GE_ASSERT (NULL, u > 0);
  ret = u * ((double) RANDOM () / RAND_MAX);
  if (ret >= u)
    ret = u - 1;
  return ret;
}

/* end of random.c */
