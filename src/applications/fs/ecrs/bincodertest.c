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
 * @file applications/fs/ecrs/bincodertest.c
 * @brief Test for bincoder.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"

#include "bincoder.c"

static int
testBC (int i)
{
  char *orig;
  char *enc;
  char dec[256];
  int ret;

  orig = MALLOC (i);
  memset (orig, i, i);
  enc = bin2enc (orig, i);
  ret = enc2bin (enc, dec, i);
  if ((ret != strlen (enc)) || (0 != memcmp (orig, dec, i)))
    {
      printf ("Failed in iteration %d\n", i);
      ret = -1;
    }
  FREE (enc);
  FREE (orig);
  return ret != -1 ? 0 : 1;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;
  int i;

  for (i = 0; i < 256; i++)
    failureCount += testBC (i);
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of bincodertest.c */
