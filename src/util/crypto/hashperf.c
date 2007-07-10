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
 * @file util/crypto/hashperf.c
 */

#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "platform.h"

static void
perfHash ()
{
  HashCode512 hc1;
  HashCode512 hc2;
  HashCode512 hc3;
  int i;
  char *buf;

  buf = MALLOC (1024 * 64);
  memset (buf, 1, 1024 * 64);
  hash ("foo", 3, &hc1);
  for (i = 0; i < 1024; i++)
    {
      hash (&hc1, sizeof (HashCode512), &hc2);
      hash (&hc2, sizeof (HashCode512), &hc1);
      hash (buf, 1024 * 64, &hc3);
    }
  FREE (buf);
}

int
main (int argc, char *argv[])
{
  cron_t start;

  start = get_time ();
  perfHash ();
  printf ("Hash perf took %llu ms\n", get_time () - start);
  return 0;
}

/* end of hashperf.c */
