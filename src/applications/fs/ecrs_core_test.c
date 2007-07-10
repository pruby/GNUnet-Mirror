/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs_core_test.c
 * @brief Test for ECRS CORE library
 * @author Christian Grothoff
 */

#include "platform.h"
#include "ecrs_core.h"
#include "gnunet_protocols.h"

#define CHECK(a,b) { if (! (a)) { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); FREENONNULL(b); return 1; } }

static int
testEC ()
{
  DBlock *data;
  Datastore_Value *value;
  HashCode512 query;
  HashCode512 key;
  unsigned int len;

  len = sizeof (DBlock) + 42;
  data = MALLOC (len);
  memset (&data[1], rand (), len - sizeof (DBlock));
  data->type = htonl (D_BLOCK);
  CHECK (D_BLOCK == getTypeOfBlock (len, data), data);
  fileBlockGetKey (data, len, &key);
  fileBlockGetQuery (data, len, &query);
  CHECK (OK == fileBlockEncode (data, len, &query, &value), data);
  memcpy (data, &value[1], len);
  FREE (value);
  CHECK (YES == isDatumApplicable (D_BLOCK,
                                   len, data, &query, 1, &query), data);
  FREE (data);
  return 0;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;

  failureCount += testEC ();
  fprintf (stderr, "\n");
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of ecrs_core_test.c */
