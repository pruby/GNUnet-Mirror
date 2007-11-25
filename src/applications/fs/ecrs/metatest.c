/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/metatest.c
 * @brief Test for meta.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include <extractor.h>
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs.h"

#define ABORT(m) { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); if (m != NULL) GNUNET_ECRS_meta_data_destroy(m); return 1; }

static int
testMeta (int i)
{
  struct GNUNET_ECRS_MetaData *m;
  char *val;
  int j;
  unsigned int size;

  m = GNUNET_ECRS_meta_data_create ();
  if (GNUNET_OK !=
      GNUNET_ECRS_meta_data_insert (m, EXTRACTOR_TITLE, "TestTitle"))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_ECRS_meta_data_insert (m, EXTRACTOR_AUTHOR, "TestTitle"))
    ABORT (m);
  if (GNUNET_OK == GNUNET_ECRS_meta_data_insert (m, EXTRACTOR_TITLE, "TestTitle"))      /* dup! */
    ABORT (m);
  if (GNUNET_OK == GNUNET_ECRS_meta_data_insert (m, EXTRACTOR_AUTHOR, "TestTitle"))     /* dup! */
    ABORT (m);
  if (2 != GNUNET_ECRS_meta_data_get_contents (m, NULL, NULL))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_ECRS_meta_data_delete (m, EXTRACTOR_AUTHOR, "TestTitle"))
    ABORT (m);
  if (GNUNET_OK == GNUNET_ECRS_meta_data_delete (m, EXTRACTOR_AUTHOR, "TestTitle"))     /* already gone */
    ABORT (m);
  if (1 != GNUNET_ECRS_meta_data_get_contents (m, NULL, NULL))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_ECRS_meta_data_delete (m, EXTRACTOR_TITLE, "TestTitle"))
    ABORT (m);
  if (GNUNET_OK == GNUNET_ECRS_meta_data_delete (m, EXTRACTOR_TITLE, "TestTitle"))      /* already gone */
    ABORT (m);
  if (0 != GNUNET_ECRS_meta_data_get_contents (m, NULL, NULL))
    ABORT (m);
  val = GNUNET_malloc (256);
  for (j = 0; j < i; j++)
    {
      GNUNET_snprintf (val, 256, "%s.%d",
                       "A teststring that should compress well.", j);
      if (GNUNET_OK !=
          GNUNET_ECRS_meta_data_insert (m, EXTRACTOR_UNKNOWN, val))
        {
          GNUNET_free (val);
          ABORT (m);
        }
    }
  GNUNET_free (val);
  if (i != GNUNET_ECRS_meta_data_get_contents (m, NULL, NULL))
    ABORT (m);

  size =
    GNUNET_ECRS_meta_data_get_serialized_size (m, GNUNET_ECRS_SERIALIZE_FULL);
  val = GNUNET_malloc (size);
  if (size != GNUNET_ECRS_meta_data_serialize (NULL,
                                               m, val, size,
                                               GNUNET_ECRS_SERIALIZE_FULL))
    {
      GNUNET_free (val);
      ABORT (m);
    }
  GNUNET_ECRS_meta_data_destroy (m);
  m = GNUNET_ECRS_meta_data_deserialize (NULL, val, size);
  GNUNET_free (val);
  if (m == NULL)
    ABORT (m);
  val = GNUNET_malloc (256);
  for (j = 0; j < i; j++)
    {
      GNUNET_snprintf (val, 256, "%s.%d",
                       "A teststring that should compress well.", j);
      if (GNUNET_OK !=
          GNUNET_ECRS_meta_data_delete (m, EXTRACTOR_UNKNOWN, val))
        {
          GNUNET_free (val);
          ABORT (m);
        }
    }
  GNUNET_free (val);
  if (0 != GNUNET_ECRS_meta_data_get_contents (m, NULL, NULL))
    {
      ABORT (m);
    }
  GNUNET_ECRS_meta_data_destroy (m);
  return 0;
}

int
testMetaMore (int i)
{
  struct GNUNET_ECRS_MetaData *meta;
  int q;
  char txt[128];
  char *data;
  unsigned long long size;

  meta = GNUNET_ECRS_meta_data_create ();
  for (q = 0; q <= i; q++)
    {
      GNUNET_snprintf (txt, 128, "%u -- %u\n", i, q);
      GNUNET_ECRS_meta_data_insert (meta,
                                    q %
                                    EXTRACTOR_getHighestKeywordTypeNumber (),
                                    txt);
    }
  size =
    GNUNET_ECRS_meta_data_get_serialized_size (meta,
                                               GNUNET_ECRS_SERIALIZE_FULL);
  data = GNUNET_malloc (size * 4);
  if (size != GNUNET_ECRS_meta_data_serialize (NULL,
                                               meta,
                                               data, size * 4,
                                               GNUNET_ECRS_SERIALIZE_FULL))
    {
      GNUNET_free (data);
      ABORT (meta);
    }
  GNUNET_ECRS_meta_data_destroy (meta);
  GNUNET_free (data);
  return 0;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;
  int i;

  for (i = 0; i < 255; i++)
    failureCount += testMeta (i);
  for (i = 1; i < 255; i++)
    failureCount += testMetaMore (i);

  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of metatest.c */
