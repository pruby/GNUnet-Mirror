/*
     This file is part of GNUnet.
     (C) 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/directorytest.c
 * @brief Test for directory.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include <extractor.h>
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }

struct PCLS
{
  GNUNET_ECRS_FileInfo *fi;
  unsigned int pos;
  unsigned int max;
};

static int
processor (const GNUNET_ECRS_FileInfo * fi,
           const GNUNET_HashCode * key, int isRoot, void *cls)
{
  struct PCLS *p = cls;
  int i;

  for (i = 0; i < p->max; i++)
    {
      if (GNUNET_meta_data_test_equal (p->fi[i].meta,
                                       fi->meta) &&
          GNUNET_ECRS_uri_test_equal (p->fi[i].uri, fi->uri))
        {
          p->pos++;
          return GNUNET_OK;
        }
    }
  fprintf (stderr, "Error at %s:%d\n", __FILE__, __LINE__);
  return GNUNET_SYSERR;
}

static int
testDirectory (unsigned int i)
{
  char *data;
  unsigned long long dlen;
  GNUNET_ECRS_FileInfo *fis;
  struct GNUNET_MetaData *meta;
  struct GNUNET_MetaData *meta2;
  struct PCLS cls;
  int p;
  int q;
  char uri[512];
  char txt[128];
  int ret = 0;

  cls.max = i;
  fis = GNUNET_malloc (sizeof (GNUNET_ECRS_FileInfo) * i);
  for (p = 0; p < i; p++)
    {
      fis[p].meta = GNUNET_meta_data_create ();
      for (q = 0; q <= p; q++)
        {
          GNUNET_snprintf (txt, 128, "%u -- %u\n", p, q);
          GNUNET_meta_data_insert (fis[p].meta,
                                   q %
                                   EXTRACTOR_getHighestKeywordTypeNumber
                                   (), txt);
        }
      GNUNET_snprintf (uri,
                       512,
                       "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.%u",
                       p);
      fis[p].uri = GNUNET_ECRS_string_to_uri (NULL, uri);
      if (fis[p].uri == NULL)
        {
          GNUNET_meta_data_destroy (fis[p].meta);
          while (--p > 0)
            {
              GNUNET_meta_data_destroy (fis[p].meta);
              GNUNET_ECRS_uri_destroy (fis[p].uri);
            }
          GNUNET_free (fis);
          ABORT ();             /* error in testcase */
        }
    }
  meta = GNUNET_meta_data_create ();
  GNUNET_meta_data_insert (meta, EXTRACTOR_TITLE, "A title");
  GNUNET_meta_data_insert (meta, EXTRACTOR_AUTHOR, "An author");
  if (GNUNET_OK !=
      GNUNET_ECRS_directory_create (NULL, &data, &dlen, i, fis, meta))
    {
      GNUNET_meta_data_destroy (meta);
      for (p = 0; p < i; p++)
        {
          GNUNET_meta_data_destroy (fis[p].meta);
          GNUNET_ECRS_uri_destroy (fis[p].uri);
        }
      GNUNET_free (fis);
      ABORT ();
    }
  cls.pos = 0;
  cls.fi = fis;
  if (i !=
      GNUNET_ECRS_directory_list_contents (NULL, data, dlen, &meta2,
                                           &processor, &cls))
    {
      printf ("expected %u\n", i);
      ret = 1;
      goto END;
    }
  if (!GNUNET_meta_data_test_equal (meta, meta2))
    {
      ret = 1;
      goto END;
    }
END:
  GNUNET_free (data);
  GNUNET_meta_data_destroy (meta);
  GNUNET_meta_data_destroy (meta2);
  for (p = 0; p < i; p++)
    {
      GNUNET_meta_data_destroy (fis[p].meta);
      GNUNET_ECRS_uri_destroy (fis[p].uri);
    }
  GNUNET_free (fis);
  return ret;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;
  int i;

  for (i = 17; i < 2000; i *= 2)
    {
      fprintf (stderr, ".");
      failureCount += testDirectory (i);
    }
  fprintf (stderr, "\n");

  if (failureCount == 0)
    return 0;
  else
    return 1;
}

/* end of directorytest.c */
