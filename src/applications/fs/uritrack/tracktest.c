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
 * @file applications/fs/uritrack/tracktest.c
 * @brief Test for uritrack library
 * @author Christian Grothoff
 */

#include "platform.h"
#include <extractor.h>
#include "gnunet_util.h"
#include "gnunet_uritrack_lib.h"

#define CHECK(a) { if (! (a)) { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; } }

static struct GNUNET_GC_Configuration *cfg;

static GNUNET_ECRS_FileInfo fi1;

static GNUNET_ECRS_FileInfo fi2;

static unsigned int notifications;

static int
notified (const GNUNET_ECRS_FileInfo * fi,
          const GNUNET_HashCode * key, int isRoot, void *cls)
{
  if ((fi1.meta != NULL) &&
      (fi1.uri != NULL) &&
      (GNUNET_ECRS_meta_data_test_equal (fi->meta,
                                         fi1.meta))
      && (GNUNET_ECRS_uri_test_equal (fi->uri, fi1.uri)))
    {
      notifications++;
      return GNUNET_OK;
    }
  if ((fi2.meta != NULL) &&
      (fi2.uri != NULL) &&
      (GNUNET_ECRS_meta_data_test_equal (fi->meta,
                                         fi2.meta))
      && (GNUNET_ECRS_uri_test_equal (fi->uri, fi2.uri)))
    {
      notifications++;
      return GNUNET_OK;
    }
  return GNUNET_OK;
}

static int
processor (const GNUNET_ECRS_FileInfo * fi,
           const GNUNET_HashCode * key, int isRoot, void *cls)
{
  if ((fi1.meta != NULL) &&
      (fi1.uri != NULL) &&
      (GNUNET_ECRS_meta_data_test_equal (fi->meta,
                                         fi1.meta))
      && (GNUNET_ECRS_uri_test_equal (fi->uri, fi1.uri)))
    {
      GNUNET_ECRS_uri_destroy (fi1.uri);
      fi1.uri = NULL;
      GNUNET_ECRS_meta_data_destroy (fi1.meta);
      fi1.meta = NULL;
      return GNUNET_OK;
    }
  if ((fi2.meta != NULL) &&
      (fi2.uri != NULL) &&
      (GNUNET_ECRS_meta_data_test_equal (fi->meta,
                                         fi2.meta))
      && (GNUNET_ECRS_uri_test_equal (fi->uri, fi2.uri)))
    {
      GNUNET_ECRS_uri_destroy (fi2.uri);
      fi2.uri = NULL;
      GNUNET_ECRS_meta_data_destroy (fi2.meta);
      fi2.meta = NULL;
      return GNUNET_OK;
    }
  return GNUNET_SYSERR;
}

static int
testTracking ()
{
  fi1.uri = GNUNET_ECRS_keyword_string_to_uri (NULL, "foo");
  fi1.meta = GNUNET_ECRS_meta_data_create ();
  GNUNET_ECRS_meta_data_insert (fi1.meta, EXTRACTOR_MIMETYPE, "foo/bar");
  fi2.uri = GNUNET_ECRS_keyword_string_to_uri (NULL, "foot");
  fi2.meta = GNUNET_ECRS_meta_data_create ();
  GNUNET_ECRS_meta_data_insert (fi2.meta, EXTRACTOR_MIMETYPE, "foo/bar");

  GNUNET_URITRACK_clear (NULL, cfg);
  GNUNET_URITRACK_register_track_callback (NULL, cfg, &notified, NULL);
  GNUNET_URITRACK_toggle_tracking (NULL, cfg, GNUNET_NO);
  GNUNET_URITRACK_clear (NULL, cfg);
  /* test non-tracking */
  GNUNET_URITRACK_track (NULL, cfg, &fi1);
  CHECK (0 == GNUNET_URITRACK_list (NULL, cfg, GNUNET_NO, NULL, NULL));
  CHECK (GNUNET_NO == GNUNET_URITRACK_get_tracking_status (NULL, cfg));
  GNUNET_URITRACK_clear (NULL, cfg);
  CHECK (notifications == 0);
  GNUNET_URITRACK_toggle_tracking (NULL, cfg, GNUNET_YES);
  GNUNET_URITRACK_clear (NULL, cfg);
  CHECK (0 == GNUNET_URITRACK_list (NULL, cfg, GNUNET_NO, NULL, NULL));
  CHECK (GNUNET_YES == GNUNET_URITRACK_get_tracking_status (NULL, cfg));
  GNUNET_URITRACK_track (NULL, cfg, &fi1);
  CHECK (1 == GNUNET_URITRACK_list (NULL, cfg, GNUNET_NO, NULL, NULL));
  GNUNET_URITRACK_track (NULL, cfg, &fi2);
  CHECK (2 == GNUNET_URITRACK_list (NULL, cfg, GNUNET_YES, &processor, NULL));
  GNUNET_URITRACK_toggle_tracking (NULL, cfg, GNUNET_NO);
  CHECK (GNUNET_NO == GNUNET_URITRACK_get_tracking_status (NULL, cfg));
  GNUNET_URITRACK_clear (NULL, cfg);
  CHECK (notifications >= 2);
  GNUNET_URITRACK_unregister_track_callback (&notified, NULL);
  return 0;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  failureCount += testTracking ();
  GNUNET_GC_free (cfg);
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of tracktest.c */
