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
#include "gnunet_util_config_impl.h"

#define CHECK(a) { if (! (a)) { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; } }

static struct GC_Configuration * cfg;

static ECRS_FileInfo fi1;

static ECRS_FileInfo fi2;

static unsigned int notifications;

static int notified(const ECRS_FileInfo * fi,
		    const HashCode512 * key,
		    int isRoot,
		    void * cls) {
  if ( (fi1.meta != NULL) &&
       (fi1.uri != NULL) &&
       (ECRS_equalsMetaData(fi->meta,
			    fi1.meta)) &&
       (ECRS_equalsUri(fi->uri,
		       fi1.uri)) ) {
    notifications++;
    return OK;
  }
  if ( (fi2.meta != NULL) &&
       (fi2.uri != NULL) &&
       (ECRS_equalsMetaData(fi->meta,
			    fi2.meta)) &&
       (ECRS_equalsUri(fi->uri,
		       fi2.uri)) ) {
    notifications++;
    return OK;
  }
  return OK;
}

static int processor(const ECRS_FileInfo * fi,
		     const HashCode512 * key,
		     int isRoot,
		     void * cls) {
  if ( (fi1.meta != NULL) &&
       (fi1.uri != NULL) &&
       (ECRS_equalsMetaData(fi->meta,
			    fi1.meta)) &&
       (ECRS_equalsUri(fi->uri,
		       fi1.uri)) ) {
    ECRS_freeUri(fi1.uri);
    fi1.uri = NULL;
    ECRS_freeMetaData(fi1.meta);
    fi1.meta = NULL;
    return OK;
  }
  if ( (fi2.meta != NULL) &&
       (fi2.uri != NULL) &&
       (ECRS_equalsMetaData(fi->meta,
			    fi2.meta)) &&
       (ECRS_equalsUri(fi->uri,
		       fi2.uri)) ) {
    ECRS_freeUri(fi2.uri);
    fi2.uri = NULL;
    ECRS_freeMetaData(fi2.meta);
    fi2.meta = NULL;
    return OK;
  }
  return SYSERR;
}

static int testTracking() {
  static const char * k1[] = {
    "foo",
    NULL,
  };
  static const char * k2[] = {
    "foot",
    NULL,
  };
  fi1.uri = ECRS_keywordsToUri(k1);
  fi1.meta = ECRS_createMetaData();
  ECRS_addToMetaData(fi1.meta,
		     EXTRACTOR_MIMETYPE,
		     "foo/bar");
  fi2.uri = ECRS_keywordsToUri(k2);
  fi2.meta = ECRS_createMetaData();
  ECRS_addToMetaData(fi2.meta,
		     EXTRACTOR_MIMETYPE,
		     "foo/bar");

  URITRACK_clearTrackedURIS(NULL,
			    cfg);
  URITRACK_registerTrackCallback(NULL,
				 cfg,
				 &notified,
				 NULL);
  URITRACK_trackURIS(NULL,
		     cfg,
		     NO);
  URITRACK_clearTrackedURIS(NULL,
			    cfg);
  /* test non-tracking */
  URITRACK_trackURI(NULL,
		    cfg,
		    &fi1);
  CHECK(0 == URITRACK_listURIs(NULL,
			       cfg,
			       NO,
			       NULL,
			       NULL));
  CHECK(NO == URITRACK_trackStatus(NULL,
				   cfg));
  URITRACK_clearTrackedURIS(NULL,
			    cfg);
  URITRACK_trackURIS(NULL,
		     cfg,
		     YES);
  URITRACK_clearTrackedURIS(NULL,
			    cfg);
  CHECK(0 == URITRACK_listURIs(NULL,
			       cfg,
			       NO,
			       NULL,
			       NULL));
  CHECK(YES == URITRACK_trackStatus(NULL,
				    cfg));
  URITRACK_trackURI(NULL,
		    cfg,
		    &fi1);
  CHECK(1 == URITRACK_listURIs(NULL,
			       cfg,
			       NO,
			       NULL,
			       NULL));
  URITRACK_trackURI(NULL,
		    cfg,
		    &fi2);
  CHECK(2 == URITRACK_listURIs(NULL,
			       cfg,
			       YES,
			       &processor,
			       NULL));
  URITRACK_trackURIS(NULL,
		     cfg,
		     NO);
  CHECK(NO == URITRACK_trackStatus(NULL,
				   cfg));
  URITRACK_clearTrackedURIS(NULL,
			    cfg);
  CHECK(notifications == 2);
  URITRACK_unregisterTrackCallback(&notified,
				   NULL);
  return 0;
}

int main(int argc,
	 char * argv[]) {
  int failureCount = 0;

  cfg = GC_create_C_impl();
  if (-1 == GC_parse_configuration(cfg,
				   "check.conf")) {
    GC_free(cfg);
    return -1;
  }
  failureCount += testTracking();
  GC_free(cfg);
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of tracktest.c */
