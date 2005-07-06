/*
     This file is part of GNUnet.
     (C) 2003, 2004 Christian Grothoff (and other contributing authors)

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

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }

static int testMeta(int i) {
  struct ECRS_MetaData * m;
  char * val;
  int j;
  unsigned int size;

  m = ECRS_createMetaData();
  if (OK != ECRS_addToMetaData(m,
			       EXTRACTOR_TITLE,
			       "TestTitle"))
    ABORT();
  if (OK != ECRS_addToMetaData(m,
			       EXTRACTOR_AUTHOR,
			       "TestTitle"))
    ABORT();
  if (OK == ECRS_addToMetaData(m,
			       EXTRACTOR_TITLE,
			       "TestTitle")) /* dup! */
    ABORT();
  if (OK == ECRS_addToMetaData(m,
			       EXTRACTOR_AUTHOR,
			       "TestTitle")) /* dup! */
    ABORT();
  if (2 != ECRS_getMetaData(m, NULL, NULL))
    ABORT();
  if (OK != ECRS_delFromMetaData(m,
				 EXTRACTOR_AUTHOR,
				 "TestTitle"))
    ABORT();
  if (OK == ECRS_delFromMetaData(m,
				 EXTRACTOR_AUTHOR,
				 "TestTitle")) /* already gone */
    ABORT();
  if (1 != ECRS_getMetaData(m, NULL, NULL))
    ABORT();
  if (OK != ECRS_delFromMetaData(m,
				 EXTRACTOR_TITLE,
				 "TestTitle"))
    ABORT();
  if (OK == ECRS_delFromMetaData(m,
				 EXTRACTOR_TITLE,
				 "TestTitle")) /* already gone */
    ABORT();
  if (0 != ECRS_getMetaData(m, NULL, NULL))
    ABORT();
  val = MALLOC(256);
  for (j=0;j<i;j++) {
    SNPRINTF(val, 256, "%s.%d",
	     "A teststring that should compress well.",
	     j);
    if (OK != ECRS_addToMetaData(m,
				 EXTRACTOR_UNKNOWN,
				 val))
      ABORT();
  }
  FREE(val);
  if (i != ECRS_getMetaData(m, NULL, NULL))
    ABORT();

  size = ECRS_sizeofMetaData(m);
  val = MALLOC(size);
  if (size != ECRS_serializeMetaData(m,
				     val,
				     size,
				     NO))
    ABORT();
  ECRS_freeMetaData(m);
  m = ECRS_deserializeMetaData(val,
			       size);
  if (m == NULL)
    ABORT();
  FREE(val);
  val = MALLOC(256);
  for (j=0;j<i;j++) {
    SNPRINTF(val, 256, "%s.%d",
	     "A teststring that should compress well.",
	     j);
    if (OK != ECRS_delFromMetaData(m,
				   EXTRACTOR_UNKNOWN,
				   val))
      ABORT();
  }
  FREE(val);
  if (0 != ECRS_getMetaData(m, NULL, NULL))
    ABORT();

  ECRS_freeMetaData(m);
  return 0;
}

int testMetaMore(int i) {
  struct ECRS_MetaData * meta;
  int q;
  char txt[128];
  char * data;
  unsigned long long size;

  meta = ECRS_createMetaData();
  for (q=0;q<=i;q++) {
    SNPRINTF(txt,
	     128,
	     "%u -- %u\n",
	     i, q);
    ECRS_addToMetaData(meta,
		       q % EXTRACTOR_getHighestKeywordTypeNumber(),
		       txt);
  }
  size = ECRS_sizeofMetaData(meta);
  data = MALLOC(size * 4);
  if (size != ECRS_serializeMetaData(meta,
				     data,
				     size * 4,
				     NO))
    ABORT();
  FREE(data);
  return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;
  int i;

  for (i=0;i<255;i++)
    failureCount += testMeta(i);
  for (i=1;i<255;i++)
    failureCount += testMetaMore(i);

  if (failureCount == 0)
    return 0;
  else
    return 1;
}

/* end of metatest.c */
