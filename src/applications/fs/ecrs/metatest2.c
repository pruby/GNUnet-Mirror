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
 * @file applications/fs/ecrs/metatest2.c
 * @brief Test for meta.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include <extractor.h>
#include "gnunet_util.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }

static int testMeta() {
  struct ECRS_MetaData * m;
  char * val;
  unsigned int size;

  m = ECRS_createMetaData();
  if (OK != ECRS_addToMetaData(m,
			       EXTRACTOR_UNKNOWN,
			       "link"))
    ABORT();
  if (OK != ECRS_addToMetaData(m,
			       EXTRACTOR_FILENAME,
			       "lib-link.m4"))
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
  ECRS_freeMetaData(m);
  return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;

  failureCount += testMeta();

  if (failureCount == 0)
    return 0;
  else
    return 1;
}

/* end of metatest2.c */
