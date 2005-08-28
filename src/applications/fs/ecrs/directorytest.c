/*
     This file is part of GNUnet.
     (C) 2005 Christian Grothoff (and other contributing authors)

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

struct PCLS {
  ECRS_FileInfo * fi;
  unsigned int pos;
};

static int processor(const ECRS_FileInfo * fi,
		     const HashCode512 * key,
		     int isRoot,
		     void * cls) {
  struct PCLS * p = cls;

  if (ECRS_equalsMetaData(p->fi[p->pos].meta,
			  fi->meta) &&
      ECRS_equalsUri(p->fi[p->pos].uri,
		     fi->uri)) {
    p->pos++;
    return OK;
  } else {
    fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__);
    return SYSERR;
  }
}

static int testDirectory(unsigned int i) {
  char * data;
  unsigned long long dlen;
  ECRS_FileInfo * fis;
  struct ECRS_MetaData * meta;
  struct ECRS_MetaData * meta2;
  struct PCLS cls;
  int p;
  int q;
  char uri[512];
  char txt[128];

  fis = MALLOC(sizeof(ECRS_FileInfo) * i);
  for (p=0;p<i;p++) {
    fis[p].meta = ECRS_createMetaData();
    for (q=0;q<=p;q++) {
      SNPRINTF(txt,
	       128,
	       "%u -- %u\n",
	       p, q);
      ECRS_addToMetaData(fis[p].meta,
			 q % EXTRACTOR_getHighestKeywordTypeNumber(),
			 txt);
    }
    SNPRINTF(uri,
	     512,
	     "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.%u",
	     p);
    fis[p].uri = ECRS_stringToUri(uri);
    if (fis[p].uri == NULL)
      ABORT(); /* error in testcase */
  }
  meta = ECRS_createMetaData();
  ECRS_addToMetaData(meta,
		     EXTRACTOR_TITLE,
		     "A title");
  ECRS_addToMetaData(meta,
		     EXTRACTOR_AUTHOR,
		     "An author");
  if (OK != ECRS_createDirectory(&data,
				 &dlen,
				 i,
				 fis,
				 meta))
    ABORT();
  cls.pos = 0;
  cls.fi = fis;
  if (i != ECRS_listDirectory(data,
			      dlen,
			      &meta2,
			      &processor,
			      &cls)) {
    printf("expected %u\n", i);
    ABORT();
  }
  if (! ECRS_equalsMetaData(meta,
			    meta2))
    ABORT();
  ECRS_freeMetaData(meta);
  ECRS_freeMetaData(meta2);
  for (p=0;p<i;p++) {
    ECRS_freeMetaData(fis[p].meta);
    ECRS_freeUri(fis[p].uri);
  }
  FREE(fis);
  return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;
  int i;

  for (i=17;i<2000;i*=2) {
    fprintf(stderr, ".");
    failureCount += testDirectory(i);
  }
  fprintf(stderr, "\n");

  if (failureCount == 0)
    return 0;
  else
    return 1;
}

/* end of directorytest.c */
