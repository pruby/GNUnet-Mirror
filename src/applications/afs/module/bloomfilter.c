/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003 Christian Grothoff (and other contributing authors)

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
 * Bloomfilter implementation.
 *
 * @author Christian Grothoff
 * @file applications/afs/module/bloomfilter.c
 */

#include "bloomfilter.h"
#include "manager.h"

/**
 * Filters.
 */
Bloomfilter * superBloomFilter;
Bloomfilter * singleBloomFilter;

#define BLOOMFILTER1 "content_bloomfilter"
#define BLOOMFILTER2 "keyword_bloomfilter"

void initBloomfilters() {
  char * fn;
  char * bf;
  unsigned int quota;
  unsigned int * qt;
  int len;
  unsigned int superbf_size;
  unsigned int singlbf_size;

  fn = getFileName("AFS",
                   "AFSDIR",
                   _("Configuration must specify directory for "
		     "AFS data in section '%s' under '%s'.\n"));
  mkdirp(fn);

  /* read existing quota, check if it changed */
  qt = NULL;
  len = stateReadContent("AFS-DISKQUOTA",
			 (void**)&qt);
  quota = getConfigurationInt("AFS",
			      "DISKQUOTA");
  if (len != sizeof(unsigned int)) {
    FREENONNULL(qt);
    qt = NULL;
    stateWriteContent("AFS-DISKQUOTA", 
		      sizeof(unsigned int),
		      &quota);
  } else {
    if (*qt != quota)
      errexit(_("AFS-Quota changed, run gnunet-convert!\n"));
    FREENONNULL(qt);
    qt = NULL;
  }
  quota = quota * 1024; /* convert to kb */
  singlbf_size = quota;    /* 8 bit per entry/kb in DB */
  superbf_size = quota;    /* WAS 1/32th of quota in 0.6.1a, which
			      is WRONG.  Thus the conversion code below */

  bf = MALLOC(strlen(fn)+
	      strlen(BLOOMFILTER1)+2);
  strcpy(bf, fn);
  strcat(bf, "/");
  strcat(bf, BLOOMFILTER1);
  superBloomFilter 
    = loadBloomfilter(bf,
		      superbf_size,
		      5); /* approx. 3% false positives at max use */
  FREE(bf);

  bf = MALLOC(strlen(fn)+
	      strlen(BLOOMFILTER2)+2);
  strcpy(bf, fn);
  strcat(bf, "/");
  strcat(bf, BLOOMFILTER2);
  singleBloomFilter 
    = loadBloomfilter(bf,
		      singlbf_size,
		      5); /* approx. 3% false positives at max use */
  FREE(bf);
  FREE(fn);
}

void doneBloomfilters() {
  freeBloomfilter(singleBloomFilter);
  freeBloomfilter(superBloomFilter);
}

void bf_deleteEntryCallback(const HashCode160 * key,
			    const ContentIndex * ce,
			    void * data,
			    unsigned int datalen,
			    void * closure) {
  switch (ntohs(ce->type)) {
  case LOOKUP_TYPE_CHK:
  case LOOKUP_TYPE_3HASH:
  case LOOKUP_TYPE_SBLOCK:
    delFromBloomfilter(singleBloomFilter,
		       key);
    break;
  case LOOKUP_TYPE_SUPER:
    delFromBloomfilter(superBloomFilter,
		       key);
    break;
  case LOOKUP_TYPE_CHKS:
    break;
  default:
    LOG(LOG_WARNING,
	_("Bloom filter notified of deletion of"
	  " unexpected type %d of content at %s:%d.\n"),
	ntohs(ce->type),
	__FILE__, __LINE__);
  }
  FREENONNULL(data);
}


/* end of bloomfilter.c */

