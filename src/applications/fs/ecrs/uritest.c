/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/ecrs/uritest.c
 * @brief Test for uri.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_util_crypto.h"
#include "gnunet_ecrs_lib.h"
#include "ecrs.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }

static int testKeyword() {
  char * uri;
  struct ECRS_URI * ret;

  if (NULL != ECRS_stringToUri(NULL, "gnunet://ecrs/ksk/++"))
    ABORT();
  ret = ECRS_stringToUri(NULL, "gnunet://ecrs/ksk/foo+bar");
  if (ret == NULL)
    ABORT();
  if (! ECRS_isKeywordUri(ret))
    ABORT();
  if ( (2 != ret->data.ksk.keywordCount) ||
       (0 != strcmp("foo", ret->data.ksk.keywords[0])) ||
       (0 != strcmp("bar", ret->data.ksk.keywords[1])) )
    ABORT();

  uri = ECRS_uriToString(ret);
  if (0 != strcmp(uri,
		  "gnunet://ecrs/ksk/foo+bar"))
    ABORT();
  FREE(uri);
  ECRS_freeUri(ret);
  return 0;
}

static int testLocation() {
  struct ECRS_URI * uri;
  char * uric;
  struct ECRS_URI * uri2;
  PublicKey pk;
  struct PrivateKey * hk;
  struct ECRS_URI * baseURI;

  baseURI = ECRS_stringToUri(NULL, "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.42");
  hk = makePrivateKey();
  getPublicKey(hk,
	       &pk);
  uri = ECRS_uriFromLocation(baseURI,
			     &pk,
			     TIME(NULL) + 60,
			     42, /* PROTO */
			     4, /* SAS */
			     1500, /* MTU */
			     "GNU!", /* location */
			     (ECRS_SignFunction) &sign,
			     hk);
  freePrivateKey(hk);
  if (uri == NULL) {
    GE_BREAK(NULL, 0);
    ECRS_freeUri(baseURI);
    return 1;
  }
  if (! ECRS_isLocationUri(uri)) {
    GE_BREAK(NULL, 0);
    ECRS_freeUri(uri);
    ECRS_freeUri(baseURI);
    return 1;
  }
  uri2 = ECRS_getContentUri(uri);
  if (! ECRS_equalsUri(baseURI,
		       uri2)) {
    GE_BREAK(NULL, 0);
    ECRS_freeUri(uri);
    ECRS_freeUri(uri2);
    ECRS_freeUri(baseURI);
    return 1;
  }
  ECRS_freeUri(uri2);
  ECRS_freeUri(baseURI);    
  uric = ECRS_uriToString(uri);
#if 0
  /* not for the faint of heart: */
  printf("URI: `%s'\n", uric);
#endif
  uri2 = ECRS_stringToUri(NULL, uric);
  FREE(uric);
  if (uri2 == NULL) {
    GE_BREAK(NULL, 0);
    ECRS_freeUri(uri);
    return 1;
  }
  if (YES != ECRS_equalsUri(uri,
			    uri2)) {
    GE_BREAK(NULL, 0);
    ECRS_freeUri(uri);
    ECRS_freeUri(uri2);
    return 1;
  }
  ECRS_freeUri(uri2);   
  ECRS_freeUri(uri);
  return 0;
}

static int testNamespace(int i) {
  char * uri;
  struct ECRS_URI * ret;

  if (NULL != ECRS_stringToUri(NULL, "gnunet://ecrs/sks/D1KJS9H2A82Q65VKQ0ML3RFU6U1D3VUK"))
    ABORT();
  if (NULL != ECRS_stringToUri(NULL, "gnunet://ecrs/sks/D1KJS9H2A82Q65VKQ0ML3RFU6U1D3V/test"))
    ABORT();
  if (NULL != ECRS_stringToUri(NULL, "gnunet://ecrs/sks/test"))
     ABORT();
  ret = ECRS_stringToUri(NULL, "gnunet://ecrs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/test");
  if (ret == NULL)
    ABORT();
  if (ECRS_isKeywordUri(ret))
    ABORT();
  if (! ECRS_isNamespaceUri(ret))
    ABORT();

  uri = ECRS_uriToString(ret);
  if (0 != strcmp(uri,
		  "gnunet://ecrs/sks/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820/TOJB1NAAUVJKJAGQHRHS22N9I8VM32C0ESN4EFS836IT950E1MP7LGC5V2GE3LFO9U4BP23VQPTH8DPIOC2CONT9LM76ULVL00KAHVO"))
    ABORT();
  FREE(uri);
  ECRS_freeUri(ret);
  return 0;
}

static int testFile(int i) {
  char * uri;
  struct ECRS_URI * ret;

  if (NULL != ECRS_stringToUri(NULL, "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H00000440000.42"))
    ABORT();
  if (NULL != ECRS_stringToUri(NULL, "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000"))
    ABORT();
  if (NULL != ECRS_stringToUri(NULL, "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.FGH"))
    ABORT();
  ret = ECRS_stringToUri(NULL, "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.42");
  if (ret == NULL)
    ABORT();
  if (ECRS_isKeywordUri(ret))
    ABORT();
  if (ECRS_isNamespaceUri(ret))
    ABORT();
  if (ntohll(ret->data.fi.file_length) != 42)
    ABORT();

  uri = ECRS_uriToString(ret);
  if (0 != strcmp(uri,
		  "gnunet://ecrs/chk/C282GG70GKK41O4551011DO413KFBVTVMQG1OG30I0K4045N0G41HAPB82G680A02JRVVFO8URVRU2F159011DO41000000022RG820.RNVVVVOOLCLK065B5D04HTNVNSIB2AI022RG8200HSLK1CO1000ATQ98824DMA2032LIMG50CG0K057NVUVG200000H000004400000.42")) {
    ABORT();
  }
  FREE(uri);
  ECRS_freeUri(ret);
  return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;
  int i;

  failureCount += testKeyword();
  failureCount += testLocation();
  for (i=0;i<255;i++) {
    failureCount += testNamespace(i);
    failureCount += testFile(i);
  }
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of uritest.c */
