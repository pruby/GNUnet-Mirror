/**
 * Test for uri.c
 * @author Christian Grothoff
 * @file applications/afs/esed2/uritest.c
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_afs_esed2.h"

#define ABORT() { fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); return 1; }

static int testKeyword() {
  char ** keywords;
  char * uri;

  if (SYSERR != parseKeywordURI("gnunet://afs/++",
				&keywords))
    ABORT();
  if (2 != parseKeywordURI("gnunet://afs/foo+bar",
			   &keywords))
    ABORT();
  if ( (0 != strcmp("foo", keywords[0])) ||
       (0 != strcmp("bar", keywords[1])))
    ABORT();
  uri = createKeywordURI(keywords, 2);
  if ( (0 != strcmp(uri,
		    "gnunet://afs/foo+bar")) &&
       (0 != strcmp(uri,
		    "gnunet://afs/search/foo+bar")) )
    ABORT();
  FREE(uri); 
  uri = createKeywordURI(keywords, 1);
  if ( (0 != strcmp(uri,
		    "gnunet://afs/foo")) &&
       (0 != strcmp(uri,
		    "gnunet://afs/search/foo")) )
    ABORT();
  FREE(uri);
  FREE(keywords[0]);
  FREE(keywords[1]);
  FREE(keywords);
  return 0;
}

static int testNamespace(int i) {
  char * uri;
  HashCode160 ns1;
  HashCode160 ns2;
  HashCode160 id1;
  HashCode160 id2;
  
  memset(&ns1, i, sizeof(HashCode160));
  memset(&id1, 255-i, sizeof(HashCode160));
  uri = createSubspaceURI(&ns1, &id1);
  if (OK != parseSubspaceURI(uri,
			     &ns2,
			     &id2))
    ABORT();
  FREE(uri);
  if ( (0 != memcmp(&id1, &id2, sizeof(HashCode160))) ||
       (0 != memcmp(&ns1, &ns2, sizeof(HashCode160))) )
    ABORT();  
  return 0;
}

static int testFile(int i) {
  char * uri;
  FileIdentifier fi;
  FileIdentifier fo;
  
  memset(&fi, i, sizeof(FileIdentifier));
  uri = createFileURI(&fi);
  if (OK != parseFileURI(uri,
			 &fo))
    ABORT();
  FREE(uri);
  if (0 != memcmp(&fi, &fo, sizeof(FileIdentifier)))
    ABORT();  
  return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;
  int i;
  
  failureCount += testKeyword();
  for (i=0;i<255;i++) {
    failureCount += testNamespace(i);
    failureCount += testFile(i);
  }

  if (failureCount == 0)
    return 0;
  else 
    return 1;
} 

/* end of uritest.c */
