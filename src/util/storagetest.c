/**
 * @file test/storagetest.c
 * @brief testcase for the storage module
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

#define TESTSTRING "Hello World\0"

static int testReadWrite() {
  HashCode160 ha;
  EncName filename;
  char tmp[100];

  hash(TESTSTRING, 
       strlen(TESTSTRING),
       &ha);
  hash2enc(&ha, &filename);
  writeFile((char*)&filename, TESTSTRING, strlen(TESTSTRING), "644");
  tmp[readFile((char*)&filename, 100, tmp)] = '\0';
  if (memcmp(tmp,TESTSTRING,strlen(TESTSTRING)+1) == 0) 
    return 0;
  else {    
    fprintf(stderr,
	    "Error in testReadWrite: *%s* != *%s* for file %s\n",
	    tmp,TESTSTRING,(char*)&filename);
    return 1;
  }
}

int main(int argc, char * argv[]) {
  int failureCount = 0;

  failureCount += testReadWrite(); 

  if (failureCount == 0)
    return 0;
  else {
    fprintf(stderr,
            "\n\n%d TESTS FAILED!\n\n",failureCount);
    return -1;
  }
} /* end of main */
