/**
 * SymCipher testcode.
 * @author Christian Grothoff
 * @file util/symciphertest.c
 */

#include "platform.h"
#include "gnunet_util.h"
#include "locking_gcrypt.h"

#define TESTSTRING "Hello World!"
#define INITVALUE "InitializationVectorValue"

static int testSymcipher() {
  SESSIONKEY key;
  char result[100];
  int size;
  char res[100];

  makeSessionkey(&key);
  size = encryptBlock(TESTSTRING,
		      strlen(TESTSTRING)+1,
		      &key,
		      (const INITVECTOR*) INITVALUE,
		      result);
  if (size == -1) {
    printf("symciphertest failed: encryptBlock returned %d\n",
	  size);
    return 1;
  }
  size = decryptBlock(&key,
		      result,
		      size,
		      (const INITVECTOR*) INITVALUE,
		      res);
  if (strlen(TESTSTRING)+1
      != size) {
    printf("symciphertest failed: decryptBlock returned %d\n",
	  size);
    return 1;
  }
  if (0 != strcmp(res,TESTSTRING)) {
    printf("symciphertest failed: %s != %s\n",
	   res, TESTSTRING);
    return 1;
  } else
    return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;

  GNUNET_ASSERT(strlen(INITVALUE) > sizeof(INITVECTOR));
  initLockingGcrypt();
  failureCount += testSymcipher();
  doneLockingGcrypt();

  if (failureCount == 0)
    return 0;
  else {
    printf("%d TESTS FAILED!\n",failureCount);
    return -1;
  }
}

/* end of symciphertest.c */
