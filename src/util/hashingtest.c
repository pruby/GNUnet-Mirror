/**
 * Test for hashing.c
 * @author Christian Grothoff
 * @file util/hashingtest.c
 */

#include "platform.h"
#include "gnunet_util.h"
#include "locking_gcrypt.h"

static int test(int number) {
  HashCode512 h1;
  HashCode512 h2;
  EncName enc;

  memset(&h1, number, sizeof(HashCode512));
  hash2enc(&h1, &enc);
  if (OK != enc2hash((char*)&enc, &h2)) {
    printf("enc2hash failed!\n");
    return 1;
  }

  if (! equalsHashCode512(&h1, &h2)) {
    return 1;
  }
  return 0;
}

static int testEncoding() {
  int i;
  for (i=0;i<255;i++)
    if (0 != test(i))
      return 1;
  return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;
  int i;

  initLockingGcrypt();
  for (i=0;i<10;i++)
    failureCount += testEncoding();
  doneLockingGcrypt();
  if (failureCount == 0)
    return 0;
  else
    return 1;
}

/* end of hashingtest.c */
