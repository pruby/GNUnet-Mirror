/** 
 * @file util/kblockkey_test.c
 * @brief testcase for util/kblockkey.c
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"


#define TESTSTRING "Hello World\0"
#define MAX_TESTVAL 20
#define ITER 10

static int testEncryptDecrypt(PrivateKey hostkey) {
  PublicKey pkey;
  RSAEncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  TIME_T start;
  int ok;

  fprintf(stderr, "W");
  getPublicKey(hostkey, &pkey);

  ok = 0;
  TIME(&start);
  for (i=0;i<ITER;i++) {
    fprintf(stderr, ".");
    if (SYSERR == encryptPrivateKey(TESTSTRING,
				 strlen(TESTSTRING)+1,
				 &pkey,
				 &target)) {
      fprintf(stderr, 
	      "encryptPrivateKey returned SYSERR\n");
      ok++;
      continue;
    }
    if (-1 == decryptPrivateKey(hostkey,
			     &target, 
			     result,
			     MAX_TESTVAL)) {
     fprintf(stderr, 
	      "decryptPrivateKey returned SYSERR\n");
      ok++;
      continue;
    }
    if (strncmp(TESTSTRING, result,
		strlen(TESTSTRING)) != 0) {
      printf("%s != %.*s - testEncryptDecrypt failed!\n",
	     TESTSTRING, 
	     MAX_TESTVAL, 
	     result);
      ok++;
      continue;
    }
  }
  printf("%d RSA encrypt/decrypt operations %ds (%d failures)\n", 
	 ITER,
	 (int) (TIME(NULL)-start),
	 ok);
  if (ok == 0)
    return OK;
  else
    return SYSERR;
}

static int testSignVerify(PrivateKey hostkey) {
  Signature sig;
  PublicKey pkey;
  int i;
  TIME_T start;
  int ok = OK;
  
  fprintf(stderr, "W");
  getPublicKey(hostkey, &pkey);
  TIME(&start);
  for (i=0;i<ITER;i++) {
    fprintf(stderr, ".");
    if (SYSERR == sign(hostkey, strlen(TESTSTRING), TESTSTRING, &sig)) {
      fprintf(stderr,
	      "sign returned SYSERR\n");
      ok = SYSERR;
      continue;
    }
    if (SYSERR == verifySig(TESTSTRING, strlen(TESTSTRING), &sig, &pkey)) {
      printf("testSignVerify failed!\n");
      ok = SYSERR;
      continue;
    }
  }
  printf("%d RSA sign/verify operations %ds\n", 
	 ITER, 
	 (int) (TIME(NULL)-start));
  return ok;
}

static int testPrivateKeyEncoding(PrivateKey hostkey) {
  PrivateKeyEncoded * encoding;
  PublicKey pkey;
  RSAEncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  TIME_T start;
  int ok = OK;

  fprintf(stderr, "W");

  TIME(&start);
  for (i=0;i<ITER;i++) {
    fprintf(stderr, ".");
    getPublicKey(hostkey, &pkey);
    if (SYSERR == encryptPrivateKey(TESTSTRING,
				 strlen(TESTSTRING)+1,
				 &pkey,
				 &target)) {
      fprintf(stderr,
	      "encryptPrivateKey returned SYSERR\n");
      ok = SYSERR;
      continue;
    }
    encoding = encodePrivateKey(hostkey);
    if (encoding == NULL) {
      fprintf(stderr,
	      "encodePrivateKey returned NULL\n");
      ok = SYSERR;
      continue;
    }
    hostkey = decodePrivateKey(encoding);
    FREE(encoding);
    if (SYSERR == decryptPrivateKey(hostkey, &target, result, MAX_TESTVAL)) {
      fprintf(stderr,
	      "decryptPrivateKey returned SYSERR\n");
      ok = SYSERR;
      continue;
    }  
    if (strncmp(TESTSTRING, result,
		strlen(TESTSTRING)) != 0) {
      printf("%s != %.*s - testEncryptDecrypt failed!\n",
	     TESTSTRING, 
	     (int) strlen(TESTSTRING), 
	     result);
      ok = SYSERR;
      continue;
    }
  }  
  printf("%d RSA encrypt/encode/decode/decrypt operations %ds\n", 
	 ITER, 
	 (int) (TIME(NULL)-start));
  return ok;
}


void initRAND(); /* hostkey_* */

#if ! USE_OPENSSL
void initLockingGcrypt();
void doneLockingGcrypt();
#endif


int main(int argc, char * argv[]) {
  int failureCount = 0;
  HashCode160 in;
  PrivateKey hostkey;

#if USE_GCRYPT
  initLockingGcrypt();
#endif
  initRAND();  
  makeRandomId(&in);

  hostkey = makeKblockKey(&in);
  if (hostkey == NULL) {
    printf("\nmakeKblockKey failed!\n");
    return 1;
  } 

 if (OK != testEncryptDecrypt(hostkey))
     failureCount++;
  if (OK != testSignVerify(hostkey))
    failureCount++;       
  if (OK != testPrivateKeyEncoding(hostkey)) 
    failureCount++;
  freePrivateKey(hostkey);
#if ! USE_OPENSSL
  doneLockingGcrypt();
#endif

  if (failureCount == 0)
    return 0;
  else {
    printf("\n\n%d TESTS FAILED!\n\n",failureCount);
    return -1;
  }  
}
