/**
 * SymCipher weak key testcode.
 * @author Krista Bennett
 * @author Christian Grothoff
 * @file test/weakkeytest.c
 */

#if USE_GCRYPT
  #include <gcrypt.h>
#endif

#include "gnunet_util.h"

#define MAX_WEAK_KEY_TRIALS 10000
#define GENERATE_WEAK_KEYS 0
#define WEAK_KEY_TESTSTRING "I hate weak keys."

#if USE_GCRYPT
void printWeakKey(SESSIONKEY* key) {
    int i;
    for (i = 0; i < SESSIONKEY_LEN; i++) {
	printf("%x ", (int)(key->key[i]));
    }
}

int testWeakKey() {

  char result[100];  
  char res[100];
  int size;
  SESSIONKEY weak_key;

  weak_key.key[0]= (char)(0x4c); 
  weak_key.key[1]= (char)(0x31);
  weak_key.key[2]= (char)(0xc6); 
  weak_key.key[3]= (char)(0x2b); 
  weak_key.key[4]= (char)(0xc1);
  weak_key.key[5]= (char)(0x5f);
  weak_key.key[6]= (char)(0x4d);
  weak_key.key[7]= (char)(0x1f);
  weak_key.key[8]= (char)(0x31);
  weak_key.key[9]= (char)(0xaa);
  weak_key.key[10]= (char)(0x12); 
  weak_key.key[11]= (char)(0x2e);
  weak_key.key[12]= (char)(0xb7);
  weak_key.key[13]= (char)(0x82);
  weak_key.key[14]= (char)(0xc0);
  weak_key.key[15]= (char)(0xb6);

  size = encryptBlock(WEAK_KEY_TESTSTRING,
                      strlen(WEAK_KEY_TESTSTRING)+1,
                      &weak_key,
                      INITVALUE,
                      result);
   
  if (size == -1) {
    printf("weakkeytest failed: encryptBlock returned %d\n",
           size);
    return 1;
  }

  size = decryptBlock(&weak_key,
                      result,
                      size,
                      INITVALUE,
                      res);

  if ((strlen(WEAK_KEY_TESTSTRING)+1) != size) {
    printf("weakkeytest failed: decryptBlock returned %d\n",
           size);
    return 1;
  }
  if (0 != strcmp(res,WEAK_KEY_TESTSTRING)) {
    printf("weakkeytest failed: %s != %s\n", res, WEAK_KEY_TESTSTRING);
    return 1;
  } 
  else
    return 0;
}

int getWeakKeys() {

  SESSIONKEY sessionkey;
  int number_of_weak_keys = 0;
  int number_of_runs;

  gcry_cipher_hd_t handle;
  int rc;
  
  for (number_of_runs = 0; number_of_runs < MAX_WEAK_KEY_TRIALS; 
       number_of_runs++) {

    if (number_of_runs % 1000 == 0) printf(".");
      /*printf("Got to run number %d.\n", number_of_runs);*/
    makeSessionkey(&sessionkey);

    rc = gcry_cipher_open(&handle,
			  GCRY_CIPHER_BLOWFISH,
			  GCRY_CIPHER_MODE_CFB,
			  0);

    if (rc) {
      printf("testweakkey: gcry_cipher_open failed on trial %d. %s\n",
	     number_of_runs, gcry_strerror(rc));
      rc = 0;
      continue;
    }

    rc = gcry_cipher_setkey(handle,
			    &sessionkey, 
			    sizeof(SESSIONKEY));

    if ((char)rc == GPG_ERR_WEAK_KEY) {    
      printf("\nWeak key (in hex): ");
      printWeakKey(&sessionkey);
      printf("\n");
      number_of_weak_keys++;
    }
    else if (rc) {
      printf("\nUnexpected error generating keys. Error is %s\n", 
             gcry_strerror(rc));
    }

    gcry_cipher_close(handle);
	    
  }

  return number_of_weak_keys;
}
#endif

int main(int argc, char * argv[]) {

#if USE_GCRYPT
  int weak_keys; 

  if (GENERATE_WEAK_KEYS) {
    weak_keys = getWeakKeys();
  
    if (weak_keys == 0) {
      printf("No weak keys found in %d runs.", MAX_WEAK_KEY_TRIALS);
    }
    else {
      printf("%d weak keys found in %d.\n",weak_keys, MAX_WEAK_KEY_TRIALS);
    }
  }

  if (testWeakKey() == 0)
     return 0;
  else {
    printf("WEAK KEY TEST FAILED.\n");
    return -1;
  }
#else
  return 0;
#endif
} 

/* end of weakkeytest.c */
