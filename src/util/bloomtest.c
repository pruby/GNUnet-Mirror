/**
 * @file test/bloomtest.c
 * @brief Testcase for the bloomfilter.
 * @author Igor Wronsky
 */

#include "gnunet_util.h"
#include "platform.h"

#define K 4
#define SIZE 65536

/**
 * Generate a random hashcode.
 */
static void nextHC(HashCode512 * hc) {
  makeRandomId(hc);
}

int main(int argc, char *argv[]) {
  struct Bloomfilter *bf;
  HashCode512 tmp;
  int i;
  int ok;
  int falseok;

  initUtil(argc, argv, NULL);
  srand(1);  
  UNLINK("/tmp/bloomtest.dat");
  bf = loadBloomfilter("/tmp/bloomtest.dat", SIZE, K);

  for(i=0;i<200;i++) {
    nextHC(&tmp);
    addToBloomfilter(bf, &tmp);
  }
  srand(1);
  ok=0;
  for(i=0;i<200;i++) {
    nextHC(&tmp);
    if (testBloomfilter(bf, &tmp) == YES)
      ok++;
  }
  if (ok != 200) {
    printf(" Got %d elements out of"
	   "200 expected after insertion.\n",
	   ok);
    doneUtil();
    return -1;
  }
  freeBloomfilter(bf);
 

   bf=loadBloomfilter("/tmp/bloomtest.dat", SIZE, K);
  
  srand(1);
  ok=0;
  for(i=0;i<200;i++) {
    nextHC(&tmp);
    if (testBloomfilter(bf, &tmp) == YES)
      ok++;
  }
  if (ok != 200) {
    printf(" Got %d elements out of 200"
	   "expected after reloading.\n", 
	   ok);
    doneUtil();
    return -1;
  }

  srand(1);  
  for(i=0;i<100;i++) {
    nextHC(&tmp);
    delFromBloomfilter(bf, &tmp);
  }

  srand(1);

  ok=0;
  for(i=0;i<200;i++) {
    nextHC(&tmp);
    if(testBloomfilter(bf, &tmp) == YES)
      ok++;
  }
  
  if (ok != 100) {
    printf(" Expected 100 elements in filter"
	   " after adding 200 and deleting 100, got %d\n", 
	   ok);
    doneUtil();
    return -1; 
  } 

  srand(3);
 
  falseok=0;
  for(i=0;i<1000;i++) {
    nextHC(&tmp);
    if(testBloomfilter(bf, &tmp) == YES)
      falseok++;
  }
 
  freeBloomfilter(bf);
  
  UNLINK("/tmp/bloomtest.dat"); 
  doneUtil();
  return(0);
}


