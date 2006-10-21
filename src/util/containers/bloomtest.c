/*
     This file is part of GNUnet.
     (C) 2004 Christian Grothoff (and other contributing authors)

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
 * @file test/containers/bloomtest.c
 * @brief Testcase for the bloomfilter.
 * @author Igor Wronsky
 */

#include "gnunet_util.h"
#include "gnunet_util_containers.h"
#include "gnunet_util_crypto.h"
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

  srand(1);
  UNLINK("/tmp/bloomtest.dat");
  bf = loadBloomfilter(NULL,
		       "/tmp/bloomtest.dat",
		       SIZE,
		       K);

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
    return -1;
  }
  freeBloomfilter(bf);


  bf=loadBloomfilter(NULL,
		     "/tmp/bloomtest.dat",
		     SIZE,
		     K);

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
  return 0;
}


