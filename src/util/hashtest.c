/**
 * @file test/hashtest.c
 * @brief testcase for util/hashing.c
 */

#include "gnunet_util.h"
#include "platform.h"

/**
 * Perform option parsing from the command line.
 */
static int parseCommandLine(int argc,
			    char * argv[]) {
  return OK;
}

int main(int argc, char * argv[]){
  HashCode512 hc;

  initUtil(argc, argv, &parseCommandLine);
  hash("TEST", 4, &hc);
  if ( (hc.bits[0] != ntohl(2080019878)) ||
       (hc.bits[1] != ntohl(-2003678137)) ||
       (hc.bits[2] != ntohl(-942529663)) ||
       (hc.bits[3] != ntohl(-234043098)) ||
       (hc.bits[4] != ntohl(-182141268)) ) {
    printf("Hash of TEST wrong (%d, %d, %d, %d, %d).\n",
	   ntohl(hc.bits[0]),
	   ntohl(hc.bits[1]),
	   ntohl(hc.bits[2]),
	   ntohl(hc.bits[3]),
	   ntohl(hc.bits[4]));
    return -1;
  }
  hash(NULL, 0, &hc);
  if ( (hc.bits[0] != ntohl(-813440715)) ||
       (hc.bits[1] != ntohl(2129639613)) ||
       (hc.bits[2] != ntohl(-246142896)) ||
       (hc.bits[3] != ntohl(-697466873)) ||
       (hc.bits[4] != ntohl(-702487547)) ) {
    printf("Hash of nothing (0-size) wrong  (%d, %d, %d, %d, %d).\n",
	   ntohl(hc.bits[0]),
	   ntohl(hc.bits[1]),
	   ntohl(hc.bits[2]),
	   ntohl(hc.bits[3]),
	   ntohl(hc.bits[4]));
    return -1;
  }
  doneUtil();
  return 0;
}
