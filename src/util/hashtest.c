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
  HashCode160 hc;

  initUtil(argc, argv, &parseCommandLine);
  hash("TEST", 4, &hc);
  if ( (hc.a != ntohl(830102737)) ||
       (hc.b != ntohl(-2066785626)) ||
       (hc.c != ntohl(-326698784)) ||
       (hc.d != ntohl(-183450437)) ||
       (hc.e != ntohl(1019905624)) ) {
    printf("Hash of TEST wrong (%d, %d, %d, %d, %d).\n",
	   hc.a, hc.b, hc.c, hc.d, hc.e);
    return -1;
  }
  hash(NULL, 0, &hc);
  if ( (hc.a != ntohl(-1676573275)) ||
       (hc.b != ntohl(-974521260)) ||
       (hc.c != ntohl(1630013591)) ||
       (hc.d != ntohl(2129196360)) ||
       (hc.e != ntohl(-1306161871)) ) {
    printf("Hash of nothing (0-size) wrong  (%d, %d, %d, %d, %d).\n",
	   hc.a, hc.b, hc.c, hc.d, hc.e);
    return -1;
  }
  doneUtil();
  return 0;
}
