/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/disk/storagetest.c
 * @brief testcase for the storage module
 * @author Christian Grothoff
 */

#include "gnunet_util.h"
#include "platform.h"

#define TESTSTRING "Hello World\0"

static int testReadWrite() {
  char tmp[100];

  disk_file_write(NULL,
		  ".testfile",
		  TESTSTRING,
		  strlen(TESTSTRING),
		  "644");
  tmp[disk_file_read(NULL,
		     ".testfile",
		     100,
		     tmp)] = '\0';
  if (0 != memcmp(tmp,
		  TESTSTRING,
		  strlen(TESTSTRING)+1)) {
    fprintf(stderr,
	    "Error in testReadWrite: *%s* != *%s* for file %s\n",
	    tmp,
	    TESTSTRING,
	    ".testfile");
    return 1;
  }
  UNLINK(".testfile");
  return 0;
}

int main(int argc, char * argv[]) {
  int failureCount = 0;

  failureCount += testReadWrite();
  if (failureCount != 0) {
    fprintf(stderr,
            "\n\n%d TESTS FAILED!\n\n",failureCount);
    return -1;
  }
  return 0;
} /* end of main */
