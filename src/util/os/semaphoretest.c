/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file src/util/os/semaphoretest.c
 * @brief testcase for util/os/semaphore.c
 */

#include "gnunet_util.h"
#include "platform.h"

#include <sys/types.h>
#ifndef MINGW             /* PORT-ME MINGW */

static IPC_Semaphore * ipc;

static int testIPCSemaphore() {
  pid_t me;
  int cnt;
  int i;
  int j;
  FILE * fd;
  int ret;
  int si;
  int sw;

  ret = 0;
  REMOVE("/tmp/gnunet_ipc_xchange");
  REMOVE("/tmp/gnunet_ipc_semtest");
  me = fork();
  sw = me;

  ipc = IPC_SEMAPHORE_NEW("/tmp/gnunet_ipc_semtest",
			  0);
  for (cnt=0;cnt<3;cnt++) {
    if (sw == 0) {
      for (i=0;i<6;i++) {
	IPC_SEMAPHORE_DOWN(ipc);
	fd = FOPEN("/tmp/gnunet_ipc_xchange",
		       "a+");
	if (fd == NULL) {
	  printf("Could not open testfile for reading: %s\n",
		 STRERROR(errno));
	  ret = 1;
	  goto END;
	}
	fseek(fd, 4*i, SEEK_SET);
	si = GN_FREAD(&j, 4, 1, fd);
	while (si == 0)
	  si = GN_FREAD(&j, 4, 1, fd);
	if (si != 1) {
	  printf("Could not read from testfile: %d - %s at %s:%d\n",
		 si,
		 STRERROR(errno),
		 __FILE__,
		 __LINE__);
	  ret = 1;
	  goto END;
	}
	fclose(fd);
	if (j != i+cnt) {
	  printf("IPC test failed at cnt=%d i=%d j=%d %s:%u\n",
		 cnt, i, j, __FILE__, __LINE__);
	  ret = 1;
	  goto END;
	} else
	  fprintf(stderr, ".");
      }
      REMOVE("/tmp/gnunet_ipc_xchange");
      sw = 1;
    } else {
      for (i=0;i<6;i++) {
	sleep(1);
	fd = FOPEN("/tmp/gnunet_ipc_xchange",
		       "w+");
	if (fd == NULL) {
	  printf("Could not open testfile for writing: %s\n",
		 STRERROR(errno));
	  ret = 1;
	  goto END;
	}
	fseek(fd, 4*i, SEEK_SET);
	j=cnt+i;
	if (1 != GN_FWRITE(&j, 4, 1, fd)) {
	  printf("Could not write to testfile: %s\n",
		 STRERROR(errno));
	  ret = 1;
	  goto END;
	}
	fclose(fd);
	IPC_SEMAPHORE_UP(ipc);
      }
      fprintf(stderr, ".");
      sleep(2); /* give reader ample time to finish */
      sw = 0;
    }
  }
 END:
  IPC_SEMAPHORE_FREE(ipc);
  REMOVE("/tmp/gnunet_ipc_xchange");
  if (me == 0) {
    exit(ret);
  } else {
    LOG(LOG_DEBUG,
	" waiting for other process to exit.\n");
    if (-1 == waitpid(me, &j, 0))
      LOG(LOG_ERROR,
	  " waitpid failed: %s\n",
	  STRERROR(errno));
    if ((! WIFEXITED(j)) || WEXITSTATUS(j) == 1)
      ret = 1; /* error in child */
  }
  return ret;
}


/**
 * Perform option parsing from the command line.
 */
static int parseCommandLine(int argc,
			    char * argv[]) {
  char c;

  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      { "loglevel",1, 0, 'L' },
      { "config",  1, 0, 'c' },
      { 0,0,0,0 }
    };

    c = GNgetopt_long(argc,
		      argv,
		      "c:L:",
		      long_options,
		      &option_index);

    if (c == -1)
      break;  /* No more flags to process */

    switch(c) {
    case 'L':
      FREENONNULL(setConfigurationString("GNUNET",
					 "LOGLEVEL",
					 GNoptarg));
      break;
    case 'c':
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    } /* end of parsing commandline */
  }
  return OK;
}
#endif /* PORT-ME MINGW */

int main(int argc, char * argv[]){
  int ret = 0;

#ifndef MINGW
  initUtil(argc, argv, &parseCommandLine);
  ret += testIPCSemaphore();
  fprintf(stderr, "\n");
  doneUtil();
#endif
  return ret;
}
