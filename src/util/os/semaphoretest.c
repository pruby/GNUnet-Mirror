/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util_error_loggers.h"
#include "platform.h"

#include <sys/types.h>

static struct IPC_SEMAPHORE * ipc;

static struct GE_Context * ectx;

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

  ipc = IPC_SEMAPHORE_CREATE(ectx,
			     "/tmp/gnunet_ipc_semtest",
			     0);
  for (cnt=0;cnt<3;cnt++) {
    if (sw == 0) {
      for (i=0;i<6;i++) {
	IPC_SEMAPHORE_DOWN(ipc,
			   YES);
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
	PTHREAD_SLEEP(50 + i*50);
	fd = FOPEN("/tmp/gnunet_ipc_xchange",
		   "a+");
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
      sleep(1); /* give reader ample time to finish */
      sw = 0;
    }
  }
 END:
  IPC_SEMAPHORE_DESTROY(ipc);
  REMOVE("/tmp/gnunet_ipc_xchange");
  if (me == 0) {
    exit(ret);
  } else {
    GE_LOG(ectx,
	   GE_DEBUG | GE_REQUEST | GE_USER,
	   "waiting for other process to exit.\n");
    if (-1 == waitpid(me, &j, 0))
      GE_LOG(ectx,
	     GE_ERROR | GE_BULK | GE_USER,
	     "waitpid failed: %s\n",
	     STRERROR(errno));
    if ((! WIFEXITED(j)) || WEXITSTATUS(j) == 1)
      ret = 1; /* error in child */
  }
  return ret;
}

int main(int argc, char * argv[]){
  int ret = 0;

  ectx = GE_create_context_stderr(NO,
				  GE_WARNING | GE_ERROR | GE_FATAL |
				  GE_USER | GE_ADMIN | GE_DEVELOPER |
				  GE_IMMEDIATE | GE_BULK);
  GE_setDefaultContext(ectx);
  os_init(ectx);
  ret += testIPCSemaphore();
  fprintf(stderr, "\n");
  GE_free_context(ectx);
  return ret;
}
