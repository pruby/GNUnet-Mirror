/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/os/console.c
 * @brief code to detach from console
 * @author Christian Grothoff
 *
 * Helper code for writing proper termination code when an application
 * receives a SIGTERM/SIGHUP etc.
 */

#include "gnunet_util_os.h"
#include "gnunet_util_error.h"
#include "gnunet_util_string.h"
#include "gnunet_util_disk.h"
#include "platform.h"

/**
 * Fork and start a new session to go into the background
 * in the way a good deamon should.
 *
 * @param filedes pointer to an array of 2 file descriptors
 *        to complete the detachment protocol (handshake)
 */
int os_terminal_detach(struct GE_Context * ectx,
		       int * filedes) {
  pid_t pid;
  int nullfd;

  /* Don't hold the wrong FS mounted */
  if (CHDIR("/") < 0) {
    GE_LOG_STRERROR(ectx,
		    GE_FATAL | GE_USER | GE_ADMIN | GE_IMMEDIATE,
		    "chdir");
    return SYSERR;
  }

#ifndef MINGW
  PIPE(filedes);
  pid = fork();
  if (pid < 0) {
    GE_LOG_STRERROR(ectx,
		    GE_FATAL | GE_USER | GE_ADMIN | GE_IMMEDIATE,
		    "fork");
    return SYSERR;
  }
  if (pid) {  /* Parent */
    int ok;
    char c;

    if (0 != CLOSE(filedes[1]))
      GE_LOG_STRERROR(ectx,
		      GE_WARNING | GE_USER | GE_BULK,
		      "close");
    ok = SYSERR;
    while (0 < READ(filedes[0],
		    &c,
		    sizeof(char))) {
      if (c == '.')
	ok = OK;
    }
    fflush(stdout);
    if (ok == OK)
      exit(0);
    else
      exit(1); /* child reported error */
  }
  if (0 != CLOSE(filedes[0]))
    GE_LOG_STRERROR(ectx,
		    GE_WARNING | GE_USER | GE_BULK,
		    "close");
  nullfd = disk_file_open(ectx,
			  "/dev/null",
			  O_RDWR | O_APPEND);
  if (nullfd < 0) {
    GE_LOG_STRERROR_FILE(ectx,
			 GE_FATAL | GE_USER | GE_ADMIN | GE_IMMEDIATE,
			 "fork",
			 "/dev/null");
    return SYSERR;
  }
  /* child - close fds linking to invoking terminal, but
   * close usual incoming fds, but redirect them somewhere
   * useful so the fds don't get reallocated elsewhere.
   */
  if (dup2(nullfd,0) < 0 ||
      dup2(nullfd,1) < 0 ||
      dup2(nullfd,2) < 0) {
    GE_LOG_STRERROR(ectx,
		    GE_FATAL | GE_USER | GE_ADMIN | GE_IMMEDIATE,
		    "dup2");
    return SYSERR;
  }
  pid = setsid(); /* Detach from controlling terminal */
  if (pid == -1)
    GE_LOG_STRERROR(ectx,
		    GE_ERROR | GE_USER | GE_ADMIN | GE_IMMEDIATE,
		    "setsid");
#else
  FreeConsole();
#endif
  return OK;
}

void os_terminal_detach_complete(struct GE_Context * ectx,
				 int * filedes,
				 int success) {
#ifndef MINGW
  char c = '.';

  if (! success)
    c = '!';
  WRITE(filedes[1],
	&c,
	sizeof(char)); /* signal success */
  if (0 != CLOSE(filedes[1]))
    GE_LOG_STRERROR(ectx,
		    GE_WARNING | GE_USER | GE_ADMIN | GE_IMMEDIATE,
		    "close");
#endif
}

