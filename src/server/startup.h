/*
     This file is part of GNUnet
     (C) 2001, 2002, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

 
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
 * @file server/startup.h
 * @author Christian Grothoff
 * @brief Helper methods for the startup of gnunetd:
 * - install signal handling
 * - system checks on startup
 * - PID file handling
 * - detaching from terminal
 * - command line parsing
 *
 **/

#ifndef STARTUP_H
#define STARTUP_H

#include "gnunet_util.h"
#include "platform.h"

int debug_flag(void);

int win_service(void);

/**
 * Initialize signal handlers
 **/
void initSignalHandlers(void);

void doneSignalHandlers(void);

void waitForSignalHandler(void);

/**
 * Fork and start a new session to go into the background
 * in the way a good deamon should.
 *
 * @param filedes pointer to an array of 2 file descriptors
 *        to complete the detachment protocol (handshake)
 **/
void detachFromTerminal(int * filedes);

/**
 * Detached process signals former parent success.
 **/
void detachFromTerminalComplete(int * filedes);


/**
 * Write our process ID to the pid file.
 **/
void writePIDFile(void);

/**
 * Delete the pid file.
 **/
void deletePIDFile(void);

/**
 * Load all of the user-specified application modules.
 */
void loadApplicationModules(void);

#ifndef MINGW
/**
 * @brief Change user ID
 */
void changeUser(const char *user);
#endif

#ifdef MINGW
BOOL WINAPI win_shutdown_gnunetd(DWORD dwCtrlType);
void win_service_main(void (*gn_main)());
#endif

#endif
/* end of startup.h */
