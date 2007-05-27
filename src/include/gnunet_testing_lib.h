/*
      This file is part of GNUnet
      (C) 2007 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_testing_lib.h
 * @brief convenience API for writing testcases for GNUnet
 * @author Christian Grothoff
 */

#ifndef GNUNET_TESTING_LIB_H
#define GNUNET_TESTING_LIB_H

#include "gnunet_util.h"

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Starts a gnunet daemon.
 *
 * @param port port to listen on for local clients
 * @param gnunetd_home directory to use for the home directory
 * @param transports transport services that should be loaded
 * @param applications application services that should be loaded
 * @param pid of the process (set)
 * @param peer identity of the peer (set)
 * @return OK on success, SYSERR on error
 */
int gnunet_testing_start_daemon(unsigned short port,
				const char * gnunetd_home,
				const char * transports,
				const char * applications,
				pid_t * pid,
				PeerIdentity * peer);

/**
 * Establish a connection between two GNUnet daemons
 * (both must run on this machine).
 * 
 * @param port1 client port of the first daemon
 * @param port2 client port of the second daemon
 * @return OK on success, SYSERR on failure
 */
int gnunet_testing_connect_daemons(unsigned short port1,
				   unsigned short port2);


/**
 * Shutdown the GNUnet daemon waiting on the given port
 * and running under the given pid.
 *
 * @return OK on success, SYSERR on failure
 */
int gnunet_testing_stop_daemon(unsigned short port,
			       pid_t pid);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif